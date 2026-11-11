using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Temporalio.Api.Enums.V1;
using Temporalio.Client;
using Temporalio.Worker;
using Temporalio.Workflows;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Database;
using Vaulty.Integration.Tests.Notifications;
using Vaulty.Workflows.Jobs;

namespace Vaulty.Integration.Tests.Temporal;

/// <summary>Workflow code that always throws: its workflow task fails and is retried without end, like a run that no longer replays.</summary>
[Workflow("ReconcileStuckStep")]
public sealed class StuckStepWorkflow
{
    [WorkflowRun]
    public Task RunAsync() => throw new InvalidOperationException("This workflow task always fails.");
}

/// <summary>A backup-like parent that waits on a child step, as a drive backup does.</summary>
[Workflow("ReconcileParent")]
public sealed class ParentOfStuckStepWorkflow
{
    [WorkflowRun]
    public Task RunAsync() => Workflow.ExecuteChildWorkflowAsync((StuckStepWorkflow w) => w.RunAsync(),
        new ChildWorkflowOptions { Id = $"{Workflow.Info.WorkflowId}/step" });
}

[Workflow("ReconcileWaiting")]
public sealed class WaitingWorkflow
{
    [WorkflowRun]
    public Task RunAsync() => Workflow.DelayAsync(TimeSpan.FromHours(1));
}

/// <summary>
/// The job reconciler against the Temporal dev server: a stuck run is reported and, once someone asked to cancel it,
/// stopped; a run that ended without recording its job closes the job and its staged snapshot; a cancellation that went to
/// a run that does not exist reaches the job's real run.
/// </summary>
public sealed class JobReconcilerTests(TemporalFixture fixture) : IClassFixture<TemporalFixture>
{
    // Jobs of this test start "two hours ago"; other tests' jobs are fresh and below the minimum age.
    private static readonly ReconcileOptions Options = new() { MinimumAge = TimeSpan.FromHours(1), StuckAttempts = 2, CancelGrace = TimeSpan.FromMinutes(2) };

    private JobReconciler Reconciler(NpgsqlDataSource worker) =>
        new(fixture.Server.Client, new JobRepair(worker, TimeProvider.System), TimeProvider.System, NullLogger<JobReconciler>.Instance, Options);

    [TemporalFact]
    public async Task A_stuck_backup_is_reported_and_stopped_once_someone_asked_to_cancel_it()
    {
        var seed = new NotificationSeed();
        await seed.SeedAsync(fixture.Database, DateTimeOffset.UtcNow.AddDays(1));
        var queue = $"reconcile-{Guid.NewGuid():N}";
        using var worker = new TemporalWorker(fixture.Server.Client,
            new TemporalWorkerOptions(queue).AddWorkflow<ParentOfStuckStepWorkflow>().AddWorkflow<StuckStepWorkflow>());
        await worker.ExecuteAsync(async () =>
        {
            var workflowId = $"backup-{seed.Object:N}";
            var handle = await fixture.Server.Client.StartWorkflowAsync((ParentOfStuckStepWorkflow w) => w.RunAsync(), new WorkflowOptions(workflowId, queue));
            var (job, snapshot) = await SeedRunningJobAsync(seed, workflowId, handle.ResultRunId);
            await UntilAsync(async () =>
            {
                try
                {
                    return (await fixture.Server.Client.WorkflowService.DescribeWorkflowExecutionAsync(new()
                    {
                        Namespace = fixture.Server.Client.Options.Namespace,
                        Execution = new() { WorkflowId = $"{workflowId}/step" },
                    })).PendingWorkflowTask?.Attempt >= 2;
                }
                catch (Temporalio.Exceptions.RpcException ex) when (ex.Code == Temporalio.Exceptions.RpcException.StatusCode.NotFound)
                {
                    return false; // the child step has not started yet
                }
            });

            await using var dataSource = VaultyDataSource.Create(fixture.Database.Worker);
            await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
            await Reconciler(dataSource).RunOnceAsync();
            // Stuck: still running, but it says so and raises one alert.
            Assert.Equal(("running", JobReconciler.StuckReason), await owner.QuerySingleAsync<(string, string)>("SELECT state, error FROM vaulty.jobs WHERE id = @job", new { job }));
            Assert.Contains("is stuck", await owner.ExecuteScalarAsync<string>(
                "SELECT message FROM vaulty.alerts WHERE protected_object_id = @o AND kind = 'backup.failed' AND resolved_at IS NULL", new { o = seed.Object }));

            // Someone asks to cancel it; a stuck run cannot process that, so the reconciler stops it and closes job and snapshot.
            await owner.ExecuteAsync("UPDATE vaulty.jobs SET cancel_requested_at = now() - interval '10 minutes' WHERE id = @job", new { job });
            Assert.Equal(1, (await Reconciler(dataSource).RunOnceAsync()).Stopped);
            Assert.Equal(WorkflowExecutionStatus.Terminated, (await handle.DescribeAsync()).Status);
            Assert.Equal("cancelled", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.jobs WHERE id = @job", new { job }));
            Assert.Equal("failed", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.snapshots WHERE id = @snapshot", new { snapshot }));
            await SettleAsync(owner, seed);
        });
    }

    [TemporalFact]
    public async Task Jobs_of_ended_or_missing_runs_are_closed_and_a_misdirected_cancellation_reaches_the_real_run()
    {
        var seed = new NotificationSeed();
        await seed.SeedAsync(fixture.Database, DateTimeOffset.UtcNow.AddDays(1));
        var queue = $"reconcile-{Guid.NewGuid():N}";
        using var worker = new TemporalWorker(fixture.Server.Client, new TemporalWorkerOptions(queue).AddWorkflow<WaitingWorkflow>());
        await worker.ExecuteAsync(async () =>
        {
            await using var dataSource = VaultyDataSource.Create(fixture.Database.Worker);
            await using var owner = new NpgsqlConnection(fixture.Database.Migrator);

            // Terminated from outside: the job is closed as cancelled and its staged snapshot with it, without an alert.
            var ended = await fixture.Server.Client.StartWorkflowAsync((WaitingWorkflow w) => w.RunAsync(), new WorkflowOptions($"backup-{seed.Object:N}", queue));
            var (endedJob, endedSnapshot) = await SeedRunningJobAsync(seed, ended.Id, ended.ResultRunId);
            await ended.TerminateAsync("test");
            // Never existed: closed as failed, with an alert.
            var (missingJob, _) = await SeedRunningJobAsync(seed, $"backup-{Guid.NewGuid():N}", Guid.NewGuid().ToString());
            await Reconciler(dataSource).RunOnceAsync();
            Assert.Equal("cancelled", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.jobs WHERE id = @endedJob", new { endedJob }));
            Assert.Equal("failed", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.snapshots WHERE id = @endedSnapshot", new { endedSnapshot }));
            Assert.Equal("failed", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.jobs WHERE id = @missingJob", new { missingJob }));
            Assert.Equal(1, await owner.ExecuteScalarAsync<int>(
                "SELECT count(*) FROM vaulty.alerts WHERE protected_object_id = @o AND kind = 'backup.failed' AND resolved_at IS NULL", new { o = seed.Object }));

            // A job that recorded another run (older versions recorded a child step's run): the cancellation goes to the real run.
            var running = await fixture.Server.Client.StartWorkflowAsync((WaitingWorkflow w) => w.RunAsync(), new WorkflowOptions($"backup-{seed.Object:N}", queue));
            var (misdirected, _) = await SeedRunningJobAsync(seed, running.Id, Guid.NewGuid().ToString());
            await owner.ExecuteAsync("UPDATE vaulty.jobs SET cancel_requested_at = now() - interval '10 minutes' WHERE id = @misdirected", new { misdirected });
            Assert.Equal(1, (await Reconciler(dataSource).RunOnceAsync()).Forwarded);
            Assert.Equal(running.ResultRunId, await owner.ExecuteScalarAsync<string>("SELECT workflow_run_id FROM vaulty.jobs WHERE id = @misdirected", new { misdirected }));
            await UntilAsync(async () => (await running.DescribeAsync()).Status == WorkflowExecutionStatus.Canceled);
            await Reconciler(dataSource).RunOnceAsync();
            Assert.Equal("cancelled", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.jobs WHERE id = @misdirected", new { misdirected }));
            await SettleAsync(owner, seed);
        });
    }

    private async Task<(Guid Job, Guid Snapshot)> SeedRunningJobAsync(NotificationSeed seed, string workflowId, string? runId)
    {
        var (job, snapshot) = (Guid.NewGuid(), Guid.NewGuid());
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.jobs (id, organization_id, kind, tenant_id, protected_object_id, state, started_at, workflow_id, workflow_run_id)
                VALUES (@job, @org, 'backup', @tenant, @o, 'running', now() - interval '2 hours', @workflowId, @runId);
            INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state, started_at)
                VALUES (@snapshot, @org, @tenant, @o, 'staged', now() - interval '2 hours');
            """, new { job, snapshot, org = seed.Org, tenant = seed.Tenant, o = seed.Object, workflowId, runId });
        return (job, snapshot);
    }

    /// <summary>Leaves nothing open for other tests that share the database.</summary>
    private static Task SettleAsync(NpgsqlConnection owner, NotificationSeed seed) => owner.ExecuteAsync(
        """
        UPDATE vaulty.alerts SET resolved_at = now(), notified_at = coalesce(notified_at, now()) WHERE organization_id = @org;
        UPDATE vaulty.jobs SET state = 'cancelled' WHERE organization_id = @org AND state IN ('queued', 'running');
        UPDATE vaulty.protected_objects SET state = 'paused' WHERE organization_id = @org;
        """, new { org = seed.Org });

    private static async Task UntilAsync(Func<Task<bool>> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (!await condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "The condition was not met in time.");
            await Task.Delay(250);
        }
    }
}
