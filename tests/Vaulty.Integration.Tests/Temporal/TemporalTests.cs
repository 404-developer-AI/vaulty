using System.Diagnostics;
using Dapper;
using Npgsql;
using Temporalio.Api.Enums.V1;
using Temporalio.Client;
using Temporalio.Worker;
using Vaulty.Infrastructure.Database;
using Vaulty.Integration.Tests.Database;
using Vaulty.Workflows;
using Vaulty.Workflows.Jobs;
using Vaulty.Workflows.Synthetic;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Temporal;

public sealed class TemporalFixture : IAsyncLifetime
{
    public PostgresDatabase Database { get; } = new();
    public TemporalDevServer Server { get; } = new();

    public async Task InitializeAsync()
    {
        await Database.InitializeAsync();
        await Server.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await Server.DisposeAsync();
        await Database.DisposeAsync();
    }
}

public sealed class TemporalTests(TemporalFixture fixture, ITestOutputHelper output) : IClassFixture<TemporalFixture>
{
    private const int Folders = 4;
    private const int PagesPerFolder = 40;
    private const int ItemsPerPage = 50;

    private async Task<SyntheticBackupInput> SeedAsync()
    {
        var org = Guid.NewGuid();
        var tenant = Guid.NewGuid();
        var obj = Guid.NewGuid();
        var snapshot = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'O');
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C', 'C');
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name) VALUES (@tenant, @org, @customer, @entra, 'T');
            INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, source_id, display_name) VALUES (@obj, @org, @tenant, 'mailbox', @obj, 'M');
            INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id) VALUES (@snapshot, @org, @tenant, @obj);
            """, new { org, customer = Guid.NewGuid(), tenant, entra = Guid.NewGuid(), obj, snapshot });
        return new SyntheticBackupInput(Guid.NewGuid(), org, tenant, obj, snapshot, Folders, PagesPerFolder, ItemsPerPage,
            PageDelayMilliseconds: 150, PagesPerRun: 10);
    }

    private async Task<List<string>> StoredSources(SyntheticBackupInput input)
    {
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        return (await owner.QueryAsync<string>(
            "SELECT source_id FROM vaulty.items WHERE tenant_id = @TenantId AND first_snapshot_id = @SnapshotId ORDER BY source_id",
            new { input.TenantId, input.SnapshotId })).ToList();
    }

    private static IEnumerable<string> ExpectedSources() =>
        from f in Enumerable.Range(0, Folders)
        from p in Enumerable.Range(0, PagesPerFolder)
        from i in Enumerable.Range(0, ItemsPerPage)
        select $"folder-{f:D3}/{p:D5}/{i:D3}";

    [TemporalFact]
    public async Task Twenty_worker_kills_end_in_the_same_result_as_an_undisturbed_run()
    {
        // Undisturbed run.
        var quiet = await SeedAsync();
        using (var worker = WorkerProcess.Start(fixture))
        {
            var result = await fixture.Server.Client.ExecuteWorkflowAsync((SyntheticObjectBackupWorkflow w) => w.RunAsync(quiet),
                new WorkflowOptions($"quiet-{quiet.SnapshotId}", TaskQueues.Backup));
            Assert.False(result.IsPartial);
        }
        var quietSources = await StoredSources(quiet);

        // The same backup, with the worker process killed 20 times at random moments.
        var disturbed = await SeedAsync();
        var id = $"kill-{disturbed.SnapshotId}";
        var random = new Random(20261109);
        var worker2 = WorkerProcess.Start(fixture);
        var handle = await fixture.Server.Client.StartWorkflowAsync((SyntheticObjectBackupWorkflow w) => w.RunAsync(disturbed),
            new WorkflowOptions(id, TaskQueues.Backup));
        var stopwatch = Stopwatch.StartNew();
        for (var kill = 0; kill < 20; kill++)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(random.Next(800, 3500)));
            worker2.Kill();
            await Task.Delay(TimeSpan.FromMilliseconds(random.Next(0, 1500)));
            worker2 = WorkerProcess.Start(fixture);
        }
        var final = await handle.GetResultAsync();
        worker2.Dispose();
        output.WriteLine($"20 kills, completed after {stopwatch.Elapsed.TotalSeconds:F0} s; counts {string.Join(", ", final.Counts)}");

        var sources = await StoredSources(disturbed);
        Assert.Equal(ExpectedSources().Order(StringComparer.Ordinal), sources);  // none missing, none twice
        Assert.Equal(quietSources, sources);
        Assert.False(final.IsPartial);
        Assert.Equal(Folders * PagesPerFolder * ItemsPerPage, final.Counts["stored"]);

        // The job mirror shows the outcome with exact counts.
        await using (var owner = new NpgsqlConnection(fixture.Database.Migrator))
        {
            var job = await owner.QuerySingleAsync<(string State, string Counts)>(
                "SELECT state, result_counts::text FROM vaulty.jobs WHERE id = @JobId", new { disturbed.JobId });
            Assert.Equal("succeeded", job.State);
            Assert.Contains("\"stored\": 8000", job.Counts, StringComparison.Ordinal);
        }

        // ContinueAsNew keeps every run's history small.
        var runs = new List<WorkflowExecution>();
        await foreach (var execution in fixture.Server.Client.ListWorkflowsAsync($"WorkflowId STARTS_WITH '{id}'")) runs.Add(execution);
        Assert.Contains(runs, r => r.Status == WorkflowExecutionStatus.ContinuedAsNew);
        var longest = runs.Max(r => r.HistoryLength);
        output.WriteLine($"{runs.Count} workflow runs, longest history {longest} events");
        Assert.True(longest < 10_000, $"history of {longest} events");
    }

    [TemporalFact]
    public async Task An_activity_without_heartbeat_is_rescheduled_and_the_second_attempt_is_idempotent()
    {
        var seed = await SeedAsync();
        await using var dataSource = VaultyDataSource.Create(fixture.Database.Worker);
        using var worker = InProcessWorker(dataSource);
        var probe = new StuckActivityInput(seed.OrganizationId, seed.SnapshotId, "probe", StuckSeconds: 6);
        var attempt = await worker.ExecuteAsync(() => fixture.Server.Client.ExecuteWorkflowAsync(
            (SyntheticHeartbeatProbeWorkflow w) => w.RunAsync(probe), new WorkflowOptions($"probe-{seed.SnapshotId}", "probe-queue")));
        Assert.True(attempt >= 2, "the hanging first attempt must have been replaced");

        // Let the abandoned first attempt finish its late write; the row stays one row with the highest attempt.
        await Task.Delay(TimeSpan.FromSeconds(7));
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        var rows = (await owner.QueryAsync<int>(
            "SELECT next_page FROM vaulty.folder_checkpoints WHERE snapshot_id = @SnapshotId AND folder_id = 'probe'", new { seed.SnapshotId })).ToList();
        Assert.Equal([attempt], rows);
    }

    [TemporalFact]
    public async Task Retry_after_from_an_activity_takes_precedence_over_the_backoff()
    {
        var seed = await SeedAsync();
        await using var dataSource = VaultyDataSource.Create(fixture.Database.Worker);
        using var worker = InProcessWorker(dataSource);
        var waited = await worker.ExecuteAsync(() => fixture.Server.Client.ExecuteWorkflowAsync(
            (SyntheticThrottleProbeWorkflow w) => w.RunAsync(new ThrottleProbeInput(3)),
            new WorkflowOptions($"throttle-{seed.SnapshotId}", "probe-queue")));
        output.WriteLine($"second attempt after {waited:F2} s");
        Assert.InRange(waited, 2.9, 6);
    }

    [TemporalFact]
    public async Task Five_thousand_concurrent_child_workflows_complete_on_one_dev_server()
    {
        await using var dataSource = VaultyDataSource.Create(fixture.Database.Worker);
        using var worker = new TemporalWorker(fixture.Server.Client, new TemporalWorkerOptions("fanout-queue")
        {
            MaxConcurrentWorkflowTasks = 200,
            MaxCachedWorkflows = 6000,
        }.AddWorkflow<SyntheticFanOutWorkflow>().AddWorkflow<SyntheticNoopWorkflow>());
        var stopwatch = Stopwatch.StartNew();
        var completed = await worker.ExecuteAsync(() => fixture.Server.Client.ExecuteWorkflowAsync(
            (SyntheticFanOutWorkflow w) => w.RunAsync(new FanOutInput(10, 500)),
            new WorkflowOptions($"fanout-{Guid.NewGuid()}", "fanout-queue") { ExecutionTimeout = TimeSpan.FromMinutes(15) }));
        stopwatch.Stop();
        output.WriteLine($"5,000 child workflows in {stopwatch.Elapsed.TotalSeconds:F1} s ({5000 / stopwatch.Elapsed.TotalSeconds:F0}/s)");
        Assert.Equal(5000, completed);
    }

    private TemporalWorker InProcessWorker(NpgsqlDataSource dataSource) =>
        new(fixture.Server.Client, new TemporalWorkerOptions("probe-queue")
            .AddAllActivities(new SyntheticActivities(dataSource))
            .AddAllActivities(new JobActivities(dataSource))
            .AddWorkflow<SyntheticHeartbeatProbeWorkflow>()
            .AddWorkflow<SyntheticThrottleProbeWorkflow>());

    /// <summary>The real worker host in its own process, so it can be killed.</summary>
    private sealed class WorkerProcess : IDisposable
    {
        private readonly Process _process;

        private WorkerProcess(Process process) => _process = process;

        public static WorkerProcess Start(TemporalFixture fixture)
        {
            var dll = typeof(Workers.WorkerHost).Assembly.Location;
            var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add(dll);
            start.Environment["Vaulty__Temporal__Address"] = fixture.Server.Address;
            start.Environment["Vaulty__Temporal__Namespace"] = TemporalDevServer.Namespace;
            start.Environment["Vaulty__Database__ConnectionString"] = fixture.Database.Worker;
            start.Environment["Vaulty__Workers__Synthetic"] = "true";
            start.Environment["Vaulty__Workers__Queues"] = TaskQueues.Backup;
            start.Environment["DOTNET_ENVIRONMENT"] = "Development";
            start.Environment["VAULTY_DEV_MASTER_KEY"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
            var process = Process.Start(start)!;
            process.OutputDataReceived += (_, _) => { };
            process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            return new WorkerProcess(process);
        }

        public void Kill()
        {
            if (!_process.HasExited) _process.Kill(entireProcessTree: true);
            _process.WaitForExit(10_000);
        }

        public void Dispose()
        {
            Kill();
            _process.Dispose();
        }
    }
}
