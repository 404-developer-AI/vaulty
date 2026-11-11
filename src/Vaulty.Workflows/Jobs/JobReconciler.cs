using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Temporalio.Api.Enums.V1;
using Temporalio.Client;
using Temporalio.Exceptions;
using Vaulty.Infrastructure.Backup;

namespace Vaulty.Workflows.Jobs;

public sealed record ReconcileOptions
{
    public TimeSpan Interval { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>A job younger than this is left alone: its workflow may not have recorded its start yet.</summary>
    public TimeSpan MinimumAge { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Failed attempts of one workflow task after which a workflow counts as stuck (it retries without end otherwise).</summary>
    public int StuckAttempts { get; init; } = 3;

    /// <summary>How long a cancellation request gets to arrive on its own before the reconciler steps in.</summary>
    public TimeSpan CancelGrace { get; init; } = TimeSpan.FromMinutes(2);
}

public sealed record ReconcileResult(int Closed, int Stuck, int Stopped, int Forwarded);

/// <summary>
/// Compares open jobs with the workflow engine, so a job never shows "Running" for a workflow that is gone or cannot move:
/// <list type="bullet">
/// <item>a workflow that ended without recording its job (terminated, timed out, removed) closes the job and its staged snapshot;</item>
/// <item>a workflow whose task keeps failing (for example after an update that no longer matches its history) is marked stuck
/// with an alert, and is stopped when someone asked to cancel it, because a stuck workflow cannot process that request itself;</item>
/// <item>a cancellation that did not reach the run (an older version recorded the run of a child step) is sent to the right run.</item>
/// </list>
/// </summary>
public sealed class JobReconciler(ITemporalClient client, JobRepair repair, TimeProvider clock, ILogger<JobReconciler> logger,
    ReconcileOptions? options = null) : BackgroundService
{
    private readonly ReconcileOptions _options = options ?? new ReconcileOptions();

    public const string StuckReason =
        "its workflow cannot continue (after an update it no longer matches the code that started it). Cancel the job to stop it; the next run starts as usual.";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var result = await RunOnceAsync(stoppingToken).ConfigureAwait(false);
                if (result.Closed + result.Stuck + result.Stopped + result.Forwarded > 0)
                {
                    logger.LogWarning("Job reconciler: {Closed} closed, {Stuck} stuck, {Stopped} stopped, {Forwarded} cancellations forwarded",
                        result.Closed, result.Stuck, result.Stopped, result.Forwarded);
                }
            }
            catch (Exception ex) when (ex is NpgsqlException or RpcException or InvalidOperationException)
            {
                logger.LogWarning(ex, "Job reconciler round failed; retrying next round");
            }
            await Task.Delay(_options.Interval, clock, stoppingToken).ConfigureAwait(false);
        }
    }

    public async Task<ReconcileResult> RunOnceAsync(CancellationToken cancellationToken = default)
    {
        var now = clock.GetUtcNow();
        int closed = 0, stuck = 0, stopped = 0, forwarded = 0;
        foreach (var job in await repair.UnfinishedAsync(now - _options.MinimumAge, cancellationToken).ConfigureAwait(false))
        {
            var description = await DescribeAsync(job.WorkflowId, job.WorkflowRunId, cancellationToken).ConfigureAwait(false);
            if (description is null)
            {
                if (await repair.CloseAsync(job, "failed", "Its workflow no longer exists.", alert: true, now, cancellationToken).ConfigureAwait(false)) closed++;
                continue;
            }
            if (description.RunId != job.WorkflowRunId)
            {
                // The recorded run is gone. The current run is this job's own unless another job records it.
                if (await repair.RunBelongsToAnotherJobAsync(job, description.RunId, cancellationToken).ConfigureAwait(false))
                {
                    var before = description.StartTime is { } s ? new DateTimeOffset(s, TimeSpan.Zero) : now;
                    if (await repair.CloseAsync(job, "failed", "Its workflow run no longer exists.", alert: false, before, cancellationToken).ConfigureAwait(false)) closed++;
                    continue;
                }
                await repair.SetRunAsync(job, description.RunId, cancellationToken).ConfigureAwait(false);
            }

            if (description.Status != WorkflowExecutionStatus.Running)
            {
                var (state, reason, alert) = description.Status switch
                {
                    WorkflowExecutionStatus.Terminated or WorkflowExecutionStatus.Canceled => ("cancelled", "It was stopped.", false),
                    WorkflowExecutionStatus.TimedOut => ("failed", "It ran out of time before it finished.", true),
                    WorkflowExecutionStatus.Failed => ("failed", "It ended with an error before it could record its outcome.", true),
                    _ => ("failed", "It ended without recording its outcome.", false),
                };
                if (await repair.CloseAsync(job, state, reason, alert, now, cancellationToken).ConfigureAwait(false)) closed++;
                continue;
            }

            var isStuck = await FailedAttemptsAsync(description, cancellationToken).ConfigureAwait(false) >= _options.StuckAttempts;
            if (job.CancelRequestedAt is { } asked && now - asked >= _options.CancelGrace)
            {
                var handle = client.GetWorkflowHandle(job.WorkflowId, description.RunId);
                try
                {
                    if (isStuck)
                    {
                        // A stuck workflow cannot run its own cancellation; ending it is the only way to honour the request.
                        await handle.TerminateAsync("Cancellation requested; the workflow was stuck and could not stop by itself.",
                            new() { Rpc = new() { CancellationToken = cancellationToken } }).ConfigureAwait(false);
                        if (await repair.CloseAsync(job, "cancelled", "Stopped on request; its workflow was stuck and could not stop by itself.",
                                alert: false, now, cancellationToken).ConfigureAwait(false)) stopped++;
                    }
                    else
                    {
                        await handle.CancelAsync(new() { Rpc = new() { CancellationToken = cancellationToken } }).ConfigureAwait(false);
                        forwarded++;
                    }
                }
                catch (RpcException ex) when (ex.Code == RpcException.StatusCode.NotFound)
                {
                    // Ended meanwhile: the next round closes the job if its workflow did not.
                }
                continue;
            }
            if (isStuck)
            {
                await repair.MarkStuckAsync(job, StuckReason, cancellationToken).ConfigureAwait(false);
                stuck++;
            }
        }
        return new ReconcileResult(closed, stuck, stopped, forwarded);
    }

    /// <summary>The run, or the current run of the workflow id when that run is not found or continued as new; null when neither exists.</summary>
    private async Task<WorkflowExecutionDescription?> DescribeAsync(string workflowId, string? runId, CancellationToken cancellationToken)
    {
        if (runId is not null)
        {
            var run = await TryDescribeAsync(workflowId, runId, cancellationToken).ConfigureAwait(false);
            if (run is not null && run.Status != WorkflowExecutionStatus.ContinuedAsNew) return run;
        }
        return await TryDescribeAsync(workflowId, null, cancellationToken).ConfigureAwait(false);
    }

    private async Task<WorkflowExecutionDescription?> TryDescribeAsync(string workflowId, string? runId, CancellationToken cancellationToken)
    {
        try
        {
            return await client.GetWorkflowHandle(workflowId, runId).DescribeAsync(new() { Rpc = new() { CancellationToken = cancellationToken } })
                .ConfigureAwait(false);
        }
        catch (RpcException ex) when (ex.Code is RpcException.StatusCode.NotFound or RpcException.StatusCode.InvalidArgument)
        {
            return null;
        }
    }

    /// <summary>The most failed attempts of a pending workflow task, of the workflow or of one of its running child steps.</summary>
    private async Task<int> FailedAttemptsAsync(WorkflowExecutionDescription description, CancellationToken cancellationToken)
    {
        var raw = await RawAsync(description.Id, description.RunId, cancellationToken).ConfigureAwait(false);
        if (raw is null) return 0;
        var attempts = raw.PendingWorkflowTask?.Attempt ?? 0;
        foreach (var child in raw.PendingChildren)
        {
            var childRaw = await RawAsync(child.WorkflowId, null, cancellationToken).ConfigureAwait(false);
            if (childRaw?.WorkflowExecutionInfo?.Status == WorkflowExecutionStatus.Running)
            {
                attempts = Math.Max(attempts, childRaw.PendingWorkflowTask?.Attempt ?? 0);
            }
        }
        return attempts;
    }

    private async Task<Temporalio.Api.WorkflowService.V1.DescribeWorkflowExecutionResponse?> RawAsync(string workflowId, string? runId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await client.WorkflowService.DescribeWorkflowExecutionAsync(new()
            {
                Namespace = client.Options.Namespace,
                Execution = new() { WorkflowId = workflowId, RunId = runId ?? "" },
            }, new() { CancellationToken = cancellationToken }).ConfigureAwait(false);
        }
        catch (RpcException ex) when (ex.Code is RpcException.StatusCode.NotFound or RpcException.StatusCode.InvalidArgument)
        {
            return null;
        }
    }
}
