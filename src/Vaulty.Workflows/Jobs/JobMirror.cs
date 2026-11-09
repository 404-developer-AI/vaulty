using System.Text.Json;
using Dapper;
using Npgsql;
using Temporalio.Activities;
using Temporalio.Exceptions;
using Temporalio.Worker.Interceptors;
using Temporalio.Workflows;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Workflows.Jobs;

/// <summary>Input of a workflow that is shown as a job in Vaulty.</summary>
public interface IJobInput
{
    Guid JobId { get; }
    Guid OrganizationId { get; }
    JobKind JobKind { get; }
}

/// <summary>Result of a job workflow: exact counts, and whether anything is missing.</summary>
public interface IJobResult
{
    IReadOnlyDictionary<string, long> Counts { get; }
    bool Partial { get; }
}

public sealed record JobStartInput(Guid JobId, Guid OrganizationId, JobKind Kind, string WorkflowId, string RunId);

public sealed record JobFinishInput(Guid JobId, Guid OrganizationId, JobState State, Dictionary<string, long> Counts, string? Error);

public sealed record JobProgressInput(Guid JobId, Guid OrganizationId, Dictionary<string, long> Progress);

/// <summary>Writes the jobs table, the mirror of the workflow engine that the UI and reports read.</summary>
public sealed class JobActivities(NpgsqlDataSource dataSource)
{
    [Activity]
    public async Task StartAsync(JobStartInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        await using var session = await OrganizationSession.BeginAsync(dataSource, input.OrganizationId).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(
            """
            INSERT INTO vaulty.jobs (id, organization_id, kind, state, workflow_id, workflow_run_id, started_at)
            VALUES (@JobId, @OrganizationId, @kind, 'running', @WorkflowId, @RunId, now())
            ON CONFLICT (id) DO UPDATE SET
                state = CASE WHEN vaulty.jobs.state = 'queued' THEN 'running' ELSE vaulty.jobs.state END,
                workflow_id = coalesce(vaulty.jobs.workflow_id, excluded.workflow_id),
                workflow_run_id = excluded.workflow_run_id,
                started_at = coalesce(vaulty.jobs.started_at, excluded.started_at)
            """,
            new { input.JobId, input.OrganizationId, kind = StateText.ToText(input.Kind), input.WorkflowId, input.RunId },
            session.Transaction).ConfigureAwait(false);
        await session.CommitAsync().ConfigureAwait(false);
    }

    [Activity]
    public async Task ProgressAsync(JobProgressInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        await using var session = await OrganizationSession.BeginAsync(dataSource, input.OrganizationId).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(
            "UPDATE vaulty.jobs SET progress = @progress::jsonb WHERE id = @JobId AND state = 'running'",
            new { input.JobId, progress = JsonSerializer.Serialize(input.Progress) }, session.Transaction).ConfigureAwait(false);
        await session.CommitAsync().ConfigureAwait(false);
    }

    [Activity]
    public async Task FinishAsync(JobFinishInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        await using var session = await OrganizationSession.BeginAsync(dataSource, input.OrganizationId).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(
            """
            UPDATE vaulty.jobs SET state = @state, finished_at = now(), result_counts = @counts::jsonb, error = @Error
             WHERE id = @JobId AND state IN ('queued', 'running')
            """,
            new { input.JobId, state = StateText.ToText(input.State), counts = JsonSerializer.Serialize(input.Counts), input.Error },
            session.Transaction).ConfigureAwait(false);
        await session.CommitAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// Mirrors every workflow whose input is an <see cref="IJobInput"/> into the jobs table: start, end, counts and error.
/// The writes are local activities, so they are part of the deterministic workflow history and survive worker crashes.
/// A run that continues as new is not an end.
/// </summary>
public sealed class JobMirrorInterceptor : IWorkerInterceptor
{
    public WorkflowInboundInterceptor InterceptWorkflow(WorkflowInboundInterceptor nextInterceptor) => new Inbound(nextInterceptor);

    private sealed class Inbound(WorkflowInboundInterceptor next) : WorkflowInboundInterceptor(next)
    {
        private static readonly LocalActivityOptions Options = new()
        {
            StartToCloseTimeout = TimeSpan.FromSeconds(30),
            // The job row must be written even when the workflow itself is being cancelled.
            CancellationToken = CancellationToken.None,
            RetryPolicy = new() { InitialInterval = TimeSpan.FromSeconds(1), MaximumInterval = TimeSpan.FromSeconds(30) },
        };

        public override async Task<object?> ExecuteWorkflowAsync(ExecuteWorkflowInput input)
        {
            if (input.Args.FirstOrDefault() is not IJobInput job || job.JobId == Guid.Empty) return await Next.ExecuteWorkflowAsync(input);

            if (!Workflow.Info.ContinuedRunId.HasValue())
            {
                var start = new JobStartInput(job.JobId, job.OrganizationId, job.JobKind, Workflow.Info.WorkflowId, Workflow.Info.RunId);
                await Workflow.ExecuteLocalActivityAsync((JobActivities a) => a.StartAsync(start), Options);
            }
            try
            {
                var result = await Next.ExecuteWorkflowAsync(input);
                var counts = result is IJobResult r ? r.Counts.ToDictionary() : [];
                var state = result is IJobResult { Partial: true } ? JobState.Partial : JobState.Succeeded;
                var finish = new JobFinishInput(job.JobId, job.OrganizationId, state, counts, null);
                await Workflow.ExecuteLocalActivityAsync((JobActivities a) => a.FinishAsync(finish), Options);
                return result;
            }
            catch (ContinueAsNewException)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || Workflow.CancellationToken.IsCancellationRequested)
            {
                var state = Workflow.CancellationToken.IsCancellationRequested ? JobState.Cancelled : JobState.Failed;
                var finish = new JobFinishInput(job.JobId, job.OrganizationId, state, new Dictionary<string, long>(), ex.Message);
                await Workflow.ExecuteLocalActivityAsync((JobActivities a) => a.FinishAsync(finish), Options);
                throw;
            }
        }
    }
}

internal static class StringExtensions
{
    public static bool HasValue(this string? value) => !string.IsNullOrEmpty(value);
}
