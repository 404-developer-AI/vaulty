using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Notifications;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Retention;

namespace Vaulty.Infrastructure.Backup;

/// <summary>An open job as the reconciler sees it.</summary>
public sealed record UnfinishedJob(Guid OrganizationId, Guid Id, string Kind, Guid? TenantId, Guid? ProtectedObjectId, string WorkflowId,
    string? WorkflowRunId, DateTimeOffset StartedAt, DateTimeOffset? CancelRequestedAt);

/// <summary>
/// The database side of reconciling jobs with the workflow engine: a job whose workflow ended without recording it is
/// closed (with its staged snapshot), and a job whose workflow is stuck says so and raises an alert instead of showing
/// "Running" for good.
/// </summary>
public sealed class JobRepair(NpgsqlDataSource dataSource, TimeProvider clock)
{
    /// <summary>Open backup and discovery jobs with a workflow, started before <paramref name="startedBefore"/>.</summary>
    public async Task<IReadOnlyList<UnfinishedJob>> UnfinishedAsync(DateTimeOffset startedBefore, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<(Guid OrganizationId, Guid Id, string Kind, Guid? TenantId, Guid? ObjectId, string WorkflowId, string? RunId,
            DateTime StartedAt, DateTime? CancelRequestedAt)>(new CommandDefinition(
            """
            SELECT organization_id, id, kind, tenant_id, protected_object_id, workflow_id, workflow_run_id, started_at, cancel_requested_at
              FROM vaulty.unfinished_jobs(@startedBefore)
            """, new { startedBefore }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new UnfinishedJob(r.OrganizationId, r.Id, r.Kind, r.TenantId, r.ObjectId, r.WorkflowId, r.RunId,
            new DateTimeOffset(DateTime.SpecifyKind(r.StartedAt, DateTimeKind.Utc)),
            r.CancelRequestedAt is { } c ? new DateTimeOffset(DateTime.SpecifyKind(c, DateTimeKind.Utc)) : null)).ToList();
    }

    /// <summary>Whether another open job records this workflow run as its own.</summary>
    public async Task<bool> RunBelongsToAnotherJobAsync(UnfinishedJob job, string runId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        await using var session = await OrganizationSession.BeginAsync(dataSource, job.OrganizationId, cancellationToken).ConfigureAwait(false);
        return await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT EXISTS (SELECT 1 FROM vaulty.jobs WHERE workflow_run_id = @runId AND id <> @Id)",
            new { runId, job.Id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>Records the run the job really belongs to (older versions could record the run of a child step).</summary>
    public async Task SetRunAsync(UnfinishedJob job, string runId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        await using var session = await OrganizationSession.BeginAsync(dataSource, job.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.jobs SET workflow_run_id = @runId
             WHERE id = @Id AND NOT EXISTS (SELECT 1 FROM vaulty.jobs o WHERE o.workflow_run_id = @runId AND o.id <> @Id)
            """, new { runId, job.Id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Closes a job whose workflow ended without recording it. A backup's snapshot that is still staged (started before
    /// <paramref name="stagedBefore"/>, so never one of a run that is still going) is closed as failed. With
    /// <paramref name="alert"/>, a backup failure alert is raised. Returns false when the job was closed already.
    /// </summary>
    public async Task<bool> CloseAsync(UnfinishedJob job, string state, string reason, bool alert, DateTimeOffset stagedBefore,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        await using var session = await OrganizationSession.BeginAsync(dataSource, job.OrganizationId, cancellationToken).ConfigureAwait(false);
        var closed = await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.jobs SET state = @state, finished_at = @now, error = @reason WHERE id = @Id AND state IN ('queued', 'running')",
            new { state, now = clock.GetUtcNow(), reason, job.Id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (closed == 0) return false;
        await Audit.AuditLog.WriteAsync(session, "system:reconciler", "job.closed", $"job:{job.Id}", new { state, reason }, cancellationToken)
            .ConfigureAwait(false);
        if (job.Kind == "backup" && job.ProtectedObjectId is { } objectId)
        {
            var code = state == "cancelled" ? "cancelled" : "failed";
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vaulty.snapshots SET state = 'failed', exceptions = @exceptions::jsonb
                 WHERE protected_object_id = @objectId AND state = 'staged' AND started_at < @stagedBefore
                """, new { objectId, stagedBefore, exceptions = JsonSerializer.Serialize(new[] { new { error_code = code, detail = reason } }) },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (alert)
            {
                await Alerts.RaiseAsync(session, job.TenantId, objectId, NotificationKinds.BackupFailed, "critical",
                    $"Backup of {await NameAsync(session, objectId, cancellationToken).ConfigureAwait(false)} failed: {reason} Vaulty retries at the next run.",
                    new { job = job.Id }, cancellationToken).ConfigureAwait(false);
            }
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>Marks a running job as stuck: its error says so and, for a backup, an alert is raised once. Returns whether the alert is new.</summary>
    public async Task<bool> MarkStuckAsync(UnfinishedJob job, string reason, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        await using var session = await OrganizationSession.BeginAsync(dataSource, job.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.jobs SET error = @reason WHERE id = @Id AND state = 'running' AND error IS DISTINCT FROM @reason",
            new { reason, job.Id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var raised = false;
        if (job.Kind == "backup" && job.ProtectedObjectId is { } objectId)
        {
            raised = await Alerts.RaiseAsync(session, job.TenantId, objectId, NotificationKinds.BackupFailed, "critical",
                $"Backup of {await NameAsync(session, objectId, cancellationToken).ConfigureAwait(false)} is stuck: {reason}",
                new { job = job.Id }, cancellationToken).ConfigureAwait(false);
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return raised;
    }

    private static async Task<string> NameAsync(OrganizationSession session, Guid objectId, CancellationToken cancellationToken) =>
        await session.Connection.ExecuteScalarAsync<string>(new CommandDefinition(
            "SELECT display_name FROM vaulty.protected_objects WHERE id = @objectId", new { objectId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false) ?? "a protected object";
}
