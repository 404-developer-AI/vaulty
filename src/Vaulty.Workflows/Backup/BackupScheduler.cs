using Dapper;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Temporalio.Client;
using Temporalio.Exceptions;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Database;
using Vaulty.Workflows.Tenants;

namespace Vaulty.Workflows.Backup;

public sealed record SchedulerOptions
{
    public TimeSpan Interval { get; init; } = TimeSpan.FromMinutes(1);
    public int MailboxesPerTenant { get; init; } = Vaulty.Core.Domain.BackupBudget.MailboxesPerTenant;
    public int DrivesPerTenant { get; init; } = Vaulty.Core.Domain.BackupBudget.DrivesPerTenant;
    public int BatchSize { get; init; } = 200;
}

/// <summary>Starts backup workflows; used by the scheduler and by "Back up now".</summary>
public sealed class BackupStarter(ITemporalClient client, NpgsqlDataSource dataSource)
{
    public static string WorkflowId(Guid objectId) => $"backup-{objectId:N}";

    /// <summary>Starts a backup unless one is running for the object. Returns the job id, or null when one was already running.</summary>
    public async Task<Guid?> StartAsync(Guid organizationId, Guid tenantId, Guid objectId, string kind, Guid? requestedBy, CancellationToken cancellationToken = default)
    {
        // A backup that runs longer than the interval is due again while it runs: ask first, so no job is recorded (and at
        // once cancelled) for a run that cannot start. The start below still refuses a second run if two callers race.
        if (await RunningAsync(objectId, cancellationToken).ConfigureAwait(false)) return null;
        var jobId = await JobRecords.CreateAsync(dataSource, organizationId, JobKind.Backup, tenantId, objectId, requestedBy, cancellationToken).ConfigureAwait(false);
        var input = new BackupInput(jobId, organizationId, tenantId, objectId, Guid.CreateVersion7());
        var options = new WorkflowOptions(WorkflowId(objectId), TaskQueues.Backup)
        {
            IdConflictPolicy = Temporalio.Api.Enums.V1.WorkflowIdConflictPolicy.Fail,
            IdReusePolicy = Temporalio.Api.Enums.V1.WorkflowIdReusePolicy.AllowDuplicate,
            ExecutionTimeout = TimeSpan.FromHours(24),
        };
        try
        {
            switch (kind)
            {
                case "mailbox":
                    await client.StartWorkflowAsync((MailboxBackupWorkflow w) => w.RunAsync(input), options).ConfigureAwait(false);
                    break;
                case "drive":
                    await client.StartWorkflowAsync((DriveBackupWorkflow w) => w.RunAsync(input), options).ConfigureAwait(false);
                    break;
                default:
                    await JobRecords.FinishAsync(dataSource, organizationId, jobId, JobState.Failed, $"Backups of {kind} objects are not available.",
                        cancellationToken).ConfigureAwait(false);
                    return null;
            }
        }
        catch (WorkflowAlreadyStartedException)
        {
            await JobRecords.FinishAsync(dataSource, organizationId, jobId, JobState.Cancelled, Infrastructure.Notifications.JobsService.BackupAlreadyRunning, cancellationToken)
                .ConfigureAwait(false);
            return null;
        }
        return jobId;
    }

    private async Task<bool> RunningAsync(Guid objectId, CancellationToken cancellationToken)
    {
        try
        {
            var description = await client.GetWorkflowHandle(WorkflowId(objectId)).DescribeAsync(new() { Rpc = new() { CancellationToken = cancellationToken } })
                .ConfigureAwait(false);
            return description.Status == Temporalio.Api.Enums.V1.WorkflowExecutionStatus.Running;
        }
        catch (Temporalio.Exceptions.RpcException ex) when (ex.Code == Temporalio.Exceptions.RpcException.StatusCode.NotFound)
        {
            return false;
        }
    }
}

/// <summary>
/// Plans backups: every minute it takes the protected objects that are due (active, consent granted), respects the
/// per-tenant budgets so one large tenant never fills all workers, and starts their workflows. Nothing is planned while the
/// storage connection test has not passed.
/// </summary>
public sealed class BackupScheduler(BackupStarter starter, IBackupStorage storage, NpgsqlDataSource dataSource, TimeProvider clock,
    ILogger<BackupScheduler> logger, SchedulerOptions? options = null) : BackgroundService
{
    private readonly SchedulerOptions _options = options ?? new SchedulerOptions();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var started = await RunOnceAsync(stoppingToken).ConfigureAwait(false);
                if (started > 0) logger.LogInformation("Scheduler started {Count} backups", started);
            }
            catch (Exception ex) when (ex is NpgsqlException or RpcException or InvalidOperationException)
            {
                logger.LogWarning(ex, "Scheduler round failed; retrying next round");
            }
            await Task.Delay(_options.Interval, clock, stoppingToken).ConfigureAwait(false);
        }
    }

    public async Task<int> RunOnceAsync(CancellationToken cancellationToken = default)
    {
        if (!await storage.ReadyAsync(cancellationToken).ConfigureAwait(false)) return 0;
        List<(Guid OrganizationId, Guid TenantId, Guid ObjectId)> due;
        Dictionary<(Guid, string), long> running;
        await using (var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        {
            due = (await connection.QueryAsync<(Guid, Guid, Guid)>(new CommandDefinition(
                "SELECT organization_id, tenant_id, protected_object_id FROM vaulty.due_protected_objects(@now, @limit)",
                new { now = clock.GetUtcNow(), limit = _options.BatchSize }, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            running = (await connection.QueryAsync<(Guid TenantId, string Kind, long Running)>(new CommandDefinition(
                "SELECT tenant_id, kind, running FROM vaulty.running_backups()", cancellationToken: cancellationToken)).ConfigureAwait(false))
                .ToDictionary(r => (r.TenantId, r.Kind), r => r.Running);
        }

        var started = 0;
        foreach (var (organizationId, tenantId, objectId) in due)
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
            var kind = await session.Connection.ExecuteScalarAsync<string>(new CommandDefinition(
                "SELECT kind FROM vaulty.protected_objects WHERE id = @objectId", new { objectId }, session.Transaction, cancellationToken: cancellationToken))
                .ConfigureAwait(false) ?? "mailbox";
            var budget = kind == "drive" ? _options.DrivesPerTenant : _options.MailboxesPerTenant;
            var key = (tenantId, kind);
            if (running.GetValueOrDefault(key) >= budget) continue;

            // Push the next run out first, so a slow start is not planned twice; the commit sets the real next run.
            var policy = await PolicyResolver.ForObjectAsync(dataSource, organizationId, tenantId, objectId, cancellationToken).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.protected_objects SET next_run_at = @next WHERE id = @objectId",
                new { objectId, next = clock.GetUtcNow().AddMinutes(policy.FrequencyMinutes) }, session.Transaction, cancellationToken: cancellationToken))
                .ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);

            if (await starter.StartAsync(organizationId, tenantId, objectId, kind, null, cancellationToken).ConfigureAwait(false) is not null)
            {
                running[key] = running.GetValueOrDefault(key) + 1;
                started++;
            }
        }
        return started;
    }
}
