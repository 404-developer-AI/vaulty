using Microsoft.Extensions.Logging;
using Npgsql;
using Temporalio.Activities;
using Temporalio.Client;
using Temporalio.Exceptions;
using Temporalio.Workflows;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Workflows.Jobs;

namespace Vaulty.Workflows.Tenants;

public sealed record DiscoveryInput(Guid JobId, Guid OrganizationId, Guid TenantId) : IJobInput
{
    public JobKind JobKind => JobKind.Discovery;
}

public sealed record DiscoveryOutput(Dictionary<string, long> ItemCounts) : IJobResult
{
    public IReadOnlyDictionary<string, long> Counts => ItemCounts;
    public bool Partial => false;
}

public sealed record HealthSweepResult(int Checked, int Healthy, int Lost, int Unknown);

/// <summary>Finds the protected objects of a tenant. Idempotent; shown as a job.</summary>
[Workflow]
public sealed class DiscoveryWorkflow
{
    [WorkflowRun]
    public async Task<DiscoveryOutput> RunAsync(DiscoveryInput input)
    {
        var options = ActivityPolicies.External(TimeSpan.FromHours(2));
        var counts = await Workflow.ExecuteActivityAsync((TenantActivities a) => a.DiscoverAsync(input), options);
        return new DiscoveryOutput(counts);
    }
}

/// <summary>Checks every connected tenant once an hour (cron) so lost consent is shown and alerted within the hour.</summary>
[Workflow]
public sealed class TenantHealthWorkflow
{
    public const string Id = "tenant-health";
    public const string Cron = "7 * * * *";

    [WorkflowRun]
    public async Task<HealthSweepResult> RunAsync()
    {
        var tenants = await Workflow.ExecuteActivityAsync((TenantActivities a) => a.ConnectedTenantsAsync(), ActivityPolicies.Database());
        int healthy = 0, lost = 0, unknown = 0;
        foreach (var tenant in tenants)
        {
            var outcome = await Workflow.ExecuteActivityAsync((TenantActivities a) => a.CheckHealthAsync(tenant),
                ActivityPolicies.External(TimeSpan.FromMinutes(2)));
            switch (outcome)
            {
                case HealthOutcome.Healthy: healthy++; break;
                case HealthOutcome.ConsentLost: lost++; break;
                default: unknown++; break;
            }
        }
        return new HealthSweepResult(tenants.Count, healthy, lost, unknown);
    }
}

public sealed record TenantRef(Guid OrganizationId, Guid TenantId);

public sealed class TenantActivities(NpgsqlDataSource dataSource, GraphServices graph, TimeProvider clock, ILogger<TenantActivities> logger)
{
    [Activity]
    public async Task<Dictionary<string, long>> DiscoverAsync(DiscoveryInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var discovery = new TenantDiscovery(dataSource, graph.Client, clock);
        var found = await discovery.FindAsync(input.TenantId, () => context.Heartbeat(), context.CancellationToken);
        var result = await discovery.ApplyAsync(input.OrganizationId, input.TenantId, found, context.CancellationToken);
        logger.LogInformation("Discovery of tenant {TenantId} found {Count} objects", input.TenantId, found.Count);
        return result.Counts();
    }

    [Activity]
    public Task<List<TenantRef>> ConnectedTenantsAsync() =>
        new TenantHealthCheck(dataSource, graph.Tokens, clock).ConnectedTenantsAsync()
            .ContinueWith(t => t.Result.Select(x => new TenantRef(x.OrganizationId, x.TenantId)).ToList(), TaskScheduler.Default);

    [Activity]
    public async Task<HealthOutcome> CheckHealthAsync(TenantRef tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var result = await new TenantHealthCheck(dataSource, graph.Tokens, clock).CheckAsync(tenant.OrganizationId, tenant.TenantId);
        if (result.BecameLost) logger.LogWarning("Tenant {TenantId} lost its consent: {Detail}", tenant.TenantId, result.Detail);
        return result.Outcome;
    }
}

/// <summary>Starts workflows from the web app and the scheduler without them knowing Temporal.</summary>
public interface IWorkflowStarter
{
    Task<Guid> StartDiscoveryAsync(Guid organizationId, Guid tenantId, Guid requestedBy, CancellationToken cancellationToken = default);

    /// <summary>"Back up now": returns the job id, or null when a backup of the object is already running.</summary>
    Task<Guid?> StartBackupAsync(Guid organizationId, Guid tenantId, Guid objectId, string kind, Guid requestedBy, CancellationToken cancellationToken = default);

    /// <summary>Starts a planned restore or export (its job and restore rows exist already).</summary>
    Task StartRestoreAsync(Guid organizationId, Guid tenantId, Guid restoreId, Guid jobId, bool isExport, CancellationToken cancellationToken = default);

    /// <summary>"pause", "resume" or "cancel" for a running restore; ignored when it already finished.</summary>
    Task SignalRestoreAsync(Guid restoreId, string signal, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requests cancellation of one workflow run (a backup or discovery). Returns false when that run was not found: it ended,
    /// or the job recorded another run; the job reconciler then closes the job or sends the request to the right run.
    /// </summary>
    Task<bool> CancelAsync(string workflowId, string? runId, CancellationToken cancellationToken = default);
}

public sealed class TemporalWorkflowStarter(Func<Task<ITemporalClient>> client, NpgsqlDataSource dataSource) : IWorkflowStarter
{
    public async Task<Guid?> StartBackupAsync(Guid organizationId, Guid tenantId, Guid objectId, string kind, Guid requestedBy,
        CancellationToken cancellationToken = default) =>
        await new Backup.BackupStarter(await client().ConfigureAwait(false), dataSource)
            .StartAsync(organizationId, tenantId, objectId, kind, requestedBy, cancellationToken).ConfigureAwait(false);

    public static string RestoreWorkflowId(Guid restoreId) => $"restore-{restoreId:N}";

    public async Task StartRestoreAsync(Guid organizationId, Guid tenantId, Guid restoreId, Guid jobId, bool isExport,
        CancellationToken cancellationToken = default)
    {
        var temporal = await client().ConfigureAwait(false);
        var input = new Restore.RestoreInput(jobId, organizationId, tenantId, restoreId, isExport);
        await temporal.StartWorkflowAsync((Restore.RestoreWorkflow w) => w.RunAsync(input, false),
            new WorkflowOptions(RestoreWorkflowId(restoreId), TaskQueues.Restore) { IdConflictPolicy = Temporalio.Api.Enums.V1.WorkflowIdConflictPolicy.UseExisting })
            .ConfigureAwait(false);
    }

    public async Task<bool> CancelAsync(string workflowId, string? runId, CancellationToken cancellationToken = default)
    {
        var handle = (await client().ConfigureAwait(false)).GetWorkflowHandle(workflowId, runId);
        try
        {
            await handle.CancelAsync(new() { Rpc = new() { CancellationToken = cancellationToken } }).ConfigureAwait(false);
            return true;
        }
        catch (Temporalio.Exceptions.RpcException ex) when (ex.Code is Temporalio.Exceptions.RpcException.StatusCode.NotFound
                                                              or Temporalio.Exceptions.RpcException.StatusCode.InvalidArgument)
        {
            return false;
        }
    }

    public async Task SignalRestoreAsync(Guid restoreId, string signal, CancellationToken cancellationToken = default)
    {
        var handle = (await client().ConfigureAwait(false)).GetWorkflowHandle<Restore.RestoreWorkflow>(RestoreWorkflowId(restoreId));
        try
        {
            switch (signal)
            {
                case "pause": await handle.SignalAsync(w => w.PauseAsync()).ConfigureAwait(false); break;
                case "resume": await handle.SignalAsync(w => w.ResumeAsync()).ConfigureAwait(false); break;
                case "cancel": await handle.SignalAsync(w => w.CancelAsync()).ConfigureAwait(false); break;
                default: throw new ArgumentException("Unknown signal.", nameof(signal));
            }
        }
        catch (Temporalio.Exceptions.RpcException ex) when (ex.Code == Temporalio.Exceptions.RpcException.StatusCode.NotFound)
        {
            // Finished already: nothing to pause or cancel.
        }
    }

    public async Task<Guid> StartDiscoveryAsync(Guid organizationId, Guid tenantId, Guid requestedBy, CancellationToken cancellationToken = default)
    {
        var jobId = await JobRecords.CreateAsync(dataSource, organizationId, JobKind.Discovery, tenantId, null, requestedBy, cancellationToken)
            .ConfigureAwait(false);
        var temporal = await client().ConfigureAwait(false);
        try
        {
            await temporal.StartWorkflowAsync((DiscoveryWorkflow w) => w.RunAsync(new DiscoveryInput(jobId, organizationId, tenantId)),
                new WorkflowOptions($"discovery-{tenantId:N}", TaskQueues.Backup)
                {
                    IdConflictPolicy = Temporalio.Api.Enums.V1.WorkflowIdConflictPolicy.Fail,
                    IdReusePolicy = Temporalio.Api.Enums.V1.WorkflowIdReusePolicy.AllowDuplicate,
                }).ConfigureAwait(false);
        }
        catch (WorkflowAlreadyStartedException)
        {
            // A discovery of this tenant is already running; the new job record is closed as such.
            await JobRecords.FinishAsync(dataSource, organizationId, jobId, JobState.Cancelled, Infrastructure.Notifications.JobsService.DiscoveryAlreadyRunning,
                cancellationToken).ConfigureAwait(false);
        }
        return jobId;
    }
}

/// <summary>Creates job rows before a workflow starts, so the job is visible at once.</summary>
public static class JobRecords
{
    public static async Task<Guid> CreateAsync(NpgsqlDataSource dataSource, Guid organizationId, JobKind kind, Guid? tenantId, Guid? objectId,
        Guid? requestedBy, CancellationToken cancellationToken = default)
    {
        var id = Guid.CreateVersion7();
        await using var session = await Infrastructure.Database.OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken)
            .ConfigureAwait(false);
        await Dapper.SqlMapper.ExecuteAsync(session.Connection, new Dapper.CommandDefinition(
            "INSERT INTO vaulty.jobs (id, organization_id, tenant_id, protected_object_id, kind, state, requested_by) VALUES (@id, @organizationId, @tenantId, @objectId, @kind, 'queued', @requestedBy)",
            new { id, organizationId, tenantId, objectId, kind = StateText.ToText(kind), requestedBy }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    public static async Task FinishAsync(NpgsqlDataSource dataSource, Guid organizationId, Guid jobId, JobState state, string? error,
        CancellationToken cancellationToken = default)
    {
        await using var session = await Infrastructure.Database.OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken)
            .ConfigureAwait(false);
        await Dapper.SqlMapper.ExecuteAsync(session.Connection, new Dapper.CommandDefinition(
            "UPDATE vaulty.jobs SET state = @state, finished_at = now(), error = @error WHERE id = @jobId",
            new { jobId, state = StateText.ToText(state), error }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }
}
