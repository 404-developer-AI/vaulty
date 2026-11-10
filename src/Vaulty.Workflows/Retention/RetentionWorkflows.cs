using Dapper;
using Microsoft.Extensions.Logging;
using Npgsql;
using Temporalio.Activities;
using Temporalio.Workflows;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Retention;

namespace Vaulty.Workflows.Retention;

public sealed record TenantTarget(Guid OrganizationId, Guid TenantId);

public sealed record VerifySummary(int Tenants, int Failures);

public sealed record GcSummary(int Tenants, int Refused, int PacksDeleted, long BytesDeleted);

/// <summary>Daily verification of every tenant with backups (verify queue), and the daily deletion reminders.</summary>
[Workflow]
public sealed class VerificationSweepWorkflow
{
    public const string Id = "verification-sweep";
    public const string Cron = "17 2 * * *";

    [WorkflowRun]
    public async Task<VerifySummary> RunAsync()
    {
        var tenants = await Workflow.ExecuteActivityAsync((VerificationActivities a) => a.TenantsAsync(), ActivityPolicies.Database());
        var failures = 0;
        foreach (var tenant in tenants)
        {
            failures += await Workflow.ExecuteActivityAsync((VerificationActivities a) => a.VerifyAsync(tenant), ActivityPolicies.External(TimeSpan.FromHours(6)));
        }
        await Workflow.ExecuteActivityAsync((VerificationActivities a) => a.RemindAsync(), ActivityPolicies.Database());
        return new VerifySummary(tenants.Count, failures);
    }
}

public sealed class VerificationActivities(NpgsqlDataSource dataSource, VerificationService verification, TenantDeletion deletion,
    ILogger<VerificationActivities> logger)
{
    [Activity("VerificationTenants")]
    public async Task<List<TenantTarget>> TenantsAsync() => await AllTenantsAsync(dataSource, "state <> 'deleted' AND EXISTS (SELECT 1 FROM vaulty.packs p WHERE p.tenant_id = t.id)");

    [Activity("VerificationRun")]
    public async Task<int> VerifyAsync(TenantTarget tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var context = ActivityExecutionContext.Current;
        var result = await verification.RunAsync(tenant.OrganizationId, tenant.TenantId, () => context.Heartbeat(), context.CancellationToken);
        if (result.Failures.Count > 0) logger.LogError("Verification of tenant {TenantId} found {Failures} problems", tenant.TenantId, result.Failures.Count);
        return result.Failures.Count;
    }

    [Activity("VerificationRemind")]
    public async Task RemindAsync()
    {
        await using var connection = await dataSource.OpenConnectionAsync();
        foreach (var organization in await connection.QueryAsync<Guid>("SELECT vaulty.active_organization_ids()")) await deletion.RemindAsync(organization);
    }

    /// <summary>Every tenant of every organization matching <paramref name="condition"/> (SQL on alias t).</summary>
    internal static async Task<List<TenantTarget>> AllTenantsAsync(NpgsqlDataSource dataSource, string condition)
    {
        var result = new List<TenantTarget>();
        List<Guid> organizations;
        await using (var connection = await dataSource.OpenConnectionAsync())
        {
            organizations = (await connection.QueryAsync<Guid>("SELECT vaulty.active_organization_ids()")).ToList();
        }
        foreach (var organization in organizations)
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, organization);
            result.AddRange((await session.Connection.QueryAsync<Guid>(new CommandDefinition($"SELECT t.id FROM vaulty.tenants t WHERE {condition}",
                transaction: session.Transaction))).Select(t => new TenantTarget(organization, t)));
        }
        return result;
    }
}

/// <summary>Daily garbage collection of every tenant (gc queue, own identity): a dry run, then the real run within the same limits.</summary>
[Workflow]
public sealed class GcSweepWorkflow
{
    public const string Id = "gc-sweep";
    public const string Cron = "37 4 * * *";

    [WorkflowRun]
    public async Task<GcSummary> RunAsync()
    {
        var tenants = await Workflow.ExecuteActivityAsync((GcActivities a) => a.TenantsAsync(), ActivityPolicies.Database());
        int refused = 0, packs = 0;
        long bytes = 0;
        foreach (var tenant in tenants)
        {
            var report = await Workflow.ExecuteActivityAsync((GcActivities a) => a.CollectAsync(tenant), ActivityPolicies.External(TimeSpan.FromHours(6)));
            if (report.State == "refused") refused++;
            packs += report.PacksDeleted;
            bytes += report.BytesDeleted;
        }
        return new GcSummary(tenants.Count, refused, packs, bytes);
    }
}

public sealed class GcActivities(NpgsqlDataSource dataSource, GarbageCollector collector, ILogger<GcActivities> logger)
{
    [Activity("GcTenants")]
    public Task<List<TenantTarget>> TenantsAsync() => VerificationActivities.AllTenantsAsync(dataSource, "true");

    [Activity("GcCollect")]
    public async Task<GcReport> CollectAsync(TenantTarget tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        var ct = ActivityExecutionContext.Current.CancellationToken;
        var dry = await collector.RunAsync(tenant.OrganizationId, tenant.TenantId, dryRun: true, ct);
        if (dry.State != "succeeded")
        {
            logger.LogWarning("Garbage collection of tenant {TenantId} refused: {Reason}", tenant.TenantId, dry.Reason);
            return dry;
        }
        if (dry.PacksDeleted == 0 && dry.SnapshotsExpired == 0 && dry.ManifestsDeleted == 0) return dry;
        return await collector.RunAsync(tenant.OrganizationId, tenant.TenantId, dryRun: false, ct);
    }
}
