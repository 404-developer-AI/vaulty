using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Domain;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Reporting;

public sealed record ObjectStatusRow(Guid Id, Guid TenantId, string Name, string Kind, string? SubKind, ProtectionStatus Status, string Reason,
    DateTimeOffset? LastSnapshotAt, long? Items, int Missing, DateTimeOffset? VerifiedAt);

public sealed record TenantStatusRow(Guid Id, Guid CustomerId, string Name, string ConsentState, string State, ProtectionStatus Status, string Reason,
    IReadOnlyDictionary<ProtectionStatus, int> Counts, DateTimeOffset? OldestLatestSnapshotAt, DateTimeOffset? LastVerificationAt, int? LastVerificationFailures,
    long Requests24h, long Throttled24h, IReadOnlyList<ObjectStatusRow> Objects);

public sealed record CustomerStatusRow(Guid Id, string Code, string Name, ProtectionStatus Status, IReadOnlyDictionary<ProtectionStatus, int> Counts,
    IReadOnlyList<TenantStatusRow> Tenants);

public sealed record AlertRow(Guid Id, string Severity, string Kind, string Message, DateTimeOffset CreatedAt, Guid? TenantId, Guid? ObjectId);

public sealed record Dashboard(IReadOnlyList<CustomerStatusRow> Customers, IReadOnlyDictionary<ProtectionStatus, int> Totals, IReadOnlyList<AlertRow> OpenAlerts)
{
    public IEnumerable<TenantStatusRow> Tenants => Customers.SelectMany(c => c.Tenants);
}

/// <summary>
/// The dashboard that tells the truth: every customer, tenant and protected object the user may see, worst state first,
/// with exact counts. A tenant takes the worst state of its objects (and is failed while consent is lost or verification
/// failed); a customer takes the worst state of its tenants.
/// </summary>
public sealed class DashboardService(NpgsqlDataSource dataSource, TimeProvider clock)
{
    private sealed record ObjectData(Guid Id, Guid TenantId, string DisplayName, string Kind, string? SubKind, string State, string? LastState,
        DateTime? CommittedAt, string? ItemCounts, int Exceptions, DateTime? VerifiedAt, int Frequency, bool LastFailed, DateTime CreatedAt);

    private sealed record TenantData(Guid Id, Guid CustomerId, string DisplayName, string ConsentState, string State, DateTime? VerificationAt,
        int? VerificationFailures, bool VerificationAlert, long Requests, long Throttled);

    public async Task<Dashboard> LoadAsync(UserAccess access, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var now = clock.GetUtcNow();
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var customers = (await session.Connection.QueryAsync<(Guid Id, string Code, string Name)>(new CommandDefinition(
            "SELECT id, code, name FROM vaulty.customers", transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
            .Where(c => access.Allows(Permissions.CustomersView, c.Id)).ToList();
        var tenants = (await session.Connection.QueryAsync<TenantData>(new CommandDefinition(
            """
            SELECT t.id, t.customer_id, t.display_name, t.consent_state, t.state,
                   v.finished_at AS verification_at, jsonb_array_length(v.failures) AS verification_failures,
                   EXISTS (SELECT 1 FROM vaulty.alerts a WHERE a.tenant_id = t.id AND a.kind = 'verification.failed' AND a.resolved_at IS NULL) AS verification_alert,
                   coalesce(u.requests, 0) AS requests, coalesce(u.throttled, 0) AS throttled
              FROM vaulty.tenants t
              LEFT JOIN LATERAL (SELECT finished_at, failures FROM vaulty.verification_runs r
                                  WHERE r.tenant_id = t.id AND r.finished_at IS NOT NULL ORDER BY r.started_at DESC LIMIT 1) v ON true
              LEFT JOIN LATERAL (SELECT sum(requests)::bigint AS requests, sum(throttled)::bigint AS throttled FROM vaulty.graph_usage_hourly g
                                  WHERE g.tenant_id = t.id AND g.hour > @since) u ON true
             WHERE t.state <> 'deleted' AND (@tenantId::uuid IS NULL OR t.id = @tenantId)
            """, new { since = now.AddHours(-24), tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var objects = (await session.Connection.QueryAsync<ObjectData>(new CommandDefinition(
            """
            SELECT o.id, o.tenant_id, o.display_name, o.kind, o.sub_kind, o.state, s.state AS last_state, s.committed_at,
                   s.item_counts::text AS item_counts, coalesce(jsonb_array_length(s.exceptions), 0) AS exceptions, s.verified_at,
                   coalesce(po.frequency_minutes, pt.frequency_minutes, 360) AS frequency,
                   EXISTS (SELECT 1 FROM vaulty.snapshots f WHERE f.protected_object_id = o.id AND f.state = 'failed'
                             AND f.started_at > coalesce(s.started_at, '-infinity'::timestamptz)) AS last_failed,
                   o.created_at
              FROM vaulty.protected_objects o
              LEFT JOIN vaulty.snapshots s ON s.id = o.last_snapshot_id
              LEFT JOIN vaulty.policies po ON po.protected_object_id = o.id
              LEFT JOIN vaulty.policies pt ON pt.tenant_id = o.tenant_id AND pt.protected_object_id IS NULL
             WHERE @tenantId::uuid IS NULL OR o.tenant_id = @tenantId
            """, new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var visibleTenants = tenants.Where(t => customers.Any(c => c.Id == t.CustomerId)).Select(t => t.Id).ToHashSet();
        var alerts = (await session.Connection.QueryAsync<(Guid Id, string Severity, string Kind, string Message, DateTime CreatedAt, Guid? TenantId, Guid? ObjectId)>(
            new CommandDefinition(
                """
                SELECT id, severity, kind, message, created_at, tenant_id, protected_object_id FROM vaulty.alerts
                 WHERE resolved_at IS NULL ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, created_at DESC LIMIT 200
                """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
            .Where(a => a.TenantId is { } t ? visibleTenants.Contains(t) : access.Allows(Permissions.SettingsManage))
            .Select(a => new AlertRow(a.Id, a.Severity, a.Kind, a.Message, Utc(a.CreatedAt)!.Value, a.TenantId, a.ObjectId)).ToList();
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);

        var customerRows = new List<CustomerStatusRow>();
        foreach (var customer in customers)
        {
            var tenantRows = new List<TenantStatusRow>();
            foreach (var tenant in tenants.Where(t => t.CustomerId == customer.Id))
            {
                var objectRows = objects.Where(o => o.TenantId == tenant.Id).Select(o =>
                {
                    var (status, reason) = Protection.Of(new ProtectionInput(o.State, o.LastState, Utc(o.CommittedAt), o.Frequency, tenant.ConsentState, false,
                        o.LastFailed, Utc(o.CreatedAt)), now);
                    return new ObjectStatusRow(o.Id, o.TenantId, o.DisplayName, o.Kind, o.SubKind, status, reason, Utc(o.CommittedAt), ItemsOf(o.ItemCounts),
                        o.LastState == "partial" ? o.Exceptions : 0, Utc(o.VerifiedAt));
                }).OrderByDescending(o => o.Status).ThenBy(o => o.Name, StringComparer.OrdinalIgnoreCase).ToList();
                var (tenantStatus, tenantReason) = TenantStatus(tenant, objectRows);
                var latest = objectRows.Where(o => o.LastSnapshotAt is not null && o.Status != ProtectionStatus.SourceDeleted).Select(o => o.LastSnapshotAt!.Value).ToList();
                tenantRows.Add(new TenantStatusRow(tenant.Id, tenant.CustomerId, tenant.DisplayName, tenant.ConsentState, tenant.State, tenantStatus, tenantReason,
                    CountsOf(objectRows.Select(o => o.Status)), latest.Count == 0 ? null : latest.Min(), Utc(tenant.VerificationAt), tenant.VerificationFailures,
                    tenant.Requests, tenant.Throttled, objectRows));
            }
            tenantRows = tenantRows.OrderByDescending(t => t.Status).ThenBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ToList();
            customerRows.Add(new CustomerStatusRow(customer.Id, customer.Code, customer.Name, Protection.Worst(tenantRows.Select(t => t.Status)),
                CountsOf(tenantRows.SelectMany(t => t.Objects).Select(o => o.Status)), tenantRows));
        }
        customerRows = customerRows.OrderByDescending(c => c.Status).ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
        return new Dashboard(customerRows, CountsOf(customerRows.SelectMany(c => c.Tenants).SelectMany(t => t.Objects).Select(o => o.Status)), alerts);
    }

    private static (ProtectionStatus, string) TenantStatus(TenantData tenant, IReadOnlyList<ObjectStatusRow> objects)
    {
        if (tenant.State == "deletion_requested") return (ProtectionStatus.Paused, "Deletion requested; backups are stopped.");
        if (tenant.ConsentState == "lost") return (ProtectionStatus.Failed, "Vaulty lost access to this tenant.");
        if (tenant.VerificationAlert) return (ProtectionStatus.Failed, "Verification found a problem in stored data.");
        var worst = Protection.Worst(objects.Select(o => o.Status));
        var selected = objects.Where(o => o.Status != ProtectionStatus.Excluded).ToList();
        var count = selected.Count(o => o.Status == worst);
        var excluded = objects.Count - selected.Count;
        var (status, reason) = worst switch
        {
            ProtectionStatus.Failed => (worst, $"{count} protected object{(count == 1 ? " is" : "s are")} failed."),
            ProtectionStatus.Partial => (worst, $"{count} protected object{(count == 1 ? " has" : "s have")} a partial latest snapshot."),
            // Not all green yet, but nothing wrong either: say how far the first backups are.
            ProtectionStatus.NotRunYet when selected.Count == 0 => (worst, "No mailbox or OneDrive is selected for backup yet."),
            ProtectionStatus.NotRunYet => (worst, $"{selected.Count - count} of {selected.Count} selected objects have a snapshot; " +
                                                  $"{count} {(count == 1 ? "waits" : "wait")} for {(count == 1 ? "its" : "their")} first backup."),
            ProtectionStatus.Excluded => (worst, "No mailbox or OneDrive is selected for backup."),
            _ => (worst, ""),
        };
        // Excluded objects never decide the status, but they are never hidden either.
        if (excluded > 0 && worst != ProtectionStatus.Excluded) reason = $"{reason} {excluded} not selected for backup.".Trim();
        return (status, reason);
    }

    private static IReadOnlyDictionary<ProtectionStatus, int> CountsOf(IEnumerable<ProtectionStatus> states) =>
        states.GroupBy(s => s).ToDictionary(g => g.Key, g => g.Count());

    private static long? ItemsOf(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("items", out var items) && items.TryGetInt64(out var n) ? n : null;
    }

    private static DateTimeOffset? Utc(DateTime? value) => value is { } v ? new DateTimeOffset(DateTime.SpecifyKind(v, DateTimeKind.Utc)) : null;
}
