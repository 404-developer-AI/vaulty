using Dapper;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Restore;

namespace Vaulty.Infrastructure.Retention;

/// <param name="HoldsBackups">The tenant has a snapshot or stored data; only then do the waiting period and the second administrator apply.</param>
public sealed record TenantDeletionState(string State, DateTimeOffset? RequestedAt, Guid? RequestedBy, DateTimeOffset? ConfirmableFrom, bool LegalHold,
    bool HoldsBackups);

/// <summary>
/// Deleting a tenant never happens on one click: one administrator requests it (backups stop at once), a reminder is raised
/// every day for 30 days, and only then can a second administrator confirm. After confirmation retention ends for the
/// tenant's snapshots and garbage collection removes the data as its Object Lock expires. Until confirmation the request
/// can be withdrawn. A legal hold blocks the deletion.
/// A tenant that never stored anything (no snapshot, no pack, no backup running) protects no data: it can be removed at
/// once, by one administrator with a fresh step-up, so a wrongly connected tenant does not block its reconnection.
/// </summary>
public sealed class TenantDeletion(NpgsqlDataSource dataSource, TimeProvider clock)
{
    public static readonly TimeSpan WaitingPeriod = TimeSpan.FromDays(30);

    public async Task<TenantDeletionState> StateAsync(UserAccess access, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var row = await TenantAsync(access, tenantId, null, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var holdsBackups = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(HoldsBackupsSql, new { tenantId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return new TenantDeletionState(row.State, Utc(row.RequestedAt), row.RequestedBy, Utc(row.RequestedAt)?.Add(WaitingPeriod), row.LegalHold, holdsBackups);
    }

    /// <summary>True when the tenant has a snapshot, a pack in storage or a backup job that is queued or running.</summary>
    internal const string HoldsBackupsSql = """
        SELECT EXISTS (SELECT 1 FROM vaulty.snapshots WHERE tenant_id = @tenantId)
            OR EXISTS (SELECT 1 FROM vaulty.packs WHERE tenant_id = @tenantId)
            OR EXISTS (SELECT 1 FROM vaulty.jobs WHERE tenant_id = @tenantId AND state IN ('queued', 'running'))
        """;

    /// <summary>
    /// Removes a tenant that holds no backups at once. Refused as soon as the tenant has a snapshot, stored data or a running
    /// backup: then only the request, the 30-day wait and a second administrator delete it.
    /// </summary>
    public async Task RemoveUnusedAsync(UserAccess access, bool stepUpFresh, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var row = await TenantAsync(access, tenantId, Permissions.TenantsDelete, cancellationToken).ConfigureAwait(false);
        if (!stepUpFresh) throw new StepUpRequiredException();
        if (row.LegalHold) throw new InvalidOperationException("The tenant is on legal hold. Release the hold before deleting it.");
        if (row.State == "deleted") throw new InvalidOperationException("This tenant is deleted already.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        // One statement: the check for backups and the removal cannot be separated by a backup that starts in between.
        var removed = await session.Connection.ExecuteAsync(new CommandDefinition(
            $"""
            UPDATE vaulty.tenants
               SET state = 'deleted', deletion_requested_at = coalesce(deletion_requested_at, @now),
                   deletion_requested_by = coalesce(deletion_requested_by, @user), deletion_confirmed_by = NULL
             WHERE id = @tenantId AND state <> 'deleted' AND NOT legal_hold AND NOT ({HoldsBackupsSql})
            """, new { tenantId, now = clock.GetUtcNow(), user = access.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (removed == 0)
        {
            throw new InvalidOperationException("This tenant holds backups. Request its deletion; a second administrator can confirm it after 30 days.");
        }
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.alerts SET resolved_at = @now, resolved_by = @user WHERE tenant_id = @tenantId AND kind = 'tenant.deletion_pending' AND resolved_at IS NULL",
            new { tenantId, now = clock.GetUtcNow(), user = access.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "tenant.removed_without_backups", $"tenant:{tenantId}", new { previous_state = row.State },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RequestAsync(UserAccess access, bool stepUpFresh, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var row = await TenantAsync(access, tenantId, Permissions.TenantsDelete, cancellationToken).ConfigureAwait(false);
        if (!stepUpFresh) throw new StepUpRequiredException();
        if (row.LegalHold) throw new InvalidOperationException("The tenant is on legal hold. Release the hold before deleting it.");
        if (row.State != "active") throw new InvalidOperationException("A deletion of this tenant was requested already.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.tenants SET state = 'deletion_requested', deletion_requested_at = @now, deletion_requested_by = @user, deletion_confirmed_by = NULL
             WHERE id = @tenantId AND state = 'active'
            """, new { tenantId, now = clock.GetUtcNow(), user = access.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "tenant.deletion_requested", $"tenant:{tenantId}",
            new { confirmable_from = clock.GetUtcNow().Add(WaitingPeriod) }, cancellationToken).ConfigureAwait(false);
        await Alerts.RaiseAsync(session, tenantId, null, "tenant.deletion_pending", "warning",
            $"Deletion of tenant {row.DisplayName} was requested. A second administrator can confirm it from {clock.GetUtcNow().Add(WaitingPeriod):d MMM yyyy}; until then it can be withdrawn.",
            null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task WithdrawAsync(UserAccess access, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await TenantAsync(access, tenantId, Permissions.TenantsDelete, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var changed = await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.tenants SET state = 'active', deletion_requested_at = NULL, deletion_requested_by = NULL
             WHERE id = @tenantId AND state = 'deletion_requested';
            UPDATE vaulty.alerts SET resolved_at = @now, resolved_by = @user WHERE tenant_id = @tenantId AND kind = 'tenant.deletion_pending' AND resolved_at IS NULL;
            """, new { tenantId, now = clock.GetUtcNow(), user = access.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (changed == 0) throw new InvalidOperationException("There is no deletion request to withdraw.");
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "tenant.deletion_withdrawn", $"tenant:{tenantId}", null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ConfirmAsync(UserAccess access, bool stepUpFresh, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var row = await TenantAsync(access, tenantId, Permissions.TenantsDelete, cancellationToken).ConfigureAwait(false);
        if (!stepUpFresh) throw new StepUpRequiredException();
        if (row.State != "deletion_requested" || row.RequestedAt is null) throw new InvalidOperationException("No deletion of this tenant was requested.");
        if (row.RequestedBy == access.UserId) throw new AccessException("A second administrator must confirm the deletion; you requested it.");
        var from = Utc(row.RequestedAt)!.Value.Add(WaitingPeriod);
        if (clock.GetUtcNow() < from) throw new InvalidOperationException($"The deletion can be confirmed from {from:d MMM yyyy, HH:mm} (UTC), 30 days after the request.");
        if (row.LegalHold) throw new InvalidOperationException("The tenant is on legal hold. Release the hold before deleting it.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.tenants SET state = 'deleted', deletion_confirmed_by = @user WHERE id = @tenantId AND state = 'deletion_requested';
            UPDATE vaulty.alerts SET resolved_at = @now, resolved_by = @user WHERE tenant_id = @tenantId AND kind = 'tenant.deletion_pending' AND resolved_at IS NULL;
            """, new { tenantId, user = access.UserId, now = clock.GetUtcNow() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "tenant.deleted", $"tenant:{tenantId}", new { requested_by = row.RequestedBy },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Daily: a fresh reminder for every pending deletion (the previous reminder is closed), so it is seen every day.</summary>
    public async Task<int> RemindAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var pending = (await session.Connection.QueryAsync<(Guid Id, string DisplayName, DateTime RequestedAt)>(new CommandDefinition(
            "SELECT id, display_name, deletion_requested_at FROM vaulty.tenants WHERE state = 'deletion_requested'", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        foreach (var tenant in pending)
        {
            var from = Utc(tenant.RequestedAt)!.Value.Add(WaitingPeriod);
            var days = Math.Max(0, (int)Math.Ceiling((from - clock.GetUtcNow()).TotalDays));
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.alerts SET resolved_at = @now WHERE tenant_id = @id AND kind = 'tenant.deletion_pending' AND resolved_at IS NULL",
                new { tenant.Id, now = clock.GetUtcNow() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await Alerts.RaiseAsync(session, tenant.Id, null, "tenant.deletion_pending", "warning", days > 0
                    ? $"Tenant {tenant.DisplayName} is set to be deleted. A second administrator can confirm in {days} day{(days == 1 ? "" : "s")}; withdraw the request if this is a mistake."
                    : $"Tenant {tenant.DisplayName} is set to be deleted and waits for a second administrator to confirm.",
                null, cancellationToken).ConfigureAwait(false);
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return pending.Count;
    }

    private sealed record TenantRow(Guid CustomerId, string DisplayName, string State, DateTime? RequestedAt, Guid? RequestedBy, bool LegalHold);

    private async Task<TenantRow> TenantAsync(UserAccess access, Guid tenantId, string? permission, CancellationToken cancellationToken)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<TenantRow>(new CommandDefinition(
            "SELECT customer_id, display_name, state, deletion_requested_at AS requested_at, deletion_requested_by AS requested_by, legal_hold FROM vaulty.tenants WHERE id = @tenantId",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (row is null || !access.Allows(Permissions.CustomersView, row.CustomerId) || (permission is not null && !access.Allows(permission, row.CustomerId)))
        {
            throw new AccessException("You do not have access to delete this tenant.");
        }
        return row;
    }

    private static DateTimeOffset? Utc(DateTime? value) => value is { } v ? new DateTimeOffset(DateTime.SpecifyKind(v, DateTimeKind.Utc)) : null;
}

/// <summary>Legal hold for a protected object or a whole tenant: retention stops for it until the hold is released. Audited.</summary>
public sealed class LegalHold(NpgsqlDataSource dataSource)
{
    /// <summary>The protected objects of a tenant that are on legal hold themselves (a tenant hold is in <see cref="TenantDeletionState"/>).</summary>
    public async Task<IReadOnlySet<Guid>> ObjectsOnHoldAsync(UserAccess access, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, Guid CustomerId)>(new CommandDefinition(
            """
            SELECT o.id, t.customer_id FROM vaulty.protected_objects o JOIN vaulty.tenants t ON t.id = o.tenant_id
             WHERE o.tenant_id = @tenantId AND o.legal_hold
            """, new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Where(r => access.Allows(Permissions.CustomersView, r.CustomerId)).Select(r => r.Id).ToHashSet();
    }

    public async Task SetForObjectAsync(UserAccess access, Guid objectId, bool hold, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var customer = await session.Connection.ExecuteScalarAsync<Guid?>(new CommandDefinition(
            "SELECT t.customer_id FROM vaulty.protected_objects o JOIN vaulty.tenants t ON t.id = o.tenant_id WHERE o.id = @objectId", new { objectId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (customer is null || !access.Allows(Permissions.LegalHoldManage, customer.Value)) throw new AccessException("You cannot change the legal hold of this protected object.");
        await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.protected_objects SET legal_hold = @hold WHERE id = @objectId",
            new { objectId, hold }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", hold ? "legalhold.placed" : "legalhold.released", $"object:{objectId}", null, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SetForTenantAsync(UserAccess access, Guid tenantId, bool hold, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var customer = await session.Connection.ExecuteScalarAsync<Guid?>(new CommandDefinition("SELECT customer_id FROM vaulty.tenants WHERE id = @tenantId",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (customer is null || !access.Allows(Permissions.LegalHoldManage, customer.Value)) throw new AccessException("You cannot change the legal hold of this tenant.");
        await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.tenants SET legal_hold = @hold WHERE id = @tenantId",
            new { tenantId, hold }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", hold ? "legalhold.placed" : "legalhold.released", $"tenant:{tenantId}", null, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }
}
