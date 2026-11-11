using Dapper;
using Npgsql;
using Vaulty.Core.Notifications;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Restore;

namespace Vaulty.Infrastructure.Tenants;

/// <summary>
/// Which mailboxes and drives of a tenant are backed up, and whether newly found ones are backed up at once. Excluding an
/// object, or no longer backing up new ones automatically, lowers protection: it needs a fresh step-up and is audited, so
/// a taken-over session cannot quietly stop backups. Snapshots of an excluded object are kept until their retention ends.
/// </summary>
public sealed class BackupSelection(NpgsqlDataSource dataSource, TimeProvider clock)
{
    public async Task<bool> ProtectsNewObjectsAsync(UserAccess access, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        await CustomerOfAsync(session, access, tenantId, Permissions.CustomersView, cancellationToken).ConfigureAwait(false);
        return await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition("SELECT protect_new_objects FROM vaulty.tenants WHERE id = @tenantId",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>Selects or excludes protected objects of one tenant; returns how many changed.</summary>
    public async Task<int> SetAsync(UserAccess access, bool stepUpFresh, Guid tenantId, IReadOnlyCollection<Guid> objectIds, bool include,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(objectIds);
        if (objectIds.Count == 0) return 0;
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        await CustomerOfAsync(session, access, tenantId, Permissions.PoliciesManage, cancellationToken).ConfigureAwait(false);
        if (!include && !stepUpFresh) throw new StepUpRequiredException();
        var now = clock.GetUtcNow();
        var ids = objectIds.Distinct().ToArray();
        var changed = (await session.Connection.QueryAsync<Guid>(new CommandDefinition(include
            ? """
              UPDATE vaulty.protected_objects SET state = 'active', next_run_at = coalesce(next_run_at, @now)
               WHERE tenant_id = @tenantId AND id = ANY(@ids) AND state IN ('excluded', 'paused')
              RETURNING id
              """
            : """
              UPDATE vaulty.protected_objects SET state = 'excluded', next_run_at = NULL
               WHERE tenant_id = @tenantId AND id = ANY(@ids) AND state IN ('active', 'paused')
              RETURNING id
              """, new { tenantId, ids, now }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        if (changed.Count == 0) return 0;
        if (!include)
        {
            // A missed run of an object that is no longer selected is no longer a problem.
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.alerts SET resolved_at = @now WHERE protected_object_id = ANY(@changed) AND kind = @kind AND resolved_at IS NULL",
                new { now, changed = changed.ToArray(), kind = NotificationKinds.BackupMissed }, session.Transaction, cancellationToken: cancellationToken))
                .ConfigureAwait(false);
        }
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", include ? "backup.objects_selected" : "backup.objects_excluded", $"tenant:{tenantId}",
            new { count = changed.Count, objects = changed }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return changed.Count;
    }

    /// <summary>Whether newly found mailboxes and drives are backed up at once (true) or wait to be selected (false).</summary>
    public async Task SetProtectNewObjectsAsync(UserAccess access, bool stepUpFresh, Guid tenantId, bool protectNew, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        await CustomerOfAsync(session, access, tenantId, Permissions.PoliciesManage, cancellationToken).ConfigureAwait(false);
        if (!protectNew && !stepUpFresh) throw new StepUpRequiredException();
        var changed = await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.tenants SET protect_new_objects = @protectNew WHERE id = @tenantId AND protect_new_objects <> @protectNew",
            new { tenantId, protectNew }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (changed == 0) return;
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "backup.new_objects_policy_changed", $"tenant:{tenantId}", new { protect_new_objects = protectNew },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task CustomerOfAsync(OrganizationSession session, UserAccess access, Guid tenantId, string permission, CancellationToken cancellationToken)
    {
        var customer = await session.Connection.ExecuteScalarAsync<Guid?>(new CommandDefinition(
            "SELECT customer_id FROM vaulty.tenants WHERE id = @tenantId AND state <> 'deleted'", new { tenantId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (customer is null || !access.Allows(permission, customer.Value)) throw new AccessException("You cannot change which objects of this tenant are backed up.");
    }
}
