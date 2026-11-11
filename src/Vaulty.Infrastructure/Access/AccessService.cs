using Dapper;
using Npgsql;
using Vaulty.Core.Domain;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Access;

/// <summary>
/// What one user may do and where: the permissions of the user's roles, and the customers and tenants of the user's
/// groups. A role never gives access to a customer and a group never gives a permission.
/// </summary>
public sealed class UserAccess
{
    private readonly IReadOnlySet<string> _permissions;

    public UserAccess(Guid userId, Guid organizationId, bool hasMfa, IReadOnlySet<string> permissions, AccessScope scope)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        ArgumentNullException.ThrowIfNull(scope);
        UserId = userId;
        OrganizationId = organizationId;
        HasMfa = hasMfa;
        _permissions = permissions;
        Scope = scope;
    }

    /// <summary>
    /// Access for system tasks and tests: per permission, every customer (null) or a set of whole customers. One scope
    /// covers all permissions, so it is never wider than any limit given: every customer only when nothing is limited,
    /// otherwise the union of the limited sets.
    /// </summary>
    public UserAccess(Guid userId, Guid organizationId, bool hasMfa, Dictionary<string, HashSet<Guid>?> grants)
        : this(userId, organizationId, hasMfa, (grants ?? throw new ArgumentNullException(nameof(grants))).Keys.ToHashSet(StringComparer.Ordinal),
            grants.Values.All(v => v is null) ? AccessScope.Everything : AccessScope.Of(grants.Values.Where(v => v is not null).SelectMany(v => v!), []))
    {
    }

    public Guid UserId { get; }
    public Guid OrganizationId { get; }
    public bool HasMfa { get; }
    public AccessScope Scope { get; }

    public IReadOnlyCollection<string> Permissions => (IReadOnlyCollection<string>)_permissions;

    /// <summary>The role holds the permission (whether or not it is effective here).</summary>
    public bool Holds(string permission) => _permissions.Contains(permission);

    /// <summary>
    /// True when the user holds the permission for this customer (or, with no customer, for at least one). A permission
    /// that requires MFA is never effective without a second factor; organization-wide permissions count only with every
    /// customer in scope; permissions on a customer as a whole need the whole customer.
    /// </summary>
    public bool Allows(string permission, Guid? customerId = null)
    {
        if (!_permissions.Contains(permission)) return false;
        var info = Core.Security.Permissions.Get(permission);
        if (info.RequiresMfa && !HasMfa) return false;
        if (info.OrganizationWide) return Scope.All;
        if (customerId is not { } customer) return !Scope.IsEmpty;
        return Core.Security.Permissions.WholeCustomer.Contains(permission) ? Scope.HasWholeCustomer(customer) : Scope.SeesCustomer(customer);
    }

    /// <summary>The permission for one tenant of a customer.</summary>
    public bool AllowsTenant(string permission, Guid customerId, Guid tenantId) => Allows(permission, customerId) && Scope.SeesTenant(customerId, tenantId);

    /// <summary>The customers the permission is effective for; null means every customer.</summary>
    public IReadOnlySet<Guid>? Customers(string permission)
    {
        if (!Allows(permission)) return new HashSet<Guid>();
        if (Scope.All) return null;
        return Core.Security.Permissions.WholeCustomer.Contains(permission) ? Scope.WholeCustomers : Scope.Customers;
    }

    public static UserAccess None(Guid userId, Guid organizationId) => new(userId, organizationId, false, new HashSet<string>(), AccessScope.Nothing);
}

public sealed class AccessException(string message) : InvalidOperationException(message);

/// <summary>Pauses a running restore or export (the web registers the Temporal implementation).</summary>
public interface IRestorePauser
{
    Task PauseAsync(Guid restoreId, CancellationToken cancellationToken = default);
}

/// <summary>Effective permissions and scope, role assignments, and what a change of access does to running work.</summary>
public sealed class AccessService(NpgsqlDataSource dataSource, IRestorePauser? pauser = null)
{
    public NpgsqlDataSource DataSource => dataSource;

    public async Task<UserAccess> GetAccessAsync(Guid organizationId, Guid userId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await LoadAsync(session, userId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The access of a user, read in an organization session without a user scope.</summary>
    public static async Task<UserAccess> LoadAsync(OrganizationSession session, Guid userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var hasMfa = await HasMfaAsync(session, userId, cancellationToken).ConfigureAwait(false);
        var permissions = (await session.Connection.QueryAsync<string>(new CommandDefinition(
            """
            SELECT DISTINCT p.permission
              FROM vaulty.role_assignments a JOIN vaulty.role_permissions p ON p.role_id = a.role_id
              JOIN vaulty.users u ON u.id = a.user_id AND u.disabled_at IS NULL
             WHERE a.user_id = @userId
            """, new { userId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
            .Where(Permissions.Exists).ToHashSet(StringComparer.Ordinal);
        return new UserAccess(userId, session.OrganizationId, hasMfa, permissions, await ScopeAsync(session, userId, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>The customers and tenants a user's groups give (vaulty.user_scope).</summary>
    public static async Task<AccessScope> ScopeAsync(OrganizationSession session, Guid userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition("SELECT vaulty.user_sees_everything(@userId)", new { userId },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
        {
            return AccessScope.Everything;
        }
        var rows = (await session.Connection.QueryAsync<(Guid CustomerId, Guid? TenantId, bool Whole)>(new CommandDefinition(
            "SELECT customer_id, tenant_id, whole FROM vaulty.user_scope(@userId)", new { userId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        return AccessScope.Of(rows.Where(r => r.Whole).Select(r => r.CustomerId),
            rows.Where(r => !r.Whole && r.TenantId is not null).Select(r => (r.CustomerId, r.TenantId!.Value)));
    }

    /// <summary>
    /// A second factor: an authenticator app (TOTP), at least one passkey, or a link to a Microsoft account while the
    /// organization leaves the second factor to its tenant (a linked user signs in with Microsoft only).
    /// </summary>
    public static async Task<bool> HasMfaAsync(OrganizationSession session, Guid userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        return await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            $"SELECT {Identity.MicrosoftSignInService.SecondFactorSql}", new { userId }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }

    // ---- role assignments ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Gives a user a role. Refused when the actor does not hold every permission of the role or may not manage the user,
    /// when the role needs a second factor the user lacks, or when the role holds organization-wide permissions and the
    /// user's groups do not cover every customer. Audited; the user's sessions pick it up at once.
    /// </summary>
    public async Task AssignRoleAsync(UserAccess actor, Guid userId, Guid roleId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        RequireAllowed(actor, Permissions.RolesManage);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        await LockAsync(session, cancellationToken).ConfigureAwait(false);
        var (roleName, permissions) = await RoleAsync(session, roleId, cancellationToken).ConfigureAwait(false);
        AccessAuthority.RequireMayGrant(actor, permissions, roleName);
        var target = await LoadAsync(session, userId, cancellationToken).ConfigureAwait(false);
        AccessAuthority.RequireMayManage(actor, target);
        await AssignAsync(session, $"user:{actor.UserId}", target, roleId, roleName, permissions, null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        await AfterChangeAsync(actor.OrganizationId, [userId], cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The first administrator receives Organization admin from setup itself.</summary>
    public async Task AssignRoleAsSystemAsync(Guid organizationId, string actor, Guid userId, Guid roleId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var (roleName, permissions) = await RoleAsync(session, roleId, cancellationToken).ConfigureAwait(false);
        var target = await LoadAsync(session, userId, cancellationToken).ConfigureAwait(false);
        await AssignAsync(session, actor, target, roleId, roleName, permissions, null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<bool> AssignAsync(OrganizationSession session, string actor, UserAccess target, Guid roleId, string roleName,
        IReadOnlyCollection<string> permissions, Guid? mappingId, CancellationToken cancellationToken)
    {
        if (Permissions.AnyRequiresMfa(permissions) && !target.HasMfa)
        {
            throw new AccessException(
                $"The role {roleName} allows restores, exports or administration. The user needs a passkey or an authenticator app first.");
        }
        if (permissions.Any(p => Permissions.Get(p).OrganizationWide) && !target.Scope.All)
        {
            throw new AccessException($"The role {roleName} administers the whole organization. Add the user to a group with every customer first.");
        }
        var added = await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id, customer_id, mapping_id)
            VALUES (@id, vaulty.current_organization_id(), @userId, @roleId, NULL, @mappingId) ON CONFLICT DO NOTHING
            """, new { id = Guid.CreateVersion7(), userId = target.UserId, roleId, mappingId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (added > 0)
        {
            await AuditLog.WriteAsync(session, actor, "role.assigned", $"user:{target.UserId}", new { role = roleName, mapping = mappingId }, cancellationToken)
                .ConfigureAwait(false);
        }
        return added > 0;
    }

    /// <summary>Takes a role away. The last Organization admin keeps the role.</summary>
    public async Task RemoveRoleAsync(UserAccess actor, Guid userId, Guid roleId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        RequireAllowed(actor, Permissions.RolesManage);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        await LockAsync(session, cancellationToken).ConfigureAwait(false);
        var (roleName, permissions) = await RoleAsync(session, roleId, cancellationToken).ConfigureAwait(false);
        AccessAuthority.RequireMayGrant(actor, permissions, roleName);
        AccessAuthority.RequireMayManage(actor, await LoadAsync(session, userId, cancellationToken).ConfigureAwait(false));
        if (await IsAdminRoleAsync(session, roleId, cancellationToken).ConfigureAwait(false) &&
            await AdminCountAsync(session, cancellationToken).ConfigureAwait(false) <= 1 && await IsAdminAsync(session, userId, cancellationToken).ConfigureAwait(false))
        {
            throw new AccessException("This is the last Organization admin. Make another user Organization admin first.");
        }
        var removed = await session.Connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM vaulty.role_assignments WHERE user_id = @userId AND role_id = @roleId AND mapping_id IS NULL",
            new { userId, roleId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (removed == 0 && await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
                "SELECT EXISTS (SELECT 1 FROM vaulty.role_assignments WHERE user_id = @userId AND role_id = @roleId AND mapping_id IS NOT NULL)",
                new { userId, roleId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
        {
            throw new AccessException($"The role {roleName} comes from a Microsoft Entra group. Remove the user from that group, or change the mapping.");
        }
        if (removed > 0)
        {
            await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "role.removed", $"user:{userId}", new { role = roleName }, cancellationToken)
                .ConfigureAwait(false);
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        await AfterChangeAsync(actor.OrganizationId, [userId], cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<(string Name, IReadOnlyList<string> Permissions)> RoleAsync(OrganizationSession session, Guid roleId, CancellationToken cancellationToken)
    {
        var name = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT name FROM vaulty.roles WHERE id = @roleId", new { roleId }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false) ?? throw new AccessException("The role does not exist.");
        var permissions = (await session.Connection.QueryAsync<string>(new CommandDefinition(
            "SELECT permission FROM vaulty.role_permissions WHERE role_id = @roleId", new { roleId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).Where(Permissions.Exists).ToList();
        return (name, permissions);
    }

    // ---- the last administrator -----------------------------------------------------------------------------------------

    /// <summary>Changes that could remove the last administrator run one at a time per organization.</summary>
    internal static Task LockAsync(OrganizationSession session, CancellationToken cancellationToken) =>
        session.Connection.ExecuteAsync(new CommandDefinition("SELECT pg_advisory_xact_lock(hashtext('access:' || vaulty.current_organization_id()::text))",
            transaction: session.Transaction, cancellationToken: cancellationToken));

    internal static Task<bool> IsAdminRoleAsync(OrganizationSession session, Guid roleId, CancellationToken cancellationToken) =>
        session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT EXISTS (SELECT 1 FROM vaulty.roles WHERE id = @roleId AND built_in AND name = @name)", new { roleId, name = BuiltInRoles.OrganizationAdmin },
            session.Transaction, cancellationToken: cancellationToken));

    internal static Task<bool> IsAdminAsync(OrganizationSession session, Guid userId, CancellationToken cancellationToken) =>
        session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            """
            SELECT EXISTS (SELECT 1 FROM vaulty.role_assignments a JOIN vaulty.roles r ON r.id = a.role_id
                            WHERE a.user_id = @userId AND r.built_in AND r.name = @name)
            """, new { userId, name = BuiltInRoles.OrganizationAdmin }, session.Transaction, cancellationToken: cancellationToken));

    /// <summary>Enabled users holding the built-in Organization admin role with every customer in scope.</summary>
    internal static Task<int> AdminCountAsync(OrganizationSession session, CancellationToken cancellationToken) =>
        session.Connection.ExecuteScalarAsync<int>(new CommandDefinition(
            """
            SELECT count(DISTINCT u.id)::int FROM vaulty.users u
              JOIN vaulty.role_assignments a ON a.user_id = u.id JOIN vaulty.roles r ON r.id = a.role_id
             WHERE u.disabled_at IS NULL AND r.built_in AND r.name = @name AND vaulty.user_sees_everything(u.id)
            """, new { name = BuiltInRoles.OrganizationAdmin }, session.Transaction, cancellationToken: cancellationToken));

    // ---- what a change of access does ---------------------------------------------------------------------------------------

    /// <summary>
    /// After a change of roles or groups: the sessions of the affected users pick up their new access at the next request
    /// (security stamp), and a restore or export one of them started is paused when the user may no longer run it. Someone
    /// who may run it resumes or cancels it.
    /// </summary>
    public async Task AfterChangeAsync(Guid organizationId, IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken = default)
    {
        if (userIds.Count == 0) return;
        List<Guid> toPause = [];
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.users SET security_stamp = replace(gen_random_uuid()::text, '-', '') WHERE id = ANY(@ids)", new { ids = userIds.ToArray() },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            var running = await session.Connection.QueryAsync<(Guid Id, Guid UserId, string Kind, string TargetMode, Guid CustomerId, Guid TenantId)>(new CommandDefinition(
                """
                SELECT r.id, r.requested_by, r.kind, r.target_mode, t.customer_id, t.id FROM vaulty.restores r JOIN vaulty.tenants t ON t.id = r.tenant_id
                 WHERE r.requested_by = ANY(@ids) AND r.state IN ('planning', 'running')
                """, new { ids = userIds.ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            foreach (var group in running.GroupBy(r => r.UserId))
            {
                var access = await LoadAsync(session, group.Key, cancellationToken).ConfigureAwait(false);
                foreach (var restore in group)
                {
                    if (access.AllowsTenant(RestorePermission(restore.Kind, restore.TargetMode), restore.CustomerId, restore.TenantId)) continue;
                    toPause.Add(restore.Id);
                    await AuditLog.WriteAsync(session, "system:access", "restore.paused", $"restore:{restore.Id}",
                        new { reason = "access_lost", user = group.Key }, cancellationToken).ConfigureAwait(false);
                }
            }
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        if (pauser is null) return;
        foreach (var id in toPause) await pauser.PauseAsync(id, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The permission a restore or export needs to run.</summary>
    public static string RestorePermission(string kind, string targetMode) => kind == "export" ? Permissions.ExportCreate
        : targetMode == "other" ? Permissions.RestoreOtherLocation
        : Permissions.RestoreInPlace;

    private static void RequireAllowed(UserAccess actor, string permission)
    {
        if (!actor.Allows(permission)) throw new AccessException("You cannot change roles.");
    }

    /// <summary>Writes one audit event in its own transaction.</summary>
    public async Task RecordAsync(Guid organizationId, string actor, string action, string? target, object? details = null,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, actor, action, target, details, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates the built-in roles of an organization and its default group "All customers".</summary>
    public static async Task<IReadOnlyDictionary<string, Guid>> CreateBuiltInRolesAsync(OrganizationSession session,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var ids = new Dictionary<string, Guid>(StringComparer.Ordinal);
        foreach (var (name, permissions) in BuiltInRoles.All)
        {
            var id = Guid.CreateVersion7();
            ids[name] = id;
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO vaulty.roles (id, organization_id, name, built_in) VALUES (@id, @org, @name, true)",
                new { id, org = session.OrganizationId, name }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO vaulty.role_permissions (organization_id, role_id, permission) VALUES (@org, @id, @permission)",
                permissions.Select(p => new { org = session.OrganizationId, id, permission = p }), session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.user_groups (id, organization_id, name, description, all_customers, is_default)
            VALUES (@id, @org, 'All customers', 'Every customer of the organization. New users join this group.', true, true)
            """, new { id = Guid.CreateVersion7(), org = session.OrganizationId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return ids;
    }
}

/// <summary>
/// No escalation: nobody gives a role with permissions they do not hold, and nobody changes a user who holds permissions
/// or sees customers the actor does not.
/// </summary>
public static class AccessAuthority
{
    /// <summary>The actor holds the permission and can use it (organization-wide ones need every customer).</summary>
    public static bool Has(UserAccess actor, string permission)
    {
        ArgumentNullException.ThrowIfNull(actor);
        return actor.Holds(permission) && (!Permissions.Get(permission).OrganizationWide || actor.Scope.All);
    }

    public static void RequireMayGrant(UserAccess actor, IEnumerable<string> permissions, string roleName)
    {
        var missing = permissions.Where(p => !Has(actor, p)).ToList();
        if (missing.Count > 0)
        {
            throw new AccessException($"The role {roleName} allows more than you may yourself ({string.Join(", ", missing.Select(m => Permissions.Get(m).Label))}).");
        }
    }

    public static void RequireMayManage(UserAccess actor, UserAccess target)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(target);
        if (actor.UserId == target.UserId) return;
        if (target.Permissions.Any(p => !Has(actor, p)))
        {
            throw new AccessException("This user may do things you may not, so you cannot change the user's access.");
        }
        if (!actor.Scope.Covers(target.Scope))
        {
            throw new AccessException("This user sees customers you do not, so you cannot change the user's access.");
        }
    }
}
