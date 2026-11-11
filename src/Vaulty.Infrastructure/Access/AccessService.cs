using Dapper;
using Npgsql;
using Vaulty.Core.Domain;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Access;

/// <summary>What one user may do: per permission, every customer or a set of customers.</summary>
public sealed class UserAccess
{
    private readonly Dictionary<string, HashSet<Guid>?> _grants;

    public UserAccess(Guid userId, Guid organizationId, bool hasMfa, Dictionary<string, HashSet<Guid>?> grants)
    {
        UserId = userId;
        OrganizationId = organizationId;
        HasMfa = hasMfa;
        _grants = grants;
    }

    public Guid UserId { get; }
    public Guid OrganizationId { get; }
    public bool HasMfa { get; }

    public IReadOnlyCollection<string> Permissions => _grants.Keys;

    /// <summary>
    /// True when the user holds the permission for this customer (or, with no customer, for at least one customer). A
    /// permission that requires MFA is never effective for a user without a second factor, whatever the role says.
    /// Organization-wide permissions count only when granted for every customer.
    /// </summary>
    public bool Allows(string permission, Guid? customerId = null)
    {
        if (!_grants.TryGetValue(permission, out var customers)) return false;
        var info = Core.Security.Permissions.Get(permission);
        if (info.RequiresMfa && !HasMfa) return false;
        if (info.OrganizationWide) return customers is null;
        return customers is null || customerId is null ? customers is null || customers.Count > 0 : customers.Contains(customerId.Value);
    }

    /// <summary>The customers the permission is limited to; null means every customer.</summary>
    public IReadOnlySet<Guid>? Customers(string permission) =>
        _grants.TryGetValue(permission, out var customers) ? customers : new HashSet<Guid>();

    public static UserAccess None(Guid userId, Guid organizationId) => new(userId, organizationId, false, []);
}

public sealed class AccessException(string message) : InvalidOperationException(message);

/// <summary>Roles, role assignments and effective permissions.</summary>
public sealed class AccessService(NpgsqlDataSource dataSource)
{
    public async Task<UserAccess> GetAccessAsync(Guid organizationId, Guid userId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var hasMfa = await HasMfaAsync(session, userId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(string Permission, Guid? CustomerId)>(new CommandDefinition(
            """
            SELECT p.permission, a.customer_id
              FROM vaulty.role_assignments a JOIN vaulty.role_permissions p ON p.role_id = a.role_id
              JOIN vaulty.users u ON u.id = a.user_id AND u.disabled_at IS NULL
             WHERE a.user_id = @userId
            """, new { userId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var grants = new Dictionary<string, HashSet<Guid>?>(StringComparer.Ordinal);
        foreach (var (permission, customer) in rows)
        {
            if (!Permissions.Exists(permission)) continue;
            if (customer is null) grants[permission] = null;
            else if (!grants.TryGetValue(permission, out var set)) grants[permission] = [customer.Value];
            else set?.Add(customer.Value);
        }
        return new UserAccess(userId, organizationId, hasMfa, grants);
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

    /// <summary>
    /// Gives a user a role, for every customer or one. Refused when the role holds a permission that requires MFA and the
    /// user has no second factor. Audited.
    /// </summary>
    public async Task AssignRoleAsync(Guid organizationId, Guid actorUserId, Guid userId, Guid roleId, Guid? customerId,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var permissions = (await session.Connection.QueryAsync<string>(new CommandDefinition(
            "SELECT permission FROM vaulty.role_permissions WHERE role_id = @roleId", new { roleId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).Where(Permissions.Exists).ToList();
        var roleName = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT name FROM vaulty.roles WHERE id = @roleId", new { roleId }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false) ?? throw new AccessException("The role does not exist.");
        if (Permissions.AnyRequiresMfa(permissions) && !await HasMfaAsync(session, userId, cancellationToken).ConfigureAwait(false))
        {
            throw new AccessException(
                $"The role {roleName} allows restores, exports or administration. The user needs a passkey or an authenticator app first.");
        }
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id, customer_id)
            VALUES (@id, @organizationId, @userId, @roleId, @customerId) ON CONFLICT DO NOTHING
            """, new { id = Guid.CreateVersion7(), organizationId, userId, roleId, customerId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actorUserId}", "role.assigned", $"user:{userId}",
            new { role = roleName, customer = customerId }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RemoveRoleAsync(Guid organizationId, Guid actorUserId, Guid userId, Guid roleId, Guid? customerId,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var removed = await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM vaulty.role_assignments WHERE user_id = @userId AND role_id = @roleId
               AND customer_id IS NOT DISTINCT FROM @customerId
            """, new { userId, roleId, customerId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (removed > 0)
        {
            await AuditLog.WriteAsync(session, $"user:{actorUserId}", "role.removed", $"user:{userId}", new { role = roleId, customer = customerId },
                cancellationToken).ConfigureAwait(false);
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Writes one audit event in its own transaction.</summary>
    public async Task RecordAsync(Guid organizationId, string actor, string action, string? target, object? details = null,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, actor, action, target, details, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates the built-in roles of an organization.</summary>
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
        return ids;
    }
}
