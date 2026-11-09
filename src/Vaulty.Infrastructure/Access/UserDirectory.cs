using Dapper;
using Npgsql;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Access;

public sealed record UserRow(Guid Id, string UserName, string? DisplayName, bool HasMfa, DateTimeOffset? DisabledAt);

public sealed record RoleRow(Guid Id, string Name, bool BuiltIn, IReadOnlyList<string> Permissions);

public sealed record AssignmentRow(Guid UserId, Guid RoleId, string RoleName, Guid? CustomerId, string? CustomerName);

public sealed record AuditRow(long Seq, DateTimeOffset OccurredAt, string Actor, string Action, string? Target, string Details);

/// <summary>Read models for the users, roles and audit log pages (organization-scoped through RLS).</summary>
public sealed class UserDirectory(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<UserRow>> UsersAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, string UserName, string? DisplayName, bool HasMfa, DateTime? DisabledAt)>(
            new CommandDefinition(
                """
                SELECT u.id, u.user_name, u.display_name,
                       (u.two_factor_enabled AND u.authenticator_key IS NOT NULL) OR EXISTS (SELECT 1 FROM vaulty.user_passkeys p WHERE p.user_id = u.id),
                       u.disabled_at
                  FROM vaulty.users u ORDER BY lower(u.user_name)
                """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new UserRow(r.Id, r.UserName, r.DisplayName, r.HasMfa,
            r.DisabledAt is { } d ? new DateTimeOffset(DateTime.SpecifyKind(d, DateTimeKind.Utc)) : null)).ToList();
    }

    public async Task<IReadOnlyList<RoleRow>> RolesAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var roles = await session.Connection.QueryAsync<(Guid Id, string Name, bool BuiltIn)>(new CommandDefinition(
            "SELECT id, name, built_in FROM vaulty.roles ORDER BY built_in DESC, name", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        var permissions = (await session.Connection.QueryAsync<(Guid RoleId, string Permission)>(new CommandDefinition(
            "SELECT role_id, permission FROM vaulty.role_permissions", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToLookup(p => p.RoleId, p => p.Permission);
        return roles.Select(r => new RoleRow(r.Id, r.Name, r.BuiltIn, permissions[r.Id].Order(StringComparer.Ordinal).ToList())).ToList();
    }

    public async Task<IReadOnlyList<AssignmentRow>> AssignmentsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<AssignmentRow>(new CommandDefinition(
            """
            SELECT a.user_id, a.role_id, r.name AS role_name, a.customer_id, c.name AS customer_name
              FROM vaulty.role_assignments a JOIN vaulty.roles r ON r.id = a.role_id
              LEFT JOIN vaulty.customers c ON c.id = a.customer_id
             ORDER BY r.name
            """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.ToList();
    }

    public async Task<IReadOnlyList<AuditRow>> AuditAsync(Guid organizationId, int limit, long? beforeSeq = null,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(long Seq, DateTime OccurredAt, string Actor, string Action, string? Target, string Details)>(
            new CommandDefinition(
                """
                SELECT seq, occurred_at, actor, action, target, details::text FROM vaulty.audit_events
                 WHERE (@beforeSeq IS NULL OR seq < @beforeSeq) ORDER BY seq DESC LIMIT @limit
                """, new { limit, beforeSeq }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new AuditRow(r.Seq, new DateTimeOffset(DateTime.SpecifyKind(r.OccurredAt, DateTimeKind.Utc)), r.Actor, r.Action,
            r.Target, r.Details)).ToList();
    }
}
