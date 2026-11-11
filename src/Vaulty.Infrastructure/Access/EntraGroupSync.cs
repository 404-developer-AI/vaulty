using Dapper;
using Microsoft.Extensions.Logging;
using Npgsql;
using Vaulty.Graph;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Identity;

namespace Vaulty.Infrastructure.Access;

/// <summary>
/// At every Microsoft sign-in, the roles and groups a person gets from Entra group mappings follow the person's Entra
/// groups at that moment: read through Graph (GroupMember.Read.All), not from the groups claim, which Entra leaves out
/// above 200 groups. When the groups cannot be read, the mapped access is taken away rather than kept (fail closed);
/// roles and groups given by hand are never touched.
/// </summary>
public sealed class EntraGroupSync(NpgsqlDataSource dataSource, MicrosoftSignInService signIn, AppRegistrationClient registrations, ILogger<EntraGroupSync> logger)
{
    /// <summary>The Entra groups of the account that have a mapping; empty when there are no mappings or they cannot be read.</summary>
    public async Task<IReadOnlySet<Guid>> MappedGroupsOfAsync(Guid organizationId, Guid objectId, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<MappingRow> mappings;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            mappings = await AccessAdministration.MappingsAsync(session, cancellationToken).ConfigureAwait(false);
        }
        if (mappings.Count == 0) return new HashSet<Guid>();
        try
        {
            var token = await signIn.AppTokenAsync(organizationId, cancellationToken).ConfigureAwait(false);
            var groups = await registrations.MemberGroupsAsync(token, objectId, cancellationToken).ConfigureAwait(false);
            return mappings.Select(m => m.EntraGroupId).Where(groups.Contains).ToHashSet();
        }
        catch (Exception ex) when (ex is GraphException or IdentityException or HttpRequestException or SignInSetupException)
        {
            logger.LogWarning("Entra groups of a signing-in account could not be read: {Error}", ex.GetType().Name);
            return new HashSet<Guid>();
        }
    }

    /// <summary>Brings the mapped roles and groups of a user in line with the Entra groups given. Returns whether anything changed.</summary>
    public async Task<bool> ApplyAsync(Guid organizationId, Guid userId, IReadOnlySet<Guid> entraGroups, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await AccessService.LockAsync(session, cancellationToken).ConfigureAwait(false);
        var mappings = await AccessAdministration.MappingsAsync(session, cancellationToken).ConfigureAwait(false);
        var applying = mappings.Where(m => entraGroups.Contains(m.EntraGroupId)).ToList();
        var wantedGroups = applying.SelectMany(m => m.GroupIds.Select(g => (Mapping: m.Id, Group: g))).DistinctBy(x => x.Group).ToList();
        var wantedRoles = applying.SelectMany(m => m.RoleIds.Select(r => (Mapping: m.Id, Role: r))).DistinctBy(x => x.Role).ToList();

        // Groups first: a role that administers the organization needs every customer in scope.
        var removedGroups = await session.Connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM vaulty.user_group_members WHERE user_id = @userId AND mapping_id IS NOT NULL AND NOT (group_id = ANY(@keep))",
            new { userId, keep = wantedGroups.Select(g => g.Group).ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var addedGroups = 0;
        foreach (var (mapping, group) in wantedGroups)
        {
            addedGroups += await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO vaulty.user_group_members (organization_id, group_id, user_id, mapping_id) VALUES (vaulty.current_organization_id(), @group, @userId, @mapping)
                ON CONFLICT (group_id, user_id) DO NOTHING
                """, new { group, userId, mapping }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        var removedRoles = await session.Connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM vaulty.role_assignments WHERE user_id = @userId AND mapping_id IS NOT NULL AND NOT (role_id = ANY(@keep))",
            new { userId, keep = wantedRoles.Select(r => r.Role).ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var target = await AccessService.LoadAsync(session, userId, cancellationToken).ConfigureAwait(false);
        var addedRoles = 0;
        foreach (var (mapping, role) in wantedRoles)
        {
            var (name, permissions) = await AccessService.RoleAsync(session, role, cancellationToken).ConfigureAwait(false);
            try
            {
                if (await AccessService.AssignAsync(session, $"group_mapping:{mapping}", target, role, name, permissions, mapping, cancellationToken).ConfigureAwait(false))
                {
                    addedRoles++;
                }
            }
            catch (AccessException ex)
            {
                // A mapped role the user cannot hold (no second factor, not every customer): skipped, and said so.
                await AuditLog.WriteAsync(session, $"group_mapping:{mapping}", "group_mapping.role_skipped", $"user:{userId}", new { role = name, reason = ex.Message },
                    cancellationToken).ConfigureAwait(false);
            }
        }
        var changed = removedGroups + addedGroups + removedRoles + addedRoles > 0;
        if (changed)
        {
            await AuditLog.WriteAsync(session, "system:group_mapping", "group_mapping.applied", $"user:{userId}",
                new { groups_added = addedGroups, groups_removed = removedGroups, roles_added = addedRoles, roles_removed = removedRoles }, cancellationToken)
                .ConfigureAwait(false);
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return changed;
    }

    /// <summary>A user created at the first sign-in starts in the mapped groups only, not in the default group.</summary>
    public async Task LeaveDefaultGroupAsync(Guid organizationId, Guid userId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM vaulty.user_group_members m USING vaulty.user_groups g
             WHERE m.group_id = g.id AND g.is_default AND m.user_id = @userId AND m.mapping_id IS NULL
            """, new { userId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }
}
