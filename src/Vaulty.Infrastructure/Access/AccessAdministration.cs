using Dapper;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Access;

public sealed record RoleDetail(Guid Id, string Name, string? Description, bool BuiltIn, IReadOnlyList<string> Permissions, int Holders);

/// <param name="Kind">"include" or "exclude".</param>
public sealed record GroupRule(string Kind, Guid? CustomerId, Guid? TenantId, string? Tag)
{
    public bool Include => Kind == "include";
}

public sealed record GroupRow(Guid Id, string Name, string? Description, bool AllCustomers, bool IsDefault, int Version, IReadOnlyList<GroupRule> Rules,
    IReadOnlyList<Guid> Members);

public sealed record GroupDraft(string Name, string? Description, bool AllCustomers, IReadOnlyList<GroupRule> Rules);

public sealed record MembershipRow(Guid GroupId, Guid UserId, bool FromMapping);

/// <summary>Something a group rule can point at: a customer, a tenant of a customer, or a customer tag.</summary>
/// <param name="Kind">"customer", "tenant" or "tag".</param>
public sealed record ScopeTarget(string Kind, Guid? Id, string? Tag, Guid? CustomerId, string Label);

public sealed record AccessHolder(Guid UserId, string UserName, string? DisplayName, IReadOnlyList<string> Roles, bool WholeCustomer);

public sealed record MappingRow(Guid Id, Guid EntraGroupId, string? DisplayName, IReadOnlyList<Guid> RoleIds, IReadOnlyList<Guid> GroupIds);

/// <summary>What a user may do and see, in words for the access view.</summary>
public sealed record AccessSummary(IReadOnlyList<string> Permissions, bool AllCustomers, IReadOnlyList<string> WholeCustomers,
    IReadOnlyList<(string Customer, IReadOnlyList<string> Tenants)> PartialCustomers);

/// <summary>
/// Custom roles, groups, group membership and Entra group mappings, with the rules that keep them safe: no escalation,
/// built-in roles fixed, the last Organization admin kept, a second factor before a role needs one, and every change
/// audited and taken into effect at once.
/// </summary>
public sealed class AccessAdministration(NpgsqlDataSource dataSource, AccessService access)
{
    public const int MaxRules = 1000;

    // ---- roles ----------------------------------------------------------------------------------------------------------

    public async Task<IReadOnlyList<RoleDetail>> RolesAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var roles = await session.Connection.QueryAsync<(Guid Id, string Name, string? Description, bool BuiltIn, int Holders)>(new CommandDefinition(
            """
            SELECT r.id, r.name, r.description, r.built_in, (SELECT count(DISTINCT a.user_id)::int FROM vaulty.role_assignments a WHERE a.role_id = r.id)
              FROM vaulty.roles r ORDER BY r.built_in DESC, lower(r.name)
            """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var permissions = (await session.Connection.QueryAsync<(Guid RoleId, string Permission)>(new CommandDefinition(
            "SELECT role_id, permission FROM vaulty.role_permissions", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToLookup(p => p.RoleId, p => p.Permission);
        return roles.Select(r => new RoleDetail(r.Id, r.Name, r.Description, r.BuiltIn,
            permissions[r.Id].Where(Permissions.Exists).Order(StringComparer.Ordinal).ToList(), r.Holders)).ToList();
    }

    /// <summary>Every permission known and every permission it requires present; the catalog stays the only list.</summary>
    public static IReadOnlyList<string> ValidPermissions(IEnumerable<string> keys)
    {
        var set = keys.Distinct(StringComparer.Ordinal).ToList();
        var unknown = set.Where(k => !Permissions.Exists(k)).ToList();
        if (unknown.Count > 0) throw new AccessException($"Unknown permission: {string.Join(", ", unknown)}.");
        var missing = Permissions.Closure(set).Except(set, StringComparer.Ordinal).ToList();
        if (missing.Count > 0)
        {
            throw new AccessException("Also choose what these permissions need: " + string.Join(", ", missing.Select(m => Permissions.Get(m).Label)) + ".");
        }
        if (set.Count == 0) throw new AccessException("Choose at least one permission.");
        return set.Order(StringComparer.Ordinal).ToList();
    }

    private static string CleanName(string? name)
    {
        var value = (name ?? "").Trim();
        if (value.Length is < 1 or > 100) throw new AccessException("Enter a name of at most 100 characters.");
        return value;
    }

    public async Task<Guid> CreateRoleAsync(UserAccess actor, string name, string? description, IEnumerable<string> permissions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        Require(actor, Permissions.RolesManage, "You cannot change roles.");
        var clean = CleanName(name);
        if (BuiltInRoles.All.Keys.Any(k => string.Equals(k, clean, StringComparison.OrdinalIgnoreCase)))
        {
            throw new AccessException($"{clean} is the name of a built-in role. Choose another name.");
        }
        var keys = ValidPermissions(permissions);
        AccessAuthority.RequireMayGrant(actor, keys, clean);
        var id = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        await UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.roles (id, organization_id, name, description, built_in) VALUES (@id, vaulty.current_organization_id(), @clean, @description, false)",
            new { id, clean, description = Description(description) }, session.Transaction, cancellationToken: cancellationToken)), $"A role named {clean} exists already.")
            .ConfigureAwait(false);
        await InsertPermissionsAsync(session, id, keys, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "role.created", $"role:{id}", new { name = clean, permissions = keys }, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    /// <summary>
    /// Changes a custom role. Every permission added or removed must be one the actor holds; every holder must be a user the
    /// actor may manage, and must have a second factor before the role needs one. Holders get the change at once.
    /// </summary>
    public async Task UpdateRoleAsync(UserAccess actor, Guid roleId, string name, string? description, IEnumerable<string> permissions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        Require(actor, Permissions.RolesManage, "You cannot change roles.");
        var clean = CleanName(name);
        var keys = ValidPermissions(permissions);
        List<Guid> holders;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false))
        {
            await AccessService.LockAsync(session, cancellationToken).ConfigureAwait(false);
            var role = await session.Connection.QuerySingleOrDefaultAsync<(string Name, bool BuiltIn)?>(new CommandDefinition(
                "SELECT name, built_in FROM vaulty.roles WHERE id = @roleId", new { roleId }, session.Transaction, cancellationToken: cancellationToken))
                .ConfigureAwait(false) ?? throw new AccessException("The role does not exist.");
            if (role.BuiltIn) throw new AccessException($"{role.Name} is built in and cannot be changed. Copy it into a role of your own.");
            if (BuiltInRoles.All.Keys.Any(k => string.Equals(k, clean, StringComparison.OrdinalIgnoreCase)))
            {
                throw new AccessException($"{clean} is the name of a built-in role. Choose another name.");
            }
            var (_, current) = await AccessService.RoleAsync(session, roleId, cancellationToken).ConfigureAwait(false);
            var added = keys.Except(current, StringComparer.Ordinal).ToList();
            var removed = current.Except(keys, StringComparer.Ordinal).ToList();
            AccessAuthority.RequireMayGrant(actor, added.Concat(removed), clean);
            holders = (await session.Connection.QueryAsync<Guid>(new CommandDefinition(
                "SELECT DISTINCT user_id FROM vaulty.role_assignments WHERE role_id = @roleId", new { roleId }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            var withoutMfa = new List<string>();
            foreach (var holder in holders)
            {
                var target = await AccessService.LoadAsync(session, holder, cancellationToken).ConfigureAwait(false);
                AccessAuthority.RequireMayManage(actor, target);
                if (Permissions.AnyRequiresMfa(added) && !target.HasMfa) withoutMfa.Add(await UserNameAsync(session, holder, cancellationToken).ConfigureAwait(false));
                if (added.Any(p => Permissions.Get(p).OrganizationWide) && !target.Scope.All)
                {
                    throw new AccessException($"{await UserNameAsync(session, holder, cancellationToken).ConfigureAwait(false)} holds this role without every customer in scope, so the role cannot administer the organization.");
                }
            }
            if (withoutMfa.Count > 0)
            {
                throw new AccessException("These users hold the role and have no passkey or authenticator app yet: " + string.Join(", ", withoutMfa.Take(5)) +
                                          (withoutMfa.Count > 5 ? $" and {withoutMfa.Count - 5} more" : "") + ".");
            }
            await UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.roles SET name = @clean, description = @description WHERE id = @roleId", new { clean, description = Description(description), roleId },
                session.Transaction, cancellationToken: cancellationToken)), $"A role named {clean} exists already.").ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.role_permissions WHERE role_id = @roleId AND permission = ANY(@removed)",
                new { roleId, removed = removed.ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await InsertPermissionsAsync(session, roleId, added, cancellationToken).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "role.updated", $"role:{roleId}",
                new { name = clean, previous_name = role.Name, added, removed }, cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        await access.AfterChangeAsync(actor.OrganizationId, holders, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteRoleAsync(UserAccess actor, Guid roleId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        Require(actor, Permissions.RolesManage, "You cannot change roles.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        var role = await session.Connection.QuerySingleOrDefaultAsync<(string Name, bool BuiltIn, int Holders)?>(new CommandDefinition(
            "SELECT name, built_in, (SELECT count(*)::int FROM vaulty.role_assignments a WHERE a.role_id = r.id) FROM vaulty.roles r WHERE id = @roleId",
            new { roleId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false) ?? throw new AccessException("The role does not exist.");
        if (role.BuiltIn) throw new AccessException($"{role.Name} is built in and cannot be deleted.");
        if (role.Holders > 0) throw new AccessException($"{role.Name} is held by {role.Holders} user(s). Take it away from them first.");
        await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.roles WHERE id = @roleId", new { roleId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "role.deleted", $"role:{roleId}", new { name = role.Name }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static Task InsertPermissionsAsync(OrganizationSession session, Guid roleId, IEnumerable<string> keys, CancellationToken cancellationToken) =>
        session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.role_permissions (organization_id, role_id, permission) VALUES (vaulty.current_organization_id(), @roleId, @permission)",
            keys.Select(k => new { roleId, permission = k }), session.Transaction, cancellationToken: cancellationToken));

    // ---- groups ---------------------------------------------------------------------------------------------------------

    public async Task<IReadOnlyList<GroupRow>> GroupsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await GroupsAsync(session, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<GroupRow>> GroupsAsync(OrganizationSession session, CancellationToken cancellationToken)
    {
        var groups = await session.Connection.QueryAsync<(Guid Id, string Name, string? Description, bool All, bool Default, int Version)>(new CommandDefinition(
            "SELECT id, name, description, all_customers, is_default, version FROM vaulty.user_groups ORDER BY is_default DESC, lower(name)",
            transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var rules = (await session.Connection.QueryAsync<(Guid GroupId, string Kind, Guid? CustomerId, Guid? TenantId, string? Tag)>(new CommandDefinition(
            "SELECT group_id, kind, customer_id, tenant_id, tag FROM vaulty.user_group_rules", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToLookup(r => r.GroupId);
        var members = (await session.Connection.QueryAsync<(Guid GroupId, Guid UserId)>(new CommandDefinition(
            "SELECT group_id, user_id FROM vaulty.user_group_members", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToLookup(m => m.GroupId, m => m.UserId);
        return groups.Select(g => new GroupRow(g.Id, g.Name, g.Description, g.All, g.Default, g.Version,
            rules[g.Id].Select(r => new GroupRule(r.Kind, r.CustomerId, r.TenantId, r.Tag)).ToList(), members[g.Id].ToList())).ToList();
    }

    public async Task<IReadOnlyList<MembershipRow>> MembershipsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return (await session.Connection.QueryAsync<MembershipRow>(new CommandDefinition(
            "SELECT group_id, user_id, mapping_id IS NOT NULL AS from_mapping FROM vaulty.user_group_members", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
    }

    /// <summary>The customers, tenants and tags a rule can point at, with a label each.</summary>
    public async Task<IReadOnlyList<ScopeTarget>> TargetsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var customers = (await session.Connection.QueryAsync<(Guid Id, string Code, string Name, string[] Tags)>(new CommandDefinition(
            "SELECT id, code, name, tags FROM vaulty.customers WHERE deleted_at IS NULL ORDER BY lower(name)", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var tenants = await session.Connection.QueryAsync<(Guid Id, Guid CustomerId, string? Name)>(new CommandDefinition(
            "SELECT id, customer_id, display_name FROM vaulty.tenants ORDER BY lower(display_name)", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        var names = customers.ToDictionary(c => c.Id, c => c.Name);
        return customers.Select(c => new ScopeTarget("customer", c.Id, null, c.Id, $"{c.Name} ({c.Code})"))
            .Concat(tenants.Where(t => names.ContainsKey(t.CustomerId)).Select(t => new ScopeTarget("tenant", t.Id, null, t.CustomerId, $"{names[t.CustomerId]} / {t.Name ?? t.Id.ToString()}")))
            .Concat(customers.SelectMany(c => c.Tags).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase)
                .Select(t => new ScopeTarget("tag", null, t, null, $"Tag: {t}")))
            .ToList();
    }

    /// <summary>
    /// Creates or changes a group. The actor must see everything the group includes (excludes only narrow it), and may
    /// manage every member; afterwards every member who administers the organization must still see every customer, and
    /// an Organization admin must remain. With an expected version a concurrent change is refused.
    /// </summary>
    public async Task<Guid> SaveGroupAsync(UserAccess actor, Guid? groupId, GroupDraft draft, int? expectedVersion = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(draft);
        Require(actor, Permissions.GroupsManage, "You cannot change groups.");
        var name = CleanName(draft.Name);
        var rules = draft.Rules.Distinct().ToList();
        if (rules.Count > MaxRules) throw new AccessException($"A group has at most {MaxRules} rules.");
        if (rules.Any(r => r.Kind is not ("include" or "exclude") || new object?[] { r.CustomerId, r.TenantId, r.Tag }.Count(v => v is not null) != 1))
        {
            throw new AccessException("Each rule includes or excludes one customer, one tenant or one tag.");
        }
        if (!draft.AllCustomers && !rules.Any(r => r.Include)) throw new AccessException("Include at least one customer, tenant or tag, or choose every customer.");
        var id = groupId ?? Guid.CreateVersion7();
        List<Guid> members;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false))
        {
            await AccessService.LockAsync(session, cancellationToken).ConfigureAwait(false);
            await RequireCoversAsync(session, actor, draft.AllCustomers, rules, cancellationToken).ConfigureAwait(false);
            var adminsBefore = await AccessService.AdminCountAsync(session, cancellationToken).ConfigureAwait(false);
            GroupRow? previous = null;
            if (groupId is not null)
            {
                previous = (await GroupsAsync(session, cancellationToken).ConfigureAwait(false)).FirstOrDefault(g => g.Id == id)
                           ?? throw new AccessException("The group does not exist.");
                await RequireCoversAsync(session, actor, previous.AllCustomers, previous.Rules, cancellationToken).ConfigureAwait(false);
                var updated = await UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE vaulty.user_groups SET name = @name, description = @description, all_customers = @all, version = version + 1, updated_at = now()
                     WHERE id = @id AND (@expected IS NULL OR version = @expected)
                    """, new { id, name, description = Description(draft.Description), all = draft.AllCustomers, expected = expectedVersion }, session.Transaction,
                    cancellationToken: cancellationToken)), $"A group named {name} exists already.").ConfigureAwait(false);
                if (updated == 0) throw new AccessException("Someone else changed this group in the meantime. Open it again to see the change.");
                await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.user_group_rules WHERE group_id = @id", new { id }, session.Transaction,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
            else
            {
                await UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
                    """
                    INSERT INTO vaulty.user_groups (id, organization_id, name, description, all_customers)
                    VALUES (@id, vaulty.current_organization_id(), @name, @description, @all)
                    """, new { id, name, description = Description(draft.Description), all = draft.AllCustomers }, session.Transaction,
                    cancellationToken: cancellationToken)), $"A group named {name} exists already.").ConfigureAwait(false);
            }
            try
            {
                await session.Connection.ExecuteAsync(new CommandDefinition(
                    """
                    INSERT INTO vaulty.user_group_rules (id, organization_id, group_id, kind, customer_id, tenant_id, tag)
                    VALUES (gen_random_uuid(), vaulty.current_organization_id(), @id, @Kind, @CustomerId, @TenantId, @Tag)
                    """, rules.Select(r => new { id, r.Kind, r.CustomerId, r.TenantId, Tag = r.Tag?.Trim() }), session.Transaction,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.ForeignKeyViolation)
            {
                throw new AccessException("A customer or tenant of a rule no longer exists. Open the group again.");
            }
            members = (previous?.Members ?? []).ToList();
            foreach (var member in members)
            {
                var target = await AccessService.LoadAsync(session, member, cancellationToken).ConfigureAwait(false);
                AccessAuthority.RequireMayManage(actor, target);
                await RequireAdministratorsKeepEverythingAsync(session, target, cancellationToken).ConfigureAwait(false);
            }
            await RequireAdminRemainsAsync(session, adminsBefore, cancellationToken).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, $"user:{actor.UserId}", groupId is null ? "user_group.created" : "user_group.updated", $"user_group:{id}", new
            {
                name, all_customers = draft.AllCustomers,
                rules = rules.Select(r => new { r.Kind, customer = r.CustomerId, tenant = r.TenantId, tag = r.Tag }),
                previous_rules = previous?.Rules.Count,
            }, cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        await access.AfterChangeAsync(actor.OrganizationId, members, cancellationToken).ConfigureAwait(false);
        return id;
    }

    public async Task DeleteGroupAsync(UserAccess actor, Guid groupId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        Require(actor, Permissions.GroupsManage, "You cannot change groups.");
        List<Guid> members;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false))
        {
            await AccessService.LockAsync(session, cancellationToken).ConfigureAwait(false);
            var group = (await GroupsAsync(session, cancellationToken).ConfigureAwait(false)).FirstOrDefault(g => g.Id == groupId)
                        ?? throw new AccessException("The group does not exist.");
            if (group.IsDefault) throw new AccessException($"{group.Name} is the group new users join and cannot be deleted.");
            await RequireCoversAsync(session, actor, group.AllCustomers, group.Rules, cancellationToken).ConfigureAwait(false);
            var adminsBefore = await AccessService.AdminCountAsync(session, cancellationToken).ConfigureAwait(false);
            members = group.Members.ToList();
            await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.user_groups WHERE id = @groupId", new { groupId }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            foreach (var member in members)
            {
                var target = await AccessService.LoadAsync(session, member, cancellationToken).ConfigureAwait(false);
                AccessAuthority.RequireMayManage(actor, target);
                await RequireAdministratorsKeepEverythingAsync(session, target, cancellationToken).ConfigureAwait(false);
            }
            await RequireAdminRemainsAsync(session, adminsBefore, cancellationToken).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "user_group.deleted", $"user_group:{groupId}", new { name = group.Name, members = members.Count },
                cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        await access.AfterChangeAsync(actor.OrganizationId, members, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sets the groups of a user (memberships from an Entra group mapping stay). The actor may manage the user and must see
    /// what each group added or removed includes.
    /// </summary>
    public async Task SetGroupsOfAsync(UserAccess actor, Guid userId, IReadOnlyCollection<Guid> groupIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(groupIds);
        Require(actor, Permissions.GroupsManage, "You cannot change groups.");
        await using (var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false))
        {
            await AccessService.LockAsync(session, cancellationToken).ConfigureAwait(false);
            AccessAuthority.RequireMayManage(actor, await AccessService.LoadAsync(session, userId, cancellationToken).ConfigureAwait(false));
            var groups = (await GroupsAsync(session, cancellationToken).ConfigureAwait(false)).ToDictionary(g => g.Id);
            if (groupIds.Any(g => !groups.ContainsKey(g))) throw new AccessException("A group no longer exists. Open the user again.");
            var manual = (await session.Connection.QueryAsync<Guid>(new CommandDefinition(
                "SELECT group_id FROM vaulty.user_group_members WHERE user_id = @userId AND mapping_id IS NULL", new { userId }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false)).ToHashSet();
            var added = groupIds.Except(manual).ToList();
            var removed = manual.Except(groupIds).ToList();
            foreach (var changed in added.Concat(removed))
            {
                await RequireCoversAsync(session, actor, groups[changed].AllCustomers, groups[changed].Rules, cancellationToken).ConfigureAwait(false);
            }
            var adminsBefore = await AccessService.AdminCountAsync(session, cancellationToken).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "DELETE FROM vaulty.user_group_members WHERE user_id = @userId AND mapping_id IS NULL AND group_id = ANY(@removed)",
                new { userId, removed = removed.ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO vaulty.user_group_members (organization_id, group_id, user_id) VALUES (vaulty.current_organization_id(), @groupId, @userId)
                ON CONFLICT (group_id, user_id) DO UPDATE SET mapping_id = NULL
                """, added.Select(g => new { groupId = g, userId }), session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await RequireAdministratorsKeepEverythingAsync(session, await AccessService.LoadAsync(session, userId, cancellationToken).ConfigureAwait(false),
                cancellationToken).ConfigureAwait(false);
            await RequireAdminRemainsAsync(session, adminsBefore, cancellationToken).ConfigureAwait(false);
            if (added.Count + removed.Count > 0)
            {
                await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "user.groups_changed", $"user:{userId}",
                    new { added = added.Select(g => groups[g].Name), removed = removed.Select(g => groups[g].Name) }, cancellationToken).ConfigureAwait(false);
            }
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        await access.AfterChangeAsync(actor.OrganizationId, [userId], cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The actor sees everything a group includes; excludes only narrow and need nothing.</summary>
    private static async Task RequireCoversAsync(OrganizationSession session, UserAccess actor, bool allCustomers, IEnumerable<GroupRule> rules,
        CancellationToken cancellationToken)
    {
        if (actor.Scope.All) return;
        const string wider = "This group includes customers you do not see, so you cannot change it.";
        if (allCustomers) throw new AccessException(wider);
        foreach (var rule in rules.Where(r => r.Include))
        {
            if (rule.Tag is not null) throw new AccessException("Only a user who sees every customer can include customers by tag.");
            if (rule.CustomerId is { } customer && !actor.Scope.HasWholeCustomer(customer)) throw new AccessException(wider);
            if (rule.TenantId is { } tenant)
            {
                var owner = await session.Connection.ExecuteScalarAsync<Guid?>(new CommandDefinition("SELECT customer_id FROM vaulty.tenants WHERE id = @tenant",
                    new { tenant }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
                if (owner is not { } c || !actor.Scope.SeesTenant(c, tenant)) throw new AccessException(wider);
            }
        }
    }

    /// <summary>Organization-wide permissions count only with every customer; a change must not leave an administrator without it.</summary>
    private static async Task RequireAdministratorsKeepEverythingAsync(OrganizationSession session, UserAccess target, CancellationToken cancellationToken)
    {
        if (target.Scope.All || !target.Permissions.Any(p => Permissions.Get(p).OrganizationWide)) return;
        throw new AccessException($"{await UserNameAsync(session, target.UserId, cancellationToken).ConfigureAwait(false)} administers the organization and must keep every customer in scope. Take the administration role away first.");
    }

    private static async Task RequireAdminRemainsAsync(OrganizationSession session, int before, CancellationToken cancellationToken)
    {
        if (before > 0 && await AccessService.AdminCountAsync(session, cancellationToken).ConfigureAwait(false) == 0)
        {
            throw new AccessException("No Organization admin with every customer would remain. Keep at least one.");
        }
    }

    // ---- who has access, what a user may do ---------------------------------------------------------------------------------

    /// <summary>The users who see (part of) a customer, with their roles.</summary>
    public async Task<IReadOnlyList<AccessHolder>> HoldersAsync(UserAccess actor, Guid customerId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        Require(actor, Permissions.AccessView, "You cannot view access.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, string UserName, string? DisplayName, string[] Roles, bool Whole)>(new CommandDefinition(
            """
            SELECT u.id, u.user_name, u.display_name,
                   coalesce((SELECT array_agg(DISTINCT r.name ORDER BY r.name) FROM vaulty.role_assignments a JOIN vaulty.roles r ON r.id = a.role_id WHERE a.user_id = u.id), '{}'),
                   vaulty.user_sees_everything(u.id) OR EXISTS (SELECT 1 FROM vaulty.user_scope(u.id) s WHERE s.customer_id = @customerId AND s.whole)
              FROM vaulty.users u
             WHERE u.disabled_at IS NULL AND vaulty.user_sees_customer(u.id, @customerId)
             ORDER BY lower(u.user_name)
            """, new { customerId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new AccessHolder(r.Id, r.UserName, r.DisplayName, r.Roles, r.Whole)).ToList();
    }

    public async Task<AccessSummary> SummaryAsync(UserAccess actor, Guid userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (actor.UserId != userId) Require(actor, Permissions.AccessView, "You cannot view access.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        var target = await AccessService.LoadAsync(session, userId, cancellationToken).ConfigureAwait(false);
        var customers = (await session.Connection.QueryAsync<(Guid Id, string Name)>(new CommandDefinition("SELECT id, name FROM vaulty.customers", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToDictionary(c => c.Id, c => c.Name);
        var tenants = (await session.Connection.QueryAsync<(Guid Id, string? Name)>(new CommandDefinition("SELECT id, display_name FROM vaulty.tenants",
            transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToDictionary(t => t.Id, t => t.Name ?? t.Id.ToString());
        var effective = target.Permissions.Where(p => target.Allows(p)).Select(p => Permissions.Get(p).Label).Order(StringComparer.Ordinal).ToList();
        return new AccessSummary(effective, target.Scope.All,
            target.Scope.WholeCustomers.Select(c => customers.GetValueOrDefault(c, c.ToString())).Order(StringComparer.OrdinalIgnoreCase).ToList(),
            target.Scope.PartialCustomers.Select(p => (customers.GetValueOrDefault(p.Key, p.Key.ToString()),
                (IReadOnlyList<string>)p.Value.Select(t => tenants.GetValueOrDefault(t, t.ToString())).Order(StringComparer.OrdinalIgnoreCase).ToList())).ToList());
    }

    // ---- Entra group mappings -----------------------------------------------------------------------------------------------

    public async Task<IReadOnlyList<MappingRow>> MappingsAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await MappingsAsync(session, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<IReadOnlyList<MappingRow>> MappingsAsync(OrganizationSession session, CancellationToken cancellationToken)
    {
        var mappings = await session.Connection.QueryAsync<(Guid Id, Guid EntraGroupId, string? Name)>(new CommandDefinition(
            "SELECT id, entra_group_id, display_name FROM vaulty.entra_group_mappings ORDER BY lower(coalesce(display_name, entra_group_id::text))",
            transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var roles = (await session.Connection.QueryAsync<(Guid MappingId, Guid RoleId)>(new CommandDefinition(
            "SELECT mapping_id, role_id FROM vaulty.entra_group_mapping_roles", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToLookup(r => r.MappingId, r => r.RoleId);
        var groups = (await session.Connection.QueryAsync<(Guid MappingId, Guid GroupId)>(new CommandDefinition(
            "SELECT mapping_id, group_id FROM vaulty.entra_group_mapping_groups", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToLookup(r => r.MappingId, r => r.GroupId);
        return mappings.Select(m => new MappingRow(m.Id, m.EntraGroupId, m.Name, roles[m.Id].ToList(), groups[m.Id].ToList())).ToList();
    }

    /// <summary>
    /// Creates or changes a mapping from an Entra security group to roles and groups. The actor must be able to give each
    /// role and see what each group includes, as if giving them by hand. Takes effect at each user's next Microsoft sign-in.
    /// </summary>
    public async Task<Guid> SaveMappingAsync(UserAccess actor, Guid? mappingId, Guid entraGroupId, string? displayName, IReadOnlyCollection<Guid> roleIds,
        IReadOnlyCollection<Guid> groupIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        Require(actor, Permissions.SignInManage, "You cannot change sign-in.");
        if (entraGroupId == Guid.Empty) throw new AccessException("Enter the object ID of the Entra group.");
        if (roleIds.Count + groupIds.Count == 0) throw new AccessException("Choose at least one role or group.");
        var id = mappingId ?? Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        foreach (var roleId in roleIds)
        {
            var (roleName, permissions) = await AccessService.RoleAsync(session, roleId, cancellationToken).ConfigureAwait(false);
            AccessAuthority.RequireMayGrant(actor, permissions, roleName);
        }
        var groups = (await GroupsAsync(session, cancellationToken).ConfigureAwait(false)).ToDictionary(g => g.Id);
        foreach (var groupId in groupIds)
        {
            if (!groups.TryGetValue(groupId, out var group)) throw new AccessException("A group no longer exists.");
            await RequireCoversAsync(session, actor, group.AllCustomers, group.Rules, cancellationToken).ConfigureAwait(false);
        }
        var name = string.IsNullOrWhiteSpace(displayName) ? null : displayName.Trim()[..Math.Min(displayName.Trim().Length, 256)];
        await UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.entra_group_mappings (id, organization_id, entra_group_id, display_name) VALUES (@id, vaulty.current_organization_id(), @entraGroupId, @name)
            ON CONFLICT (id) DO UPDATE SET entra_group_id = excluded.entra_group_id, display_name = excluded.display_name
            """, new { id, entraGroupId, name }, session.Transaction, cancellationToken: cancellationToken)), "This Entra group has a mapping already.").ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.entra_group_mapping_roles WHERE mapping_id = @id", new { id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.entra_group_mapping_groups WHERE mapping_id = @id", new { id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.entra_group_mapping_roles (organization_id, mapping_id, role_id) VALUES (vaulty.current_organization_id(), @id, @roleId)",
            roleIds.Select(r => new { id, roleId = r }), session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.entra_group_mapping_groups (organization_id, mapping_id, group_id) VALUES (vaulty.current_organization_id(), @id, @groupId)",
            groupIds.Select(g => new { id, groupId = g }), session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "group_mapping.changed", $"group_mapping:{id}",
            new { entra_group_id = entraGroupId, name, roles = roleIds, groups = groupIds }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    /// <summary>Deletes a mapping; the roles and memberships it gave go with it (cascade), and those users get the change at once.</summary>
    public async Task DeleteMappingAsync(UserAccess actor, Guid mappingId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        Require(actor, Permissions.SignInManage, "You cannot change sign-in.");
        List<Guid> affected;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false))
        {
            await AccessService.LockAsync(session, cancellationToken).ConfigureAwait(false);
            var adminsBefore = await AccessService.AdminCountAsync(session, cancellationToken).ConfigureAwait(false);
            affected = (await session.Connection.QueryAsync<Guid>(new CommandDefinition(
                """
                SELECT user_id FROM vaulty.role_assignments WHERE mapping_id = @mappingId
                UNION SELECT user_id FROM vaulty.user_group_members WHERE mapping_id = @mappingId
                """, new { mappingId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.entra_group_mappings WHERE id = @mappingId", new { mappingId },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await RequireAdminRemainsAsync(session, adminsBefore, cancellationToken).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "group_mapping.deleted", $"group_mapping:{mappingId}", new { users = affected.Count },
                cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        await access.AfterChangeAsync(actor.OrganizationId, affected, cancellationToken).ConfigureAwait(false);
    }

    // ---- helpers --------------------------------------------------------------------------------------------------------------

    private static void Require(UserAccess actor, string permission, string message)
    {
        if (!actor.Allows(permission)) throw new AccessException(message);
    }

    private static string? Description(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim()[..Math.Min(value.Trim().Length, 500)];

    private static async Task<string> UserNameAsync(OrganizationSession session, Guid userId, CancellationToken cancellationToken) =>
        await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition("SELECT coalesce(display_name, user_name) FROM vaulty.users WHERE id = @userId",
            new { userId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false) ?? userId.ToString();

    private static async Task<int> UniqueAsync(Func<Task<int>> write, string message)
    {
        try
        {
            return await write().ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            throw new AccessException(message);
        }
    }
}
