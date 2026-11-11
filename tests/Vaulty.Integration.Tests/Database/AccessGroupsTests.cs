using Dapper;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Integration.Tests.Database;

/// <summary>Records which restores a change of access paused.</summary>
internal sealed class RecordingPauser : IRestorePauser
{
    public List<Guid> Paused { get; } = [];

    public Task PauseAsync(Guid restoreId, CancellationToken cancellationToken = default)
    {
        lock (Paused) Paused.Add(restoreId);
        return Task.CompletedTask;
    }
}

public sealed class AccessGroupsTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private sealed record World(Guid Org, Guid CustomerA, Guid TenantA1, Guid TenantA2, Guid CustomerB, Guid TenantB1, NpgsqlDataSource Api,
        AccessService Access, AccessAdministration Admin, RecordingPauser Pauser);

    private async Task<World> WorldAsync()
    {
        var api = VaultyDataSource.Create(db.Api);
        var pauser = new RecordingPauser();
        var access = new AccessService(api, pauser);
        var org = await new OrganizationSetup(api, access).CreateOrganizationAsync("Org " + Guid.NewGuid(), Guid.NewGuid());
        var (a, a1, a2, b, b1) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync("INSERT INTO vaulty.customers (id, organization_id, code, name, tags) VALUES (@a, @org, @ca, 'Alpha', '{}'), (@b, @org, @cb, 'Beta', '{}')",
            new { a, b, org, ca = "A" + a.ToString("N")[..6], cb = "B" + b.ToString("N")[..6] });
        foreach (var (tenant, customer) in new[] { (a1, a), (a2, a), (b1, b) })
        {
            await owner.ExecuteAsync("INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name) VALUES (@tenant, @org, @customer, @entra, @name)",
                new { tenant, org, customer, entra = Guid.NewGuid(), name = "Tenant " + tenant.ToString("N")[..4] });
            await owner.ExecuteAsync("INSERT INTO vaulty.alerts (id, organization_id, tenant_id, kind, severity, message) VALUES (@id, @org, @tenant, 'backup.failed', 'warning', 'x')",
                new { id = Guid.NewGuid(), org, tenant });
        }
        return new World(org, a, a1, a2, b, b1, api, access, new AccessAdministration(api, access), pauser);
    }

    private async Task<Guid> UserAsync(World world, bool mfa = true, params string[] roles)
    {
        var id = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.users (id, organization_id, user_name, normalized_user_name, security_stamp, concurrency_stamp, two_factor_enabled, authenticator_key)
            VALUES (@id, @org, @name, upper(@name), 's', 'c', @mfa, CASE WHEN @mfa THEN 'KEY' END)
            """, new { id, org = world.Org, name = $"u-{id:N}@contoso.example", mfa });
        foreach (var role in roles)
        {
            await owner.ExecuteAsync(
                """
                INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id)
                SELECT gen_random_uuid(), @org, @id, r.id FROM vaulty.roles r WHERE r.organization_id = @org AND r.name = @role
                """, new { org = world.Org, id, role });
        }
        return id;
    }

    /// <summary>Puts a user in exactly these groups (as the owner, without the checks under test).</summary>
    private async Task InGroupsAsync(World world, Guid user, params Guid[] groups)
    {
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync("DELETE FROM vaulty.user_group_members WHERE user_id = @user", new { user });
        foreach (var group in groups)
        {
            await owner.ExecuteAsync("INSERT INTO vaulty.user_group_members (organization_id, group_id, user_id) VALUES (@org, @group, @user)",
                new { org = world.Org, group, user });
        }
    }

    private static UserAccess Full(World world) =>
        new(Guid.NewGuid(), world.Org, true, Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));

    private static async Task<Guid> GroupAsync(World world, string name, bool all, params GroupRule[] rules) =>
        await world.Admin.SaveGroupAsync(Full(world), null, new GroupDraft(name + " " + Guid.NewGuid().ToString("N")[..6], null, all, rules));

    private async Task<(List<Guid> Customers, List<Guid> Tenants, List<Guid> AlertTenants)> SeenAsync(World world, Guid user)
    {
        var access = await world.Access.GetAccessAsync(world.Org, user);
        await using var session = await OrganizationSession.BeginAsync(world.Api, access);
        var customers = (await session.Connection.QueryAsync<Guid>("SELECT id FROM vaulty.customers", transaction: session.Transaction)).ToList();
        var tenants = (await session.Connection.QueryAsync<Guid>("SELECT id FROM vaulty.tenants", transaction: session.Transaction)).ToList();
        var alerts = (await session.Connection.QueryAsync<Guid>("SELECT tenant_id FROM vaulty.alerts", transaction: session.Transaction)).ToList();
        return (customers, tenants, alerts);
    }

    [PostgresFact]
    public async Task A_user_in_a_group_of_customer_A_reads_no_row_of_customer_B_through_row_level_security()
    {
        var world = await WorldAsync();
        var user = await UserAsync(world, roles: BuiltInRoles.ReadOnly);
        await InGroupsAsync(world, user, await GroupAsync(world, "Alpha", false, new GroupRule("include", world.CustomerA, null, null)));

        var (customers, tenants, alerts) = await SeenAsync(world, user);
        Assert.Equal([world.CustomerA], customers);
        Assert.Equal(new[] { world.TenantA1, world.TenantA2 }.Order(), tenants.Order());
        Assert.DoesNotContain(world.TenantB1, alerts);
        Assert.Equal(2, alerts.Count);

        // Writing a row of customer B is refused by the policy as well.
        var access = await world.Access.GetAccessAsync(world.Org, user);
        await using var session = await OrganizationSession.BeginAsync(world.Api, access);
        var error = await Assert.ThrowsAsync<PostgresException>(() => session.Connection.ExecuteAsync(
            "INSERT INTO vaulty.alerts (id, organization_id, tenant_id, kind, severity, message) VALUES (gen_random_uuid(), @org, @tenant, 'x', 'info', 'x')",
            new { org = world.Org, tenant = world.TenantB1 }, session.Transaction));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [PostgresFact]
    public async Task Every_table_of_a_customer_or_tenant_carries_the_user_scope_policy()
    {
        await using var owner = new NpgsqlConnection(db.Migrator);
        var missing = (await owner.QueryAsync<string>(
            """
            SELECT DISTINCT c.table_name FROM information_schema.columns c
              JOIN pg_class k ON k.relname = c.table_name AND k.relnamespace = 'vaulty'::regnamespace AND k.relkind IN ('r', 'p') AND NOT k.relispartition
             WHERE c.table_schema = 'vaulty' AND c.column_name IN ('tenant_id', 'customer_id')
               AND c.table_name NOT IN ('role_assignments', 'user_group_rules')
               AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'vaulty' AND p.tablename = c.table_name AND p.policyname = 'user_scope'
                                                        AND p.permissive = 'RESTRICTIVE')
            """)).ToList();
        Assert.Empty(missing);
    }

    [PostgresFact]
    public async Task A_tag_rule_follows_the_tag_of_customers_added_later()
    {
        var world = await WorldAsync();
        var user = await UserAsync(world, roles: BuiltInRoles.ReadOnly);
        var tag = "gold" + Guid.NewGuid().ToString("N")[..4];
        await InGroupsAsync(world, user, await GroupAsync(world, "Gold", false, new GroupRule("include", null, null, tag)));
        Assert.Empty((await SeenAsync(world, user)).Customers);

        var gold = Guid.NewGuid();
        await using (var owner = new NpgsqlConnection(db.Migrator))
        {
            await owner.ExecuteAsync("INSERT INTO vaulty.customers (id, organization_id, code, name, tags) VALUES (@gold, @org, @code, 'Gold', @tags), (gen_random_uuid(), @org, @other, 'Plain', '{}')",
                new { gold, org = world.Org, code = "G" + gold.ToString("N")[..6], other = "P" + gold.ToString("N")[..6], tags = new[] { tag } });
        }
        Assert.Equal([gold], (await SeenAsync(world, user)).Customers);
        Assert.True((await world.Access.GetAccessAsync(world.Org, user)).Scope.HasWholeCustomer(gold));
    }

    [PostgresFact]
    public async Task An_exclude_of_one_tenant_hides_that_tenant_and_leaves_the_customer_partly_visible()
    {
        var world = await WorldAsync();
        var user = await UserAsync(world, roles: BuiltInRoles.BackupOperator);
        await InGroupsAsync(world, user, await GroupAsync(world, "All but A2", true, new GroupRule("exclude", null, world.TenantA2, null)));

        var access = await world.Access.GetAccessAsync(world.Org, user);
        Assert.False(access.Scope.All);
        Assert.True(access.Scope.HasWholeCustomer(world.CustomerB));
        Assert.False(access.Scope.HasWholeCustomer(world.CustomerA));
        Assert.True(access.AllowsTenant(Permissions.CustomersView, world.CustomerA, world.TenantA1));
        Assert.False(access.AllowsTenant(Permissions.CustomersView, world.CustomerA, world.TenantA2));
        // Acting on customer A as a whole needs all of it.
        Assert.False(access.Allows(Permissions.CustomersManage, world.CustomerA));
        Assert.True(access.Allows(Permissions.CustomersManage, world.CustomerB));
        var (customers, tenants, alerts) = await SeenAsync(world, user);
        Assert.Equal(2, customers.Count);
        Assert.DoesNotContain(world.TenantA2, tenants);
        Assert.DoesNotContain(world.TenantA2, alerts);
        // Without any group a user sees nothing.
        await InGroupsAsync(world, user);
        Assert.True((await world.Access.GetAccessAsync(world.Org, user)).Scope.IsEmpty);
        Assert.Empty((await SeenAsync(world, user)).Customers);
    }

    [PostgresFact]
    public async Task Nobody_gives_or_changes_more_than_they_hold_or_see()
    {
        var world = await WorldAsync();
        var alphaGroup = await GroupAsync(world, "Alpha", false, new GroupRule("include", world.CustomerA, null, null));
        // A manager of roles and groups for customer A only, without restore permissions.
        var role = await world.Admin.CreateRoleAsync(Full(world), "Manager " + Guid.NewGuid().ToString("N")[..6], null,
            [Permissions.RolesManage, Permissions.GroupsManage, Permissions.CustomersView, Permissions.UsersManage]);
        var managerId = await UserAsync(world);
        await world.Access.AssignRoleAsSystemAsync(world.Org, "test", managerId, role);
        await InGroupsAsync(world, managerId, alphaGroup);
        var manager = await world.Access.GetAccessAsync(world.Org, managerId);
        var restoreOperator = (await world.Admin.RolesAsync(world.Org)).Single(r => r.Name == BuiltInRoles.RestoreOperator);
        var target = await UserAsync(world);
        await InGroupsAsync(world, target, alphaGroup);

        // Roles and groups are organization-wide administration: they count only with every customer.
        Assert.False(manager.Allows(Permissions.RolesManage));
        await Assert.ThrowsAsync<AccessException>(() => world.Access.AssignRoleAsync(manager, target, restoreOperator.Id));

        // With every customer, but still without restore permissions: a role with them cannot be given.
        await InGroupsAsync(world, managerId, (await world.Admin.GroupsAsync(world.Org)).Single(g => g.IsDefault).Id);
        manager = await world.Access.GetAccessAsync(world.Org, managerId);
        var error = await Assert.ThrowsAsync<AccessException>(() => world.Access.AssignRoleAsync(manager, target, restoreOperator.Id));
        Assert.Contains("allows more than you may yourself", error.Message, StringComparison.Ordinal);
        // An Organization admin cannot be changed by someone who holds less.
        var admin = await UserAsync(world, roles: BuiltInRoles.OrganizationAdmin);
        var viewer = await world.Admin.CreateRoleAsync(Full(world), "Viewer " + Guid.NewGuid().ToString("N")[..6], null, [Permissions.CustomersView]);
        error = await Assert.ThrowsAsync<AccessException>(() => world.Access.AssignRoleAsync(manager, admin, viewer));
        Assert.Contains("may do things you may not", error.Message, StringComparison.Ordinal);

        // A group wider than one's own scope cannot be made by a user who sees only customer A.
        var narrow = new UserAccess(managerId, world.Org, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.GroupsManage] = [world.CustomerA] });
        await Assert.ThrowsAsync<AccessException>(() => world.Admin.SaveGroupAsync(narrow, null,
            new GroupDraft("Beta " + Guid.NewGuid().ToString("N")[..6], null, false, [new GroupRule("include", world.CustomerB, null, null)])));
    }

    [PostgresFact]
    public async Task Two_concurrent_removals_of_the_last_two_administrators_leave_exactly_one()
    {
        var world = await WorldAsync();
        var first = await UserAsync(world, roles: BuiltInRoles.OrganizationAdmin);
        var second = await UserAsync(world, roles: BuiltInRoles.OrganizationAdmin);
        var adminRole = (await world.Admin.RolesAsync(world.Org)).Single(r => r.Name == BuiltInRoles.OrganizationAdmin).Id;
        var actor = Full(world);
        var results = await Task.WhenAll(
            Task.Run(async () => { try { await world.Access.RemoveRoleAsync(actor, first, adminRole); return true; } catch (AccessException) { return false; } }),
            Task.Run(async () => { try { await world.Access.RemoveRoleAsync(actor, second, adminRole); return true; } catch (AccessException) { return false; } }));
        Assert.Single(results, r => r);
        await using var owner = new NpgsqlConnection(db.Migrator);
        Assert.Equal(1, await owner.ExecuteScalarAsync<int>(
            "SELECT count(*)::int FROM vaulty.role_assignments WHERE role_id = @adminRole AND user_id = ANY(@ids)", new { adminRole, ids = new[] { first, second } }));
    }

    [PostgresFact]
    public async Task A_permission_that_needs_a_second_factor_is_not_added_to_a_role_held_by_a_user_without_one()
    {
        var world = await WorldAsync();
        var role = await world.Admin.CreateRoleAsync(Full(world), "Viewers " + Guid.NewGuid().ToString("N")[..6], null, [Permissions.CustomersView]);
        var holder = await UserAsync(world, mfa: false);
        await world.Access.AssignRoleAsSystemAsync(world.Org, "test", holder, role);
        var error = await Assert.ThrowsAsync<AccessException>(() => world.Admin.UpdateRoleAsync(Full(world), role, "Viewers", null,
            [Permissions.CustomersView, Permissions.SnapshotsBrowse]));
        Assert.Contains("no passkey or authenticator app", error.Message, StringComparison.Ordinal);
        // Built-in roles stay as they are.
        var builtIn = (await world.Admin.RolesAsync(world.Org)).Single(r => r.Name == BuiltInRoles.ReadOnly);
        await Assert.ThrowsAsync<AccessException>(() => world.Admin.UpdateRoleAsync(Full(world), builtIn.Id, "Read-only", null, [Permissions.CustomersView]));
        await Assert.ThrowsAsync<AccessException>(() => world.Admin.DeleteRoleAsync(Full(world), role));
    }

    [PostgresFact]
    public async Task A_running_restore_pauses_when_its_starter_loses_access_to_the_tenant()
    {
        var world = await WorldAsync();
        var user = await UserAsync(world, roles: BuiltInRoles.RestoreOperator);
        var restore = Guid.NewGuid();
        await using (var owner = new NpgsqlConnection(db.Migrator))
        {
            await owner.ExecuteAsync(
                """
                INSERT INTO vaulty.restores (id, organization_id, tenant_id, protected_object_id, snapshot_id, job_id, kind, target_mode, selection, state, requested_by)
                VALUES (@restore, @org, @tenant, gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'restore', 'original', '{}', 'running', @user)
                """, new { restore, org = world.Org, tenant = world.TenantA1, user });
        }
        // Still allowed: nothing pauses.
        await world.Access.AfterChangeAsync(world.Org, [user]);
        Assert.Empty(world.Pauser.Paused);

        var betaOnly = await GroupAsync(world, "Beta", false, new GroupRule("include", world.CustomerB, null, null));
        await world.Admin.SetGroupsOfAsync(Full(world), user, [betaOnly]);
        Assert.Equal([restore], world.Pauser.Paused);
        await using var check = new NpgsqlConnection(db.Migrator);
        Assert.Equal(1, await check.ExecuteScalarAsync<int>(
            "SELECT count(*)::int FROM vaulty.audit_events WHERE action = 'restore.paused' AND target = @target", new { target = $"restore:{restore}" }));
    }

    [PostgresFact]
    public async Task An_Entra_group_mapping_gives_roles_and_groups_and_takes_them_away_again()
    {
        var world = await WorldAsync();
        var user = await UserAsync(world);
        await InGroupsAsync(world, user);
        var entraGroup = Guid.NewGuid();
        var alpha = await GroupAsync(world, "Alpha", false, new GroupRule("include", world.CustomerA, null, null));
        var readOnly = (await world.Admin.RolesAsync(world.Org)).Single(r => r.Name == BuiltInRoles.ReadOnly).Id;
        await world.Admin.SaveMappingAsync(Full(world), null, entraGroup, "Helpdesk", [readOnly], [alpha]);
        var sync = new EntraGroupSync(world.Api, null!, null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<EntraGroupSync>.Instance);

        Assert.True(await sync.ApplyAsync(world.Org, user, new HashSet<Guid> { entraGroup }));
        var access = await world.Access.GetAccessAsync(world.Org, user);
        Assert.True(access.Allows(Permissions.CustomersView, world.CustomerA));
        Assert.False(access.Allows(Permissions.CustomersView, world.CustomerB));
        // A mapped role is not removed by hand.
        await Assert.ThrowsAsync<AccessException>(() => world.Access.RemoveRoleAsync(Full(world), user, readOnly));

        // Out of the Entra group (or its groups could not be read): the mapped access goes, and nothing else.
        Assert.True(await sync.ApplyAsync(world.Org, user, new HashSet<Guid>()));
        access = await world.Access.GetAccessAsync(world.Org, user);
        Assert.Empty(access.Permissions);
        Assert.True(access.Scope.IsEmpty);
        Assert.False(await sync.ApplyAsync(world.Org, user, new HashSet<Guid>()));
    }

    [PostgresFact]
    public async Task Alert_mail_about_a_customer_reaches_only_users_whose_groups_include_it()
    {
        var world = await WorldAsync();
        var alphaUser = await UserAsync(world, roles: BuiltInRoles.ReadOnly);
        var everyone = await UserAsync(world, roles: BuiltInRoles.ReadOnly);
        await InGroupsAsync(world, alphaUser, await GroupAsync(world, "Alpha", false, new GroupRule("include", world.CustomerA, null, null)));
        await using var worker = new NpgsqlConnection(db.Worker);
        await worker.OpenAsync();
        await worker.ExecuteAsync("SELECT set_config('vaulty.organization_id', @org, false)", new { org = world.Org.ToString() });
        Assert.True(await worker.ExecuteScalarAsync<bool>("SELECT vaulty.user_sees_customer(@alphaUser, @a)", new { alphaUser, a = world.CustomerA }));
        Assert.False(await worker.ExecuteScalarAsync<bool>("SELECT vaulty.user_sees_customer(@alphaUser, @b)", new { alphaUser, b = world.CustomerB }));
        Assert.True(await worker.ExecuteScalarAsync<bool>("SELECT vaulty.user_sees_customer(@everyone, @b)", new { everyone, b = world.CustomerB }));
    }
}

/// <summary>The migration to groups on an organization that had roles limited to customers (its own database).</summary>
public sealed class AccessGroupsMigrationTests
{
    [PostgresFact]
    public async Task Existing_customer_limits_become_groups_without_widening_or_narrowing_access()
    {
        var db = new PostgresDatabase { MigrateTo = "20261111000018_MicrosoftSignIn" };
        await db.InitializeAsync();
        try
        {
            var (org, a, b, limited, unlimited, role) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
            await using (var owner = new NpgsqlConnection(db.Migrator))
            {
                await owner.ExecuteAsync(
                    """
                    INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'Old');
                    INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@a, @org, 'A', 'Alpha'), (@b, @org, 'B', 'Beta');
                    INSERT INTO vaulty.roles (id, organization_id, name, built_in) VALUES (@role, @org, 'Read-only', true);
                    INSERT INTO vaulty.role_permissions (organization_id, role_id, permission) VALUES (@org, @role, 'customers.view');
                    INSERT INTO vaulty.users (id, organization_id, user_name, normalized_user_name, security_stamp, concurrency_stamp)
                    VALUES (@limited, @org, 'limited@contoso.example', 'LIMITED@CONTOSO.EXAMPLE', 's', 'c'),
                           (@unlimited, @org, 'all@contoso.example', 'ALL@CONTOSO.EXAMPLE', 's', 'c');
                    INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id, customer_id)
                    VALUES (gen_random_uuid(), @org, @limited, @role, @a), (gen_random_uuid(), @org, @unlimited, @role, NULL);
                    """, new { org, a, b, limited, unlimited, role });
            }
            await db.MigrateAsync();

            var api = VaultyDataSource.Create(db.Api);
            var access = new AccessService(api);
            var limitedAccess = await access.GetAccessAsync(org, limited);
            Assert.True(limitedAccess.Allows(Permissions.CustomersView, a));
            Assert.False(limitedAccess.Allows(Permissions.CustomersView, b));
            var unlimitedAccess = await access.GetAccessAsync(org, unlimited);
            Assert.True(unlimitedAccess.Scope.All);
            // The old column keeps its value for old binaries during a rollback.
            await using var check = new NpgsqlConnection(db.Migrator);
            Assert.Equal(a, await check.ExecuteScalarAsync<Guid>("SELECT customer_id FROM vaulty.role_assignments WHERE user_id = @limited", new { limited }));
        }
        finally
        {
            await db.DisposeAsync();
        }
    }
}
