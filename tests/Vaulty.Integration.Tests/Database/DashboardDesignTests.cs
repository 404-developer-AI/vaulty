using Dapper;
using Npgsql;
using Vaulty.Core.Dashboards;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Reporting;

namespace Vaulty.Integration.Tests.Database;

public sealed class DashboardDesignTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private sealed record World(Guid Org, NpgsqlDataSource Api, DashboardDesignService Designs, ColumnLayoutService Columns, UserAccess Designer, Guid ReadOnlyRole,
        Guid BackupRole);

    private async Task<World> WorldAsync()
    {
        var api = VaultyDataSource.Create(db.Api);
        var access = new AccessService(api);
        var org = await new OrganizationSetup(api, access).CreateOrganizationAsync("Org " + Guid.NewGuid(), Guid.NewGuid());
        var roles = await new AccessAdministration(api, access).RolesAsync(org);
        var designer = new UserAccess(Guid.NewGuid(), org, true, Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));
        return new World(org, api, new DashboardDesignService(api), new ColumnLayoutService(api), designer,
            roles.Single(r => r.Name == BuiltInRoles.ReadOnly).Id, roles.Single(r => r.Name == BuiltInRoles.BackupOperator).Id);
    }

    private async Task<UserAccess> UserWithRoleAsync(World world, Guid role)
    {
        var id = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.users (id, organization_id, user_name, normalized_user_name, security_stamp, concurrency_stamp) VALUES (@id, @org, @name, upper(@name), 's', 'c');
            INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id) VALUES (gen_random_uuid(), @org, @id, @role);
            """, new { id, org = world.Org, name = $"u-{id:N}@contoso.example", role });
        return await new AccessService(world.Api).GetAccessAsync(world.Org, id);
    }

    private static DashboardLayout Layout(params string[] types)
    {
        IReadOnlyList<DashboardTile> tiles = [];
        foreach (var (type, i) in types.Select((t, i) => (t, i))) tiles = DashboardGrid.Add(tiles, new DashboardTile { Id = $"t{i}", Type = type }, true);
        return new DashboardLayout { Tiles = tiles };
    }

    [PostgresFact]
    public async Task A_draft_shows_to_nobody_until_it_is_published_and_then_only_to_its_roles()
    {
        var world = await WorldAsync();
        var viewer = await UserWithRoleAsync(world, world.ReadOnlyRole);
        var other = await UserWithRoleAsync(world, world.BackupRole);
        var id = await world.Designs.CreateAsync(world.Designer, "Helpdesk", null, [world.ReadOnlyRole], null, copyDefault: false);
        var detail = (await world.Designs.GetAsync(world.Org, id))!;
        var version = await world.Designs.SaveDraftAsync(world.Designer, id, detail.Summary.Version, Layout(DashboardTiles.Jobs, DashboardTiles.Note));

        Assert.Null((await world.Designs.ForUserAsync(viewer)).Id);
        await world.Designs.PublishAsync(world.Designer, id, version);
        var seen = await world.Designs.ForUserAsync(viewer);
        Assert.Equal(id, seen.Id);
        Assert.Equal(2, seen.Layout.Tiles.Count);
        Assert.Null((await world.Designs.ForUserAsync(other)).Id);
        Assert.Equal(DefaultDashboard.Layout, (await world.Designs.ForUserAsync(other)).Layout);
    }

    [PostgresFact]
    public async Task Two_designers_publishing_at_once_get_one_success_and_one_conflict()
    {
        var world = await WorldAsync();
        var id = await world.Designs.CreateAsync(world.Designer, "Shared", null, [], null, copyDefault: true);
        var version = (await world.Designs.GetAsync(world.Org, id))!.Summary.Version;
        var results = await Task.WhenAll(
            Task.Run(async () => { try { await world.Designs.PublishAsync(world.Designer, id, version); return true; } catch (DesignException) { return false; } }),
            Task.Run(async () => { try { await world.Designs.PublishAsync(world.Designer, id, version); return true; } catch (DesignException) { return false; } }));
        Assert.Single(results, r => r);
        var stale = await Assert.ThrowsAsync<DesignException>(() => world.Designs.SaveDraftAsync(world.Designer, id, version, Layout(DashboardTiles.Note)));
        Assert.Contains("Someone else changed this dashboard", stale.Message, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task Published_versions_are_kept_twenty_deep_and_one_can_come_back_as_the_draft()
    {
        var world = await WorldAsync();
        var id = await world.Designs.CreateAsync(world.Designer, "Versions", null, [], null, copyDefault: false);
        var version = (await world.Designs.GetAsync(world.Org, id))!.Summary.Version;
        for (var i = 0; i < 22; i++)
        {
            version = await world.Designs.SaveDraftAsync(world.Designer, id, version, Layout(Enumerable.Repeat(DashboardTiles.Note, i % 5 + 1).ToArray()));
            version = await world.Designs.PublishAsync(world.Designer, id, version);
        }
        var versions = await world.Designs.VersionsAsync(world.Org, id);
        Assert.Equal(DashboardRules.MaxVersions, versions.Count);
        Assert.Equal(22, versions[0].Version);
        Assert.Equal(3, versions[^1].Version);
        await world.Designs.RestoreVersionAsync(world.Designer, id, version, 3);
        Assert.Equal(3, (await world.Designs.GetAsync(world.Org, id))!.Draft!.Tiles.Count);
    }

    [PostgresFact]
    public async Task An_export_imported_again_gives_the_same_layout_and_a_bad_file_is_refused()
    {
        var world = await WorldAsync();
        var layout = Layout(DashboardTiles.Summary, DashboardTiles.Alerts, DashboardTiles.Note) with { };
        var id = await world.Designs.CreateAsync(world.Designer, "Export me", "With a note", [world.ReadOnlyRole], null, copyDefault: false);
        await world.Designs.SaveDraftAsync(world.Designer, id, (await world.Designs.GetAsync(world.Org, id))!.Summary.Version, layout);
        var json = await world.Designs.ExportAsync(world.Org, id);

        var copy = await world.Designs.ImportAsync(world.Designer, json);
        var imported = (await world.Designs.GetAsync(world.Org, copy))!;
        Assert.Equal(layout.ToJson(), imported.Working.ToJson());
        Assert.Equal("Export me (2)", imported.Summary.Name);
        Assert.Empty(imported.Summary.RoleIds);

        await Assert.ThrowsAsync<DesignException>(() => world.Designs.ImportAsync(world.Designer, new string(' ', DashboardRules.MaxImportBytes + 1)));
        await Assert.ThrowsAsync<DesignException>(() => world.Designs.ImportAsync(world.Designer, "{\"format\":\"something-else\"}"));
        await Assert.ThrowsAsync<DesignException>(() => world.Designs.ImportAsync(world.Designer, "not json"));
        var invalid = json.Replace("\"summary\"", "\"no-such-tile\"", StringComparison.Ordinal);
        await Assert.ThrowsAsync<DesignException>(() => world.Designs.ImportAsync(world.Designer, invalid));
    }

    [PostgresFact]
    public async Task Every_change_is_in_the_audit_log_and_needs_the_permission()
    {
        var world = await WorldAsync();
        var id = await world.Designs.CreateAsync(world.Designer, "Audited", null, [], null, copyDefault: true);
        var version = (await world.Designs.GetAsync(world.Org, id))!.Summary.Version;
        version = await world.Designs.UpdateAsync(world.Designer, id, version, "Audited", "Now with text", [world.ReadOnlyRole]);
        version = await world.Designs.SaveDraftAsync(world.Designer, id, version, Layout(DashboardTiles.Note));
        version = await world.Designs.DiscardDraftAsync(world.Designer, id, version);
        version = await world.Designs.SaveDraftAsync(world.Designer, id, version, Layout(DashboardTiles.Note));
        version = await world.Designs.PublishAsync(world.Designer, id, version);
        version = await world.Designs.RestoreVersionAsync(world.Designer, id, version, 1);
        var second = await world.Designs.CreateAsync(world.Designer, "Second", null, [], null, copyDefault: false);
        await world.Designs.MoveAsync(world.Designer, second, -1);
        await world.Designs.ImportAsync(world.Designer, await world.Designs.ExportAsync(world.Org, id));
        await world.Designs.DeleteAsync(world.Designer, second);

        await using var owner = new NpgsqlConnection(db.Migrator);
        var actions = (await owner.QueryAsync<string>(
            "SELECT DISTINCT action FROM vaulty.audit_events WHERE organization_id = @org AND action LIKE 'dashboard.%'", new { org = world.Org })).ToHashSet();
        Assert.Superset(new HashSet<string>
        {
            "dashboard.created", "dashboard.updated", "dashboard.draft_saved", "dashboard.draft_discarded", "dashboard.published", "dashboard.version_restored",
            "dashboard.order_changed", "dashboard.imported", "dashboard.deleted",
        }, actions);

        var viewer = await UserWithRoleAsync(world, world.ReadOnlyRole);
        await Assert.ThrowsAsync<DesignException>(() => world.Designs.CreateAsync(viewer, "Not allowed", null, [], null, false));
        await Assert.ThrowsAsync<DesignException>(() => world.Columns.CreateAsync(viewer, ColumnCatalog.Jobs, "Not allowed", ColumnCatalog.Default(ColumnCatalog.Jobs), []));
    }

    [PostgresFact]
    public async Task A_column_layout_applies_to_its_roles_and_never_shows_a_column_the_viewer_may_not_see()
    {
        var world = await WorldAsync();
        var readOnly = await UserWithRoleAsync(world, world.ReadOnlyRole);
        var operatorUser = await UserWithRoleAsync(world, world.BackupRole);
        await world.Columns.CreateAsync(world.Designer, ColumnCatalog.Jobs, "Short", ["status", "target", "request_id"], [world.ReadOnlyRole]);
        Assert.Equal(["status", "target", "request_id"], await world.Columns.ForUserAsync(readOnly, ColumnCatalog.Jobs));
        Assert.Equal(ColumnCatalog.Default(ColumnCatalog.Jobs), await world.Columns.ForUserAsync(operatorUser, ColumnCatalog.Jobs));

        // The backup switch of protected objects needs permission to view policies: a viewer without it never gets the column.
        await world.Columns.CreateAsync(world.Designer, ColumnCatalog.Objects, "With switch", ["backup", "object", "status"], [world.ReadOnlyRole, world.BackupRole]);
        Assert.Contains("backup", await world.Columns.ForUserAsync(readOnly, ColumnCatalog.Objects));
        var noPolicies = new UserAccess(Guid.NewGuid(), world.Org, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.CustomersView] = null });
        Assert.DoesNotContain("backup", ColumnCatalog.Visible(ColumnCatalog.Objects, ["backup", "object", "status"], p => noPolicies.Allows(p)));

        // A layout without the name or status of a row is refused.
        await Assert.ThrowsAsync<DesignException>(() => world.Columns.CreateAsync(world.Designer, ColumnCatalog.Jobs, "Bad", ["type", "started"], []));
        var layout = (await world.Columns.ListAsync(world.Org)).First(l => l.List == ColumnCatalog.Jobs);
        await world.Columns.UpdateAsync(world.Designer, layout.Id, layout.Version, "Short", ["target", "status"], [world.ReadOnlyRole]);
        await Assert.ThrowsAsync<DesignException>(() => world.Columns.UpdateAsync(world.Designer, layout.Id, layout.Version, "Again", ["target", "status"], []));
    }
}
