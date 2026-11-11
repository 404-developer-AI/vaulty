using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Npgsql;
using Vaulty.Core.Dashboards;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Reporting;

/// <summary>A refusal while designing a dashboard or column layout, in one sentence the designer can act on.</summary>
public sealed class DesignException(string message) : InvalidOperationException(message);

public sealed record DashboardSummary(Guid Id, string Name, string? Description, int Priority, int PublishedVersion, DateTimeOffset? PublishedAt, bool HasDraft,
    int Version, IReadOnlyList<Guid> RoleIds);

public sealed record DashboardDetail(DashboardSummary Summary, DashboardLayout? Published, DashboardLayout? Draft)
{
    /// <summary>What the designer edits: the draft, or a copy of what is published.</summary>
    public DashboardLayout Working => Draft ?? Published ?? new DashboardLayout();
}

public sealed record DashboardVersionRow(int Version, DateTimeOffset PublishedAt, Guid? PublishedBy, int Tiles);

/// <summary>The dashboard a user sees: a published one linked to one of their roles, or the default.</summary>
public sealed record EffectiveDashboard(Guid? Id, string Name, DashboardLayout Layout);

/// <summary>
/// Dashboards shared within an organization and linked to roles, with a draft and published versions (the last 20 kept).
/// Every change needs "Manage dashboards", is audited, and is refused when someone else changed the dashboard meanwhile.
/// </summary>
public sealed class DashboardDesignService(NpgsqlDataSource dataSource)
{
    public const string ExportFormat = "vaulty-dashboard";

    public async Task<IReadOnlyList<DashboardSummary>> ListAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await ListAsync(session, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<DashboardSummary>> ListAsync(OrganizationSession session, CancellationToken cancellationToken)
    {
        var rows = await session.Connection.QueryAsync<(Guid Id, string Name, string? Description, int Priority, int PublishedVersion, DateTime? PublishedAt, bool HasDraft, int Version)>(
            new CommandDefinition(
                """
                SELECT id, name, description, priority, published_version, published_at, draft_layout IS NOT NULL, version
                  FROM vaulty.dashboards ORDER BY priority
                """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var roles = (await session.Connection.QueryAsync<(Guid DashboardId, Guid RoleId)>(new CommandDefinition(
            "SELECT dashboard_id, role_id FROM vaulty.dashboard_roles", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToLookup(r => r.DashboardId, r => r.RoleId);
        return rows.Select(r => new DashboardSummary(r.Id, r.Name, r.Description, r.Priority, r.PublishedVersion, Utc(r.PublishedAt), r.HasDraft, r.Version,
            roles[r.Id].ToList())).ToList();
    }

    public async Task<DashboardDetail?> GetAsync(Guid organizationId, Guid id, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var summary = (await ListAsync(session, cancellationToken).ConfigureAwait(false)).FirstOrDefault(d => d.Id == id);
        if (summary is null) return null;
        var row = await session.Connection.QuerySingleAsync<(string? Published, string? Draft)>(new CommandDefinition(
            "SELECT published_layout::text, draft_layout::text FROM vaulty.dashboards WHERE id = @id", new { id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return new DashboardDetail(summary, Parse(row.Published), Parse(row.Draft));
    }

    /// <summary>A new dashboard, as a draft: empty, a copy of another dashboard, or a copy of the default.</summary>
    public async Task<Guid> CreateAsync(UserAccess actor, string name, string? description, IReadOnlyCollection<Guid> roleIds, Guid? copyOf, bool copyDefault,
        CancellationToken cancellationToken = default)
    {
        Require(actor);
        DashboardLayout layout = copyDefault ? DefaultDashboard.Layout : new DashboardLayout();
        if (copyOf is { } source)
        {
            layout = (await GetAsync(actor.OrganizationId, source, cancellationToken).ConfigureAwait(false))?.Working
                     ?? throw new DesignException("The dashboard to copy no longer exists.");
        }
        return await InsertAsync(actor, name, description, roleIds, layout, "dashboard.created", cancellationToken).ConfigureAwait(false);
    }

    private async Task<Guid> InsertAsync(UserAccess actor, string name, string? description, IReadOnlyCollection<Guid> roleIds, DashboardLayout layout, string action,
        CancellationToken cancellationToken)
    {
        RequireValid(layout);
        var clean = Name(name);
        var id = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        if (await session.Connection.ExecuteScalarAsync<int>(new CommandDefinition("SELECT count(*)::int FROM vaulty.dashboards", transaction: session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false) >= DashboardRules.MaxDashboards)
        {
            throw new DesignException($"An organization has at most {DashboardRules.MaxDashboards} dashboards.");
        }
        await UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.dashboards (id, organization_id, name, description, priority, draft_layout, updated_by)
            VALUES (@id, vaulty.current_organization_id(), @clean, @description, (SELECT coalesce(max(priority), 0) + 1 FROM vaulty.dashboards), @layout::jsonb, @user)
            """, new { id, clean, description = Text(description, 500), layout = layout.ToJson(), user = actor.UserId }, session.Transaction,
            cancellationToken: cancellationToken)), $"A dashboard named {clean} exists already.").ConfigureAwait(false);
        await SetRolesAsync(session, id, roleIds, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", action, $"dashboard:{id}", new { name = clean, roles = roleIds, tiles = layout.Tiles.Count },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    /// <summary>Name, description and roles. Returns the new version.</summary>
    public Task<int> UpdateAsync(UserAccess actor, Guid id, int expectedVersion, string name, string? description, IReadOnlyCollection<Guid> roleIds,
        CancellationToken cancellationToken = default) =>
        ChangeAsync(actor, id, expectedVersion, "dashboard.updated", async (session, before) =>
        {
            var clean = Name(name);
            await UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.dashboards SET name = @clean, description = @description WHERE id = @id",
                new { id, clean, description = Text(description, 500) }, session.Transaction, cancellationToken: cancellationToken)),
                $"A dashboard named {clean} exists already.").ConfigureAwait(false);
            await SetRolesAsync(session, id, roleIds, cancellationToken).ConfigureAwait(false);
            return new { from = new { before.Name, roles = before.RoleIds }, to = new { name = clean, roles = roleIds } };
        }, cancellationToken);

    public Task<int> SaveDraftAsync(UserAccess actor, Guid id, int expectedVersion, DashboardLayout layout, CancellationToken cancellationToken = default) =>
        ChangeAsync(actor, id, expectedVersion, "dashboard.draft_saved", async (session, _) =>
        {
            RequireValid(layout);
            await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.dashboards SET draft_layout = @layout::jsonb WHERE id = @id",
                new { id, layout = layout.ToJson() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            return new { tiles = layout.Tiles.Count };
        }, cancellationToken);

    public Task<int> DiscardDraftAsync(UserAccess actor, Guid id, int expectedVersion, CancellationToken cancellationToken = default) =>
        ChangeAsync(actor, id, expectedVersion, "dashboard.draft_discarded", async (session, _) =>
        {
            await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.dashboards SET draft_layout = NULL WHERE id = @id", new { id },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            return new { };
        }, cancellationToken);

    /// <summary>Publishes the draft as the next version; the last 20 versions are kept.</summary>
    public Task<int> PublishAsync(UserAccess actor, Guid id, int expectedVersion, CancellationToken cancellationToken = default) =>
        ChangeAsync(actor, id, expectedVersion, "dashboard.published", async (session, _) =>
        {
            var draft = Parse(await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition(
                "SELECT draft_layout::text FROM vaulty.dashboards WHERE id = @id", new { id }, session.Transaction, cancellationToken: cancellationToken))
                .ConfigureAwait(false)) ?? throw new DesignException("There is no draft to publish.");
            RequireValid(draft);
            var version = await session.Connection.ExecuteScalarAsync<int>(new CommandDefinition(
                """
                UPDATE vaulty.dashboards SET published_layout = draft_layout, draft_layout = NULL, published_version = published_version + 1,
                       published_at = now(), published_by = @user
                 WHERE id = @id RETURNING published_version
                """, new { id, user = actor.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO vaulty.dashboard_versions (organization_id, dashboard_id, version, layout, published_by)
                VALUES (vaulty.current_organization_id(), @id, @version, @layout::jsonb, @user);
                DELETE FROM vaulty.dashboard_versions WHERE dashboard_id = @id AND version <= @version - @keep;
                """, new { id, version, layout = draft.ToJson(), user = actor.UserId, keep = DashboardRules.MaxVersions }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            return new { version, tiles = draft.Tiles.Count };
        }, cancellationToken);

    public async Task<IReadOnlyList<DashboardVersionRow>> VersionsAsync(Guid organizationId, Guid id, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(int Version, DateTime PublishedAt, Guid? PublishedBy, string Layout)>(new CommandDefinition(
            "SELECT version, published_at, published_by, layout::text FROM vaulty.dashboard_versions WHERE dashboard_id = @id ORDER BY version DESC",
            new { id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new DashboardVersionRow(r.Version, Utc(r.PublishedAt)!.Value, r.PublishedBy, Parse(r.Layout)?.Tiles.Count ?? 0)).ToList();
    }

    /// <summary>Puts an earlier published version into the draft; publishing it makes it current again.</summary>
    public Task<int> RestoreVersionAsync(UserAccess actor, Guid id, int expectedVersion, int version, CancellationToken cancellationToken = default) =>
        ChangeAsync(actor, id, expectedVersion, "dashboard.version_restored", async (session, _) =>
        {
            var restored = await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vaulty.dashboards d SET draft_layout = v.layout FROM vaulty.dashboard_versions v
                 WHERE d.id = @id AND v.dashboard_id = d.id AND v.version = @version
                """, new { id, version }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (restored == 0) throw new DesignException("That version is no longer kept.");
            return new { version };
        }, cancellationToken);

    public async Task DeleteAsync(UserAccess actor, Guid id, CancellationToken cancellationToken = default)
    {
        Require(actor);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        var name = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition("DELETE FROM vaulty.dashboards WHERE id = @id RETURNING name", new { id },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false) ?? throw new DesignException("The dashboard no longer exists.");
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "dashboard.deleted", $"dashboard:{id}", new { name }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Moves a dashboard one place up (-1) or down (+1) in priority.</summary>
    public async Task MoveAsync(UserAccess actor, Guid id, int direction, CancellationToken cancellationToken = default)
    {
        Require(actor);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("SET CONSTRAINTS ALL DEFERRED", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        var list = (await ListAsync(session, cancellationToken).ConfigureAwait(false)).ToList();
        var index = list.FindIndex(d => d.Id == id);
        var other = index + Math.Sign(direction);
        if (index < 0 || other < 0 || other >= list.Count) return;
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.dashboards SET priority = CASE id WHEN @a THEN @pb WHEN @b THEN @pa END WHERE id IN (@a, @b)",
            new { a = list[index].Id, b = list[other].Id, pa = list[index].Priority, pb = list[other].Priority }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "dashboard.order_changed", $"dashboard:{id}", new { direction = Math.Sign(direction) },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The dashboard as a file: name, description and the working layout. Roles are not exported.</summary>
    public async Task<string> ExportAsync(Guid organizationId, Guid id, CancellationToken cancellationToken = default)
    {
        var detail = await GetAsync(organizationId, id, cancellationToken).ConfigureAwait(false) ?? throw new DesignException("The dashboard no longer exists.");
        return new JsonObject
        {
            ["format"] = ExportFormat, ["formatVersion"] = 1, ["name"] = detail.Summary.Name, ["description"] = detail.Summary.Description,
            ["layout"] = JsonNode.Parse(detail.Working.ToJson()),
        }.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Creates a dashboard (as a draft, linked to no role) from an exported file of at most 256 KB.</summary>
    public async Task<Guid> ImportAsync(UserAccess actor, string json, CancellationToken cancellationToken = default)
    {
        Require(actor);
        ArgumentNullException.ThrowIfNull(json);
        if (System.Text.Encoding.UTF8.GetByteCount(json) > DashboardRules.MaxImportBytes) throw new DesignException("The file is larger than 256 KB.");
        JsonObject file;
        DashboardLayout layout;
        try
        {
            file = JsonNode.Parse(json) as JsonObject ?? throw new DesignException("The file is not a Vaulty dashboard.");
            if (file["format"]?.GetValue<string>() != ExportFormat) throw new DesignException("The file is not a Vaulty dashboard.");
            layout = file["layout"]?.Deserialize<DashboardLayout>(DashboardLayout.Json) ?? throw new DesignException("The file has no layout.");
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException and not DesignException or FormatException)
        {
            throw new DesignException("The file is not a Vaulty dashboard.");
        }
        var name = file["name"]?.GetValue<string>() ?? "Imported dashboard";
        var existing = (await ListAsync(actor.OrganizationId, cancellationToken).ConfigureAwait(false)).Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unique = name;
        for (var n = 2; existing.Contains(unique); n++) unique = $"{name} ({n})";
        return await InsertAsync(actor, unique, file["description"]?.GetValue<string>(), [], layout, "dashboard.imported", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The dashboard for a user: the first published one by priority linked to one of the user's roles, or the default.</summary>
    public async Task<EffectiveDashboard> ForUserAsync(UserAccess access, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var roles = (await session.Connection.QueryAsync<Guid>(new CommandDefinition("SELECT role_id FROM vaulty.role_assignments WHERE user_id = @user",
            new { user = access.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToHashSet();
        var list = await ListAsync(session, cancellationToken).ConfigureAwait(false);
        var picked = DashboardRules.Pick(list.Select(d => new DashboardRules.Choice(d.Id, d.Priority, d.PublishedVersion > 0, d.RoleIds)), roles);
        if (picked is not { } id) return new EffectiveDashboard(null, DefaultDashboard.Name, DefaultDashboard.Layout);
        var json = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition("SELECT published_layout::text FROM vaulty.dashboards WHERE id = @id",
            new { id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        // A layout that cannot be read (a newer release, a damaged row) never leaves a user without a dashboard.
        return Parse(json) is { } layout
            ? new EffectiveDashboard(id, list.First(d => d.Id == id).Name, layout)
            : new EffectiveDashboard(null, DefaultDashboard.Name, DefaultDashboard.Layout);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------

    private async Task<int> ChangeAsync(UserAccess actor, Guid id, int expectedVersion, string action, Func<OrganizationSession, DashboardSummary, Task<object>> change,
        CancellationToken cancellationToken)
    {
        Require(actor);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        var before = (await ListAsync(session, cancellationToken).ConfigureAwait(false)).FirstOrDefault(d => d.Id == id)
                     ?? throw new DesignException("The dashboard no longer exists.");
        var bumped = await session.Connection.ExecuteScalarAsync<int?>(new CommandDefinition(
            "UPDATE vaulty.dashboards SET version = version + 1, updated_at = now(), updated_by = @user WHERE id = @id AND version = @expectedVersion RETURNING version",
            new { id, expectedVersion, user = actor.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (bumped is not { } version) throw new DesignException("Someone else changed this dashboard in the meantime. Open it again to see the change.");
        var details = await change(session, before).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", action, $"dashboard:{id}", details, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return version;
    }

    private static async Task SetRolesAsync(OrganizationSession session, Guid id, IReadOnlyCollection<Guid> roleIds, CancellationToken cancellationToken)
    {
        await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.dashboard_roles WHERE dashboard_id = @id", new { id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.dashboard_roles (organization_id, dashboard_id, role_id) VALUES (vaulty.current_organization_id(), @id, @roleId)",
            roleIds.Distinct().Select(r => new { id, roleId = r }), session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    private static void Require(UserAccess actor)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.Allows(Permissions.DashboardsManage)) throw new DesignException("You cannot change dashboards.");
    }

    private static void RequireValid(DashboardLayout layout)
    {
        var problems = DashboardRules.Validate(layout);
        if (problems.Count > 0) throw new DesignException(string.Join(" ", problems));
    }

    internal static string Name(string? name)
    {
        var value = (name ?? "").Trim();
        if (value.Length is < 1 or > 80) throw new DesignException("Enter a name of at most 80 characters.");
        return value;
    }

    private static string? Text(string? value, int max) => string.IsNullOrWhiteSpace(value) ? null : value.Trim()[..Math.Min(value.Trim().Length, max)];

    private static DashboardLayout? Parse(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        try
        {
            return DashboardLayout.FromJson(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static DateTimeOffset? Utc(DateTime? value) => value is { } v ? new DateTimeOffset(DateTime.SpecifyKind(v, DateTimeKind.Utc)) : null;

    internal static async Task<int> UniqueAsync(Func<Task<int>> write, string message)
    {
        try
        {
            return await write().ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            throw new DesignException(message);
        }
    }
}

public sealed record ColumnLayoutRow(Guid Id, string List, string Name, int Priority, IReadOnlyList<string> Columns, int Version, IReadOnlyList<Guid> RoleIds);

/// <summary>
/// Which columns a list shows, per role: the first layout of the list by priority linked to one of the user's roles, or
/// the default. Only the choice and order of columns; the name and status of a row always show.
/// </summary>
public sealed class ColumnLayoutService(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<ColumnLayoutRow>> ListAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await ListAsync(session, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<ColumnLayoutRow>> ListAsync(OrganizationSession session, CancellationToken cancellationToken)
    {
        var rows = await session.Connection.QueryAsync<(Guid Id, string List, string Name, int Priority, string[] Columns, int Version)>(new CommandDefinition(
            "SELECT id, list, name, priority, columns, version FROM vaulty.column_layouts ORDER BY list, priority", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        var roles = (await session.Connection.QueryAsync<(Guid LayoutId, Guid RoleId)>(new CommandDefinition(
            "SELECT layout_id, role_id FROM vaulty.column_layout_roles", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToLookup(r => r.LayoutId, r => r.RoleId);
        return rows.Select(r => new ColumnLayoutRow(r.Id, r.List, r.Name, r.Priority, r.Columns, r.Version, roles[r.Id].ToList())).ToList();
    }

    public async Task<Guid> CreateAsync(UserAccess actor, string list, string name, IReadOnlyList<string> columns, IReadOnlyCollection<Guid> roleIds,
        CancellationToken cancellationToken = default)
    {
        Require(actor);
        RequireValid(list, columns);
        var clean = DashboardDesignService.Name(name);
        var id = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        await DashboardDesignService.UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.column_layouts (id, organization_id, list, name, priority, columns, updated_by)
            VALUES (@id, vaulty.current_organization_id(), @list, @clean,
                    (SELECT coalesce(max(priority), 0) + 1 FROM vaulty.column_layouts WHERE list = @list), @columns, @user)
            """, new { id, list, clean, columns = columns.ToArray(), user = actor.UserId }, session.Transaction, cancellationToken: cancellationToken)),
            $"A layout named {clean} exists already for this list.").ConfigureAwait(false);
        await SetRolesAsync(session, id, roleIds, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "column_layout.created", $"column_layout:{id}", new { list, name = clean, columns, roles = roleIds },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    public async Task UpdateAsync(UserAccess actor, Guid id, int expectedVersion, string name, IReadOnlyList<string> columns, IReadOnlyCollection<Guid> roleIds,
        CancellationToken cancellationToken = default)
    {
        Require(actor);
        var clean = DashboardDesignService.Name(name);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        var before = (await ListAsync(session, cancellationToken).ConfigureAwait(false)).FirstOrDefault(l => l.Id == id)
                     ?? throw new DesignException("The layout no longer exists.");
        RequireValid(before.List, columns);
        var updated = await DashboardDesignService.UniqueAsync(() => session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.column_layouts SET name = @clean, columns = @columns, version = version + 1, updated_at = now(), updated_by = @user
             WHERE id = @id AND version = @expectedVersion
            """, new { id, clean, columns = columns.ToArray(), expectedVersion, user = actor.UserId }, session.Transaction, cancellationToken: cancellationToken)),
            $"A layout named {clean} exists already for this list.").ConfigureAwait(false);
        if (updated == 0) throw new DesignException("Someone else changed this layout in the meantime. Open it again to see the change.");
        await SetRolesAsync(session, id, roleIds, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "column_layout.updated", $"column_layout:{id}",
            new { from = new { before.Name, before.Columns, roles = before.RoleIds }, to = new { name = clean, columns, roles = roleIds } }, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(UserAccess actor, Guid id, CancellationToken cancellationToken = default)
    {
        Require(actor);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        var name = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition("DELETE FROM vaulty.column_layouts WHERE id = @id RETURNING name",
            new { id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false) ?? throw new DesignException("The layout no longer exists.");
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "column_layout.deleted", $"column_layout:{id}", new { name }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task MoveAsync(UserAccess actor, Guid id, int direction, CancellationToken cancellationToken = default)
    {
        Require(actor);
        await using var session = await OrganizationSession.BeginAsync(dataSource, actor.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("SET CONSTRAINTS ALL DEFERRED", transaction: session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        var all = await ListAsync(session, cancellationToken).ConfigureAwait(false);
        var layout = all.FirstOrDefault(l => l.Id == id);
        if (layout is null) return;
        var list = all.Where(l => l.List == layout.List).ToList();
        var index = list.FindIndex(l => l.Id == id);
        var other = index + Math.Sign(direction);
        if (other < 0 || other >= list.Count) return;
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.column_layouts SET priority = CASE id WHEN @a THEN @pb WHEN @b THEN @pa END WHERE id IN (@a, @b)",
            new { a = list[index].Id, b = list[other].Id, pa = list[index].Priority, pb = list[other].Priority }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor.UserId}", "column_layout.order_changed", $"column_layout:{id}", new { direction = Math.Sign(direction) },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The columns a user sees in a list, already without the ones the user may not see.</summary>
    public async Task<IReadOnlyList<string>> ForUserAsync(UserAccess access, string list, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var columns = await session.Connection.QueryFirstOrDefaultAsync<string[]?>(new CommandDefinition(
            """
            SELECT l.columns FROM vaulty.column_layouts l
             WHERE l.list = @list AND EXISTS (SELECT 1 FROM vaulty.column_layout_roles r JOIN vaulty.role_assignments a ON a.role_id = r.role_id
                                               WHERE r.layout_id = l.id AND a.user_id = @user)
             ORDER BY l.priority LIMIT 1
            """, new { list, user = access.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return ColumnCatalog.Visible(list, columns, p => access.Allows(p));
    }

    private static async Task SetRolesAsync(OrganizationSession session, Guid id, IReadOnlyCollection<Guid> roleIds, CancellationToken cancellationToken)
    {
        await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.column_layout_roles WHERE layout_id = @id", new { id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.column_layout_roles (organization_id, layout_id, role_id) VALUES (vaulty.current_organization_id(), @id, @roleId)",
            roleIds.Distinct().Select(r => new { id, roleId = r }), session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    private static void Require(UserAccess actor)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.Allows(Permissions.ColumnsManage)) throw new DesignException("You cannot change column layouts.");
    }

    private static void RequireValid(string list, IReadOnlyList<string> columns)
    {
        var problems = ColumnCatalog.Validate(list, columns);
        if (problems.Count > 0) throw new DesignException(string.Join(" ", problems));
    }
}
