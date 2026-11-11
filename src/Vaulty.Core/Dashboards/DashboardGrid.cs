namespace Vaulty.Core.Dashboards;

/// <summary>
/// The grid of a dashboard: 12 columns, tiles never overlap. This is the only placement algorithm: the designer script
/// proposes a place, the server places the tile here and renders every position, so the browser never decides a layout.
/// </summary>
public static class DashboardGrid
{
    public const int Columns = 12;
    public const int MaxRows = 400;
    public const int MaxTiles = 60;

    /// <summary>Places a tile at the target (clamped to the grid and its type) and moves every tile it lands on down.</summary>
    public static IReadOnlyList<DashboardTile> Move(IReadOnlyList<DashboardTile> tiles, string id, GridRect target, bool pullUp)
    {
        ArgumentNullException.ThrowIfNull(tiles);
        var moved = tiles.FirstOrDefault(t => t.Id == id);
        if (moved is null) return tiles;
        var result = PushDown(moved.At(Clamp(target, DashboardTiles.Find(moved.Type))), tiles.Where(t => t.Id != id));
        return pullUp ? Compact(result) : result;
    }

    /// <summary>Adds a tile at its default size, at the first free place from the top (or at a dropped place).</summary>
    public static IReadOnlyList<DashboardTile> Add(IReadOnlyList<DashboardTile> tiles, DashboardTile tile, bool pullUp, GridRect? at = null)
    {
        ArgumentNullException.ThrowIfNull(tiles);
        ArgumentNullException.ThrowIfNull(tile);
        var type = DashboardTiles.Find(tile.Type);
        var size = type?.Default ?? new TileSize(Math.Max(1, tile.W), Math.Max(1, tile.H));
        List<DashboardTile> result;
        if (at is { } place)
        {
            result = [.. PushDown(tile.At(Clamp(new GridRect(place.X, place.Y, size.W, size.H), type)), tiles)];
        }
        else
        {
            result = [.. tiles, tile.At(FirstFree(tiles.Select(t => t.Rect).ToList(), size.W, size.H))];
        }
        return pullUp ? Compact(result) : result;
    }

    public static IReadOnlyList<DashboardTile> PushDown(DashboardTile placed, IEnumerable<DashboardTile> others)
    {
        var result = new List<DashboardTile> { placed };
        foreach (var tile in others.OrderBy(t => t.Y).ThenBy(t => t.X))
        {
            var rect = tile.Rect;
            while (result.FirstOrDefault(r => r.Rect.Overlaps(rect)) is { } blocking) rect = rect with { Y = blocking.Rect.Bottom };
            result.Add(tile.At(rect));
        }
        return result;
    }

    /// <summary>Moves every tile up as far as it can, in reading order.</summary>
    public static IReadOnlyList<DashboardTile> Compact(IEnumerable<DashboardTile> tiles)
    {
        var result = new List<DashboardTile>();
        foreach (var tile in tiles.OrderBy(t => t.Y).ThenBy(t => t.X))
        {
            var rect = tile.Rect;
            while (rect.Y > 0 && !result.Any(r => r.Rect.Overlaps(rect with { Y = rect.Y - 1 }))) rect = rect with { Y = rect.Y - 1 };
            result.Add(tile.At(rect));
        }
        return result;
    }

    public static GridRect FirstFree(IReadOnlyList<GridRect> taken, int w, int h)
    {
        ArgumentNullException.ThrowIfNull(taken);
        w = Math.Clamp(w, 1, Columns);
        for (var y = 0; y < MaxRows; y++)
        {
            for (var x = 0; x + w <= Columns; x++)
            {
                var rect = new GridRect(x, y, w, h);
                if (!taken.Any(t => t.Overlaps(rect))) return rect;
            }
        }
        return new GridRect(0, taken.Count == 0 ? 0 : taken.Max(t => t.Bottom), w, h);
    }

    /// <summary>Keeps a place inside the grid and inside the sizes of its type.</summary>
    public static GridRect Clamp(GridRect rect, TileType? type)
    {
        var min = type?.Min ?? new TileSize(1, 1);
        var max = type?.Max ?? new TileSize(Columns, MaxRows);
        var w = Math.Clamp(rect.W, min.W, Math.Min(max.W, Columns));
        var h = Math.Clamp(rect.H, min.H, max.H);
        return new GridRect(Math.Clamp(rect.X, 0, Columns - w), Math.Clamp(rect.Y, 0, MaxRows - h), w, h);
    }

    public static int Rows(IEnumerable<DashboardTile> tiles) => tiles.Select(t => t.Y + t.H).DefaultIfEmpty(0).Max();

    public static string NewTileId(IEnumerable<DashboardTile> tiles)
    {
        var taken = tiles.Select(t => t.Id).ToHashSet(StringComparer.Ordinal);
        string id;
        do id = "t" + Guid.NewGuid().ToString("N")[..8];
        while (taken.Contains(id));
        return id;
    }
}

/// <summary>The checks every layout passes on the server, and the choice of dashboard for a user.</summary>
public static class DashboardRules
{
    public const int MaxVersions = 20;
    public const int MaxImportBytes = 256 * 1024;
    public const int MaxTextLength = 2000;
    public const int MaxDashboards = 100;

    /// <summary>Problems of a layout in plain words; empty when it is valid.</summary>
    public static IReadOnlyList<string> Validate(DashboardLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        var problems = new List<string>();
        if (layout.Schema is < 1 or > DashboardLayout.CurrentSchema) problems.Add($"The layout has schema {layout.Schema}, which this version of Vaulty does not know.");
        if (layout.Tiles.Count > DashboardGrid.MaxTiles) problems.Add($"A dashboard has at most {DashboardGrid.MaxTiles} tiles.");
        if (layout.Tiles.Select(t => t.Id).Distinct(StringComparer.Ordinal).Count() != layout.Tiles.Count) problems.Add("Two tiles have the same id.");
        foreach (var tile in layout.Tiles)
        {
            if (string.IsNullOrWhiteSpace(tile.Id) || tile.Id.Length > 40) problems.Add("A tile has no valid id.");
            var type = DashboardTiles.Find(tile.Type);
            if (type is null && !DashboardTiles.Retired.Contains(tile.Type))
            {
                problems.Add($"Unknown tile \"{tile.Type}\".");
                continue;
            }
            if (tile.X < 0 || tile.Y < 0 || tile.W < 1 || tile.H < 1 || tile.Rect.Right > DashboardGrid.Columns || tile.Rect.Bottom > DashboardGrid.MaxRows)
            {
                problems.Add($"The tile {type?.Name ?? tile.Type} lies outside the grid.");
            }
            if (type is not null && (tile.W < type.Min.W || tile.H < type.Min.H || tile.W > type.Max.W || tile.H > type.Max.H))
            {
                problems.Add($"The tile {type.Name} is smaller or larger than it may be.");
            }
            if (type is { Scoped: false } && tile.Settings.Narrows) problems.Add($"The tile {type.Name} cannot be limited to customers.");
            if (tile.Settings.Text?.Length > MaxTextLength || tile.Settings.Title?.Length > 80) problems.Add("A title or text is too long.");
            if (tile.Settings.Limit is < 1 or > 200) problems.Add("A list shows between 1 and 200 rows.");
        }
        var tiles = layout.Tiles.ToList();
        for (var i = 0; i < tiles.Count; i++)
        {
            for (var j = i + 1; j < tiles.Count; j++)
            {
                if (tiles[i].Rect.Overlaps(tiles[j].Rect)) problems.Add("Two tiles overlap.");
            }
        }
        return problems.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>A published dashboard and the roles it is linked to, in priority order (lowest first).</summary>
    public sealed record Choice(Guid Id, int Priority, bool Published, IReadOnlyCollection<Guid> Roles);

    /// <summary>The first published dashboard by priority linked to any of the user's roles; null means the default.</summary>
    public static Guid? Pick(IEnumerable<Choice> choices, IReadOnlyCollection<Guid> roleIds) =>
        choices.Where(c => c.Published && c.Roles.Any(roleIds.Contains)).OrderBy(c => c.Priority).Select(c => (Guid?)c.Id).FirstOrDefault();

    /// <summary>The tiles a viewer sees: known types whose permissions the viewer holds.</summary>
    public static IReadOnlyList<(DashboardTile Tile, TileType Type)> Visible(DashboardLayout layout, Func<string, bool> has)
    {
        ArgumentNullException.ThrowIfNull(layout);
        return layout.Tiles.Select(t => (Tile: t, Type: DashboardTiles.Find(t.Type)))
            .Where(t => t.Type is not null && DashboardTiles.CanSee(t.Type, has))
            .Select(t => (t.Tile, t.Type!)).OrderBy(t => t.Item1.Y).ThenBy(t => t.Item1.X).ToList();
    }
}
