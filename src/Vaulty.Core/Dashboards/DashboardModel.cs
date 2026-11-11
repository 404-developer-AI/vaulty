using System.Text.Json;
using System.Text.Json.Serialization;
using Vaulty.Core.Security;

namespace Vaulty.Core.Dashboards;

/// <summary>A place on the grid: column, row, width and height in cells.</summary>
public readonly record struct GridRect(int X, int Y, int W, int H)
{
    public int Right => X + W;
    public int Bottom => Y + H;

    public bool Overlaps(GridRect other) => X < other.Right && other.X < Right && Y < other.Bottom && other.Y < Bottom;
}

public readonly record struct TileSize(int W, int H);

/// <summary>
/// What a tile shows of: the dashboard's own scope (everything the viewer sees), or only some customers or a tag. A tile
/// scope only narrows; the data is read in the viewer's own session, so a scope can never show what the viewer may not see.
/// </summary>
public sealed record TileSettings
{
    public string? Title { get; init; }
    public IReadOnlyList<Guid> CustomerIds { get; init; } = [];
    public string? Tag { get; init; }
    /// <summary>Rows a list tile shows at most.</summary>
    public int? Limit { get; init; }
    /// <summary>The text of a note tile.</summary>
    public string? Text { get; init; }

    /// <summary>Fields of a newer release, kept so a rollback loses nothing.</summary>
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; init; }

    public bool Narrows => CustomerIds.Count > 0 || !string.IsNullOrWhiteSpace(Tag);
}

public sealed record DashboardTile
{
    public required string Id { get; init; }
    public required string Type { get; init; }
    public int X { get; init; }
    public int Y { get; init; }
    public int W { get; init; }
    public int H { get; init; }
    public TileSettings Settings { get; init; } = new();
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; init; }

    [JsonIgnore] public GridRect Rect => new(X, Y, W, H);

    public DashboardTile At(GridRect rect) => this with { X = rect.X, Y = rect.Y, W = rect.W, H = rect.H };
}

/// <summary>The layout of a dashboard, stored as JSON with a schema version.</summary>
public sealed record DashboardLayout
{
    public const int CurrentSchema = 1;

    public int Schema { get; init; } = CurrentSchema;
    /// <summary>Pull tiles up so no holes remain above them.</summary>
    public bool PullUp { get; init; } = true;
    public IReadOnlyList<DashboardTile> Tiles { get; init; } = [];
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; init; }

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = false };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static DashboardLayout FromJson(string json) => JsonSerializer.Deserialize<DashboardLayout>(json, Json) ?? new DashboardLayout();
}

/// <summary>One kind of tile: what it shows, what it needs, how large it may be.</summary>
/// <param name="Permissions">The tile shows only when the viewer holds all of them; every tile needs at least one.</param>
/// <param name="Scoped">The tile can be narrowed to some customers or a tag.</param>
public sealed record TileType(string Key, string Name, string Description, IReadOnlyList<string> Permissions, TileSize Min, TileSize Max, TileSize Default,
    bool Scoped);

/// <summary>
/// The catalog of tiles. Keys are stored, so they never change; a removed key goes to <see cref="Retired"/> and its tiles
/// stay in a layout without showing. "Needs attention" is not a tile: it stands above every dashboard and cannot be removed.
/// </summary>
public static class DashboardTiles
{
    public const string Summary = "summary";
    public const string Alerts = "alerts";
    public const string Rollup = "rollup";
    public const string Jobs = "jobs";
    public const string Note = "note";

    public static readonly IReadOnlyList<TileType> All =
    [
        new(Summary, "Protection summary", "Exact counts of protected, failed and partial objects, and of customers that need attention.",
            [Security.Permissions.CustomersView], new(4, 2), new(12, 3), new(12, 2), Scoped: true),
        new(Alerts, "Open alerts", "Alerts that are still open, newest first, with a link to what they are about.",
            [Security.Permissions.CustomersView], new(4, 3), new(12, 12), new(12, 4), Scoped: true),
        new(Rollup, "Customers and tenants", "Every customer with its tenants and protected objects, worst status first.",
            [Security.Permissions.CustomersView], new(6, 4), new(12, 30), new(12, 8), Scoped: true),
        new(Jobs, "Recent jobs", "The latest backups, restores, exports and verifications with their result.",
            [Security.Permissions.JobsView], new(4, 3), new(12, 12), new(6, 4), Scoped: true),
        new(Note, "Note", "A short text for the people who see this dashboard, such as who to call.",
            [Security.Permissions.CustomersView], new(2, 1), new(12, 6), new(6, 2), Scoped: false),
    ];

    /// <summary>Keys of tiles that no longer exist.</summary>
    public static readonly IReadOnlySet<string> Retired = new HashSet<string>(StringComparer.Ordinal);

    public static TileType? Find(string key) => All.FirstOrDefault(t => t.Key == key);

    public static bool CanSee(TileType type, Func<string, bool> has)
    {
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(has);
        return type.Permissions.Count > 0 && type.Permissions.All(has);
    }
}

/// <summary>The dashboard everyone sees when no published dashboard is linked to one of their roles. It cannot be changed, only copied.</summary>
public static class DefaultDashboard
{
    public const string Name = "Default";

    public static DashboardLayout Layout { get; } = new()
    {
        Tiles =
        [
            new DashboardTile { Id = "summary", Type = DashboardTiles.Summary, X = 0, Y = 0, W = 12, H = 2 },
            new DashboardTile { Id = "alerts", Type = DashboardTiles.Alerts, X = 0, Y = 2, W = 12, H = 4 },
            new DashboardTile { Id = "rollup", Type = DashboardTiles.Rollup, X = 0, Y = 6, W = 12, H = 10 },
        ],
    };
}
