using FsCheck.Xunit;
using Vaulty.Core.Dashboards;
using Vaulty.Core.Security;

namespace Vaulty.Core.Tests;

public class DashboardTests
{
    private static DashboardLayout RandomLayout(Random random, int tiles)
    {
        var result = new List<DashboardTile>();
        for (var i = 0; i < tiles; i++)
        {
            var type = DashboardTiles.All[random.Next(DashboardTiles.All.Count)];
            var tile = new DashboardTile { Id = $"t{i}", Type = random.Next(10) == 0 ? "retired-or-unknown" : type.Key };
            result = [.. DashboardGrid.Add(result, tile, pullUp: random.Next(2) == 0)];
        }
        return new DashboardLayout { Tiles = result };
    }

    [Property(MaxTest = 300)]
    public bool No_layout_shows_a_tile_whose_permissions_the_viewer_lacks(int seed)
    {
        var random = new Random(seed);
        var layout = RandomLayout(random, random.Next(0, 25));
        var held = Permissions.All.Where(_ => random.Next(2) == 0).Select(p => p.Key).ToHashSet();
        var visible = DashboardRules.Visible(layout, held.Contains);
        return visible.All(v => v.Type.Permissions.Count > 0 && v.Type.Permissions.All(held.Contains))
               && visible.All(v => DashboardTiles.Find(v.Tile.Type) is not null);
    }

    [Property(MaxTest = 300)]
    public bool Placing_tiles_never_makes_them_overlap_or_leave_the_grid(int seed)
    {
        var random = new Random(seed);
        IReadOnlyList<DashboardTile> tiles = RandomLayout(random, random.Next(1, 20)).Tiles;
        for (var move = 0; move < 10; move++)
        {
            var tile = tiles[random.Next(tiles.Count)];
            tiles = DashboardGrid.Move(tiles, tile.Id, new GridRect(random.Next(-3, 15), random.Next(-3, 30), random.Next(0, 14), random.Next(0, 12)), random.Next(2) == 0);
        }
        var list = tiles.ToList();
        var overlap = list.SelectMany((a, i) => list.Skip(i + 1).Select(b => a.Rect.Overlaps(b.Rect))).Any(o => o);
        return !overlap && list.All(t => t.X >= 0 && t.Y >= 0 && t.Rect.Right <= DashboardGrid.Columns);
    }

    [Property(MaxTest = 500)]
    public bool No_column_layout_hides_the_name_or_the_status_of_a_row(int seed)
    {
        var random = new Random(seed);
        var list = ColumnCatalog.Lists.Keys.ElementAt(random.Next(ColumnCatalog.Lists.Count));
        var known = ColumnCatalog.Lists[list].Columns.Select(c => c.Key).ToList();
        // Any stored layout: some known keys in any order, duplicates, and keys that do not exist (or no longer do).
        var stored = Enumerable.Range(0, random.Next(0, 10))
            .Select(_ => random.Next(5) == 0 ? "gone" + random.Next(3) : known[random.Next(known.Count)]).ToList();
        var held = Permissions.All.Where(_ => random.Next(2) == 0).Select(p => p.Key).ToHashSet();
        var visible = ColumnCatalog.Visible(list, random.Next(4) == 0 ? null : stored, held.Contains);
        var catalog = ColumnCatalog.Lists[list].Columns;
        return catalog.Where(c => c.Required).All(c => visible.Contains(c.Key))
               && visible.Distinct().Count() == visible.Count
               && visible.All(k => catalog.Any(c => c.Key == k))
               && visible.All(k => catalog.First(c => c.Key == k).Permission is not { } p || held.Contains(p));
    }

    [Fact]
    public void Every_tile_needs_a_permission_and_every_list_names_and_shows_status()
    {
        Assert.All(DashboardTiles.All, t => Assert.NotEmpty(t.Permissions));
        Assert.All(ColumnCatalog.Lists, l => Assert.Contains(l.Value.Columns, c => c.Key == "status" && c.Required));
        Assert.All(ColumnCatalog.Lists, l => Assert.True(l.Value.Columns.Count(c => c.Required) >= 2));
    }

    [Fact]
    public void A_layout_with_overlaps_unknown_tiles_or_a_scope_on_a_note_is_refused()
    {
        var overlap = new DashboardLayout
        {
            Tiles =
            [
                new DashboardTile { Id = "a", Type = DashboardTiles.Summary, X = 0, Y = 0, W = 6, H = 2 },
                new DashboardTile { Id = "b", Type = DashboardTiles.Summary, X = 3, Y = 1, W = 6, H = 2 },
            ],
        };
        Assert.Contains("Two tiles overlap.", DashboardRules.Validate(overlap));
        Assert.NotEmpty(DashboardRules.Validate(new DashboardLayout { Tiles = [new DashboardTile { Id = "a", Type = "nope", W = 2, H = 2 }] }));
        Assert.NotEmpty(DashboardRules.Validate(new DashboardLayout
        {
            Tiles = [new DashboardTile { Id = "a", Type = DashboardTiles.Note, W = 4, H = 2, Settings = new TileSettings { Tag = "gold" } }],
        }));
        Assert.NotEmpty(DashboardRules.Validate(new DashboardLayout { Schema = 99 }));
        Assert.Empty(DashboardRules.Validate(DefaultDashboard.Layout));
    }

    [Fact]
    public void A_layout_keeps_fields_it_does_not_know_through_a_round_trip()
    {
        const string json = """{"schema":1,"pullUp":true,"future":{"a":1},"tiles":[{"id":"x","type":"summary","x":0,"y":0,"w":12,"h":2,"glow":"on","settings":{"title":"T","mood":3}}]}""";
        var back = DashboardLayout.FromJson(DashboardLayout.FromJson(json).ToJson()).ToJson();
        Assert.Contains("\"future\"", back, StringComparison.Ordinal);
        Assert.Contains("\"glow\"", back, StringComparison.Ordinal);
        Assert.Contains("\"mood\"", back, StringComparison.Ordinal);
    }

    [Fact]
    public void The_first_published_dashboard_by_priority_of_one_of_the_users_roles_wins()
    {
        var (r1, r2, r3) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        var (a, b, c) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        DashboardRules.Choice[] choices = [new(a, 1, false, [r1]), new(b, 2, true, [r1, r2]), new(c, 3, true, [r2])];
        Assert.Equal(b, DashboardRules.Pick(choices, [r1]));
        Assert.Equal(b, DashboardRules.Pick(choices, [r2]));
        Assert.Null(DashboardRules.Pick(choices, [r3]));
    }
}
