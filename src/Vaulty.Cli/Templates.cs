using System.Globalization;
using System.Text.RegularExpressions;

namespace Vaulty.Cli;

/// <summary>Renders the templates of a release ({{NAME}} placeholders). A placeholder without a value is an error, never left in place.</summary>
public static partial class Templates
{
    public static string Render(string template, IReadOnlyDictionary<string, string> values, string name)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(values);
        var missing = new SortedSet<string>(StringComparer.Ordinal);
        var rendered = Placeholder().Replace(template, m =>
        {
            if (values.TryGetValue(m.Groups[1].Value, out var value)) return value;
            missing.Add(m.Groups[1].Value);
            return m.Value;
        });
        if (missing.Count > 0) throw new InstallException($"template {name} needs values for {string.Join(", ", missing)}.");
        return rendered;
    }

    public static IReadOnlySet<string> PlaceholdersOf(string template) =>
        Placeholder().Matches(template).Select(m => m.Groups[1].Value).ToHashSet(StringComparer.Ordinal);

    [GeneratedRegex(@"\{\{([A-Z0-9_]+)\}\}")]
    private static partial Regex Placeholder();
}

public sealed record HostFacts(string Hostname, int Vcpu, long RamMb, bool Tpm2, string OsId, string OsVersion, string Architecture);

/// <summary>Sizes derived from the host: PostgreSQL tuning and memory limits per unit, so workers never crowd out the database or the UI.</summary>
public static class Tuning
{
    public static int DefaultWorkers(int vcpu) => Math.Max(1, vcpu / 2);

    public static Dictionary<string, string> Values(HostFacts host, int workers)
    {
        ArgumentNullException.ThrowIfNull(host);
        var ram = Math.Max(1024, host.RamMb);
        var maxConnections = 200;
        // PostgreSQL and Valkey take "MB"/"GB"; systemd takes "M"/"G" and ignores a limit it cannot parse ("680MB").
        string Mb(long mb) => mb >= 1024 && mb % 1024 == 0 ? $"{mb / 1024}GB" : $"{mb}MB";
        string Unit(long mb) => mb >= 1024 && mb % 1024 == 0 ? $"{mb / 1024}G" : $"{mb}M";
        var shared = ram / 4;
        var workMem = Math.Clamp(ram / 4 / maxConnections, 4, 64);
        var parallel = Math.Max(2, host.Vcpu);
        // Of the rest after PostgreSQL's share: the workers get half, web, API and gc share the remainder.
        var forServices = ram - shared - 512;
        var workerMax = Math.Max(512, forServices / 2 / Math.Max(1, workers));
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["MAX_CONNECTIONS"] = maxConnections.ToString(CultureInfo.InvariantCulture),
            ["SHARED_BUFFERS"] = Mb(shared),
            ["EFFECTIVE_CACHE_SIZE"] = Mb(ram * 3 / 4),
            ["WORK_MEM"] = Mb(workMem),
            ["MAINTENANCE_WORK_MEM"] = Mb(Math.Min(1024, ram / 16)),
            ["MAX_WORKER_PROCESSES"] = Math.Max(8, parallel).ToString(CultureInfo.InvariantCulture),
            ["MAX_PARALLEL_WORKERS"] = parallel.ToString(CultureInfo.InvariantCulture),
            ["MAX_PARALLEL_WORKERS_PER_GATHER"] = Math.Max(1, parallel / 4).ToString(CultureInfo.InvariantCulture),
            ["MAX_PARALLEL_MAINTENANCE_WORKERS"] = Math.Max(1, parallel / 4).ToString(CultureInfo.InvariantCulture),
            ["WEB_MEMORY_MAX"] = Unit(Math.Max(512, forServices / 8)),
            ["API_MEMORY_MAX"] = Unit(Math.Max(512, forServices / 8)),
            ["GC_MEMORY_MAX"] = Unit(Math.Max(512, forServices / 8)),
            ["WORKER_MEMORY_MAX"] = Unit(workerMax),
            ["VALKEY_MAXMEMORY"] = Mb(Math.Clamp(ram / 32, 64, 1024)),
            ["TEMPORAL_HISTORY_SHARDS"] = "512",
            ["GITHUB_REPO"] = Updater.Repository,
        };
    }
}

/// <summary>
/// The recovery copy of the master key in words: each of the 32 bytes is one word from a fixed list of 256, shown as eight
/// groups of four. Easier to type from paper than base64; <see cref="Decode"/> accepts either form.
/// </summary>
public static class KeyWords
{
    private static readonly string[] Words =
    [
        "acid", "acorn", "actor", "adapt", "agent", "alarm", "album", "alert", "alpha", "amber", "angle", "apple", "april", "arena", "argue", "armor",
        "arrow", "aspen", "atlas", "audio", "autumn", "award", "badge", "baker", "bamboo", "banjo", "baron", "basil", "beach", "beard", "bench", "berry",
        "bison", "blade", "blank", "blaze", "bloom", "board", "bonus", "boost", "brave", "bread", "brick", "bridge", "brook", "brush", "bucket", "buddy",
        "cabin", "cable", "cactus", "camel", "canal", "candle", "canoe", "canyon", "cargo", "carpet", "castle", "cedar", "chalk", "charm", "chess", "chief",
        "cider", "cinema", "circle", "clamp", "cliff", "clock", "cloud", "clover", "coast", "cobalt", "cocoa", "comet", "coral", "cotton", "couch", "crane",
        "crater", "cream", "crest", "cricket", "crown", "crystal", "cube", "dairy", "daisy", "dance", "delta", "desert", "diamond", "diesel", "dingo", "dolphin",
        "donkey", "dragon", "drift", "drum", "eagle", "earth", "echo", "eclipse", "elbow", "ember", "engine", "epoch", "falcon", "fancy", "feather", "fence",
        "fern", "ferry", "fiber", "field", "finch", "flame", "flint", "flute", "forest", "fossil", "fox", "frost", "galaxy", "garden", "garlic", "gecko",
        "geyser", "ginger", "glacier", "globe", "goose", "granite", "grape", "gravel", "habit", "hammer", "harbor", "hazel", "helmet", "heron", "honey", "hornet",
        "hotel", "humble", "igloo", "island", "ivory", "jacket", "jaguar", "jasmine", "jelly", "jungle", "kayak", "kernel", "kettle", "kiwi", "koala", "ladder",
        "lagoon", "lantern", "laser", "lemon", "lily", "linen", "lizard", "llama", "lobster", "lotus", "magnet", "mango", "maple", "marble", "meadow", "melon",
        "meteor", "mint", "mirror", "monkey", "mosaic", "motor", "muffin", "nectar", "needle", "nickel", "noodle", "nutmeg", "oasis", "ocean", "olive", "onion",
        "opal", "orange", "orbit", "orchid", "otter", "owl", "oyster", "paddle", "palace", "panda", "panther", "parrot", "pebble", "pepper", "piano", "pigeon",
        "pillow", "pine", "planet", "plum", "polar", "pony", "poppy", "prism", "puffin", "pumpkin", "quartz", "quilt", "rabbit", "radar", "raven", "reef",
        "ribbon", "river", "robin", "rocket", "saddle", "salmon", "sapphire", "satin", "shell", "silver", "sketch", "sparrow", "spider", "spruce", "squid", "stone",
        "sunset", "swan", "tiger", "timber", "tomato", "topaz", "tulip", "tundra", "turtle", "velvet", "violet", "walnut", "willow", "yellow", "zebra", "zinc",
    ];

    public static string Encode(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new ArgumentException("The master key has 32 bytes.", nameof(key));
        var words = new string[32];
        for (var i = 0; i < 32; i++) words[i] = Words[key[i]];
        return string.Join("  ", Enumerable.Range(0, 8).Select(g => string.Join(' ', words.Skip(g * 4).Take(4))));
    }

    public static byte[] Decode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var trimmed = text.Trim();
        var parts = trimmed.Split([' ', '\t', '\n', '\r', '-'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 32)
        {
            var key = new byte[32];
            for (var i = 0; i < 32; i++)
            {
                var index = Array.IndexOf(Words, parts[i].ToLowerInvariant());
                if (index < 0) throw new InstallException($"'{parts[i]}' is not a recovery word (word {i + 1}).");
                key[i] = (byte)index;
            }
            return key;
        }
        try
        {
            var key = Convert.FromBase64String(trimmed);
            return key.Length == 32 ? key : throw new InstallException("The recovery copy must decode to 32 bytes.");
        }
        catch (FormatException)
        {
            throw new InstallException("Give the recovery copy as base64 or as its 32 words.");
        }
    }

    internal static int Count => Words.Length;
    internal static int Distinct => Words.Distinct(StringComparer.Ordinal).Count();
}
