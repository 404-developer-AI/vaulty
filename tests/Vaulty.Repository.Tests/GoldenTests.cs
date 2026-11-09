using System.Security.Cryptography;
using Vaulty.Core.Storage;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;

namespace Vaulty.Repository.Tests;

/// <summary>
/// Format version 1 is frozen: fixed keys and fixed input produce these exact bytes (docs/format/repository-v1.md §9), and
/// the committed golden repository under Golden/v1 must stay readable by every future version.
/// </summary>
public class GoldenTests
{
    private static readonly string GoldenDir = Path.Combine(AppContext.BaseDirectory, "Golden", "v1");

    private static async Task<(InMemoryObjectStore Store, SnapshotRoot Root)> WriteGoldenAsync(RepositoryKeys keys)
    {
        var store = new InMemoryObjectStore();
        var writer = Writers.Create(store, keys, new InMemoryChunkIndex(), 1024 * 1024, SmallChunks.Options);
        var items = new[]
        {
            new SyntheticItem(0, "mail", 1, 5_000, -1, null),
            new SyntheticItem(1, "file", 2, 40_000, -1, null),
            new SyntheticItem(2, "file", 2, 40_000, 20_000, "inserted"u8.ToArray()),
        };
        var (root, _) = await SyntheticCorpus.BackupAsync(writer, TestKeys.Tenant, TestKeys.Object,
            Guid.Parse("00000000-0000-7000-8000-000000000001"), items);
        return (store, root);
    }

    [Fact]
    public void Chunk_record_vector()
    {
        using var keys = TestKeys.Fixed();
        var plaintext = "Vaulty repository format v1"u8.ToArray();
        var id = ChunkId.Compute(keys.ChunkIdKey, plaintext);
        Assert.Equal(ChunkIdVector, id.Hex);
        Assert.Equal(RecordVector, Convert.ToHexStringLower(ChunkCodec.Encode(keys, id, plaintext)));
    }

    [Fact]
    public async Task The_same_input_always_produces_the_same_repository()
    {
        using var keys = TestKeys.Fixed();
        var (store, root) = await WriteGoldenAsync(keys);
        Assert.Equal(RootVector, Convert.ToHexStringLower(root.RootHash));
        var listing = string.Join("\n", store.Keys.Where(k => !k.EndsWith("LATEST", StringComparison.Ordinal)).OrderBy(k => k, StringComparer.Ordinal)
            .Select(k => $"{k} {Convert.ToHexStringLower(SHA256.HashData(store.Raw(k)))}"));
        Assert.Equal(File.ReadAllText(Path.Combine(GoldenDir, "listing.txt")).ReplaceLineEndings("\n").Trim(), listing);
    }

    [Fact]
    public async Task The_committed_golden_repository_is_readable()
    {
        using var keys = TestKeys.Fixed();
        var store = new InMemoryObjectStore();
        foreach (var file in Directory.EnumerateFiles(Path.Combine(GoldenDir, "store"), "*", SearchOption.AllDirectories))
        {
            var key = Path.GetRelativePath(Path.Combine(GoldenDir, "store"), file).Replace('\\', '/');
            await store.PutAsync(key, File.OpenRead(file), new Core.Abstractions.ObjectPutOptions(null));
        }
        var reader = new RepositoryReader(store, keys, await IndexRebuilder.RebuildAsync(store, keys));
        var snapshot = await reader.ReadSnapshotAsync(TestKeys.Object, Guid.Parse("00000000-0000-7000-8000-000000000001"));
        Assert.Equal(RootVector, Convert.ToHexStringLower(snapshot.RootHash));
        var entries = (await reader.ReadManifestAsync(snapshot.ManifestIds[0])).Entries;
        Assert.Equal(3, entries.Count);
        using var sink = new HashingStream();
        await reader.ReadContentAsync(entries[2].Content!, sink);
        Assert.Equal(await HashingStream.Of(new SyntheticStream(2, 40_000, 20_000, "inserted"u8.ToArray())), sink.Hash());
    }

    /// <summary>Writes the golden files; run once with VAULTY_WRITE_GOLDEN=path-to-tests/Golden/v1 when the format is created.</summary>
    [Fact]
    public async Task Write_golden_files_when_asked()
    {
        var target = Environment.GetEnvironmentVariable("VAULTY_WRITE_GOLDEN");
        if (string.IsNullOrEmpty(target)) return;
        using var keys = TestKeys.Fixed();
        var (store, _) = await WriteGoldenAsync(keys);
        var lines = new List<string>();
        foreach (var key in store.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var path = Path.Combine(target, "store", key);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllBytesAsync(path, store.Raw(key));
            if (!key.EndsWith("LATEST", StringComparison.Ordinal)) lines.Add($"{key} {Convert.ToHexStringLower(SHA256.HashData(store.Raw(key)))}");
        }
        await File.WriteAllTextAsync(Path.Combine(target, "listing.txt"), string.Join("\n", lines) + "\n");
    }

    internal const string ChunkIdVector = "397a10e74b0583651edcae8022cda24995f8b3ab71991a44d108f12a27acf074"; // gitleaks:allow (public test vector)
    internal const string RecordVector = // gitleaks:allow (public test vector)
        "397a10e74b0583651edcae8022cda24995f8b3ab71991a44d108f12a27acf07400000000010000001b0000002bdd6207ad3fdcf78f65f01ffa3b47e011a938819bdf5a38c08e07bf88093ac9dc3ddc2522277888ee115d74"; // gitleaks:allow (public test vector)
    internal const string RootVector = "fea422bbedef3dd790548ff9376575b353fe2343488d271decc84c8972d0fd59"; // gitleaks:allow (public test vector)
}
