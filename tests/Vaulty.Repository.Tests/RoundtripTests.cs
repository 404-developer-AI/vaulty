using System.Diagnostics;
using System.Text.Json;
using Vaulty.Core.Storage;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Xunit.Abstractions;

namespace Vaulty.Repository.Tests;

/// <summary>One synthetic item: a seed, a length and optionally an edit, so its bytes can be regenerated for comparison.</summary>
internal sealed record SyntheticItem(int Index, string Kind, ulong Seed, long Length, long InsertAt, byte[]? Insert)
{
    public SyntheticStream Open() => new(Seed, Length, InsertAt, Insert);
}

internal static class SyntheticCorpus
{
    /// <summary>
    /// Mail-like items of 2–200 KB and files of 1 KB–200 MB (log-uniform, few large ones), 30 % exact duplicates of an
    /// earlier item and 10 % new versions of an earlier file with a small insertion.
    /// </summary>
    public static List<SyntheticItem> Create(int count, int seed, long maxFile = 200L * 1024 * 1024)
    {
        var random = new Random(seed);
        var items = new List<SyntheticItem>(count);
        for (var i = 0; i < count; i++)
        {
            var roll = random.NextDouble();
            if (items.Count > 10 && roll < 0.30)
            {
                var original = items[random.Next(items.Count)];
                items.Add(original with { Index = i });
                continue;
            }
            if (items.Count > 10 && roll < 0.40)
            {
                var files = items.Where(x => x.Kind == "file" && x.InsertAt < 0).ToList();
                if (files.Count > 0)
                {
                    var original = files[random.Next(files.Count)];
                    var insert = new byte[random.Next(1, 200)];
                    random.NextBytes(insert);
                    items.Add(original with { Index = i, InsertAt = random.NextInt64(original.Length + 1), Insert = insert });
                    continue;
                }
            }
            var isMail = random.NextDouble() < 0.7;
            long length;
            if (isMail)
            {
                length = LogUniform(random, 2 * 1024, 200 * 1024);
            }
            else
            {
                var tier = random.NextDouble();
                length = tier < 0.95 ? LogUniform(random, 1024, 2 * 1024 * 1024)
                    : tier < 0.995 ? LogUniform(random, 2 * 1024 * 1024, 20 * 1024 * 1024)
                    : LogUniform(random, 20 * 1024 * 1024, maxFile);
            }
            items.Add(new SyntheticItem(i, isMail ? "mail" : "file", (ulong)random.NextInt64(), length, -1, null));
        }
        return items;
    }

    private static long LogUniform(Random random, long min, long max) =>
        (long)Math.Exp(Math.Log(min) + random.NextDouble() * (Math.Log(max) - Math.Log(min)));

    /// <summary>Backs up the corpus into snapshot <paramref name="snapshotId"/>, one manifest per 500 items.</summary>
    public static async Task<(SnapshotRoot Root, List<ItemContent> Contents)> BackupAsync(RepositoryWriter writer, Guid tenant,
        Guid objectId, Guid snapshotId, IReadOnlyList<SyntheticItem> items)
    {
        var contents = new List<ItemContent>(items.Count);
        var manifestIds = new List<byte[]>();
        foreach (var batch in items.Chunk(500))
        {
            var entries = new List<ManifestEntry>(batch.Length);
            foreach (var item in batch)
            {
                await using var stream = item.Open();
                var content = await writer.WriteAsync(stream);
                contents.Add(content);
                entries.Add(new ManifestEntry($"item-{item.Index}", "folder-" + (item.Index % 20), item.Kind,
                    JsonSerializer.Serialize(new { item.Index, item.Length }), content));
            }
            manifestIds.Add(await writer.WriteManifestAsync(new Manifest(objectId, entries)));
        }
        var root = new SnapshotRoot(tenant, objectId, snapshotId, new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero),
            SnapshotOutcome.Committed, JsonSerializer.Serialize(new { items = items.Count }), "[]", manifestIds);
        await writer.CommitSnapshotAsync(root);
        return (root, contents);
    }
}

public class RoundtripTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Ten_thousand_items_round_trip_byte_identical()
    {
        var count = int.TryParse(Environment.GetEnvironmentVariable("VAULTY_ROUNDTRIP_ITEMS"), out var n) ? n : 10_000;
        var items = SyntheticCorpus.Create(count, seed: 20261109);
        var store = new InMemoryObjectStore();
        using var keys = TestKeys.Random();
        var index = new InMemoryChunkIndex();
        var writer = Writers.Create(store, keys, index, packSize: 32 * 1024 * 1024);
        var objectId = Guid.NewGuid();
        var snapshotId = Guid.NewGuid();

        var writeTime = Stopwatch.StartNew();
        var (root, _) = await SyntheticCorpus.BackupAsync(writer, keys.TenantId, objectId, snapshotId, items);
        writeTime.Stop();

        // Read everything back through the snapshot, as a restore would: snapshot → manifests → chunks.
        var reader = new RepositoryReader(store, keys, index);
        var readTime = Stopwatch.StartNew();
        var snapshot = await reader.ReadSnapshotAsync(objectId, snapshotId);
        Assert.Equal(root.RootHash, snapshot.RootHash);
        var restored = 0;
        foreach (var manifestId in snapshot.ManifestIds)
        {
            var manifest = await reader.ReadManifestAsync(manifestId);
            foreach (var entry in manifest.Entries)
            {
                var item = items[int.Parse(entry.SourceId["item-".Length..], System.Globalization.CultureInfo.InvariantCulture)];
                using var restoredHash = new HashingStream();
                await reader.ReadContentAsync(entry.Content!, restoredHash);
                await using var source = item.Open();
                Assert.Equal(await HashingStream.Of(source), restoredHash.Hash());
                Assert.Equal(item.Open().TotalLength, restoredHash.Written);
                restored++;
            }
        }
        readTime.Stop();
        Assert.Equal(items.Count, restored);

        // Every pack verifies in full.
        foreach (var pack in writer.PacksWritten) await reader.VerifyPackAsync(pack);

        var stats = writer.Statistics;
        var dedup = stats.BytesIn / (double)stats.BytesNew;
        var compression = stats.BytesNew / (double)stats.BytesStored;
        output.WriteLine($"items={items.Count} bytesIn={stats.BytesIn} unique={stats.BytesNew} stored={store.TotalBytes} " +
                         $"packs={stats.PacksWritten} chunks={stats.ChunksIn} dedupChunks={stats.ChunksDeduplicated}");
        output.WriteLine($"dedup ratio={dedup:F3} compression ratio={compression:F3} " +
                         $"write={stats.BytesIn / 1048576.0 / writeTime.Elapsed.TotalSeconds:F1} MB/s " +
                         $"read={stats.BytesIn / 1048576.0 / readTime.Elapsed.TotalSeconds:F1} MB/s (single thread)");
        Assert.True(dedup > 1.2, "duplicates and versions must be deduplicated");
    }

    [Fact]
    public async Task The_index_rebuilt_from_object_storage_restores_without_a_database()
    {
        var items = SyntheticCorpus.Create(300, seed: 5, maxFile: 4 * 1024 * 1024);
        var store = new InMemoryObjectStore();
        using var keys = TestKeys.Random();
        var writer = Writers.Create(store, keys, new InMemoryChunkIndex(), packSize: 512 * 1024);
        var objectId = Guid.NewGuid();
        var snapshotId = Guid.NewGuid();
        await SyntheticCorpus.BackupAsync(writer, keys.TenantId, objectId, snapshotId, items);

        // Only the object store and the keys: no index from the writer.
        var rebuilt = await IndexRebuilder.RebuildAsync(store, keys);
        var reader = new RepositoryReader(store, keys, rebuilt);
        Assert.Equal(snapshotId, await reader.ReadLatestAsync(objectId));
        Assert.Equal([snapshotId], await reader.ListSnapshotsAsync(objectId));
        var snapshot = await reader.ReadSnapshotAsync(objectId, snapshotId);
        var count = 0;
        foreach (var id in snapshot.ManifestIds)
        {
            foreach (var entry in (await reader.ReadManifestAsync(id)).Entries)
            {
                using var sink = new HashingStream();
                await reader.ReadContentAsync(entry.Content!, sink);
                count++;
            }
        }
        Assert.Equal(items.Count, count);
    }

    [Fact]
    public async Task A_flipped_bit_in_a_pack_is_detected_on_read_and_on_verification()
    {
        var store = new InMemoryObjectStore();
        using var keys = TestKeys.Random();
        var index = new InMemoryChunkIndex();
        var writer = Writers.Create(store, keys, index);
        var content = await writer.WriteAsync(new SyntheticStream(3, 3 * 1024 * 1024));
        await writer.FlushAsync();
        var packKey = RepositoryLayout.Pack(keys.TenantId, writer.PacksWritten[0]);
        store.CorruptBit(packKey, PackFormat.HeaderSize + ChunkCodec.HeaderSize + 100);

        var reader = new RepositoryReader(store, keys, index);
        await Assert.ThrowsAnyAsync<IntegrityException>(() => reader.ReadContentAsync(content, new HashingStream()));
        await Assert.ThrowsAnyAsync<IntegrityException>(() => reader.VerifyPackAsync(writer.PacksWritten[0]));
    }
}
