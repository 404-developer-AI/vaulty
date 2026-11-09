using Vaulty.Core.Storage;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Xunit.Abstractions;

namespace Vaulty.Repository.Tests;

/// <summary>
/// The engine dies at a random fault point (between encoding, pack upload, index file, index update, manifest and
/// snapshot); the next run of the same backup must produce exactly the snapshot of an undisturbed run, every chunk the
/// snapshot references must be readable, and packs that no index references are reported as orphans.
/// </summary>
public class CrashInjectionTests(ITestOutputHelper output)
{
    private const int Runs = 50;

    [Fact]
    public async Task Fifty_crashes_at_random_points_end_in_the_same_snapshot_as_an_undisturbed_run()
    {
        var items = SyntheticCorpus.Create(250, seed: 11, maxFile: 2 * 1024 * 1024);
        var objectId = Guid.NewGuid();
        var snapshotId = Guid.NewGuid();

        // Undisturbed reference run; also counts the fault points.
        var counting = new CountingFaults();
        using var referenceKeys = TestKeys.Fixed();
        var referenceStore = new InMemoryObjectStore();
        var referenceWriter = Writers.Create(referenceStore, referenceKeys, new InMemoryChunkIndex(), 64 * 1024, SmallChunks.Options, counting);
        var (reference, _) = await SyntheticCorpus.BackupAsync(referenceWriter, TestKeys.Tenant, objectId, snapshotId, items);
        var referenceSnapshot = referenceStore.Raw(RepositoryLayout.Snapshot(TestKeys.Tenant, objectId, snapshotId));
        output.WriteLine($"fault points per run: {counting.Hits}");

        var random = new Random(20261109);
        var orphansTotal = 0;
        var crashCount = 0;
        for (var run = 0; run < Runs; run++)
        {
            using var keys = TestKeys.Fixed();
            var store = new InMemoryObjectStore();
            var index = new InMemoryChunkIndex(); // stands in for the database: survives the crash
            var crashes = 1 + run % 3;           // one to three crashes before the run completes
            for (var c = 0; c < crashes; c++)
            {
                // A rerun after a crash reaches fewer fault points (stored chunks are skipped), so the chosen point may
                // lie beyond its end; then that attempt simply completes.
                var crash = new CrashAt(random.Next(1, counting.Hits + 1));
                var writer = Writers.Create(store, keys, index, 64 * 1024, SmallChunks.Options, crash);
                try
                {
                    await SyntheticCorpus.BackupAsync(writer, TestKeys.Tenant, objectId, snapshotId, items);
                }
                catch (SimulatedCrashException)
                {
                    crashCount++;
                }
            }

            var final = Writers.Create(store, keys, index, 64 * 1024, SmallChunks.Options);
            var (root, contents) = await SyntheticCorpus.BackupAsync(final, TestKeys.Tenant, objectId, snapshotId, items);

            Assert.Equal(reference.RootHash, root.RootHash);
            Assert.Equal(referenceSnapshot, store.Raw(RepositoryLayout.Snapshot(TestKeys.Tenant, objectId, snapshotId)));

            // No referenced chunk is missing, and every item is byte-identical.
            var reader = new RepositoryReader(store, keys, index);
            for (var i = 0; i < items.Count; i++)
            {
                using var sink = new HashingStream();
                await reader.ReadContentAsync(contents[i], sink);
                await using var source = items[i].Open();
                Assert.Equal(await HashingStream.Of(source), sink.Hash());
            }

            // The same holds with an index rebuilt from object storage alone.
            var rebuilt = await IndexRebuilder.RebuildAsync(store, keys);
            foreach (var chunk in contents.SelectMany(c => c.Chunks).Distinct())
            {
                Assert.NotNull(await rebuilt.FindAsync(chunk));
            }

            orphansTotal += await CountOrphansAsync(store, index);
        }
        output.WriteLine($"{Runs} runs with {crashCount} crashes identical to the undisturbed run; orphan packs reported: {orphansTotal}");
        Assert.True(crashCount >= Runs, $"only {crashCount} crashes happened");
    }

    /// <summary>Packs in the store that the index does not reference (left by a crash before the index update).</summary>
    internal static async Task<int> CountOrphansAsync(InMemoryObjectStore store, IChunkIndex index)
    {
        var known = new HashSet<string>(StringComparer.Ordinal);
        await foreach (var hash in index.PackHashesAsync()) known.Add(hash);
        return store.Keys.Where(k => k.EndsWith(".pack", StringComparison.Ordinal))
            .Count(k => !known.Contains(RepositoryLayout.PackHashFromKey(k)));
    }
}
