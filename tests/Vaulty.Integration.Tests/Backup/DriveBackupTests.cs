using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Connectors.Drive;
using Vaulty.Core.Abstractions;
using Vaulty.Graph;
using Vaulty.Graph.Http;
using Vaulty.Integration.Tests.Temporal;
using Vaulty.Integration.Tests.Tenants;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Vaulty.Workflows.Backup;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Backup;

public sealed class DriveBackupTests(TemporalFixture fixture, ITestOutputHelper output) : IClassFixture<TemporalFixture>
{
    private static Func<string, byte[]?> Source(DriveSimulator simulator) => id =>
    {
        var at = id.IndexOf('@', StringComparison.Ordinal);
        if (at < 0) return simulator.Nodes.TryGetValue(id, out var node) && !node.IsFolder ? node.Data : null;
        var file = simulator.Nodes[id[..at]];
        return DriveSimulator.Content(file.Id, int.Parse(id[(at + 1)..].Split('.')[0], System.Globalization.CultureInfo.InvariantCulture), file.Size);
    };

    [TemporalFact]
    public async Task A_full_backup_and_incremental_runs_match_the_drive_file_for_file()
    {
        using var simulator = new DriveSimulator(files: 70);
        await using var harness = new BackupHarness(fixture, simulator.Url, Source(simulator));
        await harness.SeedTenantAsync();
        var drive = await harness.SeedDriveAsync(DriveSimulator.DriveId);
        harness.StartWorker();

        var random = new Random(7);
        var renamed = "";
        for (var run = 0; run < 4; run++)
        {
            var downloadsBefore = simulator.Downloads.Values.Sum();
            if (run == 1)
            {
                for (var i = 0; i < 8; i++) simulator.AddFile(simulator.Folders.ElementAt(random.Next(3)).Id, random.Next(1_000, 200_000));
                foreach (var file in simulator.Files.OrderBy(_ => random.Next()).Take(5).ToList()) simulator.Edit(file.Id);
                foreach (var file in simulator.Files.OrderBy(_ => random.Next()).Take(4).ToList()) simulator.Remove(file.Id);
            }
            if (run == 2)
            {
                renamed = simulator.Files.First().Id;
                simulator.Rename(renamed, "Renamed report.docx");
            }
            if (run == 3)
            {
                // A whole folder goes: its files leave the snapshot with it.
                var archive = simulator.Folders.Single(f => f.Name == "Archive");
                simulator.Remove(archive.Id);
                foreach (var child in simulator.Files.Where(f => f.ParentId == archive.Id).ToList()) simulator.Nodes.Remove(child.Id);
            }

            var (outcome, snapshotId) = await harness.DriveBackupAsync(drive);
            Assert.False(outcome.IsPartial, $"run {run}: partial with {outcome.Exceptions} exceptions");
            var entries = await harness.ReadSnapshotAsync(drive, snapshotId);
            var files = entries.Where(e => e.Kind == "file").Select(e => e.SourceId).Order(StringComparer.Ordinal).ToList();
            Assert.Equal(simulator.Files.Select(f => f.Id).Order(StringComparer.Ordinal), files);
            Assert.Equal(simulator.Folders.Select(f => f.Id).Order(StringComparer.Ordinal), entries.Where(e => e.Kind == "folder").Select(e => e.SourceId).Order(StringComparer.Ordinal));
            Assert.Equal(simulator.Files.Count(), outcome.ItemCounts["file"]);
            var versions = entries.Where(e => e.Kind == "file_version").ToList();
            Assert.All(versions, v => Assert.Contains(v.SourceId[..v.SourceId.IndexOf('@', StringComparison.Ordinal)], files));
            Assert.Equal(simulator.Files.Sum(f => Math.Min(f.Version - 1, DriveActivities.VersionsToKeep)), versions.Count);

            if (run == 2)
            {
                // A rename is a new version with the new name, without downloading the content again.
                Assert.Equal(downloadsBefore, simulator.Downloads.Values.Sum());
                using var metadata = JsonDocument.Parse(entries.Single(e => e.SourceId == renamed).Metadata);
                Assert.Equal("Renamed report.docx", metadata.RootElement.GetProperty("name").GetString());
            }
            output.WriteLine($"run {run}: {files.Count} files, {versions.Count} older versions, {simulator.Downloads.Values.Sum() - downloadsBefore} downloads");
        }

        var shared = simulator.Files.First(f => f.Shared);
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        Assert.Equal(4, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.snapshots WHERE protected_object_id = @drive AND state = 'committed'", new { drive }));
        var last = await harness.ReadSnapshotAsync(drive, await owner.ExecuteScalarAsync<Guid>(
            "SELECT id FROM vaulty.snapshots WHERE protected_object_id = @drive ORDER BY started_at DESC LIMIT 1", new { drive }), compareWithSource: false);
        using var permissions = JsonDocument.Parse(last.Single(e => e.SourceId == shared.Id).Metadata);
        Assert.Equal("organization", permissions.RootElement.GetProperty("permissions")[0].GetProperty("link").GetProperty("scope").GetString());
    }

    [TemporalFact]
    public async Task A_download_that_does_not_match_its_hash_makes_the_snapshot_partial()
    {
        using var simulator = new DriveSimulator(files: 12, seed: 4);
        await using var harness = new BackupHarness(fixture, simulator.Url, Source(simulator));
        await harness.SeedTenantAsync();
        var drive = await harness.SeedDriveAsync(DriveSimulator.DriveId);
        harness.StartWorker();
        var corrupt = simulator.Files.First().Id;
        simulator.CorruptHashes.Add(corrupt);

        var (outcome, snapshotId) = await harness.DriveBackupAsync(drive);
        Assert.True(outcome.IsPartial);
        Assert.Equal(1, outcome.Exceptions);
        Assert.Equal(simulator.Files.Count() - 1, outcome.ItemCounts["file"]);
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        Assert.Equal("hash_mismatch", await owner.ExecuteScalarAsync<string>(
            "SELECT error_code FROM vaulty.item_failures WHERE source_id = @corrupt AND last_snapshot_id = @snapshotId", new { corrupt, snapshotId }));

        // Once the transfer is right again, the next run picks the file up and the snapshot is complete.
        simulator.CorruptHashes.Clear();
        var (second, _) = await harness.DriveBackupAsync(drive);
        Assert.False(second.IsPartial, $"{second.Exceptions} exceptions");
        Assert.Equal(simulator.Files.Count(), second.ItemCounts["file"]);
    }

    [TemporalFact]
    public async Task Versions_of_one_file_share_their_chunks()
    {
        using var simulator = new DriveSimulator(files: 0, seed: 2);
        var file = simulator.AddFile(DriveSimulator.RootId, 12 * 1024 * 1024, name: "Budget.xlsx");
        for (var i = 0; i < 3; i++) simulator.Edit(file.Id);
        await using var harness = new BackupHarness(fixture, simulator.Url, Source(simulator));
        await harness.SeedTenantAsync();
        var drive = await harness.SeedDriveAsync(DriveSimulator.DriveId);
        harness.StartWorker();

        var (outcome, snapshotId) = await harness.DriveBackupAsync(drive);
        Assert.False(outcome.IsPartial);
        Assert.Equal(3, outcome.ItemCounts["file_version"]);
        await harness.ReadSnapshotAsync(drive, snapshotId);

        long logical = 4L * file.Size;
        long stored = 0;
        await foreach (var info in harness.Store.ListAsync(""))
        {
            if (info.Key.Contains("/packs/", StringComparison.Ordinal)) stored += info.Size;
        }
        var ratio = (double)logical / stored;
        output.WriteLine($"4 versions of {file.Size / 1024 / 1024} MiB: {logical / 1024 / 1024} MiB logical, {stored / 1024.0 / 1024:F1} MiB stored, dedup ratio {ratio:F2}");
        Assert.True(ratio > 2.5, $"dedup ratio {ratio:F2}");
    }
}

[Collection(MeasurementsCollection.Name)]
public sealed class LargeFileStreamingTests(ITestOutputHelper output)
{
    /// <summary>
    /// A 2 GB file streamed from a download URL through the repository engine: the connection breaks once, the download
    /// resumes with Range from the last byte, the QuickXorHash matches, and the process stays well under 256 MB extra memory.
    /// </summary>
    [Fact]
    public async Task A_2_GB_file_streams_with_bounded_memory_and_resumes_after_a_network_failure()
    {
        const long size = 2L * 1024 * 1024 * 1024;
        var content = new GeneratedFile(size);
        var hash = new QuickXorHash();
        var buffer = new byte[1024 * 1024];
        for (long at = 0; at < size; at += buffer.Length)
        {
            content.Fill(at, buffer);
            hash.Append(buffer);
        }
        var item = new DriveItem
        {
            Id = "big", Name = "Video.mp4", Size = size, DownloadUrl = "https://contoso.sharepoint.com/dl/big?tempauth=example",
            File = new FileFacet { Hashes = new FileHashes { QuickXorHash = Convert.ToBase64String(hash.Finish()) } },
        };
        var network = new BigFileHandler(content, item, breakAt: 700L * 1024 * 1024);
        var throttle = new GraphThrottle();
        var graph = new GraphClient(GraphPipeline.Create(new ScriptedTokens(), throttle, network), new Uri("https://graph.example.com/v1.0/"));
        var drive = new DriveClient(graph, new GraphDownloadClient(throttle, network));
        var store = new CountingStore();
        var writer = new RepositoryWriter(store, new RepositoryKeys(Guid.NewGuid(), new Dictionary<int, byte[]> { [1] = RandomNumberGenerator.GetBytes(32) }),
            new InMemoryChunkIndex(), new RepositoryWriterOptions { LockUntil = DateTimeOffset.UtcNow.AddDays(1), PackTargetSize = 32 * 1024 * 1024 });

        GC.Collect();
        GC.WaitForPendingFinalizers();
        var baseline = Process.GetCurrentProcess().WorkingSet64;
        long peak = baseline;
        using var stop = new CancellationTokenSource();
        var sampler = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                peak = Math.Max(peak, Process.GetCurrentProcess().WorkingSet64);
                await Task.Delay(50);
            }
        });
        var watch = Stopwatch.StartNew();
        ItemContent stored;
        await using (var stream = drive.OpenFile(new GraphRequestContext(Guid.NewGuid(), Workload: "drive"), "drive", item))
        {
            stored = await writer.WriteAsync(stream);
        }
        await writer.FlushAsync();
        await stop.CancelAsync();
        await sampler;

        var extra = (peak - baseline) / 1024 / 1024;
        output.WriteLine($"2 GiB in {watch.Elapsed.TotalSeconds:F0} s, {network.Resumes} resume(s), {network.ItemRefreshes} URL refresh(es), "
            + $"{store.Bytes / 1024 / 1024} MiB stored in {store.Objects} objects, peak working set +{extra} MiB");
        Assert.Equal(size, stored.Size);
        Assert.Equal(1, network.Resumes);
        Assert.Equal(1, network.ItemRefreshes);
        Assert.True(extra < 256, $"peak working set grew by {extra} MiB");
    }

    /// <summary>Deterministic incompressible content that can be produced from any offset.</summary>
    private sealed class GeneratedFile(long size)
    {
        private const int Block = 64 * 1024;
        public long Size { get; } = size;

        public void Fill(long offset, Span<byte> target)
        {
            var block = new byte[Block];
            var written = 0;
            while (written < target.Length && offset + written < Size)
            {
                var position = offset + written;
                var index = position / Block;
                ulong state = (ulong)index * 0x9E3779B97F4A7C15UL + 1;
                for (var i = 0; i < Block; i += 8)
                {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    BitConverter.TryWriteBytes(block.AsSpan(i), state);
                }
                var from = (int)(position % Block);
                var count = (int)Math.Min(Math.Min(Block - from, target.Length - written), Size - position);
                block.AsSpan(from, count).CopyTo(target[written..]);
                written += count;
            }
        }
    }

    /// <summary>Serves the item (with a fresh download URL) and the download with Range; the first download breaks once.</summary>
    private sealed class BigFileHandler(GeneratedFile file, DriveItem item, long breakAt) : HttpMessageHandler
    {
        private bool _broken;
        public int Resumes { get; private set; }
        public int ItemRefreshes { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!;
            if (url.Host == "graph.example.com")
            {
                ItemRefreshes++;
                var json = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["id"] = item.Id, ["size"] = item.Size, ["@microsoft.graph.downloadUrl"] = "https://contoso.sharepoint.com/dl/big?tempauth=fresh",
                });
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });
            }
            Assert.Null(request.Headers.Authorization);
            var offset = request.Headers.Range?.Ranges.First().From ?? 0;
            if (offset > 0) Resumes++;
            var response = new HttpResponseMessage(offset > 0 ? HttpStatusCode.PartialContent : HttpStatusCode.OK)
            {
                Content = new StreamContent(new GeneratedStream(file, offset, _broken ? long.MaxValue : breakAt)),
            };
            _broken = true;
            response.Content.Headers.ContentLength = file.Size - offset;
            if (offset > 0) response.Content.Headers.ContentRange = new ContentRangeHeaderValue(offset, file.Size - 1, file.Size);
            return Task.FromResult(response);
        }
    }

    private sealed class GeneratedStream(GeneratedFile file, long position, long breakAt) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => file.Size;
        public override long Position { get => position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (position >= breakAt) throw new IOException("The connection was reset by the test.");
            var count = (int)Math.Min(Math.Min(buffer.Length, file.Size - position), breakAt - position);
            if (count <= 0) return 0;
            file.Fill(position, buffer[..count]);
            position += count;
            return count;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.FromResult(Read(buffer.Span));
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => Task.FromResult(Read(buffer.AsSpan(offset, count)));
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>An object store that reads and counts what it receives and keeps nothing.</summary>
    private sealed class CountingStore : IObjectStore
    {
        public long Bytes { get; private set; }
        public int Objects { get; private set; }

        public async Task<ObjectInfo> PutAsync(string key, Stream content, ObjectPutOptions options, CancellationToken cancellationToken = default)
        {
            var buffer = new byte[81920];
            long size = 0;
            int read;
            while ((read = await content.ReadAsync(buffer, cancellationToken)) > 0) size += read;
            Bytes += size;
            Objects++;
            return new ObjectInfo(key, size, null, options.LockUntil, DateTimeOffset.UtcNow);
        }

        public Task<Stream> GetAsync(string key, ByteRange? range = null, CancellationToken cancellationToken = default) => throw new ObjectNotFoundException(key);
        public Task<ObjectInfo?> HeadAsync(string key, CancellationToken cancellationToken = default) => Task.FromResult<ObjectInfo?>(null);
        public async IAsyncEnumerable<ObjectInfo> ListAsync(string prefix, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            yield break;
        }

        public Task DeleteAsync(string key, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
