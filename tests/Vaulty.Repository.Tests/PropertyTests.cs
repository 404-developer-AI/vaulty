using FsCheck;
using FsCheck.Xunit;
using Vaulty.Repository.Chunking;
using Vaulty.Repository.Format;

namespace Vaulty.Repository.Tests;

public class ChunkerProperties
{
    private static byte[] Data(int seed, int size)
    {
        var bytes = new byte[size];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static async Task<List<byte[]>> Chunks(byte[] data, ChunkerOptions options, int readSize = int.MaxValue)
    {
        var result = new List<byte[]>();
        await FastCdc.ChunkAsync(new TrickleStream(data, readSize), options, c =>
        {
            result.Add(c.ToArray());
            return ValueTask.CompletedTask;
        });
        return result;
    }

    [Property(MaxTest = 200)]
    public bool Chunks_concatenate_to_the_input_and_respect_the_size_bounds(int seed, NonNegativeInt size, PositiveInt readSize)
    {
        var data = Data(seed, size.Get % 200_000);
        var chunks = Chunks(data, SmallChunks.Options, readSize.Get % 70_000 + 1).GetAwaiter().GetResult();
        var joined = chunks.SelectMany(c => c).ToArray();
        var boundsOk = chunks.Take(chunks.Count - 1).All(c => c.Length >= SmallChunks.Options.MinSize && c.Length <= SmallChunks.Options.MaxSize)
                       && (chunks.Count == 0 || chunks[^1].Length <= SmallChunks.Options.MaxSize);
        return joined.AsSpan().SequenceEqual(data) && boundsOk && (data.Length > 0 || chunks.Count == 0);
    }

    [Property(MaxTest = 100)]
    public bool Chunking_does_not_depend_on_how_the_stream_is_read(int seed, PositiveInt a, PositiveInt b)
    {
        var data = Data(seed, 150_000);
        var first = Chunks(data, SmallChunks.Options, a.Get % 50_000 + 1).GetAwaiter().GetResult();
        var second = Chunks(data, SmallChunks.Options, b.Get % 50_000 + 1).GetAwaiter().GetResult();
        return first.Select(c => c.Length).SequenceEqual(second.Select(c => c.Length));
    }

    [Property(MaxTest = 100)]
    public bool An_insertion_changes_only_the_chunks_around_it(int seed, NonNegativeInt position, byte[] insert)
    {
        var data = Data(seed, 200_000);
        var at = position.Get % data.Length;
        var edited = data[..at].Concat(insert ?? []).Concat(data[at..]).ToArray();
        var original = Chunks(data, SmallChunks.Options).GetAwaiter().GetResult().Select(Convert.ToHexString).ToHashSet();
        var changed = Chunks(edited, SmallChunks.Options).GetAwaiter().GetResult().Select(Convert.ToHexString).ToList();
        var newChunks = changed.Count(c => !original.Contains(c));
        // Content-defined boundaries resynchronize: only a few chunks near the edit are new.
        return newChunks <= 3;
    }

    [Fact]
    public async Task Items_smaller_than_the_minimum_are_one_chunk()
    {
        var chunks = await Chunks(Data(1, 200 * 1024), ChunkerOptions.Default);
        Assert.Single(chunks);
    }

    [Fact]
    public async Task Default_chunk_sizes_average_about_one_mebibyte()
    {
        var data = Data(7, 64 * 1024 * 1024);
        var chunks = await Chunks(data, ChunkerOptions.Default);
        var average = data.Length / (double)chunks.Count;
        Assert.InRange(average, 0.6 * 1024 * 1024, 1.6 * 1024 * 1024);
        Assert.All(chunks.SkipLast(1), c => Assert.InRange(c.Length, 256 * 1024, 4 * 1024 * 1024));
    }

    /// <summary>Returns at most a given number of bytes per read, to exercise buffer refills.</summary>
    private sealed class TrickleStream(byte[] data, int maxRead) : MemoryStream(data, writable: false)
    {
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(buffer.Length, maxRead)]);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Read(buffer.Span));
    }
}

public class FormatProperties
{
    private static readonly RepositoryKeys Keys = TestKeys.Fixed();

    [Property(MaxTest = 300)]
    public bool Chunk_records_round_trip(byte[] plaintext)
    {
        plaintext ??= [];
        var id = ChunkId.Compute(Keys.ChunkIdKey, plaintext);
        var record = ChunkCodec.Encode(Keys, id, plaintext);
        return ChunkCodec.Decode(Keys, record, id).AsSpan().SequenceEqual(plaintext)
               && record.AsSpan().SequenceEqual(ChunkCodec.Encode(Keys, id, plaintext)); // deterministic
    }

    [Property(MaxTest = 500)]
    public bool A_damaged_chunk_record_is_always_detected(byte[] plaintext, NonNegativeInt position, byte flip)
    {
        plaintext ??= [];
        var id = ChunkId.Compute(Keys.ChunkIdKey, plaintext);
        var record = ChunkCodec.Encode(Keys, id, plaintext);
        var mask = flip == 0 ? (byte)1 : flip;
        record[position.Get % record.Length] ^= mask;
        try
        {
            ChunkCodec.Decode(Keys, record, id);
            return false;
        }
        catch (Exception ex) when (ex is IntegrityException or RepositoryFormatException)
        {
            return true;
        }
    }

    [Property(MaxTest = 200)]
    public bool Manifests_round_trip(string[] sources, NonNegativeInt chunkCount)
    {
        var entries = (sources ?? []).Where(s => s is not null).Select((s, i) => new ManifestEntry(
            s, i % 2 == 0 ? null : "parent-" + s, i % 3 == 0 ? "mail" : "file", $$"""{"n":{{i}}}""",
            i % 4 == 0 ? null : new ItemContent(i * 1000L, new byte[32],
                Enumerable.Range(0, chunkCount.Get % 5).Select(c => new ChunkId(Enumerable.Repeat((byte)c, 32).ToArray())).ToList())))
            .ToList();
        var manifest = new Manifest(Guid.NewGuid(), entries);
        var bytes = StructureSerializer.Serialize(manifest);
        var back = StructureSerializer.DeserializeManifest(bytes);
        return StructureSerializer.Serialize(back).AsSpan().SequenceEqual(bytes) && back.Entries.Count == entries.Count;
    }

    [Property(MaxTest = 200)]
    public bool Snapshot_roots_round_trip_and_keep_their_merkle_root(NonNegativeInt manifests, string counts)
    {
        var ids = Enumerable.Range(0, manifests.Get % 40).Select(i => System.Security.Cryptography.SHA256.HashData(BitConverter.GetBytes(i))).ToList();
        var root = new SnapshotRoot(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UnixEpoch.AddTicks(123_456_780),
            SnapshotOutcome.Partial, counts ?? "", "[]", ids);
        var back = StructureSerializer.DeserializeSnapshot(StructureSerializer.Serialize(root));
        return back.RootHash.AsSpan().SequenceEqual(root.RootHash) && back.CreatedAt == root.CreatedAt && back.CountsJson == (counts ?? "");
    }

    [Property(MaxTest = 1000)]
    public bool Parsers_reject_garbage_with_a_format_error_only(byte[] garbage, byte kind)
    {
        garbage ??= [];
        try
        {
            switch (kind % 5)
            {
                case 0: StructureSerializer.DeserializeManifest(garbage); break;
                case 1: StructureSerializer.DeserializeSnapshot(garbage); break;
                case 2: StructureSerializer.DeserializeIndex(garbage); break;
                case 3: PackFormat.Parse(garbage, TestKeys.Tenant, "00"); break;
                default: SealedBlob.Open(Keys, BlobType.Manifest, garbage); break;
            }
            return true; // valid by chance is fine
        }
        catch (Exception ex) when (ex is RepositoryFormatException or IntegrityException)
        {
            return true;
        }
    }

    [Property(MaxTest = 300)]
    public bool Mutated_valid_structures_never_crash_a_parser(NonNegativeInt position, byte flip, NonNegativeInt cut)
    {
        var manifest = new Manifest(TestKeys.Object, [new ManifestEntry("a", "b", "mail", "{}",
            new ItemContent(5, new byte[32], [new ChunkId(new byte[32])]))]);
        var bytes = StructureSerializer.Serialize(manifest);
        bytes[position.Get % bytes.Length] ^= flip == 0 ? (byte)0x80 : flip;
        var truncated = bytes[..(bytes.Length - cut.Get % bytes.Length)];
        try
        {
            StructureSerializer.DeserializeManifest(truncated);
            return true;
        }
        catch (RepositoryFormatException)
        {
            return true;
        }
    }

    [Fact]
    public void Sealed_blobs_are_bound_to_tenant_and_type()
    {
        var body = "hello"u8.ToArray();
        var blob = SealedBlob.Seal(Keys, BlobType.Manifest, BlobKeyScope.ProtectedObject, TestKeys.Object, body);
        Assert.Equal(body, SealedBlob.Open(Keys, BlobType.Manifest, blob.Bytes).Body);
        Assert.Throws<RepositoryFormatException>(() => SealedBlob.Open(Keys, BlobType.Snapshot, blob.Bytes));
        using var otherTenant = new RepositoryKeys(Guid.NewGuid(), new Dictionary<int, byte[]> { [1] = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray() });
        Assert.Throws<IntegrityException>(() => SealedBlob.Open(otherTenant, BlobType.Manifest, blob.Bytes));
    }

    [Fact]
    public void A_shredded_object_cannot_be_read()
    {
        using var keys = new RepositoryKeys(TestKeys.Tenant, new Dictionary<int, byte[]> { [1] = new byte[32] }, id => id == TestKeys.Object);
        Assert.Throws<KeyShreddedException>(() => SealedBlob.Seal(keys, BlobType.Manifest, BlobKeyScope.ProtectedObject, TestKeys.Object, [1]));
    }
}
