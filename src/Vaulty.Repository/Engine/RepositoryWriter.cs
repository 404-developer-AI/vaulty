using System.Security.Cryptography;
using System.Text;
using Vaulty.Core.Abstractions;
using Vaulty.Repository.Chunking;
using Vaulty.Repository.Format;

namespace Vaulty.Repository.Engine;

public sealed record RepositoryWriterOptions
{
    /// <summary>A pack is stored once it reaches this size (16–64 MB in production).</summary>
    public int PackTargetSize { get; init; } = 32 * 1024 * 1024;

    public ChunkerOptions Chunker { get; init; } = ChunkerOptions.Default;

    /// <summary>Object Lock retention for everything written (retention of the policy plus 30 days).</summary>
    public required DateTimeOffset LockUntil { get; init; }
}

/// <summary>Counters of one writer, for the dedup, compression and throughput figures.</summary>
public sealed class WriterStatistics
{
    public long BytesIn { get; internal set; }
    public long ChunksIn { get; internal set; }
    public long ChunksNew { get; internal set; }
    public long ChunksDeduplicated { get; internal set; }
    public long BytesNew { get; internal set; }
    public long BytesStored { get; internal set; }
    public long ChunksCompressed { get; internal set; }
    public int PacksWritten { get; internal set; }
}

/// <summary>
/// Writes items, manifests and snapshots of one tenant. Not thread-safe: one writer per backup activity.
/// Everything is content-addressed and written with Object Lock; a crash at any point leaves either nothing or complete,
/// immutable objects, and a rerun of the same input produces the same snapshot.
/// </summary>
public sealed class RepositoryWriter
{
    private readonly IObjectStore _store;
    private readonly RepositoryKeys _keys;
    private readonly IChunkIndex _index;
    private readonly RepositoryWriterOptions _options;
    private readonly IFaultInjector _faults;
    private readonly List<string> _packsWritten = [];

    private MemoryStream? _pack;
    private readonly List<ChunkLocation> _pending = [];
    private readonly HashSet<ChunkId> _pendingIds = [];

    public RepositoryWriter(IObjectStore store, RepositoryKeys keys, IChunkIndex index, RepositoryWriterOptions options,
        IFaultInjector? faults = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        _index = index ?? throw new ArgumentNullException(nameof(index));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _faults = faults ?? NoFaults.Instance;
        _options.Chunker.Validate();
    }

    public WriterStatistics Statistics { get; } = new();

    /// <summary>Pack hashes this writer stored (new or already present).</summary>
    public IReadOnlyList<string> PacksWritten => _packsWritten;

    /// <summary>Chunks, deduplicates and stores one item. Holds at most two chunks and one pack in memory.</summary>
    public async Task<ItemContent> WriteAsync(Stream content, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        using var itemHasher = Blake3.Hasher.NewKeyed(_keys.ChunkIdKey);
        var chunks = new List<ChunkId>();
        long size = 0;
        await FastCdc.ChunkAsync(content, _options.Chunker, async chunk =>
        {
            itemHasher.Update(chunk.Span);
            size += chunk.Length;
            chunks.Add(await AddChunkAsync(chunk, cancellationToken).ConfigureAwait(false));
        }, cancellationToken).ConfigureAwait(false);
        var hash = new byte[32];
        itemHasher.Finalize(hash);
        Statistics.BytesIn += size;
        return new ItemContent(size, hash, chunks);
    }

    private async Task<ChunkId> AddChunkAsync(ReadOnlyMemory<byte> plaintext, CancellationToken cancellationToken)
    {
        var id = ChunkId.Compute(_keys.ChunkIdKey, plaintext.Span);
        Statistics.ChunksIn++;
        if (_pendingIds.Contains(id) || await _index.FindAsync(id, cancellationToken).ConfigureAwait(false) is not null)
        {
            Statistics.ChunksDeduplicated++;
            return id;
        }

        var record = ChunkCodec.Encode(_keys, id, plaintext.Span);
        _faults.Hit("chunk.encoded");
        if (_pack is null)
        {
            _pack = new MemoryStream(Math.Min(_options.PackTargetSize + 1024, 80 * 1024 * 1024));
            var header = new byte[PackFormat.HeaderSize];
            PackFormat.WriteHeader(header, _keys.TenantId);
            _pack.Write(header);
        }
        var offset = _pack.Length;
        _pack.Write(record);
        _pending.Add(new ChunkLocation(id, string.Empty, offset, record.Length, plaintext.Length));
        _pendingIds.Add(id);
        Statistics.ChunksNew++;
        Statistics.BytesNew += plaintext.Length;
        Statistics.BytesStored += record.Length;
        if ((record[32] & ChunkCodec.FlagCompressed) != 0) Statistics.ChunksCompressed++;

        if (_pack.Length >= _options.PackTargetSize) await FlushAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    /// <summary>Stores the pending pack and its index file, then records the chunks in the index (in that order).</summary>
    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        if (_pack is null || _pending.Count == 0) return;
        var body = _pack.ToArray();
        var trailer = PackFormat.Trailer(_pending.Count, SHA256.HashData(body));
        var packBytes = new byte[body.Length + trailer.Length];
        body.CopyTo(packBytes, 0);
        trailer.CopyTo(packBytes, body.Length);
        var packSha = SHA256.HashData(packBytes);
        var packHash = Convert.ToHexStringLower(packSha);
        var packKey = RepositoryLayout.Pack(_keys.TenantId, packHash);
        var entries = _pending.Select(e => e with { PackHash = packHash }).ToList();

        _faults.Hit("pack.before-put");
        await PutImmutableAsync(packKey, packBytes, packSha, cancellationToken).ConfigureAwait(false);
        _faults.Hit("pack.after-put");

        var index = SealedBlob.Seal(_keys, BlobType.Index, BlobKeyScope.Repository, Guid.Empty,
            StructureSerializer.SerializeIndex(packHash, entries));
        await PutImmutableAsync(RepositoryLayout.Index(_keys.TenantId, packHash), index.Bytes, null, cancellationToken)
            .ConfigureAwait(false);
        _faults.Hit("index-file.after-put");

        await _index.AddAsync(new PackInfo(packHash, packKey, packBytes.Length, packSha, _options.LockUntil), entries, cancellationToken)
            .ConfigureAwait(false);
        _faults.Hit("index.after-add");

        _packsWritten.Add(packHash);
        Statistics.PacksWritten++;
        await _pack.DisposeAsync().ConfigureAwait(false);
        _pack = null;
        _pending.Clear();
        _pendingIds.Clear();
    }

    /// <summary>Stores a manifest after flushing pending chunks, so a manifest never references unstored data.</summary>
    public async Task<byte[]> WriteManifestAsync(Manifest manifest, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        await FlushAsync(cancellationToken).ConfigureAwait(false);
        var blob = SealedBlob.Seal(_keys, BlobType.Manifest, BlobKeyScope.ProtectedObject, manifest.ProtectedObjectId,
            StructureSerializer.Serialize(manifest));
        await PutImmutableAsync(RepositoryLayout.Manifest(_keys.TenantId, blob.IdHex), blob.Bytes, null, cancellationToken)
            .ConfigureAwait(false);
        _faults.Hit("manifest.after-put");
        return blob.Id;
    }

    /// <summary>
    /// Stores the snapshot root, the commit point of a backup, and then the LATEST pointer. Storing the same snapshot again
    /// is a no-op; a different root under the same snapshot id is refused.
    /// </summary>
    public async Task<byte[]> CommitSnapshotAsync(SnapshotRoot root, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (root.TenantId != _keys.TenantId) throw new ArgumentException("Snapshot of another tenant.", nameof(root));
        await FlushAsync(cancellationToken).ConfigureAwait(false);
        var blob = SealedBlob.Seal(_keys, BlobType.Snapshot, BlobKeyScope.ProtectedObject, root.ProtectedObjectId,
            StructureSerializer.Serialize(root));
        var key = RepositoryLayout.Snapshot(_keys.TenantId, root.ProtectedObjectId, root.SnapshotId);
        _faults.Hit("snapshot.before-put");
        await PutImmutableAsync(key, blob.Bytes, null, cancellationToken, compareExisting: true).ConfigureAwait(false);
        _faults.Hit("snapshot.after-put");
        // LATEST is a cache for tools that browse the store; the snapshot files are the truth.
        await _store.PutAsync(RepositoryLayout.Latest(_keys.TenantId, root.ProtectedObjectId),
            new MemoryStream(Encoding.ASCII.GetBytes(root.SnapshotId.ToString("D"))), ObjectPutOptions.Mutable, cancellationToken)
            .ConfigureAwait(false);
        return root.RootHash;
    }

    private async Task PutImmutableAsync(string key, byte[] bytes, byte[]? sha256, CancellationToken cancellationToken,
        bool compareExisting = false)
    {
        try
        {
            await _store.PutAsync(key, new MemoryStream(bytes, writable: false),
                new ObjectPutOptions(_options.LockUntil, FailIfExists: true, ExpectedSha256: sha256 ?? SHA256.HashData(bytes)),
                cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectAlreadyExistsException)
        {
            // Content-addressed keys: an existing object holds the same bytes, unless it was damaged. Check.
            var head = await _store.HeadAsync(key, cancellationToken).ConfigureAwait(false);
            if (head is null || head.Size != bytes.Length) throw new IntegrityException($"Existing object {key} differs in size.");
            if (compareExisting)
            {
                await using var stream = await _store.GetAsync(key, null, cancellationToken).ConfigureAwait(false);
                var existing = await IndexRebuilder.ReadAllAsync(stream, cancellationToken).ConfigureAwait(false);
                if (!existing.AsSpan().SequenceEqual(bytes))
                {
                    throw new InvalidOperationException($"Snapshot {key} was already committed with different content.");
                }
            }
        }
    }
}
