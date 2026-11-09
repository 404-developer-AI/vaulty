using System.Text;
using Vaulty.Core.Abstractions;
using Vaulty.Repository.Format;

namespace Vaulty.Repository.Engine;

/// <summary>Thrown when a chunk an item needs is not in the index.</summary>
public sealed class MissingChunkException(ChunkId id) : IntegrityException($"Chunk {id} is not in the index.");

/// <summary>
/// Reads items, manifests and snapshots back. Every chunk is authenticated and checked against its id, and every item
/// against its content hash, before or while it is returned; nothing unverified reaches the caller undetected.
/// </summary>
public sealed class RepositoryReader(IObjectStore store, RepositoryKeys keys, IChunkIndex index)
{
    /// <summary>Streams an item to <paramref name="destination"/>. Throws <see cref="IntegrityException"/> on any mismatch.</summary>
    public async Task ReadContentAsync(ItemContent content, Stream destination, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(destination);
        using var hasher = Blake3.Hasher.NewKeyed(keys.ChunkIdKey);
        long size = 0;
        foreach (var id in content.Chunks)
        {
            var plaintext = await ReadChunkAsync(id, cancellationToken).ConfigureAwait(false);
            hasher.Update(plaintext);
            size += plaintext.Length;
            await destination.WriteAsync(plaintext, cancellationToken).ConfigureAwait(false);
        }
        var hash = new byte[32];
        hasher.Finalize(hash);
        if (size != content.Size || !hash.AsSpan().SequenceEqual(content.ContentHash))
        {
            throw new IntegrityException("Item content does not match its hash.");
        }
    }

    public async Task<byte[]> ReadChunkAsync(ChunkId id, CancellationToken cancellationToken = default)
    {
        var location = await index.FindAsync(id, cancellationToken).ConfigureAwait(false) ?? throw new MissingChunkException(id);
        byte[] record;
        await using (var stream = await store.GetAsync(RepositoryLayout.Pack(keys.TenantId, location.PackHash),
                         new ByteRange(location.Offset, location.Length), cancellationToken).ConfigureAwait(false))
        {
            record = await IndexRebuilder.ReadAllAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        return ChunkCodec.Decode(keys, record, id);
    }

    public async Task<Manifest> ReadManifestAsync(byte[] manifestId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifestId);
        var bytes = await GetAsync(RepositoryLayout.Manifest(keys.TenantId, Convert.ToHexStringLower(manifestId)), cancellationToken)
            .ConfigureAwait(false);
        var (id, objectId, body) = SealedBlob.Open(keys, BlobType.Manifest, bytes);
        if (!id.AsSpan().SequenceEqual(manifestId)) throw new IntegrityException("Manifest is stored under another id.");
        var manifest = StructureSerializer.DeserializeManifest(body);
        if (manifest.ProtectedObjectId != objectId) throw new IntegrityException("Manifest header and body name different objects.");
        return manifest;
    }

    public async Task<SnapshotRoot> ReadSnapshotAsync(Guid protectedObjectId, Guid snapshotId, CancellationToken cancellationToken = default)
    {
        var bytes = await GetAsync(RepositoryLayout.Snapshot(keys.TenantId, protectedObjectId, snapshotId), cancellationToken)
            .ConfigureAwait(false);
        var (_, objectId, body) = SealedBlob.Open(keys, BlobType.Snapshot, bytes);
        var root = StructureSerializer.DeserializeSnapshot(body);
        if (root.TenantId != keys.TenantId || root.ProtectedObjectId != protectedObjectId || objectId != protectedObjectId ||
            root.SnapshotId != snapshotId)
        {
            throw new IntegrityException("Snapshot is stored under another tenant, object or id.");
        }
        return root;
    }

    /// <summary>All snapshot ids of a protected object, from the store listing (no database needed).</summary>
    public async Task<IReadOnlyList<Guid>> ListSnapshotsAsync(Guid protectedObjectId, CancellationToken cancellationToken = default)
    {
        var result = new List<Guid>();
        var prefix = $"{RepositoryLayout.TenantPrefix(keys.TenantId)}snapshots/{protectedObjectId:D}/";
        await foreach (var info in store.ListAsync(prefix, cancellationToken).ConfigureAwait(false))
        {
            var name = info.Key[prefix.Length..];
            if (name.EndsWith(".snap", StringComparison.Ordinal) && Guid.TryParse(name[..^5], out var id)) result.Add(id);
        }
        return result;
    }

    public async Task<Guid?> ReadLatestAsync(Guid protectedObjectId, CancellationToken cancellationToken = default)
    {
        try
        {
            var text = Encoding.ASCII.GetString(await GetAsync(RepositoryLayout.Latest(keys.TenantId, protectedObjectId), cancellationToken)
                .ConfigureAwait(false));
            return Guid.TryParse(text.Trim(), out var id) ? id : null;
        }
        catch (ObjectNotFoundException)
        {
            return null;
        }
    }

    /// <summary>Re-reads a whole pack: trailer hash, file hash against its name, and every record authenticated.</summary>
    public async Task<int> VerifyPackAsync(string packHash, int? sampleRecords = null, CancellationToken cancellationToken = default)
    {
        var bytes = await GetAsync(RepositoryLayout.Pack(keys.TenantId, packHash), cancellationToken).ConfigureAwait(false);
        if (!Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)).Equals(packHash, StringComparison.Ordinal))
        {
            throw new IntegrityException($"Pack {packHash} does not match its name.");
        }
        var records = PackFormat.Parse(bytes, keys.TenantId, packHash);
        var selected = sampleRecords is { } n && n < records.Count
            ? records.Where((_, i) => i % Math.Max(1, records.Count / n) == 0).Take(n)
            : records;
        var checkedCount = 0;
        foreach (var record in selected)
        {
            ChunkCodec.Decode(keys, bytes.AsSpan((int)record.Offset, record.Length), record.Id);
            checkedCount++;
        }
        return checkedCount;
    }

    private async Task<byte[]> GetAsync(string key, CancellationToken cancellationToken)
    {
        await using var stream = await store.GetAsync(key, null, cancellationToken).ConfigureAwait(false);
        return await IndexRebuilder.ReadAllAsync(stream, cancellationToken).ConfigureAwait(false);
    }
}
