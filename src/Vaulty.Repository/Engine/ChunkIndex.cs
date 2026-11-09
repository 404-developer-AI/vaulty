using System.Collections.Concurrent;
using Vaulty.Core.Abstractions;
using Vaulty.Repository.Format;

namespace Vaulty.Repository.Engine;

/// <summary>A pack the index knows, with the time its Object Lock expires.</summary>
public sealed record PackInfo(string PackHash, string ObjectKey, long Size, byte[] Sha256, DateTimeOffset LockUntil);

/// <summary>
/// Where every chunk of a tenant is stored. The PostgreSQL implementation (chunk_index and packs tables) is the fast path;
/// the index files in object storage are the durable copy from which <see cref="IndexRebuilder"/> rebuilds it.
/// Entries are added only after the pack and its index file are stored, so the index never points to missing data.
/// </summary>
public interface IChunkIndex
{
    ValueTask<ChunkLocation?> FindAsync(ChunkId id, CancellationToken cancellationToken = default);

    Task AddAsync(PackInfo pack, IReadOnlyList<ChunkLocation> entries, CancellationToken cancellationToken = default);

    IAsyncEnumerable<string> PackHashesAsync(CancellationToken cancellationToken = default);
}

public sealed class InMemoryChunkIndex : IChunkIndex
{
    private readonly ConcurrentDictionary<ChunkId, ChunkLocation> _chunks = new();
    private readonly ConcurrentDictionary<string, PackInfo> _packs = new(StringComparer.Ordinal);

    public int ChunkCount => _chunks.Count;

    public IReadOnlyCollection<PackInfo> Packs => _packs.Values.ToList();

    public ValueTask<ChunkLocation?> FindAsync(ChunkId id, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_chunks.TryGetValue(id, out var location) ? location : null);

    public Task AddAsync(PackInfo pack, IReadOnlyList<ChunkLocation> entries, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pack);
        ArgumentNullException.ThrowIfNull(entries);
        _packs.TryAdd(pack.PackHash, pack);
        foreach (var entry in entries) _chunks.TryAdd(entry.Id, entry);
        return Task.CompletedTask;
    }

    public async IAsyncEnumerable<string> PackHashesAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var hash in _packs.Keys) yield return hash;
        await Task.CompletedTask.ConfigureAwait(false);
    }
}

/// <summary>Rebuilds a chunk index from the index files in object storage, without any database.</summary>
public static class IndexRebuilder
{
    public static async Task<InMemoryChunkIndex> RebuildAsync(IObjectStore store, RepositoryKeys keys, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(keys);
        var index = new InMemoryChunkIndex();
        var prefix = RepositoryLayout.TenantPrefix(keys.TenantId) + "indexes/";
        await foreach (var info in store.ListAsync(prefix, cancellationToken).ConfigureAwait(false))
        {
            byte[] sealedBytes;
            await using (var stream = await store.GetAsync(info.Key, null, cancellationToken).ConfigureAwait(false))
            {
                sealedBytes = await ReadAllAsync(stream, cancellationToken).ConfigureAwait(false);
            }
            var (_, _, body) = SealedBlob.Open(keys, BlobType.Index, sealedBytes);
            var (packHash, entries) = StructureSerializer.DeserializeIndex(body);
            var packKey = RepositoryLayout.Pack(keys.TenantId, packHash);
            var head = await store.HeadAsync(packKey, cancellationToken).ConfigureAwait(false);
            if (head is null) continue; // index without pack: the pack upload failed before the index was trusted
            await index.AddAsync(new PackInfo(packHash, packKey, head.Size, Convert.FromHexString(packHash),
                head.LockUntil ?? DateTimeOffset.MinValue), entries, cancellationToken).ConfigureAwait(false);
        }
        return index;
    }

    internal static async Task<byte[]> ReadAllAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer.ToArray();
    }
}

/// <summary>Fault injection points for crash tests. Production uses <see cref="NoFaults"/>.</summary>
public interface IFaultInjector
{
    void Hit(string point);
}

public sealed class NoFaults : IFaultInjector
{
    public static readonly NoFaults Instance = new();

    public void Hit(string point)
    {
    }
}
