using System.Collections.Concurrent;
using System.Security.Cryptography;
using Vaulty.Core.Crypto;

namespace Vaulty.Repository.Format;

/// <summary>Thrown when the key of a protected object was destroyed (crypto-shredding).</summary>
public sealed class KeyShreddedException(Guid protectedObjectId)
    : CryptographicException($"The key of protected object {protectedObjectId} was destroyed.")
{
    public Guid ProtectedObjectId { get; } = protectedObjectId;
}

/// <summary>
/// The unwrapped data keys of one tenant and the keys derived from them. Chunks are encrypted with the data key of the
/// version recorded in their header, so data written before a key rotation stays readable.
/// </summary>
public sealed class RepositoryKeys : IDisposable
{
    private readonly Dictionary<int, byte[]> _dataKeys;
    private readonly byte[] _chunkIdKey;
    private readonly Func<Guid, bool> _isShredded;
    private readonly ConcurrentDictionary<int, byte[]> _repositoryKeys = new();
    private readonly ConcurrentDictionary<(Guid, int), byte[]> _objectKeys = new();

    /// <param name="tenantId">The tenant (bound into every authenticated data field).</param>
    /// <param name="dataKeys">Every unwrapped data key version of the tenant; the highest is used for writing.</param>
    /// <param name="isShredded">True for protected objects on the tombstone list.</param>
    public RepositoryKeys(Guid tenantId, IReadOnlyDictionary<int, byte[]> dataKeys, Func<Guid, bool>? isShredded = null)
    {
        ArgumentNullException.ThrowIfNull(dataKeys);
        if (dataKeys.Count == 0) throw new ArgumentException("At least one data key is required.", nameof(dataKeys));
        TenantId = tenantId;
        _dataKeys = dataKeys.ToDictionary(p => p.Key, p => (byte[])p.Value.Clone());
        CurrentVersion = _dataKeys.Keys.Max();
        // Chunk ids must stay stable across key rotations (deduplication), so they derive from the first version.
        _chunkIdKey = KeyHierarchy.DeriveChunkIdKey(_dataKeys[_dataKeys.Keys.Min()]);
        _isShredded = isShredded ?? (_ => false);
    }

    public Guid TenantId { get; }
    public int CurrentVersion { get; }

    public ReadOnlySpan<byte> ChunkIdKey => _chunkIdKey;

    public ReadOnlySpan<byte> RepositoryKey(int version) =>
        _repositoryKeys.GetOrAdd(version, v => KeyHierarchy.DeriveRepositoryKey(DataKeyArray(v)));

    public ReadOnlySpan<byte> DataKey(int version) => DataKeyArray(version);

    public ReadOnlySpan<byte> ObjectKey(Guid protectedObjectId, int version)
    {
        if (_isShredded(protectedObjectId)) throw new KeyShreddedException(protectedObjectId);
        return _objectKeys.GetOrAdd((protectedObjectId, version), k => KeyHierarchy.DeriveObjectKey(DataKeyArray(k.Item2), k.Item1));
    }

    private byte[] DataKeyArray(int version) =>
        _dataKeys.TryGetValue(version, out var key) ? key : throw new CryptographicException($"Data key version {version} is not available.");

    public void Dispose()
    {
        foreach (var key in _dataKeys.Values) CryptographicOperations.ZeroMemory(key);
        foreach (var key in _objectKeys.Values) CryptographicOperations.ZeroMemory(key);
        foreach (var key in _repositoryKeys.Values) CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(_chunkIdKey);
    }
}
