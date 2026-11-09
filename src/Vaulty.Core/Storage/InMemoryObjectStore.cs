using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Vaulty.Core.Abstractions;

namespace Vaulty.Core.Storage;

/// <summary>
/// An <see cref="IObjectStore"/> in memory, for tests. It simulates Object Lock in compliance mode: an object cannot be
/// deleted or overwritten before its lock expires, by anyone. The clock is injectable so tests can let locks expire.
/// </summary>
public sealed class InMemoryObjectStore(TimeProvider? clock = null) : IObjectStore
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, StoredObject> _objects = new(StringComparer.Ordinal);

    private sealed record StoredObject(byte[] Data, DateTimeOffset? LockUntil, DateTimeOffset LastModified, string ETag);

    /// <summary>Called before every operation with its name and key; tests use it to inject failures.</summary>
    public Action<string, string>? BeforeOperation { get; set; }

    /// <summary>When false, deletes are refused as if the identity had no delete right (worker identity).</summary>
    public bool DeleteAllowed { get; set; } = true;

    public int Count => _objects.Count;

    public long TotalBytes => _objects.Values.Sum(o => (long)o.Data.Length);

    public IEnumerable<string> Keys => _objects.Keys;

    public async Task<ObjectInfo> PutAsync(string key, Stream content, ObjectPutOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(options);
        BeforeOperation?.Invoke("put", key);
        using var buffer = new MemoryStream();
        await content.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        var data = buffer.ToArray();
        if (options.ExpectedSha256 is { } expected && !SHA256.HashData(data).AsSpan().SequenceEqual(expected))
        {
            throw new ObjectIntegrityException(key, "SHA-256 of the uploaded bytes does not match");
        }

        var now = _clock.GetUtcNow();
        var etag = Convert.ToHexStringLower(MD5.HashData(data));
        var stored = new StoredObject(data, options.LockUntil, now, etag);
        while (true)
        {
            if (_objects.TryGetValue(key, out var existing))
            {
                if (options.FailIfExists) throw new ObjectAlreadyExistsException(key);
                if (existing.LockUntil is { } lockUntil && lockUntil > now) throw new ObjectLockedException(key, lockUntil);
                if (_objects.TryUpdate(key, stored, existing)) break;
            }
            else if (_objects.TryAdd(key, stored))
            {
                break;
            }
        }
        return Info(key, stored);
    }

    public Task<Stream> GetAsync(string key, ByteRange? range = null, CancellationToken cancellationToken = default)
    {
        BeforeOperation?.Invoke("get", key);
        if (!_objects.TryGetValue(key, out var stored)) throw new ObjectNotFoundException(key);
        if (range is not { } r) return Task.FromResult<Stream>(new MemoryStream(stored.Data, writable: false));
        if (r.Offset < 0 || r.Length < 0 || r.Offset + r.Length > stored.Data.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(range), $"Range {r.Offset}+{r.Length} is outside '{key}'.");
        }
        return Task.FromResult<Stream>(new MemoryStream(stored.Data, (int)r.Offset, (int)r.Length, writable: false));
    }

    public Task<ObjectInfo?> HeadAsync(string key, CancellationToken cancellationToken = default)
    {
        BeforeOperation?.Invoke("head", key);
        return Task.FromResult(_objects.TryGetValue(key, out var stored) ? Info(key, stored) : null);
    }

    public async IAsyncEnumerable<ObjectInfo> ListAsync(string prefix, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        BeforeOperation?.Invoke("list", prefix);
        foreach (var pair in _objects.Where(p => p.Key.StartsWith(prefix, StringComparison.Ordinal)).OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return Info(pair.Key, pair.Value);
        }
        await Task.CompletedTask.ConfigureAwait(false);
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        BeforeOperation?.Invoke("delete", key);
        if (!DeleteAllowed) throw new ObjectStoreAccessDeniedException(key, "delete");
        if (!_objects.TryGetValue(key, out var stored)) return Task.CompletedTask;
        if (stored.LockUntil is { } lockUntil && lockUntil > _clock.GetUtcNow()) throw new ObjectLockedException(key, lockUntil);
        _objects.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    /// <summary>Test helper: flips one bit of a stored object, bypassing every protection (simulated bit rot).</summary>
    public void CorruptBit(string key, long byteOffset, int bit = 0)
    {
        var stored = _objects[key];
        var copy = (byte[])stored.Data.Clone();
        copy[byteOffset] ^= (byte)(1 << bit);
        _objects[key] = stored with { Data = copy };
    }

    /// <summary>Test helper: the raw bytes of an object.</summary>
    public byte[] Raw(string key) => (byte[])_objects[key].Data.Clone();

    private static ObjectInfo Info(string key, StoredObject stored) =>
        new(key, stored.Data.Length, stored.ETag, stored.LockUntil, stored.LastModified);
}
