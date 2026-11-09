namespace Vaulty.Core.Abstractions;

/// <summary>Metadata of one stored object.</summary>
public sealed record ObjectInfo(string Key, long Size, string? ETag, DateTimeOffset? LockUntil, DateTimeOffset LastModified);

/// <summary>An inclusive byte range, like the HTTP Range header.</summary>
public readonly record struct ByteRange(long Offset, long Length)
{
    public long LastByte => Offset + Length - 1;
}

/// <summary>Options for writing an object.</summary>
/// <param name="LockUntil">Object Lock retention (compliance mode). Null only for the few mutable keys such as pointers.</param>
/// <param name="FailIfExists">Refuse to write when the key already exists (content-addressed keys are never rewritten).</param>
/// <param name="ExpectedSha256">When set, the store verifies the uploaded bytes against this hash.</param>
public sealed record ObjectPutOptions(DateTimeOffset? LockUntil, bool FailIfExists = true, byte[]? ExpectedSha256 = null)
{
    public static ObjectPutOptions Mutable { get; } = new(null, FailIfExists: false);
}

/// <summary>
/// Object storage with Object Lock. Implementations: the S3 adapter for production and an in-memory store with
/// simulated Object Lock for tests. Deleting is only possible with the garbage-collection identity, and only after the
/// lock has expired; the storage provider enforces this, not Vaulty.
/// </summary>
public interface IObjectStore
{
    Task<ObjectInfo> PutAsync(string key, Stream content, ObjectPutOptions options, CancellationToken cancellationToken = default);

    /// <summary>Opens the object (or a range of it) for streaming. Throws <see cref="ObjectNotFoundException"/>.</summary>
    Task<Stream> GetAsync(string key, ByteRange? range = null, CancellationToken cancellationToken = default);

    Task<ObjectInfo?> HeadAsync(string key, CancellationToken cancellationToken = default);

    IAsyncEnumerable<ObjectInfo> ListAsync(string prefix, CancellationToken cancellationToken = default);

    /// <summary>Deletes an object. Throws <see cref="ObjectLockedException"/> while the lock holds.</summary>
    Task DeleteAsync(string key, CancellationToken cancellationToken = default);
}

public class ObjectStoreException(string message, Exception? inner = null) : Exception(message, inner);

public sealed class ObjectNotFoundException(string key) : ObjectStoreException($"Object '{key}' does not exist.")
{
    public string Key { get; } = key;
}

public sealed class ObjectAlreadyExistsException(string key) : ObjectStoreException($"Object '{key}' already exists.")
{
    public string Key { get; } = key;
}

public sealed class ObjectLockedException(string key, DateTimeOffset? lockUntil)
    : ObjectStoreException($"Object '{key}' is locked until {lockUntil:O}.")
{
    public string Key { get; } = key;
    public DateTimeOffset? LockUntil { get; } = lockUntil;
}

public sealed class ObjectIntegrityException(string key, string reason)
    : ObjectStoreException($"Object '{key}' failed the integrity check: {reason}.")
{
    public string Key { get; } = key;
}

public sealed class ObjectStoreAccessDeniedException(string key, string operation, Exception? inner = null)
    : ObjectStoreException($"Access denied for {operation} on '{key}'.", inner)
{
    public string Key { get; } = key;
    public string Operation { get; } = operation;
}
