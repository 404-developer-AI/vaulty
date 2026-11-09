using System.Security.Cryptography;

namespace Vaulty.Core.Abstractions;

/// <summary>
/// A secret value. Its string form and every serializer-visible member are redacted, so a secret that ends up in a log
/// message or exception shows as <c>[redacted]</c>. Read the value with <see cref="Reveal"/> where it is used, and dispose
/// the secret to wipe the bytes.
/// </summary>
[System.Text.Json.Serialization.JsonConverter(typeof(RedactedSecretJsonConverter))]
public sealed class Secret : IDisposable
{
    public const string Redacted = "[redacted]";

    private readonly byte[] _value;
    private bool _disposed;

    public Secret(string name, int version, ReadOnlySpan<byte> value)
    {
        Name = name;
        Version = version;
        _value = value.ToArray();
    }

    public string Name { get; }
    public int Version { get; }

    /// <summary>The secret bytes. Do not keep the span beyond the call that needs it.</summary>
    public ReadOnlySpan<byte> Reveal()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _value;
    }

    public string RevealString() => System.Text.Encoding.UTF8.GetString(Reveal());

    public override string ToString() => Redacted;

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_value);
        _disposed = true;
    }
}

/// <summary>Serializes every <see cref="Secret"/> as "[redacted]"; secrets are never read from JSON.</summary>
public sealed class RedactedSecretJsonConverter : System.Text.Json.Serialization.JsonConverter<Secret>
{
    public override Secret Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert,
        System.Text.Json.JsonSerializerOptions options) =>
        throw new System.Text.Json.JsonException("Secrets are never deserialized.");

    public override void Write(System.Text.Json.Utf8JsonWriter writer, Secret value,
        System.Text.Json.JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(Secret.Redacted);
    }
}

/// <summary>
/// Application secrets (storage keys, SMTP password, tenant certificates), encrypted at rest with a key derived from the
/// host master key. A row is bound to the host: copied to another host it cannot be decrypted.
/// </summary>
public interface ISecretStore
{
    /// <summary>The newest version of a secret, or null.</summary>
    Task<Secret?> GetAsync(string name, CancellationToken cancellationToken = default);

    Task<Secret?> GetAsync(string name, int version, CancellationToken cancellationToken = default);

    /// <summary>Stores a new version and returns its number. Older versions stay until pruned.</summary>
    Task<int> SetAsync(string name, ReadOnlyMemory<byte> value, string actor, CancellationToken cancellationToken = default);

    /// <summary>Removes all but the newest <paramref name="keep"/> versions. Returns the number removed.</summary>
    Task<int> PruneAsync(string name, int keep, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SecretInfo>> ListAsync(CancellationToken cancellationToken = default);
}

/// <summary>Metadata of a stored secret; never the value.</summary>
public sealed record SecretInfo(string Name, int Version, DateTimeOffset CreatedAt, string CreatedBy);

/// <summary>What a wrapped key is bound to. Part of the authenticated data, so a wrapped key cannot be moved.</summary>
public readonly record struct KeyWrapContext(Guid TenantId, int KeyVersion);

/// <summary>
/// Wraps and unwraps tenant data encryption keys with a key encryption key. The software wrapper derives the KEK from
/// the host master key; a hardware-backed wrapper can be added without changing callers, because the wrapped form
/// carries the wrapper type and KEK version in its header.
/// </summary>
public interface IKeyWrapper
{
    /// <summary>Identifies the wrapper type in the header of a wrapped key.</summary>
    byte WrapperType { get; }

    Task<byte[]> WrapAsync(ReadOnlyMemory<byte> key, KeyWrapContext context, CancellationToken cancellationToken = default);

    Task<byte[]> UnwrapAsync(ReadOnlyMemory<byte> wrapped, KeyWrapContext context, CancellationToken cancellationToken = default);
}
