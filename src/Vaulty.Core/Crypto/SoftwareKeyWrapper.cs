using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Vaulty.Core.Abstractions;

namespace Vaulty.Core.Crypto;

/// <summary>
/// Wraps tenant data keys with AES-256-GCM under a KEK derived from the host master key (HKDF purpose "kek").
/// Wrapped form (docs/format/keys-v1.md):
/// <code>
/// magic "VYKW" | format 1 (1 byte) | wrapper type (1 byte) | KEK version (4 bytes BE) | nonce (12) | ciphertext (n) | tag (16)
/// </code>
/// The authenticated data is the 10-byte header followed by the tenant id (16 bytes, RFC 4122 order) and the data key
/// version (4 bytes BE), so a wrapped key cannot be moved to another tenant or version.
/// </summary>
public sealed class SoftwareKeyWrapper : IKeyWrapper, IDisposable
{
    public const byte Type = 1;
    public const byte FormatVersion = 1;
    public const int HeaderSize = 10;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("VYKW");

    private readonly byte[] _kek;
    private readonly int _kekVersion;
    private readonly Func<byte[]>? _nonceSource;

    /// <param name="masterKey">The 32-byte host master key.</param>
    /// <param name="kekVersion">Version of the master key the KEK is derived from; increases with every rekey.</param>
    /// <param name="nonceSource">Only for test vectors: a fixed nonce. Production always uses random nonces.</param>
    public SoftwareKeyWrapper(ReadOnlySpan<byte> masterKey, int kekVersion = 1, Func<byte[]>? nonceSource = null)
    {
        _kek = KeyHierarchy.DeriveHostKey(masterKey, HostKeyPurpose.Kek);
        _kekVersion = kekVersion;
        _nonceSource = nonceSource;
    }

    public byte WrapperType => Type;

    public int KekVersion => _kekVersion;

    public Task<byte[]> WrapAsync(ReadOnlyMemory<byte> key, KeyWrapContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(Wrap(key.Span, context));

    public Task<byte[]> UnwrapAsync(ReadOnlyMemory<byte> wrapped, KeyWrapContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(Unwrap(wrapped.Span, context));

    public byte[] Wrap(ReadOnlySpan<byte> key, KeyWrapContext context)
    {
        var output = new byte[HeaderSize + NonceSize + key.Length + TagSize];
        WriteHeader(output, _kekVersion);
        var nonce = output.AsSpan(HeaderSize, NonceSize);
        if (_nonceSource is null) RandomNumberGenerator.Fill(nonce);
        else _nonceSource().AsSpan(0, NonceSize).CopyTo(nonce);
        using var gcm = new AesGcm(_kek, TagSize);
        gcm.Encrypt(nonce, key, output.AsSpan(HeaderSize + NonceSize, key.Length),
            output.AsSpan(output.Length - TagSize), Aad(output.AsSpan(0, HeaderSize), context));
        return output;
    }

    public byte[] Unwrap(ReadOnlySpan<byte> wrapped, KeyWrapContext context)
    {
        var header = ReadHeader(wrapped);
        if (header.WrapperType != Type) throw new CryptographicException($"Key was wrapped by wrapper type {header.WrapperType}.");
        if (header.KekVersion != _kekVersion)
        {
            throw new CryptographicException($"Key was wrapped with KEK version {header.KekVersion}, this host has {_kekVersion}.");
        }
        var length = wrapped.Length - HeaderSize - NonceSize - TagSize;
        if (length <= 0) throw new CryptographicException("Wrapped key is too short.");
        var key = new byte[length];
        using var gcm = new AesGcm(_kek, TagSize);
        gcm.Decrypt(wrapped.Slice(HeaderSize, NonceSize), wrapped.Slice(HeaderSize + NonceSize, length),
            wrapped[^TagSize..], key, Aad(wrapped[..HeaderSize], context));
        return key;
    }

    /// <summary>Reads the header of a wrapped key without unwrapping it.</summary>
    public static (byte WrapperType, int KekVersion) ReadHeader(ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length < HeaderSize || !wrapped[..4].SequenceEqual(Magic)) throw new CryptographicException("Not a wrapped Vaulty key.");
        if (wrapped[4] != FormatVersion) throw new CryptographicException($"Unknown wrapped key format {wrapped[4]}.");
        return (wrapped[5], BinaryPrimitives.ReadInt32BigEndian(wrapped.Slice(6, 4)));
    }

    private static void WriteHeader(Span<byte> output, int kekVersion)
    {
        Magic.CopyTo(output);
        output[4] = FormatVersion;
        output[5] = Type;
        BinaryPrimitives.WriteInt32BigEndian(output.Slice(6, 4), kekVersion);
    }

    private static byte[] Aad(ReadOnlySpan<byte> header, KeyWrapContext context)
    {
        var aad = new byte[HeaderSize + 16 + 4];
        header.CopyTo(aad);
        KeyHierarchy.WriteGuid(context.TenantId, aad.AsSpan(HeaderSize, 16));
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(HeaderSize + 16, 4), context.KeyVersion);
        return aad;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_kek);
}
