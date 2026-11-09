using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ZstdSharp;

namespace Vaulty.Repository.Format;

public enum BlobType : byte
{
    Index = 1,
    Manifest = 2,
    Snapshot = 3,
}

/// <summary>Which derived key seals a blob.</summary>
public enum BlobKeyScope : byte
{
    /// <summary>The tenant repository key (indexes).</summary>
    Repository = 0,
    /// <summary>The key of one protected object (manifests and snapshots); destroyed by crypto-shredding.</summary>
    ProtectedObject = 1,
}

/// <summary>
/// Envelope for indexes, manifests and snapshots (docs/format/repository-v1.md §4):
/// <code>"VYBL" | format 1 | type | key scope | data key version (4) | object id (16) | blob id (32) | ciphertext ‖ tag</code>
/// The plaintext is the zstd-compressed body. The blob id is keyed BLAKE3 (chunk-id key) over type ‖ body, which makes
/// blobs content-addressed; the nonce is the first 12 bytes of the blob id. The authenticated data is the 59-byte header
/// followed by the tenant id.
/// </summary>
public static class SealedBlob
{
    public const byte FormatVersion = 1;
    public const int HeaderSize = 4 + 1 + 1 + 1 + 4 + 16 + 32;
    private static readonly byte[] Magic = "VYBL"u8.ToArray();

    public sealed record Sealed(byte[] Id, byte[] Bytes)
    {
        public string IdHex => Convert.ToHexStringLower(Id);
    }

    public static byte[] ComputeId(RepositoryKeys keys, BlobType type, ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(keys);
        using var hasher = Blake3.Hasher.NewKeyed(keys.ChunkIdKey);
        hasher.Update([(byte)type]);
        hasher.Update(body);
        var id = new byte[32];
        hasher.Finalize(id);
        return id;
    }

    public static Sealed Seal(RepositoryKeys keys, BlobType type, BlobKeyScope scope, Guid objectId, ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var id = ComputeId(keys, type, body);
        byte[] compressed;
        using (var compressor = new Compressor(ChunkCodec.CompressionLevel))
        {
            compressed = compressor.Wrap(body).ToArray();
        }
        var version = keys.CurrentVersion;
        var output = new byte[HeaderSize + compressed.Length + 16];
        Magic.CopyTo(output, 0);
        output[4] = FormatVersion;
        output[5] = (byte)type;
        output[6] = (byte)scope;
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(7, 4), version);
        Core.Crypto.KeyHierarchy.WriteGuid(objectId, output.AsSpan(11, 16));
        id.CopyTo(output, 27);
        using var gcm = new AesGcm(Key(keys, scope, objectId, version), 16);
        gcm.Encrypt(id.AsSpan(0, 12), compressed, output.AsSpan(HeaderSize, compressed.Length), output.AsSpan(HeaderSize + compressed.Length),
            Aad(output.AsSpan(0, HeaderSize), keys.TenantId));
        return new Sealed(id, output);
    }

    /// <summary>Opens a blob, checks its type and that the body hashes to the id in the header.</summary>
    public static (byte[] Id, Guid ObjectId, byte[] Body) Open(RepositoryKeys keys, BlobType expectedType, ReadOnlySpan<byte> data,
        int maxBodySize = 256 * 1024 * 1024)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var header = ReadHeader(data);
        if (header.Type != expectedType) throw new RepositoryFormatException($"Blob is a {header.Type}, expected {expectedType}.");
        var cipherLength = data.Length - HeaderSize - 16;
        if (cipherLength < 0) throw new RepositoryFormatException("Truncated blob.");
        var compressed = new byte[cipherLength];
        try
        {
            using var gcm = new AesGcm(Key(keys, header.Scope, header.ObjectId, header.Version), 16);
            gcm.Decrypt(header.Id.AsSpan(0, 12), data.Slice(HeaderSize, cipherLength), data[^16..], compressed,
                Aad(data[..HeaderSize], keys.TenantId));
        }
        catch (AuthenticationTagMismatchException ex)
        {
            throw new IntegrityException($"{expectedType} {Convert.ToHexStringLower(header.Id)} does not authenticate.", ex);
        }

        byte[] body;
        try
        {
            var size = Decompressor.GetDecompressedSize(compressed);
            if (size > (ulong)maxBodySize) throw new RepositoryFormatException($"Blob body of {size} bytes is too large.");
            using var decompressor = new Decompressor();
            body = decompressor.Unwrap(compressed).ToArray();
        }
        catch (ZstdException ex)
        {
            throw new IntegrityException("Blob does not decompress.", ex);
        }
        if (!ComputeId(keys, header.Type, body).AsSpan().SequenceEqual(header.Id))
        {
            throw new IntegrityException($"{expectedType} {Convert.ToHexStringLower(header.Id)} does not match its id.");
        }
        return (header.Id, header.ObjectId, body);
    }

    public static (BlobType Type, BlobKeyScope Scope, int Version, Guid ObjectId, byte[] Id) ReadHeader(ReadOnlySpan<byte> data)
    {
        var parser = new BinaryParser(data);
        parser.Expect(Magic, "sealed blob");
        var format = parser.U8();
        if (format != FormatVersion) throw new RepositoryFormatException($"Unknown blob format {format}.");
        var type = parser.U8();
        if (!Enum.IsDefined(typeof(BlobType), type)) throw new RepositoryFormatException($"Unknown blob type {type}.");
        var scope = parser.U8();
        if (!Enum.IsDefined(typeof(BlobKeyScope), scope)) throw new RepositoryFormatException($"Unknown key scope {scope}.");
        var version = (int)parser.U32();
        var objectId = parser.Guid();
        var id = parser.Bytes(32).ToArray();
        return ((BlobType)type, (BlobKeyScope)scope, version, objectId, id);
    }

    private static ReadOnlySpan<byte> Key(RepositoryKeys keys, BlobKeyScope scope, Guid objectId, int version) =>
        scope == BlobKeyScope.Repository ? keys.RepositoryKey(version) : keys.ObjectKey(objectId, version);

    private static byte[] Aad(ReadOnlySpan<byte> header, Guid tenantId)
    {
        var aad = new byte[header.Length + 16];
        header.CopyTo(aad);
        Core.Crypto.KeyHierarchy.WriteGuid(tenantId, aad.AsSpan(header.Length));
        return aad;
    }

    internal static string Hex(ReadOnlySpan<byte> id) => Convert.ToHexStringLower(id);

    internal static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);
}
