using System.Buffers.Binary;
using System.Security.Cryptography;
using ZstdSharp;

namespace Vaulty.Repository.Format;

/// <summary>Thrown when stored data does not match its hash or does not authenticate.</summary>
public class IntegrityException(string message, Exception? inner = null) : CryptographicException(message, inner);

/// <summary>A 32-byte chunk id: keyed BLAKE3 of the plaintext with the tenant's chunk-id key.</summary>
public readonly record struct ChunkId(byte[] Value)
{
    public const int Size = 32;

    public static ChunkId Compute(ReadOnlySpan<byte> chunkIdKey, ReadOnlySpan<byte> plaintext)
    {
        using var hasher = Blake3.Hasher.NewKeyed(chunkIdKey);
        hasher.Update(plaintext);
        var value = new byte[Size];
        hasher.Finalize(value);
        return new ChunkId(value);
    }

    public string Hex => Convert.ToHexStringLower(Value);

    public bool Equals(ChunkId other) => Value.AsSpan().SequenceEqual(other.Value);

    public override int GetHashCode() => BinaryPrimitives.ReadInt32LittleEndian(Value);

    public override string ToString() => Hex;
}

/// <summary>
/// Encodes one chunk as a pack record (docs/format/repository-v1.md §3):
/// <code>chunk id (32) | flags (1) | data key version (4) | plaintext length (4) | stored length (4) | ciphertext ‖ tag</code>
/// The plaintext is compressed with zstd level 3 unless that saves less than 3 %, then encrypted with AES-256-GCM under the
/// tenant data key. The nonce is the first 12 bytes of the chunk id, so the same chunk always encrypts to the same bytes
/// (writes are idempotent) and two different chunks never share a nonce unless their keyed hashes collide.
/// </summary>
public static class ChunkCodec
{
    public const byte FormatVersion = 1;
    public const byte FlagCompressed = 0x01;
    public const int HeaderSize = ChunkId.Size + 1 + 4 + 4 + 4;
    public const int TagSize = 16;
    public const double CompressionThreshold = 0.97;
    public const int CompressionLevel = 3;

    [ThreadStatic] private static Compressor? _compressor;

    /// <summary>The largest record a plaintext of this length can produce, for sizing a buffer for <see cref="EncodeInto"/>.</summary>
    public static int MaxRecordSize(int plaintextLength) => HeaderSize + Math.Max(plaintextLength, Compressor.GetCompressBound(plaintextLength)) + TagSize;

    public static byte[] Encode(RepositoryKeys keys, ChunkId id, ReadOnlySpan<byte> plaintext)
    {
        var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(MaxRecordSize(plaintext.Length));
        try
        {
            var length = EncodeInto(keys, id, plaintext, buffer);
            return buffer.AsSpan(0, length).ToArray();
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Encodes the record into <paramref name="destination"/> (at least <see cref="MaxRecordSize"/> bytes) and returns its length.
    /// Allocates nothing per chunk beyond a pooled compression buffer, so streaming large files keeps memory flat.
    /// </summary>
    public static int EncodeInto(RepositoryKeys keys, ChunkId id, ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (destination.Length < MaxRecordSize(plaintext.Length)) throw new ArgumentException("Destination too small.", nameof(destination));
        byte flags = 0;
        byte[]? rented = null;
        try
        {
            var payload = plaintext;
            if (plaintext.Length >= 64)
            {
                rented = System.Buffers.ArrayPool<byte>.Shared.Rent(Compressor.GetCompressBound(plaintext.Length));
                var compressor = _compressor ??= new Compressor(CompressionLevel);
                var compressedLength = compressor.Wrap(plaintext, rented);
                if (compressedLength < plaintext.Length * CompressionThreshold)
                {
                    flags = FlagCompressed;
                    payload = rented.AsSpan(0, compressedLength);
                }
            }

            var version = keys.CurrentVersion;
            var length = HeaderSize + payload.Length + TagSize;
            var record = destination[..length];
            id.Value.CopyTo(record);
            record[32] = flags;
            BinaryPrimitives.WriteInt32BigEndian(record.Slice(33, 4), version);
            BinaryPrimitives.WriteInt32BigEndian(record.Slice(37, 4), plaintext.Length);
            BinaryPrimitives.WriteInt32BigEndian(record.Slice(41, 4), payload.Length + TagSize);
            using var gcm = new AesGcm(keys.DataKey(version), TagSize);
            gcm.Encrypt(id.Value.AsSpan(0, 12), payload, record.Slice(HeaderSize, payload.Length), record.Slice(HeaderSize + payload.Length, TagSize),
                Aad(keys.TenantId, id, flags, version));
            return length;
        }
        finally
        {
            if (rented is not null) System.Buffers.ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>Total record length from its header, or throws if the header is malformed.</summary>
    public static int RecordLength(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderSize) throw new RepositoryFormatException("Truncated chunk header.");
        var stored = BinaryPrimitives.ReadInt32BigEndian(header.Slice(41, 4));
        if (stored < TagSize || stored > 64 * 1024 * 1024) throw new RepositoryFormatException($"Invalid stored length {stored}.");
        return HeaderSize + stored;
    }

    public static ChunkId ReadId(ReadOnlySpan<byte> record)
    {
        if (record.Length < HeaderSize) throw new RepositoryFormatException("Truncated chunk header.");
        return new ChunkId(record[..ChunkId.Size].ToArray());
    }

    /// <summary>Decrypts and decompresses a record and checks that the plaintext hashes to the expected id.</summary>
    public static byte[] Decode(RepositoryKeys keys, ReadOnlySpan<byte> record, ChunkId? expected = null)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var length = RecordLength(record);
        if (record.Length != length) throw new RepositoryFormatException($"Record is {record.Length} bytes, header says {length}.");
        var id = ReadId(record);
        if (expected is { } e && !e.Equals(id)) throw new IntegrityException($"Record holds chunk {id}, expected {e}.");
        var flags = record[32];
        if ((flags & ~FlagCompressed) != 0) throw new RepositoryFormatException($"Unknown chunk flags {flags:x2}.");
        var version = BinaryPrimitives.ReadInt32BigEndian(record.Slice(33, 4));
        var plainLength = BinaryPrimitives.ReadInt32BigEndian(record.Slice(37, 4));
        if (plainLength < 0 || plainLength > 64 * 1024 * 1024) throw new RepositoryFormatException($"Invalid plaintext length {plainLength}.");
        var cipherLength = length - HeaderSize - TagSize;
        var payload = new byte[cipherLength];
        try
        {
            using var gcm = new AesGcm(keys.DataKey(version), TagSize);
            gcm.Decrypt(id.Value.AsSpan(0, 12), record.Slice(HeaderSize, cipherLength), record[^TagSize..], payload,
                Aad(keys.TenantId, id, flags, version));
        }
        catch (AuthenticationTagMismatchException ex)
        {
            throw new IntegrityException($"Chunk {id} does not authenticate.", ex);
        }

        byte[] plaintext;
        if ((flags & FlagCompressed) != 0)
        {
            plaintext = new byte[plainLength];
            using var decompressor = new Decompressor();
            int written;
            try
            {
                written = decompressor.Unwrap(payload, plaintext, 0);
            }
            catch (ZstdException ex)
            {
                throw new IntegrityException($"Chunk {id} does not decompress.", ex);
            }
            if (written != plainLength) throw new IntegrityException($"Chunk {id} decompressed to {written} bytes, expected {plainLength}.");
        }
        else
        {
            if (payload.Length != plainLength) throw new IntegrityException($"Chunk {id} has {payload.Length} bytes, expected {plainLength}.");
            plaintext = payload;
        }

        if (!ChunkId.Compute(keys.ChunkIdKey, plaintext).Equals(id)) throw new IntegrityException($"Chunk {id} does not match its id.");
        return plaintext;
    }

    /// <summary>tenant id (16) ‖ chunk id (32) ‖ format version (1) ‖ flags (1) ‖ data key version (4).</summary>
    private static byte[] Aad(Guid tenantId, ChunkId id, byte flags, int version)
    {
        var aad = new byte[16 + 32 + 1 + 1 + 4];
        Core.Crypto.KeyHierarchy.WriteGuid(tenantId, aad);
        id.Value.CopyTo(aad, 16);
        aad[48] = FormatVersion;
        aad[49] = flags;
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(50), version);
        return aad;
    }
}
