using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Vaulty.Repository.Format;

/// <summary>
/// Pack file (docs/format/repository-v1.md §3): a header, chunk records, and a trailer with the record count and the
/// SHA-256 of everything before the trailer. The object key of a pack is the SHA-256 of the whole file, so a pack is
/// content-addressed and writing it twice is harmless.
/// <code>
/// header  "VYPK" | format 1 | 3 zero bytes | tenant id (16)                 = 24 bytes
/// records chunk records (ChunkCodec)
/// trailer "VYPE" | record count (4) | SHA-256 of header and records (32)    = 40 bytes
/// </code>
/// </summary>
public static class PackFormat
{
    public const byte FormatVersion = 1;
    public const int HeaderSize = 24;
    public const int TrailerSize = 40;
    private static readonly byte[] Magic = "VYPK"u8.ToArray();
    private static readonly byte[] TrailerMagic = "VYPE"u8.ToArray();

    public static void WriteHeader(Span<byte> destination, Guid tenantId)
    {
        Magic.CopyTo(destination);
        destination[4] = FormatVersion;
        destination[5] = destination[6] = destination[7] = 0;
        Core.Crypto.KeyHierarchy.WriteGuid(tenantId, destination.Slice(8, 16));
    }

    public static byte[] Trailer(int recordCount, ReadOnlySpan<byte> sha256OfBody)
    {
        var trailer = new byte[TrailerSize];
        TrailerMagic.CopyTo(trailer, 0);
        BinaryPrimitives.WriteInt32BigEndian(trailer.AsSpan(4, 4), recordCount);
        sha256OfBody.CopyTo(trailer.AsSpan(8));
        return trailer;
    }

    /// <summary>
    /// Parses a complete pack: checks header, tenant, every record boundary and the trailer hash. Returns the records'
    /// locations (offset of the record start, record length). Never decrypts.
    /// </summary>
    public static IReadOnlyList<ChunkLocation> Parse(ReadOnlySpan<byte> pack, Guid expectedTenant, string packHash)
    {
        if (pack.Length < HeaderSize + TrailerSize) throw new RepositoryFormatException("Pack is too short.");
        var header = new BinaryParser(pack[..HeaderSize]);
        header.Expect(Magic, "pack");
        if (header.U8() != FormatVersion) throw new RepositoryFormatException("Unknown pack format.");
        header.Bytes(3);
        if (header.Guid() != expectedTenant) throw new IntegrityException("Pack belongs to another tenant.");

        var body = pack[..^TrailerSize];
        var trailer = new BinaryParser(pack[^TrailerSize..]);
        trailer.Expect(TrailerMagic, "pack trailer");
        var count = (int)trailer.U32();
        if (!trailer.Bytes(32).SequenceEqual(SHA256.HashData(body))) throw new IntegrityException("Pack trailer hash does not match.");

        var locations = new List<ChunkLocation>(Math.Min(count, 100_000));
        var offset = HeaderSize;
        while (offset < body.Length)
        {
            var length = ChunkCodec.RecordLength(body[offset..]);
            if (offset + length > body.Length) throw new RepositoryFormatException("Record runs past the end of the pack.");
            var record = body.Slice(offset, length);
            var plain = BinaryPrimitives.ReadInt32BigEndian(record.Slice(37, 4));
            locations.Add(new ChunkLocation(ChunkCodec.ReadId(record), packHash, offset, length, plain));
            offset += length;
        }
        if (locations.Count != count) throw new RepositoryFormatException($"Pack has {locations.Count} records, trailer says {count}.");
        return locations;
    }
}

/// <summary>Object keys of a tenant repository (docs/format/repository-v1.md §2).</summary>
public static class RepositoryLayout
{
    public static string TenantPrefix(Guid tenantId) => $"tenants/{tenantId:D}/";

    public static string Pack(Guid tenantId, string packHash) => $"{TenantPrefix(tenantId)}packs/{packHash[..2]}/{packHash}.pack";

    public static string Index(Guid tenantId, string packHash) => $"{TenantPrefix(tenantId)}indexes/{packHash}.idx";

    public static string Manifest(Guid tenantId, string manifestId) =>
        $"{TenantPrefix(tenantId)}manifests/{manifestId[..2]}/{manifestId}.manifest";

    public static string Snapshot(Guid tenantId, Guid objectId, Guid snapshotId) =>
        $"{TenantPrefix(tenantId)}snapshots/{objectId:D}/{snapshotId:D}.snap";

    public static string Latest(Guid tenantId, Guid objectId) => $"{TenantPrefix(tenantId)}snapshots/{objectId:D}/LATEST";

    public static string DataKey(Guid tenantId, int version) => $"{TenantPrefix(tenantId)}keys/dek-{version}.json";

    public static string PackHashFromKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var name = key[(key.LastIndexOf('/') + 1)..];
        return name.EndsWith(".pack", StringComparison.Ordinal) ? name[..^5] : throw new ArgumentException($"Not a pack key: {key}");
    }
}
