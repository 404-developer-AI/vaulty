using System.Security.Cryptography;

namespace Vaulty.Repository.Format;

/// <summary>Where a chunk is stored: a byte range of a pack.</summary>
public sealed record ChunkLocation(ChunkId Id, string PackHash, long Offset, int Length, int PlaintextLength);

/// <summary>The content of one item: its size, keyed BLAKE3 over the whole plaintext, and its chunks in order.</summary>
public sealed record ItemContent(long Size, byte[] ContentHash, IReadOnlyList<ChunkId> Chunks)
{
    public string ContentHashHex => Convert.ToHexStringLower(ContentHash);
}

/// <summary>One item in a manifest.</summary>
public sealed record ManifestEntry(
    string SourceId,
    string? ParentSourceId,
    string Kind,
    string MetadataJson,
    ItemContent? Content)
{
    public bool HasContent => Content is not null;
}

/// <summary>The items of one folder or drive part at the time of a snapshot.</summary>
public sealed record Manifest(Guid ProtectedObjectId, IReadOnlyList<ManifestEntry> Entries);

public enum SnapshotOutcome : byte
{
    Committed = 1,
    Partial = 2,
}

/// <summary>The root of a snapshot: references to every manifest, counts, and a Merkle root over the manifest ids.</summary>
public sealed record SnapshotRoot(
    Guid TenantId,
    Guid ProtectedObjectId,
    Guid SnapshotId,
    DateTimeOffset CreatedAt,
    SnapshotOutcome Outcome,
    string CountsJson,
    string ExceptionsJson,
    IReadOnlyList<byte[]> ManifestIds)
{
    public byte[] RootHash => Merkle.Root(ManifestIds);
}

/// <summary>
/// Binary Merkle tree over 32-byte ids: leaf = SHA-256(0x00 ‖ id), node = SHA-256(0x01 ‖ left ‖ right), an odd node is
/// promoted unchanged; the root of an empty list is SHA-256 of nothing.
/// </summary>
public static class Merkle
{
    public static byte[] Root(IReadOnlyList<byte[]> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        if (ids.Count == 0) return SHA256.HashData([]);
        var level = ids.Select(id => SHA256.HashData([0x00, .. id])).ToList();
        while (level.Count > 1)
        {
            var next = new List<byte[]>((level.Count + 1) / 2);
            for (var i = 0; i < level.Count; i += 2)
            {
                next.Add(i + 1 < level.Count ? SHA256.HashData([0x01, .. level[i], .. level[i + 1]]) : level[i]);
            }
            level = next;
        }
        return level[0];
    }
}

/// <summary>Serialization of manifests, snapshot roots and index files (docs/format/repository-v1.md §5–7).</summary>
public static class StructureSerializer
{
    private static readonly byte[] ManifestMagic = "VYMF"u8.ToArray();
    private static readonly byte[] SnapshotMagic = "VYSN"u8.ToArray();
    private static readonly byte[] IndexMagic = "VYIX"u8.ToArray();
    public const byte FormatVersion = 1;

    public static byte[] Serialize(Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var b = new BinaryBuilder(64 + manifest.Entries.Count * 128).Bytes(ManifestMagic).U8(FormatVersion)
            .Guid(manifest.ProtectedObjectId).U32((uint)manifest.Entries.Count);
        foreach (var entry in manifest.Entries)
        {
            b.String(entry.SourceId).U8(entry.ParentSourceId is null ? (byte)0 : (byte)1).String(entry.ParentSourceId)
                .String(entry.Kind).String(entry.MetadataJson).U8(entry.Content is null ? (byte)0 : (byte)1);
            if (entry.Content is { } content)
            {
                b.I64(content.Size).Bytes(content.ContentHash).U32((uint)content.Chunks.Count);
                foreach (var chunk in content.Chunks) b.Bytes(chunk.Value);
            }
        }
        return b.ToArray();
    }

    public static Manifest DeserializeManifest(ReadOnlySpan<byte> data)
    {
        var p = new BinaryParser(data);
        p.Expect(ManifestMagic, "manifest");
        ExpectVersion(p.U8());
        var objectId = p.Guid();
        var count = p.Count(14);
        var entries = new List<ManifestEntry>(Math.Min(count, 100_000));
        for (var i = 0; i < count; i++)
        {
            var source = p.String();
            var hasParent = Flag(p.U8());
            var parent = p.String();
            var kind = p.String(256);
            var metadata = p.String(16 * 1024 * 1024);
            ItemContent? content = null;
            if (Flag(p.U8()))
            {
                var size = p.I64();
                if (size < 0) throw new RepositoryFormatException($"Negative size {size}.");
                var hash = p.Bytes(32).ToArray();
                var chunkCount = p.Count(ChunkId.Size);
                var chunks = new ChunkId[chunkCount];
                for (var c = 0; c < chunkCount; c++) chunks[c] = new ChunkId(p.Bytes(ChunkId.Size).ToArray());
                content = new ItemContent(size, hash, chunks);
            }
            entries.Add(new ManifestEntry(source, hasParent ? parent : null, kind, metadata, content));
        }
        p.End();
        return new Manifest(objectId, entries);
    }

    public static byte[] Serialize(SnapshotRoot root)
    {
        ArgumentNullException.ThrowIfNull(root);
        var b = new BinaryBuilder().Bytes(SnapshotMagic).U8(FormatVersion).Guid(root.TenantId).Guid(root.ProtectedObjectId)
            .Guid(root.SnapshotId).I64(Micros(root.CreatedAt)).U8((byte)root.Outcome).String(root.CountsJson)
            .String(root.ExceptionsJson).U32((uint)root.ManifestIds.Count);
        foreach (var id in root.ManifestIds) b.Bytes(id);
        return b.Bytes(root.RootHash).ToArray();
    }

    public static SnapshotRoot DeserializeSnapshot(ReadOnlySpan<byte> data)
    {
        var p = new BinaryParser(data);
        p.Expect(SnapshotMagic, "snapshot");
        ExpectVersion(p.U8());
        var tenant = p.Guid();
        var objectId = p.Guid();
        var snapshotId = p.Guid();
        var created = DateTimeOffset.UnixEpoch.AddTicks(p.I64() * 10);
        var outcome = p.U8();
        if (outcome is not ((byte)SnapshotOutcome.Committed or (byte)SnapshotOutcome.Partial))
        {
            throw new RepositoryFormatException($"Unknown snapshot outcome {outcome}.");
        }
        var counts = p.String(16 * 1024 * 1024);
        var exceptions = p.String(64 * 1024 * 1024);
        var manifestCount = p.Count(32);
        var ids = new List<byte[]>(manifestCount);
        for (var i = 0; i < manifestCount; i++) ids.Add(p.Bytes(32).ToArray());
        var root = new SnapshotRoot(tenant, objectId, snapshotId, created, (SnapshotOutcome)outcome, counts, exceptions, ids);
        if (!p.Bytes(32).SequenceEqual(root.RootHash)) throw new IntegrityException("Snapshot root hash does not match its manifests.");
        p.End();
        return root;
    }

    public static byte[] SerializeIndex(string packHash, IReadOnlyList<ChunkLocation> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var b = new BinaryBuilder(48 + entries.Count * 48).Bytes(IndexMagic).U8(FormatVersion).Bytes(Convert.FromHexString(packHash))
            .U32((uint)entries.Count);
        foreach (var e in entries) b.Bytes(e.Id.Value).I64(e.Offset).U32((uint)e.Length).U32((uint)e.PlaintextLength);
        return b.ToArray();
    }

    public static (string PackHash, IReadOnlyList<ChunkLocation> Entries) DeserializeIndex(ReadOnlySpan<byte> data)
    {
        var p = new BinaryParser(data);
        p.Expect(IndexMagic, "index");
        ExpectVersion(p.U8());
        var packHash = Convert.ToHexStringLower(p.Bytes(32));
        var count = p.Count(48);
        var entries = new List<ChunkLocation>(count);
        for (var i = 0; i < count; i++)
        {
            var id = new ChunkId(p.Bytes(32).ToArray());
            var offset = p.I64();
            var length = p.U32();
            var plain = p.U32();
            if (offset < 0 || length > int.MaxValue || plain > int.MaxValue) throw new RepositoryFormatException("Invalid index entry.");
            entries.Add(new ChunkLocation(id, packHash, offset, (int)length, (int)plain));
        }
        p.End();
        return (packHash, entries);
    }

    public static long Micros(DateTimeOffset value) => (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

    private static bool Flag(byte value) => value switch
    {
        0 => false,
        1 => true,
        _ => throw new RepositoryFormatException($"Invalid flag {value}."),
    };

    private static void ExpectVersion(byte version)
    {
        if (version != FormatVersion) throw new RepositoryFormatException($"Unknown structure format {version}.");
    }
}
