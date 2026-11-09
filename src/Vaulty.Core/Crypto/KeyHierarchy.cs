using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Vaulty.Core.Crypto;

/// <summary>Purposes of the keys derived from the host master key. Each label is part of the public key specification.</summary>
public enum HostKeyPurpose
{
    /// <summary>Encrypts the rows of the secrets table.</summary>
    Secrets,
    /// <summary>Encrypts the ASP.NET Data Protection key ring (cookies, antiforgery tokens).</summary>
    DataProtection,
    /// <summary>Encrypts an export of the secrets store.</summary>
    Export,
    /// <summary>The key encryption key of the software key wrapper, which wraps tenant data keys.</summary>
    Kek,
}

/// <summary>
/// The key derivations of Vaulty (specification: docs/format/keys-v1.md). All derivations are HKDF-SHA256 with a fixed
/// salt per level and an info string naming the purpose, so no derived key can be used for another purpose.
/// </summary>
public static class KeyHierarchy
{
    public const int KeySize = 32;

    /// <summary>Salt for keys derived from the host master key.</summary>
    public static readonly byte[] HostSalt = Encoding.ASCII.GetBytes("vaulty-host-keys-v1");

    /// <summary>Salt for keys derived from a tenant data key.</summary>
    public static readonly byte[] TenantSalt = Encoding.ASCII.GetBytes("vaulty-tenant-keys-v1");

    public static string Label(HostKeyPurpose purpose) => purpose switch
    {
        HostKeyPurpose.Secrets => "secrets",
        HostKeyPurpose.DataProtection => "dataprotection",
        HostKeyPurpose.Export => "export",
        HostKeyPurpose.Kek => "kek",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose)),
    };

    /// <summary>HKDF-SHA256(ikm = master key, salt = "vaulty-host-keys-v1", info = purpose label), 32 bytes.</summary>
    public static byte[] DeriveHostKey(ReadOnlySpan<byte> masterKey, HostKeyPurpose purpose)
    {
        if (masterKey.Length != KeySize) throw new ArgumentException("The master key must be 32 bytes.", nameof(masterKey));
        var output = new byte[KeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, output, HostSalt, Encoding.ASCII.GetBytes(Label(purpose)));
        return output;
    }

    /// <summary>
    /// The key for one protected object: HKDF-SHA256(ikm = tenant data key, salt = "vaulty-tenant-keys-v1",
    /// info = "object:" ‖ object id as 16 bytes in RFC 4122 order). Destroying the object's entry in the tombstone list
    /// stops this derivation, which makes the object's data unreadable (crypto-shredding).
    /// </summary>
    public static byte[] DeriveObjectKey(ReadOnlySpan<byte> tenantKey, Guid protectedObjectId) =>
        DeriveTenantSubkey(tenantKey, "object:", protectedObjectId);

    /// <summary>The key of the keyed BLAKE3 chunk ids of a tenant: info = "chunk-id".</summary>
    public static byte[] DeriveChunkIdKey(ReadOnlySpan<byte> tenantKey) => DeriveTenantSubkey(tenantKey, "chunk-id", null);

    /// <summary>The key that encrypts item metadata in the database: info = "metadata".</summary>
    public static byte[] DeriveMetadataKey(ReadOnlySpan<byte> tenantKey) => DeriveTenantSubkey(tenantKey, "metadata", null);

    /// <summary>The key that encrypts repository structures shared by a tenant (indexes, manifests, snapshots): info = "repository".</summary>
    public static byte[] DeriveRepositoryKey(ReadOnlySpan<byte> tenantKey) => DeriveTenantSubkey(tenantKey, "repository", null);

    private static byte[] DeriveTenantSubkey(ReadOnlySpan<byte> tenantKey, string label, Guid? id)
    {
        if (tenantKey.Length != KeySize) throw new ArgumentException("A tenant key must be 32 bytes.", nameof(tenantKey));
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var info = new byte[labelBytes.Length + (id.HasValue ? 16 : 0)];
        labelBytes.CopyTo(info, 0);
        if (id.HasValue) WriteGuid(id.Value, info.AsSpan(labelBytes.Length));
        var output = new byte[KeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, tenantKey, output, TenantSalt, info);
        return output;
    }

    /// <summary>Writes a GUID as 16 bytes in RFC 4122 (big-endian) order, the order its text form shows.</summary>
    public static void WriteGuid(Guid value, Span<byte> destination)
    {
        if (!value.TryWriteBytes(destination, bigEndian: true, out _)) throw new ArgumentException("Need 16 bytes.", nameof(destination));
    }

    public static byte[] GuidBytes(Guid value)
    {
        var bytes = new byte[16];
        WriteGuid(value, bytes);
        return bytes;
    }

    internal static void WriteInt32(Span<byte> destination, int value) => BinaryPrimitives.WriteInt32BigEndian(destination, value);
}
