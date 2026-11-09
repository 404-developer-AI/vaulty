using System.Security.Cryptography;
using System.Text;

namespace Vaulty.Core.Crypto;

/// <summary>One encrypted secret value as stored in the secrets table.</summary>
public sealed record SealedSecret(byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>
/// AES-256-GCM for rows of the secrets table, with the key derived for purpose "secrets". The authenticated data is
/// "vaulty-secret-v1" ‖ 0x1F ‖ name ‖ 0x1F ‖ version ‖ 0x1F ‖ host id (UTF-8), so a row copied to another name, version or
/// host does not decrypt.
/// </summary>
public sealed class SecretCipher : IDisposable
{
    private readonly byte[] _key;

    public SecretCipher(ReadOnlySpan<byte> masterKey, string hostId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostId);
        _key = KeyHierarchy.DeriveHostKey(masterKey, HostKeyPurpose.Secrets);
        HostId = hostId;
    }

    public string HostId { get; }

    public static byte[] AssociatedData(string name, int version, string hostId) =>
        Encoding.UTF8.GetBytes(string.Join('\u001f', "vaulty-secret-v1", name,
            version.ToString(System.Globalization.CultureInfo.InvariantCulture), hostId));

    public SealedSecret Seal(string name, int version, ReadOnlySpan<byte> plaintext, byte[]? nonce = null)
    {
        nonce ??= RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(_key, 16);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData(name, version, HostId));
        return new SealedSecret(nonce, ciphertext, tag);
    }

    public byte[] Open(string name, int version, SealedSecret sealedSecret)
    {
        ArgumentNullException.ThrowIfNull(sealedSecret);
        var plaintext = new byte[sealedSecret.Ciphertext.Length];
        using var gcm = new AesGcm(_key, 16);
        gcm.Decrypt(sealedSecret.Nonce, sealedSecret.Ciphertext, sealedSecret.Tag, plaintext,
            AssociatedData(name, version, HostId));
        return plaintext;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
