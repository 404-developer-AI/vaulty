using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dapper;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using Vaulty.Core.Crypto;

namespace Vaulty.Infrastructure.Secrets;

/// <summary>
/// Seals keys of the ASP.NET Data Protection ring with AES-256-GCM under the key derived for purpose "dataprotection".
/// Layout: nonce (12) | ciphertext | tag (16); authenticated data "vaulty-dataprotection-v1" ‖ 0x1F ‖ friendly name.
/// </summary>
public sealed class DataProtectionKeyCipher : IDisposable
{
    private readonly byte[] _key;

    public DataProtectionKeyCipher(ReadOnlySpan<byte> masterKey)
    {
        _key = KeyHierarchy.DeriveHostKey(masterKey, HostKeyPurpose.DataProtection);
    }

    public byte[] Seal(string xml, string friendlyName)
    {
        var plaintext = Encoding.UTF8.GetBytes(xml);
        var output = new byte[12 + plaintext.Length + 16];
        RandomNumberGenerator.Fill(output.AsSpan(0, 12));
        using var gcm = new AesGcm(_key, 16);
        gcm.Encrypt(output.AsSpan(0, 12), plaintext, output.AsSpan(12, plaintext.Length), output.AsSpan(12 + plaintext.Length),
            Aad(friendlyName));
        CryptographicOperations.ZeroMemory(plaintext);
        return output;
    }

    public string Open(byte[] sealedXml, string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(sealedXml);
        var length = sealedXml.Length - 28;
        if (length < 0) throw new CryptographicException("Sealed key is too short.");
        var plaintext = new byte[length];
        using var gcm = new AesGcm(_key, 16);
        gcm.Decrypt(sealedXml.AsSpan(0, 12), sealedXml.AsSpan(12, length), sealedXml.AsSpan(12 + length), plaintext, Aad(friendlyName));
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] Aad(string friendlyName) => Encoding.UTF8.GetBytes("vaulty-dataprotection-v1\u001f" + friendlyName);

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}

/// <summary>
/// Stores the Data Protection key ring in PostgreSQL, sealed per key, so web and API share one ring and nobody who
/// reads the database without the host master key can forge a session cookie.
/// </summary>
public sealed class PostgresXmlRepository(NpgsqlDataSource dataSource, DataProtectionKeyCipher cipher) : IXmlRepository
{
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var connection = dataSource.OpenConnection();
        return connection.Query<(string FriendlyName, byte[] Sealed)>(
                "SELECT friendly_name, sealed_xml FROM vaulty.data_protection_keys ORDER BY id")
            .Select(r => XElement.Parse(cipher.Open(r.Sealed, r.FriendlyName)))
            .ToList();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        using var connection = dataSource.OpenConnection();
        connection.Execute(
            "INSERT INTO vaulty.data_protection_keys (friendly_name, sealed_xml) VALUES (@friendlyName, @sealedXml)",
            new { friendlyName, sealedXml = cipher.Seal(element.ToString(SaveOptions.DisableFormatting), friendlyName) });
    }
}

public static class DataProtectionSetup
{
    /// <summary>Persists the key ring in PostgreSQL, sealed with the host master key.</summary>
    public static IDataProtectionBuilder PersistKeysToVaultyDatabase(this IDataProtectionBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(services =>
            new ConfigureOptions<KeyManagementOptions>(options =>
            {
                options.XmlRepository = new PostgresXmlRepository(services.GetRequiredService<NpgsqlDataSource>(),
                    services.GetRequiredService<DataProtectionKeyCipher>());
                // The repository seals every key; the element-level encryptor would only double it.
                options.XmlEncryptor = new NullXmlEncryptor();
            }));
        return builder;
    }
}
