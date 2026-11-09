using System.Security.Cryptography;
using System.Text.Json;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Crypto;

namespace Vaulty.Core.Tests;

/// <summary>The test vectors published in docs/format/keys-v1.md. A change here is a format change.</summary>
public class KeyVectorTests
{
    private static readonly byte[] MasterKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] TenantKey = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] DataKey = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] FixedNonce = Enumerable.Range(0xa0, 12).Select(i => (byte)i).ToArray();
    private static readonly Guid TenantId = Guid.Parse("11111111-2222-3333-4444-555555555555");

    [Theory]
    [InlineData(HostKeyPurpose.Secrets, "e7501eceb1bd56f0d9469aa832dbd684522b11d17b101b4ba2a7c1a917edc0f6")] // gitleaks:allow (public test vector, docs/format/keys-v1.md)
    [InlineData(HostKeyPurpose.DataProtection, "d6bf680bcb637361f8c2faa3a56b938a05505d03796dc263922f59a8c5d6a8f1")]
    [InlineData(HostKeyPurpose.Export, "b55e52dd842817edc472b4cdc5804833f8c023f353042baba68d999758423d93")] // gitleaks:allow (public test vector, docs/format/keys-v1.md)
    [InlineData(HostKeyPurpose.Kek, "506e16cd548a7119ca2096991643722562a50a8c12cc68f15e57c1458f8ab2d5")] // gitleaks:allow (public test vector, docs/format/keys-v1.md)
    public void Host_key_derivations_match_the_specification(HostKeyPurpose purpose, string expected)
    {
        Assert.Equal(expected, Convert.ToHexStringLower(KeyHierarchy.DeriveHostKey(MasterKey, purpose)));
    }

    [Fact]
    public void Tenant_key_derivations_match_the_specification()
    {
        Assert.Equal("f10f280b566035337a064dd513984cb5985a687b061e5d99b1be1ae266219d66",
            Convert.ToHexStringLower(KeyHierarchy.DeriveObjectKey(TenantKey, TenantId)));
        Assert.Equal("732fc2a0a43302c95099357f56a7b9dde2b8ef385d2b8f2016fb9b4da0c64967",
            Convert.ToHexStringLower(KeyHierarchy.DeriveChunkIdKey(TenantKey)));
        Assert.Equal("f50b5ec5bef1706a753148adbf9f6ac4fd42eda7ee61daa8655c6251c0d49af3",
            Convert.ToHexStringLower(KeyHierarchy.DeriveMetadataKey(TenantKey)));
        Assert.Equal("54af3c9a5cbb9b936bec6944cd2e7d02d5e38f3180f4506537a88407d18c4685",
            Convert.ToHexStringLower(KeyHierarchy.DeriveRepositoryKey(TenantKey)));
    }

    [Fact]
    public void Wrapped_key_matches_the_specification()
    {
        using var wrapper = new SoftwareKeyWrapper(MasterKey, kekVersion: 1, nonceSource: () => FixedNonce);
        var wrapped = wrapper.Wrap(DataKey, new KeyWrapContext(TenantId, 1));
        Assert.Equal(WrapVector, Convert.ToHexStringLower(wrapped));
        Assert.Equal(DataKey, wrapper.Unwrap(wrapped, new KeyWrapContext(TenantId, 1)));
    }

    [Fact]
    public void Sealed_secret_matches_the_specification()
    {
        using var cipher = new SecretCipher(MasterKey, "host-a");
        var sealedSecret = cipher.Seal("smtp.password", 1, "correct horse"u8, Enumerable.Range(0, 12).Select(i => (byte)i).ToArray());
        Assert.Equal(SecretVector, Convert.ToHexStringLower([.. sealedSecret.Ciphertext, .. sealedSecret.Tag]));
    }

    internal const string WrapVector =
        "56594b57010100000001a0a1a2a3a4a5a6a7a8a9aaab573ed73c913e2955df41983e6218b478bfaf2e22e7e5cffe74ee5e673eb8a3594c37704dfea8d64de729640cd9cfc212";
    internal const string SecretVector = "bff76430a22b20b0f92209bafdf383c7321ff810aff472a2f9fa470976"; // gitleaks:allow (public test vector, docs/format/keys-v1.md)
}

public class KeyWrapperTests
{
    private static readonly byte[] MasterKey = RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void A_wrapped_key_is_bound_to_its_tenant_and_version()
    {
        using var wrapper = new SoftwareKeyWrapper(MasterKey);
        var tenant = Guid.NewGuid();
        var dek = RandomNumberGenerator.GetBytes(32);
        var wrapped = wrapper.Wrap(dek, new KeyWrapContext(tenant, 3));
        Assert.Equal(dek, wrapper.Unwrap(wrapped, new KeyWrapContext(tenant, 3)));
        Assert.ThrowsAny<CryptographicException>(() => wrapper.Unwrap(wrapped, new KeyWrapContext(Guid.NewGuid(), 3)));
        Assert.ThrowsAny<CryptographicException>(() => wrapper.Unwrap(wrapped, new KeyWrapContext(tenant, 4)));
    }

    [Fact]
    public void The_header_records_wrapper_type_and_kek_version_and_is_authenticated()
    {
        using var wrapper = new SoftwareKeyWrapper(MasterKey, kekVersion: 7);
        var context = new KeyWrapContext(Guid.NewGuid(), 1);
        var wrapped = wrapper.Wrap(new byte[32], context);
        Assert.Equal((SoftwareKeyWrapper.Type, 7), SoftwareKeyWrapper.ReadHeader(wrapped));

        using var otherVersion = new SoftwareKeyWrapper(MasterKey, kekVersion: 8);
        Assert.ThrowsAny<CryptographicException>(() => otherVersion.Unwrap(wrapped, context));

        var tampered = (byte[])wrapped.Clone();
        tampered[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => wrapper.Unwrap(tampered, context));
    }

    [Fact]
    public void Another_master_key_cannot_unwrap()
    {
        using var wrapper = new SoftwareKeyWrapper(MasterKey);
        using var other = new SoftwareKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var context = new KeyWrapContext(Guid.NewGuid(), 1);
        Assert.ThrowsAny<CryptographicException>(() => other.Unwrap(wrapper.Wrap(new byte[32], context), context));
    }

    [Fact]
    public void A_sealed_secret_is_bound_to_name_version_and_host()
    {
        using var cipher = new SecretCipher(MasterKey, "host-a");
        using var otherHost = new SecretCipher(MasterKey, "host-b");
        var sealedSecret = cipher.Seal("storage.worker.secret", 2, "value"u8);
        Assert.Equal("value"u8.ToArray(), cipher.Open("storage.worker.secret", 2, sealedSecret));
        Assert.ThrowsAny<CryptographicException>(() => otherHost.Open("storage.worker.secret", 2, sealedSecret));
        Assert.ThrowsAny<CryptographicException>(() => cipher.Open("storage.gc.secret", 2, sealedSecret));
        Assert.ThrowsAny<CryptographicException>(() => cipher.Open("storage.worker.secret", 1, sealedSecret));
    }
}

public class SecretRedactionTests
{
    [Fact]
    public void A_secret_never_shows_its_value_as_text_or_json()
    {
        using var secret = new Secret("smtp.password", 1, "hunter2-value"u8);
        Assert.Equal("[redacted]", secret.ToString());
        Assert.Equal("[redacted]", $"{secret}");
        var json = JsonSerializer.Serialize(new { password = secret });
        Assert.DoesNotContain("hunter2", json, StringComparison.Ordinal);
        Assert.Contains("[redacted]", json, StringComparison.Ordinal);
        Assert.Equal("hunter2-value", secret.RevealString());
    }

    [Fact]
    public void A_disposed_secret_is_wiped()
    {
        var secret = new Secret("x", 1, "abc"u8);
        secret.Dispose();
        Assert.Throws<ObjectDisposedException>(() => secret.Reveal().Length);
    }
}
