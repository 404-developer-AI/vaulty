using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Vaulty.Infrastructure.Access;
using Vaulty.Integration.Tests.Database;

namespace Vaulty.Integration.Tests.Web;

/// <summary>The web app on a throwaway database, with a development master key, served over https://localhost.</summary>
public sealed class WebAppFixture : IAsyncLifetime
{
    public PostgresDatabase Database { get; } = new();
    public WebApplicationFactory<Vaulty.Web.WebMarker> Factory { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await Database.InitializeAsync();
        if (string.IsNullOrEmpty(PostgresDatabase.AdminConnectionString)) return;
        Environment.SetEnvironmentVariable("VAULTY_DEV_MASTER_KEY", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        var connection = Database.Api;
        Factory = new WebApplicationFactory<Vaulty.Web.WebMarker>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Development");
            b.UseSetting("Vaulty:Database:ConnectionString", connection);
            b.UseSetting("Vaulty:HostId", "test-host");
            b.UseSetting("Vaulty:PublicHost", "localhost");
        });
    }

    public async Task DisposeAsync()
    {
        if (Factory is not null) await Factory.DisposeAsync();
        await Database.DisposeAsync();
    }

    public HttpClient Client() => Factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    public async Task<string> IssueSetupTokenAsync()
    {
        using var scope = Factory.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<SetupTokens>().IssueAsync("test");
    }
}

internal static partial class Html
{
    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"__RequestVerificationToken\"")]
    private static partial Regex FormToken();

    [GeneratedRegex("<meta name=\"vaulty-antiforgery\" content=\"([^\"]+)\"")]
    private static partial Regex MetaToken();

    [GeneratedRegex("<span class=\"vy-secret\">([^<]+)</span>")]
    private static partial Regex Secret();

    [GeneratedRegex("<div class=\"vy-codes\">(.*?)</div>", RegexOptions.Singleline)]
    private static partial Regex Codes();

    public static string FormTokenOf(string html)
    {
        var match = FormToken().Match(html);
        Assert.True(match.Success, "no antiforgery token in the page");
        return WebUtility.HtmlDecode(match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value);
    }

    public static string MetaTokenOf(string html) => WebUtility.HtmlDecode(MetaToken().Match(html).Groups[1].Value);

    public static string AuthenticatorKeyOf(string html) => Secret().Match(html).Groups[1].Value.Replace(" ", "", StringComparison.Ordinal);

    public static IReadOnlyList<string> RecoveryCodesOf(string html) =>
        Regex.Matches(Codes().Match(html).Groups[1].Value, "<span>([^<]+)</span>").Select(m => m.Groups[1].Value).ToList();

    public static async Task<HttpResponseMessage> PostFormAsync(this HttpClient client, string url, string token,
        params (string Name, string Value)[] fields)
    {
        var form = new FormUrlEncodedContent(fields.Append(("__RequestVerificationToken", token))
            .Select(f => new KeyValuePair<string, string>(f.Item1, f.Item2)));
        return await client.PostAsync(url, form);
    }

    public static async Task<HttpResponseMessage> PostJsonAsync(this HttpClient client, string url, string token, object? body = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.Add("X-Vaulty-Antiforgery", token);
        request.Headers.Add("Origin", "https://localhost");
        request.Content = new StringContent(body is null ? "" : JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        return await client.SendAsync(request);
    }
}

/// <summary>RFC 6238 TOTP (SHA-1, 6 digits, 30 seconds), as authenticator apps compute it.</summary>
internal static class Totp
{
    public static string Code(string base32Key, DateTimeOffset? at = null)
    {
        var key = Base32Decode(base32Key);
        var counter = (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / 30;
        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(message, counter);
        var hash = HMACSHA1.HashData(key, message);
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = 0;
        var value = 0;
        var output = new List<byte>();
        foreach (var c in input.TrimEnd('=').ToUpperInvariant())
        {
            value = (value << 5) | alphabet.IndexOf(c, StringComparison.Ordinal);
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(value >> (bits - 8)));
                bits -= 8;
            }
        }
        return [.. output];
    }
}

/// <summary>A software WebAuthn authenticator (ES256, "none" attestation, discoverable), standing in for a passkey.</summary>
internal sealed class SoftwareAuthenticator : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] _credentialId = RandomNumberGenerator.GetBytes(32);
    private string? _userHandle;
    private uint _signCount;

    public string Origin { get; init; } = "https://localhost";
    public string RpId { get; init; } = "localhost";

    public static string B64(ReadOnlySpan<byte> data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Answers navigator.credentials.create() for the given creation options JSON.</summary>
    public string Create(string optionsJson)
    {
        using var options = JsonDocument.Parse(optionsJson);
        var root = options.RootElement;
        var challenge = root.GetProperty("challenge").GetString()!;
        _userHandle = root.GetProperty("user").GetProperty("id").GetString();
        var clientData = ClientData("webauthn.create", challenge);

        var parameters = _key.ExportParameters(false);
        var cose = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2);     // kty: EC2
        cose.WriteInt32(3); cose.WriteInt32(-7);    // alg: ES256
        cose.WriteInt32(-1); cose.WriteInt32(1);    // crv: P-256
        cose.WriteInt32(-2); cose.WriteByteString(parameters.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(parameters.Q.Y!);
        cose.WriteEndMap();
        var coseKey = cose.Encode();

        var authData = new List<byte>();
        authData.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)));
        authData.Add(0x45); // UP | UV | AT
        authData.AddRange(new byte[4]);
        authData.AddRange(new byte[16]); // AAGUID
        authData.Add((byte)(_credentialId.Length >> 8));
        authData.Add((byte)_credentialId.Length);
        authData.AddRange(_credentialId);
        authData.AddRange(coseKey);

        var attestation = new CborWriter(CborConformanceMode.Ctap2Canonical);
        attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt"); attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
        attestation.WriteTextString("authData"); attestation.WriteByteString(authData.ToArray());
        attestation.WriteEndMap();

        return JsonSerializer.Serialize(new
        {
            id = B64(_credentialId),
            rawId = B64(_credentialId),
            type = "public-key",
            authenticatorAttachment = "platform",
            clientExtensionResults = new { },
            response = new
            {
                clientDataJSON = B64(clientData),
                attestationObject = B64(attestation.Encode()),
                transports = new[] { "internal" },
            },
        });
    }

    /// <summary>Answers navigator.credentials.get() for the given request options JSON.</summary>
    public string Get(string optionsJson)
    {
        using var options = JsonDocument.Parse(optionsJson);
        var challenge = options.RootElement.GetProperty("challenge").GetString()!;
        var clientData = ClientData("webauthn.get", challenge);
        var authData = new byte[37];
        SHA256.HashData(Encoding.UTF8.GetBytes(RpId)).CopyTo(authData, 0);
        authData[32] = 0x05; // UP | UV
        BinaryPrimitives.WriteUInt32BigEndian(authData.AsSpan(33), ++_signCount);
        var signed = authData.Concat(SHA256.HashData(clientData)).ToArray();
        var signature = _key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return JsonSerializer.Serialize(new
        {
            id = B64(_credentialId),
            rawId = B64(_credentialId),
            type = "public-key",
            authenticatorAttachment = "platform",
            clientExtensionResults = new { },
            response = new
            {
                clientDataJSON = B64(clientData),
                authenticatorData = B64(authData),
                signature = B64(signature),
                userHandle = _userHandle,
            },
        });
    }

    private byte[] ClientData(string type, string challenge) =>
        JsonSerializer.SerializeToUtf8Bytes(new { type, challenge, origin = Origin, crossOrigin = false });

    public void Dispose() => _key.Dispose();
}
