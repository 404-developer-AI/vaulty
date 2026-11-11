using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Vaulty.Graph.Onboarding;

/// <summary>Where the Microsoft identity platform and Microsoft Graph live; tests point both at a local mock.</summary>
public sealed record MicrosoftEndpoints(Uri AuthorityHost, Uri Graph)
{
    public static readonly MicrosoftEndpoints Public = new(new Uri("https://login.microsoftonline.com/"), new Uri("https://graph.microsoft.com/v1.0/"));

    public Uri Authorize(string tenant) => new(AuthorityHost, $"{Uri.EscapeDataString(tenant)}/oauth2/v2.0/authorize");

    public Uri Token(string tenant) => new(AuthorityHost, $"{Uri.EscapeDataString(tenant)}/oauth2/v2.0/token");
}

/// <summary>Compact JWTs signed with a certificate's RSA key (RS256), as the identity platform accepts them.</summary>
public static class CertificateJwt
{
    /// <summary>Audience of a proof of possession for addKey and removeKey.</summary>
    public const string ProofAudience = "00000002-0000-0000-c000-000000000000";

    public static string Base64Url(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }

    public static string Sign(X509Certificate2 certificate, JsonObject claims)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(claims);
        using var rsa = certificate.GetRSAPrivateKey() ?? throw new InvalidOperationException("The certificate has no RSA private key.");
        var header = new JsonObject
        {
            ["alg"] = "RS256",
            ["typ"] = "JWT",
            ["kid"] = certificate.Thumbprint,
            ["x5t"] = Base64Url(certificate.GetCertHash()),
            ["x5t#S256"] = Base64Url(certificate.GetCertHash(HashAlgorithmName.SHA256)),
        };
        // No padding in either part: the identity platform refuses a proof with '=' in it.
        var signingInput = $"{Base64Url(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{Base64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()))}";
        var signature = rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64Url(signature)}";
    }

    /// <summary>The client assertion a confidential client signs in with (certificate credential).</summary>
    public static string ClientAssertion(X509Certificate2 certificate, Guid clientId, Uri tokenEndpoint, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(tokenEndpoint);
        return Sign(certificate, new JsonObject
        {
            ["aud"] = tokenEndpoint.ToString(),
            ["iss"] = clientId.ToString(),
            ["sub"] = clientId.ToString(),
            ["jti"] = Guid.NewGuid().ToString(),
            ["nbf"] = now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(9).ToUnixTimeSeconds(),
        });
    }

    /// <summary>
    /// Proof that the caller holds a key of the application (addKey, removeKey): signed with a valid certificate of the
    /// application, issuer the application's object id, valid ten minutes.
    /// </summary>
    public static string KeyProof(X509Certificate2 certificate, Guid applicationObjectId, DateTimeOffset now) => Sign(certificate, new JsonObject
    {
        ["aud"] = ProofAudience,
        ["iss"] = applicationObjectId.ToString(),
        ["nbf"] = now.ToUnixTimeSeconds(),
        ["exp"] = now.AddMinutes(10).ToUnixTimeSeconds(),
    });

    /// <summary>The payload of a JWT, without validating it.</summary>
    public static JsonObject Payload(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        var parts = jwt.Split('.');
        if (parts.Length < 2) throw new FormatException("Not a JWT.");
        return JsonNode.Parse(FromBase64Url(parts[1]))?.AsObject() ?? throw new FormatException("Not a JWT.");
    }
}

/// <summary>Proof Key for Code Exchange (RFC 7636, S256).</summary>
public static class Pkce
{
    public static string NewVerifier() => CertificateJwt.Base64Url(RandomNumberGenerator.GetBytes(32));

    public static string Challenge(string verifier) => CertificateJwt.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
}

/// <summary>What Vaulty reads from the id token of a delegated sign-in.</summary>
/// <param name="DirectoryRoles">Role template ids (wids claim); null when the token carries none.</param>
public sealed record SignedInUser(Guid TenantId, Guid ObjectId, string UserName, string? Nonce, IReadOnlyList<Guid>? DirectoryRoles)
{
    /// <summary>Global Administrator and Privileged Role Administrator: the roles that can grant application permissions.</summary>
    public static readonly Guid[] GrantingRoles =
    [
        Guid.Parse("62e90394-69f5-4237-9190-012177145e10"),
        Guid.Parse("e8611ab8-c189-46e8-94e1-60213ab1f814"),
    ];

    /// <summary>False only when the token lists the user's roles and none of them can grant application permissions.</summary>
    public bool MayGrantPermissions => DirectoryRoles is null || DirectoryRoles.Any(GrantingRoles.Contains);

    public static SignedInUser FromIdToken(string idToken)
    {
        var claims = CertificateJwt.Payload(idToken);
        static string? Text(JsonObject o, string name) => o.TryGetPropertyValue(name, out var v) && v is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;
        var tid = Guid.TryParse(Text(claims, "tid"), out var t) ? t : throw new FormatException("The id token has no tenant.");
        var oid = Guid.TryParse(Text(claims, "oid"), out var o) ? o : Guid.Empty;
        var name = Text(claims, "preferred_username") ?? Text(claims, "upn") ?? Text(claims, "email") ?? "unknown";
        IReadOnlyList<Guid>? roles = claims.TryGetPropertyValue("wids", out var wids) && wids is JsonArray array
            ? array.Select(w => Guid.TryParse(w?.GetValue<string>(), out var g) ? g : Guid.Empty).Where(g => g != Guid.Empty).ToList()
            : null;
        return new SignedInUser(tid, oid, name, Text(claims, "nonce"), roles);
    }
}

/// <summary>The result of a delegated sign-in: held in memory only, never stored.</summary>
public sealed record DelegatedToken(string AccessToken, DateTimeOffset ExpiresOn, SignedInUser User);

/// <summary>A sign-in or token request the identity platform refused (AADSTS code in the message).</summary>
public sealed class IdentityException(string error, string description) : Exception($"{error}: {description}")
{
    public string Error { get; } = error;
    public string Description { get; } = description;
}

/// <summary>
/// The OAuth 2.0 flows of the "Vaulty setup" app: authorization code with PKCE for a delegated sign-in (no refresh token
/// is requested), and client credentials for its own app-only token. The client authenticates with its certificate.
/// </summary>
public sealed class IdentityClient(HttpClient http, MicrosoftEndpoints endpoints, TimeProvider clock)
{
    /// <summary>Delegated permissions the setup app asks for; nothing else, and no offline_access.</summary>
    public static readonly string[] SetupScopes =
    [
        "https://graph.microsoft.com/Application.ReadWrite.All",
        "https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All",
        "openid",
        "profile",
    ];

    public MicrosoftEndpoints Endpoints => endpoints;

    public Uri AuthorizationUrl(string tenant, Guid clientId, Uri redirectUri, string state, string nonce, string codeChallenge, bool consent,
        string? loginHint = null)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        var query = new List<KeyValuePair<string, string>>
        {
            new("client_id", clientId.ToString()),
            new("response_type", "code"),
            new("redirect_uri", redirectUri.ToString()),
            new("response_mode", "query"),
            new("scope", string.Join(' ', SetupScopes)),
            new("state", state),
            new("nonce", nonce),
            new("code_challenge", codeChallenge),
            new("code_challenge_method", "S256"),
        };
        query.Add(new("prompt", consent ? "consent" : "select_account"));
        if (!string.IsNullOrWhiteSpace(loginHint)) query.Add(new("login_hint", loginHint));
        var text = string.Join('&', query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        return new Uri($"{endpoints.Authorize(tenant)}?{text}");
    }

    public async Task<DelegatedToken> RedeemCodeAsync(string tenant, Guid clientId, X509Certificate2 certificate, Uri redirectUri, string code,
        string codeVerifier, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        var tokenEndpoint = endpoints.Token(tenant);
        var form = new Dictionary<string, string>
        {
            ["client_id"] = clientId.ToString(),
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri.ToString(),
            ["code_verifier"] = codeVerifier,
            ["scope"] = string.Join(' ', SetupScopes),
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = CertificateJwt.ClientAssertion(certificate, clientId, tokenEndpoint, clock.GetUtcNow()),
        };
        var json = await PostAsync(tokenEndpoint, form, cancellationToken).ConfigureAwait(false);
        var idToken = json["id_token"]?.GetValue<string>() ?? throw new IdentityException("invalid_response", "No id token in the response.");
        return new DelegatedToken(AccessToken(json), ExpiresOn(json), SignedInUser.FromIdToken(idToken));
    }

    /// <summary>An app-only Graph token of an application with a certificate (client credentials).</summary>
    public async Task<(string AccessToken, DateTimeOffset ExpiresOn)> AppOnlyTokenAsync(string tenant, Guid clientId, X509Certificate2 certificate,
        CancellationToken cancellationToken = default)
    {
        var tokenEndpoint = endpoints.Token(tenant);
        var json = await PostAsync(tokenEndpoint, new Dictionary<string, string>
        {
            ["client_id"] = clientId.ToString(),
            ["grant_type"] = "client_credentials",
            ["scope"] = "https://graph.microsoft.com/.default",
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = CertificateJwt.ClientAssertion(certificate, clientId, tokenEndpoint, clock.GetUtcNow()),
        }, cancellationToken).ConfigureAwait(false);
        return (AccessToken(json), ExpiresOn(json));
    }

    private static string AccessToken(JsonObject json) =>
        json["access_token"]?.GetValue<string>() ?? throw new IdentityException("invalid_response", "No access token in the response.");

    private DateTimeOffset ExpiresOn(JsonObject json) =>
        clock.GetUtcNow().AddSeconds(json["expires_in"] is JsonValue v && (v.TryGetValue<int>(out var i) || int.TryParse(v.ToString(), out i)) ? i : 3600);

    private async Task<JsonObject> PostAsync(Uri endpoint, Dictionary<string, string> form, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new FormUrlEncodedContent(form) };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        JsonObject? json = null;
        try
        {
            json = JsonNode.Parse(body)?.AsObject();
        }
        catch (JsonException)
        {
        }
        if (!response.IsSuccessStatusCode || json is null)
        {
            throw new IdentityException(json?["error"]?.GetValue<string>() ?? $"http_{(int)response.StatusCode}",
                json?["error_description"]?.GetValue<string>() ?? "The identity platform refused the request.");
        }
        return json;
    }
}

/// <summary>Turns identity platform and Graph refusals into one sentence that says what to do.</summary>
public static class SignInErrors
{
    public static string Explain(string? error, string? description)
    {
        var text = $"{error} {description}";
        if (Has(text, "AADSTS65004") || Has(text, "consent_required") && Has(text, "declined") || Has(error, "access_denied"))
        {
            return "The sign-in was cancelled or consent was declined, so nothing was changed. Start again and accept the permissions.";
        }
        if (Has(text, "AADSTS90094") || Has(text, "AADSTS90008") || Has(text, "AADSTS65001"))
        {
            return "This account cannot give consent for the tenant. Sign in as a Global Administrator or Privileged Role Administrator.";
        }
        if (Has(text, "AADSTS53003") || Has(text, "AADSTS53000") || Has(text, "AADSTS53001"))
        {
            return "A Conditional Access policy of the tenant blocked the sign-in. Sign in from a device or location the policy allows, or use the script.";
        }
        if (Has(text, "AADSTS50020") || Has(text, "AADSTS90072"))
        {
            return "This account does not belong to the tenant you are connecting. Sign in with an account of that tenant, or enter its domain for a GDAP sign-in.";
        }
        if (Has(text, "AADSTS700016") || Has(text, "AADSTS7000112") || Has(text, "AADSTS500113") || Has(text, "AADSTS50011"))
        {
            return "Microsoft does not accept the Vaulty setup app (it is missing, disabled or its redirect URI differs). Check it under Settings > Microsoft 365.";
        }
        if (Has(text, "AADSTS9002313") || Has(text, "AADSTS54005") || Has(text, "AADSTS70008"))
        {
            return "The sign-in expired or was already used. Start again.";
        }
        if (Has(text, "AADSTS700027") || Has(text, "AADSTS7000222") || Has(text, "AADSTS700024"))
        {
            return "Microsoft refused the certificate of the Vaulty setup app. Check it under Settings > Microsoft 365.";
        }
        return "Microsoft refused the sign-in" + (string.IsNullOrWhiteSpace(error) ? "." : $" ({FirstCode(text) ?? error}).") + " Start again, or use the script instead.";
    }

    private static bool Has(string? text, string value) => text?.Contains(value, StringComparison.OrdinalIgnoreCase) == true;

    private static string? FirstCode(string text)
    {
        var index = text.IndexOf("AADSTS", StringComparison.Ordinal);
        if (index < 0) return null;
        var end = index + 6;
        while (end < text.Length && char.IsDigit(text[end])) end++;
        return text[index..end];
    }
}
