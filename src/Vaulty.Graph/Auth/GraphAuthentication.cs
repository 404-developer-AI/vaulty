using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Identity.Client;

namespace Vaulty.Graph.Auth;

/// <summary>The application identity Vaulty uses in one Microsoft 365 tenant (dedicated app: an app in the customer's tenant).</summary>
public sealed record GraphCredential(Guid EntraTenantId, Guid ClientId, X509Certificate2 Certificate);

/// <summary>Resolves the credential of a tenant. Phase 1: dedicated app per tenant, certificate from the secrets store.</summary>
public interface IGraphCredentialProvider
{
    Task<GraphCredential> GetAsync(Guid tenantId, CancellationToken cancellationToken = default);
}

/// <summary>An app-only access token for Microsoft Graph.</summary>
public sealed record GraphToken(string AccessToken, DateTimeOffset ExpiresOn)
{
    /// <summary>The application permissions granted to the app, from the token's roles claim.</summary>
    public IReadOnlyList<string> Roles => TokenClaims.Roles(AccessToken);
}

public interface IGraphTokenProvider
{
    Task<GraphToken> GetTokenAsync(Guid tenantId, bool forceRefresh = false, CancellationToken cancellationToken = default);
}

/// <summary>
/// MSAL confidential client per tenant credential with certificate authentication (x5c sent, so certificate rotation in
/// the app registration works by subject name too). Tokens are cached by MSAL in memory, partitioned per tenant.
/// </summary>
public sealed class MsalGraphTokenProvider(IGraphCredentialProvider credentials, string authorityHost = "https://login.microsoftonline.com")
    : IGraphTokenProvider
{
    private static readonly string[] Scopes = ["https://graph.microsoft.com/.default"];
    private readonly ConcurrentDictionary<string, IConfidentialClientApplication> _apps = new(StringComparer.Ordinal);

    public async Task<GraphToken> GetTokenAsync(Guid tenantId, bool forceRefresh = false, CancellationToken cancellationToken = default)
    {
        var credential = await credentials.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
        var key = $"{credential.EntraTenantId:N}/{credential.ClientId:N}/{credential.Certificate.Thumbprint}";
        var app = _apps.GetOrAdd(key, _ => ConfidentialClientApplicationBuilder
            .Create(credential.ClientId.ToString())
            .WithCertificate(credential.Certificate, sendX5C: true)
            .WithAuthority($"{authorityHost.TrimEnd('/')}/{credential.EntraTenantId:D}")
            .WithLegacyCacheCompatibility(false)
            .Build());
        var result = await app.AcquireTokenForClient(Scopes).WithForceRefresh(forceRefresh)
            .ExecuteAsync(cancellationToken).ConfigureAwait(false);
        return new GraphToken(result.AccessToken, result.ExpiresOn);
    }
}

/// <summary>Reads claims from a JWT without validating it (the token comes from the identity platform over TLS).</summary>
public static class TokenClaims
{
    public static IReadOnlyList<string> Roles(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        var parts = jwt.Split('.');
        if (parts.Length < 2) return [];
        try
        {
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
            return doc.RootElement.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array
                ? roles.EnumerateArray().Select(r => r.GetString()).OfType<string>().ToList()
                : [];
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return [];
        }
    }
}
