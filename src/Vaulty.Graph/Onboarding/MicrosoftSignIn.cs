using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Vaulty.Graph.Onboarding;

/// <summary>The Entra account an id token proves, after every rule of <see cref="SignInTokenRules"/> passed.</summary>
/// <param name="Account">The account name (<c>preferred_username</c>), for display and the audit log only; never used to match.</param>
/// <param name="MfaProven">The <c>amr</c> claim names a multi-factor method; false whenever the token does not say so.</param>
/// <param name="Methods">The <c>amr</c> values as short names, for the audit log.</param>
/// <param name="AuthenticatedAt">The <c>auth_time</c> claim: when the person last entered credentials at Microsoft.</param>
public sealed record MicrosoftAccount(Guid TenantId, Guid ObjectId, string? Account, string? DisplayName, bool MfaProven, IReadOnlyList<string> Methods,
    string? AuthenticationClass, DateTimeOffset? AuthenticatedAt);

/// <summary>Either the account the token proves, or why it is refused (one sentence the person signing in can act on).</summary>
public sealed record SignInTokenOutcome(MicrosoftAccount? Account, string? Refusal)
{
    public static SignInTokenOutcome Accept(MicrosoftAccount account) => new(account, null);

    public static SignInTokenOutcome Refuse(string refusal) => new(null, refusal);
}

/// <summary>
/// What Vaulty demands of an id token for signing in, beyond the transport: the token comes straight from the token
/// endpoint of the identity platform over TLS in exchange for a code with PKCE and the app's certificate, which is what
/// lets OpenID Connect skip the signature check (Core 1.0, ID Token Validation). Everything else is checked here: issuer and tenant
/// are the organization's tenant, the audience is the sign-in app, the token is current, the nonce is the one Vaulty
/// sent, the account is a member and not a guest, and it has an object id. Accounts are matched on tenant and object id,
/// never on a name or an e-mail address.
/// </summary>
public static class SignInTokenRules
{
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>The <c>amr</c> values that stand for a second factor.</summary>
    public static readonly IReadOnlySet<string> MultiFactorMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "mfa", "fido", "hwk" };

    /// <summary>The issuer of a v2.0 id token of a tenant.</summary>
    public static string Issuer(Uri authorityHost, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(authorityHost);
        return new Uri(authorityHost, $"{tenantId:D}/v2.0").ToString();
    }

    public static SignInTokenOutcome Check(JsonObject claims, Uri authorityHost, Guid expectedTenant, Guid clientId, string expectedNonce, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(expectedNonce);
        const string otherTenant = "This Microsoft account belongs to another tenant than the one this Vaulty signs in with.";
        var issuer = Text(claims, "iss");
        if (!string.Equals(issuer, Issuer(authorityHost, expectedTenant), StringComparison.Ordinal)) return SignInTokenOutcome.Refuse(otherTenant);
        if (!Guid.TryParse(Text(claims, "tid"), out var tid) || tid != expectedTenant) return SignInTokenOutcome.Refuse(otherTenant);
        if (!Audiences(claims).Contains(clientId.ToString("D"), StringComparer.OrdinalIgnoreCase))
        {
            return SignInTokenOutcome.Refuse("The sign-in was meant for another app. Start again.");
        }
        if (Seconds(claims, "exp") is not { } exp || DateTimeOffset.FromUnixTimeSeconds(exp) + ClockSkew < now ||
            Seconds(claims, "nbf") is { } nbf && DateTimeOffset.FromUnixTimeSeconds(nbf) - ClockSkew > now)
        {
            return SignInTokenOutcome.Refuse("The sign-in expired. Start again.");
        }
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Text(claims, "nonce") ?? ""), Encoding.UTF8.GetBytes(expectedNonce)))
        {
            return SignInTokenOutcome.Refuse("The sign-in could not be verified. Start again.");
        }
        // A guest is an identity of another directory: Entra marks it with acct=1 and names its own issuer in idp.
        var guest = Seconds(claims, "acct") is 1 || Text(claims, "idp") is { Length: > 0 } idp && !string.Equals(idp, issuer, StringComparison.Ordinal);
        if (guest) return SignInTokenOutcome.Refuse("This account is a guest of the tenant. Guests sign in with a Vaulty account.");
        if (!Guid.TryParse(Text(claims, "oid"), out var oid) || oid == Guid.Empty)
        {
            return SignInTokenOutcome.Refuse("Microsoft did not name the account. Check that the sign-in app asks for the profile permission.");
        }
        var methods = Names(claims["amr"] is JsonArray amr ? amr.Select(a => a?.ToString()).OfType<string>() : []);
        return SignInTokenOutcome.Accept(new MicrosoftAccount(tid, oid, Trim(Text(claims, "preferred_username") ?? Text(claims, "email"), 320),
            Trim(Text(claims, "name"), 200), methods.Any(MultiFactorMethods.Contains), methods, Names(Text(claims, "acr") is { } acr ? [acr] : []).FirstOrDefault(),
            Seconds(claims, "auth_time") is { } at ? DateTimeOffset.FromUnixTimeSeconds(at) : null));
    }

    /// <summary>Short identifiers only, at most ten, so whatever a token carries cannot put more than a name into the audit log.</summary>
    public static IReadOnlyList<string> Names(IEnumerable<string> values) =>
        values.Where(v => v is { Length: > 0 and <= 40 } && v.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':')).Take(10).ToList();

    private static IEnumerable<string> Audiences(JsonObject claims) => claims["aud"] switch
    {
        JsonArray array => array.Select(a => a?.ToString()).OfType<string>(),
        JsonValue value when value.TryGetValue<string>(out var s) => [s],
        _ => [],
    };

    private static string? Text(JsonObject claims, string name) =>
        claims.TryGetPropertyValue(name, out var v) && v is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;

    private static long? Seconds(JsonObject claims, string name)
    {
        if (!claims.TryGetPropertyValue(name, out var v) || v is not JsonValue value) return null;
        if (value.TryGetValue<long>(out var l)) return l;
        if (value.TryGetValue<int>(out var i)) return i;
        return value.TryGetValue<string>(out var s) && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
    }

    private static string? Trim(string? value, int max) => string.IsNullOrWhiteSpace(value) ? null : value.Length <= max ? value : value[..max];
}

/// <summary>How the Microsoft tenant of an organization asks its people for a second factor, as far as Vaulty can read it.</summary>
public enum TenantMfaPosture
{
    /// <summary>Not read: the sign-in app lacks Policy.Read.All.</summary>
    Unknown,
    /// <summary>Security defaults are on: every account registers and uses multi-factor authentication.</summary>
    SecurityDefaults,
    /// <summary>An enabled Conditional Access policy requires multi-factor authentication of all users.</summary>
    ConditionalAccess,
    /// <summary>Neither: Microsoft may let people in with a password only.</summary>
    None,
}

/// <summary>A member of the organization's tenant, for the user picker.</summary>
public sealed record DirectoryMember(Guid ObjectId, string? DisplayName, string? UserPrincipalName);

/// <summary>The Microsoft Graph application permissions the sign-in app may hold, each for one optional feature.</summary>
public static class SignInAppPermissions
{
    /// <summary>Pick users from the tenant when adding or linking them.</summary>
    public const string UserReadAll = "User.Read.All";
    /// <summary>Read whether the tenant requires multi-factor authentication.</summary>
    public const string PolicyReadAll = "Policy.Read.All";

    public static readonly IReadOnlyList<string> Optional = [UserReadAll, PolicyReadAll];

    /// <summary>The application permissions in an app-only access token (its roles claim); empty when the token is not a JWT.</summary>
    public static IReadOnlyList<string> Granted(string accessToken)
    {
        try
        {
            return CertificateJwt.Payload(accessToken)["roles"] is JsonArray roles ? roles.Select(r => r?.ToString()).OfType<string>().ToList() : [];
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
        {
            return [];
        }
    }
}
