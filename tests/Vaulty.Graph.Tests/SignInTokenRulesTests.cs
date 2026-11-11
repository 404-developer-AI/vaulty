using System.Text.Json.Nodes;
using Vaulty.Graph.Onboarding;

namespace Vaulty.Graph.Tests;

public class SignInTokenRulesTests
{
    private static readonly Uri Authority = new("https://login.microsoftonline.com/");
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Client = Guid.NewGuid();
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    private static JsonObject Claims(Action<JsonObject>? shape = null)
    {
        var claims = new JsonObject
        {
            ["iss"] = $"https://login.microsoftonline.com/{Tenant}/v2.0",
            ["tid"] = Tenant.ToString(),
            ["aud"] = Client.ToString(),
            ["oid"] = Guid.NewGuid().ToString(),
            ["nonce"] = "n-1",
            ["exp"] = Now.AddMinutes(60).ToUnixTimeSeconds(),
            ["nbf"] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["auth_time"] = Now.AddSeconds(-20).ToUnixTimeSeconds(),
            ["preferred_username"] = "alex@contoso.example",
            ["name"] = "Alex",
        };
        shape?.Invoke(claims);
        return claims;
    }

    private static SignInTokenOutcome Check(JsonObject claims) => SignInTokenRules.Check(claims, Authority, Tenant, Client, "n-1", Now);

    [Fact]
    public void A_member_of_the_tenant_is_accepted_with_its_object_id_and_tenant()
    {
        var claims = Claims();
        var outcome = Check(claims);
        Assert.Null(outcome.Refusal);
        Assert.Equal(Guid.Parse(claims["oid"]!.GetValue<string>()), outcome.Account!.ObjectId);
        Assert.Equal(Tenant, outcome.Account.TenantId);
        Assert.Equal("alex@contoso.example", outcome.Account.Account);
        Assert.False(outcome.Account.MfaProven);
        Assert.Equal(Now.AddSeconds(-20), outcome.Account.AuthenticatedAt);
    }

    [Fact]
    public void The_issuer_is_built_from_the_authority_host_as_Entra_issues_it()
    {
        Assert.Equal($"https://login.microsoftonline.com/{Tenant}/v2.0", SignInTokenRules.Issuer(Authority, Tenant));
    }

    public static TheoryData<string, Action<JsonObject>> Refused => new()
    {
        { "issuer of another tenant", c => c["iss"] = $"https://login.microsoftonline.com/{Guid.NewGuid()}/v2.0" },
        { "tenant claim of another tenant", c => c["tid"] = Guid.NewGuid().ToString() },
        { "no tenant claim", c => c.Remove("tid") },
        { "another audience", c => c["aud"] = Guid.NewGuid().ToString() },
        { "expired", c => c["exp"] = Now.AddMinutes(-6).ToUnixTimeSeconds() },
        { "not yet valid", c => c["nbf"] = Now.AddMinutes(6).ToUnixTimeSeconds() },
        { "no expiry", c => c.Remove("exp") },
        { "another nonce", c => c["nonce"] = "n-2" },
        { "no nonce", c => c.Remove("nonce") },
        { "guest by account type", c => c["acct"] = 1 },
        { "guest by identity provider", c => c["idp"] = "https://sts.windows.net/" + Guid.NewGuid() + "/" },
        { "no object id", c => c.Remove("oid") },
        { "empty object id", c => c["oid"] = Guid.Empty.ToString() },
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public void A_token_that_breaks_a_rule_is_refused_with_a_sentence(string rule, Action<JsonObject> shape)
    {
        var outcome = Check(Claims(shape));
        Assert.Null(outcome.Account);
        Assert.False(string.IsNullOrWhiteSpace(outcome.Refusal), rule);
    }

    [Fact]
    public void An_audience_array_with_the_app_is_accepted()
    {
        Assert.NotNull(Check(Claims(c => c["aud"] = new JsonArray(Guid.NewGuid().ToString(), Client.ToString()))).Account);
    }

    [Fact]
    public void An_identity_provider_equal_to_the_issuer_is_a_member()
    {
        Assert.NotNull(Check(Claims(c => c["idp"] = c["iss"]!.GetValue<string>())).Account);
    }

    [Fact]
    public void A_multi_factor_method_in_amr_proves_the_second_factor()
    {
        Assert.True(Check(Claims(c => c["amr"] = new JsonArray("pwd", "mfa"))).Account!.MfaProven);
        Assert.False(Check(Claims(c => c["amr"] = new JsonArray("pwd"))).Account!.MfaProven);
    }

    [Fact]
    public void Only_short_identifiers_of_a_token_reach_the_audit_log()
    {
        var names = SignInTokenRules.Names(["pwd", "mfa", "<script>", new string('a', 41), "", "c1", "x y"]);
        Assert.Equal(["pwd", "mfa", "c1"], names);
        Assert.Equal(10, SignInTokenRules.Names(Enumerable.Range(0, 20).Select(i => $"m{i}")).Count);
    }

    [Fact]
    public void The_sign_in_url_asks_for_identity_only_and_a_fresh_sign_in_for_step_up()
    {
        var identity = new IdentityClient(new HttpClient(), MicrosoftEndpoints.Public, TimeProvider.System);
        var normal = System.Web.HttpUtility.ParseQueryString(identity.SignInAuthorizationUrl(Tenant.ToString(), Client,
            new Uri("https://vaulty.example.com/account/microsoft/callback"), "s", "n", "c", fresh: false).Query);
        Assert.Equal("openid profile email", normal["scope"]);
        Assert.Equal("select_account", normal["prompt"]);
        Assert.Null(normal["max_age"]);
        Assert.Equal("S256", normal["code_challenge_method"]);
        var fresh = System.Web.HttpUtility.ParseQueryString(identity.SignInAuthorizationUrl(Tenant.ToString(), Client,
            new Uri("https://vaulty.example.com/account/microsoft/callback"), "s", "n", "c", fresh: true).Query);
        Assert.Equal("login", fresh["prompt"]);
        Assert.Equal("0", fresh["max_age"]);
    }

    [Fact]
    public void The_granted_application_permissions_come_from_the_roles_of_the_token()
    {
        var payload = CertificateJwt.Base64Url(System.Text.Encoding.UTF8.GetBytes("{\"roles\":[\"User.Read.All\",\"Policy.Read.All\"]}"));
        Assert.Equal(["User.Read.All", "Policy.Read.All"], SignInAppPermissions.Granted($"e30.{payload}.sig"));
        Assert.Empty(SignInAppPermissions.Granted("not-a-jwt"));
    }

    [Theory]
    [InlineData("AADSTS50011", "redirect URI")]
    [InlineData("AADSTS65001", "admin consent")]
    [InlineData("AADSTS53003", "Conditional Access")]
    [InlineData("AADSTS700027", "certificate")]
    public void Microsoft_refusals_of_a_sign_in_become_one_sentence(string code, string expected)
    {
        Assert.Contains(expected, SignInErrors.ExplainSignIn("invalid_request", $"{code}: something"), StringComparison.Ordinal);
    }
}
