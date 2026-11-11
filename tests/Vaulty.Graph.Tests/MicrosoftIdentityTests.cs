using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Vaulty.Graph.Onboarding;

namespace Vaulty.Graph.Tests;

public class MicrosoftIdentityTests
{
    [Fact]
    public void Pkce_matches_the_RFC_7636_test_vector()
    {
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        var verifier = Pkce.NewVerifier();
        Assert.InRange(verifier.Length, 43, 128);
        Assert.DoesNotContain('=', verifier);
    }

    [Fact]
    public void A_key_proof_has_the_claims_addKey_requires_and_is_signed_by_the_current_certificate()
    {
        var material = TenantCertificate.Create("Contoso");
        using var certificate = TenantCertificate.Load(material.Pfx);
        var objectId = Guid.NewGuid();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var proof = CertificateJwt.KeyProof(certificate, objectId, now);

        Assert.DoesNotContain('=', proof);
        var claims = CertificateJwt.Payload(proof);
        Assert.Equal("00000002-0000-0000-c000-000000000000", claims["aud"]!.GetValue<string>());
        Assert.Equal(objectId.ToString(), claims["iss"]!.GetValue<string>());
        Assert.Equal(600, claims["exp"]!.GetValue<long>() - claims["nbf"]!.GetValue<long>());

        var parts = proof.Split('.');
        var header = JsonNode.Parse(CertificateJwt.FromBase64Url(parts[0]))!;
        Assert.Equal("RS256", header["alg"]!.GetValue<string>());
        Assert.Equal(CertificateJwt.Base64Url(certificate.GetCertHash()), header["x5t"]!.GetValue<string>());
        using var rsa = certificate.GetRSAPublicKey()!;
        Assert.True(rsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), CertificateJwt.FromBase64Url(parts[2]), HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void A_client_assertion_names_the_client_and_the_token_endpoint()
    {
        using var certificate = TenantCertificate.Load(TenantCertificate.Create("Setup").Pfx);
        var clientId = Guid.NewGuid();
        var endpoint = MicrosoftEndpoints.Public.Token("organizations");
        var claims = CertificateJwt.Payload(CertificateJwt.ClientAssertion(certificate, clientId, endpoint, DateTimeOffset.UtcNow));
        Assert.Equal(("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", clientId.ToString(), clientId.ToString()),
            (claims["aud"]!.GetValue<string>(), claims["iss"]!.GetValue<string>(), claims["sub"]!.GetValue<string>()));
        Assert.True(Guid.TryParse(claims["jti"]!.GetValue<string>(), out _));
    }

    [Fact]
    public void The_authorize_request_asks_for_a_code_with_PKCE_and_no_refresh_token()
    {
        var identity = new IdentityClient(new HttpClient(), MicrosoftEndpoints.Public, TimeProvider.System);
        var url = identity.AuthorizationUrl("contoso.onmicrosoft.com", Guid.NewGuid(), new Uri("https://vaulty.example.com/connect/microsoft/callback"), "s", "n", "c", consent: true);
        var query = System.Web.HttpUtility.ParseQueryString(url.Query);
        Assert.StartsWith("https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize?", url.ToString(), StringComparison.Ordinal);
        Assert.Equal(("code", "S256", "consent", "s", "n"), (query["response_type"], query["code_challenge_method"], query["prompt"], query["state"], query["nonce"]));
        var scopes = query["scope"]!.Split(' ');
        Assert.Equal(["https://graph.microsoft.com/Application.ReadWrite.All", "https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All", "openid", "profile"], scopes);
    }

    [Fact]
    public void The_id_token_tells_whether_the_account_may_grant_permissions()
    {
        static string IdToken(object claims) =>
            $"{CertificateJwt.Base64Url("{}"u8)}.{CertificateJwt.Base64Url(Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(claims)))}.";
        var tid = Guid.NewGuid();
        var admin = SignedInUser.FromIdToken(IdToken(new { tid, oid = Guid.NewGuid(), preferred_username = "a@example.com", nonce = "n", wids = new[] { "62e90394-69f5-4237-9190-012177145e10" } }));
        Assert.Equal((tid, "a@example.com", "n", true), (admin.TenantId, admin.UserName, admin.Nonce, admin.MayGrantPermissions));
        var reader = SignedInUser.FromIdToken(IdToken(new { tid, wids = new[] { "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" } }));
        Assert.False(reader.MayGrantPermissions);
        // Without the claim Vaulty cannot tell, and relies on Microsoft refusing the grant.
        Assert.True(SignedInUser.FromIdToken(IdToken(new { tid })).MayGrantPermissions);
        Assert.Throws<FormatException>(() => SignedInUser.FromIdToken(IdToken(new { oid = Guid.NewGuid() })));
    }

    [Theory]
    [InlineData("access_denied", "AADSTS65004: User declined to consent", "consent was declined")]
    [InlineData("invalid_grant", "AADSTS53003: Access has been blocked by Conditional Access policies", "Conditional Access")]
    [InlineData("invalid_request", "AADSTS50020: User account from identity provider does not exist in tenant", "does not belong to the tenant")]
    [InlineData("invalid_client", "AADSTS700016: Application not found in the directory", "setup app")]
    [InlineData("invalid_grant", "AADSTS54005: OAuth2 Authorization code was already redeemed", "already used")]
    [InlineData("server_error", "AADSTS90033: A transient error", "AADSTS90033")]
    public void Sign_in_errors_say_what_to_do(string error, string description, string expected) =>
        Assert.Contains(expected, SignInErrors.Explain(error, description), StringComparison.Ordinal);

    [Fact]
    public void A_registered_key_matches_its_thumbprint_in_every_form_Graph_reports()
    {
        const string thumbprint = "829BCF51DF2E826366D0911E8A501AF9F1639928";
        Assert.True(new RegisteredKey(Guid.NewGuid(), thumbprint, null).Matches(thumbprint));
        Assert.True(new RegisteredKey(Guid.NewGuid(), Convert.ToBase64String(Convert.FromHexString(thumbprint)), null).Matches(thumbprint));
        Assert.True(new RegisteredKey(Guid.NewGuid(), Convert.ToBase64String(Encoding.UTF8.GetBytes(thumbprint)), null).Matches(thumbprint));
        Assert.False(new RegisteredKey(Guid.NewGuid(), "AAAA", null).Matches(thumbprint));
    }
}
