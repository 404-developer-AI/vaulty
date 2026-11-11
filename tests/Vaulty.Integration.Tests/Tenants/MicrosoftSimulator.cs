using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Vaulty.Graph.Onboarding;
using WireMock;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Types;
using WireMock.Util;

namespace Vaulty.Integration.Tests.Tenants;

/// <summary>
/// A small Microsoft 365 tenant behind WireMock: the identity platform's token endpoint and the Graph calls that create,
/// check and repair an app registration. It checks what the real services check (PKCE, the client assertion's signature,
/// the proof of possession for addKey and removeKey) and records every call, so tests assert the exact sequence.
/// </summary>
internal sealed class MicrosoftSimulator : IDisposable
{
    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<string, (string Nonce, string Challenge, Guid Tenant)> _codes = new(StringComparer.Ordinal);

    public MicrosoftSimulator()
    {
        Endpoints = new MicrosoftEndpoints(new Uri($"{_server.Url}/login/"), new Uri($"{_server.Url}/graph/v1.0/"));
        GraphServicePrincipalId = Guid.NewGuid();
        foreach (var permission in GraphPermissions.All) ApplicationRoles[permission.Name] = Guid.NewGuid();
        DelegatedScopes["Application.ReadWrite.All"] = Guid.NewGuid();
        DelegatedScopes["AppRoleAssignment.ReadWrite.All"] = Guid.NewGuid();
        _server.Given(Request.Create().WithPath("/*")).RespondWith(Response.Create().WithCallback(Handle));
    }

    public MicrosoftEndpoints Endpoints { get; }
    public Uri GraphBase => Endpoints.Graph;
    public Guid TenantId { get; set; } = Guid.NewGuid();
    public string UserName { get; set; } = "admin@contoso.example.com";
    /// <summary>The wids claim of the next id token; null leaves it out.</summary>
    public Guid[]? DirectoryRoles { get; set; } = [SignedInUser.GrantingRoles[0]];
    public Guid GraphServicePrincipalId { get; }
    public Dictionary<string, Guid> ApplicationRoles { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, Guid> DelegatedScopes { get; } = new(StringComparer.Ordinal);
    public X509Certificate2? SetupCertificate { get; set; }
    public Guid SetupClientId { get; set; }

    // ---- the organization's "Vaulty sign-in" app
    public X509Certificate2? SignInCertificate { get; set; }
    public Guid SignInClientId { get; set; }
    /// <summary>The application permissions in the sign-in app's own token (its roles claim).</summary>
    public string[] SignInAppRoles { get; set; } = [];
    /// <summary>The oid of the next id token; null gives a new one each time.</summary>
    public Guid? NextObjectId { get; set; }
    /// <summary>Changes the claims of the next id tokens (a guest, another nonce, an old auth_time).</summary>
    public Action<JsonObject>? ShapeIdToken { get; set; }
    public List<(Guid Id, string Name, string Upn, string Type)> Members { get; } = [];
    public bool SecurityDefaults { get; set; }
    /// <summary>The Entra security groups of each account (object id), for transitiveMemberOf.</summary>
    public Dictionary<Guid, HashSet<Guid>> EntraGroups { get; } = [];

    public Dictionary<Guid, JsonObject> Applications { get; } = [];
    public Dictionary<Guid, Guid> ServicePrincipals { get; } = [];
    public Dictionary<Guid, HashSet<Guid>> Assignments { get; } = [];
    public List<(string Method, string Path)> Calls { get; } = [];
    /// <summary>Every token and code handed out, to prove none of them is stored anywhere.</summary>
    public List<string> Issued { get; } = [];

    /// <summary>appRoleAssignedTo answers 400 "does not exist" this many times first (Entra replication).</summary>
    public int ReplicationDelays { get; set; }
    /// <summary>appRoleAssignedTo answers 403 (the account may not grant application permissions).</summary>
    public bool ForbidGrants { get; set; }
    /// <summary>addKey answers 403.</summary>
    public bool RefuseAddKey { get; set; }
    /// <summary>The next call whose "METHOD path" starts with this fails once with 500.</summary>
    public string? FailOnce { get; set; }

    public IEnumerable<string> GraphCalls => Calls.Where(c => c.Path.StartsWith("/graph/", StringComparison.Ordinal)).Select(c => $"{c.Method} {c.Path}");

    /// <summary>The administrator signs in: Microsoft hands out a code for the authorize request Vaulty built.</summary>
    public string SignIn(Uri authorizeUrl)
    {
        var query = System.Web.HttpUtility.ParseQueryString(authorizeUrl.Query);
        var code = "code-" + Guid.NewGuid().ToString("N");
        _codes[code] = (query["nonce"]!, query["code_challenge"]!, TenantId);
        lock (_lock) Issued.Add(code);
        return code;
    }

    /// <summary>Microsoft accepts the certificate of an application (a token request with it would succeed).</summary>
    public bool Accepts(Guid appId, X509Certificate2 certificate)
    {
        lock (_lock)
        {
            return Applications.Values.Any(a => a["appId"]!.GetValue<string>() == appId.ToString()
                                               && Keys(a).Any(k => k["customKeyIdentifier"]!.GetValue<string>() == certificate.Thumbprint));
        }
    }

    public static IEnumerable<JsonObject> Keys(JsonObject app) => (app["keyCredentials"] as JsonArray ?? []).OfType<JsonObject>();

    private ResponseMessage Handle(IRequestMessage request)
    {
        var uri = new Uri(request.Url);
        var path = Uri.UnescapeDataString(uri.AbsolutePath);
        var query = Uri.UnescapeDataString(uri.Query);
        lock (_lock)
        {
            Calls.Add((request.Method, path));
            if (FailOnce is { } fail && $"{request.Method} {path}".StartsWith(fail, StringComparison.Ordinal))
            {
                FailOnce = null;
                return Error(500, "InternalServerError", "Injected failure.");
            }
            try
            {
                return path.StartsWith("/login/", StringComparison.Ordinal) ? Token(path, request.Body ?? "") : Graph(request.Method, path["/graph/v1.0/".Length..], query, request.Body);
            }
            catch (InvalidOperationException ex)
            {
                return Error(400, "Request_BadRequest", ex.Message);
            }
        }
    }

    // ------------------------------------------------------------------ identity platform

    private ResponseMessage Token(string path, string body)
    {
        var form = System.Web.HttpUtility.ParseQueryString(body);
        var tenant = path.Split('/')[2];
        var tokenEndpoint = Endpoints.Token(tenant).ToString();
        var clientId = Guid.Parse(form["client_id"]!);
        if (!VerifyAssertion(form["client_assertion"]!, clientId, tokenEndpoint)) return Json(401, new JsonObject { ["error"] = "invalid_client", ["error_description"] = "AADSTS700027: Client assertion failed signature validation." });
        var access = "access-" + Guid.NewGuid().ToString("N");
        Issued.Add(access);
        if (form["grant_type"] == "client_credentials" && clientId == SignInClientId && SignInClientId != Guid.Empty)
        {
            // An app-only token is a JWT whose roles claim lists the application permissions of the app.
            var payload = new JsonObject { ["roles"] = new JsonArray(SignInAppRoles.Select(r => (JsonNode)r).ToArray()) };
            access = $"{CertificateJwt.Base64Url("{\"alg\":\"none\"}"u8)}.{CertificateJwt.Base64Url(Encoding.UTF8.GetBytes(payload.ToJsonString()))}.{Guid.NewGuid():N}";
            Issued.Add(access);
        }
        if (form["grant_type"] == "client_credentials") return Json(200, new JsonObject { ["access_token"] = access, ["expires_in"] = 3599 });
        if (!_codes.TryRemove(form["code"]!, out var issued)) return Json(400, new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "AADSTS54005: The code was already redeemed." });
        if (Pkce.Challenge(form["code_verifier"]!) != issued.Challenge) return Json(400, new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "AADSTS501481: The code verifier does not match." });
        var claims = new JsonObject
        {
            ["tid"] = issued.Tenant.ToString(), ["oid"] = (NextObjectId ?? Guid.NewGuid()).ToString(), ["preferred_username"] = UserName, ["nonce"] = issued.Nonce,
            ["iss"] = SignInTokenRules.Issuer(Endpoints.AuthorityHost, issued.Tenant), ["aud"] = clientId.ToString(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(), ["nbf"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["name"] = "Alex Example",
        };
        if (DirectoryRoles is { } roles) claims["wids"] = new JsonArray(roles.Select(r => (JsonNode)r.ToString()).ToArray());
        ShapeIdToken?.Invoke(claims);
        var idToken = $"{CertificateJwt.Base64Url("{\"alg\":\"none\"}"u8)}.{CertificateJwt.Base64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()))}.";
        Issued.Add(idToken);
        return Json(200, new JsonObject { ["access_token"] = access, ["id_token"] = idToken, ["expires_in"] = 3599, ["token_type"] = "Bearer" });
    }

    private bool VerifyAssertion(string assertion, Guid clientId, string tokenEndpoint)
    {
        var payload = CertificateJwt.Payload(assertion);
        if (payload["aud"]?.GetValue<string>() != tokenEndpoint || payload["iss"]?.GetValue<string>() != clientId.ToString()) return false;
        var certificates = clientId == SetupClientId && SetupCertificate is not null ? [SetupCertificate]
            : clientId == SignInClientId && SignInCertificate is not null ? [SignInCertificate]
            : Applications.Values.Where(a => a["appId"]!.GetValue<string>() == clientId.ToString()).SelectMany(Keys).Select(KeyCertificate).ToList();
        return certificates.Any(c => SignedBy(assertion, c));
    }

    public static bool SignedBy(string jwt, X509Certificate2 certificate)
    {
        var parts = jwt.Split('.');
        using var rsa = certificate.GetRSAPublicKey()!;
        return rsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), CertificateJwt.FromBase64Url(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static X509Certificate2 KeyCertificate(JsonObject key) => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(key["key"]!.GetValue<string>()));

    // ------------------------------------------------------------------ Graph

    private ResponseMessage Graph(string method, string path, string query, string? body)
    {
        var json = string.IsNullOrEmpty(body) ? null : JsonNode.Parse(body) as JsonObject;
        switch (method)
        {
            case "GET" when path == $"servicePrincipals(appId='{OnboardingScript.GraphAppId}')":
                return Json(200, new JsonObject
                {
                    ["id"] = GraphServicePrincipalId.ToString(),
                    ["appRoles"] = new JsonArray(ApplicationRoles.Select(r => (JsonNode)new JsonObject
                        { ["id"] = r.Value.ToString(), ["value"] = r.Key, ["allowedMemberTypes"] = new JsonArray("Application") }).ToArray()),
                    ["oauth2PermissionScopes"] = new JsonArray(DelegatedScopes.Select(r => (JsonNode)new JsonObject { ["id"] = r.Value.ToString(), ["value"] = r.Key }).ToArray()),
                });
            case "GET" when path.StartsWith("servicePrincipals(appId='", StringComparison.Ordinal):
            {
                var appId = Guid.Parse(path[25..61]);
                return ServicePrincipals.TryGetValue(appId, out var sp) ? Json(200, new JsonObject { ["id"] = sp.ToString() }) : Error(404, "Request_ResourceNotFound", "Not found.");
            }
            case "DELETE" when path.StartsWith("servicePrincipals(appId='", StringComparison.Ordinal):
                return ServicePrincipals.Remove(Guid.Parse(path[25..61])) ? new ResponseMessage { StatusCode = 204 } : Error(404, "Request_ResourceNotFound", "Not found.");
            case "POST" when path == "servicePrincipals":
            {
                var appId = Guid.Parse(json!["appId"]!.GetValue<string>());
                if (!Applications.Values.Any(a => a["appId"]!.GetValue<string>() == appId.ToString())) throw new InvalidOperationException("The application does not exist.");
                var id = Guid.NewGuid();
                ServicePrincipals[appId] = id;
                return Json(201, new JsonObject { ["id"] = id.ToString(), ["appId"] = appId.ToString() });
            }
            case "GET" when path.StartsWith("servicePrincipals/", StringComparison.Ordinal) && path.EndsWith("/appRoleAssignments", StringComparison.Ordinal):
            {
                var sp = Guid.Parse(path.Split('/')[1]);
                var roles = Assignments.TryGetValue(sp, out var set) ? set : [];
                return Json(200, new JsonObject
                {
                    ["value"] = new JsonArray(roles.Select(r => (JsonNode)new JsonObject { ["appRoleId"] = r.ToString(), ["resourceId"] = GraphServicePrincipalId.ToString() }).ToArray()),
                });
            }
            case "POST" when path == $"servicePrincipals/{GraphServicePrincipalId}/appRoleAssignedTo":
            {
                if (ReplicationDelays > 0)
                {
                    ReplicationDelays--;
                    return Error(400, "Request_BadRequest", "Resource '...' does not exist or one of its queried reference-property objects are not present.");
                }
                if (ForbidGrants) return Error(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.");
                var principal = Guid.Parse(json!["principalId"]!.GetValue<string>());
                var role = Guid.Parse(json["appRoleId"]!.GetValue<string>());
                if (!Assignments.TryGetValue(principal, out var set)) Assignments[principal] = set = [];
                if (!set.Add(role)) return Error(409, "Request_BadRequest", "Permission being assigned already exists on the object.");
                return Json(201, new JsonObject { ["id"] = Guid.NewGuid().ToString() });
            }
            case "GET" when path == "applications" && query.Contains("displayName eq '", StringComparison.Ordinal):
            {
                var name = query.Split("displayName eq '")[1].Split('\'')[0];
                return Json(200, new JsonObject
                {
                    ["value"] = new JsonArray(Applications.Values.Where(a => a["displayName"]!.GetValue<string>() == name)
                        .Select(a => (JsonNode)new JsonObject { ["id"] = a["id"]!.GetValue<string>(), ["appId"] = a["appId"]!.GetValue<string>() }).ToArray()),
                });
            }
            case "GET" when path.StartsWith("applications(appId='", StringComparison.Ordinal):
            {
                var appId = path[20..56];
                var app = Applications.Values.FirstOrDefault(a => a["appId"]!.GetValue<string>() == appId);
                return app is null ? Error(404, "Request_ResourceNotFound", "Not found.") : Json(200, Public(app));
            }
            case "POST" when path == "applications":
            {
                var id = Guid.NewGuid();
                json!["id"] = id.ToString();
                json["appId"] = Guid.NewGuid().ToString();
                json["passwordCredentials"] = new JsonArray();
                foreach (var key in Keys(json)) Register(key);
                Applications[id] = json;
                return Json(201, Public(json));
            }
            case "PATCH" when path.StartsWith("applications/", StringComparison.Ordinal):
            {
                var app = Applications[Guid.Parse(path.Split('/')[1])];
                foreach (var (name, value) in json!.ToList())
                {
                    var copy = value?.DeepClone();
                    if (name == "keyCredentials") foreach (var key in ((JsonArray)copy!).OfType<JsonObject>()) Register(key);
                    app[name] = copy;
                }
                return new ResponseMessage { StatusCode = 204 };
            }
            case "DELETE" when path.StartsWith("applications/", StringComparison.Ordinal):
            {
                var id = Guid.Parse(path.Split('/')[1]);
                if (Applications.Remove(id, out var app)) ServicePrincipals.Remove(Guid.Parse(app["appId"]!.GetValue<string>()));
                return new ResponseMessage { StatusCode = 204 };
            }
            case "POST" when path.EndsWith("/addKey", StringComparison.Ordinal) || path.EndsWith("/removeKey", StringComparison.Ordinal):
            {
                var id = Guid.Parse(path.Split('/')[1]);
                var app = Applications[id];
                if (RefuseAddKey && path.EndsWith("/addKey", StringComparison.Ordinal)) return Error(403, "Authorization_RequestDenied", "Insufficient privileges.");
                var proof = json!["proof"]!.GetValue<string>();
                var claims = CertificateJwt.Payload(proof);
                if (claims["aud"]?.GetValue<string>() != CertificateJwt.ProofAudience || claims["iss"]?.GetValue<string>() != id.ToString()
                    || !Keys(app).Any(k => SignedBy(proof, KeyCertificate(k))))
                {
                    return Error(401, "Authentication_MissingOrMalformed", "Access Token missing or malformed.");
                }
                var keys = (JsonArray)app["keyCredentials"]!;
                if (path.EndsWith("/addKey", StringComparison.Ordinal))
                {
                    var key = (JsonObject)json["keyCredential"]!.DeepClone();
                    Register(key);
                    keys.Add(key);
                    return Json(200, new JsonObject { ["keyId"] = key["keyId"]!.GetValue<string>() });
                }
                var keyId = json["keyId"]!.GetValue<string>();
                var match = Keys(app).FirstOrDefault(k => k["keyId"]!.GetValue<string>() == keyId);
                if (match is null) return Error(404, "Request_ResourceNotFound", "No credentials found to be removed.");
                keys.Remove(match);
                return new ResponseMessage { StatusCode = 204 };
            }
            case "GET" when path == "users" && query.Contains("startswith(displayName,'", StringComparison.Ordinal):
            {
                var text = query.Split("startswith(displayName,'")[1].Split('\'')[0];
                return Json(200, new JsonObject
                {
                    ["value"] = new JsonArray(Members.Where(m => m.Type == "Member" && (m.Name.StartsWith(text, StringComparison.OrdinalIgnoreCase) || m.Upn.StartsWith(text, StringComparison.OrdinalIgnoreCase)))
                        .Select(m => (JsonNode)new JsonObject { ["id"] = m.Id.ToString(), ["displayName"] = m.Name, ["userPrincipalName"] = m.Upn }).ToArray()),
                });
            }
            case "GET" when path.StartsWith("users/", StringComparison.Ordinal) && path.Contains("/transitiveMemberOf", StringComparison.Ordinal):
            {
                var groups = EntraGroups.TryGetValue(Guid.Parse(path[6..42]), out var set) ? set : [];
                return Json(200, new JsonObject { ["value"] = new JsonArray(groups.Select(g => (JsonNode)new JsonObject { ["id"] = g.ToString() }).ToArray()) });
            }
            case "GET" when path.StartsWith("users/", StringComparison.Ordinal):
            {
                var member = Members.FirstOrDefault(m => m.Id == Guid.Parse(path[6..42]));
                return member.Id == Guid.Empty ? Error(404, "Request_ResourceNotFound", "Not found.")
                    : Json(200, new JsonObject { ["id"] = member.Id.ToString(), ["displayName"] = member.Name, ["userPrincipalName"] = member.Upn, ["userType"] = member.Type });
            }
            case "GET" when path == "policies/identitySecurityDefaultsEnforcementPolicy":
                return Json(200, new JsonObject { ["isEnabled"] = SecurityDefaults });
            case "GET" when path == "identity/conditionalAccess/policies":
                return Json(200, new JsonObject { ["value"] = new JsonArray() });
            case "GET" when path is "organization" or "users":
                return Json(200, new JsonObject { ["value"] = new JsonArray() });
        }
        return Error(404, "UnknownRoute", $"{method} {path}");
    }

    private static void Register(JsonObject key)
    {
        key["keyId"] ??= Guid.NewGuid().ToString();
        key["customKeyIdentifier"] = KeyCertificate(key).Thumbprint;
    }

    /// <summary>Graph never returns key material.</summary>
    private static JsonObject Public(JsonObject app)
    {
        var copy = (JsonObject)app.DeepClone();
        foreach (var key in Keys(copy)) key.Remove("key");
        return copy;
    }

    private static ResponseMessage Json(int status, JsonObject body) => new()
    {
        StatusCode = status,
        Headers = new Dictionary<string, WireMockList<string>> { ["Content-Type"] = new("application/json") },
        BodyData = new BodyData { BodyAsString = body.ToJsonString(), DetectedBodyType = BodyType.String },
    };

    private static ResponseMessage Error(int status, string code, string message) =>
        Json(status, new JsonObject { ["error"] = new JsonObject { ["code"] = code, ["message"] = message } });

    public void Dispose() => _server.Stop();
}
