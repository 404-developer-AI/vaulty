using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vaulty.Graph.Http;

namespace Vaulty.Graph.Onboarding;

/// <summary>An application permission (app role) of Microsoft Graph.</summary>
public sealed record GraphAppRole(Guid Id, string Value);

/// <param name="DelegatedScopes">Delegated permissions of Microsoft Graph (oauth2PermissionScopes), by id and value.</param>
public sealed record GraphResourceApp(Guid ServicePrincipalId, IReadOnlyList<GraphAppRole> ApplicationRoles, IReadOnlyList<GraphAppRole> DelegatedScopes);

public sealed record CreatedApplication(Guid ObjectId, Guid AppId, Guid? KeyId);

/// <summary>The fields of an application registration Vaulty reads to check or repair it.</summary>
public sealed record ApplicationRegistration(Guid ObjectId, Guid AppId, string DisplayName, string? SignInAudience, IReadOnlyList<string> RedirectUris,
    IReadOnlyList<RegisteredKey> Keys, int PasswordCount, IReadOnlyList<(Guid ResourceAppId, Guid Id, string Type)> RequiredAccess,
    string? GroupMembershipClaims)
{
    public static ApplicationRegistration From(JsonObject json)
    {
        ArgumentNullException.ThrowIfNull(json);
        var keys = (json["keyCredentials"] as JsonArray ?? []).OfType<JsonObject>().Select(k => new RegisteredKey(
            Guid.TryParse(k["keyId"]?.GetValue<string>(), out var id) ? id : Guid.Empty,
            k["customKeyIdentifier"]?.GetValue<string>(),
            DateTimeOffset.TryParse(k["endDateTime"]?.GetValue<string>(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var end) ? end : null))
            .ToList();
        var access = (json["requiredResourceAccess"] as JsonArray ?? []).OfType<JsonObject>().SelectMany(r =>
        {
            var resource = Guid.TryParse(r["resourceAppId"]?.GetValue<string>(), out var res) ? res : Guid.Empty;
            return (r["resourceAccess"] as JsonArray ?? []).OfType<JsonObject>().Select(a =>
                (resource, Guid.TryParse(a["id"]?.GetValue<string>(), out var g) ? g : Guid.Empty, a["type"]?.GetValue<string>() ?? ""));
        }).ToList();
        var redirects = (json["web"]?["redirectUris"] as JsonArray ?? []).Select(u => u?.GetValue<string>()).OfType<string>().ToList();
        return new ApplicationRegistration(
            Guid.Parse(json["id"]!.GetValue<string>()), Guid.Parse(json["appId"]!.GetValue<string>()), json["displayName"]?.GetValue<string>() ?? "",
            json["signInAudience"]?.GetValue<string>(), redirects, keys, (json["passwordCredentials"] as JsonArray)?.Count ?? 0, access,
            json["groupMembershipClaims"]?.GetValue<string>());
    }

    /// <summary>The key of the application with this certificate thumbprint (Graph stores it as customKeyIdentifier).</summary>
    public RegisteredKey? KeyFor(string thumbprint) => Keys.FirstOrDefault(k => k.Matches(thumbprint));
}

public sealed record RegisteredKey(Guid KeyId, string? CustomKeyIdentifier, DateTimeOffset? EndDateTime)
{
    public bool Matches(string thumbprint)
    {
        if (CustomKeyIdentifier is null) return false;
        if (string.Equals(CustomKeyIdentifier, thumbprint, StringComparison.OrdinalIgnoreCase)) return true;
        try
        {
            // Graph reports the identifier base64-encoded: the thumbprint bytes, or the thumbprint as text.
            var bytes = Convert.FromBase64String(CustomKeyIdentifier);
            return string.Equals(Convert.ToHexString(bytes), thumbprint, StringComparison.OrdinalIgnoreCase)
                   || string.Equals(Encoding.UTF8.GetString(bytes), thumbprint, StringComparison.OrdinalIgnoreCase);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

/// <summary>
/// Microsoft Graph calls that create, check and repair an app registration, with a token Vaulty holds only for the call:
/// a delegated token of the signed-in administrator, or the app's own token for addKey and removeKey. Throttling
/// (429, 503) honours Retry-After; Entra's replication delay right after a create is retried for up to two minutes.
/// </summary>
public sealed class AppRegistrationClient(HttpClient http, MicrosoftEndpoints endpoints, Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    public static readonly TimeSpan ReplicationWindow = TimeSpan.FromMinutes(2);
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;

    public async Task<GraphResourceApp> GraphResourceAsync(string token, CancellationToken cancellationToken = default)
    {
        var json = await SendAsync(token, HttpMethod.Get, $"servicePrincipals(appId='{OnboardingScript.GraphAppId}')?$select=id,appRoles,oauth2PermissionScopes", null,
            cancellationToken).ConfigureAwait(false) ?? throw new GraphException(HttpStatusCode.NotFound, "NotFound", "Microsoft Graph has no service principal.", null);
        var roles = (json["appRoles"] as JsonArray ?? []).OfType<JsonObject>()
            .Where(r => (r["allowedMemberTypes"] as JsonArray ?? []).Any(t => t?.GetValue<string>() == "Application"))
            .Select(r => new GraphAppRole(Guid.Parse(r["id"]!.GetValue<string>()), r["value"]?.GetValue<string>() ?? ""))
            .ToList();
        var scopes = (json["oauth2PermissionScopes"] as JsonArray ?? []).OfType<JsonObject>()
            .Select(r => new GraphAppRole(Guid.Parse(r["id"]!.GetValue<string>()), r["value"]?.GetValue<string>() ?? ""))
            .ToList();
        return new GraphResourceApp(Guid.Parse(json["id"]!.GetValue<string>()), roles, scopes);
    }

    public async Task<IReadOnlyList<(Guid ObjectId, Guid AppId)>> ApplicationsNamedAsync(string token, string displayName, CancellationToken cancellationToken = default)
    {
        var filter = Uri.EscapeDataString($"displayName eq '{displayName.Replace("'", "''", StringComparison.Ordinal)}'");
        var json = await SendAsync(token, HttpMethod.Get, $"applications?$filter={filter}&$select=id,appId", null, cancellationToken).ConfigureAwait(false);
        return (json?["value"] as JsonArray ?? []).OfType<JsonObject>()
            .Select(a => (Guid.Parse(a["id"]!.GetValue<string>()), Guid.Parse(a["appId"]!.GetValue<string>()))).ToList();
    }

    public async Task<ApplicationRegistration?> ApplicationAsync(string token, Guid appId, CancellationToken cancellationToken = default)
    {
        var json = await SendAsync(token, HttpMethod.Get,
            $"applications(appId='{appId}')?$select=id,appId,displayName,signInAudience,web,keyCredentials,passwordCredentials,requiredResourceAccess,groupMembershipClaims",
            null, cancellationToken, notFoundIsNull: true).ConfigureAwait(false);
        return json is null ? null : ApplicationRegistration.From(json);
    }

    /// <summary>A single-tenant app with the given application permissions and the certificate as its only credential.</summary>
    public async Task<CreatedApplication> CreateApplicationAsync(string token, string displayName, IEnumerable<Guid> roleIds, TenantCertificateMaterial certificate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var body = new JsonObject
        {
            ["displayName"] = displayName,
            ["signInAudience"] = "AzureADMyOrg",
            ["requiredResourceAccess"] = RequiredAccess(roleIds),
            ["keyCredentials"] = new JsonArray(KeyCredential(certificate, displayName)),
        };
        var json = await SendAsync(token, HttpMethod.Post, "applications", body, cancellationToken).ConfigureAwait(false)
                   ?? throw new GraphException(HttpStatusCode.InternalServerError, null, "Graph returned no application.", null);
        var keyId = (json["keyCredentials"] as JsonArray ?? []).OfType<JsonObject>().Select(k => Guid.TryParse(k["keyId"]?.GetValue<string>(), out var g) ? g : (Guid?)null)
            .FirstOrDefault(g => g is not null);
        return new CreatedApplication(Guid.Parse(json["id"]!.GetValue<string>()), Guid.Parse(json["appId"]!.GetValue<string>()), keyId);
    }

    public static JsonArray RequiredAccess(IEnumerable<Guid> roleIds) => new(new JsonObject
    {
        ["resourceAppId"] = OnboardingScript.GraphAppId,
        ["resourceAccess"] = new JsonArray(roleIds.Distinct().Select(id => (JsonNode)new JsonObject { ["id"] = id.ToString(), ["type"] = "Role" }).ToArray()),
    });

    public static JsonObject KeyCredential(TenantCertificateMaterial certificate, string displayName)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new JsonObject
        {
            ["type"] = "AsymmetricX509Cert",
            ["usage"] = "Verify",
            ["key"] = certificate.PublicCertificateBase64,
            ["displayName"] = $"{displayName} {certificate.NotAfter:yyyy-MM-dd}",
            // Microsoft refuses an end date later than the certificate's own; both carry whole seconds.
            ["endDateTime"] = certificate.NotAfter.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
        };
    }

    public Task UpdateApplicationAsync(string token, Guid objectId, JsonObject patch, CancellationToken cancellationToken = default) =>
        SendAsync(token, HttpMethod.Patch, $"applications/{objectId}", patch, cancellationToken);

    public Task DeleteApplicationAsync(string token, Guid objectId, CancellationToken cancellationToken = default) =>
        SendAsync(token, HttpMethod.Delete, $"applications/{objectId}", null, cancellationToken, notFoundIsNull: true);

    public async Task<Guid?> ServicePrincipalAsync(string token, Guid appId, CancellationToken cancellationToken = default)
    {
        var json = await SendAsync(token, HttpMethod.Get, $"servicePrincipals(appId='{appId}')?$select=id", null, cancellationToken, notFoundIsNull: true)
            .ConfigureAwait(false);
        return json is null ? null : Guid.Parse(json["id"]!.GetValue<string>());
    }

    /// <summary>Creates the service principal of a new app, or returns the existing one.</summary>
    public async Task<Guid> CreateServicePrincipalAsync(string token, Guid appId, CancellationToken cancellationToken = default)
    {
        if (await ServicePrincipalAsync(token, appId, cancellationToken).ConfigureAwait(false) is { } existing) return existing;
        var json = await WithReplicationRetryAsync(() => SendAsync(token, HttpMethod.Post, "servicePrincipals", new JsonObject { ["appId"] = appId.ToString() },
            cancellationToken), cancellationToken).ConfigureAwait(false);
        return Guid.Parse(json!["id"]!.GetValue<string>());
    }

    /// <summary>The app roles of a resource already assigned to a service principal.</summary>
    public async Task<IReadOnlySet<Guid>> AssignedRolesAsync(string token, Guid servicePrincipalId, Guid resourceId, CancellationToken cancellationToken = default)
    {
        var json = await SendAsync(token, HttpMethod.Get, $"servicePrincipals/{servicePrincipalId}/appRoleAssignments?$select=appRoleId,resourceId&$top=999",
            null, cancellationToken).ConfigureAwait(false);
        return (json?["value"] as JsonArray ?? []).OfType<JsonObject>()
            .Where(a => Guid.TryParse(a["resourceId"]?.GetValue<string>(), out var r) && r == resourceId)
            .Select(a => Guid.Parse(a["appRoleId"]!.GetValue<string>())).ToHashSet();
    }

    /// <summary>Admin consent for one application permission: assigns the app role to the app's service principal.</summary>
    public Task AssignRoleAsync(string token, Guid resourceId, Guid servicePrincipalId, Guid roleId, CancellationToken cancellationToken = default) =>
        WithReplicationRetryAsync(() => SendAsync(token, HttpMethod.Post, $"servicePrincipals/{resourceId}/appRoleAssignedTo", new JsonObject
        {
            ["principalId"] = servicePrincipalId.ToString(),
            ["resourceId"] = resourceId.ToString(),
            ["appRoleId"] = roleId.ToString(),
        }, cancellationToken), cancellationToken);

    /// <summary>Removes an app's service principal (and with it every consent) from the tenant; true when it is gone.</summary>
    public async Task DeleteServicePrincipalAsync(string token, Guid appId, CancellationToken cancellationToken = default) =>
        await SendAsync(token, HttpMethod.Delete, $"servicePrincipals(appId='{appId}')", null, cancellationToken, notFoundIsNull: true).ConfigureAwait(false);

    /// <summary>Adds a certificate to the application, proven with one of its current certificates (no permission needed for itself).</summary>
    public async Task<Guid?> AddKeyAsync(string token, Guid objectId, TenantCertificateMaterial certificate, string proof, string displayName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var key = KeyCredential(certificate, displayName);
        key.Remove("endDateTime");
        var json = await SendAsync(token, HttpMethod.Post, $"applications/{objectId}/addKey", new JsonObject
        {
            ["keyCredential"] = key,
            ["passwordCredential"] = null,
            ["proof"] = proof,
        }, cancellationToken).ConfigureAwait(false);
        return Guid.TryParse(json?["keyId"]?.GetValue<string>(), out var id) ? id : null;
    }

    public Task RemoveKeyAsync(string token, Guid objectId, Guid keyId, string proof, CancellationToken cancellationToken = default) =>
        SendAsync(token, HttpMethod.Post, $"applications/{objectId}/removeKey", new JsonObject { ["keyId"] = keyId.ToString(), ["proof"] = proof },
            cancellationToken);

    /// <summary>Right after a create, Entra may not know the new object yet (404, or 400 "does not exist"); retry that, nothing else.</summary>
    private async Task<JsonObject?> WithReplicationRetryAsync(Func<Task<JsonObject?>> call, CancellationToken cancellationToken)
    {
        var waited = TimeSpan.Zero;
        var wait = TimeSpan.FromSeconds(2);
        while (true)
        {
            try
            {
                return await call().ConfigureAwait(false);
            }
            catch (GraphException ex) when (IsReplicationDelay(ex) && waited < ReplicationWindow)
            {
                await _delay(wait, cancellationToken).ConfigureAwait(false);
                waited += wait;
                wait = TimeSpan.FromSeconds(Math.Min(wait.TotalSeconds * 2, 20));
            }
        }
    }

    public static bool IsReplicationDelay(GraphException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception.Status == HttpStatusCode.NotFound
               || exception.Status == HttpStatusCode.BadRequest && (exception.Message.Contains("does not exist", StringComparison.OrdinalIgnoreCase)
                                                                    || exception.Message.Contains("not found", StringComparison.OrdinalIgnoreCase)
                                                                    || exception.Message.Contains("Request_ResourceNotFound", StringComparison.Ordinal));
    }

    // ---- reads of the sign-in app, with its own app-only token and only the optional permissions it was given ------------

    /// <summary>Members of the tenant whose name or account starts with the text (User.Read.All); guests are left out.</summary>
    public async Task<IReadOnlyList<DirectoryMember>> SearchMembersAsync(string token, string text, CancellationToken cancellationToken = default)
    {
        var value = (text ?? "").Trim().Replace("'", "''", StringComparison.Ordinal);
        if (value.Length < 2) return [];
        var filter = Uri.EscapeDataString($"userType eq 'Member' and (startswith(displayName,'{value}') or startswith(userPrincipalName,'{value}'))");
        var json = await SendAsync(token, HttpMethod.Get, $"users?$filter={filter}&$select=id,displayName,userPrincipalName&$top=10&$count=true",
            null, cancellationToken, consistencyEventual: true).ConfigureAwait(false);
        return (json?["value"] as JsonArray ?? []).OfType<JsonObject>().Select(Member).OfType<DirectoryMember>().ToList();
    }

    /// <summary>One member of the tenant by object id (User.Read.All); null for a guest or an unknown id.</summary>
    public async Task<DirectoryMember?> MemberAsync(string token, Guid objectId, CancellationToken cancellationToken = default)
    {
        var json = await SendAsync(token, HttpMethod.Get, $"users/{objectId}?$select=id,displayName,userPrincipalName,userType", null, cancellationToken,
            notFoundIsNull: true).ConfigureAwait(false);
        return json is not null && string.Equals(json["userType"]?.GetValue<string>(), "Member", StringComparison.OrdinalIgnoreCase) ? Member(json) : null;
    }

    /// <summary>Whether the tenant requires multi-factor authentication of everyone (Policy.Read.All).</summary>
    public async Task<TenantMfaPosture> MfaPostureAsync(string token, CancellationToken cancellationToken = default)
    {
        var defaults = await SendAsync(token, HttpMethod.Get, "policies/identitySecurityDefaultsEnforcementPolicy", null, cancellationToken).ConfigureAwait(false);
        if (defaults?["isEnabled"] is JsonValue on && on.TryGetValue<bool>(out var enabled) && enabled) return TenantMfaPosture.SecurityDefaults;
        var policies = await SendAsync(token, HttpMethod.Get, "identity/conditionalAccess/policies", null, cancellationToken).ConfigureAwait(false);
        var everyone = (policies?["value"] as JsonArray ?? []).OfType<JsonObject>().Any(p =>
            p["state"]?.GetValue<string>() == "enabled"
            && (p["conditions"]?["users"]?["includeUsers"] as JsonArray ?? []).Any(u => u?.ToString() == "All")
            && ((p["grantControls"]?["builtInControls"] as JsonArray ?? []).Any(c => c?.ToString() == "mfa") || p["grantControls"]?["authenticationStrength"] is JsonObject));
        return everyone ? TenantMfaPosture.ConditionalAccess : TenantMfaPosture.None;
    }

    /// <summary>The security groups a member belongs to, directly or through other groups (GroupMember.Read.All).</summary>
    public async Task<IReadOnlySet<Guid>> MemberGroupsAsync(string token, Guid objectId, CancellationToken cancellationToken = default)
    {
        var groups = new HashSet<Guid>();
        string? next = $"users/{objectId}/transitiveMemberOf/microsoft.graph.group?$select=id&$top=999";
        for (var page = 0; next is not null && page < 50; page++)
        {
            var json = await SendAsync(token, HttpMethod.Get, next, null, cancellationToken).ConfigureAwait(false);
            foreach (var item in (json?["value"] as JsonArray ?? []).OfType<JsonObject>())
            {
                if (Guid.TryParse(item["id"]?.GetValue<string>(), out var id)) groups.Add(id);
            }
            // The next link is absolute; it must stay on Graph.
            next = json?["@odata.nextLink"]?.GetValue<string>() is { } link && Uri.TryCreate(link, UriKind.Absolute, out var uri) &&
                   uri.Host == endpoints.Graph.Host ? uri.ToString() : null;
        }
        return groups;
    }

    private static DirectoryMember? Member(JsonObject json) => Guid.TryParse(json["id"]?.GetValue<string>(), out var id)
        ? new DirectoryMember(id, json["displayName"]?.GetValue<string>(), json["userPrincipalName"]?.GetValue<string>())
        : null;

    private async Task<JsonObject?> SendAsync(string token, HttpMethod method, string path, JsonObject? body, CancellationToken cancellationToken,
        bool notFoundIsNull = false, bool consistencyEventual = false)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, new Uri(endpoints.Graph, path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.ParseAdd(DecorationHandler.UserAgent);
            request.Headers.Add("client-request-id", Guid.NewGuid().ToString());
            // Filters on userType with startswith are advanced queries.
            if (consistencyEventual) request.Headers.Add("ConsistencyLevel", "eventual");
            if (body is not null) request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var text = response.Content is null ? "" : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (ThrottlingHandler.IsThrottling(response.StatusCode) && attempt < 5)
            {
                await _delay(ThrottlingHandler.RetryAfter(response) ?? TimeSpan.FromSeconds(Math.Pow(2, attempt + 1)), cancellationToken).ConfigureAwait(false);
                continue;
            }
            if (response.StatusCode == HttpStatusCode.NotFound && notFoundIsNull) return null;
            if (!response.IsSuccessStatusCode)
            {
                var error = GraphException.FromBody(response.StatusCode, text);
                var requestId = response.Headers.TryGetValues("request-id", out var ids) ? ids.FirstOrDefault() : null;
                throw new GraphException(error.Status, error.Code, error.Message.Split(": ", 2).Last(), requestId);
            }
            if (string.IsNullOrWhiteSpace(text)) return null;
            try
            {
                return JsonNode.Parse(text) as JsonObject;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }
}
