using System.Net;
using System.Reflection;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Web;
using Vaulty.Integration.Tests.Database;

namespace Vaulty.Integration.Tests.Web;

public sealed class AuthorizationMatrixTests(WebAppFixture app) : IClassFixture<WebAppFixture>
{
    /// <summary>Every page of the web app and the policy it must carry. A new page fails this test until it is listed.</summary>
    private static readonly Dictionary<string, string?> ExpectedPages = new(StringComparer.Ordinal)
    {
        ["/account/login"] = "anonymous",
        ["/account/login/second-factor"] = "anonymous",
        ["/setup"] = "anonymous",
        ["/account/mfa-setup"] = VaultyPolicies.SignedIn,
        ["/account/recovery-codes"] = VaultyPolicies.SignedIn,
        ["/access-denied"] = VaultyPolicies.SignedIn,
        ["/account/confirm"] = null,   // signed in with a second factor (fallback policy)
        ["/"] = null,
        ["/settings/users"] = VaultyPolicies.Permission(Permissions.UsersManage),
        ["/settings/audit"] = VaultyPolicies.Permission(Permissions.AuditView),
        ["/settings/storage"] = VaultyPolicies.Permission(Permissions.StorageManage),
        ["/settings/platform"] = VaultyPolicies.Permission(Permissions.SettingsManage),
        ["/settings/webhooks"] = VaultyPolicies.Permission(Permissions.SettingsManage),
        ["/jobs"] = VaultyPolicies.Permission(Permissions.JobsView),
        ["/customers"] = VaultyPolicies.Permission(Permissions.CustomersView),
        ["/customers/{CustomerId:guid}"] = VaultyPolicies.Permission(Permissions.CustomersView),
        ["/tenants/{TenantId:guid}"] = VaultyPolicies.Permission(Permissions.CustomersView),
        ["/search"] = VaultyPolicies.Permission(Permissions.SnapshotsBrowse),
        ["/objects/{ObjectId:guid}"] = VaultyPolicies.Permission(Permissions.SnapshotsBrowse),
        ["/objects/{ObjectId:guid}/snapshots/{SnapshotId:guid}"] = VaultyPolicies.Permission(Permissions.SnapshotsBrowse),
        ["/restores/{RestoreId:guid}"] = VaultyPolicies.Permission(Permissions.SnapshotsBrowse),
    };

    private static string Concrete(string route) => route.Replace("{CustomerId:guid}", Guid.NewGuid().ToString()).Replace("{TenantId:guid}", Guid.NewGuid().ToString())
        .Replace("{ObjectId:guid}", Guid.NewGuid().ToString()).Replace("{SnapshotId:guid}", Guid.NewGuid().ToString()).Replace("{RestoreId:guid}", Guid.NewGuid().ToString());

    [Fact]
    public void Every_page_declares_exactly_the_expected_authorization()
    {
        var pages = typeof(Vaulty.Web.WebMarker).Assembly.GetTypes()
            .SelectMany(t => t.GetCustomAttributes<RouteAttribute>().Select(r => (Route: r.Template, Type: t)))
            .ToList();
        Assert.Equal(ExpectedPages.Keys.Order(StringComparer.Ordinal), pages.Select(p => p.Route).Order(StringComparer.Ordinal));
        foreach (var (route, type) in pages)
        {
            var anonymous = type.GetCustomAttribute<AllowAnonymousAttribute>() is not null;
            var authorize = type.GetCustomAttributes<AuthorizeAttribute>().ToList();
            var expected = ExpectedPages[route];
            if (expected == "anonymous")
            {
                Assert.True(anonymous, $"{route} must allow anonymous access");
                continue;
            }
            Assert.False(anonymous, $"{route} must not allow anonymous access");
            Assert.True(authorize.Count > 0, $"{route} has no [Authorize]");
            Assert.Equal(expected, authorize.Single().Policy);
        }
    }

    [PostgresFact]
    public void Every_endpoint_of_the_web_app_declares_its_authorization()
    {
        var endpoints = app.Factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();
        Assert.NotEmpty(endpoints);
        var anonymous = new[] { "/account/login", "/account/login/second-factor", "/account/passkey/request-options", "/account/passkey/login",
            "/setup", "/healthz" };
        foreach (var endpoint in endpoints)
        {
            var route = "/" + endpoint.RoutePattern.RawText?.TrimStart('/');
            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            {
                // Static assets and framework endpoints are anonymous by design; application endpoints only when listed.
                if (route.StartsWith("/_", StringComparison.Ordinal) || route.Contains('.', StringComparison.Ordinal) ||
                    route.StartsWith("/{", StringComparison.Ordinal)) continue;
                Assert.Contains(route, anonymous);
            }
        }
    }

    [PostgresFact]
    public async Task A_user_without_a_permission_cannot_open_its_page_and_anonymous_users_are_sent_to_sign_in()
    {
        var anonymous = app.Client();
        foreach (var route in ExpectedPages.Where(p => p.Value != "anonymous").Select(p => Concrete(p.Key)))
        {
            var response = await anonymous.GetAsync(route);
            Assert.True(response.StatusCode == HttpStatusCode.Redirect, $"{route}: {response.StatusCode}");
            Assert.StartsWith("/account/login", response.Headers.Location?.AbsolutePath ?? response.Headers.Location?.OriginalString,
                StringComparison.Ordinal);
        }

        // Signed in, with a second factor, but without any role: the permission pages are refused.
        var (client, _) = await SignedInUserWithoutRolesAsync();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
        foreach (var route in ExpectedPages.Where(p => p.Value?.StartsWith(VaultyPolicies.PermissionPrefix, StringComparison.Ordinal) == true))
        {
            var response = await client.GetAsync(Concrete(route.Key));
            Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        }
        // Previews follow the same permission.
        Assert.NotEqual(HttpStatusCode.OK, (await client.GetAsync($"/preview/{Guid.NewGuid()}/{Guid.NewGuid()}/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await anonymous.GetAsync($"/preview/{Guid.NewGuid()}/{Guid.NewGuid()}/{Guid.NewGuid()}")).StatusCode);
        // Export downloads need the export permission.
        Assert.NotEqual(HttpStatusCode.OK, (await client.GetAsync($"/exports/{Guid.NewGuid()}/download?t=x")).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await anonymous.GetAsync($"/exports/{Guid.NewGuid()}/download?t=x")).StatusCode);
    }

    [PostgresFact]
    public async Task A_user_without_a_second_factor_cannot_receive_a_restore_role()
    {
        var (_, organizationId, adminId, userId) = await SeedOrganizationWithUserAsync(withMfa: false);
        using var scope = app.Factory.Services.CreateScope();
        var access = scope.ServiceProvider.GetRequiredService<AccessService>();
        var roles = await scope.ServiceProvider.GetRequiredService<UserDirectory>().RolesAsync(organizationId);

        foreach (var role in roles.Where(r => Permissions.AnyRequiresMfa(r.Permissions)))
        {
            var error = await Assert.ThrowsAsync<AccessException>(() => access.AssignRoleAsync(organizationId, adminId, userId, role.Id, null));
            Assert.Contains("passkey or an authenticator app", error.Message, StringComparison.Ordinal);
        }
        var readOnly = roles.Single(r => r.Name == BuiltInRoles.ReadOnly);
        await access.AssignRoleAsync(organizationId, adminId, userId, readOnly.Id, null);
        var effective = await access.GetAccessAsync(organizationId, userId);
        Assert.True(effective.Allows(Permissions.CustomersView));
        Assert.False(effective.Allows(Permissions.RestoreInPlace));
    }

    [PostgresFact]
    public async Task Mfa_permissions_are_not_effective_without_a_second_factor_even_if_a_role_holds_them()
    {
        var (_, organizationId, _, userId) = await SeedOrganizationWithUserAsync(withMfa: false);
        await using (var owner = new NpgsqlConnection(app.Database.Migrator))
        {
            // Simulate a role given before the factor was removed.
            await owner.ExecuteAsync(
                """
                INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id)
                SELECT gen_random_uuid(), @organizationId, @userId, id FROM vaulty.roles WHERE organization_id = @organizationId AND name = 'Restore operator'
                """, new { organizationId, userId });
        }
        using var scope = app.Factory.Services.CreateScope();
        var effective = await scope.ServiceProvider.GetRequiredService<AccessService>().GetAccessAsync(organizationId, userId);
        Assert.False(effective.Allows(Permissions.RestoreInPlace));
        Assert.True(effective.Allows(Permissions.CustomersView));
    }

    [PostgresFact]
    public async Task Pages_carry_security_headers_with_a_nonce()
    {
        var response = await app.Client().GetAsync("/account/login");
        var csp = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("script-src 'self' 'nonce-", csp, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Contains("max-age", response.Headers.GetValues("Strict-Transport-Security").Single(), StringComparison.Ordinal);
    }

    private async Task<(HttpClient Client, Guid UserId)> SignedInUserWithoutRolesAsync()
    {
        var (_, _, _, userId) = await SeedOrganizationWithUserAsync(withMfa: true, password: "member password long");
        var client = app.Client();
        var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var first = await client.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", $"member-{userId:N}@contoso.example"),
            ("password", "member password long"));
        var second = await (await client.GetAsync(first.Headers.Location)).Content.ReadAsStringAsync();
        var done = await client.PostFormAsync("/account/login/second-factor", Html.FormTokenOf(second), ("code", Totp.Code(MemberKey)));
        Assert.Equal(HttpStatusCode.Redirect, done.StatusCode);
        return (client, userId);
    }

    private const string MemberKey = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    /// <summary>An organization with built-in roles, an admin, and a member (optionally with an authenticator app).</summary>
    private async Task<(Guid Customer, Guid OrganizationId, Guid AdminId, Guid UserId)> SeedOrganizationWithUserAsync(bool withMfa,
        string password = "member password long")
    {
        using var scope = app.Factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<Vaulty.Core.Domain.User>>();
        var adminId = Guid.NewGuid();
        var organizationId = await scope.ServiceProvider.GetRequiredService<OrganizationSetup>().CreateOrganizationAsync("Matrix " + adminId, adminId);
        var userId = Guid.NewGuid();
        foreach (var (id, name) in new[] { (adminId, $"admin-{adminId:N}@contoso.example"), (userId, $"member-{userId:N}@contoso.example") })
        {
            var user = new Vaulty.Core.Domain.User
            {
                Id = id, OrganizationId = organizationId, UserName = name, NormalizedUserName = users.NormalizeName(name), Email = name,
                NormalizedEmail = users.NormalizeEmail(name),
            };
            if (id == userId && withMfa)
            {
                user.AuthenticatorKey = MemberKey;
                user.TwoFactorEnabled = true;
            }
            Assert.True((await users.CreateAsync(user, password)).Succeeded);
        }
        return (Guid.Empty, organizationId, adminId, userId);
    }
}

public sealed class ApiTests(WebAppFixture app) : IClassFixture<WebAppFixture>
{
    [PostgresFact]
    public async Task The_api_answers_health_checks_and_refuses_anonymous_calls()
    {
        using var api = new WebApplicationFactory<Vaulty.Api.ApiMarker>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Development");
            b.UseSetting("Vaulty:Database:ConnectionString", app.Database.Api);
            b.UseSetting("Vaulty:HostId", "test-host");
        });
        var client = api.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/healthz")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/healthz/ready")).StatusCode);
        // The test server has no loopback peer address: like any remote caller, it gets nothing from /metrics.
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/metrics")).StatusCode);
        using (var forwarded = new HttpRequestMessage(HttpMethod.Get, "/metrics"))
        {
            forwarded.Headers.Add("X-Forwarded-For", "203.0.113.7");
            Assert.Equal(HttpStatusCode.NotFound, (await client.SendAsync(forwarded)).StatusCode);
        }
        var openApi = await client.GetAsync("/api/v1/openapi.json");
        Assert.Equal(HttpStatusCode.OK, openApi.StatusCode);
        Assert.Contains("Vaulty API", await openApi.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/me")).StatusCode);

        // Every API endpoint is either explicitly anonymous (health, OpenAPI) or requires authorization.
        foreach (var endpoint in api.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>())
        {
            var route = "/" + endpoint.RoutePattern.RawText?.TrimStart('/');
            var anonymous = endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null;
            // /metrics answers only on the loopback interface and never through the reverse proxy (checked below).
            if (anonymous) Assert.Contains(route, new[] { "/api/v1/healthz", "/api/v1/healthz/ready", "/api/v1/openapi.json", "/metrics" });
            else Assert.NotEmpty(endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>());
        }
    }
}
