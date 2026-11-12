using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Dapper;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Vaulty.Infrastructure.Web;
using Vaulty.Core.Domain;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Identity;
using Vaulty.Integration.Tests.Database;
using Vaulty.Integration.Tests.Tenants;

namespace Vaulty.Integration.Tests.Web;

/// <summary>
/// The web app with one organization whose sign-in with Microsoft is set up against the simulated tenant. Security
/// stamps are checked on every request, so a change that ends sessions shows at the next request.
/// </summary>
public sealed class SignInWebFixture : IAsyncLifetime
{
    public const string AdminPassword = "correct horse battery";

    public PostgresDatabase Database { get; } = new();
    internal MicrosoftSimulator Microsoft { get; } = new();
    public WebApplicationFactory<Vaulty.Web.WebMarker> Factory { get; private set; } = null!;
    public Guid Organization { get; private set; }
    public Guid Tenant { get; } = Guid.NewGuid();
    public User Admin { get; private set; } = null!;

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
            b.UseSetting("Vaulty:Microsoft:AuthorityHost", Microsoft.Endpoints.AuthorityHost.ToString());
            b.UseSetting("Vaulty:Microsoft:GraphBaseUrl", Microsoft.Endpoints.Graph.ToString());
            b.ConfigureTestServices(s => s.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.Zero));
        });
        Microsoft.TenantId = Tenant;
        Microsoft.SignInClientId = Guid.NewGuid();
        Microsoft.SignInAppRoles = [SignInAppPermissions.UserReadAll, SignInAppPermissions.PolicyReadAll, SignInAppPermissions.GroupMemberReadAll];
        Microsoft.SecurityDefaults = true;

        using var scope = Factory.Services.CreateScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<User>>();
        var adminId = Guid.CreateVersion7();
        Organization = await services.GetRequiredService<OrganizationSetup>().CreateOrganizationAsync("Contoso IT", adminId);
        Admin = NewUser(users, "admin@contoso.example", adminId);
        Assert.True((await users.CreateAsync(Admin, AdminPassword)).Succeeded);
        await AddPasskeyAsync(Admin.Id);
        Assert.True(await services.GetRequiredService<OrganizationSetup>().CompleteFirstAdminAsync(Organization, Admin.Id));

        var signIn = services.GetRequiredService<MicrosoftSignInService>();
        await signIn.CreateCertificateAsync(Organization, "test");
        using (var certificate = await signIn.LoadCertificateAsync(Organization))
        {
            Microsoft.SignInCertificate = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
        }
        var settings = await signIn.SaveIdsAsync(Organization, Microsoft.SignInClientId, Tenant, null, "test");
        Assert.True(settings.CredentialWorks, settings.CredentialDetail);
        Assert.Equal(TenantMfaPosture.SecurityDefaults, settings.MfaPosture);
        Assert.True(settings.CanPickUsers);
        await signIn.RecordSignInCheckAsync(Organization, "test", MicrosoftSignInService.SignInChecksFrom(
            new MicrosoftAccount(Tenant, Guid.NewGuid(), "admin@contoso.example", null, false, [], null, DateTimeOffset.UtcNow), null));
        await signIn.SetOptionsAsync(Organization, "test", enabled: true, microsoftHandlesSecondFactor: true, signInOnly: false);
    }

    public User NewUser(UserManager<User> users, string email, Guid? id = null) => new()
    {
        Id = id ?? Guid.CreateVersion7(),
        OrganizationId = Organization,
        UserName = email,
        NormalizedUserName = users.NormalizeName(email),
        Email = email,
        NormalizedEmail = users.NormalizeEmail(email),
    };

    /// <summary>A passkey row as enrollment writes it; sign-in with it is not exercised here, only that the user has one.</summary>
    public async Task AddPasskeyAsync(Guid userId)
    {
        await using var owner = new NpgsqlConnection(Database.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.user_passkeys (organization_id, user_id, credential_id, public_key, name, created_at, is_user_verified, is_backup_eligible,
                                              is_backed_up, attestation_object, client_data_json)
            VALUES (@org, @userId, @credential, '\x00', 'Test passkey', now(), true, false, false, '\x00', '\x00')
            """, new { org = Organization, userId, credential = RandomNumberGenerator.GetBytes(16) });
    }

    public HttpClient Client() => Factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    public async Task DisposeAsync()
    {
        if (Factory is not null) await Factory.DisposeAsync();
        Microsoft.Dispose();
        await Database.DisposeAsync();
    }
}

public sealed partial class MicrosoftSignInTests(SignInWebFixture app) : IClassFixture<SignInWebFixture>
{
    [GeneratedRegex("content=\"0;url=([^\"]+)\"")]
    private static partial Regex Refresh();

    private static string RefreshTarget(string html) => WebUtility.HtmlDecode(Refresh().Match(html).Groups[1].Value);

    private T Service<T>() where T : notnull => app.Factory.Services.GetRequiredService<T>();

    /// <summary>A user of the organization, optionally with a password, optionally linked to the Entra account with this object id.</summary>
    private async Task<(User User, Guid ObjectId)> UserAsync(string name, bool link = true, string? password = null)
    {
        using var scope = app.Factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var user = app.NewUser(users, $"{name}-{Guid.NewGuid():N}@contoso.example");
        Assert.True((password is null ? await users.CreateAsync(user) : await users.CreateAsync(user, password)).Succeeded);
        var objectId = Guid.NewGuid();
        if (link) await Service<MicrosoftSignInService>().LinkAsync(app.Organization, "test", user.Id, objectId, user.UserName);
        return (user, objectId);
    }

    /// <summary>Starts at the sign-in page, signs in at the simulated Microsoft, and follows the callback page to the finish.</summary>
    private async Task<HttpResponseMessage> SignInWithMicrosoftAsync(HttpClient client, Guid objectId, Action<JsonObject>? shape = null, string returnUrl = "/")
    {
        var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
        Assert.Contains("Sign in with Microsoft", login, StringComparison.Ordinal);
        var start = await client.PostFormAsync("/account/microsoft/start", Html.FormTokenOf(login), ("returnUrl", returnUrl));
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        return await CompleteAtMicrosoftAsync(client, start.Headers.Location!, objectId, shape);
    }

    private async Task<HttpResponseMessage> CompleteAtMicrosoftAsync(HttpClient client, Uri authorize, Guid objectId, Action<JsonObject>? shape = null)
    {
        Assert.StartsWith(app.Microsoft.Endpoints.Authorize(app.Tenant.ToString()).ToString(), authorize.ToString(), StringComparison.Ordinal);
        var code = app.Microsoft.SignIn(authorize);
        var state = System.Web.HttpUtility.ParseQueryString(authorize.Query)["state"]!;
        // The id token is made when the callback redeems the code: the account and the shape apply until then, and not after.
        app.Microsoft.NextObjectId = objectId;
        app.Microsoft.ShapeIdToken = shape;
        string next;
        try
        {
            var callback = await client.GetAsync($"/account/microsoft/callback?state={Uri.EscapeDataString(state)}&code={Uri.EscapeDataString(code)}");
            next = RefreshTarget(await callback.Content.ReadAsStringAsync());
        }
        finally
        {
            app.Microsoft.NextObjectId = null;
            app.Microsoft.ShapeIdToken = null;
        }
        return await client.GetAsync(next);
    }

    private static async Task AssertSignedOutAsync(HttpClient client) =>
        Assert.Equal(HttpStatusCode.Redirect, (await client.GetAsync("/")).StatusCode);

    private async Task<List<string>> AuditAsync(Guid userId)
    {
        await using var owner = new NpgsqlConnection(app.Database.Migrator);
        return (await owner.QueryAsync<string>("SELECT action || ' ' || details::text FROM vaulty.audit_events WHERE target = @target ORDER BY seq",
            new { target = $"user:{userId}" })).ToList();
    }

    [PostgresFact]
    public async Task A_linked_user_signs_in_with_Microsoft_and_the_tenant_handles_the_second_factor()
    {
        var (user, objectId) = await UserAsync("alex");
        var client = app.Client();

        var finish = await SignInWithMicrosoftAsync(client, objectId, returnUrl: "/jobs");

        Assert.Equal("/jobs", finish.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
        var audit = await AuditAsync(user.Id);
        Assert.Contains(audit, a => a.StartsWith("user.linked", StringComparison.Ordinal));
        Assert.Contains(audit, a => a.StartsWith("login.succeeded", StringComparison.Ordinal) && a.Contains("\"microsoft\"", StringComparison.Ordinal)
                                    && a.Contains("\"delegated\"", StringComparison.Ordinal));
        // The Microsoft sign-in counts as the second factor, also for permissions that require one.
        await using var session = await Vaulty.Infrastructure.Database.OrganizationSession.BeginAsync(Service<NpgsqlDataSource>(), app.Organization);
        Assert.True(await AccessService.HasMfaAsync(session, user.Id));
    }

    [PostgresFact]
    public async Task A_token_that_proves_a_second_factor_says_so_in_the_audit_log()
    {
        var (user, objectId) = await UserAsync("mfa");
        await SignInWithMicrosoftAsync(app.Client(), objectId, c => c["amr"] = new JsonArray("pwd", "mfa"));
        Assert.Contains(await AuditAsync(user.Id), a => a.StartsWith("login.succeeded", StringComparison.Ordinal) && a.Contains("\"entra\"", StringComparison.Ordinal));
    }

    public static TheoryData<string> Refusals => ["other tenant", "guest", "no object id", "not linked", "same e-mail, other account", "other nonce"];

    [PostgresTheory]
    [MemberData(nameof(Refusals))]
    public async Task A_sign_in_that_breaks_a_rule_gets_no_session(string rule)
    {
        var (user, objectId) = await UserAsync("refused");
        var client = app.Client();
        var signInAs = objectId;
        Action<JsonObject>? shape = null;
        var tenant = app.Microsoft.TenantId;
        switch (rule)
        {
            case "other tenant": app.Microsoft.TenantId = Guid.NewGuid(); break;
            case "guest": shape = c => c["acct"] = 1; break;
            case "no object id": shape = c => c.Remove("oid"); break;
            case "not linked": signInAs = Guid.NewGuid(); break;
            case "same e-mail, other account":
                signInAs = Guid.NewGuid();
                shape = c => c["preferred_username"] = user.UserName;
                break;
            case "other nonce": shape = c => c["nonce"] = "forged"; break;
        }
        try
        {
            var finish = await SignInWithMicrosoftAsync(client, signInAs, shape);
            Assert.StartsWith("/account/login?error=microsoft", finish.Headers.Location?.OriginalString, StringComparison.Ordinal);
            var page = await (await client.GetAsync(finish.Headers.Location)).Content.ReadAsStringAsync();
            Assert.Contains("vy-alert error", page, StringComparison.Ordinal);
        }
        finally
        {
            app.Microsoft.TenantId = tenant;
        }
        await AssertSignedOutAsync(client);
    }

    [PostgresFact]
    public async Task A_state_works_once_and_only_in_the_browser_that_started_it()
    {
        var (_, objectId) = await UserAsync("state");
        var browser = app.Client();
        var login = await (await browser.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var start = await browser.PostFormAsync("/account/microsoft/start", Html.FormTokenOf(login), ("returnUrl", "/"));
        var code = app.Microsoft.SignIn(start.Headers.Location!);
        var state = System.Web.HttpUtility.ParseQueryString(start.Headers.Location!.Query)["state"]!;
        var callback = $"/account/microsoft/callback?state={Uri.EscapeDataString(state)}&code={Uri.EscapeDataString(code)}";

        // Another browser (no binding cookie) gets nothing, and Microsoft is not even asked.
        var attacker = app.Client();
        var stolen = RefreshTarget(await (await attacker.GetAsync(callback)).Content.ReadAsStringAsync());
        Assert.Equal("/account/login?error=expired", stolen);
        await AssertSignedOutAsync(attacker);

        // The state was used up by that attempt: the browser that started it starts again.
        Assert.Equal("/account/login?error=expired", RefreshTarget(await (await browser.GetAsync(callback)).Content.ReadAsStringAsync()));
        await AssertSignedOutAsync(browser);

        // A forged ticket is refused as well.
        Assert.Equal("/account/login?error=expired", (await browser.GetAsync("/account/microsoft/finish?ticket=forged")).Headers.Location?.OriginalString);
    }

    [PostgresFact]
    public async Task A_code_is_redeemed_once()
    {
        var (_, objectId) = await UserAsync("code");
        var first = app.Client();
        var second = app.Client();
        async Task<Uri> StartAsync(HttpClient client)
        {
            var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
            return (await client.PostFormAsync("/account/microsoft/start", Html.FormTokenOf(login), ("returnUrl", "/"))).Headers.Location!;
        }
        var a = await StartAsync(first);
        var b = await StartAsync(second);
        var code = app.Microsoft.SignIn(a);
        app.Microsoft.NextObjectId = objectId;
        string Callback(Uri authorize) =>
            $"/account/microsoft/callback?state={Uri.EscapeDataString(System.Web.HttpUtility.ParseQueryString(authorize.Query)["state"]!)}&code={Uri.EscapeDataString(code)}";

        await first.GetAsync(RefreshTarget(await (await first.GetAsync(Callback(a))).Content.ReadAsStringAsync()));
        Assert.Equal(HttpStatusCode.OK, (await first.GetAsync("/")).StatusCode);

        app.Microsoft.NextObjectId = null;
        var replay = await second.GetAsync(RefreshTarget(await (await second.GetAsync(Callback(b))).Content.ReadAsStringAsync()));
        Assert.StartsWith("/account/login?error=microsoft", replay.Headers.Location?.OriginalString, StringComparison.Ordinal);
        await AssertSignedOutAsync(second);
    }

    [PostgresFact]
    public async Task No_code_or_token_is_stored_anywhere_in_the_database()
    {
        var (_, objectId) = await UserAsync("scan");
        await SignInWithMicrosoftAsync(app.Client(), objectId);
        await SignInWithMicrosoftAsync(app.Client(), Guid.NewGuid());
        await using var owner = new NpgsqlConnection(app.Database.Migrator);
        var tables = (await owner.QueryAsync<string>("SELECT tablename FROM pg_tables WHERE schemaname = 'vaulty'")).ToList();
        var everything = new System.Text.StringBuilder();
        foreach (var table in tables) everything.AppendJoin('\n', await owner.QueryAsync<string>($"SELECT t::text FROM vaulty.\"{table}\" t"));
        var text = everything.ToString();
        List<string> issued;
        lock (app.Microsoft.Issued) issued = [.. app.Microsoft.Issued];
        Assert.NotEmpty(issued);
        foreach (var value in issued)
        {
            // The middle part of a JWT is unique enough; a code or opaque token is checked whole.
            var probe = value.Count(c => c == '.') >= 2 ? value.Split('.')[1] : value;
            Assert.DoesNotContain(probe, text, StringComparison.Ordinal);
        }
    }

    [PostgresFact]
    public async Task A_linked_user_cannot_sign_in_with_a_password()
    {
        var (user, _) = await UserAsync("password", password: "a long enough password");
        var client = app.Client();
        var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var right = await client.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", user.UserName), ("password", "a long enough password"));
        Assert.StartsWith("/account/login?error=use-microsoft", right.Headers.Location?.OriginalString, StringComparison.Ordinal);
        var wrong = await client.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", user.UserName), ("password", "not the password at all"));
        Assert.StartsWith("/account/login?error=invalid", wrong.Headers.Location?.OriginalString, StringComparison.Ordinal);
        await AssertSignedOutAsync(client);
    }

    [PostgresFact]
    public async Task Unlinking_ends_the_session_at_once()
    {
        var (user, objectId) = await UserAsync("unlink");
        var client = app.Client();
        await SignInWithMicrosoftAsync(client, objectId);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);

        await Service<MicrosoftSignInService>().UnlinkAsync(app.Organization, "test", user.Id);

        await AssertSignedOutAsync(client);
        Assert.Contains(await AuditAsync(user.Id), a => a.StartsWith("user.unlinked", StringComparison.Ordinal));
    }

    [PostgresFact]
    public async Task Without_Microsoft_handling_the_second_factor_a_linked_user_needs_one_of_Vaulty()
    {
        var signIn = Service<MicrosoftSignInService>();
        var (other, otherObject) = await UserAsync("session");
        var running = app.Client();
        await SignInWithMicrosoftAsync(running, otherObject);
        Assert.Equal(HttpStatusCode.OK, (await running.GetAsync("/")).StatusCode);
        var (user, objectId) = await UserAsync("own-factor");
        try
        {
            await signIn.SetOptionsAsync(app.Organization, "test", enabled: true, microsoftHandlesSecondFactor: false, signInOnly: false);

            // Switching it off ended the running session of a linked user.
            await AssertSignedOutAsync(running);
            // A new Microsoft sign-in without a Vaulty passkey or code reaches only the page to add one.
            var client = app.Client();
            var finish = await SignInWithMicrosoftAsync(client, objectId);
            Assert.Equal("/account/mfa-setup", finish.Headers.Location?.OriginalString);
            Assert.NotEqual(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
            await using var session = await Vaulty.Infrastructure.Database.OrganizationSession.BeginAsync(Service<NpgsqlDataSource>(), app.Organization);
            Assert.False(await AccessService.HasMfaAsync(session, user.Id));
            Assert.False(await AccessService.HasMfaAsync(session, other.Id));
        }
        finally
        {
            await signIn.SetOptionsAsync(app.Organization, "test", enabled: true, microsoftHandlesSecondFactor: true, signInOnly: false);
        }
    }

    [PostgresFact]
    public async Task A_fresh_Microsoft_sign_in_counts_as_confirmation_and_a_reused_Microsoft_session_does_not()
    {
        var (_, objectId) = await UserAsync("fresh");
        var fresh = await SignInWithMicrosoftAsync(app.Client(), objectId);
        Assert.True(VaultyWebSetup.HasFreshStepUp(Session.StartedBy(app.Factory, fresh), TimeProvider.System));

        var reused = await SignInWithMicrosoftAsync(app.Client(), objectId, c => c["auth_time"] = DateTimeOffset.UtcNow.AddHours(-3).ToUnixTimeSeconds());
        var session = Session.StartedBy(app.Factory, reused);
        Assert.NotNull(VaultyWebSetup.UserId(session));
        Assert.False(VaultyWebSetup.HasFreshStepUp(session, TimeProvider.System));
    }

    [PostgresFact]
    public async Task Confirm_its_you_is_a_fresh_Microsoft_sign_in_of_the_same_account()
    {
        var (user, objectId) = await UserAsync("stepup");
        var client = app.Client();
        await SignInWithMicrosoftAsync(client, objectId);

        async Task<HttpResponseMessage> ConfirmAsync(Guid signInAs, Action<JsonObject>? shape = null)
        {
            var page = await (await client.GetAsync("/account/confirm?returnUrl=%2Fjobs")).Content.ReadAsStringAsync();
            Assert.Contains("Confirm with Microsoft", page, StringComparison.Ordinal);
            var start = await client.PostFormAsync("/account/microsoft/stepup", Html.FormTokenOf(page), ("returnUrl", "/jobs"));
            var query = System.Web.HttpUtility.ParseQueryString(start.Headers.Location!.Query);
            Assert.Equal("login", query["prompt"]);
            Assert.Equal("0", query["max_age"]);
            return await CompleteAtMicrosoftAsync(client, start.Headers.Location!, signInAs, shape);
        }

        var stale = await ConfirmAsync(objectId, c => c["auth_time"] = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds());
        Assert.Contains("error=microsoft", stale.Headers.Location?.OriginalString, StringComparison.Ordinal);
        var other = await ConfirmAsync(Guid.NewGuid());
        Assert.Contains("error=microsoft", other.Headers.Location?.OriginalString, StringComparison.Ordinal);
        var fresh = await ConfirmAsync(objectId);
        Assert.Equal("/jobs", fresh.Headers.Location?.OriginalString);

        var audit = await AuditAsync(user.Id);
        Assert.Equal(2, audit.Count(a => a.StartsWith("stepup.failed", StringComparison.Ordinal)));
        Assert.Contains(audit, a => a.StartsWith("stepup.confirmed", StringComparison.Ordinal) && a.Contains("\"microsoft\"", StringComparison.Ordinal));
        // Still signed in after the refusals.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
    }

    [PostgresFact]
    public async Task A_local_user_links_their_own_Microsoft_account_and_then_signs_in_with_it()
    {
        var (user, _) = await UserAsync("self", link: false, password: "a long enough password");
        var client = app.Client();
        var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
        var password = await client.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", user.UserName), ("password", "a long enough password"));
        Assert.Equal("/account/mfa-setup", password.Headers.Location?.OriginalString);
        var page = await (await client.GetAsync("/account/mfa-setup")).Content.ReadAsStringAsync();
        var start = await client.PostFormAsync("/account/microsoft/link", Html.FormTokenOf(page));
        var objectId = Guid.NewGuid();
        var finish = await CompleteAtMicrosoftAsync(client, start.Headers.Location!, objectId);

        Assert.Equal("/account/login?linked=1", finish.Headers.Location?.OriginalString);
        await AssertSignedOutAsync(client);
        Assert.Equal(objectId, (await Service<MicrosoftSignInService>().LinkOfAsync(app.Organization, user.Id))!.ObjectId);
        var again = app.Client();
        await SignInWithMicrosoftAsync(again, objectId);
        Assert.Equal(HttpStatusCode.OK, (await again.GetAsync("/")).StatusCode);
    }

    [PostgresFact]
    public async Task The_last_local_Organization_admin_stays_local()
    {
        var error = await Assert.ThrowsAsync<SignInSetupException>(() =>
            Service<MicrosoftSignInService>().LinkAsync(app.Organization, "test", app.Admin.Id, Guid.NewGuid(), app.Admin.UserName));
        Assert.Contains("last local Organization admin", error.Message, StringComparison.Ordinal);
        Assert.Null(await Service<MicrosoftSignInService>().LinkOfAsync(app.Organization, app.Admin.Id));
    }

    [PostgresFact]
    public async Task With_Microsoft_sign_in_only_a_local_sign_in_is_refused_except_for_an_emergency_administrator()
    {
        var signIn = Service<MicrosoftSignInService>();
        var (local, _) = await UserAsync("local", link: false, password: "a long enough password");
        var running = app.Client();
        var runningLogin = await (await running.GetAsync("/account/login")).Content.ReadAsStringAsync();
        await running.PostFormAsync("/account/login", Html.FormTokenOf(runningLogin), ("username", local.UserName), ("password", "a long enough password"));
        Assert.Equal(HttpStatusCode.OK, (await running.GetAsync("/account/mfa-setup")).StatusCode);
        try
        {
            await signIn.SetOptionsAsync(app.Organization, "test", enabled: true, microsoftHandlesSecondFactor: true, signInOnly: true);
            // The running local session ended.
            Assert.Equal(HttpStatusCode.Redirect, (await running.GetAsync("/account/mfa-setup")).StatusCode);

            var client = app.Client();
            var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
            Assert.Contains("Emergency access", login, StringComparison.Ordinal);
            var refused = await client.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", local.UserName), ("password", "a long enough password"));
            Assert.StartsWith("/account/login?error=microsoft-only", refused.Headers.Location?.OriginalString, StringComparison.Ordinal);

            var admin = app.Client();
            var adminLogin = await (await admin.GetAsync("/account/login")).Content.ReadAsStringAsync();
            var emergency = await admin.PostFormAsync("/account/login", Html.FormTokenOf(adminLogin), ("username", app.Admin.UserName),
                ("password", SignInWebFixture.AdminPassword));
            Assert.Equal(HttpStatusCode.Redirect, emergency.StatusCode);
            Assert.DoesNotContain("error", emergency.Headers.Location?.OriginalString, StringComparison.Ordinal);
            await using var owner = new NpgsqlConnection(app.Database.Migrator);
            Assert.Equal(1, await owner.ExecuteScalarAsync<int>(
                "SELECT count(*)::int FROM vaulty.alerts WHERE kind = 'signin.break_glass' AND resolved_at IS NULL AND severity = 'critical'"));
        }
        finally
        {
            await signIn.SetOptionsAsync(app.Organization, "test", enabled: true, microsoftHandlesSecondFactor: true, signInOnly: false);
        }
    }

    [PostgresFact]
    public async Task Microsoft_sign_in_only_needs_an_emergency_administrator_with_a_passkey()
    {
        var signIn = Service<MicrosoftSignInService>();
        await using var owner = new NpgsqlConnection(app.Database.Migrator);
        var passkeys = (await owner.QueryAsync<byte[]>("SELECT credential_id FROM vaulty.user_passkeys WHERE user_id = @id", new { id = app.Admin.Id })).ToList();
        await owner.ExecuteAsync("DELETE FROM vaulty.user_passkeys WHERE user_id = @id", new { id = app.Admin.Id });
        try
        {
            var error = await Assert.ThrowsAsync<SignInSetupException>(() =>
                signIn.SetOptionsAsync(app.Organization, "test", enabled: true, microsoftHandlesSecondFactor: true, signInOnly: true));
            Assert.Contains("passkey", error.Message, StringComparison.Ordinal);
            Assert.False((await signIn.GetAsync(app.Organization)).SignInOnly);
        }
        finally
        {
            await app.AddPasskeyAsync(app.Admin.Id);
        }
    }

    [PostgresFact]
    public async Task An_account_linked_in_another_organization_does_not_sign_in_here()
    {
        using var scope = app.Factory.Services.CreateScope();
        var otherOrg = await scope.ServiceProvider.GetRequiredService<OrganizationSetup>().CreateOrganizationAsync("Fabrikam", Guid.NewGuid());
        var objectId = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(app.Database.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.users (id, organization_id, user_name, normalized_user_name, security_stamp, concurrency_stamp, entra_tenant_id, entra_object_id)
            VALUES (@id, @org, @name, upper(@name), 'x', 'y', @tenant, @objectId)
            """, new { id = Guid.NewGuid(), org = otherOrg, name = $"x-{objectId:N}@fabrikam.example", tenant = app.Tenant, objectId });

        Assert.Null(await Service<MicrosoftSignInService>().FindLinkedUserAsync(app.Tenant, objectId));
        var finish = await SignInWithMicrosoftAsync(app.Client(), objectId);
        Assert.StartsWith("/account/login?error=microsoft", finish.Headers.Location?.OriginalString, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task Opening_the_second_factor_page_keeps_the_session_while_the_user_sets_up_the_app()
    {
        var (user, _) = await UserAsync("totp", link: false, password: "a long enough password");
        var client = app.Client();
        var login = await (await client.GetAsync("/account/login")).Content.ReadAsStringAsync();
        await client.PostFormAsync("/account/login", Html.FormTokenOf(login), ("username", user.UserName), ("password", "a long enough password"));
        // The first visit creates the authenticator key; the stamp is checked on every request here, and must not have changed.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/account/mfa-setup")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/account/mfa-setup")).StatusCode);
    }

    [Fact]
    public async Task Refreshing_the_session_keeps_its_sign_in_time_method_and_second_factor_source()
    {
        var current = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
        [
            new(Vaulty.Infrastructure.Web.VaultyClaims.AuthTime, "1000"), new(Vaulty.Infrastructure.Web.VaultyClaims.Method, "microsoft"),
            new(Vaulty.Infrastructure.Web.VaultyClaims.MfaSource, "entra"),
        ], "test"));
        var fresh = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
            [new System.Security.Claims.Claim(Vaulty.Infrastructure.Web.VaultyClaims.AuthTime, "9999")], "test"));
        await Vaulty.Infrastructure.Web.VaultyWebSetup.KeepSessionClaims(new SecurityStampRefreshingPrincipalContext { CurrentPrincipal = current, NewPrincipal = fresh });
        // The 8-hour limit counts from the original sign-in, not from the refresh.
        Assert.Equal("1000", Assert.Single(fresh.FindAll(Vaulty.Infrastructure.Web.VaultyClaims.AuthTime)).Value);
        Assert.Equal("microsoft", fresh.FindFirst(Vaulty.Infrastructure.Web.VaultyClaims.Method)?.Value);
        Assert.True(fresh.HasClaim(Vaulty.Infrastructure.Web.VaultyClaims.Mfa, "1"));
    }

    [PostgresFact]
    public async Task An_Entra_group_gives_its_mapped_role_at_sign_in_and_takes_it_away_after_leaving_it()
    {
        var (user, objectId) = await UserAsync("mapped");
        var administration = Service<AccessAdministration>();
        var readOnly = (await administration.RolesAsync(app.Organization)).Single(r => r.Name == Vaulty.Core.Security.BuiltInRoles.ReadOnly).Id;
        var entraGroup = Guid.NewGuid();
        var actor = new UserAccess(app.Admin.Id, app.Organization, true,
            Vaulty.Core.Security.Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));
        var mapping = await administration.SaveMappingAsync(actor, null, entraGroup, "Helpdesk", [readOnly], []);
        try
        {
            app.Microsoft.EntraGroups[objectId] = [entraGroup];
            await SignInWithMicrosoftAsync(app.Client(), objectId);
            Assert.Contains(Vaulty.Core.Security.Permissions.ReportsView, (await Service<AccessService>().GetAccessAsync(app.Organization, user.Id)).Permissions);

            app.Microsoft.EntraGroups[objectId] = [];
            await SignInWithMicrosoftAsync(app.Client(), objectId);
            Assert.Empty((await Service<AccessService>().GetAccessAsync(app.Organization, user.Id)).Permissions);
        }
        finally
        {
            await administration.DeleteMappingAsync(actor, mapping);
        }
    }

    [PostgresFact]
    public async Task A_member_of_a_mapped_group_gets_a_user_at_the_first_sign_in_when_that_is_switched_on()
    {
        var administration = Service<AccessAdministration>();
        var signIn = Service<MicrosoftSignInService>();
        var readOnly = (await administration.RolesAsync(app.Organization)).Single(r => r.Name == Vaulty.Core.Security.BuiltInRoles.ReadOnly).Id;
        var entraGroup = Guid.NewGuid();
        var actor = new UserAccess(app.Admin.Id, app.Organization, true,
            Vaulty.Core.Security.Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));
        var mapping = await administration.SaveMappingAsync(actor, null, entraGroup, "New staff", [readOnly], []);
        var newcomer = Guid.NewGuid();
        var outsider = Guid.NewGuid();
        app.Microsoft.EntraGroups[newcomer] = [entraGroup];
        try
        {
            // Off by default: an account without a Vaulty user is refused.
            var refused = await SignInWithMicrosoftAsync(app.Client(), newcomer);
            Assert.StartsWith("/account/login?error=microsoft", refused.Headers.Location?.OriginalString, StringComparison.Ordinal);

            await signIn.SetJitProvisioningAsync(app.Organization, "test", true);
            var client = app.Client();
            await SignInWithMicrosoftAsync(client, newcomer);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
            var created = await signIn.FindLinkedUserAsync(app.Tenant, newcomer);
            Assert.NotNull(created);
            var access = await Service<AccessService>().GetAccessAsync(app.Organization, created.Value.UserId);
            Assert.Contains(Vaulty.Core.Security.Permissions.ReportsView, access.Permissions);
            // In no mapped group: still no user.
            var other = await SignInWithMicrosoftAsync(app.Client(), outsider);
            Assert.StartsWith("/account/login?error=microsoft", other.Headers.Location?.OriginalString, StringComparison.Ordinal);
            Assert.Null(await signIn.FindLinkedUserAsync(app.Tenant, outsider));
        }
        finally
        {
            await signIn.SetJitProvisioningAsync(app.Organization, "test", false);
            await administration.DeleteMappingAsync(actor, mapping);
        }
    }

    [Fact]
    public void A_test_sign_in_without_the_sign_in_time_claim_does_not_make_the_app_ready()
    {
        var checks = MicrosoftSignInService.SignInChecksFrom(new MicrosoftAccount(Guid.NewGuid(), Guid.NewGuid(), "a@contoso.example", null, false, [], null, null), null);
        var time = Assert.Single(checks, c => c.Name == "Sign-in time in the token");
        Assert.True(time.Required);
        Assert.False(time.Passed);
        Assert.Contains("auth_time", time.Detail, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task The_user_picker_finds_members_and_leaves_guests_out()
    {
        var member = Guid.NewGuid();
        app.Microsoft.Members.Add((member, "Robin Member", "robin@contoso.example", "Member"));
        app.Microsoft.Members.Add((Guid.NewGuid(), "Robin Guest", "robin_guest#EXT#@contoso.example", "Guest"));
        var signIn = Service<MicrosoftSignInService>();
        var found = await signIn.SearchMembersAsync(app.Organization, "Robin");
        Assert.Equal(member, Assert.Single(found).ObjectId);
        Assert.NotNull(await signIn.MemberAsync(app.Organization, member));
    }

    [PostgresFact]
    public async Task A_failed_test_sign_in_is_recorded_as_a_failed_check_in_plain_words()
    {
        var logins = Service<MicrosoftLogins>();
        var binding = MicrosoftLogins.NewBindingValue();
        var authorize = await logins.BeginAsync(MicrosoftLoginPurpose.Check, app.Organization, app.Admin.Id,
            new Uri("https://localhost/account/microsoft/callback"), "/settings/sign-in", binding);
        var state = System.Web.HttpUtility.ParseQueryString(authorize.Query)["state"];
        var ticket = await logins.CompleteAsync(state, null, "invalid_request", "AADSTS50011: The redirect URI does not match.", binding);
        var result = logins.Redeem(ticket, binding)!;
        var checks = MicrosoftSignInService.SignInChecksFrom(result.Account, result.Error);
        var check = Assert.Single(checks);
        Assert.False(check.Passed);
        Assert.Contains("redirect URI", check.Detail, StringComparison.Ordinal);
        // A ticket works once.
        Assert.Null(logins.Redeem(ticket, binding));
    }
}
