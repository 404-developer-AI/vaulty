using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Dapper;
using Microsoft.Extensions.Logging;
using Npgsql;
using Vaulty.Core.Crypto;
using Vaulty.Graph.Auth;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Infrastructure.Storage;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Integration.Tests.Database;

namespace Vaulty.Integration.Tests.Tenants;

/// <summary>Collects log lines, to prove no token reaches a log.</summary>
internal sealed class CapturingLogger<T> : ILogger<T>
{
    public List<string> Lines { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (Lines) Lines.Add(formatter(state, exception) + " " + exception);
    }
}

/// <summary>The simulated tenant accepts a certificate once it is a key of the app.</summary>
internal sealed class SimulatedVerifier(MicrosoftSimulator microsoft) : ICredentialVerifier
{
    public Task VerifyAsync(GraphCredential credential, CancellationToken cancellationToken = default) =>
        microsoft.Accepts(credential.ClientId, credential.Certificate)
            ? Task.CompletedTask
            : throw new IdentityException("invalid_client", "AADSTS700027: the certificate is not a key of the app.");
}

public sealed class BrowserConnectTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>, IDisposable
{
    private static readonly Uri Redirect = new("https://vaulty.example.com/connect/microsoft/callback");
    // One key for the class: the setup app's certificate is a platform secret that every test in the database shares.
    private static readonly byte[] MasterKey = RandomNumberGenerator.GetBytes(32);
    private readonly MicrosoftSimulator _microsoft = new();
    private readonly HttpClient _http = new();

    private sealed record World(Guid Org, Guid Customer, Guid Admin, NpgsqlDataSource Api, PostgresSecretStore Secrets, SetupAppService Setup,
        BrowserConnection Connection, TenantService Tenants, CapturingLogger<BrowserConnection> Log, DedicatedAppCredentialProvider Credentials,
        GraphServices Graph, AppRegistrationClient Registrations);

    private async Task<World> WorldAsync(bool readySetup = true)
    {
        var api = VaultyDataSource.Create(db.Api);
        var adminId = Guid.NewGuid();
        var access = new AccessService(api);
        var org = await new OrganizationSetup(api, access).CreateOrganizationAsync("Org " + adminId, adminId);
        var customer = await new CustomerService(api).CreateAsync(org, adminId, "C" + adminId.ToString("N")[..6], "Contoso", []);
        var secrets = new PostgresSecretStore(api, new SecretCipher(MasterKey, "host-a"), TimeProvider.System, TimeSpan.Zero);
        var identity = new IdentityClient(_http, _microsoft.Endpoints, TimeProvider.System);
        var registrations = new AppRegistrationClient(_http, _microsoft.Endpoints, (_, _) => Task.CompletedTask);
        var settings = new PlatformSettings(api);
        var setup = new SetupAppService(settings, secrets, identity, registrations, TimeProvider.System);
        var credentials = new DedicatedAppCredentialProvider(api, secrets, TimeProvider.System);
        var graph = new GraphServices(new ScriptedTokens(), graphBaseUri: _microsoft.GraphBase);
        var log = new CapturingLogger<BrowserConnection>();
        var connection = new BrowserConnection(api, secrets, credentials, graph, setup, identity, registrations, new MicrosoftSignIns(TimeProvider.System),
            TimeProvider.System, log, new BrowserConnectionOptions { ProbeAttempts = 1, ProbeWait = TimeSpan.Zero });
        if (readySetup)
        {
            // The platform's setup app: the platform settings are shared by every test in this database.
            var current = await setup.GetAsync();
            if (!current.Ready) current = await setup.CreateCertificateAsync("test");
            var clientId = current.ClientId ?? Guid.NewGuid();
            await settings.SetAsync(SetupAppSettings.SettingKey, current with
            {
                ClientId = clientId, HomeTenantId = current.HomeTenantId ?? Guid.NewGuid(), CredentialWorks = true,
                RegistrationChecks = [new SetupCheck("All", true, true, "")],
            }, "test");
            _microsoft.SetupClientId = clientId;
            using var certificate = await setup.LoadCertificateAsync(SetupAppSettings.CertificateSecretName, default);
            _microsoft.SetupCertificate = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
            _microsoft.ServicePrincipals[clientId] = Guid.NewGuid();
        }
        return new World(org, customer, adminId, api, secrets, setup, connection, new TenantService(api, secrets, credentials, graph, TimeProvider.System), log,
            credentials, graph, registrations);
    }

    /// <summary>Technician starts, administrator signs in at Microsoft, Microsoft redirects back; returns the finished run.</summary>
    private async Task<(SetupRunView Run, string Path)> SignInAndRunAsync(World w, SignInPurpose purpose, Guid target, bool includeRestore = true, Guid? user = null)
    {
        var url = await w.Connection.BeginAsync(purpose, w.Org, user ?? w.Admin, target, Redirect, "/customers/x/connect", includeRestore);
        var state = System.Web.HttpUtility.ParseQueryString(url.Query)["state"];
        var path = await w.Connection.CompleteSignInAsync(state, _microsoft.SignIn(url), null, null);
        var run = Guid.Parse(System.Web.HttpUtility.ParseQueryString(new Uri(new Uri("https://x"), path).Query)["run"]!);
        return (await w.Connection.WaitAsync(run, user ?? w.Admin), path);
    }

    private async Task<Guid> PendingAsync(World w, bool includeRestore = true) =>
        (await w.Tenants.BeginConnectAsync(w.Org, w.Admin, w.Customer, "Contoso", includeRestore, default, browser: true)).Id;

    [PostgresFact]
    public async Task A_sign_in_creates_the_app_grants_its_permissions_connects_the_tenant_and_removes_the_setup_app()
    {
        var w = await WorldAsync();
        var pending = await PendingAsync(w);
        var url = await w.Connection.BeginAsync(SignInPurpose.Connect, w.Org, w.Admin, pending, Redirect, "/customers/x/connect", true);
        var query = System.Web.HttpUtility.ParseQueryString(url.Query);
        Assert.Equal(("code", "S256", "query"), (query["response_type"], query["code_challenge_method"], query["response_mode"]));
        Assert.DoesNotContain("offline_access", query["scope"], StringComparison.Ordinal);
        Assert.StartsWith(_microsoft.Endpoints.Authorize("organizations").ToString(), url.ToString(), StringComparison.Ordinal);

        var path = await w.Connection.CompleteSignInAsync(query["state"], _microsoft.SignIn(url), null, null);
        var runId = Guid.Parse(System.Web.HttpUtility.ParseQueryString(new Uri(new Uri("https://x"), path).Query)["run"]!);
        var run = await w.Connection.WaitAsync(runId, w.Admin);
        Assert.True(run.State == SetupRunState.Succeeded, run.Message);
        Assert.Empty(run.Warnings);

        // Exactly the expected Graph calls, in order.
        var app = Assert.Single(_microsoft.Applications.Values);
        var appId = Guid.Parse(app["appId"]!.GetValue<string>());
        var objectId = Guid.Parse(app["id"]!.GetValue<string>());
        var graphCalls = _microsoft.GraphCalls.ToList();
        Assert.Equal(1, graphCalls.Count(c => c == "POST /graph/v1.0/applications"));
        Assert.Equal(1, graphCalls.Count(c => c == "POST /graph/v1.0/servicePrincipals"));
        Assert.Equal(GraphPermissions.All.Count, graphCalls.Count(c => c == $"POST /graph/v1.0/servicePrincipals/{_microsoft.GraphServicePrincipalId}/appRoleAssignedTo"));
        Assert.Equal($"DELETE /graph/v1.0/servicePrincipals(appId='{_microsoft.SetupClientId}')", graphCalls.Last(c => !c.EndsWith("organization", StringComparison.Ordinal) && !c.EndsWith("users", StringComparison.Ordinal)));
        Assert.True(graphCalls.IndexOf("POST /graph/v1.0/applications") < graphCalls.IndexOf("POST /graph/v1.0/servicePrincipals"));
        Assert.Equal("AzureADMyOrg", app["signInAudience"]!.GetValue<string>());
        Assert.Equal(GraphPermissions.All.Count, ((JsonArray)app["requiredResourceAccess"]![0]!["resourceAccess"]!).Count);
        Assert.False(_microsoft.ServicePrincipals.ContainsKey(_microsoft.SetupClientId));
        var sp = _microsoft.ServicePrincipals[appId];
        Assert.Equal(_microsoft.ApplicationRoles.Values.ToHashSet(), _microsoft.Assignments[sp]);

        // The tenant row: the ids come from Microsoft, nobody typed them; the certificate is the pending one.
        var tenant = Assert.Single(await w.Tenants.ListAsync(w.Org, w.Customer));
        Assert.Equal((_microsoft.TenantId, (Guid?)appId, "granted", (Guid?)objectId), (tenant.EntraTenantId, tenant.ClientId, tenant.ConsentState, tenant.ApplicationObjectId));
        Assert.Equal(tenant.Id, run.TenantId);
        var credential = await w.Credentials.GetAsync(tenant.Id);
        Assert.True(_microsoft.Accepts(appId, credential.Certificate));

        await using var owner = new NpgsqlConnection(db.Migrator);
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>("SELECT count(*)::int FROM vaulty.pending_tenant_connections WHERE id = @pending", new { pending }));
        var actions = (await owner.QueryAsync<string>("SELECT action FROM vaulty.audit_events WHERE organization_id = @org ORDER BY seq", new { org = w.Org })).ToList();
        Assert.Equal(["tenant.connect_started", "tenant.connect_signed_in", "tenant.connect_app_created", "tenant.connect_service_principal_created",
            "tenant.connect_permissions_granted", "tenant.connected", "tenant.probed", "tenant.setup_app_removed"], actions.Where(a => a.StartsWith("tenant.", StringComparison.Ordinal)));
        Assert.Contains(_microsoft.UserName, await owner.ExecuteScalarAsync<string>(
            "SELECT details::text FROM vaulty.audit_events WHERE action = 'tenant.connected' AND organization_id = @org", new { org = w.Org }), StringComparison.Ordinal);

        // No token, code or id token is stored anywhere or logged.
        await AssertNoTokenStoredAsync(w);
    }

    private async Task AssertNoTokenStoredAsync(World w)
    {
        await using var owner = new NpgsqlConnection(db.Migrator);
        var dump = string.Join('\n', await owner.QueryAsync<string>(
            """
            SELECT row_to_json(t)::text FROM vaulty.audit_events t UNION ALL
            SELECT row_to_json(t)::text FROM vaulty.tenants t UNION ALL
            SELECT row_to_json(t)::text FROM vaulty.pending_tenant_connections t UNION ALL
            SELECT row_to_json(t)::text FROM vaulty.platform_settings t UNION ALL
            SELECT name FROM vaulty.secrets
            """));
        var log = string.Join('\n', w.Log.Lines);
        Assert.NotEmpty(_microsoft.Issued);
        foreach (var issued in _microsoft.Issued)
        {
            Assert.DoesNotContain(issued, dump, StringComparison.Ordinal);
            Assert.DoesNotContain(issued, log, StringComparison.Ordinal);
        }
    }

    [PostgresFact]
    public async Task A_wrong_reused_or_foreign_sign_in_is_refused_without_a_Graph_call()
    {
        var w = await WorldAsync();
        var pending = await PendingAsync(w);
        var url = await w.Connection.BeginAsync(SignInPurpose.Connect, w.Org, w.Admin, pending, Redirect, "/customers/x/connect", true);
        var state = System.Web.HttpUtility.ParseQueryString(url.Query)["state"];
        var code = _microsoft.SignIn(url);

        Assert.Equal("/connect/microsoft/expired", await w.Connection.CompleteSignInAsync("forged-state", code, null, null));
        Assert.Equal("/connect/microsoft/expired", await w.Connection.CompleteSignInAsync(null, code, null, null));
        var path = await w.Connection.CompleteSignInAsync(state, code, null, null);
        // The same state a second time (a replayed redirect) is refused.
        Assert.Equal("/connect/microsoft/expired", await w.Connection.CompleteSignInAsync(state, code, null, null));

        // The run belongs to the user who started it: another Vaulty user sees nothing.
        var run = Guid.Parse(System.Web.HttpUtility.ParseQueryString(new Uri(new Uri("https://x"), path).Query)["run"]!);
        Assert.Null(w.Connection.Get(run, Guid.NewGuid()));
        await w.Connection.WaitAsync(run, w.Admin);

        // A code that was already redeemed fails at Microsoft and creates nothing.
        var before = _microsoft.GraphCalls.Count();
        var second = await w.Connection.BeginAsync(SignInPurpose.Connect, w.Org, w.Admin, Guid.NewGuid(), Redirect, "/customers/x/connect", true);
        var reused = await w.Connection.CompleteSignInAsync(System.Web.HttpUtility.ParseQueryString(second.Query)["state"], code, null, null);
        var failed = await w.Connection.WaitAsync(Guid.Parse(reused.Split("run=")[1]), w.Admin);
        Assert.Equal(SetupRunState.Failed, failed.State);
        Assert.Contains("expired or was already used", failed.Message, StringComparison.Ordinal);
        Assert.Equal(before, _microsoft.GraphCalls.Count());

        // Consent declined at Microsoft: a plain message, no Graph call.
        var third = await w.Connection.BeginAsync(SignInPurpose.Connect, w.Org, w.Admin, pending, Redirect, "/customers/x/connect", true);
        var declined = await w.Connection.CompleteSignInAsync(System.Web.HttpUtility.ParseQueryString(third.Query)["state"], null, "access_denied",
            "AADSTS65004: User declined to consent.");
        var declinedRun = await w.Connection.WaitAsync(Guid.Parse(declined.Split("run=")[1]), w.Admin);
        Assert.Contains("cancelled or consent was declined", declinedRun.Message, StringComparison.Ordinal);
        Assert.Equal(before, _microsoft.GraphCalls.Count());
    }

    [PostgresFact]
    public async Task A_tenant_connected_elsewhere_or_an_account_without_an_admin_role_is_refused_before_an_app_is_created()
    {
        var w = await WorldAsync();
        // Already connected (here by a script connection of the same Microsoft 365 tenant).
        var script = await w.Tenants.BeginConnectAsync(w.Org, w.Admin, w.Customer, "Earlier");
        await w.Tenants.CompleteConnectAsync(w.Org, w.Admin, script.Id, _microsoft.TenantId, Guid.NewGuid());
        var (taken, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w));
        Assert.Equal(SetupRunState.Failed, taken.State);
        Assert.Contains("already connected", taken.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /graph/v1.0/applications", _microsoft.GraphCalls);

        // A user without Global Administrator or Privileged Role Administrator, in another tenant.
        _microsoft.TenantId = Guid.NewGuid();
        _microsoft.DirectoryRoles = [Guid.Parse("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3")];
        _microsoft.ServicePrincipals[_microsoft.SetupClientId] = Guid.NewGuid();
        var (notAdmin, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w));
        Assert.Equal(SetupRunState.Failed, notAdmin.State);
        Assert.Contains("not a Global Administrator", notAdmin.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /graph/v1.0/applications", _microsoft.GraphCalls);
        // The setup app's consent does not stay behind in the tenant.
        Assert.False(_microsoft.ServicePrincipals.ContainsKey(_microsoft.SetupClientId));
        await AssertNoTokenStoredAsync(w);
    }

    [PostgresFact]
    public async Task Without_role_claims_a_refused_grant_removes_the_app_again()
    {
        var w = await WorldAsync();
        _microsoft.DirectoryRoles = null;
        _microsoft.ForbidGrants = true;
        var (run, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w));
        Assert.Equal(SetupRunState.Failed, run.State);
        Assert.Contains("removed the app", run.Message, StringComparison.Ordinal);
        Assert.Empty(_microsoft.Applications);
        Assert.Empty(await w.Tenants.ListAsync(w.Org, w.Customer));
    }

    [PostgresFact]
    public async Task Entra_replication_delay_is_retried_without_an_error()
    {
        var w = await WorldAsync();
        _microsoft.ReplicationDelays = 2;
        var (run, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w));
        Assert.True(run.State == SetupRunState.Succeeded, run.Message);
        Assert.Equal(0, _microsoft.ReplicationDelays);
        Assert.Single(await w.Tenants.ListAsync(w.Org, w.Customer));
    }

    [PostgresTheory]
    [InlineData("POST /graph/v1.0/applications")]
    [InlineData("POST /graph/v1.0/servicePrincipals")]
    [InlineData("GET /graph/v1.0/servicePrincipals/")]
    [InlineData("POST /graph/v1.0/servicePrincipals/{graph}/appRoleAssignedTo")]
    [InlineData("GET /graph/v1.0/servicePrincipals(appId='00000003")]
    public async Task An_interruption_at_any_step_resumes_with_a_new_sign_in_and_one_app_registration(string failingCall)
    {
        var w = await WorldAsync();
        var pending = await PendingAsync(w);
        _microsoft.FailOnce = failingCall.Replace("{graph}", _microsoft.GraphServicePrincipalId.ToString(), StringComparison.Ordinal);
        var (first, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, pending);
        Assert.Equal(SetupRunState.Failed, first.State);
        Assert.Contains("Sign in again", first.Message, StringComparison.Ordinal);
        Assert.Null(_microsoft.FailOnce);
        Assert.True(_microsoft.Applications.Count <= 1);

        var (second, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, pending);
        Assert.True(second.State == SetupRunState.Succeeded, second.Message);
        var app = Assert.Single(_microsoft.Applications.Values);
        Assert.Equal(app["appId"]!.GetValue<string>(), Assert.Single(await w.Tenants.ListAsync(w.Org, w.Customer)).ClientId.ToString());
        Assert.Equal(_microsoft.ApplicationRoles.Values.ToHashSet(), _microsoft.Assignments[_microsoft.ServicePrincipals[Guid.Parse(app["appId"]!.GetValue<string>())]]);
    }

    [PostgresFact]
    public async Task An_existing_app_named_Vaulty_stops_the_set_up_with_an_explanation()
    {
        var w = await WorldAsync();
        var other = Guid.NewGuid();
        _microsoft.Applications[other] = new JsonObject { ["id"] = other.ToString(), ["appId"] = Guid.NewGuid().ToString(), ["displayName"] = "Vaulty", ["keyCredentials"] = new JsonArray() };
        var (run, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w));
        Assert.Equal(SetupRunState.Failed, run.State);
        Assert.Contains("already exists", run.Message, StringComparison.Ordinal);
        Assert.Single(_microsoft.Applications);
    }

    [PostgresFact]
    public async Task Back_up_only_grants_no_restore_permission()
    {
        var w = await WorldAsync();
        var (run, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w, includeRestore: false), includeRestore: false);
        Assert.True(run.State == SetupRunState.Succeeded, run.Message);
        var app = Assert.Single(_microsoft.Applications.Values);
        var granted = _microsoft.Assignments[_microsoft.ServicePrincipals[Guid.Parse(app["appId"]!.GetValue<string>())]];
        Assert.Equal(GraphPermissions.All.Where(p => !p.ForRestore).Select(p => _microsoft.ApplicationRoles[p.Name]).ToHashSet(), granted);
    }

    [PostgresFact]
    public async Task Repair_creates_a_removed_app_again_with_the_tenant_certificate_and_records_its_object_id()
    {
        var w = await WorldAsync();
        var (connected, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w));
        var tenantId = connected.TenantId!.Value;
        // Someone deletes the app in Entra.
        _microsoft.Applications.Clear();
        _microsoft.ServicePrincipals[_microsoft.SetupClientId] = Guid.NewGuid();

        var (repaired, _) = await SignInAndRunAsync(w, SignInPurpose.Repair, tenantId);
        Assert.True(repaired.State == SetupRunState.Succeeded, repaired.Message);
        var app = Assert.Single(_microsoft.Applications.Values);
        var tenant = Assert.Single(await w.Tenants.ListAsync(w.Org, w.Customer));
        Assert.Equal((app["appId"]!.GetValue<string>(), (Guid?)Guid.Parse(app["id"]!.GetValue<string>())), (tenant.ClientId.ToString(), tenant.ApplicationObjectId));
        w.Credentials.Invalidate(tenantId);
        Assert.True(_microsoft.Accepts(tenant.ClientId!.Value, (await w.Credentials.GetAsync(tenantId)).Certificate));

        // A repair of a tenant in another Microsoft 365 tenant than the sign-in is refused.
        _microsoft.TenantId = Guid.NewGuid();
        var (wrongTenant, _) = await SignInAndRunAsync(w, SignInPurpose.Repair, tenantId);
        Assert.Equal(SetupRunState.Failed, wrongTenant.State);
        Assert.Contains("Sign in with an account of that tenant", wrongTenant.Message, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task Rotation_adds_the_new_key_itself_and_removes_the_old_one_only_after_the_new_one_works()
    {
        var w = await WorldAsync();
        var (connected, _) = await SignInAndRunAsync(w, SignInPurpose.Connect, await PendingAsync(w));
        var tenantId = connected.TenantId!.Value;
        var app = Assert.Single(_microsoft.Applications.Values);
        var appId = Guid.Parse(app["appId"]!.GetValue<string>());
        var before = (await w.Credentials.GetAsync(tenantId)).Certificate.Thumbprint;

        // A refused addKey keeps the current certificate and offers the script.
        _microsoft.RefuseAddKey = true;
        var rotation = new CertificateRotation(w.Api, w.Secrets, w.Credentials, w.Graph, w.Registrations, new SimulatedVerifier(_microsoft), TimeProvider.System,
            new CapturingLogger<CertificateRotation>()) { VerifyAttempts = 1 };
        var refused = await rotation.RotateAsync(w.Org, "test", tenantId);
        Assert.False(refused.Rotated);
        Assert.NotNull(refused.FallbackScript);
        w.Credentials.Invalidate(tenantId);
        Assert.Equal(before, (await w.Credentials.GetAsync(tenantId)).Certificate.Thumbprint);
        Assert.Single(MicrosoftSimulator.Keys(app));

        // Allowed: the new key is added with a proof from the current certificate, switched to, and the old key removed.
        _microsoft.RefuseAddKey = false;
        var outcome = await rotation.RotateAsync(w.Org, "test", tenantId);
        Assert.True(outcome.Rotated, outcome.Message);
        Assert.True(outcome.OldKeyRemoved, outcome.Message);
        w.Credentials.Invalidate(tenantId);
        var after = (await w.Credentials.GetAsync(tenantId)).Certificate;
        Assert.NotEqual(before, after.Thumbprint);
        Assert.Equal(after.Thumbprint, Assert.Single(MicrosoftSimulator.Keys(app))["customKeyIdentifier"]!.GetValue<string>());
        Assert.True(_microsoft.Accepts(appId, after));
        var row = Assert.Single(await w.Tenants.ListAsync(w.Org, w.Customer));
        Assert.Null(row.NextCertificateExpiresAt);

        // A tenant whose new key never signs in keeps its current certificate.
        var stubborn = new CertificateRotation(w.Api, w.Secrets, w.Credentials, w.Graph, w.Registrations, new NeverVerifier(), TimeProvider.System,
            new CapturingLogger<CertificateRotation>()) { VerifyAttempts = 1 };
        var notYet = await stubborn.RotateAsync(w.Org, "test", tenantId);
        Assert.False(notYet.Rotated);
        w.Credentials.Invalidate(tenantId);
        Assert.Equal(after.Thumbprint, (await w.Credentials.GetAsync(tenantId)).Certificate.Thumbprint);
    }

    private sealed class NeverVerifier : ICredentialVerifier
    {
        public Task VerifyAsync(GraphCredential credential, CancellationToken cancellationToken = default) =>
            throw new IdentityException("invalid_client", "AADSTS700027");
    }

    [PostgresFact]
    public async Task The_setup_assistant_checks_the_certificate_and_names_each_wrong_setting()
    {
        var w = await WorldAsync(readySetup: false);
        // Its own platform settings: a separate database row would be shared, so this test uses a fresh key set on a copy.
        var settings = new PlatformSettings(w.Api);
        await settings.SetAsync(SetupAppSettings.SettingKey, new SetupAppSettings(), "test");
        var setup = await w.Setup.CreateCertificateAsync("test");
        var publicCertificate = await w.Setup.PublicCertificateAsync();
        _microsoft.SetupCertificate = X509CertificateLoader.LoadCertificate(publicCertificate!);
        var home = Guid.NewGuid();
        var clientId = Guid.NewGuid();
        _microsoft.SetupClientId = clientId;

        var saved = await w.Setup.SaveIdsAsync(clientId, home, "test");
        Assert.True(saved.CredentialWorks, saved.CredentialDetail);
        Assert.False(saved.Ready);

        // The registration as someone made it: single tenant, wrong redirect URI, a client secret, an application permission.
        var objectId = Guid.NewGuid();
        _microsoft.Applications[objectId] = new JsonObject
        {
            ["id"] = objectId.ToString(), ["appId"] = clientId.ToString(), ["displayName"] = "Vaulty setup", ["signInAudience"] = "AzureADMyOrg",
            ["web"] = new JsonObject { ["redirectUris"] = new JsonArray("https://other.example.com/callback") },
            ["passwordCredentials"] = new JsonArray(new JsonObject { ["keyId"] = Guid.NewGuid().ToString() }),
            ["requiredResourceAccess"] = new JsonArray(new JsonObject
            {
                ["resourceAppId"] = OnboardingScript.GraphAppId,
                ["resourceAccess"] = new JsonArray(
                    new JsonObject { ["id"] = _microsoft.DelegatedScopes["Application.ReadWrite.All"].ToString(), ["type"] = "Scope" },
                    new JsonObject { ["id"] = _microsoft.ApplicationRoles["User.Read.All"].ToString(), ["type"] = "Role" }),
            }),
            ["keyCredentials"] = new JsonArray(new JsonObject { ["key"] = Convert.ToBase64String(publicCertificate!), ["keyId"] = Guid.NewGuid().ToString(),
                ["customKeyIdentifier"] = setup.CertificateThumbprint }),
        };
        _microsoft.TenantId = home;
        var (run, _) = await SignInAndRunAsync(w, SignInPurpose.SetupCheck, Guid.Empty);
        Assert.Equal(SetupRunState.Succeeded, run.State);
        var checks = (await w.Setup.GetAsync()).RegistrationChecks.ToDictionary(c => c.Name);
        Assert.False(checks["Accounts in any organizational directory"].Passed);
        Assert.False(checks["Redirect URI"].Passed);
        Assert.Contains(Redirect.ToString(), checks["Redirect URI"].Detail, StringComparison.Ordinal);
        Assert.False(checks["Delegated permissions"].Passed);
        Assert.Contains("AppRoleAssignment.ReadWrite.All", checks["Delegated permissions"].Detail, StringComparison.Ordinal);
        Assert.False(checks["No application permissions"].Passed);
        Assert.False(checks["No secret"].Passed);
        Assert.True(checks["Certificate"].Passed);
        Assert.True(checks["Directory roles in the token"].Passed);
        Assert.False((await w.Setup.GetAsync()).Ready);
        // Not ready: a connection from the browser cannot start.
        await Assert.ThrowsAsync<TenantException>(() => w.Connection.BeginAsync(SignInPurpose.Connect, w.Org, w.Admin, Guid.NewGuid(), Redirect, "/x", true));

        // Fixed in Entra: every required check passes and the object id is known (for renewing the certificate).
        var app = _microsoft.Applications[objectId];
        app["signInAudience"] = "AzureADMultipleOrgs";
        app["web"] = new JsonObject { ["redirectUris"] = new JsonArray(Redirect.ToString()) };
        app["passwordCredentials"] = new JsonArray();
        app["requiredResourceAccess"] = new JsonArray(new JsonObject
        {
            ["resourceAppId"] = OnboardingScript.GraphAppId,
            ["resourceAccess"] = new JsonArray(
                new JsonObject { ["id"] = _microsoft.DelegatedScopes["Application.ReadWrite.All"].ToString(), ["type"] = "Scope" },
                new JsonObject { ["id"] = _microsoft.DelegatedScopes["AppRoleAssignment.ReadWrite.All"].ToString(), ["type"] = "Scope" }),
        });
        await SignInAndRunAsync(w, SignInPurpose.SetupCheck, Guid.Empty);
        var ready = await w.Setup.GetAsync();
        Assert.True(ready.Ready, string.Join("; ", ready.RegistrationChecks.Where(c => !c.Passed).Select(c => c.Detail)));
        Assert.Equal(objectId, ready.ApplicationObjectId);

        // A wrong certificate (another one uploaded) fails check 1 with a plain message.
        _microsoft.SetupCertificate = X509CertificateLoader.LoadCertificate(TenantCertificate.Create("other").PublicCertificate);
        var wrong = await w.Setup.TestCredentialAsync("test");
        Assert.False(wrong.CredentialWorks);
        Assert.Contains("certificate", wrong.CredentialDetail, StringComparison.OrdinalIgnoreCase);
        await settings.SetAsync(SetupAppSettings.SettingKey, new SetupAppSettings(), "test");
    }

    public void Dispose()
    {
        _microsoft.Dispose();
        _http.Dispose();
    }
}
