using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Microsoft.Extensions.Time.Testing;
using Microsoft.Identity.Client;
using Npgsql;
using Vaulty.Core.Crypto;
using Vaulty.Graph;
using Vaulty.Graph.Auth;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Integration.Tests.Database;
using WireMock;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Types;
using WireMock.Util;

namespace Vaulty.Integration.Tests.Tenants;

/// <summary>A token provider whose behaviour the test sets: roles, or an exception.</summary>
internal sealed class ScriptedTokens : IGraphTokenProvider
{
    public Func<GraphToken> Next { get; set; } = () => Token(GraphPermissions.All.Select(p => p.Name).ToArray());

    public static GraphToken Token(params string[] roles)
    {
        static string B64(string s) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return new GraphToken($"{B64("{}")}.{B64(JsonSerializer.Serialize(new { roles }))}.x", DateTimeOffset.UtcNow.AddHours(1));
    }

    public Task<GraphToken> GetTokenAsync(Guid tenantId, bool forceRefresh = false, CancellationToken cancellationToken = default) =>
        Task.FromResult(Next());
}

public sealed class TenantTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>, IDisposable
{
    private readonly WireMockServer _graph = WireMockServer.Start();

    private async Task<(Guid Org, Guid Customer, Guid Admin, NpgsqlDataSource Api, PostgresSecretStore Secrets)> OrganizationAsync()
    {
        var api = VaultyDataSource.Create(db.Api);
        var adminId = Guid.NewGuid();
        var access = new AccessService(api);
        var org = await new OrganizationSetup(api, access).CreateOrganizationAsync("Org " + adminId, adminId);
        var customer = await new CustomerService(api).CreateAsync(org, adminId, "C" + adminId.ToString("N")[..6], "Contoso", ["gold"]);
        var secrets = new PostgresSecretStore(api, new SecretCipher(RandomNumberGenerator.GetBytes(32), "host-a"), TimeProvider.System, TimeSpan.Zero);
        return (org, customer, adminId, api, secrets);
    }

    private TenantService Tenants(NpgsqlDataSource api, PostgresSecretStore secrets, IGraphTokenProvider? tokens = null) =>
        new(api, secrets, new DedicatedAppCredentialProvider(api, secrets, TimeProvider.System),
            new GraphServices(tokens ?? new ScriptedTokens(), graphBaseUri: new Uri($"{_graph.Url}/v1.0/")), TimeProvider.System);

    [PostgresFact]
    public async Task The_customer_list_shows_code_name_tags_and_tenant_count_and_is_empty_for_a_new_organization()
    {
        var (org, customer, admin, api, secrets) = await OrganizationAsync();
        var customers = new CustomerService(api);
        var row = Assert.Single(await customers.ListAsync(org));
        Assert.Equal((customer, "Contoso", 0), (row.Id, row.Name, row.Tenants));
        Assert.Equal(["gold"], row.Tags);

        var tenants = Tenants(api, secrets);
        var pending = await tenants.BeginConnectAsync(org, admin, customer, "Contoso tenant");
        await tenants.CompleteConnectAsync(org, admin, pending.Id, Guid.NewGuid(), Guid.NewGuid());
        Assert.Equal(1, Assert.Single(await customers.ListAsync(org)).Tenants);

        var empty = await new OrganizationSetup(api, new AccessService(api)).CreateOrganizationAsync("Empty " + Guid.NewGuid(), Guid.NewGuid());
        Assert.Empty(await customers.ListAsync(empty));
    }

    [PostgresFact]
    public async Task A_tenant_without_backups_is_removed_at_once_and_its_Microsoft_365_tenant_can_be_connected_again()
    {
        var (org, customer, admin, api, secrets) = await OrganizationAsync();
        var tenants = Tenants(api, secrets);
        var entra = Guid.NewGuid();
        var first = await tenants.CompleteConnectAsync(org, admin, (await tenants.BeginConnectAsync(org, admin, customer, "Wrong")).Id, entra, Guid.NewGuid());
        var deletion = new Vaulty.Infrastructure.Retention.TenantDeletion(api, TimeProvider.System);
        var access = new UserAccess(admin, org, true, Vaulty.Core.Security.Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));

        Assert.False((await deletion.StateAsync(access, first)).HoldsBackups);
        await Assert.ThrowsAsync<Vaulty.Infrastructure.Restore.StepUpRequiredException>(() => deletion.RemoveUnusedAsync(access, false, first));
        var readOnly = new UserAccess(Guid.NewGuid(), org, true, new Dictionary<string, HashSet<Guid>?> { [Vaulty.Core.Security.Permissions.CustomersView] = null });
        await Assert.ThrowsAsync<AccessException>(() => deletion.RemoveUnusedAsync(readOnly, true, first));
        // Also after a deletion was requested: no 30-day wait for a tenant that protects nothing.
        await deletion.RequestAsync(access, true, first);
        await deletion.RemoveUnusedAsync(access, true, first);
        Assert.DoesNotContain(await tenants.ListAsync(org, customer), t => t.Id == first);

        // The same Microsoft 365 tenant connects again.
        var second = await tenants.CompleteConnectAsync(org, admin, (await tenants.BeginConnectAsync(org, admin, customer, "Right")).Id, entra, Guid.NewGuid());
        Assert.Equal(second, Assert.Single(await tenants.ListAsync(org, customer)).Id);
        await using var owner = new NpgsqlConnection(db.Migrator);
        Assert.Equal(["tenant.connected", "tenant.deletion_requested", "tenant.removed_without_backups"], (await owner.QueryAsync<string>(
            "SELECT action FROM vaulty.audit_events WHERE target = @target ORDER BY seq", new { target = $"tenant:{first}" })).ToList());
    }

    [PostgresFact]
    public async Task The_tenant_id_and_application_id_of_a_tenant_without_backups_can_be_corrected()
    {
        var (org, customer, admin, api, secrets) = await OrganizationAsync();
        var tenants = Tenants(api, secrets);
        var tenantId = await tenants.CompleteConnectAsync(org, admin, (await tenants.BeginConnectAsync(org, admin, customer, "Contoso")).Id, Guid.NewGuid(), Guid.NewGuid());
        var (entra, client) = (Guid.NewGuid(), Guid.NewGuid());
        await tenants.CorrectConnectionAsync(org, admin, tenantId, entra, client);
        var row = Assert.Single(await tenants.ListAsync(org, customer));
        Assert.Equal((entra, (Guid?)client, "pending"), (row.EntraTenantId, row.ClientId, row.ConsentState));

        // A tenant id that another tenant uses is refused.
        var other = Guid.NewGuid();
        await tenants.CompleteConnectAsync(org, admin, (await tenants.BeginConnectAsync(org, admin, customer, "Fabrikam")).Id, other, Guid.NewGuid());
        var taken = await Assert.ThrowsAsync<TenantException>(() => tenants.CorrectConnectionAsync(org, admin, tenantId, other, client));
        Assert.Contains("already connected", taken.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<TenantException>(() => tenants.CorrectConnectionAsync(org, admin, tenantId, Guid.Empty, client));
    }

    [PostgresFact]
    public async Task Connecting_stores_the_certificate_and_refuses_a_tenant_connected_elsewhere()
    {
        var (org, customer, admin, api, secrets) = await OrganizationAsync();
        var tenants = Tenants(api, secrets);
        var pending = await tenants.BeginConnectAsync(org, admin, customer, "Contoso tenant");
        Assert.Contains("New-MgApplication", pending.Script, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", pending.Script, StringComparison.Ordinal);
        var entra = Guid.NewGuid();
        var tenantId = await tenants.CompleteConnectAsync(org, admin, pending.Id, entra, Guid.NewGuid());

        using (var certificate = await secrets.GetAsync(TenantService.CertificateSecret(tenantId)))
        using (var x509 = TenantCertificate.Load(certificate!.Reveal()))
        {
            Assert.True(x509.HasPrivateKey);
            Assert.Equal(pending.CertificateThumbprint, x509.Thumbprint);
        }
        var row = Assert.Single(await tenants.ListAsync(org, customer));
        Assert.Equal("pending", row.ConsentState);

        // Completing twice or connecting the same Microsoft 365 tenant from another organization is refused.
        await Assert.ThrowsAsync<TenantException>(() => tenants.CompleteConnectAsync(org, admin, pending.Id, entra, Guid.NewGuid()));
        var (org2, customer2, admin2, api2, secrets2) = await OrganizationAsync();
        var other = Tenants(api2, secrets2);
        var pending2 = await other.BeginConnectAsync(org2, admin2, customer2, "Same tenant");
        var refused = await Assert.ThrowsAsync<TenantException>(() => other.CompleteConnectAsync(org2, admin2, pending2.Id, entra, Guid.NewGuid()));
        Assert.Contains("already connected", refused.Message, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task Lost_consent_is_detected_recorded_and_audited_and_recovers()
    {
        var (org, customer, admin, api, secrets) = await OrganizationAsync();
        var tenants = Tenants(api, secrets);
        var pending = await tenants.BeginConnectAsync(org, admin, customer, "Health tenant");
        var tenantId = await tenants.CompleteConnectAsync(org, admin, pending.Id, Guid.NewGuid(), Guid.NewGuid());
        var tokens = new ScriptedTokens();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var health = new TenantHealthCheck(api, tokens, clock);

        Assert.Equal(HealthOutcome.Healthy, (await health.CheckAsync(org, tenantId)).Outcome);
        Assert.Equal("granted", Assert.Single(await tenants.ListAsync(org, customer)).ConsentState);

        // The administrator disables the app in Entra.
        tokens.Next = () => throw new MsalServiceException("unauthorized_client",
            "AADSTS7000112: Application 'x' is disabled.");
        var lost = await health.CheckAsync(org, tenantId);
        Assert.Equal(HealthOutcome.ConsentLost, lost.Outcome);
        Assert.True(lost.BecameLost);
        Assert.Equal("lost", Assert.Single(await tenants.ListAsync(org, customer)).ConsentState);
        Assert.False((await health.CheckAsync(org, tenantId)).BecameLost); // alerted once, not every hour

        // A network failure does not flip the state either way.
        tokens.Next = () => throw new HttpRequestException("no route");
        Assert.Equal(HealthOutcome.Unknown, (await health.CheckAsync(org, tenantId)).Outcome);
        Assert.Equal("lost", Assert.Single(await tenants.ListAsync(org, customer)).ConsentState);

        // Permissions removed is lost too; restored is granted again.
        tokens.Next = () => ScriptedTokens.Token("User.Read.All");
        Assert.Equal(HealthOutcome.ConsentLost, (await health.CheckAsync(org, tenantId)).Outcome);
        tokens.Next = () => ScriptedTokens.Token(GraphPermissions.All.Select(p => p.Name).ToArray());
        Assert.Equal(HealthOutcome.Healthy, (await health.CheckAsync(org, tenantId)).Outcome);

        // An expired certificate is lost without asking Microsoft.
        clock.Advance(TimeSpan.FromDays(800));
        Assert.Equal(HealthOutcome.ConsentLost, (await health.CheckAsync(org, tenantId)).Outcome);

        await using var owner = new NpgsqlConnection(db.Migrator);
        var actions = (await owner.QueryAsync<string>(
            "SELECT action FROM vaulty.audit_events WHERE organization_id = @org AND target = @target ORDER BY seq",
            new { org, target = $"tenant:{tenantId}" })).ToList();
        Assert.Equal(2, actions.Count(a => a == "tenant.consent_lost"));
        Assert.Contains("tenant.consent_restored", actions);
        Assert.Contains("tenant.connected", actions);
    }

    [PostgresFact]
    public async Task Discovery_is_idempotent_and_marks_vanished_objects_as_source_deleted()
    {
        var (org, customer, admin, api, secrets) = await OrganizationAsync();
        var tenants = Tenants(api, secrets);
        var pending = await tenants.BeginConnectAsync(org, admin, customer, "Discovery tenant");
        var tenantId = await tenants.CompleteConnectAsync(org, admin, pending.Id, Guid.NewGuid(), Guid.NewGuid());
        var users = new List<string> { "u1", "u2", "u3", "room1" };
        MockDirectory(() => users);
        var graph = new GraphClient(GraphPipeline.Create(new ScriptedTokens(), new Graph.Http.GraphThrottle()), new Uri($"{_graph.Url}/v1.0/"));
        var discovery = new TenantDiscovery(api, graph, TimeProvider.System);

        var first = await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        Assert.Equal((2, 1, 1, 2), (first.Mailboxes, first.SharedMailboxes, first.ResourceMailboxes, first.Drives));
        var objects = await tenants.ProtectedObjectsAsync(org, tenantId);
        Assert.Equal(7, objects.Count); // 4 mailboxes (u2 shared), 2 drives, 1 archive
        Assert.Contains(objects, o => o.SubKind == "shared");
        Assert.Single(objects, o => o.State == "not_protected"); // the archive mailbox of u1

        // Second run: nothing changes.
        await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        var again = await tenants.ProtectedObjectsAsync(org, tenantId);
        Assert.Equal(objects.Select(o => (o.Id, o.State)), again.Select(o => (o.Id, o.State)));

        // u3 leaves the company: its mailbox and OneDrive become source deleted, with a date.
        users.Remove("u3");
        var third = await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        Assert.Equal(2, third.SourceDeleted);
        var afterDelete = await tenants.ProtectedObjectsAsync(org, tenantId);
        Assert.Equal(2, afterDelete.Count(o => o.State == "source_deleted" && o.SourceDeletedAt is not null));
        Assert.Equal(7, afterDelete.Count); // kept, not removed

        // u3 is restored in Microsoft 365: active again.
        users.Add("u3");
        var fourth = await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        Assert.Equal(2, fourth.Reappeared);
        Assert.DoesNotContain(await tenants.ProtectedObjectsAsync(org, tenantId), o => o.State == "source_deleted");
    }

    [Fact]
    public void The_data_of_an_object_without_further_backups_goes_after_retention_and_never_before_its_lock_ends()
    {
        var newest = new DateTimeOffset(2026, 11, 11, 10, 0, 0, TimeSpan.Zero);
        ProtectedObjectRow Row(DateTimeOffset? lockedUntil) => new(Guid.NewGuid(), "mailbox", "user", "m1", "Finance", "excluded", null, newest, "committed", "{}",
            newest, lockedUntil);
        Assert.Equal(newest.AddDays(90), Row(newest.AddDays(60)).DataRemovedFrom(90));
        Assert.Equal(newest.AddDays(120), Row(newest.AddDays(120)).DataRemovedFrom(90));
        Assert.Null((Row(null) with { NewestSnapshotAt = null }).DataRemovedFrom(90));
    }

    [PostgresFact]
    public async Task Found_objects_wait_to_be_selected_and_excluding_needs_a_fresh_confirmation()
    {
        var (org, customer, admin, api, secrets) = await OrganizationAsync();
        var tenants = Tenants(api, secrets);
        var tenantId = await tenants.CompleteConnectAsync(org, admin, (await tenants.BeginConnectAsync(org, admin, customer, "Selection tenant")).Id,
            Guid.NewGuid(), Guid.NewGuid());
        var users = new List<string> { "u1", "u2", "u3", "room1" };
        MockDirectory(() => users);
        var graph = new GraphClient(GraphPipeline.Create(new ScriptedTokens(), new Graph.Http.GraphThrottle()), new Uri($"{_graph.Url}/v1.0/"));
        var discovery = new TenantDiscovery(api, graph, TimeProvider.System);
        var selection = new BackupSelection(api, TimeProvider.System);
        var access = new UserAccess(admin, org, true, Vaulty.Core.Security.Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));
        await using var owner = new NpgsqlConnection(db.Migrator);
        const string Due = "SELECT count(*) FROM vaulty.due_protected_objects(now() + interval '1 day', 1000) WHERE tenant_id = @tenantId";
        // The scheduler only plans for tenants whose consent is granted.
        await owner.ExecuteAsync("UPDATE vaulty.tenants SET consent_state = 'granted' WHERE id = @tenantId", new { tenantId });

        // By default nothing found is backed up until it is selected; nothing is due.
        Assert.False(await selection.ProtectsNewObjectsAsync(access, tenantId));
        var found = await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        Assert.Equal(6, found.NotSelected);
        var objects = await tenants.ProtectedObjectsAsync(org, tenantId);
        Assert.Equal(6, objects.Count(o => o.State == "excluded"));
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>(Due, new { tenantId }));

        // Selecting the mailboxes makes them due at once; no confirmation is needed to add protection.
        var mailboxes = objects.Where(o => o.Kind == "mailbox" && o.State == "excluded").Select(o => o.Id).ToList();
        Assert.Equal(4, await selection.SetAsync(access, false, tenantId, mailboxes, include: true));
        Assert.Equal(4, await owner.ExecuteScalarAsync<int>(Due, new { tenantId }));

        // Excluding lowers protection: only with a fresh step-up, and audited.
        await Assert.ThrowsAsync<Vaulty.Infrastructure.Restore.StepUpRequiredException>(() => selection.SetAsync(access, false, tenantId, mailboxes.Take(1).ToList(), false));
        // The first mailbox has a failed backup alert and a backup running.
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.alerts (id, organization_id, tenant_id, protected_object_id, kind, severity, message)
                VALUES (gen_random_uuid(), @org, @tenantId, @o, 'backup.failed', 'critical', 'Backup failed; Vaulty retries at the next run.');
            INSERT INTO vaulty.jobs (id, organization_id, kind, tenant_id, protected_object_id, state, started_at, workflow_id, workflow_run_id)
                VALUES (gen_random_uuid(), @org, 'backup', @tenantId, @o, 'running', now(), 'backup-excluded', 'run-x');
            """, new { org, tenantId, o = mailboxes[0] });
        Assert.Empty(await selection.RunningBackupsToStopAsync(access, tenantId, mailboxes.Take(1).ToList())); // still selected: nothing to stop
        Assert.Equal(1, await selection.SetAsync(access, true, tenantId, mailboxes.Take(1).ToList(), include: false));
        // Excluded: its backup alerts are settled, and its running backup is the one to stop.
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.alerts WHERE protected_object_id = @o AND resolved_at IS NULL",
            new { o = mailboxes[0] }));
        Assert.Equal([("backup-excluded", (string?)"run-x")], await selection.RunningBackupsToStopAsync(access, tenantId, mailboxes.Take(1).ToList()));
        await owner.ExecuteAsync("UPDATE vaulty.jobs SET state = 'cancelled' WHERE protected_object_id = @o", new { o = mailboxes[0] });
        Assert.Equal(3, await owner.ExecuteScalarAsync<int>(Due, new { tenantId }));
        var readOnly = new UserAccess(Guid.NewGuid(), org, true, new Dictionary<string, HashSet<Guid>?> { [Vaulty.Core.Security.Permissions.CustomersView] = null });
        await Assert.ThrowsAsync<AccessException>(() => selection.SetAsync(readOnly, true, tenantId, mailboxes, true));
        Assert.Equal(["backup.objects_selected", "backup.objects_excluded"], (await owner.QueryAsync<string>(
            "SELECT action FROM vaulty.audit_events WHERE target = @target AND action LIKE 'backup.%' ORDER BY seq", new { target = $"tenant:{tenantId}" })).ToList());

        // With "back up new ones automatically", a new colleague is protected at once; turning that off needs a step-up.
        await selection.SetProtectNewObjectsAsync(access, false, tenantId, true);
        users.Add("u4");
        await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        Assert.All((await tenants.ProtectedObjectsAsync(org, tenantId)).Where(o => o.SourceId.Contains("u4", StringComparison.Ordinal)),
            o => Assert.Equal("active", o.State));
        await Assert.ThrowsAsync<Vaulty.Infrastructure.Restore.StepUpRequiredException>(() => selection.SetProtectNewObjectsAsync(access, false, tenantId, false));
        await selection.SetProtectNewObjectsAsync(access, true, tenantId, false);

        // An object that was backed up and comes back after it vanished stays selected, whatever the tenant's choice.
        var u1Mailbox = (await tenants.ProtectedObjectsAsync(org, tenantId)).First(o => o.Kind == "mailbox" && o.State == "active");
        await owner.ExecuteAsync("UPDATE vaulty.protected_objects SET last_snapshot_id = @s WHERE id = @id", new { s = Guid.NewGuid(), id = u1Mailbox.Id });
        var vanished = users.Single(u => u1Mailbox.SourceId.Contains(u, StringComparison.Ordinal) || u1Mailbox.DisplayName.Contains(u, StringComparison.Ordinal));
        users.Remove(vanished);
        await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        users.Add(vanished);
        await discovery.ApplyAsync(org, tenantId, await discovery.FindAsync(tenantId));
        Assert.Equal("active", (await tenants.ProtectedObjectsAsync(org, tenantId)).Single(o => o.Id == u1Mailbox.Id).State);
    }

    /// <summary>Users and per-user batch answers: u2 is a shared mailbox (no OneDrive), room1 a room, u1 has an archive.</summary>
    private void MockDirectory(Func<List<string>> users)
    {
        _graph.Given(Request.Create().WithPath("/v1.0/users").UsingGet()).RespondWith(Response.Create().WithCallback(_ => Json(new JsonObject
        {
            ["value"] = new JsonArray(users().Select(u => (JsonNode)new JsonObject
            {
                ["id"] = u, ["displayName"] = u.ToUpperInvariant(), ["userPrincipalName"] = $"{u}@contoso.example",
                ["mail"] = $"{u}@contoso.example", ["userType"] = "Member",
            }).ToArray()),
        })));
        _graph.Given(Request.Create().WithPath("/v1.0/$batch").UsingPost()).RespondWith(Response.Create().WithCallback(request =>
        {
            var body = JsonNode.Parse(request.Body!)!["requests"]!.AsArray();
            var responses = new JsonArray();
            foreach (var item in body)
            {
                var id = item!["id"]!.GetValue<string>();
                var user = id.Split('|')[0];
                var what = id.Split('|')[1];
                JsonObject answer = what switch
                {
                    "purpose" => Ok(new JsonObject { ["userPurpose"] = user == "u2" ? "shared" : user == "room1" ? "room" : "user" }),
                    "exchange" => Ok(user == "u1"
                        ? new JsonObject { ["primaryMailboxId"] = $"MBX:{user}", ["archiveMailboxId"] = $"MBX:{user}-archive" }
                        : new JsonObject { ["primaryMailboxId"] = $"MBX:{user}" }),
                    _ => user is "u2" or "room1"
                        ? new JsonObject { ["status"] = 404, ["body"] = new JsonObject { ["error"] = new JsonObject { ["code"] = "ResourceNotFound" } } }
                        : Ok(new JsonObject { ["id"] = $"drive-{user}", ["driveType"] = "business" }),
                };
                answer["id"] = id;
                responses.Add(answer);
            }
            return Json(new JsonObject { ["responses"] = responses });
        }));

        static JsonObject Ok(JsonObject body) => new() { ["status"] = 200, ["body"] = body };
    }

    private static ResponseMessage Json(JsonNode node) => new()
    {
        StatusCode = 200,
        Headers = new Dictionary<string, WireMockList<string>> { ["Content-Type"] = new("application/json") },
        BodyData = new BodyData { BodyAsString = node.ToJsonString(), DetectedBodyType = BodyType.String },
    };

    public void Dispose() => _graph.Dispose();
}
