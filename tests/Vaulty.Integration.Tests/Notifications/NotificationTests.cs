using Vaulty.Core.Domain;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Notifications;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Notifications;
using Vaulty.Infrastructure.Platform;
using Vaulty.Infrastructure.Reporting;
using Vaulty.Infrastructure.Storage;
using Vaulty.Infrastructure.Web;
using Vaulty.Integration.Tests.Database;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Vaulty.Integration.Tests.Notifications;

internal sealed class MemorySecretStore : ISecretStore
{
    private readonly ConcurrentDictionary<string, List<byte[]>> _values = new(StringComparer.Ordinal);

    public Task<Secret?> GetAsync(string name, CancellationToken cancellationToken = default) =>
        Task.FromResult(_values.TryGetValue(name, out var v) ? new Secret(name, v.Count, v[^1]) : null);

    public Task<Secret?> GetAsync(string name, int version, CancellationToken cancellationToken = default) =>
        Task.FromResult(_values.TryGetValue(name, out var v) && version >= 1 && version <= v.Count ? new Secret(name, version, v[version - 1]) : null);

    public Task<int> SetAsync(string name, ReadOnlyMemory<byte> value, string actor, CancellationToken cancellationToken = default)
    {
        var list = _values.GetOrAdd(name, _ => []);
        lock (list) list.Add(value.ToArray());
        return Task.FromResult(list.Count);
    }

    public Task<int> PruneAsync(string name, int keep, CancellationToken cancellationToken = default) => Task.FromResult(0);

    public Task<IReadOnlyList<SecretInfo>> ListAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<SecretInfo>>(_values.Select(v => new SecretInfo(v.Key, v.Value.Count, DateTimeOffset.UtcNow, "test")).ToList());
}

internal sealed class RecordingMailSender : IMailSender
{
    public ConcurrentQueue<MailMessage> Sent { get; } = new();

    public Task SendAsync(MailMessage message, CancellationToken cancellationToken = default)
    {
        Sent.Enqueue(message);
        return Task.CompletedTask;
    }
}

/// <summary>
/// What a customer's webhook receiver does: verify the signature over the raw body, reject a stale timestamp, and drop a
/// delivery id it has seen before. Kept deliberately small, as the example in the documentation.
/// </summary>
internal sealed class SampleReceiver(byte[] secret, TimeProvider clock)
{
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    public string Accept(IReadOnlyDictionary<string, string> headers, byte[] body)
    {
        if (!WebhookSignature.Verify(secret, headers.GetValueOrDefault(WebhookSignature.SignatureHeader), body, clock.GetUtcNow())) return "rejected: signature";
        var delivery = headers.GetValueOrDefault(WebhookSignature.DeliveryHeader) ?? "";
        if (!_seen.Add(delivery)) return "rejected: replay";
        return "accepted";
    }
}

internal sealed class NotificationSeed
{
    public Guid Org { get; } = Guid.NewGuid();
    public Guid Customer { get; } = Guid.NewGuid();
    public Guid Tenant { get; } = Guid.NewGuid();
    public Guid Object { get; } = Guid.NewGuid();
    public Guid User { get; } = Guid.NewGuid();

    public async Task SeedAsync(PostgresDatabase db, DateTimeOffset nextRunAt)
    {
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'O');
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C1', 'Contoso');
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name, consent_state, client_id)
                VALUES (@tenant, @org, @customer, @entra, 'Contoso tenant', 'granted', @client);
            INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name, next_run_at)
                VALUES (@object, @org, @tenant, 'mailbox', 'user', 'm1', 'Finance mailbox', @nextRunAt);
            INSERT INTO vaulty.users (id, organization_id, user_name, normalized_user_name, email, security_stamp, concurrency_stamp)
                VALUES (@user, @org, @name, upper(@name), @name, 's', 'c');
            INSERT INTO vaulty.roles (id, organization_id, name) VALUES (@role, @org, 'Reports');
            INSERT INTO vaulty.role_permissions (role_id, organization_id, permission) VALUES (@role, @org, 'reports.view');
            INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id) VALUES (@assignment, @org, @user, @role);
            """, new
            {
                org = Org, customer = Customer, tenant = Tenant, entra = Guid.NewGuid(), client = Guid.NewGuid(), @object = Object, nextRunAt, user = User,
                name = $"ops-{User:N}@example.com", role = Guid.NewGuid(), assignment = Guid.NewGuid(),
            });
    }
}

public sealed class NotificationTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static async Task ConfigureSmtpAsync(NpgsqlDataSource api)
    {
        await new PlatformSettings(api).SetAsync(SmtpSettings.SettingKey, new SmtpSettings("smtp.example.com", 587, "starttls", null, "vaulty@example.com", "Vaulty"), "test");
    }

    private NotificationDispatcher Dispatcher(NpgsqlDataSource worker, TimeProvider clock, IMailSender mail, ISecretStore secrets, IWebhookSender? webhooks = null) =>
        new(worker, webhooks ?? new WebhookSender(clock, new WebhookOptions { AllowPrivateTargets = true }), mail, secrets, new PlatformSettings(worker),
            new VaultyHostOptions { PublicHost = "vaulty.example.com" }, new DashboardService(worker, clock), clock, NullLogger<NotificationDispatcher>.Instance);

    [PostgresFact]
    public async Task A_missed_run_is_alerted_and_mailed_within_15_minutes()
    {
        var due = DateTimeOffset.UtcNow;
        var seed = new NotificationSeed();
        await seed.SeedAsync(db, due);
        await using var api = VaultyDataSource.Create(db.Api);
        await using var worker = VaultyDataSource.Create(db.Worker);
        await ConfigureSmtpAsync(api);
        var clock = new FakeTimeProvider(due);
        var mail = new RecordingMailSender();
        var dispatcher = Dispatcher(worker, clock, mail, new MemorySecretStore());

        // The sweep runs every minute; the first minute in which the alert exists and its mail went out.
        TimeSpan? alerted = null;
        for (var minute = 0; minute <= 15 && alerted is null; minute++)
        {
            clock.SetUtcNow(due.AddMinutes(minute));
            await dispatcher.FindMissedRunsAsync();
            await dispatcher.FanOutEventsAsync();
            await dispatcher.MailAlertsAsync();
            if (mail.Sent.Any(m => m.Subject.Contains("Finance mailbox", StringComparison.Ordinal))) alerted = TimeSpan.FromMinutes(minute);
        }
        Assert.NotNull(alerted);
        Assert.True(alerted <= TimeSpan.FromMinutes(15), $"alerted after {alerted}");
        Assert.True(alerted >= TimeSpan.FromMinutes(10), "a backup that is a few minutes late is not yet a missed run");

        var message = Assert.Single(mail.Sent);
        Assert.Equal($"ops-{seed.User:N}@example.com", message.To);
        Assert.Contains("has not started", message.Text, StringComparison.Ordinal);
        Assert.Contains("https://vaulty.example.com/tenants/", message.Text, StringComparison.Ordinal);
        Assert.NotNull(message.Html);

        // Still missed a minute later: no second alert, no second mail; an event was published once for webhooks.
        clock.Advance(TimeSpan.FromMinutes(1));
        await dispatcher.FindMissedRunsAsync();
        await dispatcher.MailAlertsAsync();
        Assert.Single(mail.Sent);
        await using var owner = new NpgsqlConnection(db.Migrator);
        Assert.Equal(1, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.notification_events WHERE protected_object_id = @o AND kind = 'backup.missed'",
            new { o = seed.Object }));
    }

    [PostgresFact]
    public async Task A_running_backup_is_not_a_missed_run()
    {
        var due = DateTimeOffset.UtcNow.AddHours(-2);
        var seed = new NotificationSeed();
        await seed.SeedAsync(db, due);
        await using (var owner = new NpgsqlConnection(db.Migrator))
        {
            await owner.ExecuteAsync("INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state) VALUES (@id, @org, @tenant, @o, 'staged')",
                new { id = Guid.NewGuid(), org = seed.Org, tenant = seed.Tenant, o = seed.Object });
        }
        await using var worker = VaultyDataSource.Create(db.Worker);
        var dispatcher = Dispatcher(worker, TimeProvider.System, new RecordingMailSender(), new MemorySecretStore());
        await dispatcher.FindMissedRunsAsync();
        await using var check = new NpgsqlConnection(db.Migrator);
        Assert.Equal(0, await check.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.alerts WHERE protected_object_id = @o", new { o = seed.Object }));
    }

    [PostgresFact]
    public async Task An_object_queued_behind_its_tenants_budget_is_not_missed_and_a_started_run_settles_its_alert()
    {
        var due = DateTimeOffset.UtcNow.AddHours(-2);
        var seed = new NotificationSeed();
        await seed.SeedAsync(db, due);
        await using var owner = new NpgsqlConnection(db.Migrator);
        // The tenant runs as many mailbox backups as its budget allows; the seeded mailbox waits for a free place.
        for (var i = 0; i < BackupBudget.MailboxesPerTenant; i++)
        {
            var other = Guid.NewGuid();
            await owner.ExecuteAsync(
                """
                INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name, next_run_at)
                    VALUES (@other, @org, @tenant, 'mailbox', 'user', @source, @name, @due);
                INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state) VALUES (@snapshot, @org, @tenant, @other, 'staged');
                """, new { other, org = seed.Org, tenant = seed.Tenant, source = $"busy-{i}", name = $"Busy {i}", due, snapshot = Guid.NewGuid() });
        }
        await using var worker = VaultyDataSource.Create(db.Worker);
        var dispatcher = Dispatcher(worker, TimeProvider.System, new RecordingMailSender(), new MemorySecretStore());
        const string Open = "SELECT count(*) FROM vaulty.alerts WHERE protected_object_id = @o AND kind = 'backup.missed' AND resolved_at IS NULL";
        await dispatcher.FindMissedRunsAsync();
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>(Open, new { o = seed.Object }));

        // A place frees up and the run still does not start: that is missed, with the causes that remain.
        await owner.ExecuteAsync("UPDATE vaulty.snapshots SET state = 'failed' WHERE tenant_id = @tenant AND protected_object_id <> @o AND state = 'staged' " +
                                 "AND id = (SELECT id FROM vaulty.snapshots WHERE tenant_id = @tenant AND state = 'staged' LIMIT 1)", new { tenant = seed.Tenant, o = seed.Object });
        await dispatcher.FindMissedRunsAsync();
        Assert.Equal(1, await owner.ExecuteScalarAsync<int>(Open, new { o = seed.Object }));
        Assert.Contains("worker service", await owner.ExecuteScalarAsync<string>(
            "SELECT message FROM vaulty.alerts WHERE protected_object_id = @o AND kind = 'backup.missed'", new { o = seed.Object }), StringComparison.Ordinal);

        // Once its backup starts, the alert is settled without waiting for the snapshot.
        await owner.ExecuteAsync("INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state) VALUES (@id, @org, @tenant, @o, 'staged')",
            new { id = Guid.NewGuid(), org = seed.Org, tenant = seed.Tenant, o = seed.Object });
        await dispatcher.FindMissedRunsAsync();
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>(Open, new { o = seed.Object }));
        // The sweep walks every organization of the shared test database: leave nothing for other tests to mail.
        await owner.ExecuteAsync("UPDATE vaulty.alerts SET notified_at = now() WHERE organization_id = @org; UPDATE vaulty.protected_objects SET state = 'paused' WHERE organization_id = @org",
            new { org = seed.Org });
    }

    [PostgresFact]
    public async Task Webhook_deliveries_are_signed_verifiable_by_a_receiver_and_retried()
    {
        var seed = new NotificationSeed();
        await seed.SeedAsync(db, DateTimeOffset.UtcNow.AddDays(1));
        await using var api = VaultyDataSource.Create(db.Api);
        await using var worker = VaultyDataSource.Create(db.Worker);
        var secrets = new MemorySecretStore();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var server = WireMockServer.Start();
        server.Given(Request.Create().WithPath("/hook").UsingPost()).InScenario("hook").WillSetStateTo("up")
            .RespondWith(Response.Create().WithStatusCode(503));
        server.Given(Request.Create().WithPath("/hook").UsingPost()).InScenario("hook").WhenStateIs("up")
            .RespondWith(Response.Create().WithStatusCode(204));

        var admin = new UserAccess(seed.User, seed.Org, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.SettingsManage] = null });
        var service = new WebhookService(api, secrets, new WebhookOptions { AllowPrivateTargets = true });
        var (hookId, secretText) = await service.CreateAsync(admin, "PSA", $"{server.Url}/hook", [NotificationKinds.BackupPartial, NotificationKinds.RestoreCompleted]);
        var secret = Convert.FromBase64String(secretText);
        await Assert.ThrowsAsync<AccessException>(() => service.ListAsync(new UserAccess(seed.User, seed.Org, true, new Dictionary<string, HashSet<Guid>?>())));
        var listed = Assert.Single(await service.ListAsync(admin), w => w.Id == hookId);
        Assert.Equal([NotificationKinds.BackupPartial, NotificationKinds.RestoreCompleted], listed.Events.Order(StringComparer.Ordinal));

        // An event the webhook subscribed to, and one it did not.
        await using (var session = await OrganizationSession.BeginAsync(worker, seed.Org))
        {
            await NotificationEvents.PublishAsync(session, NotificationKinds.BackupPartial, seed.Tenant, seed.Object, new { missing = 3, message = "Backup of Finance mailbox is partial" });
            await NotificationEvents.PublishAsync(session, NotificationKinds.BackupMissed, seed.Tenant, seed.Object, new { });
            await session.CommitAsync();
        }
        var dispatcher = Dispatcher(worker, clock, new RecordingMailSender(), secrets);
        Assert.Equal(1, await dispatcher.FanOutEventsAsync());

        // First attempt: the receiver is down; the delivery waits a minute and is tried again.
        Assert.Equal(0, await dispatcher.DeliverWebhooksAsync());
        var first = Assert.Single(await service.DeliveriesAsync(admin, hookId));
        Assert.Equal(("pending", 1, (int?)503), (first.State, first.Attempts, first.LastStatus));
        Assert.Equal(0, await dispatcher.DeliverWebhooksAsync()); // not due yet
        clock.Advance(TimeSpan.FromMinutes(1.5));
        Assert.Equal(1, await dispatcher.DeliverWebhooksAsync());
        Assert.Equal("delivered", Assert.Single(await service.DeliveriesAsync(admin, hookId)).State);

        // The sample receiver accepts the real delivery, and rejects tampering, a replay and a stale copy.
        var request = server.LogEntries.Last().RequestMessage!;
        var headers = request.Headers!.ToDictionary(h => h.Key, h => h.Value.First(), StringComparer.OrdinalIgnoreCase);
        var body = request.BodyAsBytes!;
        Assert.Equal(NotificationKinds.BackupPartial, headers[WebhookSignature.EventHeader]);
        using (var json = JsonDocument.Parse(body))
        {
            Assert.Equal(NotificationKinds.BackupPartial, json.RootElement.GetProperty("type").GetString());
            Assert.Equal(seed.Object.ToString(), json.RootElement.GetProperty("protected_object_id").GetString());
            Assert.Equal(3, json.RootElement.GetProperty("data").GetProperty("missing").GetInt32());
        }
        var receiver = new SampleReceiver(secret, clock);
        Assert.Equal("rejected: signature", receiver.Accept(headers, Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(body).Replace("3", "0", StringComparison.Ordinal))));
        Assert.Equal("accepted", receiver.Accept(headers, body));
        Assert.Equal("rejected: replay", receiver.Accept(headers, body));
        Assert.Equal("rejected: signature", new SampleReceiver(secret, new FakeTimeProvider(clock.GetUtcNow().AddMinutes(6))).Accept(headers, body));
        Assert.Equal("rejected: signature", new SampleReceiver(new byte[32], clock).Accept(headers, body));
        Assert.Equal(2, server.LogEntries.Count());
    }

    [PostgresFact]
    public async Task The_daily_digest_goes_out_once_with_exact_counts_and_metrics_count_the_same()
    {
        var seed = new NotificationSeed();
        await seed.SeedAsync(db, DateTimeOffset.UtcNow.AddHours(1));
        await using (var owner = new NpgsqlConnection(db.Migrator))
        {
            var snapshot = Guid.NewGuid();
            await owner.ExecuteAsync(
                """
                INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state, started_at, committed_at, item_counts, exceptions, manifest_root_hash, sequence)
                    VALUES (@snapshot, @org, @tenant, @o, 'partial', now(), now(), '{"items": 40}', '[{"error_code":"too_large"}]', '\x00', 1);
                UPDATE vaulty.protected_objects SET last_snapshot_id = @snapshot WHERE id = @o;
                """, new { snapshot, org = seed.Org, tenant = seed.Tenant, o = seed.Object });
        }
        await using var api = VaultyDataSource.Create(db.Api);
        await using var worker = VaultyDataSource.Create(db.Worker);
        await ConfigureSmtpAsync(api);
        var mail = new RecordingMailSender();
        // The digest hour is local to the display time zone; UTC here, so the test does not depend on the host's time zone data.
        await new PlatformSettings(api).SetAsync(DisplaySettings.SettingKey, DisplaySettings.Default with { TimeZone = "UTC" }, "test");
        var early = new DateTimeOffset(DateTime.UtcNow.Date.AddHours(6), TimeSpan.Zero);
        var clock = new FakeTimeProvider(early);
        var dispatcher = Dispatcher(worker, clock, mail, new MemorySecretStore());

        Assert.Equal(0, await dispatcher.SendDigestsAsync()); // before 07:00 local time
        clock.Advance(TimeSpan.FromHours(1.5));
        Assert.True(await dispatcher.SendDigestsAsync() >= 1);
        var digest = mail.Sent.Single(m => m.To == $"ops-{seed.User:N}@example.com");
        Assert.Equal("Daily summary: 1 protected object needs attention", digest.Subject);
        Assert.Contains("1 partial", digest.Text, StringComparison.Ordinal);
        Assert.Contains("Partial: Finance mailbox (Contoso · Contoso tenant)", digest.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("%", digest.Text, StringComparison.Ordinal);
        Assert.Equal(0, await dispatcher.SendDigestsAsync()); // once a day

        var metrics = await new PlatformMetrics(api, new DashboardService(api, TimeProvider.System), TimeProvider.System).CollectAsync();
        Assert.Matches(@"vaulty_protected_objects\{status=""partial""\} [1-9]", metrics);
        Assert.Contains("# TYPE vaulty_alerts_open gauge", metrics, StringComparison.Ordinal);
        Assert.DoesNotContain("Finance", metrics, StringComparison.Ordinal);
        Assert.DoesNotContain(seed.Tenant.ToString(), metrics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Webhooks_never_reach_internal_addresses()
    {
        Assert.NotNull(WebhookSender.Validate("http://hooks.example.com/x"));
        Assert.NotNull(WebhookSender.Validate("https://127.0.0.1/x"));
        Assert.NotNull(WebhookSender.Validate("https://[::1]/x"));
        Assert.NotNull(WebhookSender.Validate("https://169.254.169.254/latest"));
        Assert.NotNull(WebhookSender.Validate("https://user:pass@hooks.example.com/x"));
        Assert.Null(WebhookSender.Validate("https://hooks.example.com/vaulty"));
        foreach (var internalAddress in new[] { "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "0.0.0.0", "fd00::1", "fe80::1", "::ffff:127.0.0.1" })
        {
            Assert.True(WebhookSender.IsInternal(IPAddress.Parse(internalAddress)), internalAddress);
        }
        Assert.False(WebhookSender.IsInternal(IPAddress.Parse("203.0.113.10")));

        // A host name that resolves to loopback is refused when connecting, not only when the URL is checked.
        using var sender = new WebhookSender(TimeProvider.System);
        var result = await sender.SendAsync(new Uri("https://localhost:9/hook"), "webhook.test", Guid.NewGuid(), [1], new byte[32], TimeSpan.FromSeconds(5));
        Assert.False(result.Delivered);
        Assert.Contains("private or local address", result.Error, StringComparison.Ordinal);
    }
}
