using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Security;
using Vaulty.Core.Storage;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Restore;
using Vaulty.Infrastructure.Retention;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Integration.Tests.Backup;
using Vaulty.Integration.Tests.Database;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Retention;

/// <summary>A tenant whose protected objects got many backups over a simulated year, written through the real backup store.</summary>
internal sealed class History : IAsyncDisposable
{
    private readonly PostgresDatabase _db;

    public History(PostgresDatabase db, DateTimeOffset start)
    {
        _db = db;
        Clock = new FakeTimeProvider(start);
        Store = new InMemoryObjectStore(Clock);
        Worker = VaultyDataSource.Create(db.Worker);
        Gc = VaultyDataSource.Create(db.Gc);
        Storage = new MemoryBackupStorage(Store);
    }

    public FakeTimeProvider Clock { get; }
    public InMemoryObjectStore Store { get; }
    public NpgsqlDataSource Worker { get; }
    public NpgsqlDataSource Gc { get; }
    public MemoryBackupStorage Storage { get; }
    public byte[] MasterKey { get; } = RandomNumberGenerator.GetBytes(32);
    public Guid Org { get; } = Guid.NewGuid();
    public Guid Tenant { get; } = Guid.NewGuid();
    public List<(Guid Id, int RetentionDays)> Objects { get; } = [];
    private readonly Dictionary<Guid, Dictionary<string, int>> _items = [];

    public TenantKeyProvider Keys(NpgsqlDataSource dataSource) => new(dataSource, new StaticMasterKeySource(MasterKey), Storage, Clock);

    public async Task SeedAsync(int objects, Random random)
    {
        await using var owner = new NpgsqlConnection(_db.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'O');
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C', 'C');
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name, consent_state, client_id)
                VALUES (@tenant, @org, @customer, @entra, 'T', 'granted', @client);
            INSERT INTO vaulty.policies (id, organization_id, tenant_id, name) VALUES (@policy, @org, @tenant, 'Default');
            """, new { org = Org, customer = Guid.NewGuid(), tenant = Tenant, entra = Guid.NewGuid(), client = Guid.NewGuid(), policy = Guid.NewGuid() });
        for (var i = 0; i < objects; i++)
        {
            var id = Guid.NewGuid();
            var retention = random.Next(90, 151);
            await owner.ExecuteAsync(
                """
                INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name)
                    VALUES (@id, @org, @tenant, 'mailbox', 'user', @source, 'M');
                INSERT INTO vaulty.policies (id, organization_id, tenant_id, protected_object_id, name, retention_days)
                    VALUES (@policy, @org, @tenant, @id, 'Object', @retention);
                """, new { id, org = Org, tenant = Tenant, source = id.ToString("N"), policy = Guid.NewGuid(), retention });
            Objects.Add((id, retention));
            _items[id] = new Dictionary<string, int>(StringComparer.Ordinal);
        }
    }

    public static byte[] Content(Guid objectId, string sourceId, int version)
    {
        var seed = BitConverter.ToInt32(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{objectId}/{sourceId}/{version}")));
        var random = new Random(seed);
        var bytes = new byte[random.Next(1_000, 8_000)];
        random.NextBytes(bytes);
        return bytes;
    }

    /// <summary>One backup of one object at the current time: a few items change, one appears, one disappears.</summary>
    public async Task<Guid> BackupAsync(Guid objectId, int retentionDays, int round, Random random, bool commit = true, int extraItems = 0, int removeItems = 0)
    {
        var keys = await Keys(Worker).GetAsync(Org, Tenant);
        var store = new BackupStore(Worker, Clock);
        var snapshotId = Guid.CreateVersion7();
        var target = new BackupTarget(Org, Tenant, objectId, snapshotId);
        await store.PrepareSnapshotAsync(target);
        var policy = new EffectivePolicy(360, retentionDays, new HashSet<string>(), false);
        var lockUntil = policy.LockUntil(Clock.GetUtcNow());
        var writer = new RepositoryWriter(Store, keys, new PostgresChunkIndex(Worker, Org, Tenant), new RepositoryWriterOptions { LockUntil = lockUntil });
        var items = _items[objectId];
        var changed = new List<string>();
        var removed = new List<string>();
        if (round == 0)
        {
            for (var i = 0; i < 12 + extraItems; i++) changed.Add($"item-{i}");
        }
        else
        {
            changed.AddRange(items.Keys.OrderBy(_ => random.Next()).Take(2));
            changed.Add($"item-{round}-new");
            removed.AddRange(items.Keys.Except(changed).OrderBy(_ => random.Next()).Take(Math.Max(1, removeItems)));
        }
        var versions = new List<ItemVersion>();
        if (round == 0) versions.Add(new ItemVersion("inbox", null, "folder", "f1", 0, Clock.GetUtcNow(), null, "{\"name\":\"Inbox\"}"));
        foreach (var source in changed)
        {
            items[source] = items.GetValueOrDefault(source) + 1;
            await using var content = new MemoryStream(Content(objectId, source, items[source]));
            var stored = await writer.WriteAsync(content);
            versions.Add(new ItemVersion(source, "inbox", "mail", $"v{items[source]}", stored.Size, Clock.GetUtcNow(), stored,
                JsonSerializer.Serialize(new { subject = $"{source} v{items[source]}" })));
        }
        foreach (var source in removed) items.Remove(source);
        await writer.FlushAsync();
        await store.StageVersionsAsync(target, keys, versions);
        await store.StageRemovalsAsync(target, removed);
        if (!commit) return snapshotId;
        var reader = new RepositoryReader(Store, keys, new PostgresChunkIndex(Worker, Org, Tenant));
        await store.CommitAsync(target, keys, writer, reader, [], lockUntil, TimeSpan.FromDays(3));
        return snapshotId;
    }

    /// <summary>Everything a snapshot holds, read back from object storage and checked: source id → content hash.</summary>
    public async Task<Dictionary<string, string>> ReadAsync(Guid objectId, Guid snapshotId)
    {
        var keys = await Keys(Worker).GetAsync(Org, Tenant);
        var reader = new RepositoryReader(Store, keys, new PostgresChunkIndex(Worker, Org, Tenant));
        var root = await reader.ReadSnapshotAsync(objectId, snapshotId);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var manifestId in root.ManifestIds)
        {
            foreach (var entry in (await reader.ReadManifestAsync(manifestId)).Entries.Where(e => e.Content is not null))
            {
                using var buffer = new MemoryStream();
                await reader.ReadContentAsync(entry.Content!, buffer);
                result[entry.SourceId] = Convert.ToHexString(SHA256.HashData(buffer.ToArray()));
            }
        }
        return result;
    }

    /// <summary>
    /// Garbage collection under its own role. The simulated clock runs in the past, so by default it is also the reference
    /// clock; <paramref name="databaseReference"/> compares with the real database clock instead.
    /// </summary>
    public GarbageCollector Collector(GcOptions? options = null, TimeProvider? clock = null, bool databaseReference = false)
    {
        var effective = options ?? new GcOptions();
        if (!databaseReference) effective = effective with { ReferenceClock = _ => Task.FromResult((clock ?? Clock).GetUtcNow()) };
        return new GarbageCollector(Gc, Storage, Keys(Gc), clock ?? Clock, effective);
    }

    public async ValueTask DisposeAsync()
    {
        await Worker.DisposeAsync();
        await Gc.DisposeAsync();
    }
}

public sealed class RetentionTests(PostgresDatabase db, ITestOutputHelper output) : IClassFixture<PostgresDatabase>
{
    [PostgresFact]
    public async Task Garbage_collection_over_1000_snapshots_with_random_retention_never_removes_referenced_data()
    {
        var start = new DateTimeOffset(2025, 1, 1, 6, 0, 0, TimeSpan.Zero);
        await using var history = new History(db, start);
        var random = new Random(1000);
        await history.SeedAsync(objects: 10, random);
        var snapshots = new List<(Guid Object, Guid Snapshot, DateTimeOffset At)>();
        var watch = Stopwatch.StartNew();
        for (var round = 0; round < 100; round++)
        {
            foreach (var (objectId, retention) in history.Objects)
            {
                snapshots.Add((objectId, await history.BackupAsync(objectId, retention, round, random), history.Clock.GetUtcNow()));
            }
            history.Clock.Advance(TimeSpan.FromDays(3));
        }
        output.WriteLine($"{snapshots.Count} snapshots in {watch.Elapsed.TotalSeconds:F0} s, {history.Store.Count} objects, {history.Store.TotalBytes / 1024} KiB");
        Assert.Equal(1000, snapshots.Count);

        // What must survive: every snapshot within its object's retention, and the newest of each object.
        var now = history.Clock.GetUtcNow();
        var live = snapshots.Where(s => s.At >= now.AddDays(-history.Objects.Single(o => o.Id == s.Object).RetentionDays)
                                        || s.Snapshot == snapshots.Last(x => x.Object == s.Object).Snapshot).ToList();
        var before = new Dictionary<Guid, Dictionary<string, string>>();
        foreach (var s in live) before[s.Snapshot] = await history.ReadAsync(s.Object, s.Snapshot);

        // The kill switch: the default limit refuses to remove this much at once.
        var refused = await history.Collector().RunAsync(history.Org, history.Tenant, dryRun: true);
        Assert.Equal("refused", refused.State);
        Assert.Contains("more than the limit", refused.Reason, StringComparison.Ordinal);

        var options = new GcOptions { MaxDeleteFraction = 0.95 };
        var objectsBefore = history.Store.Count;
        var dry = await history.Collector(options).RunAsync(history.Org, history.Tenant, dryRun: true);
        Assert.Equal("succeeded", dry.State);
        Assert.Equal(1000 - live.Count, dry.SnapshotsExpired);
        Assert.True(dry.PacksDeleted > 0, "the dry run found nothing to remove");
        Assert.Equal(objectsBefore, history.Store.Count);

        var run = await history.Collector(options).RunAsync(history.Org, history.Tenant, dryRun: false);
        output.WriteLine($"dry run: {dry.PacksDeleted} packs ({dry.BytesDeleted / 1024} KiB), {dry.PacksWaitingForLock} waiting for their lock; "
            + $"run: {run.PacksDeleted} packs, {run.ManifestsDeleted} manifests, {run.ItemRowsDeleted} item rows, {run.SnapshotsExpired} snapshots expired");
        Assert.Equal("succeeded", run.State);
        Assert.Equal(dry.PacksDeleted, run.PacksDeleted);
        Assert.Equal(0, run.PacksLocked);
        Assert.True(history.Store.Count < objectsBefore);

        // Every remaining snapshot still reads back completely, with the same content.
        foreach (var s in live) Assert.Equal(before[s.Snapshot], await history.ReadAsync(s.Object, s.Snapshot));
        await using var owner = new NpgsqlConnection(db.Migrator);
        Assert.Equal(1000 - live.Count, await owner.ExecuteScalarAsync<int>(
            "SELECT count(*) FROM vaulty.snapshots WHERE tenant_id = @tenant AND state = 'expired'", new { tenant = history.Tenant }));
        // No chunk that a live item version needs points to a pack that is gone.
        var missing = await owner.ExecuteScalarAsync<int>(
            """
            SELECT count(*) FROM vaulty.chunk_index c JOIN vaulty.packs p ON p.id = c.pack_id WHERE c.tenant_id = @tenant AND p.state = 'deleted'
            """, new { tenant = history.Tenant });
        Assert.Equal(0, missing);

        // A second run finds nothing new; data still under its Object Lock waits.
        var again = await history.Collector(options).RunAsync(history.Org, history.Tenant, dryRun: false);
        Assert.Equal(0, again.PacksDeleted);
        Assert.Equal(dry.PacksWaitingForLock, again.PacksWaitingForLock);
    }

    [PostgresFact]
    public async Task Object_Lock_refuses_deletes_inside_the_lock_even_when_the_database_says_otherwise()
    {
        await using var history = new History(db, new DateTimeOffset(2025, 1, 1, 6, 0, 0, TimeSpan.Zero));
        var random = new Random(7);
        await history.SeedAsync(objects: 2, random);
        for (var round = 0; round < 40; round++)
        {
            foreach (var (objectId, retention) in history.Objects) await history.BackupAsync(objectId, retention, round, random);
            history.Clock.Advance(TimeSpan.FromDays(3));
        }
        await using var owner = new NpgsqlConnection(db.Migrator);
        var options = new GcOptions { MaxDeleteFraction = 1 };
        var dry = await history.Collector(options).RunAsync(history.Org, history.Tenant, dryRun: true);
        Assert.True(dry.PacksWaitingForLock > 0, "no pack waits for its lock");

        // A pack directly: the store refuses while the lock holds, for the garbage-collection identity too.
        var lockedKey = await owner.ExecuteScalarAsync<string>("SELECT object_key FROM vaulty.packs WHERE tenant_id = @tenant AND lock_until > @now LIMIT 1",
            new { tenant = history.Tenant, now = history.Clock.GetUtcNow() });
        await Assert.ThrowsAsync<ObjectLockedException>(() => history.Store.DeleteAsync(lockedKey!));

        // The database claims every lock has expired; storage still holds them: nothing locked is removed.
        await owner.ExecuteAsync("UPDATE vaulty.packs SET lock_until = @past WHERE tenant_id = @tenant",
            new { tenant = history.Tenant, past = history.Clock.GetUtcNow().AddDays(-1) });
        var run = await history.Collector(options).RunAsync(history.Org, history.Tenant, dryRun: false);
        Assert.Equal("succeeded", run.State);
        Assert.True(run.PacksLocked >= dry.PacksWaitingForLock, $"{run.PacksLocked} refused by the lock");
        Assert.NotNull(await history.Store.HeadAsync(lockedKey!));
    }

    [PostgresFact]
    public async Task Garbage_collection_refuses_while_a_backup_runs_or_the_clock_is_off()
    {
        await using var history = new History(db, new DateTimeOffset(2025, 1, 1, 6, 0, 0, TimeSpan.Zero));
        var random = new Random(3);
        await history.SeedAsync(objects: 1, random);
        var (objectId, retention) = history.Objects[0];
        await history.BackupAsync(objectId, retention, 0, random);
        // The fake clock of the history is far from the database clock.
        var skewed = await history.Collector(databaseReference: true).RunAsync(history.Org, history.Tenant, dryRun: true);
        Assert.Equal("refused", skewed.State);
        Assert.Contains("clock", skewed.Reason, StringComparison.Ordinal);

        var system = history.Collector(clock: TimeProvider.System, databaseReference: true);
        Assert.Equal("succeeded", (await system.RunAsync(history.Org, history.Tenant, dryRun: true)).State);
        history.Clock.SetUtcNow(DateTimeOffset.UtcNow);
        await history.BackupAsync(objectId, retention, 1, random, commit: false);
        var busy = await system.RunAsync(history.Org, history.Tenant, dryRun: true);
        Assert.Equal("refused", busy.State);
        Assert.Contains("backup of this tenant is running", busy.Reason, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task A_corrupted_chunk_is_found_by_the_scrub_and_raises_a_critical_alert()
    {
        await using var history = new History(db, DateTimeOffset.UtcNow.AddDays(-10));
        var random = new Random(11);
        await history.SeedAsync(objects: 2, random);
        for (var round = 0; round < 5; round++)
        {
            foreach (var (objectId, retention) in history.Objects) await history.BackupAsync(objectId, retention, round, random);
            history.Clock.Advance(TimeSpan.FromDays(1));
        }
        var options = new VerificationOptions { WeeklyScrubFraction = 7 }; // every pack in one run
        var clean = await new VerificationService(history.Gc, history.Storage, history.Keys(history.Gc), history.Clock, options)
            .RunAsync(history.Org, history.Tenant);
        Assert.Empty(clean.Failures);
        Assert.True(clean.PacksScrubbed > 0);
        Assert.Equal(10, clean.ItemsDrilled);
        await using var owner = new NpgsqlConnection(db.Migrator);
        Assert.Equal(2, await owner.ExecuteScalarAsync<int>(
            "SELECT count(*) FROM vaulty.snapshots WHERE tenant_id = @tenant AND verified_at IS NOT NULL", new { tenant = history.Tenant }));

        // One bit of one pack flips in storage.
        var packKey = history.Store.Keys.First(k => k.Contains("/packs/", StringComparison.Ordinal));
        history.Store.CorruptBit(packKey, history.Store.Raw(packKey).Length / 2, bit: 2);
        history.Clock.Advance(TimeSpan.FromDays(1));
        var result = await new VerificationService(history.Gc, history.Storage, history.Keys(history.Gc), history.Clock, options)
            .RunAsync(history.Org, history.Tenant);
        var failure = Assert.Single(result.Failures, f => f.Kind == "pack");
        Assert.Equal(packKey, failure.Target);
        var alert = await owner.QuerySingleAsync<(string Severity, string Message)>(
            "SELECT severity, message FROM vaulty.alerts WHERE tenant_id = @tenant AND kind = 'verification.failed' AND resolved_at IS NULL", new { tenant = history.Tenant });
        Assert.Equal("critical", alert.Severity);
        Assert.Equal(1, await owner.ExecuteScalarAsync<int>(
            "SELECT count(*) FROM vaulty.packs WHERE tenant_id = @tenant AND scrub_failed_at IS NOT NULL", new { tenant = history.Tenant }));
        output.WriteLine($"scrub: {result.PacksScrubbed} packs, {result.ItemsDrilled} items, {result.Failures.Count} failures: {failure.Detail}");
    }

    [PostgresFact]
    public async Task Deleting_a_tenant_waits_30_days_and_needs_a_second_administrator()
    {
        await using var history = new History(db, DateTimeOffset.UtcNow);
        await history.SeedAsync(objects: 1, new Random(5));
        await using var api = VaultyDataSource.Create(db.Api);
        var deletion = new TenantDeletion(api, history.Clock);
        UserAccess Admin(Guid user) => new(user, history.Org, true, Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();

        await Assert.ThrowsAsync<StepUpRequiredException>(() => deletion.RequestAsync(Admin(first), false, history.Tenant));
        var readOnly = new UserAccess(Guid.NewGuid(), history.Org, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.CustomersView] = null });
        await Assert.ThrowsAsync<AccessException>(() => deletion.RequestAsync(readOnly, true, history.Tenant));
        await deletion.RequestAsync(Admin(first), true, history.Tenant);

        await using var owner = new NpgsqlConnection(db.Migrator);
        Assert.Equal("deletion_requested", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.tenants WHERE id = @t", new { t = history.Tenant }));
        // No more backups for it.
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.due_protected_objects(now() + interval '10 years', 100) WHERE tenant_id = @t",
            new { t = history.Tenant }));

        await Assert.ThrowsAsync<AccessException>(() => deletion.ConfirmAsync(Admin(first), true, history.Tenant));
        history.Clock.Advance(TimeSpan.FromDays(29));
        var early = await Assert.ThrowsAsync<InvalidOperationException>(() => deletion.ConfirmAsync(Admin(second), true, history.Tenant));
        Assert.Contains("30 days after the request", early.Message, StringComparison.Ordinal);

        // A reminder every day while it waits.
        await using (var gc = VaultyDataSource.Create(db.Gc)) await new TenantDeletion(gc, history.Clock).RemindAsync(history.Org);
        Assert.Contains("confirm in 1 day", await owner.ExecuteScalarAsync<string>(
            "SELECT message FROM vaulty.alerts WHERE tenant_id = @t AND kind = 'tenant.deletion_pending' AND resolved_at IS NULL", new { t = history.Tenant }),
            StringComparison.Ordinal);

        history.Clock.Advance(TimeSpan.FromDays(1.01));
        await Assert.ThrowsAsync<StepUpRequiredException>(() => deletion.ConfirmAsync(Admin(second), false, history.Tenant));
        await deletion.ConfirmAsync(Admin(second), true, history.Tenant);
        var row = await owner.QuerySingleAsync<(string State, Guid RequestedBy, Guid ConfirmedBy)>(
            "SELECT state, deletion_requested_by, deletion_confirmed_by FROM vaulty.tenants WHERE id = @t", new { t = history.Tenant });
        Assert.Equal(("deleted", first, second), row);
        Assert.Equal(["tenant.deletion_requested", "tenant.deleted"], (await owner.QueryAsync<string>(
            "SELECT action FROM vaulty.audit_events WHERE target = @target ORDER BY seq", new { target = $"tenant:{history.Tenant}" })).ToList());
    }

    [PostgresFact]
    public async Task A_snapshot_with_far_fewer_items_than_the_previous_one_raises_a_drift_alert()
    {
        await using var history = new History(db, DateTimeOffset.UtcNow);
        var random = new Random(13);
        await history.SeedAsync(objects: 1, random);
        var (objectId, retention) = history.Objects[0];
        await history.BackupAsync(objectId, retention, 0, random, extraItems: 40);
        await history.BackupAsync(objectId, retention, 1, random);
        await using var owner = new NpgsqlConnection(db.Migrator);
        const string Open = "SELECT count(*) FROM vaulty.alerts WHERE protected_object_id = @o AND kind = 'backup.drift' AND resolved_at IS NULL";
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>(Open, new { o = objectId }));

        // 52 items, then 40 of them disappear at the source: a drop of more than 30%.
        await history.BackupAsync(objectId, retention, 2, random, removeItems: 40);
        Assert.Equal(1, await owner.ExecuteScalarAsync<int>(Open, new { o = objectId }));
        var message = await owner.ExecuteScalarAsync<string>(
            "SELECT message FROM vaulty.alerts WHERE protected_object_id = @o AND kind = 'backup.drift'", new { o = objectId });
        Assert.Contains("fewer than the previous one", message, StringComparison.Ordinal);
        Assert.False(DriftDetection.IsDrift(19, 0));
        Assert.False(DriftDetection.IsDrift(100, 70));
        Assert.True(DriftDetection.IsDrift(100, 69));
    }

    [PostgresFact]
    public async Task Legal_hold_keeps_every_snapshot_beyond_retention()
    {
        await using var history = new History(db, new DateTimeOffset(2025, 1, 1, 6, 0, 0, TimeSpan.Zero));
        var random = new Random(9);
        await history.SeedAsync(objects: 1, random);
        var (objectId, retention) = history.Objects[0];
        for (var round = 0; round < 80; round++)
        {
            await history.BackupAsync(objectId, retention, round, random);
            history.Clock.Advance(TimeSpan.FromDays(3));
        }
        await using var api = VaultyDataSource.Create(db.Api);
        var admin = new UserAccess(Guid.NewGuid(), history.Org, true, Permissions.All.ToDictionary(p => p.Key, _ => (HashSet<Guid>?)null));
        await new LegalHold(api).SetForObjectAsync(admin, objectId, true);
        var held = await history.Collector(new GcOptions { MaxDeleteFraction = 1 }).RunAsync(history.Org, history.Tenant, dryRun: false);
        Assert.Equal(0, held.SnapshotsExpired);
        Assert.Equal(0, held.PacksDeleted);

        await new LegalHold(api).SetForObjectAsync(admin, objectId, false);
        var released = await history.Collector(new GcOptions { MaxDeleteFraction = 1 }).RunAsync(history.Org, history.Tenant, dryRun: true);
        Assert.True(released.SnapshotsExpired > 0);
    }
}
