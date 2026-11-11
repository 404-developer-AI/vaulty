using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Temporalio.Client;
using Temporalio.Worker;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Storage;
using Vaulty.Graph;
using Vaulty.Graph.Http;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Integration.Tests.Temporal;
using Vaulty.Integration.Tests.Tenants;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Vaulty.Workflows.Backup;
using Vaulty.Workflows.Jobs;
using Vaulty.Workflows.Tenants;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Backup;

internal sealed class MemoryExportStorage(InMemoryObjectStore store, InMemoryObjectUploads uploads) : Vaulty.Infrastructure.Restore.IExportStorage
{
    public Task<IObjectUploads> UploadsAsync(CancellationToken cancellationToken = default) => Task.FromResult<IObjectUploads>(uploads);
    public Task<IObjectStore> StoreAsync(CancellationToken cancellationToken = default) => Task.FromResult<IObjectStore>(store);
}

internal sealed class MemoryBackupStorage(InMemoryObjectStore store) : IBackupStorage
{
    public Task<IObjectStore> WorkerStoreAsync(CancellationToken cancellationToken = default) => Task.FromResult<IObjectStore>(store);
    public Task<bool> ReadyAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
}

/// <summary>Everything a backup needs, wired to a simulated mailbox, an in-memory store and the Temporal dev server.</summary>
internal sealed class BackupHarness : IAsyncDisposable
{
    private readonly TemporalFixture _fixture;
    private TemporalWorker? _worker;
    private CancellationTokenSource? _stop;
    private Task? _running;

    private readonly Func<string, byte[]?> _source;

    public BackupHarness(TemporalFixture fixture, MailboxSimulator simulator)
        : this(fixture, simulator.Url, id => simulator.Items.TryGetValue(id, out var item) ? item.Data : null)
    {
    }

    /// <param name="source">The source bytes of an item by its source id, to compare restored content with (null: not compared).</param>
    public BackupHarness(TemporalFixture fixture, string graphUrl, Func<string, byte[]?> source)
    {
        _fixture = fixture;
        _source = source;
        ExportUploads = new InMemoryObjectUploads(ExportStore, partSize: 256 * 1024);
        Api = VaultyDataSource.Create(fixture.Database.Api);
        Restores = new Vaulty.Infrastructure.Restore.RestoreStore(VaultyDataSource.Create(fixture.Database.Worker), TimeProvider.System);
        DataSource = VaultyDataSource.Create(fixture.Database.Worker);
        Storage = new MemoryBackupStorage(Store);
        Keys = new TenantKeyProvider(DataSource, new StaticMasterKeySource(MasterKey), Storage, TimeProvider.System);
        var host = new Uri(graphUrl).Host;
        Graph = new GraphServices(new ScriptedTokens(), new GraphThrottle(), new Uri($"{graphUrl}/v1.0/"),
            downloads: throttle => new GraphDownloadClient(throttle, allowedHostSuffixes: [host], allowHttpForTests: true));
    }

    public string Queue { get; } = $"backup-test-{Guid.NewGuid():N}";
    public NpgsqlDataSource DataSource { get; }
    public InMemoryObjectStore Store { get; } = new();
    public MemoryBackupStorage Storage { get; }
    public TenantKeyProvider Keys { get; }
    public GraphServices Graph { get; }
    public byte[] MasterKey { get; } = RandomNumberGenerator.GetBytes(32);
    public InMemoryObjectStore ExportStore { get; } = new();
    public InMemoryObjectUploads ExportUploads { get; private set; } = null!;
    public NpgsqlDataSource Api { get; private set; } = null!;
    public Vaulty.Infrastructure.Restore.RestoreStore Restores { get; private set; } = null!;
    public Guid Org { get; private set; }
    public Guid Tenant { get; private set; }

    public void StartWorker()
    {
        var activities = new MailboxActivities(DataSource, Graph, new BackupStore(DataSource, TimeProvider.System), Storage, Keys, TimeProvider.System,
            NullLogger<MailboxActivities>.Instance);
        var restores = new Vaulty.Workflows.Restore.RestoreActivities(DataSource, Graph, Restores, Storage, Keys, new MemoryExportStorage(ExportStore, ExportUploads),
            TimeProvider.System, NullLogger<Vaulty.Workflows.Restore.RestoreActivities>.Instance);
        var drives = new DriveActivities(DataSource, Graph, new BackupStore(DataSource, TimeProvider.System), Storage, Keys, TimeProvider.System,
            NullLogger<DriveActivities>.Instance);
        _worker = new TemporalWorker(_fixture.Server.Client, new TemporalWorkerOptions(Queue)
        {
            Interceptors = [new JobMirrorInterceptor()],
            GracefulShutdownTimeout = TimeSpan.Zero,
            StickyQueueScheduleToStartTimeout = TimeSpan.FromSeconds(1),
        }.AddAllActivities(activities).AddAllActivities(new JobActivities(DataSource)).AddWorkflow<MailboxBackupWorkflow>().AddWorkflow<FolderBackupWorkflow>()
          .AddAllActivities(drives).AddWorkflow<DriveBackupWorkflow>().AddWorkflow<DriveSyncWorkflow>()
          .AddAllActivities(restores).AddWorkflow<Vaulty.Workflows.Restore.RestoreWorkflow>());
        _stop = new CancellationTokenSource();
        _running = _worker.ExecuteAsync(_stop.Token);
    }

    /// <summary>Stops the worker abruptly, like a killed process: running activities are abandoned.</summary>
    public async Task KillWorkerAsync()
    {
        if (_stop is null) return;
        await _stop.CancelAsync();
        try
        {
            await _running!;
        }
        catch (OperationCanceledException)
        {
        }
        _worker!.Dispose();
        _stop.Dispose();
        _stop = null;
    }

    public async Task SeedTenantAsync()
    {
        Org = Guid.NewGuid();
        Tenant = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(_fixture.Database.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'O');
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C', 'C');
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name, consent_state, client_id)
                VALUES (@tenant, @org, @customer, @entra, 'T', 'granted', @client);
            INSERT INTO vaulty.policies (id, organization_id, tenant_id, name) VALUES (@policy, @org, @tenant, 'Default');
            """, new { org = Org, customer = Guid.NewGuid(), tenant = Tenant, entra = Guid.NewGuid(), client = Guid.NewGuid(), policy = Guid.NewGuid() });
    }

    public async Task<Guid> SeedMailboxAsync(string mailboxId = MailboxSimulator.MailboxId)
    {
        var id = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(_fixture.Database.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name, source_details)
            VALUES (@id, @org, @tenant, 'mailbox', 'user', @source, 'Mailbox', @details::jsonb)
            """, new { id, org = Org, tenant = Tenant, source = $"{MailboxSimulator.UserId}|{id:N}", details = JsonSerializer.Serialize(new { mailbox_id = mailboxId }) });
        return id;
    }

    public async Task<Guid> SeedDriveAsync(string driveId)
    {
        var id = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(_fixture.Database.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name)
            VALUES (@id, @org, @tenant, 'drive', 'onedrive', @driveId, 'OneDrive')
            """, new { id, org = Org, tenant = Tenant, driveId });
        return id;
    }

    public async Task<(BackupOutcome Outcome, Guid SnapshotId)> DriveBackupAsync(Guid objectId)
    {
        var jobId = await JobRecords.CreateAsync(DataSource, Org, Vaulty.Core.Domain.JobKind.Backup, Tenant, objectId, null);
        var input = new BackupInput(jobId, Org, Tenant, objectId, Guid.CreateVersion7());
        var handle = await _fixture.Server.Client.StartWorkflowAsync((DriveBackupWorkflow w) => w.RunAsync(input),
            new WorkflowOptions(BackupStarter.WorkflowId(objectId), Queue) { ExecutionTimeout = TimeSpan.FromMinutes(10) });
        return (await handle.GetResultAsync(), input.SnapshotId);
    }

    public async Task<(BackupOutcome Outcome, Guid SnapshotId)> BackupAsync(Guid objectId, Func<WorkflowHandle<MailboxBackupWorkflow, BackupOutcome>, Task>? whileRunning = null)
    {
        var jobId = await JobRecords.CreateAsync(DataSource, Org, Vaulty.Core.Domain.JobKind.Backup, Tenant, objectId, null);
        var input = new BackupInput(jobId, Org, Tenant, objectId, Guid.CreateVersion7());
        var handle = await _fixture.Server.Client.StartWorkflowAsync((MailboxBackupWorkflow w) => w.RunAsync(input),
            new WorkflowOptions(BackupStarter.WorkflowId(objectId), Queue) { ExecutionTimeout = TimeSpan.FromMinutes(10) });
        if (whileRunning is not null) await whileRunning(handle);
        return (await handle.GetResultAsync(), input.SnapshotId);
    }

    /// <summary>Every item in the snapshot as stored in object storage: (source id, kind, content hash, bytes match the source).</summary>
    public async Task<List<(string SourceId, string Kind, string Metadata, string ContentHash)>> ReadSnapshotAsync(Guid objectId, Guid snapshotId,
        bool compareWithSource = true)
    {
        using var keys = await Keys.GetAsync(Org, Tenant);
        var reader = new RepositoryReader(Store, keys, new PostgresChunkIndex(DataSource, Org, Tenant));
        var root = await reader.ReadSnapshotAsync(objectId, snapshotId);
        var entries = new List<(string, string, string, string)>();
        foreach (var manifestId in root.ManifestIds)
        {
            foreach (var entry in (await reader.ReadManifestAsync(manifestId)).Entries)
            {
                if (entry.Content is not null && compareWithSource && _source(entry.SourceId) is { } source)
                {
                    using var buffer = new MemoryStream();
                    await reader.ReadContentAsync(entry.Content, buffer);
                    Assert.Equal(source, buffer.ToArray());
                }
                entries.Add((entry.SourceId, entry.Kind, entry.MetadataJson, entry.Content?.ContentHashHex ?? ""));
            }
        }
        return entries;
    }

    public Vaulty.Infrastructure.Access.UserAccess Access(Guid? user = null, params string[] permissions) =>
        new(user ?? AdminUser, Org, true, (permissions.Length == 0 ? Vaulty.Core.Security.Permissions.All.Select(p => p.Key) : permissions)
            .ToDictionary(p => p, _ => (HashSet<Guid>?)null));

    public Guid AdminUser { get; } = Guid.NewGuid();

    public Vaulty.Infrastructure.Restore.RestoreService RestoreService()
    {
        var keys = new TenantKeyProvider(Api, new StaticMasterKeySource(MasterKey), Storage, TimeProvider.System);
        var browser = new Vaulty.Infrastructure.Browse.SnapshotBrowser(Api, keys, new Vaulty.Integration.Tests.Browse.StoreReaders(Store, Api, keys));
        return new Vaulty.Infrastructure.Restore.RestoreService(Api, browser, TimeProvider.System);
    }

    /// <summary>Requests a restore or export as the web app does, starts the workflow on the test queue and returns its handle.</summary>
    public async Task<(Guid RestoreId, WorkflowHandle<Vaulty.Workflows.Restore.RestoreWorkflow, Vaulty.Workflows.Restore.RestoreOutcome> Handle)> StartRestoreAsync(
        Guid objectId, Guid snapshotId, Vaulty.Infrastructure.Restore.RestoreSelection selection, string mode = "restore_folder", Guid? target = null,
        string conflict = "rename")
    {
        var created = await RestoreService().CreateAsync(Access(), stepUpFresh: true,
            new Vaulty.Infrastructure.Restore.RestoreRequest(objectId, snapshotId, selection, mode, target, conflict));
        var input = new Vaulty.Workflows.Restore.RestoreInput(created.JobId, Org, Tenant, created.RestoreId, created.IsExport);
        var handle = await _fixture.Server.Client.StartWorkflowAsync((Vaulty.Workflows.Restore.RestoreWorkflow w) => w.RunAsync(input, false),
            new WorkflowOptions($"restore-{created.RestoreId:N}", Queue) { ExecutionTimeout = TimeSpan.FromMinutes(10) });
        return (created.RestoreId, handle);
    }

    public async Task<(Guid RestoreId, Vaulty.Workflows.Restore.RestoreOutcome Outcome)> RestoreAsync(Guid objectId, Guid snapshotId,
        Vaulty.Infrastructure.Restore.RestoreSelection selection, string mode = "restore_folder", Guid? target = null, string conflict = "rename")
    {
        var (id, handle) = await StartRestoreAsync(objectId, snapshotId, selection, mode, target, conflict);
        return (id, await handle.GetResultAsync());
    }

    public async ValueTask DisposeAsync()
    {
        await HistoryCapture.CaptureAsync(_fixture.Server.Client, Queue);
        await KillWorkerAsync();
        await DataSource.DisposeAsync();
        await Api.DisposeAsync();
    }
}

public sealed class MailboxBackupTests(TemporalFixture fixture, ITestOutputHelper output) : IClassFixture<TemporalFixture>
{
    [TemporalFact]
    public async Task A_cancelled_backup_closes_its_snapshot_and_its_job_says_cancelled()
    {
        using var simulator = new MailboxSimulator(items: 400, seed: 21);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();
        // Cancelled as soon as it runs; whatever step it is in, the snapshot must not stay staged.
        var cancelled = await Assert.ThrowsAnyAsync<Exception>(() => harness.BackupAsync(mailbox, async handle => await handle.CancelAsync()));
        Assert.True(Temporalio.Exceptions.TemporalException.IsCanceledException(cancelled) || cancelled is Temporalio.Exceptions.WorkflowFailedException,
            cancelled.GetType().Name);
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.snapshots WHERE protected_object_id = @mailbox AND state = 'staged'", new { mailbox }));
        var snapshot = await owner.QuerySingleAsync<(string State, string Exceptions)>(
            "SELECT state, exceptions::text FROM vaulty.snapshots WHERE protected_object_id = @mailbox", new { mailbox });
        Assert.Equal("failed", snapshot.State);
        Assert.Contains("cancelled", snapshot.Exceptions, StringComparison.Ordinal);
        Assert.Equal("cancelled", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.jobs WHERE protected_object_id = @mailbox", new { mailbox }));
        // A choice, not a fault: no critical alert.
        Assert.Equal(0, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.alerts WHERE protected_object_id = @mailbox AND kind = 'backup.failed'", new { mailbox }));

        // The next run backs the mailbox up normally.
        var (next, _) = await harness.BackupAsync(mailbox);
        Assert.False(next.IsPartial);
    }

    [Fact]
    public async Task A_step_without_progress_of_its_own_heartbeats_until_it_ends()
    {
        // A commit that ran longer than the heartbeat timeout was declared dead and started again while still running.
        var beats = 0;
        var result = await Vaulty.Workflows.Heartbeats.WhileRunningAsync(() => Interlocked.Increment(ref beats), async () =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(400));
            return 42;
        }, TimeSpan.FromMilliseconds(50));
        Assert.Equal(42, result);
        Assert.True(beats >= 4, $"{beats} heartbeats during the step");
        var after = beats;
        await Task.Delay(TimeSpan.FromMilliseconds(200));
        Assert.Equal(after, beats);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Vaulty.Workflows.Heartbeats.WhileRunningAsync<int>(() => { },
            () => throw new InvalidOperationException("commit failed"), TimeSpan.FromMilliseconds(50)));
    }

    [TemporalFact]
    public async Task Every_run_of_a_protected_object_records_its_own_job_under_the_same_workflow_id()
    {
        // The scheduler gives every run of an object the same workflow id; the second run must record and finish its job like
        // the first (a unique workflow id per job made every run after the first wait forever to record its start).
        using var simulator = new MailboxSimulator(items: 12, seed: 3);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();
        var (first, _) = await harness.BackupAsync(mailbox);
        simulator.Add("f-inbox");
        var (second, _) = await harness.BackupAsync(mailbox);
        Assert.False(first.IsPartial || second.IsPartial);
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        var jobs = (await owner.QueryAsync<(string State, string WorkflowId, string RunId)>(
            "SELECT state, workflow_id, workflow_run_id FROM vaulty.jobs WHERE protected_object_id = @mailbox ORDER BY created_at", new { mailbox })).ToList();
        Assert.Equal(2, jobs.Count);
        Assert.All(jobs, j => Assert.Equal("succeeded", j.State));
        Assert.Equal(jobs[0].WorkflowId, jobs[1].WorkflowId);
        Assert.NotEqual(jobs[0].RunId, jobs[1].RunId);
        // Only the first backup knows its size beforehand, for the progress bar; an incremental run does not guess.
        var expected = (await owner.QueryAsync<long?>(
            "SELECT (progress->>'expected_items')::bigint FROM vaulty.jobs WHERE protected_object_id = @mailbox ORDER BY created_at", new { mailbox })).ToList();
        Assert.True(expected[0] > 0, "the first backup records how many items it expects");
        Assert.Null(expected[1]);
    }

    [TemporalFact]
    public async Task A_full_backup_and_three_incremental_runs_match_the_source_item_for_item()
    {
        using var simulator = new MailboxSimulator(items: 180);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();

        var random = new Random(5);
        for (var run = 0; run < 4; run++)
        {
            if (run > 0)
            {
                // Between runs: new mail, changed items, deleted items, in several folders.
                for (var i = 0; i < 12; i++) simulator.Add(simulator.Folders[random.Next(simulator.Folders.Count)].Id, random.Next(500, 20_000));
                foreach (var id in simulator.Items.Keys.OrderBy(_ => random.Next()).Take(6).ToList()) simulator.Change(id);
                foreach (var id in simulator.Items.Keys.OrderBy(_ => random.Next()).Take(4).ToList()) simulator.Remove(id);
            }
            var (outcome, snapshotId) = await harness.BackupAsync(mailbox);
            Assert.False(outcome.IsPartial, $"run {run}: partial with {outcome.Exceptions} exceptions");
            Assert.Equal(simulator.Items.Count, outcome.ItemCounts["items"]);

            var entries = await harness.ReadSnapshotAsync(mailbox, snapshotId);
            var items = entries.Where(e => e.Kind != "folder").ToList();
            Assert.Equal(simulator.Items.Keys.Order(StringComparer.Ordinal), items.Select(e => e.SourceId).Order(StringComparer.Ordinal));
            foreach (var folder in simulator.Folders)
            {
                Assert.Equal(simulator.CountIn(folder.Id), items.Count(e => simulator.Items[e.SourceId].FolderId == folder.Id));
            }
            output.WriteLine($"run {run}: {items.Count} items, snapshot {snapshotId}");
        }

        // Delta links are stored only after commit, per folder; the job mirror shows the last run with exact counts.
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        var deltaState = await owner.ExecuteScalarAsync<string>("SELECT delta_state::text FROM vaulty.protected_objects WHERE id = @mailbox", new { mailbox });
        Assert.All(simulator.Folders, f => Assert.Contains(f.Id, deltaState, StringComparison.Ordinal));
        Assert.Equal(4, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.jobs WHERE protected_object_id = @mailbox AND state = 'succeeded'", new { mailbox }));
        Assert.Equal(4, await owner.ExecuteScalarAsync<int>("SELECT count(*) FROM vaulty.snapshots WHERE protected_object_id = @mailbox AND state = 'committed'", new { mailbox }));
    }

    [TemporalFact]
    public async Task Five_failing_items_make_the_snapshot_partial_with_exactly_those_five()
    {
        using var simulator = new MailboxSimulator(items: 60, seed: 9);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();

        var failing = simulator.Items.Keys.OrderBy(k => k, StringComparer.Ordinal).Take(5).ToHashSet(StringComparer.Ordinal);
        simulator.FailingExports.UnionWith(failing);
        var (outcome, snapshotId) = await harness.BackupAsync(mailbox);
        Assert.True(outcome.IsPartial);
        Assert.Equal(5, outcome.Exceptions);
        Assert.Equal(simulator.Items.Count - 5, outcome.ItemCounts["items"]);

        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        var snapshot = await owner.QuerySingleAsync<(string State, string Exceptions)>(
            "SELECT state, exceptions::text FROM vaulty.snapshots WHERE id = @snapshotId", new { snapshotId });
        Assert.Equal("partial", snapshot.State);
        using var exceptions = JsonDocument.Parse(snapshot.Exceptions);
        Assert.Equal(failing.Order(StringComparer.Ordinal), exceptions.RootElement.EnumerateArray().Select(e => e.GetProperty("SourceId").GetString()!).Order(StringComparer.Ordinal));
        Assert.Equal("partial", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.jobs WHERE protected_object_id = @mailbox", new { mailbox }));

        // A message whose full-fidelity export fails but whose MIME works is kept, marked limited fidelity.
        simulator.FailingExports.Clear();
        var limited = simulator.Add("f-inbox");
        simulator.FailingExports.Add(limited.Id);
        simulator.MimeAlsoFails = false;
        var (second, _) = await harness.BackupAsync(mailbox);
        Assert.False(second.IsPartial, $"{second.Exceptions} exceptions");
        Assert.True(await owner.ExecuteScalarAsync<bool>("SELECT limited_fidelity FROM vaulty.items WHERE source_id = @id", new { id = limited.Id }));
    }

    [TemporalFact]
    public async Task Throttling_makes_the_run_slower_but_it_succeeds()
    {
        using var simulator = new MailboxSimulator(items: 80, seed: 3) { ThrottleEvery = 3 };
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();
        var (outcome, _) = await harness.BackupAsync(mailbox);
        Assert.False(outcome.IsPartial);
        Assert.Equal(simulator.Items.Count, outcome.ItemCounts["items"]);
        Assert.True(simulator.Throttled > 3, $"only {simulator.Throttled} throttled responses");
        Assert.True(harness.Graph.Throttle.ThrottledResponses(harness.Tenant) >= simulator.Throttled - 1);
        output.WriteLine($"{simulator.Throttled} requests throttled, run succeeded with {outcome.ItemCounts["items"]} items");
    }

    [TemporalFact]
    public async Task A_worker_killed_during_the_run_ends_in_the_same_snapshot_content()
    {
        using var simulator = new MailboxSimulator(items: 300, seed: 21);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var quiet = await harness.SeedMailboxAsync();
        var disturbed = await harness.SeedMailboxAsync();
        harness.StartWorker();
        var (_, quietSnapshot) = await harness.BackupAsync(quiet);

        var random = new Random(11);
        var kills = 0;
        var (outcome, disturbedSnapshot) = await harness.BackupAsync(disturbed, async handle =>
        {
            for (var i = 0; i < 5; i++)
            {
                await Task.Delay(random.Next(150, 700));
                var description = await handle.DescribeAsync();
                if (description.Status != Temporalio.Api.Enums.V1.WorkflowExecutionStatus.Running) break;
                await harness.KillWorkerAsync();
                kills++;
                await Task.Delay(random.Next(100, 400));
                harness.StartWorker();
            }
        });
        output.WriteLine($"{kills} worker kills during the run");
        Assert.False(outcome.IsPartial);
        var a = await harness.ReadSnapshotAsync(quiet, quietSnapshot);
        var b = await harness.ReadSnapshotAsync(disturbed, disturbedSnapshot);
        Assert.Equal(a.OrderBy(e => e.SourceId, StringComparer.Ordinal), b.OrderBy(e => e.SourceId, StringComparer.Ordinal));
        Assert.True(kills > 0, "the run finished before the first kill");
    }
}
