using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Npgsql;
using Temporalio.Activities;
using Temporalio.Workflows;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Database;
using Vaulty.Workflows.Jobs;

namespace Vaulty.Workflows.Synthetic;

// Synthetic workflows that exercise the patterns of the real backup workflows (page checkpoints in PostgreSQL,
// heartbeats, ContinueAsNew, child workflows per folder, idempotent upserts, Retry-After) without Microsoft Graph.
// They are registered only when Vaulty:Workers:Synthetic is true (tests); production workers never load them.

public sealed record SyntheticBackupInput(
    Guid JobId,
    Guid OrganizationId,
    Guid TenantId,
    Guid ProtectedObjectId,
    Guid SnapshotId,
    int Folders,
    int PagesPerFolder,
    int ItemsPerPage,
    int PageDelayMilliseconds,
    int PagesPerRun) : IJobInput
{
    public JobKind JobKind => JobKind.Backup;
}

public sealed record SyntheticBackupResult(Dictionary<string, long> ItemCounts, bool IsPartial) : IJobResult
{
    public IReadOnlyDictionary<string, long> Counts => ItemCounts;
    public bool Partial => IsPartial;
}

public sealed record FolderSyncInput(
    Guid OrganizationId,
    Guid TenantId,
    Guid ProtectedObjectId,
    Guid SnapshotId,
    string FolderId,
    int TotalPages,
    int ItemsPerPage,
    int PageDelayMilliseconds,
    int PagesPerRun,
    int StartPage);

public sealed record SyncPageInput(
    Guid OrganizationId,
    Guid TenantId,
    Guid ProtectedObjectId,
    Guid SnapshotId,
    string FolderId,
    int Page,
    int ItemsPerPage,
    int PageDelayMilliseconds);

public sealed record CheckpointInput(Guid OrganizationId, Guid SnapshotId, string FolderId);

/// <summary>The backup of one protected object: one child workflow per folder, then the commit.</summary>
[Workflow]
public sealed class SyntheticObjectBackupWorkflow
{
    [WorkflowRun]
    public async Task<SyntheticBackupResult> RunAsync(SyntheticBackupInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var children = new List<Task<long>>();
        for (var f = 0; f < input.Folders; f++)
        {
            var folder = $"folder-{f:D3}";
            children.Add(Workflow.ExecuteChildWorkflowAsync((SyntheticFolderSyncWorkflow w) => w.RunAsync(new FolderSyncInput(
                    input.OrganizationId, input.TenantId, input.ProtectedObjectId, input.SnapshotId, folder, input.PagesPerFolder,
                    input.ItemsPerPage, input.PageDelayMilliseconds, input.PagesPerRun, 0)),
                new ChildWorkflowOptions { Id = $"{Workflow.Info.WorkflowId}/{folder}" }));
        }
        var perFolder = await Workflow.WhenAllAsync(children);
        var committed = await Workflow.ExecuteActivityAsync((SyntheticActivities a) =>
            a.CommitSnapshotAsync(new CheckpointInput(input.OrganizationId, input.SnapshotId, string.Empty)), ActivityPolicies.Database());
        return new SyntheticBackupResult(new Dictionary<string, long>
        {
            ["expected"] = perFolder.Sum(),
            ["stored"] = committed,
        }, IsPartial: committed != perFolder.Sum());
    }
}

/// <summary>Synchronizes one folder page by page, continuing as new after a number of pages to bound its history.</summary>
[Workflow]
public sealed class SyntheticFolderSyncWorkflow
{
    [WorkflowRun]
    public async Task<long> RunAsync(FolderSyncInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        // Resume from the database checkpoint, so even a restarted workflow does not redo committed pages.
        var checkpoint = await Workflow.ExecuteActivityAsync((SyntheticActivities a) =>
            a.GetCheckpointAsync(new CheckpointInput(input.OrganizationId, input.SnapshotId, input.FolderId)), ActivityPolicies.Database());
        var page = Math.Max(input.StartPage, checkpoint);
        var processed = 0;
        while (page < input.TotalPages)
        {
            if (processed >= input.PagesPerRun)
            {
                var next = input with { StartPage = page };
                throw Workflow.CreateContinueAsNewException((SyntheticFolderSyncWorkflow w) => w.RunAsync(next));
            }
            var options = ActivityPolicies.External(TimeSpan.FromMinutes(2));
            options.HeartbeatTimeout = TimeSpan.FromSeconds(3);
            options.RetryPolicy!.InitialInterval = TimeSpan.FromMilliseconds(200);
            options.RetryPolicy.MaximumInterval = TimeSpan.FromSeconds(2);
            options.RetryPolicy.MaximumAttempts = 0;
            await Workflow.ExecuteActivityAsync((SyntheticActivities a) => a.SyncPageAsync(new SyncPageInput(input.OrganizationId,
                input.TenantId, input.ProtectedObjectId, input.SnapshotId, input.FolderId, page, input.ItemsPerPage,
                input.PageDelayMilliseconds)), options);
            page++;
            processed++;
        }
        return (long)input.TotalPages * input.ItemsPerPage;
    }
}

public sealed record FanOutInput(int Parents, int ChildrenPerParent);

/// <summary>
/// Starts many children at once, to measure how many concurrent child workflows one server handles. With Parents &gt; 0
/// it starts that many fan-out children, each with ChildrenPerParent no-op children (two levels, because the server
/// limits pending children per parent).
/// </summary>
[Workflow]
public sealed class SyntheticFanOutWorkflow
{
    [WorkflowRun]
    public async Task<int> RunAsync(FanOutInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.Parents > 0)
        {
            var leaf = new FanOutInput(0, input.ChildrenPerParent);
            var parents = Enumerable.Range(0, input.Parents).Select(p => Workflow.ExecuteChildWorkflowAsync(
                (SyntheticFanOutWorkflow w) => w.RunAsync(leaf), new ChildWorkflowOptions { Id = $"{Workflow.Info.WorkflowId}/{p}" })).ToList();
            return (await Workflow.WhenAllAsync(parents)).Sum();
        }
        var tasks = Enumerable.Range(0, input.ChildrenPerParent).Select(i => Workflow.ExecuteChildWorkflowAsync((SyntheticNoopWorkflow w) => w.RunAsync(i),
            new ChildWorkflowOptions { Id = $"{Workflow.Info.WorkflowId}/{i}" })).ToList();
        return (await Workflow.WhenAllAsync(tasks)).Length;
    }
}

[Workflow]
public sealed class SyntheticNoopWorkflow
{
    [WorkflowRun]
    public Task<int> RunAsync(int value) => Task.FromResult(value);
}

public sealed record StuckActivityInput(Guid OrganizationId, Guid SnapshotId, string FolderId, int StuckSeconds);

/// <summary>Runs an activity whose first attempt hangs without heartbeat, so the engine must reschedule it.</summary>
[Workflow]
public sealed class SyntheticHeartbeatProbeWorkflow
{
    [WorkflowRun]
    public async Task<int> RunAsync(StuckActivityInput input)
    {
        var options = new ActivityOptions
        {
            StartToCloseTimeout = TimeSpan.FromMinutes(2),
            HeartbeatTimeout = TimeSpan.FromSeconds(2),
            RetryPolicy = new() { InitialInterval = TimeSpan.FromMilliseconds(100), MaximumAttempts = 5 },
        };
        return await Workflow.ExecuteActivityAsync((SyntheticActivities a) => a.StuckOnceAsync(input), options);
    }
}

public sealed record ThrottleProbeInput(int RetryAfterSeconds);

/// <summary>An activity that is throttled once with Retry-After; the retry must wait exactly that long.</summary>
[Workflow]
public sealed class SyntheticThrottleProbeWorkflow
{
    [WorkflowRun]
    public async Task<double> RunAsync(ThrottleProbeInput input)
    {
        var options = ActivityPolicies.External(TimeSpan.FromSeconds(30));
        options.RetryPolicy!.InitialInterval = TimeSpan.FromMilliseconds(100);
        return await Workflow.ExecuteActivityAsync((SyntheticActivities a) => a.ThrottledOnceAsync(input), options);
    }
}

public sealed class SyntheticActivities(NpgsqlDataSource dataSource)
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTimeOffset> FirstAttempts = new();

    [Activity]
    public async Task<int> GetCheckpointAsync(CheckpointInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        await using var session = await OrganizationSession.BeginAsync(dataSource, input.OrganizationId).ConfigureAwait(false);
        return await session.Connection.ExecuteScalarAsync<int?>(
            "SELECT next_page FROM vaulty.folder_checkpoints WHERE snapshot_id = @SnapshotId AND folder_id = @FolderId",
            new { input.SnapshotId, input.FolderId }, session.Transaction).ConfigureAwait(false) ?? 0;
    }

    /// <summary>Stores one page of items and the checkpoint in one transaction. Running it twice changes nothing.</summary>
    [Activity]
    public async Task SyncPageAsync(SyncPageInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        // Simulated Graph calls: wait in slices and heartbeat, so a dead worker is detected within the heartbeat timeout.
        var remaining = input.PageDelayMilliseconds;
        while (remaining > 0)
        {
            var slice = Math.Min(remaining, 200);
            await Task.Delay(slice, context.CancellationToken).ConfigureAwait(false);
            remaining -= slice;
            context.Heartbeat(input.Page);
        }

        await using var session = await OrganizationSession.BeginAsync(dataSource, input.OrganizationId, context.CancellationToken)
            .ConfigureAwait(false);
        var rows = Enumerable.Range(0, input.ItemsPerPage).Select(i => new
        {
            org = input.OrganizationId,
            tenant = input.TenantId,
            id = DeterministicId(input.SnapshotId, input.FolderId, input.Page, i),
            obj = input.ProtectedObjectId,
            snapshot = input.SnapshotId,
            source = $"{input.FolderId}/{input.Page:D5}/{i:D3}",
            parent = input.FolderId,
        });
        await session.Connection.ExecuteAsync(
            """
            INSERT INTO vaulty.items (organization_id, tenant_id, id, protected_object_id, first_snapshot_id, source_id, parent_source_id, kind)
            VALUES (@org, @tenant, @id, @obj, @snapshot, @source, @parent, 'synthetic')
            ON CONFLICT (tenant_id, protected_object_id, source_id, first_snapshot_id) DO NOTHING
            """, rows, session.Transaction).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(
            """
            INSERT INTO vaulty.folder_checkpoints (organization_id, tenant_id, snapshot_id, folder_id, next_page)
            VALUES (@OrganizationId, @TenantId, @SnapshotId, @FolderId, @next)
            ON CONFLICT (snapshot_id, folder_id) DO UPDATE
                SET next_page = greatest(vaulty.folder_checkpoints.next_page, excluded.next_page), updated_at = now()
            """, new { input.OrganizationId, input.TenantId, input.SnapshotId, input.FolderId, next = input.Page + 1 },
            session.Transaction).ConfigureAwait(false);
        await session.CommitAsync(context.CancellationToken).ConfigureAwait(false);
    }

    [Activity]
    public async Task<long> CommitSnapshotAsync(CheckpointInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        await using var session = await OrganizationSession.BeginAsync(dataSource, input.OrganizationId).ConfigureAwait(false);
        var tenant = await session.Connection.ExecuteScalarAsync<Guid>(
            "SELECT tenant_id FROM vaulty.snapshots WHERE id = @SnapshotId", new { input.SnapshotId }, session.Transaction).ConfigureAwait(false);
        var count = await session.Connection.ExecuteScalarAsync<long>(
            "SELECT count(*) FROM vaulty.items WHERE tenant_id = @tenant AND first_snapshot_id = @SnapshotId",
            new { tenant, input.SnapshotId }, session.Transaction).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(
            """
            UPDATE vaulty.snapshots SET state = 'committed', committed_at = coalesce(committed_at, now()),
                   manifest_root_hash = coalesce(manifest_root_hash, @hash), item_counts = @counts::jsonb
             WHERE id = @SnapshotId AND state IN ('staged', 'committed')
            """, new { input.SnapshotId, hash = SHA256.HashData(input.SnapshotId.ToByteArray()), counts = JsonSerializer.Serialize(new { items = count }) },
            session.Transaction).ConfigureAwait(false);
        await session.CommitAsync().ConfigureAwait(false);
        return count;
    }

    /// <summary>The first attempt hangs without heartbeat; later attempts succeed. Both write the same row (idempotent).</summary>
    [Activity]
    public async Task<int> StuckOnceAsync(StuckActivityInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        if (context.Info.Attempt == 1)
        {
            // No heartbeat: the engine times the attempt out and schedules attempt 2. This attempt still finishes later.
            await Task.Delay(TimeSpan.FromSeconds(input.StuckSeconds), CancellationToken.None).ConfigureAwait(false);
        }
        await using var session = await OrganizationSession.BeginAsync(dataSource, input.OrganizationId).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(
            """
            INSERT INTO vaulty.folder_checkpoints (organization_id, tenant_id, snapshot_id, folder_id, next_page)
            SELECT @OrganizationId, tenant_id, @SnapshotId, @FolderId, @attempt FROM vaulty.snapshots WHERE id = @SnapshotId
            ON CONFLICT (snapshot_id, folder_id) DO UPDATE SET next_page = greatest(vaulty.folder_checkpoints.next_page, excluded.next_page)
            """, new { input.OrganizationId, input.SnapshotId, input.FolderId, attempt = context.Info.Attempt }, session.Transaction)
            .ConfigureAwait(false);
        await session.CommitAsync().ConfigureAwait(false);
        return context.Info.Attempt;
    }

    [Activity]
    public Task<double> ThrottledOnceAsync(ThrottleProbeInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var key = context.Info.WorkflowId ?? string.Empty;
        if (context.Info.Attempt == 1)
        {
            FirstAttempts[key] = DateTimeOffset.UtcNow;
            throw ActivityPolicies.Throttled(TimeSpan.FromSeconds(input.RetryAfterSeconds));
        }
        return Task.FromResult((DateTimeOffset.UtcNow - FirstAttempts[key]).TotalSeconds);
    }

    private static Guid DeterministicId(Guid snapshot, string folder, int page, int index)
    {
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{snapshot:N}/{folder}/{page}/{index}"));
        return new Guid(hash.AsSpan(0, 16));
    }
}
