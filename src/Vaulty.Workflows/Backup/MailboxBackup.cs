using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Npgsql;
using Temporalio.Activities;
using Temporalio.Exceptions;
using Temporalio.Workflows;
using Vaulty.Connectors.Exchange;
using Vaulty.Core.Domain;
using Vaulty.Graph;
using Vaulty.Graph.Http;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Vaulty.Workflows.Jobs;

namespace Vaulty.Workflows.Backup;

public sealed record BackupInput(Guid JobId, Guid OrganizationId, Guid TenantId, Guid ProtectedObjectId, Guid SnapshotId) : IJobInput
{
    public JobKind JobKind => JobKind.Backup;

    public BackupTarget Target => new(OrganizationId, TenantId, ProtectedObjectId, SnapshotId);
}

public sealed record FolderPlan(string Id, string Name, string? ParentId, string? Type, long SourceCount);

public sealed record MailboxPlan(string MailboxId, string UserId, List<FolderPlan> Folders);

public sealed record FolderSyncInput(BackupInput Backup, string MailboxId, string UserId, string FolderId, int PagesPerRun);

public sealed record CommitInput(BackupInput Backup, List<FolderPlan> Folders);

public sealed record BackupOutcome(Dictionary<string, long> ItemCounts, bool IsPartial, int Exceptions) : IJobResult
{
    public IReadOnlyDictionary<string, long> Counts => ItemCounts;
    public bool Partial => IsPartial;
}

/// <summary>
/// Backs up one mailbox: folders, then one child workflow per folder (in windows, because the server limits pending
/// children per workflow), then the atomic commit. Delta links are stored only by the commit; a crash at any point leaves
/// the previous snapshot as it was and the next run continues from the page checkpoints.
/// </summary>
[Workflow]
public sealed class MailboxBackupWorkflow
{
    public const int ChildWindow = 50;

    [WorkflowRun]
    public async Task<BackupOutcome> RunAsync(BackupInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        try
        {
            var plan = await Workflow.ExecuteActivityAsync((MailboxActivities a) => a.PrepareAsync(input), ActivityPolicies.External(TimeSpan.FromMinutes(30)));
            foreach (var window in plan.Folders.Chunk(ChildWindow))
            {
                var children = window.Select(folder => Workflow.ExecuteChildWorkflowAsync((FolderBackupWorkflow w) =>
                        w.RunAsync(new FolderSyncInput(input, plan.MailboxId, plan.UserId, folder.Id, 50)),
                    new ChildWorkflowOptions { Id = $"{Workflow.Info.WorkflowId}/{input.SnapshotId:N}/{Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(folder.Id)))[..16]}" })).ToList();
                await Workflow.WhenAllAsync(children);
            }
            return await Workflow.ExecuteActivityAsync((MailboxActivities a) => a.CommitAsync(new CommitInput(input, plan.Folders)),
                ActivityPolicies.External(TimeSpan.FromHours(2)));
        }
        catch (Exception ex) when (ex is not ContinueAsNewException && !TemporalException.IsCanceledException(ex))
        {
            await Workflow.ExecuteActivityAsync((MailboxActivities a) => a.FailAsync(input, ex.Message), ActivityPolicies.Database());
            throw;
        }
    }
}

/// <summary>Synchronizes one folder page by page from its checkpoint; continues as new to keep its history small.</summary>
[Workflow]
public sealed class FolderBackupWorkflow
{
    [WorkflowRun]
    public async Task RunAsync(FolderSyncInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        for (var page = 0; ; page++)
        {
            if (page >= input.PagesPerRun) throw Workflow.CreateContinueAsNewException((FolderBackupWorkflow w) => w.RunAsync(input));
            var done = await Workflow.ExecuteActivityAsync((MailboxActivities a) => a.SyncFolderPageAsync(input), ActivityPolicies.External(TimeSpan.FromMinutes(30)));
            if (done) return;
        }
    }
}

/// <summary>Metadata of an item version, stored sealed in the database and in plain form inside the encrypted manifest.</summary>
public sealed record ItemMetadataDocument(
    [property: JsonPropertyName("type")] string? Type,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("created")] DateTimeOffset? Created,
    [property: JsonPropertyName("modified")] DateTimeOffset? Modified,
    [property: JsonPropertyName("categories")] IReadOnlyList<string> Categories,
    [property: JsonPropertyName("subject")] string? Subject,
    [property: JsonPropertyName("from")] string? From,
    [property: JsonPropertyName("to")] IReadOnlyList<string> To,
    [property: JsonPropertyName("received")] DateTimeOffset? Received,
    [property: JsonPropertyName("has_attachments")] bool HasAttachments,
    [property: JsonPropertyName("is_read")] bool? IsRead,
    [property: JsonPropertyName("flag")] string? Flag,
    [property: JsonPropertyName("preview")] string? Preview,
    [property: JsonPropertyName("folder")] string? FolderName = null);

public sealed class MailboxActivities(NpgsqlDataSource dataSource, GraphServices graph, BackupStore store, IBackupStorage storage,
    TenantKeyProvider keys, TimeProvider clock, ILogger<MailboxActivities> logger)
{
    /// <summary>Total size of one export call; with up to 20 items, this bounds the memory of one batch.</summary>
    public const long ExportBatchBytes = 32L * 1024 * 1024;

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.Never };

    private ExchangeClient Exchange => new(graph.Client);

    [Activity]
    public async Task<MailboxPlan> PrepareAsync(BackupInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var target = input.Target;
        await store.PrepareSnapshotAsync(target, context.CancellationToken);
        var (mailboxId, userId) = await MailboxOfAsync(input, context.CancellationToken);
        var policy = await PolicyResolver.ForObjectAsync(dataSource, input.OrganizationId, input.TenantId, input.ProtectedObjectId, context.CancellationToken);
        var repositoryKeys = await keys.GetAsync(input.OrganizationId, input.TenantId, context.CancellationToken);

        var folders = new List<MailboxFolderInfo>();
        await foreach (var folder in Exchange.FoldersAsync(new GraphRequestContext(input.TenantId, mailboxId, "mail"), mailboxId, context.CancellationToken))
        {
            folders.Add(folder);
            context.Heartbeat();
        }

        // Folders are versioned like items: a renamed or moved folder is a new version; a folder that disappeared is removed.
        var current = await store.CurrentVersionsAsync(target, folders.Select(f => f.Id).ToList(), context.CancellationToken);
        var versions = folders.Select(f => new ItemVersion(f.Id, f.ParentFolderId, "folder", FolderKey(f), 0, null, null,
                JsonSerializer.Serialize(new { name = f.DisplayName, type = f.Type, well_known_name = f.WellKnownName }, Json)))
            .Where(v => !current.TryGetValue(v.SourceId, out var c) || c.ChangeKey != v.ChangeKey).ToList();
        await store.StageVersionsAsync(target, repositoryKeys, versions, context.CancellationToken);
        await StageVanishedFoldersAsync(target, folders, context.CancellationToken);

        var included = folders.Where(f => f.WellKnownName is null || !policy.ExcludedFolders.Contains(f.WellKnownName)).ToList();
        return new MailboxPlan(mailboxId, userId, included.Select(f => new FolderPlan(f.Id, f.DisplayName ?? f.Id, f.ParentFolderId, f.Type, f.TotalItemCount)).ToList());
    }

    /// <summary>
    /// One page of a folder's item delta: removals are staged, new and changed items are exported in batches of at most
    /// 20 items and 32 MB, stored through the repository engine and staged; then the page checkpoint moves on. Returns true
    /// when the folder is complete. Running it again for the same page changes nothing.
    /// </summary>
    [Activity]
    public async Task<bool> SyncFolderPageAsync(FolderSyncInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var ct = context.CancellationToken;
        var target = input.Backup.Target;
        var checkpoint = await store.CheckpointAsync(target, input.FolderId, ct);
        if (checkpoint.Completed) return true;

        var graphContext = new GraphRequestContext(input.Backup.TenantId, input.MailboxId, "mail");
        var link = checkpoint.PageCursor ?? (checkpoint.NextPage == 0 ? await store.CommittedDeltaLinkAsync(target, input.FolderId, ct) : null);
        var resync = checkpoint.Resynced;
        GraphDeltaPage<MailboxItemChange> page;
        try
        {
            page = await Exchange.ItemDeltaAsync(graphContext, input.MailboxId, input.FolderId, link, ct);
        }
        catch (DeltaResyncRequiredException) when (link is not null)
        {
            // The delta token expired: list the folder again from the start. Unchanged items are recognized by their change key.
            logger.LogWarning("Delta of a folder needs a resync; listing it again");
            page = await Exchange.ItemDeltaAsync(graphContext, input.MailboxId, input.FolderId, null, ct);
            resync = true;
        }
        catch (GraphException ex) when (ex.Status is System.Net.HttpStatusCode.BadRequest or System.Net.HttpStatusCode.NotFound or System.Net.HttpStatusCode.Forbidden)
        {
            // A folder that cannot be read (for example a search folder) is reported, not hidden.
            await store.RecordFailureAsync(target, $"folder:{input.FolderId}", input.FolderId, "folder_unreadable", $"{(int)ex.Status} {ex.Code}", ct);
            await store.SaveCheckpointAsync(target, input.FolderId, new FolderCheckpoint(null, null, true, resync, checkpoint.NextPage + 1), ct);
            return true;
        }
        context.Heartbeat();

        await store.StageRemovalsAsync(target, page.Items.Where(i => i.IsRemoved).Select(i => i.Id).ToList(), ct);
        var changes = page.Items.Where(i => !i.IsRemoved).ToList();
        if (page.DeltaLink is not null)
        {
            // Last page: items that failed in earlier runs are not in the delta any more; try them again.
            var seen = changes.Select(c => c.Id).ToHashSet(StringComparer.Ordinal);
            changes.AddRange((await store.OpenFailuresAsync(target, input.FolderId, ct)).Where(f => !seen.Contains(f.SourceId))
                .Select(f => new MailboxItemChange { Id = f.SourceId, Type = f.ItemType }));
        }
        var current = await store.CurrentVersionsAsync(target, changes.Select(c => c.Id).ToList(), ct);
        var fetch = changes.Where(c => !current.TryGetValue(c.Id, out var v) || v.ChangeKey != c.ChangeKey).ToList();
        var poisoned = await store.PoisonedAsync(target, fetch.Select(f => f.Id).ToList(), ct);
        fetch = fetch.Where(f => !poisoned.Contains(f.Id)).ToList();

        if (fetch.Count > 0)
        {
            var repositoryKeys = await keys.GetAsync(input.Backup.OrganizationId, input.Backup.TenantId, ct);
            var policy = await PolicyResolver.ForObjectAsync(dataSource, input.Backup.OrganizationId, input.Backup.TenantId, input.Backup.ProtectedObjectId, ct);
            var objectStore = await storage.WorkerStoreAsync(ct);
            var writer = new RepositoryWriter(objectStore, repositoryKeys, new PostgresChunkIndex(dataSource, input.Backup.OrganizationId, input.Backup.TenantId),
                new RepositoryWriterOptions { LockUntil = policy.LockUntil(clock.GetUtcNow()), PackTargetSize = 16 * 1024 * 1024 });
            var metadata = await Exchange.MetadataAsync(graphContext, input.UserId, fetch.Select(f => (f.Id, f.Type)).ToList(), ct);
            var versions = new List<ItemVersion>();
            foreach (var batch in Batches(fetch))
            {
                await ExportBatchAsync(input, graphContext, target, writer, batch, metadata, versions, ct);
                context.Heartbeat();
            }
            await writer.FlushAsync(ct);
            await store.StageVersionsAsync(target, repositoryKeys, versions, ct);
        }

        var completed = page.DeltaLink is not null;
        await store.SaveCheckpointAsync(target, input.FolderId, new FolderCheckpoint(page.NextLink, page.DeltaLink, completed, resync, checkpoint.NextPage + 1), ct);
        return completed;
    }

    private async Task ExportBatchAsync(FolderSyncInput input, GraphRequestContext graphContext, BackupTarget target, RepositoryWriter writer,
        IReadOnlyList<MailboxItemChange> batch, IReadOnlyDictionary<string, ItemMetadata> metadata, List<ItemVersion> versions, CancellationToken ct)
    {
        IReadOnlyList<ExportedItem> exported;
        try
        {
            exported = await Exchange.ExportAsync(graphContext, input.MailboxId, batch.Select(b => b.Id).ToList(), ct);
        }
        catch (GraphException ex) when (batch.Count > 1 && (int)ex.Status is >= 400 and < 500)
        {
            // One bad item fails the whole call: export the items one by one to isolate it.
            foreach (var single in batch) await ExportBatchAsync(input, graphContext, target, writer, [single], metadata, versions, ct);
            return;
        }
        catch (GraphException ex) when ((int)ex.Status is >= 400 and < 500)
        {
            await FallbackOrFailAsync(input, graphContext, target, writer, batch[0], metadata, versions, ex.Code ?? ((int)ex.Status).ToString(System.Globalization.CultureInfo.InvariantCulture), ex.Message, ct);
            return;
        }

        var byId = exported.ToDictionary(e => e.ItemId, StringComparer.Ordinal);
        foreach (var item in batch)
        {
            if (!byId.TryGetValue(item.Id, out var result) || result.Data is null)
            {
                var code = result?.Error?.Code ?? "missing_from_export";
                await FallbackOrFailAsync(input, graphContext, target, writer, item, metadata, versions, code, result?.Error?.Message, ct);
                continue;
            }
            await using var stream = new MemoryStream(Convert.FromBase64String(result.Data), writable: false);
            var content = await writer.WriteAsync(stream, ct);
            versions.Add(Version(input, item, content, metadata, limitedFidelity: false));
        }
    }

    /// <summary>Messages that cannot be exported in full fidelity fall back to MIME, marked as limited fidelity; anything else is a failure.</summary>
    private async Task FallbackOrFailAsync(FolderSyncInput input, GraphRequestContext graphContext, BackupTarget target, RepositoryWriter writer,
        MailboxItemChange item, IReadOnlyDictionary<string, ItemMetadata> metadata, List<ItemVersion> versions, string code, string? detail, CancellationToken ct)
    {
        if (ExchangeClient.Kind(item.Type) == "mail" && code is not "missing_from_export")
        {
            try
            {
                await using var mime = await Exchange.MimeAsync(graphContext, input.UserId, item.Id, ct);
                var content = await writer.WriteAsync(mime, ct);
                versions.Add(Version(input, item, content, metadata, limitedFidelity: true));
                return;
            }
            catch (GraphException)
            {
                // fall through to the failure record
            }
        }
        await store.RecordFailureAsync(target, item.Id, input.FolderId, code, detail, ct, item.Type);
    }

    private static ItemVersion Version(FolderSyncInput input, MailboxItemChange item, ItemContent content, IReadOnlyDictionary<string, ItemMetadata> metadata,
        bool limitedFidelity)
    {
        metadata.TryGetValue(item.Id, out var meta);
        var document = new ItemMetadataDocument(item.Type, item.Size, item.CreatedDateTime, item.LastModifiedDateTime, item.Categories ?? meta?.Categories.ToList() ?? [],
            meta?.Subject, meta?.From, meta?.To ?? [], meta?.Received, meta?.HasAttachments ?? false, meta?.IsRead, meta?.Flag, meta?.BodyPreview);
        return new ItemVersion(item.Id, input.FolderId, ExchangeClient.Kind(item.Type), item.ChangeKey, item.Size, item.LastModifiedDateTime, content,
            JsonSerializer.Serialize(document, Json), limitedFidelity);
    }

    [Activity]
    public async Task<BackupOutcome> CommitAsync(CommitInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var backup = input.Backup;
        var repositoryKeys = await keys.GetAsync(backup.OrganizationId, backup.TenantId, context.CancellationToken);
        var policy = await PolicyResolver.ForObjectAsync(dataSource, backup.OrganizationId, backup.TenantId, backup.ProtectedObjectId, context.CancellationToken);
        var objectStore = await storage.WorkerStoreAsync(context.CancellationToken);
        var index = new PostgresChunkIndex(dataSource, backup.OrganizationId, backup.TenantId);
        var writer = new RepositoryWriter(objectStore, repositoryKeys, index, new RepositoryWriterOptions { LockUntil = policy.LockUntil(clock.GetUtcNow()) });
        var reader = new RepositoryReader(objectStore, repositoryKeys, index);
        var result = await store.CommitAsync(backup.Target, repositoryKeys, writer, reader,
            input.Folders.Select(f => new FolderCount(f.Id, f.Name, f.SourceCount)).ToList(), policy.LockUntil(clock.GetUtcNow()),
            TimeSpan.FromMinutes(policy.FrequencyMinutes), context.CancellationToken);
        return new BackupOutcome(result.Counts, result.Partial, result.Exceptions.Count);
    }

    [Activity]
    public Task FailAsync(BackupInput input, string reason)
    {
        ArgumentNullException.ThrowIfNull(input);
        return store.FailAsync(input.Target, reason);
    }

    private async Task<(string MailboxId, string UserId)> MailboxOfAsync(BackupInput input, CancellationToken ct)
    {
        await using var session = await Infrastructure.Database.OrganizationSession.BeginAsync(dataSource, input.OrganizationId, ct);
        var row = await Dapper.SqlMapper.QuerySingleAsync<(string SourceId, string Details)>(session.Connection, new Dapper.CommandDefinition(
            "SELECT source_id, source_details::text FROM vaulty.protected_objects WHERE id = @id", new { id = input.ProtectedObjectId }, session.Transaction,
            cancellationToken: ct));
        using var details = JsonDocument.Parse(row.Details);
        var mailboxId = details.RootElement.TryGetProperty("mailbox_id", out var m) ? m.GetString() : null;
        if (mailboxId is null) throw new ApplicationFailureException("The mailbox has no mailbox id; run discovery again.", ErrorTypes.NonRetryable, nonRetryable: true);
        return (mailboxId, row.SourceId.Split('|')[0]);
    }

    private async Task StageVanishedFoldersAsync(BackupTarget target, IReadOnlyList<MailboxFolderInfo> folders, CancellationToken ct)
    {
        await using var session = await Infrastructure.Database.OrganizationSession.BeginAsync(dataSource, target.OrganizationId, ct);
        var present = folders.Select(f => f.Id).ToArray();
        var vanished = (await Dapper.SqlMapper.QueryAsync<string>(session.Connection, new Dapper.CommandDefinition(
            """
            SELECT source_id FROM vaulty.items
             WHERE tenant_id = @TenantId AND protected_object_id = @ProtectedObjectId AND deleted_in_snapshot_id IS NULL AND state = 'committed'
               AND (kind = 'folder' AND NOT (source_id = ANY(@present)) OR kind <> 'folder' AND NOT (parent_source_id = ANY(@present)))
            """, new { target.TenantId, target.ProtectedObjectId, present }, session.Transaction, cancellationToken: ct))).ToList();
        await session.DisposeAsync();
        await store.StageRemovalsAsync(target, vanished, ct);
    }

    private static string FolderKey(MailboxFolderInfo folder) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{folder.DisplayName}\u001f{folder.ParentFolderId}\u001f{folder.Type}")))[..32];

    /// <summary>Batches of at most 20 items and about 32 MB.</summary>
    internal static IEnumerable<List<MailboxItemChange>> Batches(IEnumerable<MailboxItemChange> items)
    {
        var batch = new List<MailboxItemChange>();
        long bytes = 0;
        foreach (var item in items)
        {
            if (batch.Count > 0 && (batch.Count == GraphClient.MaxExportItems || bytes + item.Size > ExportBatchBytes))
            {
                yield return batch;
                batch = [];
                bytes = 0;
            }
            batch.Add(item);
            bytes += item.Size;
        }
        if (batch.Count > 0) yield return batch;
    }
}
