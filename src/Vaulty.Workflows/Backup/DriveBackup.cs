using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Npgsql;
using Temporalio.Activities;
using Temporalio.Exceptions;
using Temporalio.Workflows;
using Vaulty.Connectors.Drive;
using Vaulty.Graph;
using Vaulty.Graph.Http;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Repository.Engine;

namespace Vaulty.Workflows.Backup;

public sealed record DrivePlan(string DriveId, string RootId);

/// <summary>
/// Backs up one drive: the drive delta page by page (each page is one activity: changed files are streamed through the
/// repository engine and checked against their hash), then the same atomic commit as mailboxes.
/// </summary>
[Workflow]
public sealed class DriveBackupWorkflow
{
    public const int PagesPerRun = 100;

    [WorkflowRun]
    public async Task<BackupOutcome> RunAsync(BackupInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        try
        {
            var plan = await Workflow.ExecuteActivityAsync((DriveActivities a) => a.PrepareAsync(input), ActivityPolicies.External(TimeSpan.FromMinutes(10)));
            await Workflow.ExecuteChildWorkflowAsync((DriveSyncWorkflow w) => w.RunAsync(input, plan.DriveId),
                new ChildWorkflowOptions { Id = $"{Workflow.Info.WorkflowId}/{input.SnapshotId:N}/sync" });
            return await Workflow.ExecuteActivityAsync((DriveActivities a) => a.CommitAsync(input, plan.RootId), ActivityPolicies.External(TimeSpan.FromHours(2)));
        }
        catch (Exception ex) when (ex is not ContinueAsNewException && !TemporalException.IsCanceledException(ex))
        {
            await Workflow.ExecuteActivityAsync((DriveActivities a) => a.FailAsync(input, ex.Message), ActivityPolicies.Database());
            throw;
        }
    }
}

[Workflow]
public sealed class DriveSyncWorkflow
{
    [WorkflowRun]
    public async Task RunAsync(BackupInput input, string driveId)
    {
        for (var page = 0; ; page++)
        {
            if (page >= DriveBackupWorkflow.PagesPerRun) throw Workflow.CreateContinueAsNewException((DriveSyncWorkflow w) => w.RunAsync(input, driveId));
            // Large files take time: a page activity may run long, but it heartbeats while it streams.
            var done = await Workflow.ExecuteActivityAsync((DriveActivities a) => a.SyncPageAsync(input, driveId), ActivityPolicies.External(TimeSpan.FromHours(6)));
            if (done) return;
        }
    }
}

public sealed record DriveMetadataDocument(
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("path")] string? Path,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("created")] DateTimeOffset? Created,
    [property: JsonPropertyName("modified")] DateTimeOffset? Modified,
    [property: JsonPropertyName("mime_type")] string? MimeType,
    [property: JsonPropertyName("quick_xor_hash")] string? QuickXorHash,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("package")] string? Package,
    [property: JsonPropertyName("permissions")] JsonElement? Permissions,
    [property: JsonPropertyName("path_warning")] string? PathWarning);

public sealed class DriveActivities(NpgsqlDataSource dataSource, GraphServices graph, BackupStore store, IBackupStorage storage, TenantKeyProvider keys,
    TimeProvider clock, ILogger<DriveActivities> logger)
{
    public const string Folder = "drive";
    /// <summary>Older versions of a changed file that are kept besides the current one.</summary>
    public const int VersionsToKeep = 3;
    private static readonly char[] RefusedCharacters = ['"', '*', ':', '<', '>', '?', '/', '\\', '|'];

    private DriveClient Drive => new(graph.Client, graph.Downloads);

    [Activity("DrivePrepare")]
    public async Task<DrivePlan> PrepareAsync(BackupInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var ct = ActivityExecutionContext.Current.CancellationToken;
        await store.PrepareSnapshotAsync(input.Target, ct);
        await keys.GetAsync(input.OrganizationId, input.TenantId, ct);
        await using var session = await Infrastructure.Database.OrganizationSession.BeginAsync(dataSource, input.OrganizationId, ct);
        var driveId = await Dapper.SqlMapper.ExecuteScalarAsync<string>(session.Connection, new Dapper.CommandDefinition(
            "SELECT source_id FROM vaulty.protected_objects WHERE id = @id", new { id = input.ProtectedObjectId }, session.Transaction, cancellationToken: ct));
        var root = await Drive.RootAsync(new GraphRequestContext(input.TenantId, Workload: "drive"), driveId!, ct);
        return new DrivePlan(driveId!, root.Id);
    }

    [Activity("DriveSyncPage")]
    public async Task<bool> SyncPageAsync(BackupInput input, string driveId)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var ct = context.CancellationToken;
        var target = input.Target;
        var checkpoint = await store.CheckpointAsync(target, Folder, ct);
        if (checkpoint.Completed) return true;
        var graphContext = new GraphRequestContext(input.TenantId, Workload: "drive");
        var link = checkpoint.PageCursor ?? (checkpoint.NextPage == 0 ? await store.CommittedDeltaLinkAsync(target, Folder, ct) : null);
        var resync = checkpoint.Resynced;
        GraphDeltaPage<DriveItem> page;
        try
        {
            page = await Drive.DeltaAsync(graphContext, driveId, link, ct);
        }
        catch (DeltaResyncRequiredException) when (link is not null)
        {
            logger.LogWarning("Drive delta needs a resync; listing the drive again");
            page = await Drive.DeltaAsync(graphContext, driveId, null, ct);
            resync = true;
        }
        context.Heartbeat();

        await store.StageRemovalsAsync(target, page.Items.Where(i => i.IsDeleted).Select(i => i.Id).ToList(), ct);
        var present = page.Items.Where(i => !i.IsDeleted && i.Root is null).ToList();
        if (page.DeltaLink is not null)
        {
            var seen = present.Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
            foreach (var failure in await store.OpenFailuresAsync(target, Folder, ct))
            {
                if (seen.Contains(failure.SourceId)) continue;
                try
                {
                    present.Add(await Drive.ItemAsync(graphContext, driveId, failure.SourceId, ct));
                }
                catch (GraphException ex) when (ex.Status == System.Net.HttpStatusCode.NotFound)
                {
                    await store.StageRemovalsAsync(target, [failure.SourceId], ct);
                }
            }
        }

        var current = await store.CurrentVersionsAsync(target, present.Select(p => p.Id).ToList(), ct);
        var changed = present.Where(p => !current.TryGetValue(p.Id, out var v) || v.ChangeKey != ChangeKey(p)).ToList();
        var poisoned = await store.PoisonedAsync(target, changed.Select(c => c.Id).ToList(), ct);
        changed = changed.Where(c => !poisoned.Contains(c.Id)).ToList();

        if (changed.Count > 0)
        {
            var repositoryKeys = await keys.GetAsync(input.OrganizationId, input.TenantId, ct);
            var policy = await PolicyResolver.ForObjectAsync(dataSource, input.OrganizationId, input.TenantId, input.ProtectedObjectId, ct);
            var writer = new RepositoryWriter(await storage.WorkerStoreAsync(ct), repositoryKeys, new PostgresChunkIndex(dataSource, input.OrganizationId, input.TenantId),
                new RepositoryWriterOptions { LockUntil = policy.LockUntil(clock.GetUtcNow()), PackTargetSize = 32 * 1024 * 1024 });
            var files = changed.Where(c => c.File is not null).ToList();
            var permissions = await Drive.PermissionsAsync(graphContext, driveId, files.Where(f => f.Shared is not null).Select(f => f.Id).ToList(), ct);
            var versions = new List<ItemVersion>();
            foreach (var item in changed)
            {
                if (item.File is null)
                {
                    versions.Add(new ItemVersion(item.Id, item.ParentReference?.Id, item.Package is not null ? "package" : "folder", ChangeKey(item), 0,
                        item.LastModifiedDateTime, null, Metadata(item, null, null), SearchText: Search(item)));
                    continue;
                }
                if (item.Size > DriveClient.MaximumFileSize)
                {
                    await store.RecordFailureAsync(target, item.Id, Folder, "too_large", "Files over 250 GB cannot be downloaded through Microsoft Graph.", ct, "file");
                    continue;
                }
                if (current.TryGetValue(item.Id, out var known) && ContentTag(known.ChangeKey) == ContentTag(ChangeKey(item)) && ContentTag(known.ChangeKey) is not null
                    && (await store.CurrentContentAsync(target, [item.Id], ct)).TryGetValue(item.Id, out var unchanged))
                {
                    // Renamed or moved, content unchanged: the new version points at the stored content, nothing is downloaded.
                    permissions.TryGetValue(item.Id, out var kept);
                    versions.Add(new ItemVersion(item.Id, item.ParentReference?.Id, "file", ChangeKey(item), item.Size, item.LastModifiedDateTime, unchanged,
                        Metadata(item, kept, null), SearchText: Search(item)));
                    continue;
                }
                try
                {
                    await using (var stream = Drive.OpenFile(graphContext, driveId, item))
                    {
                        var content = await writer.WriteAsync(new HeartbeatStream(stream, context), ct);
                        permissions.TryGetValue(item.Id, out var permission);
                        versions.Add(new ItemVersion(item.Id, item.ParentReference?.Id, "file", ChangeKey(item), item.Size, item.LastModifiedDateTime, content,
                            Metadata(item, permission, null), SearchText: Search(item)));
                    }
                    await StoreOlderVersionsAsync(graphContext, driveId, item, writer, current, versions, ct);
                }
                catch (Exception ex) when (ex is GraphException or DriveIntegrityException or IOException or HttpRequestException)
                {
                    await store.RecordFailureAsync(target, item.Id, Folder, ex is DriveIntegrityException ? "hash_mismatch" : ex is GraphException g ? g.Code ?? "graph_error" : "download_failed",
                        ex.Message, ct, "file");
                }
                context.Heartbeat();
            }
            await writer.FlushAsync(ct);
            await store.StageVersionsAsync(target, repositoryKeys, versions, ct);
        }

        var completed = page.DeltaLink is not null;
        await store.SaveCheckpointAsync(target, Folder, new FolderCheckpoint(page.NextLink, page.DeltaLink, completed, resync, checkpoint.NextPage + 1), ct);
        return completed;
    }

    /// <summary>Older versions of a changed file, as separate items under the file; versions stored before are skipped.</summary>
    private async Task StoreOlderVersionsAsync(GraphRequestContext context, string driveId, DriveItem item, RepositoryWriter writer,
        IReadOnlyDictionary<string, CurrentVersion> current, List<ItemVersion> versions, CancellationToken ct)
    {
        IReadOnlyList<DriveItemVersion> all;
        try
        {
            all = await Drive.VersionsAsync(context, driveId, item.Id, ct);
        }
        catch (GraphException)
        {
            return; // versions are a bonus; the current content is stored
        }
        // The newest entry is the current version, which is already stored.
        foreach (var version in all.OrderByDescending(v => v.LastModifiedDateTime).Skip(1).Take(VersionsToKeep))
        {
            var sourceId = $"{item.Id}@{version.Id}";
            if (current.ContainsKey(sourceId)) continue;
            await using var stream = Drive.OpenFile(context, driveId, item, version.Id);
            var content = await writer.WriteAsync(stream, ct);
            versions.Add(new ItemVersion(sourceId, item.Id, "file_version", version.Id, version.Size, version.LastModifiedDateTime, content,
                Metadata(item, null, version)));
        }
    }

    [Activity("DriveCommit")]
    public async Task<BackupOutcome> CommitAsync(BackupInput input, string rootId)
    {
        ArgumentNullException.ThrowIfNull(input);
        var ct = ActivityExecutionContext.Current.CancellationToken;
        var repositoryKeys = await keys.GetAsync(input.OrganizationId, input.TenantId, ct);
        var policy = await PolicyResolver.ForObjectAsync(dataSource, input.OrganizationId, input.TenantId, input.ProtectedObjectId, ct);
        // Items under a deleted folder and versions of a deleted file leave the snapshot with their parent.
        await store.StageOrphanRemovalsAsync(input.Target, [rootId], ct);
        var objectStore = await storage.WorkerStoreAsync(ct);
        var index = new PostgresChunkIndex(dataSource, input.OrganizationId, input.TenantId);
        var writer = new RepositoryWriter(objectStore, repositoryKeys, index, new RepositoryWriterOptions { LockUntil = policy.LockUntil(clock.GetUtcNow()) });
        var result = await store.CommitAsync(input.Target, repositoryKeys, writer, new RepositoryReader(objectStore, repositoryKeys, index), [],
            policy.LockUntil(clock.GetUtcNow()), TimeSpan.FromMinutes(policy.FrequencyMinutes), ct);
        return new BackupOutcome(result.Counts, result.Partial, result.Exceptions.Count);
    }

    [Activity("DriveFail")]
    public Task FailAsync(BackupInput input, string reason)
    {
        ArgumentNullException.ThrowIfNull(input);
        return store.FailAsync(input.Target, reason);
    }

    /// <summary>
    /// Files: content tag (cTag) and entity tag (eTag), so a rename or move is a new version too; only a new cTag means new content.
    /// Folders and packages: the eTag.
    /// </summary>
    public static string? ChangeKey(DriveItem item) => item.File is not null ? $"{item.CTag}|{item.ETag}" : item.ETag;

    private static string? ContentTag(string? changeKey) =>
        changeKey is null || !changeKey.Contains('|', StringComparison.Ordinal) ? null : changeKey[..changeKey.IndexOf('|', StringComparison.Ordinal)] is { Length: > 0 } tag ? tag : null;

    /// <summary>File name and path: the words a file is found by.</summary>
    private static string Search(DriveItem item) => $"{item.Name} {item.ParentReference?.Path?.Replace("/drive/root:", "", StringComparison.Ordinal)}";

    private static string Metadata(DriveItem item, string? permissions, DriveItemVersion? version)
    {
        var path = item.ParentReference?.Path is { } parent ? $"{parent}/{item.Name}" : item.Name;
        string? warning = null;
        if (path is { Length: > 400 }) warning = "The path is longer than 400 characters; a restore to the same place shortens it.";
        else if (item.Name?.IndexOfAny(RefusedCharacters) >= 0 || item.Name?.EndsWith('.') == true) warning = "The name contains characters that a restore replaces.";
        return JsonSerializer.Serialize(new DriveMetadataDocument(item.Name, path, version?.Size ?? item.Size, item.CreatedDateTime,
            version?.LastModifiedDateTime ?? item.LastModifiedDateTime, item.File?.MimeType, version is null ? item.File?.Hashes?.QuickXorHash : null,
            version?.Id, item.Package?.Type, permissions is null ? null : JsonDocument.Parse(permissions).RootElement.Clone(), warning));
    }

    /// <summary>Reports progress to the workflow engine while a large file streams, so a dead worker is noticed.</summary>
    private sealed class HeartbeatStream(Stream inner, ActivityExecutionContext context) : Stream
    {
        private long _read;
        private long _lastBeat;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => _read; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            _read += read;
            if (_read - _lastBeat > 64 * 1024 * 1024)
            {
                context.Heartbeat(_read);
                _lastBeat = _read;
            }
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
