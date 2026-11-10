using System.Text.Json;
using System.Text.Json.Serialization;
using Dapper;
using Npgsql;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Browse;
using Vaulty.Infrastructure.Database;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Restore;

public static class RestoreModes
{
    public const string RestoreFolder = "restore_folder";
    public const string Original = "original";
    public const string Other = "other";
    public const string Export = "export";
}

/// <summary>What to restore: items by id (any version) and folders by source id (with everything under them).</summary>
public sealed record RestoreSelection(
    [property: JsonPropertyName("items")] IReadOnlyList<Guid> ItemIds,
    [property: JsonPropertyName("folders")] IReadOnlyList<string> FolderIds);

public sealed record RestoreRow(Guid Id, Guid OrganizationId, Guid TenantId, Guid ProtectedObjectId, Guid SnapshotId, Guid JobId, string Kind,
    string TargetMode, Guid? TargetObjectId, string Conflict, string Selection, string State, Guid RequestedBy, DateTime CreatedAt, DateTime? FinishedAt,
    string Counts);

/// <summary>One item to restore with what the connectors need: content, metadata, its place in the folder tree.</summary>
public sealed record PendingItem(Guid ItemId, string SourceId, string Kind, string? ParentSourceId, string RelativePath, string? FolderType,
    long Size, DateTimeOffset ModifiedAt, string MetadataJson, ItemContent? Content, ItemContent? Preview, string? PreviewType, bool LimitedFidelity);

public sealed record ItemResult(Guid ItemId, string State, string? TargetId, string? Detail);

public sealed record RestoreCounts(long Total, long Restored, long Skipped, long Failed, long Pending);

/// <summary>
/// The restore plan and its per-item results in PostgreSQL. Planning resolves the selection against the snapshot's point
/// in time (folders recursively) and is idempotent, so a restarted workflow continues where it was.
/// </summary>
public sealed class RestoreStore(NpgsqlDataSource dataSource, TimeProvider clock)
{
    public async Task<RestoreRow> GetAsync(Guid organizationId, Guid restoreId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await session.Connection.QuerySingleAsync<RestoreRow>(new CommandDefinition(
            """
            SELECT id, organization_id, tenant_id, protected_object_id, snapshot_id, job_id, kind, target_mode, target_object_id, conflict,
                   selection::text AS selection, state, requested_by, created_at, finished_at, counts::text AS counts
              FROM vaulty.restores WHERE id = @restoreId
            """, new { restoreId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>Writes the restore items of the selection (once) and returns how many there are.</summary>
    public async Task<long> PlanAsync(Guid organizationId, Guid restoreId, RepositoryKeys keys, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var restore = await GetAsync(organizationId, restoreId, cancellationToken).ConfigureAwait(false);
        var selection = JsonSerializer.Deserialize<RestoreSelection>(restore.Selection) ?? new RestoreSelection([], []);
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var planned = await session.Connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT count(*) FROM vaulty.restore_items WHERE restore_id = @restoreId", new { restoreId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (planned > 0 || restore.State != "planning") return planned;

        var sequence = await session.Connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT sequence FROM vaulty.snapshots WHERE id = @SnapshotId", restore, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var p = new { tenantId = restore.TenantId, objectId = restore.ProtectedObjectId, sequence };

        // The folder tree of the snapshot: names and types of every folder (and notebook), for paths and restore folders.
        var folders = (await session.Connection.QueryAsync<(string SourceId, string? ParentSourceId, byte[]? SealedMetadata)>(new CommandDefinition(
            $"""
            SELECT source_id, parent_source_id, sealed_metadata FROM vaulty.items
             WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND kind IN ('folder', 'package') AND {SnapshotBrowser.Membership}
            """, p, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
            .ToDictionary(f => f.SourceId, f =>
            {
                var json = f.SealedMetadata is null ? "{}" : MetadataSealer.Open(keys, restore.ProtectedObjectId, f.SourceId, f.SealedMetadata);
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                return (f.ParentSourceId, Name: root.TryGetProperty("name", out var n) ? n.GetString() ?? f.SourceId : f.SourceId,
                    Type: root.TryGetProperty("type", out var t) ? t.GetString() : null);
            }, StringComparer.Ordinal);

        string PathOf(string? folderId)
        {
            var parts = new List<string>();
            var guard = 0;
            for (var id = folderId; id is not null && folders.TryGetValue(id, out var folder) && guard++ < 256; id = folder.ParentSourceId) parts.Insert(0, folder.Name);
            return string.Join('/', parts);
        }

        // Selected folders with every folder below them.
        var selectedFolders = new HashSet<string>(selection.FolderIds, StringComparer.Ordinal);
        var children = folders.GroupBy(f => f.Value.ParentSourceId ?? "").ToDictionary(g => g.Key, g => g.Select(f => f.Key).ToList(), StringComparer.Ordinal);
        var queue = new Queue<string>(selectedFolders);
        while (queue.Count > 0)
        {
            if (!children.TryGetValue(queue.Dequeue(), out var below)) continue;
            foreach (var child in below.Where(selectedFolders.Add)) queue.Enqueue(child);
        }

        var rows = (await session.Connection.QueryAsync<(Guid Id, string SourceId, string Kind, string? ParentSourceId)>(new CommandDefinition(
            $"""
            SELECT id, source_id, kind, parent_source_id FROM vaulty.items
             WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND kind NOT IN ('folder', 'package') AND {SnapshotBrowser.Membership}
               AND (id = ANY(@items) OR (parent_source_id = ANY(@folders) AND kind <> 'file_version'))
            """, new { p.tenantId, p.objectId, p.sequence, items = selection.ItemIds.ToArray(), folders = selectedFolders.ToArray() }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();

        // A file version lives under its file; its place is the file's folder.
        var versionParents = rows.Where(r => r.Kind == "file_version" && r.ParentSourceId is not null).Select(r => r.ParentSourceId!).Distinct().ToArray();
        var fileParents = versionParents.Length == 0 ? new Dictionary<string, string?>() : (await session.Connection.QueryAsync<(string SourceId, string? ParentSourceId)>(
            new CommandDefinition(
                $"""
                SELECT DISTINCT ON (source_id) source_id, parent_source_id FROM vaulty.items
                 WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND source_id = ANY(@ids) AND {SnapshotBrowser.Membership}
                """, new { p.tenantId, p.objectId, p.sequence, ids = versionParents }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToDictionary(r => r.SourceId, r => r.ParentSourceId, StringComparer.Ordinal);

        var inserts = rows.Select(r =>
        {
            var folder = r.Kind == "file_version" && r.ParentSourceId is not null ? fileParents.GetValueOrDefault(r.ParentSourceId) : r.ParentSourceId;
            return new
            {
                organizationId, restoreId, itemId = r.Id, sourceId = r.SourceId, kind = r.Kind, relativePath = PathOf(folder),
                folderType = folder is not null && folders.TryGetValue(folder, out var f) ? f.Type : null,
            };
        }).ToList();
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.restore_items (organization_id, restore_id, item_id, source_id, kind, relative_path, folder_type)
            SELECT @organizationId, @restoreId, x.item_id, x.source_id, x.kind, x.relative_path, x.folder_type
              FROM unnest(@ids, @sources, @kinds, @paths, @types) AS x(item_id, source_id, kind, relative_path, folder_type)
            ON CONFLICT DO NOTHING;
            UPDATE vaulty.restores SET state = 'running' WHERE id = @restoreId AND state = 'planning';
            """, new
            {
                organizationId, restoreId, ids = inserts.Select(i => i.itemId).ToArray(), sources = inserts.Select(i => i.sourceId).ToArray(),
                kinds = inserts.Select(i => i.kind).ToArray(), paths = inserts.Select(i => i.relativePath).ToArray(), types = inserts.Select(i => i.folderType).ToArray(),
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return inserts.Count;
    }

    /// <summary>The next pending items with their content references and decrypted metadata.</summary>
    public async Task<IReadOnlyList<PendingItem>> PendingAsync(RestoreRow restore, RepositoryKeys keys, int take, CancellationToken cancellationToken = default,
        PendingItem? after = null)
    {
        ArgumentNullException.ThrowIfNull(restore);
        ArgumentNullException.ThrowIfNull(keys);
        await using var session = await OrganizationSession.BeginAsync(dataSource, restore.OrganizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<PendingRow>(new CommandDefinition(
            """
            SELECT r.item_id, r.source_id, r.kind, r.relative_path, r.folder_type, i.parent_source_id, i.size, i.modified_at, i.sealed_metadata,
                   i.content_hash, i.content_chunks, i.preview_hash, i.preview_chunks, i.preview_size, i.preview_type, i.limited_fidelity
              FROM vaulty.restore_items r
              JOIN vaulty.items i ON i.tenant_id = @TenantId AND i.id = r.item_id
             WHERE r.restore_id = @Id AND r.state = 'pending'
               AND (@afterPath::text IS NULL OR (r.relative_path, r.item_id) > (@afterPath, @afterItem))
             ORDER BY r.relative_path, r.item_id LIMIT @take
            """, new { restore.TenantId, restore.Id, take, afterPath = after?.RelativePath, afterItem = after?.ItemId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new PendingItem(r.ItemId, r.SourceId, r.Kind, r.ParentSourceId, r.RelativePath, r.FolderType, r.Size,
            new DateTimeOffset(DateTime.SpecifyKind(r.ModifiedAt, DateTimeKind.Utc)),
            r.SealedMetadata is null ? "{}" : MetadataSealer.Open(keys, restore.ProtectedObjectId, r.SourceId, r.SealedMetadata),
            r.ContentChunks is null ? null : new ItemContent(r.Size, r.ContentHash ?? [], Chunks(r.ContentChunks)),
            r.PreviewChunks is null ? null : new ItemContent(r.PreviewSize ?? 0, r.PreviewHash ?? [], Chunks(r.PreviewChunks)), r.PreviewType, r.LimitedFidelity)).ToList();
    }

    public async Task RecordAsync(Guid organizationId, Guid restoreId, IReadOnlyList<ItemResult> results, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(results);
        if (results.Count == 0) return;
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.restore_items r SET state = x.state, target_id = x.target_id, detail = x.detail, finished_at = @now
              FROM unnest(@ids, @states, @targets, @details) AS x(item_id, state, target_id, detail)
             WHERE r.restore_id = @restoreId AND r.item_id = x.item_id AND r.state = 'pending'
            """, new
            {
                restoreId, now = clock.GetUtcNow(), ids = results.Select(r => r.ItemId).ToArray(), states = results.Select(r => r.State).ToArray(),
                targets = results.Select(r => r.TargetId).ToArray(), details = results.Select(r => r.Detail).ToArray(),
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<RestoreCounts> CountsAsync(Guid organizationId, Guid restoreId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await session.Connection.QuerySingleAsync<RestoreCounts>(new CommandDefinition(
            """
            SELECT count(*) AS total, count(*) FILTER (WHERE state = 'restored') AS restored, count(*) FILTER (WHERE state = 'skipped') AS skipped,
                   count(*) FILTER (WHERE state = 'failed') AS failed, count(*) FILTER (WHERE state = 'pending') AS pending
              FROM vaulty.restore_items WHERE restore_id = @restoreId
            """, new { restoreId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task SetStateAsync(Guid organizationId, Guid restoreId, string state, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.restores SET state = @state WHERE id = @restoreId AND finished_at IS NULL", new { restoreId, state }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Closes the restore: items not done when it was cancelled are skipped; the outcome and counts are recorded and audited.</summary>
    public async Task<(string State, RestoreCounts Counts)> FinishAsync(Guid organizationId, Guid restoreId, bool cancelled, string? failure,
        CancellationToken cancellationToken = default)
    {
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.restore_items SET state = 'skipped', detail = @detail, finished_at = @now WHERE restore_id = @restoreId AND state = 'pending'",
                new { restoreId, now = clock.GetUtcNow(), detail = cancelled ? "The restore was cancelled before this item." : failure ?? "Not processed." },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        var counts = await CountsAsync(organizationId, restoreId, cancellationToken).ConfigureAwait(false);
        var state = failure is not null ? "failed" : cancelled ? "cancelled" : counts.Failed > 0 ? "partial" : "succeeded";
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            var kind = await session.Connection.ExecuteScalarAsync<string>(new CommandDefinition(
                """
                UPDATE vaulty.restores SET state = @state, finished_at = coalesce(finished_at, @now), counts = @counts::jsonb
                 WHERE id = @restoreId RETURNING kind
                """, new { restoreId, state, now = clock.GetUtcNow(), counts = JsonSerializer.Serialize(counts) }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, "system:restore", $"{kind}.{state}", $"restore:{restoreId}",
                new { counts.Total, counts.Restored, counts.Skipped, counts.Failed }, cancellationToken).ConfigureAwait(false);
            var target = await session.Connection.QuerySingleAsync<(Guid TenantId, Guid ObjectId)>(new CommandDefinition(
                "SELECT tenant_id, protected_object_id FROM vaulty.restores WHERE id = @restoreId", new { restoreId }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            await Notifications.NotificationEvents.PublishAsync(session, Core.Notifications.NotificationKinds.RestoreCompleted, target.TenantId, target.ObjectId,
                new { restore = restoreId, kind, state, counts.Total, counts.Restored, counts.Skipped, counts.Failed }, cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        return (state, counts);
    }

    /// <summary>The source details of a protected object (mailbox id, drive id) for the connectors.</summary>
    public async Task<(string Kind, string SourceId, string? MailboxId)> TargetAsync(Guid organizationId, Guid objectId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleAsync<(string Kind, string SourceId, string? Details)>(new CommandDefinition(
            "SELECT kind, source_id, source_details::text FROM vaulty.protected_objects WHERE id = @objectId", new { objectId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        string? mailbox = null;
        if (row.Details is not null)
        {
            using var document = JsonDocument.Parse(row.Details);
            if (document.RootElement.TryGetProperty("mailbox_id", out var m)) mailbox = m.GetString();
        }
        return (row.Kind, row.SourceId, mailbox);
    }

    public async Task<Guid> RecordExportAsync(Guid organizationId, Guid restoreId, string objectKey, long size, byte[] sha256, Guid createdBy,
        CancellationToken cancellationToken = default)
    {
        var id = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.exports (id, organization_id, restore_id, object_key, size, sha256, created_by, expires_at)
            VALUES (@id, @organizationId, @restoreId, @objectKey, @size, @sha256, @createdBy, @expires)
            """, new { id, organizationId, restoreId, objectKey, size, sha256, createdBy, expires = clock.GetUtcNow().AddHours(24) }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    private static List<ChunkId> Chunks(byte[] packed)
    {
        var list = new List<ChunkId>(packed.Length / ChunkId.Size);
        for (var i = 0; i + ChunkId.Size <= packed.Length; i += ChunkId.Size) list.Add(new ChunkId(packed.AsSpan(i, ChunkId.Size).ToArray()));
        return list;
    }

    private sealed class PendingRow
    {
        public Guid ItemId { get; set; }
        public string SourceId { get; set; } = "";
        public string Kind { get; set; } = "";
        public string RelativePath { get; set; } = "";
        public string? FolderType { get; set; }
        public string? ParentSourceId { get; set; }
        public long Size { get; set; }
        public DateTime ModifiedAt { get; set; }
        public byte[]? SealedMetadata { get; set; }
        public byte[]? ContentHash { get; set; }
        public byte[]? ContentChunks { get; set; }
        public byte[]? PreviewHash { get; set; }
        public byte[]? PreviewChunks { get; set; }
        public long? PreviewSize { get; set; }
        public string? PreviewType { get; set; }
        public bool LimitedFidelity { get; set; }
    }
}

/// <summary>The export bucket: no Object Lock, a one-day lifecycle; workers write exports, the web app reads and deletes them.</summary>
public interface IExportStorage
{
    Task<Core.Abstractions.IObjectUploads> UploadsAsync(CancellationToken cancellationToken = default);

    Task<Core.Abstractions.IObjectStore> StoreAsync(CancellationToken cancellationToken = default);
}

public sealed class S3ExportStorage(Storage.StorageClientFactory factory, Storage.StorageRole role) : IExportStorage
{
    public async Task<Core.Abstractions.IObjectUploads> UploadsAsync(CancellationToken cancellationToken = default) =>
        await factory.CreateAsync(role, exportBucket: true, cancellationToken).ConfigureAwait(false);

    public async Task<Core.Abstractions.IObjectStore> StoreAsync(CancellationToken cancellationToken = default) =>
        await factory.CreateAsync(role, exportBucket: true, cancellationToken).ConfigureAwait(false);
}
