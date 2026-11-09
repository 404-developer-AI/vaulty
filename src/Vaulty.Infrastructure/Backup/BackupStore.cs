using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Crypto;
using Vaulty.Infrastructure.Database;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Backup;

public sealed record BackupTarget(Guid OrganizationId, Guid TenantId, Guid ProtectedObjectId, Guid SnapshotId);

public sealed record CurrentVersion(Guid ItemId, string? ChangeKey, bool StagedHere);

/// <summary>One new version of an item (or folder) seen in this backup.</summary>
public sealed record ItemVersion(string SourceId, string? ParentSourceId, string Kind, string? ChangeKey, long Size, DateTimeOffset? ModifiedAt,
    ItemContent? Content, string MetadataJson, bool LimitedFidelity = false);

public sealed record FolderCheckpoint(string? PageCursor, string? DeltaLink, bool Completed, bool Resynced, int NextPage);

public sealed record FolderCount(string FolderId, string Name, long SourceCount);

public sealed record ItemException(string SourceId, string? FolderId, string ErrorCode, string? Detail);

public sealed record CommitResult(bool Partial, Dictionary<string, long> Counts, IReadOnlyList<ItemException> Exceptions, byte[] RootHash);

/// <summary>
/// Encrypts item metadata (subject, names, addresses) for the database with the tenant's metadata key. Layout:
/// nonce (12) | ciphertext | tag (16); authenticated data "vaulty-metadata-v1" ‖ tenant id ‖ protected object id ‖ source id.
/// </summary>
public static class MetadataSealer
{
    public static byte[] Seal(RepositoryKeys keys, Guid protectedObjectId, string sourceId, string json)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var key = KeyHierarchy.DeriveMetadataKey(keys.DataKey(keys.CurrentVersion));
        var plaintext = Encoding.UTF8.GetBytes(json);
        var output = new byte[4 + 12 + plaintext.Length + 16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(output, keys.CurrentVersion);
        RandomNumberGenerator.Fill(output.AsSpan(4, 12));
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(output.AsSpan(4, 12), plaintext, output.AsSpan(16, plaintext.Length), output.AsSpan(16 + plaintext.Length),
            Aad(keys.TenantId, protectedObjectId, sourceId));
        CryptographicOperations.ZeroMemory(key);
        return output;
    }

    public static string Open(RepositoryKeys keys, Guid protectedObjectId, string sourceId, byte[] sealedMetadata)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(sealedMetadata);
        var version = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(sealedMetadata);
        var key = KeyHierarchy.DeriveMetadataKey(keys.DataKey(version));
        var length = sealedMetadata.Length - 32;
        var plaintext = new byte[length];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(sealedMetadata.AsSpan(4, 12), sealedMetadata.AsSpan(16, length), sealedMetadata.AsSpan(16 + length), plaintext,
            Aad(keys.TenantId, protectedObjectId, sourceId));
        CryptographicOperations.ZeroMemory(key);
        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] Aad(Guid tenantId, Guid objectId, string sourceId) =>
        [.. "vaulty-metadata-v1"u8, .. KeyHierarchy.GuidBytes(tenantId), .. KeyHierarchy.GuidBytes(objectId), .. Encoding.UTF8.GetBytes(sourceId)];
}

/// <summary>
/// Database side of a backup: staged item versions, removals and failures during the run, and the atomic commit that turns
/// them into a snapshot. Nothing is visible as committed until <see cref="CommitAsync"/> succeeds; delta links are copied
/// to the protected object only then.
/// </summary>
public sealed class BackupStore(NpgsqlDataSource dataSource, TimeProvider clock)
{
    public const int PoisonThreshold = 3;
    public static readonly TimeSpan PoisonRetryInterval = TimeSpan.FromDays(1);

    private Task<OrganizationSession> Session(BackupTarget target, CancellationToken cancellationToken) =>
        OrganizationSession.BeginAsync(dataSource, target.OrganizationId, cancellationToken);

    /// <summary>Creates the snapshot row (staged) with the next sequence number; idempotent.</summary>
    public async Task<long> PrepareSnapshotAsync(BackupTarget target, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "SELECT pg_advisory_xact_lock(hashtextextended('vaulty.snapshot:' || @object::text, 0))", new { @object = target.ProtectedObjectId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var existing = await session.Connection.ExecuteScalarAsync<long?>(new CommandDefinition(
            "SELECT sequence FROM vaulty.snapshots WHERE id = @SnapshotId", target, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        if (existing is { } seq) return seq;
        var next = 1 + await session.Connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT coalesce(max(sequence), 0) FROM vaulty.snapshots WHERE protected_object_id = @ProtectedObjectId", target, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state, started_at, sequence)
            VALUES (@SnapshotId, @OrganizationId, @TenantId, @ProtectedObjectId, 'staged', @now, @next)
            """, new { target.SnapshotId, target.OrganizationId, target.TenantId, target.ProtectedObjectId, now = clock.GetUtcNow(), next },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return next;
    }

    /// <summary>The current version of each source item: committed and not deleted, or already staged by this snapshot.</summary>
    public async Task<Dictionary<string, CurrentVersion>> CurrentVersionsAsync(BackupTarget target, IReadOnlyCollection<string> sourceIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sourceIds);
        if (sourceIds.Count == 0) return new Dictionary<string, CurrentVersion>(StringComparer.Ordinal);
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(string SourceId, Guid Id, string? ChangeKey, Guid FirstSnapshotId)>(new CommandDefinition(
            """
            SELECT source_id, id, change_key, first_snapshot_id FROM vaulty.items
             WHERE tenant_id = @TenantId AND protected_object_id = @ProtectedObjectId AND source_id = ANY(@ids) AND deleted_in_snapshot_id IS NULL
               AND (state = 'committed' OR first_snapshot_id = @SnapshotId)
            """, new { target.TenantId, target.ProtectedObjectId, target.SnapshotId, ids = sourceIds.ToArray() }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        var result = new Dictionary<string, CurrentVersion>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            // A version staged by this snapshot wins over the committed one it replaces.
            var staged = row.FirstSnapshotId == target.SnapshotId;
            if (!result.TryGetValue(row.SourceId, out var known) || staged) result[row.SourceId] = new CurrentVersion(row.Id, row.ChangeKey, staged || known?.StagedHere == true);
        }
        return result;
    }

    public async Task StageVersionsAsync(BackupTarget target, RepositoryKeys keys, IReadOnlyList<ItemVersion> versions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(versions);
        if (versions.Count == 0) return;
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        var rows = versions.Select(v => new
        {
            target.OrganizationId, target.TenantId, id = Guid.CreateVersion7(), target.ProtectedObjectId, target.SnapshotId,
            v.SourceId, v.ParentSourceId, v.Kind, sealedMetadata = MetadataSealer.Seal(keys, target.ProtectedObjectId, v.SourceId, v.MetadataJson),
            contentHash = v.Content?.ContentHash, size = v.Content?.Size ?? v.Size, v.ModifiedAt,
            chunks = v.Content is null ? null : v.Content.Chunks.SelectMany(c => c.Value).ToArray(), v.ChangeKey, v.LimitedFidelity,
        });
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.items (organization_id, tenant_id, id, protected_object_id, first_snapshot_id, state, source_id, parent_source_id, kind,
                sealed_metadata, content_hash, size, modified_at, content_chunks, change_key, limited_fidelity)
            VALUES (@OrganizationId, @TenantId, @id, @ProtectedObjectId, @SnapshotId, 'staged', @SourceId, @ParentSourceId, @Kind,
                @sealedMetadata, @contentHash, @size, @ModifiedAt, @chunks, @ChangeKey, @LimitedFidelity)
            ON CONFLICT (tenant_id, protected_object_id, source_id, first_snapshot_id) DO NOTHING
            """, rows, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.item_failures SET resolved_at = @now WHERE protected_object_id = @ProtectedObjectId AND source_id = ANY(@ids) AND resolved_at IS NULL",
            new { now = clock.GetUtcNow(), target.ProtectedObjectId, ids = versions.Select(v => v.SourceId).ToArray() }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task StageRemovalsAsync(BackupTarget target, IReadOnlyCollection<string> sourceIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sourceIds);
        if (sourceIds.Count == 0) return;
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.pending_removals (organization_id, tenant_id, snapshot_id, protected_object_id, source_id)
            VALUES (@OrganizationId, @TenantId, @SnapshotId, @ProtectedObjectId, @sourceId) ON CONFLICT DO NOTHING
            """, sourceIds.Select(s => new { target.OrganizationId, target.TenantId, target.SnapshotId, target.ProtectedObjectId, sourceId = s }),
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        // An item that no longer exists at the source is no longer missing from the backup.
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.item_failures SET resolved_at = now() WHERE protected_object_id = @ProtectedObjectId AND source_id = ANY(@ids) AND resolved_at IS NULL",
            new { target.ProtectedObjectId, ids = sourceIds.ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Records a failure. The same error three times makes the item a poison item.</summary>
    public async Task RecordFailureAsync(BackupTarget target, string sourceId, string? folderId, string errorCode, string? detail,
        CancellationToken cancellationToken = default, string? itemType = null)
    {
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.item_failures (organization_id, tenant_id, protected_object_id, source_id, folder_id, error_code, error_detail, last_snapshot_id, item_type)
            VALUES (@OrganizationId, @TenantId, @ProtectedObjectId, @sourceId, @folderId, @errorCode, @detail, @SnapshotId, @itemType)
            ON CONFLICT (protected_object_id, source_id) DO UPDATE SET
                failure_count = CASE WHEN vaulty.item_failures.last_snapshot_id = excluded.last_snapshot_id THEN vaulty.item_failures.failure_count
                                     WHEN vaulty.item_failures.error_code = excluded.error_code AND vaulty.item_failures.resolved_at IS NULL
                                     THEN vaulty.item_failures.failure_count + 1 ELSE 1 END,
                error_code = excluded.error_code, error_detail = excluded.error_detail, folder_id = excluded.folder_id,
                item_type = coalesce(excluded.item_type, vaulty.item_failures.item_type),
                last_failed_at = now(), last_snapshot_id = excluded.last_snapshot_id, resolved_at = NULL
            """, new { target.OrganizationId, target.TenantId, target.ProtectedObjectId, target.SnapshotId, sourceId, folderId, errorCode, detail, itemType },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Unresolved failures of a folder from earlier runs: the delta moved past them, so they are retried explicitly.</summary>
    public async Task<List<(string SourceId, string? ItemType)>> OpenFailuresAsync(BackupTarget target, string folderId, CancellationToken cancellationToken = default)
    {
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        return (await session.Connection.QueryAsync<(string, string?)>(new CommandDefinition(
            """
            SELECT source_id, item_type FROM vaulty.item_failures
             WHERE protected_object_id = @ProtectedObjectId AND folder_id = @folderId AND resolved_at IS NULL
               AND last_snapshot_id <> @SnapshotId AND source_id NOT LIKE 'folder:%'
            """, new { target.ProtectedObjectId, target.SnapshotId, folderId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
    }

    /// <summary>Poison items that were already tried in the last day: they stay in the exception list and are not fetched again.</summary>
    public async Task<HashSet<string>> PoisonedAsync(BackupTarget target, IReadOnlyCollection<string> sourceIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sourceIds);
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        var ids = await session.Connection.QueryAsync<string>(new CommandDefinition(
            """
            SELECT source_id FROM vaulty.item_failures
             WHERE protected_object_id = @ProtectedObjectId AND source_id = ANY(@ids) AND resolved_at IS NULL
               AND failure_count >= @threshold AND last_failed_at > @since
            """, new { target.ProtectedObjectId, ids = sourceIds.ToArray(), threshold = PoisonThreshold, since = clock.GetUtcNow() - PoisonRetryInterval },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        // A poison item skipped in this run is still an exception of this snapshot.
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.item_failures SET last_snapshot_id = @SnapshotId WHERE protected_object_id = @ProtectedObjectId AND source_id = ANY(@ids)",
            new { target.SnapshotId, target.ProtectedObjectId, ids = ids.ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return ids.ToHashSet(StringComparer.Ordinal);
    }

    public async Task<FolderCheckpoint> CheckpointAsync(BackupTarget target, string folderId, CancellationToken cancellationToken = default)
    {
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<(string? PageCursor, string? DeltaLink, bool Completed, bool Resynced, int NextPage)?>(
            new CommandDefinition(
                "SELECT page_cursor, delta_link, completed, resynced, next_page FROM vaulty.folder_checkpoints WHERE snapshot_id = @SnapshotId AND folder_id = @folderId",
                new { target.SnapshotId, folderId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row is { } r ? new FolderCheckpoint(r.PageCursor, r.DeltaLink, r.Completed, r.Resynced, r.NextPage) : new FolderCheckpoint(null, null, false, false, 0);
    }

    public async Task SaveCheckpointAsync(BackupTarget target, string folderId, FolderCheckpoint checkpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.folder_checkpoints (organization_id, tenant_id, snapshot_id, folder_id, next_page, page_cursor, delta_link, completed, resynced)
            VALUES (@OrganizationId, @TenantId, @SnapshotId, @folderId, @NextPage, @PageCursor, @DeltaLink, @Completed, @Resynced)
            ON CONFLICT (snapshot_id, folder_id) DO UPDATE SET
                next_page = greatest(vaulty.folder_checkpoints.next_page, excluded.next_page), page_cursor = excluded.page_cursor,
                delta_link = coalesce(excluded.delta_link, vaulty.folder_checkpoints.delta_link),
                completed = vaulty.folder_checkpoints.completed OR excluded.completed,
                resynced = vaulty.folder_checkpoints.resynced OR excluded.resynced, updated_at = now()
            """, new { target.OrganizationId, target.TenantId, target.SnapshotId, folderId, checkpoint.NextPage, checkpoint.PageCursor,
                checkpoint.DeltaLink, checkpoint.Completed, checkpoint.Resynced }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The stored delta link of a folder from the last committed snapshot, or null for a first run.</summary>
    public async Task<string?> CommittedDeltaLinkAsync(BackupTarget target, string folderId, CancellationToken cancellationToken = default)
    {
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        return await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT delta_state ->> @folderId FROM vaulty.protected_objects WHERE id = @ProtectedObjectId", new { folderId, target.ProtectedObjectId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>
    /// Commits the snapshot. Verifies a sample of every new pack, writes one manifest per folder and the snapshot root
    /// (the commit point in object storage), then in one database transaction: applies replacements and removals, marks
    /// staged items and packs committed, records the snapshot with exact counts and exceptions, and only now stores the new
    /// delta links. A snapshot with exceptions or count differences is committed as partial, never as succeeded.
    /// </summary>
    public async Task<CommitResult> CommitAsync(BackupTarget target, RepositoryKeys keys, RepositoryWriter writer, RepositoryReader reader,
        IReadOnlyList<FolderCount> sourceCounts, DateTimeOffset lockUntil, TimeSpan frequency, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(sourceCounts);

        List<MemberRow> members;
        List<ItemException> exceptions;
        DateTimeOffset startedAt;
        List<string> newPacks;
        await using (var session = await Session(target, cancellationToken).ConfigureAwait(false))
        {
            startedAt = new DateTimeOffset(DateTime.SpecifyKind(await session.Connection.ExecuteScalarAsync<DateTime>(new CommandDefinition(
                "SELECT started_at FROM vaulty.snapshots WHERE id = @SnapshotId", target, session.Transaction, cancellationToken: cancellationToken))
                .ConfigureAwait(false), DateTimeKind.Utc));
            // Membership after this snapshot: the latest version of every source item that is not removed.
            members = (await session.Connection.QueryAsync<MemberRow>(new CommandDefinition(
                """
                SELECT DISTINCT ON (i.source_id) i.id, i.source_id, i.parent_source_id, i.kind, i.sealed_metadata, i.content_hash, i.size, i.content_chunks
                  FROM vaulty.items i
                 WHERE i.tenant_id = @TenantId AND i.protected_object_id = @ProtectedObjectId AND i.deleted_in_snapshot_id IS NULL
                   AND (i.state = 'committed' OR i.first_snapshot_id = @SnapshotId)
                   AND NOT EXISTS (SELECT 1 FROM vaulty.pending_removals r WHERE r.snapshot_id = @SnapshotId AND r.source_id = i.source_id)
                 ORDER BY i.source_id, (i.first_snapshot_id = @SnapshotId) DESC, i.created_at DESC
                """, target, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            exceptions = (await session.Connection.QueryAsync<ItemException>(new CommandDefinition(
                """
                SELECT source_id, folder_id, error_code, error_detail AS detail FROM vaulty.item_failures
                 WHERE protected_object_id = @ProtectedObjectId AND last_snapshot_id = @SnapshotId AND resolved_at IS NULL ORDER BY source_id
                """, target, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            newPacks = (await session.Connection.QueryAsync<string>(new CommandDefinition(
                "SELECT object_key FROM vaulty.packs WHERE tenant_id = @TenantId AND state = 'staged'", target, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        }

        // Post-write verification: re-read a sample of every new pack before anything refers to it as committed.
        foreach (var key in newPacks) await reader.VerifyPackAsync(RepositoryLayout.PackHashFromKey(key), sampleRecords: 2, cancellationToken).ConfigureAwait(false);

        // Count check per folder: every item the source reports must be in the snapshot or in the exception list.
        var countIssues = new List<ItemException>();
        foreach (var folder in sourceCounts)
        {
            var inSnapshot = members.Count(m => m.ParentSourceId == folder.FolderId && m.Kind != "folder");
            var excepted = exceptions.Count(e => e.FolderId == folder.FolderId);
            if (inSnapshot + excepted != folder.SourceCount)
            {
                countIssues.Add(new ItemException($"folder:{folder.FolderId}", folder.FolderId, "count_mismatch",
                    $"{folder.Name}: Microsoft 365 reports {folder.SourceCount} items, the snapshot has {inSnapshot} and {excepted} exceptions."));
            }
        }
        var allExceptions = exceptions.Concat(countIssues).ToList();

        // Manifests: one per folder (and one for the folders themselves), entries sorted, so unchanged folders reuse their manifest.
        var manifestIds = new List<byte[]>();
        foreach (var group in members.GroupBy(m => m.Kind == "folder" ? "\u0000folders" : m.ParentSourceId ?? "").OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var entries = group.OrderBy(m => m.SourceId, StringComparer.Ordinal).Select(m => new ManifestEntry(m.SourceId, m.ParentSourceId, m.Kind,
                m.SealedMetadata is null ? "{}" : MetadataSealer.Open(keys, target.ProtectedObjectId, m.SourceId, m.SealedMetadata),
                m.ContentChunks is null ? null : new ItemContent(m.Size, m.ContentHash ?? [], Chunks(m.ContentChunks)))).ToList();
            manifestIds.Add(await writer.WriteManifestAsync(new Manifest(target.ProtectedObjectId, entries), cancellationToken).ConfigureAwait(false));
        }

        var counts = members.Where(m => m.Kind != "folder").GroupBy(m => m.Kind).ToDictionary(g => g.Key, g => (long)g.Count());
        counts["folders"] = members.Count(m => m.Kind == "folder");
        counts["items"] = members.Count(m => m.Kind != "folder");
        counts["exceptions"] = exceptions.Count;
        var partial = allExceptions.Count > 0;
        var countsJson = JsonSerializer.Serialize(counts.OrderBy(c => c.Key, StringComparer.Ordinal).ToDictionary());
        var exceptionsJson = JsonSerializer.Serialize(allExceptions);
        var root = new SnapshotRoot(target.TenantId, target.ProtectedObjectId, target.SnapshotId, startedAt,
            partial ? SnapshotOutcome.Partial : SnapshotOutcome.Committed, countsJson, exceptionsJson, manifestIds);
        var rootHash = await writer.CommitSnapshotAsync(root, cancellationToken).ConfigureAwait(false);

        await using (var session = await Session(target, cancellationToken).ConfigureAwait(false))
        {
            var now = clock.GetUtcNow();
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                -- Older versions replaced by a version of this snapshot, and removed items, end with this snapshot.
                UPDATE vaulty.items old SET deleted_in_snapshot_id = @SnapshotId
                  FROM vaulty.items newer
                 WHERE old.tenant_id = @TenantId AND old.protected_object_id = @ProtectedObjectId AND old.deleted_in_snapshot_id IS NULL
                   AND old.state = 'committed' AND newer.tenant_id = @TenantId AND newer.protected_object_id = @ProtectedObjectId
                   AND newer.first_snapshot_id = @SnapshotId AND newer.source_id = old.source_id AND newer.id <> old.id;
                UPDATE vaulty.items SET deleted_in_snapshot_id = @SnapshotId
                 WHERE tenant_id = @TenantId AND protected_object_id = @ProtectedObjectId AND deleted_in_snapshot_id IS NULL
                   AND source_id IN (SELECT source_id FROM vaulty.pending_removals WHERE snapshot_id = @SnapshotId);
                UPDATE vaulty.items SET state = 'committed'
                 WHERE tenant_id = @TenantId AND protected_object_id = @ProtectedObjectId AND first_snapshot_id = @SnapshotId AND state = 'staged';
                UPDATE vaulty.packs SET state = 'committed' WHERE tenant_id = @TenantId AND state = 'staged' AND object_key = ANY(@newPacks);
                UPDATE vaulty.snapshots SET state = @state, committed_at = coalesce(committed_at, @now), item_counts = @countsJson::jsonb,
                       exceptions = @exceptionsJson::jsonb, manifest_root_hash = @rootHash, object_key = @objectKey, lock_until = @lockUntil
                 WHERE id = @SnapshotId AND state = 'staged';
                UPDATE vaulty.protected_objects o
                   SET delta_state = o.delta_state || coalesce((SELECT jsonb_object_agg(c.folder_id, c.delta_link) FROM vaulty.folder_checkpoints c
                                                                 WHERE c.snapshot_id = @SnapshotId AND c.completed AND c.delta_link IS NOT NULL), '{}'::jsonb),
                       last_snapshot_id = @SnapshotId, next_run_at = @nextRun
                 WHERE o.id = @ProtectedObjectId;
                """,
                new
                {
                    target.TenantId, target.ProtectedObjectId, target.SnapshotId, newPacks = newPacks.ToArray(), state = partial ? "partial" : "committed",
                    now, countsJson, exceptionsJson, rootHash, objectKey = RepositoryLayout.Snapshot(target.TenantId, target.ProtectedObjectId, target.SnapshotId),
                    lockUntil, nextRun = now + frequency,
                }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await Audit.AuditLog.WriteAsync(session, "system:backup", partial ? "backup.partial" : "backup.completed", $"object:{target.ProtectedObjectId}",
                new { snapshot = target.SnapshotId, items = counts["items"], exceptions = allExceptions.Count }, cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        return new CommitResult(partial, counts, allExceptions, rootHash);
    }

    /// <summary>Marks a snapshot that could not be committed as failed; its staged data is ignored and cleaned up later.</summary>
    public async Task FailAsync(BackupTarget target, string reason, CancellationToken cancellationToken = default)
    {
        await using var session = await Session(target, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.snapshots SET state = 'failed', exceptions = @reason::jsonb WHERE id = @SnapshotId AND state = 'staged'",
            new { target.SnapshotId, reason = JsonSerializer.Serialize(new[] { new { error_code = "failed", detail = reason } }) }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await Audit.AuditLog.WriteAsync(session, "system:backup", "backup.failed", $"object:{target.ProtectedObjectId}",
            new { snapshot = target.SnapshotId, reason }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static List<ChunkId> Chunks(byte[] packed)
    {
        var list = new List<ChunkId>(packed.Length / ChunkId.Size);
        for (var i = 0; i + ChunkId.Size <= packed.Length; i += ChunkId.Size) list.Add(new ChunkId(packed.AsSpan(i, ChunkId.Size).ToArray()));
        return list;
    }

    private sealed class MemberRow
    {
        public Guid Id { get; set; }
        public string SourceId { get; set; } = "";
        public string? ParentSourceId { get; set; }
        public string Kind { get; set; } = "";
        public byte[]? SealedMetadata { get; set; }
        public byte[]? ContentHash { get; set; }
        public long Size { get; set; }
        public byte[]? ContentChunks { get; set; }
    }
}
