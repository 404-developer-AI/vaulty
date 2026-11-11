using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Database;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Retention;

public sealed record GcOptions
{
    /// <summary>A run that would remove more than this share of a tenant's stored bytes is refused (kill switch).</summary>
    public double MaxDeleteFraction { get; init; } = 0.25;

    /// <summary>Largest accepted difference between this host's clock and the database clock.</summary>
    public TimeSpan MaxClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Data of failed backups is kept this long before it counts as unreferenced.</summary>
    public TimeSpan FailedBackupGrace { get; init; } = TimeSpan.FromDays(7);

    /// <summary>The independent clock this host's clock is compared with; null means the database clock.</summary>
    public Func<CancellationToken, Task<DateTimeOffset>>? ReferenceClock { get; init; }
}

public sealed record GcReport(
    Guid RunId, bool DryRun, string State, string? Reason, int SnapshotsExpired, int LiveSnapshots, int PacksDeleted, long BytesDeleted,
    int PacksWaitingForLock, int PacksLocked, int ManifestsDeleted, int ItemRowsDeleted, long TenantBytes, IReadOnlyList<string> SampleKeys);

/// <summary>
/// Garbage collection of one tenant, mark and sweep. Mark: snapshots outside retention (never under legal hold, and never
/// the newest snapshot of an object that still exists) expire; everything a remaining snapshot references is live. Sweep:
/// packs, index files, manifests and snapshot roots that nothing live references and whose Object Lock has expired are
/// deleted with the garbage-collection identity, the only one that may delete. Refuses to run when the clocks disagree,
/// while a backup of the tenant runs, or when a run would remove more than the kill-switch share of the tenant.
/// </summary>
public sealed class GarbageCollector(NpgsqlDataSource dataSource, IBackupStorage storage, TenantKeyProvider keys, TimeProvider clock, GcOptions? options = null)
{
    private readonly GcOptions _options = options ?? new GcOptions();

    public async Task<GcReport> RunAsync(Guid organizationId, Guid tenantId, bool dryRun, CancellationToken cancellationToken = default)
    {
        var runId = Guid.CreateVersion7();
        var now = clock.GetUtcNow();
        var store = await storage.WorkerStoreAsync(cancellationToken).ConfigureAwait(false);
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            DateTimeOffset reference;
            if (_options.ReferenceClock is { } referenceClock)
            {
                reference = await referenceClock(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                var databaseNow = await session.Connection.ExecuteScalarAsync<DateTime>(new CommandDefinition("SELECT now()", transaction: session.Transaction,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
                reference = new DateTimeOffset(DateTime.SpecifyKind(databaseNow, DateTimeKind.Utc));
            }
            var skew = (now - reference).Duration();
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO vaulty.gc_runs (id, organization_id, tenant_id, dry_run, started_at) VALUES (@runId, @organizationId, @tenantId, @dryRun, @now)",
                new { runId, organizationId, tenantId, dryRun, now }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            if (skew > _options.MaxClockSkew)
            {
                return await RefuseAsync(organizationId, runId, dryRun, $"The clock of this host differs {skew.TotalMinutes:F0} minutes from the database clock.",
                    cancellationToken).ConfigureAwait(false);
            }
        }

        var plan = await PlanAsync(store, organizationId, tenantId, now, cancellationToken).ConfigureAwait(false);
        if (plan.RunningBackups > 0)
        {
            return await RefuseAsync(organizationId, runId, dryRun, "A backup of this tenant is running; garbage collection waits for it.", cancellationToken)
                .ConfigureAwait(false);
        }
        var deletable = plan.DeadPacks.Where(p => p.LockUntil <= now).ToList();
        var deletableBytes = deletable.Sum(p => p.Size);
        if (!plan.TenantDeleted && plan.TenantBytes > 0 && (double)deletableBytes / plan.TenantBytes > _options.MaxDeleteFraction)
        {
            return await RefuseAsync(organizationId, runId, dryRun,
                $"This run would remove {100.0 * deletableBytes / plan.TenantBytes:F0}% of the tenant's data, more than the limit of {100 * _options.MaxDeleteFraction:F0}%.",
                cancellationToken).ConfigureAwait(false);
        }

        var packsDeleted = 0;
        var locked = 0;
        long bytesDeleted = 0;
        var manifestsDeleted = 0;
        var itemRows = 0;
        if (!dryRun)
        {
            foreach (var pack in deletable)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    // The index file first: a pack without index file is found by a rebuild, an index file without pack is not.
                    await DeleteIfPresentAsync(store, RepositoryLayout.Index(tenantId, pack.Hash), cancellationToken).ConfigureAwait(false);
                    await DeleteIfPresentAsync(store, pack.ObjectKey, cancellationToken).ConfigureAwait(false);
                }
                catch (ObjectLockedException)
                {
                    // Object Lock disagrees with the database: the storage provider wins, nothing is removed.
                    locked++;
                    continue;
                }
                await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
                await session.Connection.ExecuteAsync(new CommandDefinition(
                    """
                    DELETE FROM vaulty.chunk_index WHERE tenant_id = @tenantId AND pack_id = @id;
                    UPDATE vaulty.packs SET state = 'deleted' WHERE id = @id;
                    """, new { tenantId, pack.Id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
                await session.CommitAsync(cancellationToken).ConfigureAwait(false);
                packsDeleted++;
                bytesDeleted += pack.Size;
            }
            foreach (var key in plan.DeadManifestKeys.Concat(plan.ExpiredRootKeys))
            {
                try
                {
                    var head = await store.HeadAsync(key, cancellationToken).ConfigureAwait(false);
                    if (head is null || head.LockUntil > now) continue;
                    await store.DeleteAsync(key, cancellationToken).ConfigureAwait(false);
                    if (plan.DeadManifestKeys.Contains(key)) manifestsDeleted++;
                }
                catch (ObjectLockedException)
                {
                    locked++;
                }
            }
            await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
            {
                await session.Connection.ExecuteAsync(new CommandDefinition(
                    "UPDATE vaulty.snapshots SET state = 'expired' WHERE id = ANY(@ids) AND state IN ('committed', 'partial')",
                    new { ids = plan.ExpiredSnapshots.ToArray() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
                // Item versions that only expired snapshots held, once none of their chunks remain in a pack that still exists.
                itemRows = await session.Connection.ExecuteAsync(new CommandDefinition(
                    """
                    DELETE FROM vaulty.items i USING unnest(@objects, @limits) AS l(object_id, live_from)
                     WHERE i.tenant_id = @tenantId AND i.protected_object_id = l.object_id AND i.state = 'committed'
                       AND i.deleted_sequence IS NOT NULL AND i.deleted_sequence <= l.live_from
                    """, new { tenantId, objects = plan.LiveFrom.Keys.ToArray(), limits = plan.LiveFrom.Values.ToArray() }, session.Transaction,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
                await AuditLog.WriteAsync(session, "system:gc", "gc.completed", $"tenant:{tenantId}",
                    new { run = runId, packs = packsDeleted, bytes = bytesDeleted, snapshots = plan.ExpiredSnapshots.Count, locked }, cancellationToken).ConfigureAwait(false);
                await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        var report = new GcReport(runId, dryRun, "succeeded", null, plan.ExpiredSnapshots.Count, plan.LiveSnapshots, dryRun ? deletable.Count : packsDeleted,
            dryRun ? deletableBytes : bytesDeleted, plan.DeadPacks.Count - deletable.Count, locked, dryRun ? plan.DeadManifestKeys.Count : manifestsDeleted, itemRows,
            plan.TenantBytes, deletable.Take(20).Select(p => p.ObjectKey).ToList());
        await FinishAsync(organizationId, report, cancellationToken).ConfigureAwait(false);
        return report;
    }

    private sealed record DeadPack(Guid Id, string Hash, string ObjectKey, long Size, DateTimeOffset LockUntil);

    private sealed record Plan(List<Guid> ExpiredSnapshots, int LiveSnapshots, Dictionary<Guid, long> LiveFrom, List<DeadPack> DeadPacks,
        HashSet<string> DeadManifestKeys, List<string> ExpiredRootKeys, long TenantBytes, int RunningBackups, bool TenantDeleted);

    private async Task<Plan> PlanAsync(IObjectStore store, Guid organizationId, Guid tenantId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var tenant = await session.Connection.QuerySingleAsync<(string State, bool LegalHold)>(new CommandDefinition(
            "SELECT state, legal_hold FROM vaulty.tenants WHERE id = @tenantId", new { tenantId }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        var running = await session.Connection.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT count(*) FROM vaulty.snapshots WHERE tenant_id = @tenantId AND state = 'staged' AND started_at > @since",
            new { tenantId, since = now - _options.FailedBackupGrace }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var objects = (await session.Connection.QueryAsync<(Guid Id, string State, bool LegalHold)>(new CommandDefinition(
            "SELECT id, state, legal_hold FROM vaulty.protected_objects WHERE tenant_id = @tenantId", new { tenantId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var snapshots = (await session.Connection.QueryAsync<(Guid Id, Guid ObjectId, long Sequence, DateTime StartedAt)>(new CommandDefinition(
            "SELECT id, protected_object_id, sequence, started_at FROM vaulty.snapshots WHERE tenant_id = @tenantId AND state IN ('committed', 'partial')",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();

        var tenantDeleted = tenant.State == "deleted";
        var expired = new List<Guid>();
        var live = new List<(Guid Id, Guid ObjectId)>();
        var liveFrom = new Dictionary<Guid, long>();
        foreach (var o in objects)
        {
            var policy = await PolicyResolver.ForObjectAsync(dataSource, organizationId, tenantId, o.Id, cancellationToken).ConfigureAwait(false);
            var hold = o.LegalHold || tenant.LegalHold;
            var cutoff = now.AddDays(-policy.RetentionDays);
            var own = snapshots.Where(s => s.ObjectId == o.Id).OrderBy(s => s.Sequence).ToList();
            var newest = own.LastOrDefault();
            foreach (var s in own)
            {
                // The newest snapshot outlives retention while backups are meant to continue, so stopped backups never lose
                // the last copy. A deleted tenant, a vanished source and a deliberately excluded object have no next backup:
                // there every snapshot ends with its retention.
                var keep = hold || new DateTimeOffset(DateTime.SpecifyKind(s.StartedAt, DateTimeKind.Utc)) >= cutoff
                           || (!tenantDeleted && o.State is not ("source_deleted" or "excluded") && s.Id == newest.Id);
                if (keep) live.Add((s.Id, o.Id));
                else expired.Add(s.Id);
            }
            // Retention removes the oldest snapshots first, so the live ones are the newest; their lowest sequence is the boundary.
            var liveSequences = own.Where(s => live.Any(l => l.Id == s.Id)).Select(s => s.Sequence).ToList();
            liveFrom[o.Id] = liveSequences.Count == 0 ? long.MaxValue : liveSequences.Min();
        }

        // Live packs: every pack holding a chunk of an item version that a live snapshot contains (content or preview), and
        // every pack written by a backup that is still within its grace period.
        var livePacks = (await session.Connection.QueryAsync<Guid>(new CommandDefinition(
            """
            WITH bounds AS (SELECT * FROM unnest(@objects, @limits) AS b(object_id, live_from)),
            versions AS (
                SELECT i.content_chunks AS chunks FROM vaulty.items i JOIN bounds b ON b.object_id = i.protected_object_id
                 WHERE i.tenant_id = @tenantId AND i.state = 'committed' AND b.live_from <> 9223372036854775807
                   AND (i.deleted_sequence IS NULL OR i.deleted_sequence > b.live_from) AND i.content_chunks IS NOT NULL
                UNION ALL
                SELECT i.preview_chunks FROM vaulty.items i JOIN bounds b ON b.object_id = i.protected_object_id
                 WHERE i.tenant_id = @tenantId AND i.state = 'committed' AND b.live_from <> 9223372036854775807
                   AND (i.deleted_sequence IS NULL OR i.deleted_sequence > b.live_from) AND i.preview_chunks IS NOT NULL
                UNION ALL
                SELECT coalesce(i.content_chunks, '') || coalesce(i.preview_chunks, '') FROM vaulty.items i
                 WHERE i.tenant_id = @tenantId AND i.state = 'staged' AND i.created_at > @grace
            ),
            ids AS (SELECT DISTINCT substring(v.chunks FROM g * 32 + 1 FOR 32) AS chunk FROM versions v, generate_series(0, length(v.chunks) / 32 - 1) g)
            SELECT DISTINCT c.pack_id FROM ids JOIN vaulty.chunk_index c ON c.tenant_id = @tenantId AND c.chunk_hash = ids.chunk
            """, new { tenantId, objects = liveFrom.Keys.ToArray(), limits = liveFrom.Values.ToArray(), grace = now - _options.FailedBackupGrace },
            session.Transaction, commandTimeout: 600, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToHashSet();
        var packs = (await session.Connection.QueryAsync<(Guid Id, string ObjectKey, long Size, DateTime LockUntil, string State, DateTime CreatedAt)>(new CommandDefinition(
            "SELECT id, object_key, size, lock_until, state, created_at FROM vaulty.packs WHERE tenant_id = @tenantId AND state <> 'deleted'",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var dead = packs.Where(p => !livePacks.Contains(p.Id) && (p.State == "committed" || p.CreatedAt < (now - _options.FailedBackupGrace).UtcDateTime))
            .Select(p => new DeadPack(p.Id, RepositoryLayout.PackHashFromKey(p.ObjectKey), p.ObjectKey, p.Size, new DateTimeOffset(DateTime.SpecifyKind(p.LockUntil, DateTimeKind.Utc))))
            .ToList();

        // Manifests are shared between snapshots: only those that no live snapshot lists are removed, with their expired roots.
        var repositoryKeys = await keys.GetAsync(organizationId, tenantId, cancellationToken).ConfigureAwait(false);
        var reader = new RepositoryReader(store, repositoryKeys, new PostgresChunkIndex(dataSource, organizationId, tenantId));
        var liveManifests = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, objectId) in live)
        {
            var root = await reader.ReadSnapshotAsync(objectId, id, cancellationToken).ConfigureAwait(false);
            foreach (var m in root.ManifestIds) liveManifests.Add(RepositoryLayout.Manifest(tenantId, Convert.ToHexStringLower(m)));
        }
        var deadManifests = new HashSet<string>(StringComparer.Ordinal);
        var expiredRoots = new List<string>();
        foreach (var id in expired)
        {
            var objectId = snapshots.Single(s => s.Id == id).ObjectId;
            try
            {
                var root = await reader.ReadSnapshotAsync(objectId, id, cancellationToken).ConfigureAwait(false);
                foreach (var m in root.ManifestIds)
                {
                    var key = RepositoryLayout.Manifest(tenantId, Convert.ToHexStringLower(m));
                    if (!liveManifests.Contains(key)) deadManifests.Add(key);
                }
            }
            catch (ObjectNotFoundException)
            {
                // Removed by an earlier run.
            }
            expiredRoots.Add(RepositoryLayout.Snapshot(tenantId, objectId, id));
        }
        return new Plan(expired, live.Count, liveFrom, dead, deadManifests, expiredRoots, packs.Where(p => p.State == "committed").Sum(p => p.Size), running,
            tenantDeleted);
    }

    private static async Task DeleteIfPresentAsync(IObjectStore store, string key, CancellationToken cancellationToken)
    {
        if (await store.HeadAsync(key, cancellationToken).ConfigureAwait(false) is null) return;
        await store.DeleteAsync(key, cancellationToken).ConfigureAwait(false);
    }

    private async Task<GcReport> RefuseAsync(Guid organizationId, Guid runId, bool dryRun, string reason, CancellationToken cancellationToken)
    {
        var report = new GcReport(runId, dryRun, "refused", reason, 0, 0, 0, 0, 0, 0, 0, 0, 0, []);
        await FinishAsync(organizationId, report, cancellationToken).ConfigureAwait(false);
        return report;
    }

    private async Task FinishAsync(Guid organizationId, GcReport report, CancellationToken cancellationToken)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.gc_runs SET finished_at = @now, state = @State, snapshots_expired = @SnapshotsExpired, packs_deleted = @PacksDeleted,
                   bytes_deleted = @BytesDeleted, report = @json::jsonb
             WHERE id = @RunId
            """, new { now = clock.GetUtcNow(), report.State, report.SnapshotsExpired, report.PacksDeleted, report.BytesDeleted, report.RunId,
                json = JsonSerializer.Serialize(report) }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }
}
