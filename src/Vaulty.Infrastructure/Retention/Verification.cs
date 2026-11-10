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

public sealed record VerificationFailure(string Kind, string Target, string Detail);

public sealed record VerificationResult(Guid RunId, int PacksScrubbed, int ItemsDrilled, int SnapshotsChecked, IReadOnlyList<VerificationFailure> Failures);

public sealed record VerificationOptions
{
    /// <summary>Share of a tenant's packs that is re-read in full per week.</summary>
    public double WeeklyScrubFraction { get; init; } = 0.01;

    /// <summary>Items reconstructed in memory per run (the restore drill).</summary>
    public int DrillItems { get; init; } = 10;

    /// <summary>A snapshot counts as verified only when its tenant had a scrub this recently.</summary>
    public TimeSpan ScrubValidity { get; init; } = TimeSpan.FromDays(7);
}

/// <summary>
/// Re-reads stored data to prove it can be restored. A scrub re-reads whole packs (oldest scrub first, at least the weekly
/// share); the restore drill reconstructs random items in memory and compares their content hash; every latest snapshot is
/// opened (root, Merkle root, manifests). Anything that does not match is a critical alert. Snapshots are marked verified
/// only when all of that passed and the tenant's scrub is recent.
/// </summary>
public sealed class VerificationService(NpgsqlDataSource dataSource, IBackupStorage storage, TenantKeyProvider keys, TimeProvider clock,
    VerificationOptions? options = null)
{
    private readonly VerificationOptions _options = options ?? new VerificationOptions();

    public async Task<VerificationResult> RunAsync(Guid organizationId, Guid tenantId, Action? heartbeat = null, CancellationToken cancellationToken = default)
    {
        var runId = Guid.CreateVersion7();
        var now = clock.GetUtcNow();
        var failures = new List<VerificationFailure>();
        var repositoryKeys = await keys.GetAsync(organizationId, tenantId, cancellationToken).ConfigureAwait(false);
        var store = await storage.WorkerStoreAsync(cancellationToken).ConfigureAwait(false);
        var reader = new RepositoryReader(store, repositoryKeys, new PostgresChunkIndex(dataSource, organizationId, tenantId));

        List<(Guid Id, string ObjectKey)> packs;
        List<(Guid ItemId, Guid ObjectId, string SourceId, long Size, byte[] Hash, byte[] Chunks)> drill;
        List<(Guid SnapshotId, Guid ObjectId)> latest;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO vaulty.verification_runs (id, organization_id, tenant_id, started_at) VALUES (@runId, @organizationId, @tenantId, @now)",
                new { runId, organizationId, tenantId, now }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            var total = await session.Connection.ExecuteScalarAsync<int>(new CommandDefinition(
                "SELECT count(*) FROM vaulty.packs WHERE tenant_id = @tenantId AND state = 'committed'", new { tenantId }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            // A daily run scrubs a seventh of the weekly share, at least one pack; packs never scrubbed come first.
            var take = Math.Max(1, (int)Math.Ceiling(total * _options.WeeklyScrubFraction / 7));
            packs = (await session.Connection.QueryAsync<(Guid, string)>(new CommandDefinition(
                """
                SELECT id, object_key FROM vaulty.packs WHERE tenant_id = @tenantId AND state = 'committed'
                 ORDER BY last_scrubbed_at NULLS FIRST, created_at LIMIT @take
                """, new { tenantId, take }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            drill = (await session.Connection.QueryAsync<(Guid, Guid, string, long, byte[], byte[])>(new CommandDefinition(
                """
                SELECT id, protected_object_id, source_id, size, content_hash, content_chunks FROM vaulty.items
                 WHERE tenant_id = @tenantId AND state = 'committed' AND deleted_sequence IS NULL AND content_chunks IS NOT NULL
                 ORDER BY random() LIMIT @n
                """, new { tenantId, n = _options.DrillItems }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            latest = (await session.Connection.QueryAsync<(Guid, Guid)>(new CommandDefinition(
                """
                SELECT DISTINCT ON (protected_object_id) id, protected_object_id FROM vaulty.snapshots
                 WHERE tenant_id = @tenantId AND state IN ('committed', 'partial') ORDER BY protected_object_id, sequence DESC
                """, new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }

        var scrubbed = new List<Guid>();
        var damaged = new List<Guid>();
        foreach (var (id, key) in packs)
        {
            try
            {
                await reader.VerifyPackAsync(RepositoryLayout.PackHashFromKey(key), null, cancellationToken).ConfigureAwait(false);
                scrubbed.Add(id);
            }
            catch (Exception ex) when (ex is IntegrityException or RepositoryFormatException or ObjectNotFoundException)
            {
                damaged.Add(id);
                failures.Add(new VerificationFailure("pack", key, ex.Message));
            }
            heartbeat?.Invoke();
        }

        foreach (var item in drill)
        {
            try
            {
                var content = new ItemContent(item.Size, item.Hash, Chunks(item.Chunks));
                await reader.ReadContentAsync(content, Stream.Null, cancellationToken).ConfigureAwait(false); // checks every chunk and the content hash
            }
            catch (Exception ex) when (ex is IntegrityException or RepositoryFormatException or ObjectNotFoundException)
            {
                failures.Add(new VerificationFailure("item", $"object:{item.ObjectId}/item:{item.ItemId}", ex.Message));
            }
            heartbeat?.Invoke();
        }

        var opened = new List<Guid>();
        foreach (var (snapshotId, objectId) in latest)
        {
            try
            {
                var root = await reader.ReadSnapshotAsync(objectId, snapshotId, cancellationToken).ConfigureAwait(false);
                foreach (var manifest in root.ManifestIds) await reader.ReadManifestAsync(manifest, cancellationToken).ConfigureAwait(false);
                opened.Add(snapshotId);
            }
            catch (Exception ex) when (ex is IntegrityException or RepositoryFormatException or ObjectNotFoundException)
            {
                failures.Add(new VerificationFailure("snapshot", $"object:{objectId}/snapshot:{snapshotId}", ex.Message));
            }
            heartbeat?.Invoke();
        }

        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            var finished = clock.GetUtcNow();
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vaulty.packs SET last_scrubbed_at = @finished WHERE id = ANY(@scrubbed);
                UPDATE vaulty.packs SET scrub_failed_at = @finished WHERE id = ANY(@damaged);
                UPDATE vaulty.verification_runs SET finished_at = @finished, packs_scrubbed = @packs, items_drilled = @items, snapshots_checked = @snapshots,
                       failures = @failures::jsonb
                 WHERE id = @runId;
                """, new
                {
                    finished, scrubbed = scrubbed.ToArray(), damaged = damaged.ToArray(), packs = packs.Count, items = drill.Count, snapshots = latest.Count,
                    failures = JsonSerializer.Serialize(failures), runId,
                }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            var scrubRecent = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
                """
                SELECT NOT EXISTS (SELECT 1 FROM vaulty.packs WHERE tenant_id = @tenantId AND scrub_failed_at IS NOT NULL)
                   AND EXISTS (SELECT 1 FROM vaulty.packs WHERE tenant_id = @tenantId AND last_scrubbed_at > @since)
                """, new { tenantId, since = finished - _options.ScrubValidity }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (failures.Count == 0 && scrubRecent)
            {
                await session.Connection.ExecuteAsync(new CommandDefinition(
                    "UPDATE vaulty.snapshots SET verified_at = @finished WHERE id = ANY(@ids)", new { finished, ids = opened.ToArray() }, session.Transaction,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
            if (failures.Count > 0)
            {
                await Alerts.RaiseAsync(session, tenantId, null, "verification.failed", "critical",
                    $"Verification found {failures.Count} problem{(failures.Count == 1 ? "" : "s")} in stored data. Check the verification report; affected snapshots are not marked verified.",
                    new { run = runId, failures = failures.Take(50) }, cancellationToken).ConfigureAwait(false);
            }
            await AuditLog.WriteAsync(session, "system:verify", failures.Count == 0 ? "verification.completed" : "verification.failed", $"tenant:{tenantId}",
                new { run = runId, packs = packs.Count, items = drill.Count, snapshots = latest.Count, failures = failures.Count }, cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        return new VerificationResult(runId, packs.Count, drill.Count, latest.Count, failures);
    }

    private static List<ChunkId> Chunks(byte[] packed)
    {
        var list = new List<ChunkId>(packed.Length / ChunkId.Size);
        for (var i = 0; i + ChunkId.Size <= packed.Length; i += ChunkId.Size) list.Add(new ChunkId(packed.AsSpan(i, ChunkId.Size).ToArray()));
        return list;
    }
}

/// <summary>
/// Raising an alert: one open alert per kind and target, so a daily failure does not flood the list. A new alert is also
/// published as a notification event for webhooks unless the caller publishes its own event for every occurrence.
/// </summary>
public static class Alerts
{
    public static async Task<bool> RaiseAsync(OrganizationSession session, Guid? tenantId, Guid? objectId, string kind, string severity, string message, object? details,
        CancellationToken cancellationToken = default, bool publishEvent = true)
    {
        ArgumentNullException.ThrowIfNull(session);
        var inserted = await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.alerts (id, organization_id, tenant_id, protected_object_id, kind, severity, message, details)
            SELECT @id, vaulty.current_organization_id(), @tenantId, @objectId, @kind, @severity, @message, @details::jsonb
             WHERE NOT EXISTS (SELECT 1 FROM vaulty.alerts WHERE kind = @kind AND resolved_at IS NULL
                                 AND tenant_id IS NOT DISTINCT FROM @tenantId AND protected_object_id IS NOT DISTINCT FROM @objectId)
            """, new { id = Guid.CreateVersion7(), tenantId, objectId, kind, severity, message, details = JsonSerializer.Serialize(details ?? new { }) },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false) > 0;
        if (inserted && publishEvent)
        {
            await Notifications.NotificationEvents.PublishAsync(session, kind, tenantId, objectId, new { severity, message, details }, cancellationToken)
                .ConfigureAwait(false);
        }
        return inserted;
    }

    /// <summary>Closes the open alerts of these kinds for a protected object (a later success settles them).</summary>
    public static async Task<int> ResolveAsync(OrganizationSession session, Guid objectId, IReadOnlyCollection<string> kinds, DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        return await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.alerts SET resolved_at = @now WHERE protected_object_id = @objectId AND kind = ANY(@kinds) AND resolved_at IS NULL",
            new { objectId, kinds = kinds.ToArray(), now }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}

/// <summary>A drop of more than 30% of the items between two snapshots of one protected object is drift and raises an alert.</summary>
public static class DriftDetection
{
    public const double Threshold = 0.30;

    /// <summary>Small objects are left out: a few deleted items in a nearly empty mailbox are not a signal.</summary>
    public const long MinimumItems = 20;

    public static bool IsDrift(long? previous, long current) =>
        previous is { } p && p >= MinimumItems && current < p * (1 - Threshold);

    public static int DropPercent(long previous, long current) => previous <= 0 ? 0 : (int)Math.Round(100.0 * (previous - current) / previous);
}
