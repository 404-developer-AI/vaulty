using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Browse;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Restore;

public sealed record RestoreRequest(Guid ObjectId, Guid SnapshotId, RestoreSelection Selection, string Mode, Guid? TargetObjectId, string Conflict);

public sealed record CreatedRestore(Guid RestoreId, Guid JobId, Guid TenantId, bool IsExport);

public sealed record RestoreSummary(Guid Id, Guid ProtectedObjectId, string Kind, string TargetMode, string State, DateTimeOffset CreatedAt,
    DateTimeOffset? FinishedAt, RestoreCounts? Counts, Guid RequestedBy);

public sealed record RestoreItemReport(Guid ItemId, string SourceId, string Kind, string RelativePath, string State, string? TargetId, string? Detail);

public sealed record ExportInfo(Guid Id, long Size, DateTimeOffset ExpiresAt, DateTimeOffset? DownloadedAt, bool HasLink, Guid CreatedBy);

public sealed record RestoreReport(RestoreSummary Restore, ObjectHeader Object, IReadOnlyList<RestoreItemReport> Items, ExportInfo? Export);

/// <summary>A sensitive action was asked without a recent "Confirm it's you".</summary>
public sealed class StepUpRequiredException() : InvalidOperationException("Confirm it's you before this action.");

/// <summary>
/// Restores and exports as the web app starts and follows them: permission per customer (restore in place, to another
/// location, export), "Confirm it's you" for exports and restores elsewhere, and one-time export links bound to the user.
/// </summary>
public sealed class RestoreService(NpgsqlDataSource dataSource, SnapshotBrowser browser, TimeProvider clock)
{
    public static readonly TimeSpan LinkLifetime = TimeSpan.FromHours(24);

    public async Task<CreatedRestore> CreateAsync(UserAccess access, bool stepUpFresh, RestoreRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(request);
        var source = await browser.ObjectAsync(access, request.ObjectId, cancellationToken).ConfigureAwait(false)
                     ?? throw new AccessException("You do not have access to this protected object.");
        if (request.Selection.ItemIds.Count == 0 && request.Selection.FolderIds.Count == 0) throw new ArgumentException("Select at least one item or folder.");
        var conflict = request.Conflict is "rename" or "skip" or "overwrite" ? request.Conflict : throw new ArgumentException("Unknown conflict choice.");
        var isExport = request.Mode == RestoreModes.Export;
        switch (request.Mode)
        {
            case RestoreModes.Export:
                Require(access, Permissions.ExportCreate, source.CustomerId);
                if (!stepUpFresh) throw new StepUpRequiredException();
                break;
            case RestoreModes.Other:
                Require(access, Permissions.RestoreOtherLocation, source.CustomerId);
                if (!stepUpFresh) throw new StepUpRequiredException();
                var target = request.TargetObjectId is { } t ? await browser.ObjectAsync(access, t, cancellationToken).ConfigureAwait(false) : null;
                if (target is null || target.TenantId != source.TenantId || target.Kind != source.Kind || target.Id == source.Id)
                {
                    throw new ArgumentException("Choose another protected object of the same type in the same tenant.");
                }
                Require(access, Permissions.RestoreOtherLocation, target.CustomerId);
                break;
            case RestoreModes.RestoreFolder or RestoreModes.Original:
                Require(access, Permissions.RestoreInPlace, source.CustomerId);
                break;
            default:
                throw new ArgumentException("Unknown restore target.");
        }

        var restoreId = Guid.CreateVersion7();
        var jobId = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var valid = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT EXISTS (SELECT 1 FROM vaulty.snapshots WHERE id = @SnapshotId AND protected_object_id = @ObjectId AND state IN ('committed', 'partial'))",
            request, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (!valid) throw new ArgumentException("The snapshot does not exist.");
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.jobs (id, organization_id, tenant_id, protected_object_id, kind, state, requested_by)
                VALUES (@jobId, @org, @tenant, @ObjectId, @jobKind, 'queued', @user);
            INSERT INTO vaulty.restores (id, organization_id, tenant_id, protected_object_id, snapshot_id, job_id, kind, target_mode, target_object_id,
                conflict, selection, requested_by)
                VALUES (@restoreId, @org, @tenant, @ObjectId, @SnapshotId, @jobId, @jobKind, @Mode, @target, @conflict, @selection::jsonb, @user);
            """, new
            {
                jobId, restoreId, org = access.OrganizationId, tenant = source.TenantId, request.ObjectId, request.SnapshotId, request.Mode,
                target = request.Mode == RestoreModes.Other ? request.TargetObjectId : null, conflict, user = access.UserId,
                jobKind = isExport ? "export" : "restore", selection = JsonSerializer.Serialize(request.Selection),
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", isExport ? "export.requested" : "restore.requested", $"object:{request.ObjectId}",
            new
            {
                restore = restoreId, snapshot = request.SnapshotId, mode = request.Mode, target = request.TargetObjectId, conflict,
                items = request.Selection.ItemIds.Count, folders = request.Selection.FolderIds.Count,
            }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new CreatedRestore(restoreId, jobId, source.TenantId, isExport);
    }

    public async Task<IReadOnlyList<RestoreSummary>> ListAsync(UserAccess access, Guid objectId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        if (await browser.ObjectAsync(access, objectId, cancellationToken).ConfigureAwait(false) is null) return [];
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<SummaryRow>(new CommandDefinition(
            """
            SELECT id, protected_object_id, kind, target_mode, state, created_at, finished_at, counts::text AS counts, requested_by
              FROM vaulty.restores WHERE protected_object_id = @objectId AND report_expires_at > now() ORDER BY created_at DESC LIMIT 50
            """, new { objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(Summary).ToList();
    }

    /// <summary>The restore with its result per item (the first 2,000; the counts cover all).</summary>
    public async Task<RestoreReport?> ReportAsync(UserAccess access, Guid restoreId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        SummaryRow? row;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false))
        {
            row = await session.Connection.QuerySingleOrDefaultAsync<SummaryRow>(new CommandDefinition(
                """
                SELECT id, protected_object_id, kind, target_mode, state, created_at, finished_at, counts::text AS counts, requested_by
                  FROM vaulty.restores WHERE id = @restoreId AND report_expires_at > now()
                """, new { restoreId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        if (row is null) return null;
        var header = await browser.ObjectAsync(access, row.ProtectedObjectId, cancellationToken).ConfigureAwait(false);
        if (header is null) return null;
        await using var read = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var items = (await read.Connection.QueryAsync<RestoreItemReport>(new CommandDefinition(
            """
            SELECT item_id, source_id, kind, relative_path, state, target_id, detail FROM vaulty.restore_items
             WHERE restore_id = @restoreId ORDER BY (state = 'failed') DESC, relative_path, item_id LIMIT 2000
            """, new { restoreId }, read.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var counts = await read.Connection.QuerySingleAsync<RestoreCounts>(new CommandDefinition(
            """
            SELECT count(*) AS total, count(*) FILTER (WHERE state = 'restored') AS restored, count(*) FILTER (WHERE state = 'skipped') AS skipped,
                   count(*) FILTER (WHERE state = 'failed') AS failed, count(*) FILTER (WHERE state = 'pending') AS pending
              FROM vaulty.restore_items WHERE restore_id = @restoreId
            """, new { restoreId }, read.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var export = await read.Connection.QuerySingleOrDefaultAsync<(Guid Id, long Size, DateTime ExpiresAt, DateTime? DownloadedAt, byte[]? TokenHash, Guid CreatedBy)>(
            new CommandDefinition("SELECT id, size, expires_at, downloaded_at, token_hash, created_by FROM vaulty.exports WHERE restore_id = @restoreId",
                new { restoreId }, read.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return new RestoreReport(Summary(row) with { Counts = counts }, header, items,
            export.Id == Guid.Empty ? null : new ExportInfo(export.Id, export.Size, Utc(export.ExpiresAt), export.DownloadedAt is { } d ? Utc(d) : null,
                export.TokenHash is not null, export.CreatedBy));
    }

    /// <summary>
    /// A new one-time download link for an export, for the user who asked for it, after "Confirm it's you". The token is
    /// returned once; only its hash is stored. A new link replaces an earlier one that was not used.
    /// </summary>
    public async Task<(Guid ExportId, string Token)> CreateLinkAsync(UserAccess access, bool stepUpFresh, Guid restoreId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        if (!stepUpFresh) throw new StepUpRequiredException();
        var report = await ReportAsync(access, restoreId, cancellationToken).ConfigureAwait(false);
        if (report?.Export is not { } export) throw new AccessException("This export does not exist.");
        Require(access, Permissions.ExportCreate, report.Object.CustomerId);
        if (export.CreatedBy != access.UserId) throw new AccessException("Only the user who asked for the export can download it.");
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var updated = await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.exports SET token_hash = @hash WHERE id = @id AND downloaded_at IS NULL AND expires_at > @now AND created_by = @user",
            new { id = export.Id, hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token)), now = clock.GetUtcNow(), user = access.UserId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (updated == 0) throw new AccessException("This export was downloaded already or has expired.");
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "export.link_created", $"restore:{restoreId}", new { export = export.Id },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return (export.Id, token);
    }

    /// <summary>
    /// Claims the download: succeeds once, for the user the link belongs to, with the right token, before it expires.
    /// Returns the object key of the zip, or null when the link is not (or no longer) valid.
    /// </summary>
    public async Task<(string ObjectKey, long Size, Guid RestoreId)?> ClaimDownloadAsync(UserAccess access, bool stepUpFresh, Guid exportId, string token,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(token);
        if (!stepUpFresh || !access.Allows(Permissions.ExportCreate)) return null;
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var claimed = await session.Connection.QuerySingleOrDefaultAsync<(string ObjectKey, long Size, Guid RestoreId)?>(new CommandDefinition(
            """
            UPDATE vaulty.exports SET downloaded_at = @now
             WHERE id = @exportId AND downloaded_at IS NULL AND expires_at > @now AND created_by = @user AND token_hash = @hash
            RETURNING object_key, size, restore_id
            """, new { exportId, now = clock.GetUtcNow(), user = access.UserId, hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token)) },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", claimed is null ? "export.download_refused" : "export.downloaded", $"export:{exportId}", null,
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return claimed;
    }

    private static void Require(UserAccess access, string permission, Guid customerId)
    {
        if (!access.Allows(permission, customerId)) throw new AccessException($"You do not have the permission \"{Permissions.Get(permission).Label}\" for this customer.");
    }

    private static RestoreSummary Summary(SummaryRow r) => new(r.Id, r.ProtectedObjectId, r.Kind, r.TargetMode, r.State, Utc(r.CreatedAt),
        r.FinishedAt is { } f ? Utc(f) : null, string.IsNullOrEmpty(r.Counts) || r.Counts == "{}" ? null : JsonSerializer.Deserialize<RestoreCounts>(r.Counts), r.RequestedBy);

    private static DateTimeOffset Utc(DateTime value) => new(DateTime.SpecifyKind(value, DateTimeKind.Utc));

    private sealed class SummaryRow
    {
        public Guid Id { get; set; }
        public Guid ProtectedObjectId { get; set; }
        public string Kind { get; set; } = "";
        public string TargetMode { get; set; } = "";
        public string State { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public DateTime? FinishedAt { get; set; }
        public string? Counts { get; set; }
        public Guid RequestedBy { get; set; }
    }
}
