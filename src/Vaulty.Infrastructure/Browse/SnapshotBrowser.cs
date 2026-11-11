using System.Globalization;
using System.Text;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Database;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Browse;

public sealed record ObjectHeader(Guid Id, Guid TenantId, Guid CustomerId, string CustomerName, string TenantName, string Kind, string? SubKind,
    string DisplayName, string State);

public sealed record SnapshotSummary(Guid Id, long Sequence, string State, DateTimeOffset StartedAt, DateTimeOffset? CommittedAt,
    IReadOnlyDictionary<string, long> Counts, int Exceptions, DateTimeOffset? VerifiedAt);

/// <summary>One item a partial snapshot misses: the reason code, its explanation and where it was.</summary>
public sealed record SnapshotException(string Code, string? Detail, string? FolderId, string? SourceId);

public sealed record FolderNode(string SourceId, string? ParentSourceId, string Name, IReadOnlyList<FolderNode> Children);

public sealed record ItemRow(Guid Id, string SourceId, string Kind, long Size, DateTimeOffset ModifiedAt, string Title, string? Subtitle,
    bool HasPreview, bool LimitedFidelity);

public sealed record ItemPage(IReadOnlyList<ItemRow> Items, string? NextCursor, long Total);

public sealed record ItemVersionRow(Guid Id, string VersionId, long Size, DateTimeOffset ModifiedAt);

public sealed record ItemDetail(ItemRow Row, string? ParentSourceId, IReadOnlyDictionary<string, string> Fields, string? PreviewType,
    IReadOnlyList<ItemVersionRow> Versions);

public sealed record SearchHit(Guid ObjectId, string ObjectName, string ObjectKind, Guid TenantId, string TenantName, string CustomerName, Guid ItemId,
    string Kind, string Title, string? Subtitle, DateTimeOffset ModifiedAt);

/// <summary>A preview ready to serve: bytes and media type; HTML is already sanitized.</summary>
public sealed record ItemPreview(byte[] Content, string MediaType, string FileName);

/// <summary>Opens a reader on the backup data with the read-only identity of the web app.</summary>
public interface IRepositoryReaderFactory
{
    Task<RepositoryReader> CreateAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Read side of snapshots for the web app: snapshots of a protected object, the folder tree and pages of items of any
/// snapshot (point in time), item detail, search and previews. Every call checks the user's access to the customer; the
/// database checks the organization (row-level security). Metadata is decrypted per page, never stored in plain text.
/// </summary>
public sealed class SnapshotBrowser(NpgsqlDataSource dataSource, TenantKeyProvider keys, IRepositoryReaderFactory readers)
{
    public const int PageSize = 100;
    public const long PreviewLimit = 20 * 1024 * 1024;

    /// <summary>Media types a file preview is shown for; anything else (SVG and HTML files included) is download-only.</summary>
    public static readonly IReadOnlySet<string> PreviewableFileTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "application/pdf", "text/plain", "text/csv",
    };

    public async Task<ObjectHeader?> ObjectAsync(UserAccess access, Guid objectId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var header = await session.Connection.QuerySingleOrDefaultAsync<ObjectHeader>(new CommandDefinition(
            """
            SELECT o.id, o.tenant_id, c.id AS customer_id, c.name AS customer_name, t.display_name AS tenant_name, o.kind, o.sub_kind, o.display_name, o.state
              FROM vaulty.protected_objects o JOIN vaulty.tenants t ON t.id = o.tenant_id JOIN vaulty.customers c ON c.id = t.customer_id
             WHERE o.id = @objectId
            """, new { objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return header is not null && access.Allows(Permissions.SnapshotsBrowse, header.CustomerId) ? header : null;
    }

    public async Task<IReadOnlyList<SnapshotSummary>> SnapshotsAsync(UserAccess access, Guid objectId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        if (await ObjectAsync(access, objectId, cancellationToken).ConfigureAwait(false) is null) return [];
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, long Sequence, string State, DateTime StartedAt, DateTime? CommittedAt, string Counts,
            int Exceptions, DateTime? VerifiedAt)>(new CommandDefinition(
            """
            SELECT id, sequence, state, started_at, committed_at, item_counts::text, jsonb_array_length(exceptions), verified_at
              FROM vaulty.snapshots WHERE protected_object_id = @objectId AND state IN ('committed', 'partial') ORDER BY sequence DESC
            """, new { objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new SnapshotSummary(r.Id, r.Sequence, r.State, Utc(r.StartedAt), r.CommittedAt is { } c ? Utc(c) : null,
            JsonSerializer.Deserialize<Dictionary<string, long>>(r.Counts) ?? [], r.Exceptions, r.VerifiedAt is { } v ? Utc(v) : null)).ToList();
    }

    /// <summary>
    /// The items a snapshot misses, each with its reason, as recorded when the snapshot was committed. The list carries
    /// source ids and reasons only; names stay sealed with the item metadata.
    /// </summary>
    public async Task<IReadOnlyList<SnapshotException>> ExceptionsAsync(UserAccess access, Guid objectId, Guid snapshotId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        if (await ObjectAsync(access, objectId, cancellationToken).ConfigureAwait(false) is null) return [];
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var json = await session.Connection.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT exceptions::text FROM vaulty.snapshots WHERE id = @snapshotId AND protected_object_id = @objectId",
            new { snapshotId, objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return ParseExceptions(json);
    }

    /// <summary>Reads the exception list of a snapshot; entries are written both as ErrorCode/Detail and as error_code/detail.</summary>
    public static IReadOnlyList<SnapshotException> ParseExceptions(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return [];
        var list = new List<SnapshotException>();
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.Object) continue;
            list.Add(new SnapshotException(Text(e, "ErrorCode", "error_code") ?? "unknown", Text(e, "Detail", "detail"), Text(e, "FolderId", "folder_id"),
                Text(e, "SourceId", "source_id")));
        }
        return list;

        static string? Text(JsonElement e, string pascal, string snake) =>
            (e.TryGetProperty(pascal, out var v) || e.TryGetProperty(snake, out v)) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    /// <summary>The folder tree of a snapshot. The top level holds the containers the folders hang under (a mailbox root, a drive root).</summary>
    public async Task<IReadOnlyList<FolderNode>> FoldersAsync(UserAccess access, Guid objectId, Guid snapshotId, CancellationToken cancellationToken = default)
    {
        var (header, sequence) = await ResolveAsync(access, objectId, snapshotId, cancellationToken).ConfigureAwait(false);
        var repositoryKeys = await keys.GetAsync(access.OrganizationId, header.TenantId, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var folders = (await session.Connection.QueryAsync<(string SourceId, string? ParentSourceId, byte[]? SealedMetadata)>(new CommandDefinition(
            $"""
            SELECT source_id, parent_source_id, sealed_metadata FROM vaulty.items
             WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND kind = 'folder' AND {Membership}
            """, new { tenantId = header.TenantId, objectId, sequence }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var ids = folders.Select(f => f.SourceId).ToHashSet(StringComparer.Ordinal);
        // Parents of items that are not folders themselves: the drive root, or items outside any folder. A skip scan over the
        // browse index visits each distinct parent once instead of every item.
        var parents = (await session.Connection.QueryAsync<string>(new CommandDefinition(
            $"""
            WITH RECURSIVE p(parent) AS (
                (SELECT parent_source_id FROM vaulty.items
                  WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND parent_source_id IS NOT NULL
                    AND kind NOT IN ('folder', 'file_version') AND {Membership}
                  ORDER BY parent_source_id LIMIT 1)
                UNION ALL
                SELECT (SELECT parent_source_id FROM vaulty.items
                         WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND parent_source_id > p.parent
                           AND kind NOT IN ('folder', 'file_version') AND {Membership}
                         ORDER BY parent_source_id LIMIT 1)
                  FROM p WHERE p.parent IS NOT NULL)
            SELECT parent FROM p WHERE parent IS NOT NULL
            """, new { tenantId = header.TenantId, objectId, sequence }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToList();
        var looseParents = parents.Where(p => !ids.Contains(p)).ToList();

        var names = folders.ToDictionary(f => f.SourceId, f => Field(Open(repositoryKeys, objectId, f.SourceId, f.SealedMetadata), "name") ?? f.SourceId,
            StringComparer.Ordinal);
        var children = folders.GroupBy(f => f.ParentSourceId ?? "").ToDictionary(g => g.Key, g => g.Select(f => f.SourceId).ToList(), StringComparer.Ordinal);
        FolderNode Build(string id, string? parent, string name) => new(id, parent, name,
            children.TryGetValue(id, out var list) ? list.Select(c => Build(c, id, names[c])).OrderBy(n => n.Name, StringComparer.CurrentCultureIgnoreCase).ToList() : []);

        var roots = folders.Where(f => f.ParentSourceId is null || !ids.Contains(f.ParentSourceId)).Select(f => f.ParentSourceId ?? "")
            .Concat(looseParents).Distinct(StringComparer.Ordinal).ToList();
        var rootName = header.Kind == "drive" ? "Files" : header.DisplayName;
        return roots.Select(r => Build(r, null, roots.Count == 1 ? rootName : $"{rootName} ({r[..Math.Min(8, r.Length)]})")).ToList();
    }

    /// <summary>One page of the items in a folder of a snapshot, newest first, with keyset paging (<paramref name="cursor"/>).</summary>
    public async Task<ItemPage> ItemsAsync(UserAccess access, Guid objectId, Guid snapshotId, string folderId, string? cursor,
        CancellationToken cancellationToken = default)
    {
        var (header, sequence) = await ResolveAsync(access, objectId, snapshotId, cancellationToken).ConfigureAwait(false);
        var repositoryKeys = await keys.GetAsync(access.OrganizationId, header.TenantId, cancellationToken).ConfigureAwait(false);
        DateTime? afterModified = null;
        Guid? afterId = null;
        if (cursor is not null)
        {
            var parts = cursor.Split('_');
            afterModified = new DateTime(long.Parse(parts[0], CultureInfo.InvariantCulture), DateTimeKind.Utc);
            afterId = Guid.Parse(parts[1]);
        }
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var parameters = new { tenantId = header.TenantId, objectId, sequence, folderId, afterModified, afterId, take = PageSize + 1 };
        var rows = (await session.Connection.QueryAsync<Row>(new CommandDefinition(
            $"""
            SELECT id, source_id, kind, size, modified_at, sealed_metadata, preview_size, limited_fidelity FROM vaulty.items
             WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND parent_source_id = @folderId
               AND kind NOT IN ('folder', 'file_version') AND {Membership}
               AND (@afterModified::timestamptz IS NULL OR (modified_at, id) < (@afterModified, @afterId))
             ORDER BY modified_at DESC, id DESC LIMIT @take
            """, parameters, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var total = await session.Connection.ExecuteScalarAsync<long>(new CommandDefinition(
            $"""
            SELECT count(*) FROM vaulty.items
             WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND parent_source_id = @folderId
               AND kind NOT IN ('folder', 'file_version') AND {Membership}
            """, parameters, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var page = rows.Take(PageSize).Select(r => ToRow(repositoryKeys, objectId, r)).ToList();
        var next = rows.Count > PageSize ? $"{rows[PageSize - 1].ModifiedAt.Ticks.ToString(CultureInfo.InvariantCulture)}_{rows[PageSize - 1].Id:N}" : null;
        return new ItemPage(page, next, total);
    }

    public async Task<ItemDetail?> ItemAsync(UserAccess access, Guid objectId, Guid snapshotId, Guid itemId, CancellationToken cancellationToken = default)
    {
        var (header, sequence) = await ResolveAsync(access, objectId, snapshotId, cancellationToken).ConfigureAwait(false);
        var repositoryKeys = await keys.GetAsync(access.OrganizationId, header.TenantId, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
            $"""
            SELECT id, source_id, parent_source_id, kind, size, modified_at, sealed_metadata, preview_size, preview_type, limited_fidelity FROM vaulty.items
             WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND id = @itemId AND {Membership}
            """, new { tenantId = header.TenantId, objectId, sequence, itemId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (row is null) return null;
        var versions = (await session.Connection.QueryAsync<Row>(new CommandDefinition(
            $"""
            SELECT id, source_id, kind, size, modified_at, sealed_metadata FROM vaulty.items
             WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND parent_source_id = @sourceId AND kind = 'file_version' AND {Membership}
             ORDER BY modified_at DESC
            """, new { tenantId = header.TenantId, objectId, sequence, sourceId = row.SourceId }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).Select(v => new ItemVersionRow(v.Id, v.SourceId[(v.SourceId.IndexOf('@', StringComparison.Ordinal) + 1)..], v.Size,
                Utc(v.ModifiedAt))).ToList();
        var json = Open(repositoryKeys, objectId, row.SourceId, row.SealedMetadata);
        var item = ToRow(repositoryKeys, objectId, row, json);
        return new ItemDetail(item, row.ParentSourceId, Fields(json), PreviewTypeOf(row, json), versions);
    }

    /// <summary>
    /// Searches subject, sender, file name and path in the current state of every protected object the user may browse, or
    /// in one tenant or protected object. Words are matched as prefixes.
    /// </summary>
    public async Task<IReadOnlyList<SearchHit>> SearchAsync(UserAccess access, string query, Guid? tenantId = null, Guid? objectId = null, int limit = 50,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var tsQuery = SearchText.ToQuery(query);
        if (tsQuery is null || !access.Allows(Permissions.SnapshotsBrowse)) return [];
        var customers = access.Customers(Permissions.SnapshotsBrowse);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var rows = (await session.Connection.QueryAsync<HitRow>(new CommandDefinition(
            """
            SELECT i.id, i.tenant_id, i.protected_object_id, i.source_id, i.kind, i.size, i.modified_at, i.sealed_metadata,
                   o.display_name AS object_name, o.kind AS object_kind, t.display_name AS tenant_name, c.name AS customer_name
              FROM vaulty.items i
              JOIN vaulty.protected_objects o ON o.id = i.protected_object_id
              JOIN vaulty.tenants t ON t.id = i.tenant_id
              JOIN vaulty.customers c ON c.id = t.customer_id
             WHERE i.search_vector @@ to_tsquery('simple', @tsQuery) AND i.state = 'committed' AND i.deleted_sequence IS NULL
               AND i.kind NOT IN ('folder', 'file_version')
               AND (@allCustomers OR c.id = ANY(@customers))
               AND (@tenantId::uuid IS NULL OR i.tenant_id = @tenantId) AND (@objectId::uuid IS NULL OR i.protected_object_id = @objectId)
             ORDER BY i.modified_at DESC LIMIT @limit
            """, new { tsQuery, allCustomers = customers is null, customers = customers?.ToArray() ?? [], tenantId, objectId, limit = Math.Clamp(limit, 1, 200) },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        var hits = new List<SearchHit>(rows.Count);
        foreach (var tenant in rows.GroupBy(r => r.TenantId))
        {
            var repositoryKeys = await keys.GetAsync(access.OrganizationId, tenant.Key, cancellationToken).ConfigureAwait(false);
            foreach (var r in tenant)
            {
                var item = ToRow(repositoryKeys, r.ProtectedObjectId, new Row { Id = r.Id, SourceId = r.SourceId, Kind = r.Kind, Size = r.Size, ModifiedAt = r.ModifiedAt, SealedMetadata = r.SealedMetadata });
                hits.Add(new SearchHit(r.ProtectedObjectId, r.ObjectName, r.ObjectKind, r.TenantId, r.TenantName, r.CustomerName, r.Id, r.Kind, item.Title,
                    item.Subtitle, item.ModifiedAt));
            }
        }
        return hits.OrderByDescending(h => h.ModifiedAt).ToList();
    }

    /// <summary>The latest snapshot of a protected object that holds the item version (for opening a search hit).</summary>
    public async Task<Guid?> LatestSnapshotAsync(UserAccess access, Guid objectId, CancellationToken cancellationToken = default) =>
        (await SnapshotsAsync(access, objectId, cancellationToken).ConfigureAwait(false)).FirstOrDefault()?.Id;

    /// <summary>
    /// The preview of an item: the sanitized HTML body of a message, or the file itself for images, PDF and text under the
    /// size limit. Every preview is written to the audit log.
    /// </summary>
    public async Task<ItemPreview?> PreviewAsync(UserAccess access, Guid objectId, Guid snapshotId, Guid itemId, CancellationToken cancellationToken = default)
    {
        var (header, sequence) = await ResolveAsync(access, objectId, snapshotId, cancellationToken).ConfigureAwait(false);
        var repositoryKeys = await keys.GetAsync(access.OrganizationId, header.TenantId, cancellationToken).ConfigureAwait(false);
        Row? row;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false))
        {
            row = await session.Connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
                $"""
                SELECT id, source_id, kind, size, modified_at, sealed_metadata, content_hash, content_chunks, preview_chunks, preview_hash, preview_size, preview_type
                  FROM vaulty.items
                 WHERE tenant_id = @tenantId AND protected_object_id = @objectId AND id = @itemId AND {Membership}
                """, new { tenantId = header.TenantId, objectId, sequence, itemId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (row is null) return null;
            await AuditLog.WriteAsync(session, $"user:{access.UserId}", "item.previewed", $"object:{objectId}", new { snapshot = snapshotId, item = itemId },
                cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        var json = Open(repositoryKeys, objectId, row.SourceId, row.SealedMetadata);
        var type = PreviewTypeOf(row, json);
        if (type is null) return null;
        ItemContent content;
        if (row.PreviewChunks is not null)
        {
            content = new ItemContent(row.PreviewSize ?? 0, row.PreviewHash ?? [], Chunks(row.PreviewChunks));
        }
        else
        {
            if (row.ContentChunks is null) return null;
            content = new ItemContent(row.Size, row.ContentHash ?? [], Chunks(row.ContentChunks));
        }
        var reader = await readers.CreateAsync(access.OrganizationId, header.TenantId, cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        await reader.ReadContentAsync(content, buffer, cancellationToken).ConfigureAwait(false);
        var bytes = buffer.ToArray();
        var name = Field(json, "name") ?? Field(json, "subject") ?? "item";
        if (type == "text/html") return new ItemPreview(Encoding.UTF8.GetBytes(MailHtmlSanitizer.Sanitize(Encoding.UTF8.GetString(bytes))), "text/html", name);
        return new ItemPreview(bytes, type, name);
    }

    /// <summary>Membership of an item version in the snapshot with sequence @sequence.</summary>
    internal const string Membership = "state = 'committed' AND first_sequence <= @sequence AND (deleted_sequence IS NULL OR deleted_sequence > @sequence)";

    private async Task<(ObjectHeader Header, long Sequence)> ResolveAsync(UserAccess access, Guid objectId, Guid snapshotId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(access);
        var header = await ObjectAsync(access, objectId, cancellationToken).ConfigureAwait(false)
                     ?? throw new AccessException("You do not have access to this protected object.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var sequence = await session.Connection.ExecuteScalarAsync<long?>(new CommandDefinition(
            "SELECT sequence FROM vaulty.snapshots WHERE id = @snapshotId AND protected_object_id = @objectId AND state IN ('committed', 'partial')",
            new { snapshotId, objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)
            ?? throw new AccessException("The snapshot does not exist.");
        return (header, sequence);
    }

    private static string? PreviewTypeOf(Row row, string json)
    {
        if (row.PreviewChunks is not null || row.PreviewSize is > 0) return row.PreviewType;
        if (row.Kind != "file" && row.Kind != "file_version") return null;
        var mime = Field(json, "mime_type");
        if (mime is null || !PreviewableFileTypes.Contains(mime) || row.Size > PreviewLimit) return null;
        return mime.ToLowerInvariant();
    }

    private static ItemRow ToRow(Repository.Format.RepositoryKeys keys, Guid objectId, Row row, string? json = null)
    {
        json ??= Open(keys, objectId, row.SourceId, row.SealedMetadata);
        string title, subtitle;
        switch (row.Kind)
        {
            case "file" or "file_version" or "package":
                title = Field(json, "name") ?? row.SourceId;
                subtitle = Field(json, "path") ?? "";
                break;
            case "contact":
                title = Field(json, "subject") ?? "(no name)";
                subtitle = string.Join(", ", List(json, "to"));
                break;
            default:
                title = Field(json, "subject") is { Length: > 0 } s ? s : "(no subject)";
                subtitle = Field(json, "from") ?? "";
                break;
        }
        var hasPreview = row.PreviewSize is > 0 || PreviewTypeOf(row, json) is not null;
        return new ItemRow(row.Id, row.SourceId, row.Kind, row.Size, Utc(row.ModifiedAt), title, subtitle, hasPreview, row.LimitedFidelity);
    }

    private static Dictionary<string, string> Fields(string json)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        using var document = JsonDocument.Parse(json);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            var value = property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => property.Value.GetRawText(),
                JsonValueKind.Array => string.Join(", ", property.Value.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : e.GetRawText())),
                JsonValueKind.Object => property.Value.GetRawText(),
                _ => null,
            };
            if (!string.IsNullOrEmpty(value)) result[property.Name] = value;
        }
        return result;
    }

    private static string Open(Repository.Format.RepositoryKeys keys, Guid objectId, string sourceId, byte[]? sealedMetadata) =>
        sealedMetadata is null ? "{}" : MetadataSealer.Open(keys, objectId, sourceId, sealedMetadata);

    private static string? Field(string json, string name)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private static List<string> List(string json, string name)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList()
            : [];
    }

    private static List<ChunkId> Chunks(byte[] packed)
    {
        var list = new List<ChunkId>(packed.Length / ChunkId.Size);
        for (var i = 0; i + ChunkId.Size <= packed.Length; i += ChunkId.Size) list.Add(new ChunkId(packed.AsSpan(i, ChunkId.Size).ToArray()));
        return list;
    }

    private static DateTimeOffset Utc(DateTime value) => new(DateTime.SpecifyKind(value, DateTimeKind.Utc));

    private sealed class Row
    {
        public Guid Id { get; set; }
        public string SourceId { get; set; } = "";
        public string? ParentSourceId { get; set; }
        public string Kind { get; set; } = "";
        public long Size { get; set; }
        public DateTime ModifiedAt { get; set; }
        public byte[]? SealedMetadata { get; set; }
        public byte[]? ContentHash { get; set; }
        public byte[]? ContentChunks { get; set; }
        public byte[]? PreviewChunks { get; set; }
        public byte[]? PreviewHash { get; set; }
        public long? PreviewSize { get; set; }
        public string? PreviewType { get; set; }
        public bool LimitedFidelity { get; set; }
    }

    private sealed class HitRow
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public Guid ProtectedObjectId { get; set; }
        public string SourceId { get; set; } = "";
        public string Kind { get; set; } = "";
        public long Size { get; set; }
        public DateTime ModifiedAt { get; set; }
        public byte[]? SealedMetadata { get; set; }
        public string ObjectName { get; set; } = "";
        public string ObjectKind { get; set; } = "";
        public string TenantName { get; set; } = "";
        public string CustomerName { get; set; } = "";
    }
}

/// <summary>Search words: what is indexed and how a user's query becomes a prefix query, with only letters and digits.</summary>
public static class SearchText
{
    private const int MaxLength = 4000;

    /// <summary>The text that is indexed: the fields as given, plus their words split on punctuation (so "q3_report.xlsx" finds "report").</summary>
    public static string? Normalize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var words = Words(text);
        var result = string.Join(' ', words);
        return result.Length > MaxLength ? result[..MaxLength] : result;
    }

    /// <summary>A prefix query on every word, or null when there is nothing to search for.</summary>
    public static string? ToQuery(string? query)
    {
        if (string.IsNullOrWhiteSpace(query)) return null;
        var words = Words(query).Distinct(StringComparer.Ordinal).Take(8).ToList();
        return words.Count == 0 ? null : string.Join(" & ", words.Select(w => $"{w}:*"));
    }

    private static List<string> Words(string text)
    {
        var words = new List<string>();
        var current = new StringBuilder();
        foreach (var c in text.Normalize(NormalizationForm.FormC))
        {
            if (char.IsLetterOrDigit(c)) current.Append(char.ToLowerInvariant(c));
            else Flush();
        }
        Flush();
        return words;

        void Flush()
        {
            if (current.Length > 0 && current.Length <= 64) words.Add(current.ToString());
            current.Clear();
        }
    }
}
