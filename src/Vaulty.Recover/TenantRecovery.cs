using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Crypto;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Keys;
using Vaulty.Infrastructure.Restore;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;

namespace Vaulty.Recover;

public sealed record RecoveryRequest(Guid TenantId, string OutputDirectory)
{
    /// <summary>Only these protected objects; empty means every object with a snapshot.</summary>
    public IReadOnlyCollection<Guid> Objects { get; init; } = [];

    /// <summary>This snapshot instead of the newest one (only with a single object).</summary>
    public Guid? Snapshot { get; init; }

    /// <summary>Also write the older file versions that a snapshot keeps.</summary>
    public bool IncludeVersions { get; init; }

    /// <summary>The master key version the data keys were wrapped with; null takes the newest found in the key files.</summary>
    public int? MasterKeyVersion { get; init; }
}

public sealed record RecoveredItem(Guid ObjectId, Guid SnapshotId, string SourceId, string Kind, string? Path, string State, string? Detail);

public sealed record RecoveryReport(Guid TenantId, DateTimeOffset StartedAt, DateTimeOffset FinishedAt, IReadOnlyList<RecoveredObject> Objects)
{
    public long Items => Objects.Sum(o => o.Items.Count);
    public long Failed => Objects.Sum(o => o.Items.Count(i => i.State == "failed"));
}

public sealed record RecoveredObject(Guid ObjectId, Guid SnapshotId, DateTimeOffset SnapshotAt, string Outcome, string Directory, IReadOnlyList<RecoveredItem> Items);

/// <summary>
/// Rebuilds a tenant from object storage alone: the data keys from the key files (unwrapped with the master key's recovery
/// copy), the chunk index from the index files, and for every protected object the newest snapshot (or the chosen one)
/// from its root and manifests. Every chunk is authenticated and every item's content hash checked while it is written.
/// Items are written exactly as the platform writes an export: messages as EML, events as ICS, contacts as VCF, files as
/// they are, with a manifest per snapshot and a report of every item.
/// </summary>
public static class TenantRecovery
{
    public static async Task<RecoveryReport> RunAsync(IObjectStore store, ReadOnlyMemory<byte> masterKey, RecoveryRequest request, TextWriter log,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(log);
        var started = DateTimeOffset.UtcNow;
        Directory.CreateDirectory(request.OutputDirectory);
        if (Directory.EnumerateFileSystemEntries(request.OutputDirectory).Any())
        {
            throw new RecoveryException($"The output directory {request.OutputDirectory} is not empty.");
        }

        var version = request.MasterKeyVersion ?? await NewestKekVersionAsync(store, request.TenantId, cancellationToken).ConfigureAwait(false);
        RepositoryKeys keys;
        using (var wrapper = new SoftwareKeyWrapper(masterKey.Span, version))
        {
            try
            {
                keys = await TenantKeyService.LoadFromStoreAsync(store, wrapper, request.TenantId, cancellationToken).ConfigureAwait(false);
            }
            catch (CryptographicException ex)
            {
                throw new RecoveryException($"The data keys cannot be unwrapped with this master key (version {version}): {ex.Message}");
            }
        }
        using (keys)
        {
            await log.WriteLineAsync($"Data keys of tenant {request.TenantId} unwrapped.").ConfigureAwait(false);
            var index = await IndexRebuilder.RebuildAsync(store, keys, cancellationToken).ConfigureAwait(false);
            await log.WriteLineAsync($"Chunk index rebuilt from object storage: {index.ChunkCount} chunks in {index.Packs.Count} packs.").ConfigureAwait(false);
            var reader = new RepositoryReader(store, keys, index);

            var objects = request.Objects.Count > 0 ? request.Objects.ToList() : await ObjectsAsync(store, request.TenantId, cancellationToken).ConfigureAwait(false);
            if (request.Snapshot is not null && objects.Count != 1) throw new RecoveryException("--snapshot needs exactly one --object.");
            var results = new List<RecoveredObject>();
            foreach (var objectId in objects)
            {
                var root = await ChooseSnapshotAsync(reader, objectId, request.Snapshot, cancellationToken).ConfigureAwait(false);
                if (root is null)
                {
                    await log.WriteLineAsync($"Protected object {objectId}: no committed snapshot found.").ConfigureAwait(false);
                    continue;
                }
                var directory = Path.Combine(request.OutputDirectory, objectId.ToString("D"), root.SnapshotId.ToString("D"));
                var items = await RecoverSnapshotAsync(reader, root, directory, request.IncludeVersions, cancellationToken).ConfigureAwait(false);
                var failed = items.Count(i => i.State == "failed");
                await log.WriteLineAsync($"Protected object {objectId}, snapshot {root.SnapshotId} of {root.CreatedAt:yyyy-MM-dd HH:mm} UTC ({Outcome(root.Outcome)}): "
                                         + $"{items.Count(i => i.State == "restored")} written, {items.Count(i => i.State == "skipped")} listed only, {failed} failed.")
                    .ConfigureAwait(false);
                results.Add(new RecoveredObject(objectId, root.SnapshotId, root.CreatedAt, Outcome(root.Outcome), directory, items));
            }
            var report = new RecoveryReport(request.TenantId, started, DateTimeOffset.UtcNow, results);
            await File.WriteAllTextAsync(Path.Combine(request.OutputDirectory, "recovery-report.json"),
                JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower }),
                cancellationToken).ConfigureAwait(false);
            return report;
        }
    }

    private static async Task<List<RecoveredItem>> RecoverSnapshotAsync(RepositoryReader reader, SnapshotRoot root, string directory, bool includeVersions,
        CancellationToken cancellationToken)
    {
        var entries = new List<ManifestEntry>();
        foreach (var manifestId in root.ManifestIds) entries.AddRange((await reader.ReadManifestAsync(manifestId, cancellationToken).ConfigureAwait(false)).Entries);

        // The folder tree, exactly as the platform builds paths for a restore or export.
        var folders = entries.Where(e => e.Kind is "folder" or "package").ToDictionary(e => e.SourceId, e =>
        {
            using var document = JsonDocument.Parse(e.MetadataJson);
            var r = document.RootElement;
            return (e.ParentSourceId, Name: r.TryGetProperty("name", out var n) ? n.GetString() ?? e.SourceId : e.SourceId,
                Type: r.TryGetProperty("type", out var t) ? t.GetString() : null);
        }, StringComparer.Ordinal);
        string PathOf(string? folderId)
        {
            var parts = new List<string>();
            var guard = 0;
            for (var id = folderId; id is not null && folders.TryGetValue(id, out var folder) && guard++ < 256; id = folder.ParentSourceId) parts.Insert(0, folder.Name);
            return string.Join('/', parts);
        }
        var parentOf = entries.ToLookup(e => e.SourceId, e => e.ParentSourceId, StringComparer.Ordinal);

        var pending = entries.Where(e => e.Kind is not ("folder" or "package") && (includeVersions || e.Kind != "file_version")).Select(e =>
        {
            var folder = e.Kind == "file_version" && e.ParentSourceId is not null ? parentOf[e.ParentSourceId].FirstOrDefault() : e.ParentSourceId;
            using var document = JsonDocument.Parse(e.MetadataJson);
            var recovery = RecoveryMetadata.Read(document.RootElement);
            return new PendingItem(ItemId(root.ProtectedObjectId, e.SourceId), e.SourceId, e.Kind, e.ParentSourceId, PathOf(folder),
                folder is not null && folders.TryGetValue(folder, out var f) ? f.Type : null, e.Content?.Size ?? 0, recovery.ModifiedAt ?? root.CreatedAt,
                e.MetadataJson, e.Content, recovery.Preview, recovery.PreviewType, recovery.LimitedFidelity);
        }).OrderBy(p => p.RelativePath, StringComparer.Ordinal).ThenBy(p => p.SourceId, StringComparer.Ordinal).ToList();

        var results = new List<RecoveredItem>();
        var target = new DirectoryExportTarget(directory);
        await using var writer = new ExportWriter(target);
        foreach (var item in pending)
        {
            ExportEntry entry;
            try
            {
                entry = await writer.AddAsync(item, async destination => await reader.ReadContentAsync(item.Content!, destination, cancellationToken).ConfigureAwait(false),
                    async () => item.Preview is null ? null : await ReadTextAsync(reader, item.Preview, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IntegrityException or RepositoryFormatException or ObjectNotFoundException or InvalidDataException)
            {
                target.DiscardCurrent();
                results.Add(new RecoveredItem(root.ProtectedObjectId, root.SnapshotId, item.SourceId, item.Kind, null, "failed", ex.Message));
                continue;
            }
            results.Add(new RecoveredItem(root.ProtectedObjectId, root.SnapshotId, item.SourceId, item.Kind, entry.Path, entry.State, entry.Detail));
        }
        await writer.FinishAsync().ConfigureAwait(false);
        return results;
    }

    private static async Task<string> ReadTextAsync(RepositoryReader reader, ItemContent content, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        await reader.ReadContentAsync(content, buffer, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    /// <summary>The newest committed or partial snapshot of the object, or the requested one.</summary>
    private static async Task<SnapshotRoot?> ChooseSnapshotAsync(RepositoryReader reader, Guid objectId, Guid? snapshot, CancellationToken cancellationToken)
    {
        if (snapshot is { } chosen) return await reader.ReadSnapshotAsync(objectId, chosen, cancellationToken).ConfigureAwait(false);
        SnapshotRoot? newest = null;
        foreach (var id in await reader.ListSnapshotsAsync(objectId, cancellationToken).ConfigureAwait(false))
        {
            var root = await reader.ReadSnapshotAsync(objectId, id, cancellationToken).ConfigureAwait(false);
            if (root.Outcome is not (SnapshotOutcome.Committed or SnapshotOutcome.Partial)) continue;
            if (newest is null || root.CreatedAt > newest.CreatedAt) newest = root;
        }
        return newest;
    }

    private static async Task<List<Guid>> ObjectsAsync(IObjectStore store, Guid tenantId, CancellationToken cancellationToken)
    {
        var prefix = RepositoryLayout.TenantPrefix(tenantId) + "snapshots/";
        var objects = new SortedSet<Guid>();
        await foreach (var info in store.ListAsync(prefix, cancellationToken).ConfigureAwait(false))
        {
            var rest = info.Key[prefix.Length..];
            var slash = rest.IndexOf('/', StringComparison.Ordinal);
            if (slash > 0 && Guid.TryParse(rest[..slash], out var id)) objects.Add(id);
        }
        return [.. objects];
    }

    private static async Task<int> NewestKekVersionAsync(IObjectStore store, Guid tenantId, CancellationToken cancellationToken)
    {
        var newest = 0;
        await foreach (var info in store.ListAsync(RepositoryLayout.TenantPrefix(tenantId) + "keys/", cancellationToken).ConfigureAwait(false))
        {
            if (!info.Key.EndsWith(".json", StringComparison.Ordinal)) continue;
            await using var stream = await store.GetAsync(info.Key, null, cancellationToken).ConfigureAwait(false);
            var file = await JsonSerializer.DeserializeAsync<DataKeyFile>(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (file is not null && file.TenantId == tenantId) newest = Math.Max(newest, file.KekVersion);
        }
        return newest == 0 ? throw new RecoveryException($"No data key file of tenant {tenantId} in object storage.") : newest;
    }

    private static string Outcome(SnapshotOutcome outcome) => outcome == SnapshotOutcome.Partial ? "partial" : outcome == SnapshotOutcome.Committed ? "committed" : "failed";

    /// <summary>A stable id per object and source id (the database id is not in object storage).</summary>
    private static Guid ItemId(Guid objectId, string sourceId) =>
        new(SHA256.HashData(Encoding.UTF8.GetBytes($"{objectId:D}/{sourceId}")).AsSpan(0, 16));
}

public sealed class RecoveryException(string message) : Exception(message);
