using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Npgsql;
using Temporalio.Activities;
using Temporalio.Exceptions;
using Temporalio.Workflows;
using Vaulty.Connectors.Drive;
using Vaulty.Connectors.Exchange;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Domain;
using Vaulty.Graph;
using Vaulty.Graph.Http;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Restore;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Vaulty.Workflows.Jobs;

namespace Vaulty.Workflows.Restore;

public sealed record RestoreInput(Guid JobId, Guid OrganizationId, Guid TenantId, Guid RestoreId, bool IsExport) : IJobInput
{
    public JobKind JobKind => IsExport ? JobKind.Export : JobKind.Restore;
}

public sealed record RestoreOutcome(string State, Dictionary<string, long> ItemCounts) : IJobResult
{
    public IReadOnlyDictionary<string, long> Counts => ItemCounts;
    public bool Partial => State == "partial";
}

/// <summary>
/// A restore or export: plan the items, then restore them in small batches (pausable and cancellable between batches; what
/// was restored stays restored), then close with a report per item. An export writes one zip to the export bucket.
/// </summary>
[Workflow]
public sealed class RestoreWorkflow
{
    public const int BatchSize = 10;
    public const int BatchesPerRun = 1000;
    private bool _paused;
    private bool _cancelled;

    [WorkflowRun]
    public async Task<RestoreOutcome> RunAsync(RestoreInput input, bool planned = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        try
        {
            if (!planned) await Workflow.ExecuteActivityAsync((RestoreActivities a) => a.PlanAsync(input), ActivityPolicies.Database());
            if (input.IsExport)
            {
                if (!_cancelled) await Workflow.ExecuteActivityAsync((RestoreActivities a) => a.ExportAsync(input), ActivityPolicies.External(TimeSpan.FromHours(12)));
            }
            else
            {
                for (var batch = 0; ; batch++)
                {
                    if (_paused && !_cancelled)
                    {
                        await Workflow.ExecuteActivityAsync((RestoreActivities a) => a.SetStateAsync(input, "paused"), ActivityPolicies.Database());
                        await Workflow.WaitConditionAsync(() => !_paused || _cancelled);
                        if (!_cancelled) await Workflow.ExecuteActivityAsync((RestoreActivities a) => a.SetStateAsync(input, "running"), ActivityPolicies.Database());
                    }
                    if (_cancelled) break;
                    if (batch >= BatchesPerRun) throw Workflow.CreateContinueAsNewException((RestoreWorkflow w) => w.RunAsync(input, true));
                    var remaining = await Workflow.ExecuteActivityAsync((RestoreActivities a) => a.RestoreBatchAsync(input),
                        ActivityPolicies.External(TimeSpan.FromHours(2)));
                    if (remaining == 0) break;
                }
            }
            return await Workflow.ExecuteActivityAsync((RestoreActivities a) => a.FinishAsync(input, _cancelled, null), ActivityPolicies.Database());
        }
        catch (Exception ex) when (ex is not ContinueAsNewException && !TemporalException.IsCanceledException(ex))
        {
            await Workflow.ExecuteActivityAsync((RestoreActivities a) => a.FinishAsync(input, false, ex.Message), ActivityPolicies.Database());
            throw;
        }
    }

    [WorkflowSignal]
    public Task PauseAsync()
    {
        _paused = true;
        return Task.CompletedTask;
    }

    [WorkflowSignal]
    public Task ResumeAsync()
    {
        _paused = false;
        return Task.CompletedTask;
    }

    [WorkflowSignal]
    public Task CancelAsync()
    {
        _cancelled = true;
        return Task.CompletedTask;
    }

    [WorkflowQuery]
    public string Status => _cancelled ? "cancelling" : _paused ? "paused" : "running";
}

public sealed class RestoreActivities(NpgsqlDataSource dataSource, GraphServices graph, RestoreStore store, IBackupStorage storage, TenantKeyProvider keys,
    IExportStorage exports, TimeProvider clock, ILogger<RestoreActivities> logger)
{
    public const string RestoreFolderName = "Vaulty Restore";

    [Activity("RestorePlan")]
    public async Task<long> PlanAsync(RestoreInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var ct = ActivityExecutionContext.Current.CancellationToken;
        return await store.PlanAsync(input.OrganizationId, input.RestoreId, await keys.GetAsync(input.OrganizationId, input.TenantId, ct), ct);
    }

    [Activity("RestoreSetState")]
    public Task SetStateAsync(RestoreInput input, string state)
    {
        ArgumentNullException.ThrowIfNull(input);
        return store.SetStateAsync(input.OrganizationId, input.RestoreId, state);
    }

    [Activity("RestoreFinish")]
    public async Task<RestoreOutcome> FinishAsync(RestoreInput input, bool cancelled, string? failure)
    {
        ArgumentNullException.ThrowIfNull(input);
        var (state, counts) = await store.FinishAsync(input.OrganizationId, input.RestoreId, cancelled, failure);
        return new RestoreOutcome(state, new Dictionary<string, long>
        {
            ["items"] = counts.Total, ["restored"] = counts.Restored, ["skipped"] = counts.Skipped, ["failed"] = counts.Failed,
        });
    }

    /// <summary>Restores the next batch of items; returns how many are still pending.</summary>
    [Activity("RestoreBatch")]
    public async Task<long> RestoreBatchAsync(RestoreInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var ct = context.CancellationToken;
        var restore = await store.GetAsync(input.OrganizationId, input.RestoreId, ct);
        var repositoryKeys = await keys.GetAsync(input.OrganizationId, input.TenantId, ct);
        var items = await store.PendingAsync(restore, repositoryKeys, RestoreWorkflow.BatchSize, ct);
        if (items.Count == 0) return 0;
        var reader = new RepositoryReader(await storage.WorkerStoreAsync(ct), repositoryKeys, new PostgresChunkIndex(dataSource, input.OrganizationId, input.TenantId));
        var source = await store.TargetAsync(input.OrganizationId, restore.ProtectedObjectId, ct);
        var target = restore.TargetObjectId is { } other ? await store.TargetAsync(input.OrganizationId, other, ct) : source;
        var graphContext = new GraphRequestContext(input.TenantId, Workload: source.Kind == "drive" ? "drive" : "exchange");
        IReadOnlyList<ItemResult> results;
        if (target.Kind != source.Kind)
        {
            results = items.Select(i => new ItemResult(i.ItemId, "failed", null, "The target is a different type of protected object.")).ToList();
        }
        else if (source.Kind == "mailbox")
        {
            results = await new MailRestore(graph, restore, source, target, clock, context).RestoreAsync(graphContext, items, reader, ct);
        }
        else if (source.Kind == "drive")
        {
            results = await new FileRestore(graph, restore, source, target, clock, context).RestoreAsync(graphContext, items, reader, ct);
        }
        else
        {
            results = items.Select(i => new ItemResult(i.ItemId, "failed", null, "Restores of this type are not available yet.")).ToList();
        }
        await store.RecordAsync(input.OrganizationId, input.RestoreId, results, ct);
        logger.LogInformation("Restore {RestoreId}: {Restored} restored, {Failed} failed in this batch", input.RestoreId,
            results.Count(r => r.State == "restored"), results.Count(r => r.State == "failed"));
        return (await store.CountsAsync(input.OrganizationId, input.RestoreId, ct)).Pending;
    }

    /// <summary>Writes the zip of every planned item straight to the export bucket, then records the results and the export.</summary>
    [Activity("RestoreExport")]
    public async Task ExportAsync(RestoreInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var context = ActivityExecutionContext.Current;
        var ct = context.CancellationToken;
        var restore = await store.GetAsync(input.OrganizationId, input.RestoreId, ct);
        var repositoryKeys = await keys.GetAsync(input.OrganizationId, input.TenantId, ct);
        var reader = new RepositoryReader(await storage.WorkerStoreAsync(ct), repositoryKeys, new PostgresChunkIndex(dataSource, input.OrganizationId, input.TenantId));
        var key = $"{RepositoryLayout.TenantPrefix(input.TenantId)}exports/{input.RestoreId:N}.zip";
        var uploads = await exports.UploadsAsync(ct);
        var results = new List<ItemResult>();
        ObjectInfo info;
        byte[] sha256;
        await using (var upload = await uploads.BeginUploadAsync(key, new ObjectPutOptions(null, FailIfExists: false), ct))
        {
            await using (var writer = new ExportWriter(upload.Stream))
            {
                PendingItem? after = null;
                while (true)
                {
                    var page = await store.PendingAsync(restore, repositoryKeys, 200, ct, after);
                    if (page.Count == 0) break;
                    foreach (var item in page)
                    {
                        try
                        {
                            var entry = await writer.AddAsync(item, s => reader.ReadContentAsync(item.Content!, s, ct), async () =>
                            {
                                if (item.Preview is null) return null;
                                using var buffer = new MemoryStream();
                                await reader.ReadContentAsync(item.Preview, buffer, ct);
                                return Encoding.UTF8.GetString(buffer.ToArray());
                            });
                            results.Add(new ItemResult(item.ItemId, entry.State, entry.Path, entry.Detail));
                        }
                        catch (IntegrityException ex)
                        {
                            // A damaged item fails alone; the zip entry already started holds what was read, the manifest says it failed.
                            results.Add(new ItemResult(item.ItemId, "failed", null, $"The stored data failed its integrity check: {ex.Message}"));
                        }
                    }
                    after = page[^1];
                    context.Heartbeat(results.Count);
                }
                await writer.FinishAsync();
            }
            info = await upload.CompleteAsync(ct);
            sha256 = upload.Sha256;
        }
        foreach (var chunk in results.Chunk(1000)) await store.RecordAsync(input.OrganizationId, input.RestoreId, chunk, ct);
        await store.RecordExportAsync(input.OrganizationId, input.RestoreId, key, info.Size, sha256, restore.RequestedBy, ct);
    }

    /// <summary>Streams stored content into an upload without holding the whole item in memory.</summary>
    internal static async Task<T> StreamAsync<T>(RepositoryReader reader, ItemContent content, Func<Stream, Task<T>> consume, CancellationToken ct)
    {
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: 8 * 1024 * 1024, resumeWriterThreshold: 4 * 1024 * 1024));
        var producer = Task.Run(async () =>
        {
            try
            {
                await using var sink = pipe.Writer.AsStream();
                await reader.ReadContentAsync(content, sink, ct);
                await pipe.Writer.CompleteAsync();
            }
            catch (Exception ex)
            {
                await pipe.Writer.CompleteAsync(ex);
            }
        }, ct);
        try
        {
            await using var source = pipe.Reader.AsStream();
            return await consume(source);
        }
        finally
        {
            await pipe.Reader.CompleteAsync();
            await producer;
        }
    }

    internal static string Stamp(RestoreRow restore) => new DateTimeOffset(DateTime.SpecifyKind(restore.CreatedAt, DateTimeKind.Utc)).ToString("yyyy-MM-dd HH-mm",
        System.Globalization.CultureInfo.InvariantCulture);

    internal static string? Text(string json, string name)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }
}

/// <summary>Mail, calendar, contacts and tasks through the import API: into the restore folder, the original folder or another mailbox.</summary>
internal sealed class MailRestore(GraphServices graph, RestoreRow restore, (string Kind, string SourceId, string? MailboxId) source,
    (string Kind, string SourceId, string? MailboxId) target, TimeProvider clock, ActivityExecutionContext context)
{
    private readonly ExchangeRestoreClient _client = new(graph.Client, graph.Downloads);
    private readonly Dictionary<string, string> _created = new(StringComparer.Ordinal);
    private List<MailboxFolderInfo> _folders = [];
    private ImportSession? _session;

    public async Task<IReadOnlyList<ItemResult>> RestoreAsync(GraphRequestContext graphContext, IReadOnlyList<PendingItem> items, RepositoryReader reader,
        CancellationToken ct)
    {
        var results = new List<ItemResult>();
        if (target.MailboxId is not { } mailbox)
        {
            return items.Select(i => new ItemResult(i.ItemId, "failed", null, "The target mailbox is not known yet; run a discovery of the tenant.")).ToList();
        }
        _folders = (await _client.FoldersAsync(graphContext, mailbox, ct)).ToList();
        foreach (var item in items)
        {
            if (item.Kind is not ("mail" or "event" or "contact" or "task"))
            {
                results.Add(new ItemResult(item.ItemId, "skipped", null, "This item type is not restored."));
                continue;
            }
            if (item.LimitedFidelity)
            {
                results.Add(new ItemResult(item.ItemId, "failed", null,
                    "This message was backed up as MIME (limited fidelity). Export it instead; a restore needs the full-fidelity copy."));
                continue;
            }
            if (item.Content is null)
            {
                results.Add(new ItemResult(item.ItemId, "failed", null, "The item has no stored content."));
                continue;
            }
            try
            {
                string? note = null;
                string folder;
                var sameMailbox = target.MailboxId == source.MailboxId;
                if (restore.TargetMode == RestoreModes.Original && sameMailbox && _folders.Any(f => f.Id == item.ParentSourceId))
                {
                    folder = item.ParentSourceId!;
                }
                else
                {
                    if (restore.TargetMode == RestoreModes.Original) note = "The original folder no longer exists; the item is in the restore folder.";
                    folder = await RestoreFolderAsync(graphContext, mailbox, item, ct);
                }
                using var data = new MemoryStream();
                await reader.ReadContentAsync(item.Content, data, ct);
                var imported = await ImportAsync(graphContext, mailbox, folder, data.GetBuffer().AsMemory(0, (int)data.Length), ct);
                results.Add(new ItemResult(item.ItemId, "restored", imported.ItemId, note));
            }
            catch (Exception ex) when (ex is GraphException or IntegrityException or HttpRequestException)
            {
                results.Add(new ItemResult(item.ItemId, "failed", null, ex.Message));
            }
            context.Heartbeat();
        }
        return results;
    }

    private async Task<ImportedItem> ImportAsync(GraphRequestContext graphContext, string mailbox, string folder, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        if (_session is null || ExchangeRestoreClient.IsExpired(_session, clock.GetUtcNow())) _session = await _client.CreateImportSessionAsync(graphContext, mailbox, ct);
        try
        {
            return await _client.ImportAsync(graphContext, _session, folder, data, ct);
        }
        catch (GraphException ex) when (ex.Status is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden)
        {
            // The session ended early: one new session, one more try.
            _session = await _client.CreateImportSessionAsync(graphContext, mailbox, ct);
            return await _client.ImportAsync(graphContext, _session, folder, data, ct);
        }
    }

    /// <summary>"Vaulty Restore/&lt;date time&gt;/&lt;original folder path&gt;", created as needed; the last folder has the original folder's type.</summary>
    private async Task<string> RestoreFolderAsync(GraphRequestContext graphContext, string mailbox, PendingItem item, CancellationToken ct)
    {
        var segments = new List<string> { RestoreActivities.RestoreFolderName, RestoreActivities.Stamp(restore) };
        segments.AddRange(item.RelativePath.Split('/', StringSplitOptions.RemoveEmptyEntries));
        var top = _folders.FirstOrDefault(f => f.WellKnownName == "inbox")?.ParentFolderId;
        string? parent = null;
        var path = "";
        for (var i = 0; i < segments.Count; i++)
        {
            var name = segments[i];
            var type = i == segments.Count - 1 && i >= 2 ? item.FolderType ?? "IPF.Note" : "IPF.Note";
            path += "/" + name;
            if (_created.TryGetValue(path, out var known))
            {
                parent = known;
                continue;
            }
            var existing = _folders.FirstOrDefault(f => f.DisplayName == name && (parent is null ? f.ParentFolderId == top || f.ParentFolderId is null : f.ParentFolderId == parent));
            var id = existing?.Id;
            if (id is null)
            {
                var created = await _client.CreateFolderAsync(graphContext, mailbox, parent, name, type, ct);
                _folders.Add(created);
                id = created.Id;
            }
            _created[path] = id;
            parent = id;
        }
        return parent!;
    }
}

/// <summary>Files and versions into OneDrive: the restore folder, the original folder, or another user's drive.</summary>
internal sealed class FileRestore(GraphServices graph, RestoreRow restore, (string Kind, string SourceId, string? MailboxId) source,
    (string Kind, string SourceId, string? MailboxId) target, TimeProvider clock, ActivityExecutionContext context)
{
    private readonly DriveRestoreClient _client = new(graph.Client, graph.Downloads, clock);
    private readonly DriveClient _drive = new(graph.Client, graph.Downloads);
    private readonly Dictionary<string, string> _folders = new(StringComparer.Ordinal);
    private string? _root;

    public async Task<IReadOnlyList<ItemResult>> RestoreAsync(GraphRequestContext graphContext, IReadOnlyList<PendingItem> items, RepositoryReader reader,
        CancellationToken ct)
    {
        var driveId = target.SourceId;
        var conflict = restore.Conflict switch { "overwrite" => DriveConflict.Overwrite, "skip" => DriveConflict.Skip, _ => DriveConflict.Rename };
        var results = new List<ItemResult>();
        foreach (var item in items)
        {
            if (item.Kind is not ("file" or "file_version"))
            {
                results.Add(new ItemResult(item.ItemId, "skipped", null, "This item type is not restored."));
                continue;
            }
            if (item.Content is null)
            {
                results.Add(new ItemResult(item.ItemId, "failed", null, "The file has no stored content."));
                continue;
            }
            try
            {
                string? note = null;
                var parent = restore.TargetMode == RestoreModes.Original && driveId == source.SourceId ? await OriginalParentAsync(graphContext, driveId, item, ct) : null;
                if (parent is null)
                {
                    if (restore.TargetMode == RestoreModes.Original) note = "The original folder no longer exists; the file is in the restore folder.";
                    parent = await RestoreFolderAsync(graphContext, driveId, item, ct);
                }
                var name = RestoreActivities.Text(item.MetadataJson, "name") ?? item.SourceId;
                var created = DateTimeOffset.TryParse(RestoreActivities.Text(item.MetadataJson, "created"), System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var c) ? c : (DateTimeOffset?)null;
                var uploaded = await RestoreActivities.StreamAsync(reader, item.Content, s =>
                    _client.UploadAsync(graphContext, driveId, parent, name, s, item.Content.Size, created, item.ModifiedAt, conflict, ct), ct);
                results.Add(uploaded.Skipped
                    ? new ItemResult(item.ItemId, "skipped", uploaded.Id, "A file with this name exists and the restore was set to skip it.")
                    : new ItemResult(item.ItemId, "restored", uploaded.Id, note ?? (uploaded.Name != DriveRestoreClient.SafeName(name) ? $"Restored as {uploaded.Name}." : null)));
            }
            catch (Exception ex) when (ex is GraphException or IntegrityException or HttpRequestException or IOException)
            {
                results.Add(new ItemResult(item.ItemId, "failed", null, ex.Message));
            }
            context.Heartbeat();
        }
        return results;
    }

    private async Task<string?> OriginalParentAsync(GraphRequestContext graphContext, string driveId, PendingItem item, CancellationToken ct)
    {
        try
        {
            if (item.ParentSourceId is null) return null;
            if (item.Kind == "file_version")
            {
                // A version goes next to its file, if the file is still there.
                var file = await _drive.ItemAsync(graphContext, driveId, item.ParentSourceId, ct);
                return file.ParentReference?.Id;
            }
            return (await _drive.ItemAsync(graphContext, driveId, item.ParentSourceId, ct)).Id;
        }
        catch (GraphException ex) when (ex.Status == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    private async Task<string> RestoreFolderAsync(GraphRequestContext graphContext, string driveId, PendingItem item, CancellationToken ct)
    {
        _root ??= await _client.RootIdAsync(graphContext, driveId, ct);
        var segments = new List<string> { RestoreActivities.RestoreFolderName, RestoreActivities.Stamp(restore) };
        segments.AddRange(item.RelativePath.Split('/', StringSplitOptions.RemoveEmptyEntries));
        var parent = _root;
        var path = "";
        foreach (var segment in segments)
        {
            path += "/" + segment;
            if (!_folders.TryGetValue(path, out var id))
            {
                id = await _client.EnsureFolderAsync(graphContext, driveId, parent, segment, ct);
                _folders[path] = id;
            }
            parent = id;
        }
        return parent;
    }
}
