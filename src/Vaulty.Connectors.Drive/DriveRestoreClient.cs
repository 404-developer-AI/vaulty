using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vaulty.Graph;
using Vaulty.Graph.Http;

namespace Vaulty.Connectors.Drive;

/// <summary>How a restored file treats a file of the same name at the target.</summary>
public enum DriveConflict
{
    /// <summary>Keep both: the restored file gets "(restored yyyy-MM-dd)" in its name.</summary>
    Rename,
    /// <summary>Leave the existing file and report the item as skipped.</summary>
    Skip,
    /// <summary>Replace the existing file; only on an explicit choice.</summary>
    Overwrite,
}

public sealed record UploadedFile(string Id, string Name, long Size, bool Skipped);

/// <summary>
/// Restores into OneDrive: folders are created as needed, files are uploaded through an upload session in 10 MiB parts
/// (the upload URL is pre-authenticated and never receives a token), with their original created and modified times.
/// </summary>
public sealed class DriveRestoreClient(GraphClient graph, GraphDownloadClient preauthenticated, TimeProvider clock)
{
    /// <summary>Upload part size: a multiple of 320 KiB as the upload session requires.</summary>
    public const int PartSize = 32 * 320 * 1024;

    public async Task<string> RootIdAsync(GraphRequestContext context, string driveId, CancellationToken cancellationToken = default) =>
        (await new DriveClient(graph, preauthenticated).RootAsync(context, driveId, cancellationToken).ConfigureAwait(false)).Id;

    /// <summary>The child folder of that name, created when it does not exist.</summary>
    public async Task<string> EnsureFolderAsync(GraphRequestContext context, string driveId, string parentId, string name,
        CancellationToken cancellationToken = default)
    {
        var safe = SafeName(name);
        if (await ChildAsync(context, driveId, parentId, safe, cancellationToken).ConfigureAwait(false) is { } existing) return existing.Id;
        var body = new JsonObject { ["name"] = safe, ["folder"] = new JsonObject(), ["@microsoft.graph.conflictBehavior"] = "fail" };
        try
        {
            using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            using var response = await graph.SendAsync(context, HttpMethod.Post, $"drives/{E(driveId)}/items/{E(parentId)}/children", content, null, cancellationToken)
                .ConfigureAwait(false);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            return document.RootElement.GetProperty("id").GetString()!;
        }
        catch (GraphException ex) when (ex.Status == HttpStatusCode.Conflict)
        {
            // Created at the same moment by another part of the restore.
            return (await ChildAsync(context, driveId, parentId, safe, cancellationToken).ConfigureAwait(false))!.Id;
        }
    }

    public async Task<DriveItem?> ChildAsync(GraphRequestContext context, string driveId, string parentId, string name, CancellationToken cancellationToken = default)
    {
        try
        {
            return await graph.GetAsync(context, $"drives/{E(driveId)}/items/{E(parentId)}:/{Uri.EscapeDataString(name)}", DriveJson.Default.DriveItem, null,
                cancellationToken).ConfigureAwait(false);
        }
        catch (GraphException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    /// <summary>Uploads a file of <paramref name="size"/> bytes from <paramref name="content"/> into the folder.</summary>
    public async Task<UploadedFile> UploadAsync(GraphRequestContext context, string driveId, string parentId, string name, Stream content, long size,
        DateTimeOffset? created, DateTimeOffset? modified, DriveConflict conflict, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        var target = SafeName(name);
        var existing = await ChildAsync(context, driveId, parentId, target, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            if (conflict == DriveConflict.Skip) return new UploadedFile(existing.Id, existing.Name ?? target, existing.Size, Skipped: true);
            if (conflict == DriveConflict.Rename) target = RestoredName(target, clock.GetUtcNow());
        }
        var behavior = conflict == DriveConflict.Overwrite ? "replace" : "rename";
        if (size == 0)
        {
            // An upload session needs at least one byte; an empty file is a simple upload.
            using var empty = new ByteArrayContent([]);
            using var put = await graph.SendAsync(context, HttpMethod.Put,
                $"drives/{E(driveId)}/items/{E(parentId)}:/{Uri.EscapeDataString(target)}:/content?@microsoft.graph.conflictBehavior={behavior}", empty, null,
                cancellationToken).ConfigureAwait(false);
            using var answer = JsonDocument.Parse(await put.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            return new UploadedFile(answer.RootElement.GetProperty("id").GetString()!, target, 0, Skipped: false);
        }
        var item = new JsonObject { ["@microsoft.graph.conflictBehavior"] = behavior, ["name"] = target };
        if (created is not null || modified is not null)
        {
            var info = new JsonObject();
            if (created is { } c) info["createdDateTime"] = c.ToUniversalTime().ToString("O");
            if (modified is { } m) info["lastModifiedDateTime"] = m.ToUniversalTime().ToString("O");
            item["fileSystemInfo"] = info;
        }
        using var request = new StringContent(new JsonObject { ["item"] = item }.ToJsonString(), Encoding.UTF8, "application/json");
        Uri uploadUrl;
        using (var response = await graph.SendAsync(context, HttpMethod.Post, $"drives/{E(driveId)}/items/{E(parentId)}:/{Uri.EscapeDataString(target)}:/createUploadSession",
                   request, null, cancellationToken).ConfigureAwait(false))
        {
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            uploadUrl = new Uri(document.RootElement.GetProperty("uploadUrl").GetString()!);
        }

        var buffer = new byte[Math.Max(1, (int)Math.Min(PartSize, size))];
        long offset = 0;
        JsonDocument? final = null;
        try
        {
            do
            {
                var length = 0;
                while (length < buffer.Length && offset + length < size)
                {
                    var read = await content.ReadAsync(buffer.AsMemory(length, (int)Math.Min(buffer.Length - length, size - offset - length)), cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0) throw new IOException($"The content ended after {offset + length} of {size} bytes.");
                    length += read;
                }
                using var part = new ByteArrayContent(buffer, 0, length);
                part.Headers.ContentLength = length;
                part.Headers.ContentRange = size == 0 ? null : new ContentRangeHeaderValue(offset, offset + length - 1, size);
                using var response = await preauthenticated.SendAsync(context, HttpMethod.Put, uploadUrl, part, cancellationToken).ConfigureAwait(false);
                var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) throw GraphException.FromBody(response.StatusCode, text);
                offset += length;
                if (response.StatusCode is HttpStatusCode.OK or HttpStatusCode.Created) final = JsonDocument.Parse(text);
            }
            while (offset < size);
            if (final is null) throw new GraphException(HttpStatusCode.BadGateway, "uploadIncomplete", "The upload session did not return the file.", null);
            var root = final.RootElement;
            return new UploadedFile(root.GetProperty("id").GetString()!, root.TryGetProperty("name", out var n) ? n.GetString() ?? target : target,
                root.TryGetProperty("size", out var s) ? s.GetInt64() : size, Skipped: false);
        }
        finally
        {
            final?.Dispose();
        }
    }

    /// <summary>"Report.docx" becomes "Report (restored 2026-11-09).docx".</summary>
    public static string RestoredName(string name, DateTimeOffset now)
    {
        var extension = Path.GetExtension(name);
        var stem = extension.Length > 0 && extension.Length < name.Length ? name[..^extension.Length] : name;
        if (extension.Length == name.Length) extension = "";
        return $"{stem} (restored {now:yyyy-MM-dd}){extension}";
    }

    /// <summary>
    /// A name OneDrive accepts: characters it refuses are replaced, trailing dots and spaces removed, at most 250 characters;
    /// a name that would point elsewhere ("..", "") is never produced.
    /// </summary>
    public static string SafeName(string name)
    {
        var builder = new StringBuilder();
        foreach (var c in name ?? "")
        {
            builder.Append(c is '"' or '*' or ':' or '<' or '>' or '?' or '/' or '\\' or '|' || char.IsControl(c) ? '_' : c);
        }
        var result = builder.ToString().Trim().TrimEnd('.', ' ');
        if (result.Length > 250) result = result[..250];
        return result.Length == 0 || result is "." or ".." ? "item" : result;
    }

    private static string E(string value) => Uri.EscapeDataString(value);
}
