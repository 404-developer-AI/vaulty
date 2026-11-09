using System.Text.Json;
using System.Text.Json.Serialization;
using Vaulty.Graph;
using Vaulty.Graph.Http;

namespace Vaulty.Connectors.Drive;

public sealed class DriveItem
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("eTag")] public string? ETag { get; set; }
    [JsonPropertyName("cTag")] public string? CTag { get; set; }
    [JsonPropertyName("createdDateTime")] public DateTimeOffset? CreatedDateTime { get; set; }
    [JsonPropertyName("lastModifiedDateTime")] public DateTimeOffset? LastModifiedDateTime { get; set; }
    [JsonPropertyName("parentReference")] public ItemReference? ParentReference { get; set; }
    [JsonPropertyName("file")] public FileFacet? File { get; set; }
    [JsonPropertyName("folder")] public JsonElement? Folder { get; set; }
    [JsonPropertyName("package")] public PackageFacet? Package { get; set; }
    [JsonPropertyName("root")] public JsonElement? Root { get; set; }
    [JsonPropertyName("deleted")] public JsonElement? Deleted { get; set; }
    [JsonPropertyName("shared")] public JsonElement? Shared { get; set; }
    [JsonPropertyName("@microsoft.graph.downloadUrl")] public string? DownloadUrl { get; set; }

    [JsonIgnore] public bool IsDeleted => Deleted is { ValueKind: JsonValueKind.Object };
    [JsonIgnore] public bool IsFolder => Folder is { ValueKind: JsonValueKind.Object } || Root is { ValueKind: JsonValueKind.Object };
}

public sealed class ItemReference
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("path")] public string? Path { get; set; }
}

public sealed class FileFacet
{
    [JsonPropertyName("mimeType")] public string? MimeType { get; set; }
    [JsonPropertyName("hashes")] public FileHashes? Hashes { get; set; }
}

public sealed class FileHashes
{
    [JsonPropertyName("quickXorHash")] public string? QuickXorHash { get; set; }
    [JsonPropertyName("sha256Hash")] public string? Sha256Hash { get; set; }
}

public sealed class PackageFacet
{
    [JsonPropertyName("type")] public string? Type { get; set; }
}

public sealed class DriveItemVersion
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("lastModifiedDateTime")] public DateTimeOffset? LastModifiedDateTime { get; set; }
}

[JsonSerializable(typeof(GraphCollection<DriveItem>), TypeInfoPropertyName = "Items")]
[JsonSerializable(typeof(GraphCollection<DriveItemVersion>), TypeInfoPropertyName = "Versions")]
[JsonSerializable(typeof(DriveItem))]
public sealed partial class DriveJson : JsonSerializerContext;

/// <summary>Thrown when a downloaded file does not match the hash Microsoft reports for it.</summary>
public sealed class DriveIntegrityException(string message) : Exception(message);

/// <summary>
/// OneDrive (and later SharePoint libraries) through Microsoft Graph: drive delta, versions, permissions, and downloads
/// through the pre-authenticated download URL with Range resumption and hash checks.
/// </summary>
public sealed class DriveClient(GraphClient graph, GraphDownloadClient downloads)
{
    public const int DeltaPageSize = 200;
    public const long MaximumFileSize = 250L * 1024 * 1024 * 1024;

    public Task<GraphDeltaPage<DriveItem>> DeltaAsync(GraphRequestContext context, string driveId, string? link, CancellationToken cancellationToken = default) =>
        graph.DeltaPageAsync(context, link ?? $"drives/{Uri.EscapeDataString(driveId)}/root/delta",
            DriveJson.Default.Items, new Dictionary<string, string> { ["Prefer"] = $"odata.maxpagesize={DeltaPageSize}, deltaExcludeParent=true" }, cancellationToken);

    /// <summary>The item with a fresh download URL (the URL is valid for a short time only).</summary>
    public Task<DriveItem> ItemAsync(GraphRequestContext context, string driveId, string itemId, CancellationToken cancellationToken = default) =>
        graph.GetAsync(context, $"drives/{Uri.EscapeDataString(driveId)}/items/{Uri.EscapeDataString(itemId)}", DriveJson.Default.DriveItem, null, cancellationToken);

    public Task<DriveItem> RootAsync(GraphRequestContext context, string driveId, CancellationToken cancellationToken = default) =>
        graph.GetAsync(context, $"drives/{Uri.EscapeDataString(driveId)}/root", DriveJson.Default.DriveItem, null, cancellationToken);

    public async Task<IReadOnlyList<DriveItemVersion>> VersionsAsync(GraphRequestContext context, string driveId, string itemId, CancellationToken cancellationToken = default)
    {
        var result = new List<DriveItemVersion>();
        await foreach (var page in graph.PagesAsync(context, $"drives/{Uri.EscapeDataString(driveId)}/items/{Uri.EscapeDataString(itemId)}/versions",
                           DriveJson.Default.Versions, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            result.AddRange(page.Items);
        }
        return result;
    }

    /// <summary>Sharing links and permissions of changed files as metadata, 20 per $batch; missing answers are left out.</summary>
    public async Task<IReadOnlyDictionary<string, string>> PermissionsAsync(GraphRequestContext context, string driveId, IReadOnlyList<string> itemIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(itemIds);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var batch in itemIds.Chunk(GraphClient.MaxBatchSize))
        {
            var requests = batch.Select((id, n) => new GraphBatchRequest(n.ToString(System.Globalization.CultureInfo.InvariantCulture), "GET",
                $"/drives/{driveId}/items/{Uri.EscapeDataString(id)}/permissions")).ToList();
            IReadOnlyList<GraphBatchResponse> responses;
            try
            {
                responses = await graph.BatchAsync(context, requests, cancellationToken).ConfigureAwait(false);
            }
            catch (GraphException)
            {
                continue;
            }
            foreach (var response in responses.Where(r => r.Status == 200 && r.Body is { ValueKind: JsonValueKind.Object }))
            {
                if (response.Body!.Value.TryGetProperty("value", out var value)) result[batch[int.Parse(response.Id, System.Globalization.CultureInfo.InvariantCulture)]] = value.GetRawText();
            }
        }
        return result;
    }

    /// <summary>
    /// Streams a file. A broken connection is resumed with a Range request from the last byte received (the download URL is
    /// refreshed when it expired), at most <paramref name="maxResumes"/> times. The returned stream checks the QuickXorHash (or
    /// SHA-256) at its end and throws <see cref="DriveIntegrityException"/> on a mismatch.
    /// </summary>
    public Stream OpenFile(GraphRequestContext context, string driveId, DriveItem item, string? versionId = null, int maxResumes = 5) =>
        new ResumableDownload(this, context, driveId, item, versionId, maxResumes);

    internal async Task<Stream> OpenAtAsync(GraphRequestContext context, string driveId, DriveItem item, string? versionId, long offset, bool refresh,
        CancellationToken cancellationToken)
    {
        if (versionId is not null)
        {
            // /content answers with a redirect to a pre-authenticated URL; the Graph client does not follow it with the token.
            var response = await graph.SendAsync(context, HttpMethod.Get,
                $"drives/{Uri.EscapeDataString(driveId)}/items/{Uri.EscapeDataString(item.Id)}/versions/{Uri.EscapeDataString(versionId)}/content", null,
                offset > 0 ? new Dictionary<string, string> { ["Range"] = $"bytes={offset}-" } : null, cancellationToken).ConfigureAwait(false);
            return await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        }
        var url = item.DownloadUrl;
        if (url is null || refresh) url = (await ItemAsync(context, driveId, item.Id, cancellationToken).ConfigureAwait(false)).DownloadUrl;
        if (url is null) throw new GraphException(System.Net.HttpStatusCode.NotFound, "noDownloadUrl", "The item has no download URL.", null);
        return await downloads.OpenAsync(context, new Uri(url), offset, cancellationToken).ConfigureAwait(false);
    }

    private sealed class ResumableDownload(DriveClient client, GraphRequestContext context, string driveId, DriveItem item, string? versionId, int maxResumes) : Stream
    {
        private readonly QuickXorHash _quickXor = new();
        private readonly System.Security.Cryptography.IncrementalHash _sha256 = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        private Stream? _inner;
        private long _position;
        private int _resumes;
        private bool _checked;

        public int Resumes => _resumes;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => item.Size;
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                try
                {
                    _inner ??= await client.OpenAtAsync(context, driveId, item, versionId, _position, refresh: _resumes > 0, cancellationToken).ConfigureAwait(false);
                    var read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        Verify();
                        return 0;
                    }
                    _quickXor.Append(buffer.Span[..read]);
                    _sha256.AppendData(buffer.Span[..read]);
                    _position += read;
                    return read;
                }
                catch (Exception ex) when (ex is IOException or HttpRequestException && _resumes < maxResumes && !cancellationToken.IsCancellationRequested)
                {
                    _resumes++;
                    if (_inner is not null) await _inner.DisposeAsync().ConfigureAwait(false);
                    _inner = null;
                }
            }
        }

        private void Verify()
        {
            if (_checked) return;
            _checked = true;
            if (_position != item.Size && versionId is null) throw new DriveIntegrityException($"Received {_position} bytes, the file has {item.Size}.");
            var hashes = versionId is null ? item.File?.Hashes : null;
            if (hashes?.QuickXorHash is { } expected && Convert.ToBase64String(_quickXor.Finish()) != expected)
            {
                throw new DriveIntegrityException("The downloaded file does not match its QuickXorHash.");
            }
            if (hashes?.Sha256Hash is { } sha && !Convert.ToHexString(_sha256.GetHashAndReset()).Equals(sha, StringComparison.OrdinalIgnoreCase))
            {
                throw new DriveIntegrityException("The downloaded file does not match its SHA-256.");
            }
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner?.Dispose();
                _sha256.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
