using System.Net;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Vaulty.Graph.Http;

namespace Vaulty.Graph;

/// <summary>A Graph error with Microsoft's request-id for support cases.</summary>
public class GraphException(HttpStatusCode status, string? code, string message, string? requestId)
    : Exception($"Graph returned {(int)status} {code}: {message}")
{
    public HttpStatusCode Status { get; } = status;
    public string? Code { get; } = code;
    public string? RequestId { get; } = requestId;
}

/// <summary>The delta token is no longer valid (410 Gone or resyncRequired): start the resync route, never a silent full run.</summary>
public sealed class DeltaResyncRequiredException(string? code, string? requestId, string? location)
    : GraphException(HttpStatusCode.Gone, code, "The delta token is no longer valid; a resync is required.", requestId)
{
    /// <summary>The URL Graph suggests to restart the delta from, when it sends one.</summary>
    public string? Location { get; } = location;
}

/// <summary>One page of a collection with the link to the next page (persist it as the checkpoint).</summary>
public sealed record GraphPage<T>(IReadOnlyList<T> Items, string? NextLink);

/// <summary>One page of a delta query: either a next link (more pages) or the delta link (store after commit).</summary>
public sealed record GraphDeltaPage<T>(IReadOnlyList<T> Items, string? NextLink, string? DeltaLink);

public sealed class GraphCollection<T>
{
    [JsonPropertyName("value")] public List<T> Value { get; set; } = [];
    [JsonPropertyName("@odata.nextLink")] public string? NextLink { get; set; }
    [JsonPropertyName("@odata.deltaLink")] public string? DeltaLink { get; set; }
}

public sealed record GraphBatchRequest(string Id, string Method, string Url, JsonElement? Body = null,
    IReadOnlyDictionary<string, string>? Headers = null);

public sealed record GraphBatchResponse(string Id, int Status, JsonElement? Body, IReadOnlyDictionary<string, string>? Headers);

/// <summary>
/// Raw Graph client on the Vaulty pipeline (telemetry → throttling → decoration → authentication). JSON with source-generated
/// metadata; v1.0 only. Every call carries a <see cref="GraphRequestContext"/>.
/// </summary>
public sealed class GraphClient(HttpClient http, Uri? baseUri = null)
{
    public const int MaxBatchSize = 20;
    public const int MaxExportItems = 20;

    public Uri BaseUri { get; } = baseUri ?? new Uri("https://graph.microsoft.com/v1.0/");

    public async Task<T> GetAsync<T>(GraphRequestContext context, string pathOrUrl, JsonTypeInfo<T> type,
        IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(context, HttpMethod.Get, pathOrUrl, null, headers, cancellationToken).ConfigureAwait(false);
        return await ReadAsync(response, type, cancellationToken).ConfigureAwait(false);
    }

    public async Task<TResponse> PostAsync<TBody, TResponse>(GraphRequestContext context, string path, TBody body, JsonTypeInfo<TBody> bodyType,
        JsonTypeInfo<TResponse> responseType, CancellationToken cancellationToken = default)
    {
        using var content = JsonContent.Create(body, bodyType);
        using var response = await SendAsync(context, HttpMethod.Post, path, content, null, cancellationToken).ConfigureAwait(false);
        return await ReadAsync(response, responseType, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Follows @odata.nextLink. Start from <paramref name="resumeFrom"/> (a stored next link) to continue after a restart.</summary>
    public async IAsyncEnumerable<GraphPage<T>> PagesAsync<T>(GraphRequestContext context, string path, JsonTypeInfo<GraphCollection<T>> type,
        string? resumeFrom = null, IReadOnlyDictionary<string, string>? headers = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string? url = resumeFrom ?? path;
        while (url is not null)
        {
            var page = await GetAsync(context, url, type, headers, cancellationToken).ConfigureAwait(false);
            url = page.NextLink;
            yield return new GraphPage<T>(page.Value, page.NextLink);
        }
    }

    /// <summary>One delta page. 410 Gone or a resync error code throws <see cref="DeltaResyncRequiredException"/>.</summary>
    public async Task<GraphDeltaPage<T>> DeltaPageAsync<T>(GraphRequestContext context, string url, JsonTypeInfo<GraphCollection<T>> type,
        IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var page = await GetAsync(context, url, type, headers, cancellationToken).ConfigureAwait(false);
        return new GraphDeltaPage<T>(page.Value, page.NextLink, page.DeltaLink);
    }

    /// <summary>
    /// Sends up to 20 independent requests in one $batch. Sub-requests that come back throttled are sent again (in a new batch)
    /// after the longest Retry-After among them, so the caller only receives final answers.
    /// </summary>
    public async Task<IReadOnlyList<GraphBatchResponse>> BatchAsync(GraphRequestContext context, IReadOnlyList<GraphBatchRequest> requests,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requests);
        if (requests.Count > MaxBatchSize) throw new ArgumentException($"At most {MaxBatchSize} requests per batch.", nameof(requests));
        var pending = requests.ToDictionary(r => r.Id, StringComparer.Ordinal);
        var results = new Dictionary<string, GraphBatchResponse>(StringComparer.Ordinal);
        for (var round = 1; pending.Count > 0; round++)
        {
            var payload = new BatchEnvelope
            {
                Requests = pending.Values.Select(r => new BatchItem
                {
                    Id = r.Id, Method = r.Method, Url = r.Url, Body = r.Body,
                    Headers = r.Body is null ? r.Headers?.ToDictionary() : new Dictionary<string, string>(r.Headers ?? new Dictionary<string, string>())
                    {
                        ["Content-Type"] = "application/json",
                    },
                }).ToList(),
            };
            var answer = await PostAsync(context, "$batch", payload, GraphJson.Default.BatchEnvelope, GraphJson.Default.BatchResult, cancellationToken)
                .ConfigureAwait(false);
            TimeSpan wait = TimeSpan.Zero;
            foreach (var response in answer.Responses)
            {
                if (ThrottlingHandler.IsThrottling((HttpStatusCode)response.Status) && round < 50)
                {
                    var retryAfter = response.Headers?.FirstOrDefault(h => h.Key.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)).Value;
                    var seconds = int.TryParse(retryAfter, out var s) ? s : 1 << Math.Min(round, 6);
                    if (TimeSpan.FromSeconds(seconds) > wait) wait = TimeSpan.FromSeconds(seconds);
                    continue;
                }
                results[response.Id] = new GraphBatchResponse(response.Id, response.Status, response.Body, response.Headers);
                pending.Remove(response.Id);
            }
            if (pending.Count > 0) await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
        return requests.Select(r => results[r.Id]).ToList();
    }

    /// <summary>Full-fidelity export of up to 20 items of one mailbox (mailbox import/export API, v1.0).</summary>
    public async Task<IReadOnlyList<ExportedItem>> ExportItemsAsync(GraphRequestContext context, string mailboxId, IReadOnlyList<string> itemIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(itemIds);
        if (itemIds.Count is 0 or > MaxExportItems) throw new ArgumentException($"Export 1 to {MaxExportItems} items per call.", nameof(itemIds));
        var result = await PostAsync(context, $"admin/exchange/mailboxes/{Uri.EscapeDataString(mailboxId)}/exportItems",
            new ExportItemsRequest { ItemIds = [.. itemIds] }, GraphJson.Default.ExportItemsRequest,
            GraphJson.Default.GraphCollectionExportedItem, cancellationToken).ConfigureAwait(false);
        return result.Value;
    }

    public async Task<HttpResponseMessage> SendAsync(GraphRequestContext context, HttpMethod method, string pathOrUrl, HttpContent? content,
        IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken)
    {
        var uri = Uri.TryCreate(pathOrUrl, UriKind.Absolute, out var absolute) && absolute.Scheme is "https" or "http"
            ? absolute
            : new Uri(BaseUri, pathOrUrl);
        if (!uri.Host.Equals(BaseUri.Host, StringComparison.OrdinalIgnoreCase) || uri.Port != BaseUri.Port)
        {
            // next/delta links always point back to Graph; anything else is refused (no token leaves for another host).
            throw new GraphException(HttpStatusCode.BadRequest, "foreignLink", $"Refusing to send a token to {uri.Host}.", null);
        }
        using var request = new HttpRequestMessage(method, uri) { Content = content }.WithContext(context);
        if (headers is not null)
        {
            foreach (var (name, value) in headers) request.Headers.TryAddWithoutValidation(name, value);
        }
        var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode) return response;
        using (response)
        {
            throw await ToExceptionAsync(response, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync(stream, type, cancellationToken).ConfigureAwait(false)
               ?? throw new GraphException(response.StatusCode, "emptyBody", "Graph returned an empty body.", RequestId(response));
    }

    private static async Task<GraphException> ToExceptionAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string? code = null;
        var message = response.ReasonPhrase ?? "error";
        try
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (body.Length > 0 && JsonSerializer.Deserialize(body, GraphJson.Default.ErrorEnvelope)?.Error is { } error)
            {
                code = error.Code;
                message = error.Message ?? message;
            }
        }
        catch (JsonException)
        {
        }
        var requestId = RequestId(response);
        if (response.StatusCode == HttpStatusCode.Gone || code is "resyncRequired" or "syncStateNotFound" or "syncStateInvalid")
        {
            return new DeltaResyncRequiredException(code, requestId, response.Headers.Location?.ToString());
        }
        return new GraphException(response.StatusCode, code, message, requestId);
    }

    private static string? RequestId(HttpResponseMessage response) =>
        response.Headers.TryGetValues("request-id", out var values) ? values.FirstOrDefault() : null;
}

/// <summary>Builds the Graph pipeline: telemetry → throttling → decoration → authentication → network.</summary>
public static class GraphPipeline
{
    public static HttpClient Create(Auth.IGraphTokenProvider tokens, GraphThrottle throttle, HttpMessageHandler? network = null)
    {
        var auth = new AuthenticationHandler(tokens) { InnerHandler = network ?? new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) } };
        var decoration = new DecorationHandler { InnerHandler = auth };
        var throttling = new ThrottlingHandler(throttle) { InnerHandler = decoration };
        var telemetry = new TelemetryHandler { InnerHandler = throttling };
        return new HttpClient(telemetry) { Timeout = TimeSpan.FromMinutes(30) };
    }
}

public sealed class ExportItemsRequest
{
    [JsonPropertyName("itemIds")] public List<string> ItemIds { get; set; } = [];
}

public sealed class ExportedItem
{
    [JsonPropertyName("itemId")] public string ItemId { get; set; } = "";
    [JsonPropertyName("changeKey")] public string? ChangeKey { get; set; }
    /// <summary>The opaque full-fidelity stream, base64.</summary>
    [JsonPropertyName("data")] public string? Data { get; set; }
    [JsonPropertyName("error")] public GraphError? Error { get; set; }
}

public sealed class ErrorEnvelope
{
    [JsonPropertyName("error")] public GraphError? Error { get; set; }
}

public sealed class GraphError
{
    [JsonPropertyName("code")] public string? Code { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
}

public sealed class BatchEnvelope
{
    [JsonPropertyName("requests")] public List<BatchItem> Requests { get; set; } = [];
}

public sealed class BatchItem
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("method")] public string Method { get; set; } = "GET";
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("body")] public JsonElement? Body { get; set; }
    [JsonPropertyName("headers")] public Dictionary<string, string>? Headers { get; set; }
}

public sealed class BatchResult
{
    [JsonPropertyName("responses")] public List<BatchResultItem> Responses { get; set; } = [];
}

public sealed class BatchResultItem
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("status")] public int Status { get; set; }
    [JsonPropertyName("headers")] public Dictionary<string, string>? Headers { get; set; }
    [JsonPropertyName("body")] public JsonElement? Body { get; set; }
}

public sealed class GraphUser
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("displayName")] public string? DisplayName { get; set; }
    [JsonPropertyName("userPrincipalName")] public string? UserPrincipalName { get; set; }
    [JsonPropertyName("mail")] public string? Mail { get; set; }
    [JsonPropertyName("accountEnabled")] public bool? AccountEnabled { get; set; }
    [JsonPropertyName("userType")] public string? UserType { get; set; }
    [JsonPropertyName("@removed")] public JsonElement? Removed { get; set; }
}

public sealed class GraphOrganization
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("displayName")] public string? DisplayName { get; set; }
    [JsonPropertyName("verifiedDomains")] public List<GraphVerifiedDomain> VerifiedDomains { get; set; } = [];
}

public sealed class GraphVerifiedDomain
{
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("isDefault")] public bool IsDefault { get; set; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(GraphCollection<ExportedItem>), TypeInfoPropertyName = "GraphCollectionExportedItem")]
[JsonSerializable(typeof(GraphCollection<GraphUser>), TypeInfoPropertyName = "GraphCollectionGraphUser")]
[JsonSerializable(typeof(GraphCollection<GraphOrganization>), TypeInfoPropertyName = "GraphCollectionGraphOrganization")]
[JsonSerializable(typeof(GraphCollection<JsonElement>), TypeInfoPropertyName = "GraphCollectionJsonElement")]
[JsonSerializable(typeof(ExportItemsRequest))]
[JsonSerializable(typeof(ErrorEnvelope))]
[JsonSerializable(typeof(BatchEnvelope))]
[JsonSerializable(typeof(BatchResult))]
[JsonSerializable(typeof(GraphUser))]
[JsonSerializable(typeof(JsonElement))]
public sealed partial class GraphJson : JsonSerializerContext;
