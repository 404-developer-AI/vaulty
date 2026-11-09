using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Vaulty.Graph;
using Vaulty.Graph.Http;

namespace Vaulty.Connectors.Exchange;

/// <summary>A folder of a mailbox (mail, calendar, contacts, tasks, notes), from the mailbox import/export API.</summary>
public sealed class MailboxFolderInfo
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("displayName")] public string? DisplayName { get; set; }
    [JsonPropertyName("parentFolderId")] public string? ParentFolderId { get; set; }
    [JsonPropertyName("wellKnownName")] public string? WellKnownName { get; set; }
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("totalItemCount")] public int TotalItemCount { get; set; }
    [JsonPropertyName("childFolderCount")] public int ChildFolderCount { get; set; }
}

/// <summary>One change in a folder's item delta: an added or changed item, or a removal.</summary>
public sealed class MailboxItemChange
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("changeKey")] public string? ChangeKey { get; set; }
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("createdDateTime")] public DateTimeOffset? CreatedDateTime { get; set; }
    [JsonPropertyName("lastModifiedDateTime")] public DateTimeOffset? LastModifiedDateTime { get; set; }
    [JsonPropertyName("categories")] public List<string>? Categories { get; set; }
    [JsonPropertyName("@removed")] public JsonElement? Removed { get; set; }

    [JsonIgnore] public bool IsRemoved => Removed is { ValueKind: JsonValueKind.Object };
}

/// <summary>Searchable metadata of an item, read best-effort from the regular mail, calendar and contacts endpoints.</summary>
public sealed record ItemMetadata(string? Subject, string? From, IReadOnlyList<string> To, DateTimeOffset? Received, bool HasAttachments,
    string? BodyPreview, IReadOnlyList<string> Categories, bool? IsRead, string? Flag);

[JsonSerializable(typeof(GraphCollection<MailboxFolderInfo>), TypeInfoPropertyName = "Folders")]
[JsonSerializable(typeof(GraphCollection<MailboxItemChange>), TypeInfoPropertyName = "ItemChanges")]
public sealed partial class ExchangeJson : JsonSerializerContext;

/// <summary>
/// Exchange Online through Microsoft Graph: folders and item delta from the mailbox import/export API (v1.0), full-fidelity
/// export of up to 20 items per call, searchable metadata from the regular endpoints, and the MIME fallback for messages.
/// </summary>
public sealed class ExchangeClient(GraphClient graph)
{
    public const int DeltaPageSize = 200;

    /// <summary>Every folder of the mailbox, including hidden and search folders.</summary>
    public async IAsyncEnumerable<MailboxFolderInfo> FoldersAsync(GraphRequestContext context, string mailboxId,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var path = $"admin/exchange/mailboxes/{Uri.EscapeDataString(mailboxId)}/folders?$top=250";
        await foreach (var page in graph.PagesAsync(context, path, ExchangeJson.Default.Folders, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            foreach (var folder in page.Items) yield return folder;
        }
    }

    /// <summary>One page of a folder's item delta, from the start (no link), a next link or the stored delta link.</summary>
    public Task<GraphDeltaPage<MailboxItemChange>> ItemDeltaAsync(GraphRequestContext context, string mailboxId, string folderId, string? link,
        CancellationToken cancellationToken = default) =>
        graph.DeltaPageAsync(context, link ?? $"admin/exchange/mailboxes/{Uri.EscapeDataString(mailboxId)}/folders/{Uri.EscapeDataString(folderId)}/items/delta",
            ExchangeJson.Default.ItemChanges, new Dictionary<string, string> { ["Prefer"] = $"odata.maxpagesize={DeltaPageSize}" }, cancellationToken);

    public Task<IReadOnlyList<ExportedItem>> ExportAsync(GraphRequestContext context, string mailboxId, IReadOnlyList<string> itemIds,
        CancellationToken cancellationToken = default) =>
        graph.ExportItemsAsync(context, mailboxId, itemIds, cancellationToken);

    /// <summary>
    /// Subject, sender, recipients and flags for search and browsing, 20 items per $batch. Items whose metadata cannot be read
    /// are simply missing from the result: content backup never depends on this path.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, ItemMetadata>> MetadataAsync(GraphRequestContext context, string userId,
        IReadOnlyList<(string Id, string? Type)> items, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(items);
        var result = new Dictionary<string, ItemMetadata>(StringComparer.Ordinal);
        foreach (var batch in items.Where(i => Endpoint(i.Type) is not null).Chunk(GraphClient.MaxBatchSize))
        {
            var requests = batch.Select((item, n) => new GraphBatchRequest(n.ToString(System.Globalization.CultureInfo.InvariantCulture), "GET",
                $"/users/{userId}/{Endpoint(item.Type)}/{Uri.EscapeDataString(item.Id)}?$select={Select(item.Type)}",
                Headers: new Dictionary<string, string> { ["Prefer"] = "IdType=\"ImmutableId\"" })).ToList();
            IReadOnlyList<GraphBatchResponse> responses;
            try
            {
                responses = await graph.BatchAsync(context, requests, cancellationToken).ConfigureAwait(false);
            }
            catch (GraphException)
            {
                continue;
            }
            foreach (var response in responses)
            {
                if (response.Status != 200 || response.Body is not { ValueKind: JsonValueKind.Object } body) continue;
                var item = batch[int.Parse(response.Id, System.Globalization.CultureInfo.InvariantCulture)];
                result[item.Id] = Parse(body);
            }
        }
        return result;
    }

    /// <summary>The MIME of a message, for the limited-fidelity fallback when full-fidelity export is refused.</summary>
    public async Task<Stream> MimeAsync(GraphRequestContext context, string userId, string itemId, CancellationToken cancellationToken = default)
    {
        var response = await graph.SendAsync(context, HttpMethod.Get, $"users/{userId}/messages/{Uri.EscapeDataString(itemId)}/$value", null, null,
            cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
    }

    public static string Kind(string? type) => type switch
    {
        null => "item",
        _ when type.StartsWith("IPM.Appointment", StringComparison.OrdinalIgnoreCase) || type.StartsWith("IPM.Schedule", StringComparison.OrdinalIgnoreCase) => "event",
        _ when type.StartsWith("IPM.Contact", StringComparison.OrdinalIgnoreCase) || type.StartsWith("IPM.DistList", StringComparison.OrdinalIgnoreCase) => "contact",
        _ when type.StartsWith("IPM.Task", StringComparison.OrdinalIgnoreCase) => "task",
        _ when type.StartsWith("IPM.StickyNote", StringComparison.OrdinalIgnoreCase) => "note",
        _ => "mail",
    };

    private static string? Endpoint(string? type) => Kind(type) switch
    {
        "mail" => "messages",
        "event" => "events",
        "contact" => "contacts",
        _ => null,
    };

    private static string Select(string? type) => Kind(type) switch
    {
        "event" => "subject,organizer,attendees,start,hasAttachments,categories,bodyPreview",
        "contact" => "displayName,emailAddresses,companyName,categories",
        _ => "subject,from,toRecipients,receivedDateTime,hasAttachments,categories,bodyPreview,isRead,flag",
    };

    private static ItemMetadata Parse(JsonElement body)
    {
        static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static string? Address(JsonElement e) =>
            e.TryGetProperty("emailAddress", out var a) && a.ValueKind == JsonValueKind.Object ? Str(a, "address") ?? Str(a, "name") : null;
        static List<string> Addresses(JsonElement e, string name) =>
            e.TryGetProperty(name, out var list) && list.ValueKind == JsonValueKind.Array ? list.EnumerateArray().Select(Address).OfType<string>().ToList() : [];

        var subject = Str(body, "subject") ?? Str(body, "displayName");
        var from = body.TryGetProperty("from", out var f) && f.ValueKind == JsonValueKind.Object ? Address(f)
            : body.TryGetProperty("organizer", out var o) && o.ValueKind == JsonValueKind.Object ? Address(o) : null;
        var to = Addresses(body, "toRecipients");
        if (to.Count == 0) to = Addresses(body, "attendees");
        if (to.Count == 0 && body.TryGetProperty("emailAddresses", out var emails) && emails.ValueKind == JsonValueKind.Array)
        {
            to = emails.EnumerateArray().Select(e => Str(e, "address")).OfType<string>().ToList();
        }
        DateTimeOffset? received = Str(body, "receivedDateTime") is { } r && DateTimeOffset.TryParse(r, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;
        var categories = body.TryGetProperty("categories", out var c) && c.ValueKind == JsonValueKind.Array
            ? c.EnumerateArray().Select(x => x.GetString()).OfType<string>().ToList()
            : [];
        bool? isRead = body.TryGetProperty("isRead", out var read) && read.ValueKind is JsonValueKind.True or JsonValueKind.False ? read.GetBoolean() : null;
        var flag = body.TryGetProperty("flag", out var fl) && fl.ValueKind == JsonValueKind.Object ? Str(fl, "flagStatus") : null;
        var attachments = body.TryGetProperty("hasAttachments", out var h) && h.ValueKind == JsonValueKind.True;
        return new ItemMetadata(subject, from, to, received, attachments, Str(body, "bodyPreview"), categories, isRead, flag);
    }
}
