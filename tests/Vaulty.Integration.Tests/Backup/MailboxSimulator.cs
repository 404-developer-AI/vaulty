using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using WireMock;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Types;
using WireMock.Util;

namespace Vaulty.Integration.Tests.Backup;

/// <summary>
/// A mailbox behind a WireMock Graph endpoint: folders, item delta with paging and delta tokens, full-fidelity export,
/// metadata through $batch and the MIME fallback. Tests change it between runs and inject failures and throttling.
/// </summary>
internal sealed class MailboxSimulator : IDisposable
{
    public const string MailboxId = "MBX:sim@contoso";
    public const string UserId = "user-1";
    private const int PageSize = 25;
    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly object _gate = new();
    private int _clock;
    private int _requests;

    public sealed record Folder(string Id, string Name, string Type, string? WellKnownName);

    public sealed class Item
    {
        public required string Id { get; init; }
        public required string FolderId { get; set; }
        public required string Type { get; init; }
        public int Version { get; set; } = 1;
        public int ChangedAt { get; set; }
        public int Size { get; init; }
        public string ChangeKey => $"ck-{Id}-{Version}";
        public byte[] Data => Content(Id, Version, Size);
    }

    public List<Folder> Folders { get; } =
    [
        new("f-inbox", "Inbox", "IPF.Note", "inbox"),
        new("f-sent", "Sent Items", "IPF.Note", "sentitems"),
        new("f-calendar", "Calendar", "IPF.Appointment", "calendar"),
        new("f-contacts", "Contacts", "IPF.Contact", "contacts"),
    ];

    public Dictionary<string, Item> Items { get; } = new(StringComparer.Ordinal);

    /// <summary>Removals per folder with the clock value when they happened.</summary>
    private readonly List<(string FolderId, string Id, int At)> _removals = [];

    /// <summary>Items whose export fails; with <see cref="MimeAlsoFails"/> the MIME fallback fails too.</summary>
    public HashSet<string> FailingExports { get; } = new(StringComparer.Ordinal);
    public bool MimeAlsoFails { get; set; } = true;

    /// <summary>Every n-th request is answered with 429 and Retry-After: 1 (0 = never).</summary>
    public int ThrottleEvery { get; set; }
    public int Throttled { get; private set; }

    public string Url => _server.Url!;

    public MailboxSimulator(int items, int seed = 1)
    {
        var random = new Random(seed);
        for (var i = 0; i < items; i++) Add(Folders[random.Next(Folders.Count)].Id, random.Next(500, 60_000));
        Map();
    }

    public static byte[] Content(string id, int version, int size)
    {
        var bytes = new byte[size];
        var seed = SHA256.HashData(Encoding.UTF8.GetBytes($"{id}/{version}"));
        for (var i = 0; i < size; i += 32) seed.AsSpan(0, Math.Min(32, size - i)).CopyTo(bytes.AsSpan(i));
        for (var i = 0; i < size; i++) bytes[i] ^= (byte)(i % 7); // mildly compressible, unique per item and version
        return bytes;
    }

    public Item Add(string folderId, int size = 4_000)
    {
        lock (_gate)
        {
            var folder = Folders.Single(f => f.Id == folderId);
            var type = folder.Type switch { "IPF.Appointment" => "IPM.Appointment", "IPF.Contact" => "IPM.Contact", _ => "IPM.Note" };
            var item = new Item { Id = $"item-{Items.Count:D5}-{Guid.NewGuid():N}"[..20], FolderId = folderId, Type = type, Size = size, ChangedAt = ++_clock };
            Items[item.Id] = item;
            return item;
        }
    }

    public void Change(string id)
    {
        lock (_gate)
        {
            Items[id].Version++;
            Items[id].ChangedAt = ++_clock;
        }
    }

    public void Remove(string id)
    {
        lock (_gate)
        {
            _removals.Add((Items[id].FolderId, id, ++_clock));
            Items.Remove(id);
        }
    }

    public int CountIn(string folderId) => Items.Values.Count(i => i.FolderId == folderId);

    private void Map()
    {
        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/admin/exchange/mailboxes/[^/]+/folders$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(_ => Respond(() => new JsonObject
            {
                ["value"] = new JsonArray(Folders.Select(f => (JsonNode)new JsonObject
                {
                    ["id"] = f.Id, ["displayName"] = f.Name, ["parentFolderId"] = "root", ["type"] = f.Type, ["wellKnownName"] = f.WellKnownName,
                    ["totalItemCount"] = CountIn(f.Id), ["childFolderCount"] = 0,
                }).ToArray()),
            })));

        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/admin/exchange/mailboxes/[^/]+/folders/[^/]+/items/delta$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(request => Respond(() => Delta(request))));

        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/admin/exchange/mailboxes/[^/]+/exportItems$")).UsingPost())
            .RespondWith(Response.Create().WithCallback(request => Respond(() =>
            {
                var ids = JsonNode.Parse(request.Body!)!["itemIds"]!.AsArray().Select(n => n!.GetValue<string>()).ToList();
                return new JsonObject
                {
                    ["value"] = new JsonArray(ids.Select(id => (JsonNode)(FailingExports.Contains(id) || !Items.ContainsKey(id)
                        ? new JsonObject { ["itemId"] = id, ["error"] = new JsonObject { ["code"] = "ErrorItemCorrupt", ["message"] = "The item is corrupt." } }
                        : new JsonObject { ["itemId"] = id, ["changeKey"] = Items[id].ChangeKey, ["data"] = Convert.ToBase64String(Items[id].Data) })).ToArray()),
                };
            })));

        _server.Given(Request.Create().WithPath("/v1.0/$batch").UsingPost()).RespondWith(Response.Create().WithCallback(request => Respond(() =>
        {
            var responses = new JsonArray();
            foreach (var r in JsonNode.Parse(request.Body!)!["requests"]!.AsArray())
            {
                var url = r!["url"]!.GetValue<string>();
                var id = Uri.UnescapeDataString(url.Split('/')[4].Split('?')[0]);
                responses.Add(Items.TryGetValue(id, out var item)
                    ? new JsonObject
                    {
                        ["id"] = r["id"]!.GetValue<string>(), ["status"] = 200,
                        ["body"] = new JsonObject
                        {
                            ["subject"] = $"Subject of {id}", ["from"] = new JsonObject { ["emailAddress"] = new JsonObject { ["address"] = "sender@contoso.example" } },
                            ["isRead"] = true, ["hasAttachments"] = false,
                        },
                    }
                    : new JsonObject { ["id"] = r["id"]!.GetValue<string>(), ["status"] = 404 });
            }
            return new JsonObject { ["responses"] = responses };
        })));

        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/users/[^/]+/messages/[^/]+/\\$value$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(request =>
            {
                var id = Uri.UnescapeDataString(request.Path.Split('/')[5]);
                if (MimeAlsoFails || !Items.ContainsKey(id)) return new ResponseMessage { StatusCode = 404 };
                return new ResponseMessage
                {
                    StatusCode = 200,
                    BodyData = new BodyData { BodyAsBytes = Encoding.UTF8.GetBytes($"Subject: {id}\r\n\r\nMIME body"), DetectedBodyType = BodyType.Bytes },
                };
            }));
    }

    private JsonObject Delta(IRequestMessage request)
    {
        var folderId = request.Path.Split('/')[7];
        var query = request.Query ?? new Dictionary<string, WireMockList<string>>();
        int since = -1, offset = 0, upto;
        if (query.TryGetValue("$skiptoken", out var skip))
        {
            var parts = skip[0].Split('.');
            since = int.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture);
            offset = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
            upto = int.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture);
        }
        else
        {
            if (query.TryGetValue("$deltatoken", out var token)) since = int.Parse(token[0], System.Globalization.CultureInfo.InvariantCulture);
            upto = _clock;
        }

        // Changes in (since, upto]: current items changed in that window, removals in that window. A full listing has since = -1.
        var changes = Items.Values.Where(i => i.FolderId == folderId && (since < 0 || (i.ChangedAt > since && i.ChangedAt <= upto)))
            .OrderBy(i => i.Id, StringComparer.Ordinal)
            .Select(i => (JsonNode)new JsonObject
            {
                ["id"] = i.Id, ["changeKey"] = i.ChangeKey, ["type"] = i.Type, ["size"] = i.Size, ["categories"] = new JsonArray(),
                ["createdDateTime"] = "2026-11-01T10:00:00Z", ["lastModifiedDateTime"] = "2026-11-02T10:00:00Z",
            })
            .Concat(since < 0 ? [] : _removals.Where(r => r.FolderId == folderId && r.At > since && r.At <= upto).OrderBy(r => r.Id, StringComparer.Ordinal)
                .Select(r => (JsonNode)new JsonObject { ["id"] = r.Id, ["@removed"] = new JsonObject { ["reason"] = "deleted" } }))
            .ToList();
        var page = changes.Skip(offset).Take(PageSize).Select(n => n!.DeepClone()).ToArray();
        var result = new JsonObject { ["value"] = new JsonArray(page) };
        var basePath = $"{Url}/v1.0/admin/exchange/mailboxes/{Uri.EscapeDataString(MailboxId)}/folders/{folderId}/items/delta";
        if (offset + PageSize < changes.Count) result["@odata.nextLink"] = $"{basePath}?$skiptoken={since}.{offset + PageSize}.{upto}";
        else result["@odata.deltaLink"] = $"{basePath}?$deltatoken={upto}";
        return result;
    }

    private ResponseMessage Respond(Func<JsonObject> body)
    {
        lock (_gate)
        {
            _requests++;
            if (ThrottleEvery > 0 && _requests % ThrottleEvery == 0)
            {
                Throttled++;
                return new ResponseMessage { StatusCode = 429, Headers = new Dictionary<string, WireMockList<string>> { ["Retry-After"] = new("1") } };
            }
            return new ResponseMessage
            {
                StatusCode = 200,
                Headers = new Dictionary<string, WireMockList<string>> { ["Content-Type"] = new("application/json") },
                BodyData = new BodyData { BodyAsString = body().ToJsonString(), DetectedBodyType = BodyType.String },
            };
        }
    }

    public void Dispose() => _server.Dispose();
}
