using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Vaulty.Connectors.Drive;
using WireMock;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Types;
using WireMock.Util;

namespace Vaulty.Integration.Tests.Backup;

/// <summary>
/// A OneDrive behind a WireMock Graph endpoint: drive delta with paging and delta tokens, items with download URLs that honour
/// Range, versions with content, and permissions through $batch. Tests change it between runs.
/// </summary>
internal sealed class DriveSimulator : IDisposable
{
    public const string DriveId = "b!drive-sim";
    public const string RootId = "01ROOTSIM";
    private const int PageSize = 20;
    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly object _gate = new();
    private readonly List<(string Id, int At)> _removals = [];
    private int _clock;
    private int _next;

    public sealed class Node
    {
        public required string Id { get; init; }
        public required string Name { get; set; }
        public required string ParentId { get; set; }
        public bool IsFolder { get; init; }
        public int Size { get; init; }
        public int Version { get; set; } = 1;
        public int MetadataVersion { get; set; } = 1;
        public int ChangedAt { get; set; }
        public bool Shared { get; init; }
        public byte[] Data => Content(Id, Version, Size);
    }

    public Dictionary<string, Node> Nodes { get; } = new(StringComparer.Ordinal);
    public IEnumerable<Node> Files => Nodes.Values.Where(n => !n.IsFolder);
    public IEnumerable<Node> Folders => Nodes.Values.Where(n => n.IsFolder);

    /// <summary>Downloads served (full or ranged), per file id.</summary>
    public Dictionary<string, int> Downloads { get; } = new(StringComparer.Ordinal);

    /// <summary>Files whose download reports a different hash than the content (a corrupted transfer).</summary>
    public HashSet<string> CorruptHashes { get; } = new(StringComparer.Ordinal);

    public string Url => _server.Url!;

    public DriveSimulator(int files, int seed = 1)
    {
        var random = new Random(seed);
        var docs = AddFolder("Documents", RootId);
        var photos = AddFolder("Photos", RootId);
        var archive = AddFolder("Archive", docs.Id);
        string[] parents = [RootId, docs.Id, photos.Id, archive.Id];
        for (var i = 0; i < files; i++) AddFile(parents[random.Next(parents.Length)], random.Next(1_000, 300_000), shared: i % 7 == 0);
        Map();
    }

    /// <summary>
    /// Content of a file version: a fixed random body per file, with a small edit per version at a version-dependent place,
    /// so versions of one file share most of their chunks, like real edits.
    /// </summary>
    public static byte[] Content(string id, int version, int size)
    {
        var bytes = new byte[size];
        new Random(BitConverter.ToInt32(SHA256.HashData(Encoding.UTF8.GetBytes(id)))).NextBytes(bytes);
        for (var v = 2; v <= version; v++)
        {
            var at = (int)((long)v * 2_654_435_761 % Math.Max(1, size - 64));
            var edit = SHA256.HashData(Encoding.UTF8.GetBytes($"{id}/{v}"));
            for (var i = 0; i < 64 && at + i < size; i++) bytes[at + i] ^= edit[i % 32];
        }
        return bytes;
    }

    public Node AddFolder(string name, string parentId)
    {
        lock (_gate)
        {
            var node = new Node { Id = $"fld-{++_next:D4}", Name = name, ParentId = parentId, IsFolder = true, ChangedAt = ++_clock };
            Nodes[node.Id] = node;
            return node;
        }
    }

    public Node AddFile(string parentId, int size, bool shared = false, string? name = null)
    {
        lock (_gate)
        {
            var id = $"file-{++_next:D5}";
            var node = new Node { Id = id, Name = name ?? $"{id}.bin", ParentId = parentId, Size = size, ChangedAt = ++_clock, Shared = shared };
            Nodes[id] = node;
            return node;
        }
    }

    public void Edit(string id)
    {
        lock (_gate)
        {
            Nodes[id].Version++;
            Nodes[id].MetadataVersion++;
            Nodes[id].ChangedAt = ++_clock;
        }
    }

    /// <summary>A rename: new name and eTag, same content and cTag.</summary>
    public void Rename(string id, string name)
    {
        lock (_gate)
        {
            Nodes[id].Name = name;
            Nodes[id].MetadataVersion++;
            Nodes[id].ChangedAt = ++_clock;
        }
    }

    public void Remove(string id)
    {
        lock (_gate)
        {
            _removals.Add((id, ++_clock));
            Nodes.Remove(id);
        }
    }

    private string PathOf(string parentId)
    {
        var parts = new List<string>();
        for (var id = parentId; id != RootId; id = Nodes[id].ParentId) parts.Insert(0, Nodes[id].Name);
        return "/drive/root:" + (parts.Count == 0 ? "" : "/" + string.Join('/', parts));
    }

    private JsonObject Json(Node node)
    {
        var json = new JsonObject
        {
            ["id"] = node.Id, ["name"] = node.Name, ["size"] = node.IsFolder ? 0 : node.Size,
            ["eTag"] = $"\"{{{node.Id}}},{node.MetadataVersion}\"",
            ["createdDateTime"] = "2026-10-01T08:00:00Z", ["lastModifiedDateTime"] = $"2026-11-0{1 + node.Version % 8}T08:00:00Z",
            ["parentReference"] = new JsonObject { ["id"] = node.ParentId, ["driveId"] = DriveId, ["path"] = PathOf(node.ParentId) },
        };
        if (node.IsFolder)
        {
            json["folder"] = new JsonObject { ["childCount"] = Nodes.Values.Count(n => n.ParentId == node.Id) };
            return json;
        }
        json["cTag"] = $"\"c:{{{node.Id}}},{node.Version}\"";
        var data = node.Data;
        var hash = QuickXorHash.Base64(data);
        if (CorruptHashes.Contains(node.Id)) hash = QuickXorHash.Base64([1, 2, 3]);
        json["file"] = new JsonObject { ["mimeType"] = "application/octet-stream", ["hashes"] = new JsonObject { ["quickXorHash"] = hash } };
        json["@microsoft.graph.downloadUrl"] = $"{Url}/download/{node.Id}/{node.Version}?tempauth=example";
        if (node.Shared) json["shared"] = new JsonObject { ["scope"] = "organization" };
        return json;
    }

    private void Map()
    {
        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/drives/[^/]+/root/delta$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(request => Respond(() => Delta(request))));

        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/drives/[^/]+/root$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(_ =>
                Json200(new JsonObject { ["id"] = RootId, ["name"] = "root", ["root"] = new JsonObject(), ["folder"] = new JsonObject() }.ToJsonString())));

        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/drives/[^/]+/items/[^/]+$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(request =>
            {
                var id = Uri.UnescapeDataString(request.Path.Split('/')[5]);
                lock (_gate) return Nodes.TryGetValue(id, out var node) ? Json200(Json(node).ToJsonString()) : new ResponseMessage { StatusCode = 404 };
            }));

        // Versions: the newest first, version ids "1.0" … "n.0"; the newest is the current one.
        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/drives/[^/]+/items/[^/]+/versions$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(request =>
            {
                var id = Uri.UnescapeDataString(request.Path.Split('/')[5]);
                lock (_gate)
                {
                    if (!Nodes.TryGetValue(id, out var node)) return new ResponseMessage { StatusCode = 404 };
                    var list = Enumerable.Range(1, node.Version).Reverse().Select(v => (JsonNode)new JsonObject
                    {
                        ["id"] = $"{v}.0", ["size"] = node.Size, ["lastModifiedDateTime"] = $"2026-10-{v:D2}T08:00:00Z",
                    }).ToArray();
                    return Json200(new JsonObject { ["value"] = new JsonArray(list) }.ToJsonString());
                }
            }));

        _server.Given(Request.Create().WithPath(new RegexMatcher("^/v1\\.0/drives/[^/]+/items/[^/]+/versions/[^/]+/content$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(request =>
            {
                var parts = request.Path.Split('/');
                var id = Uri.UnescapeDataString(parts[5]);
                var version = int.Parse(Uri.UnescapeDataString(parts[7]).Split('.')[0], System.Globalization.CultureInfo.InvariantCulture);
                lock (_gate)
                {
                    if (!Nodes.TryGetValue(id, out var node)) return new ResponseMessage { StatusCode = 404 };
                    return Bytes(Content(id, version, node.Size), request);
                }
            }));

        _server.Given(Request.Create().WithPath(new RegexMatcher("^/download/[^/]+/[^/]+$")).UsingGet())
            .RespondWith(Response.Create().WithCallback(request =>
            {
                if (request.Headers?.ContainsKey("Authorization") == true) return new ResponseMessage { StatusCode = 400 }; // never send a token here
                var parts = request.Path.Split('/');
                lock (_gate)
                {
                    if (!Nodes.TryGetValue(parts[2], out var node)) return new ResponseMessage { StatusCode = 404 };
                    Downloads[node.Id] = Downloads.GetValueOrDefault(node.Id) + 1;
                    return Bytes(Content(node.Id, int.Parse(parts[3], System.Globalization.CultureInfo.InvariantCulture), node.Size), request);
                }
            }));

        _server.Given(Request.Create().WithPath("/v1.0/$batch").UsingPost()).RespondWith(Response.Create().WithCallback(request => Respond(() =>
        {
            var responses = new JsonArray();
            foreach (var r in JsonNode.Parse(request.Body!)!["requests"]!.AsArray())
            {
                responses.Add(new JsonObject
                {
                    ["id"] = r!["id"]!.GetValue<string>(), ["status"] = 200,
                    ["body"] = new JsonObject
                    {
                        ["value"] = new JsonArray(new JsonObject
                        {
                            ["id"] = "perm-1", ["roles"] = new JsonArray("read"),
                            ["link"] = new JsonObject { ["scope"] = "organization", ["type"] = "view" },
                        }),
                    },
                });
            }
            return new JsonObject { ["responses"] = responses };
        })));
    }

    private JsonObject Delta(IRequestMessage request)
    {
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
            if (query.TryGetValue("token", out var token)) since = int.Parse(token[0], System.Globalization.CultureInfo.InvariantCulture);
            upto = _clock;
        }

        var root = new JsonObject { ["id"] = RootId, ["name"] = "root", ["root"] = new JsonObject(), ["folder"] = new JsonObject() };
        var changes = (since < 0 ? [root] : new List<JsonNode>())
            .Concat(Nodes.Values.Where(n => since < 0 || (n.ChangedAt > since && n.ChangedAt <= upto))
                .OrderBy(n => n.IsFolder ? 0 : 1).ThenBy(n => n.Id, StringComparer.Ordinal).Select(n => (JsonNode)Json(n)))
            .Concat(since < 0 ? [] : _removals.Where(r => r.At > since && r.At <= upto).OrderBy(r => r.Id, StringComparer.Ordinal)
                .Select(r => (JsonNode)new JsonObject { ["id"] = r.Id, ["deleted"] = new JsonObject { ["state"] = "deleted" } }))
            .ToList();
        var page = changes.Skip(offset).Take(PageSize).Select(n => n!.DeepClone()).ToArray();
        var result = new JsonObject { ["value"] = new JsonArray(page) };
        var basePath = $"{Url}/v1.0/drives/{Uri.EscapeDataString(DriveId)}/root/delta";
        if (offset + PageSize < changes.Count) result["@odata.nextLink"] = $"{basePath}?$skiptoken={since}.{offset + PageSize}.{upto}";
        else result["@odata.deltaLink"] = $"{basePath}?token={upto}";
        return result;
    }

    private static ResponseMessage Bytes(byte[] data, IRequestMessage request)
    {
        var offset = 0;
        if (request.Headers?.TryGetValue("Range", out var range) == true)
        {
            offset = int.Parse(range[0]["bytes=".Length..].TrimEnd('-'), System.Globalization.CultureInfo.InvariantCulture);
            return new ResponseMessage
            {
                StatusCode = 206,
                Headers = new Dictionary<string, WireMockList<string>> { ["Content-Range"] = new($"bytes {offset}-{data.Length - 1}/{data.Length}") },
                BodyData = new BodyData { BodyAsBytes = data[offset..], DetectedBodyType = BodyType.Bytes },
            };
        }
        return new ResponseMessage { StatusCode = 200, BodyData = new BodyData { BodyAsBytes = data, DetectedBodyType = BodyType.Bytes } };
    }

    private ResponseMessage Respond(Func<JsonObject> body)
    {
        lock (_gate) return Json200(body().ToJsonString());
    }

    private static ResponseMessage Json200(string json) => new()
    {
        StatusCode = 200,
        Headers = new Dictionary<string, WireMockList<string>> { ["Content-Type"] = new("application/json") },
        BodyData = new BodyData { BodyAsString = json, DetectedBodyType = BodyType.String },
    };

    public void Dispose() => _server.Dispose();
}
