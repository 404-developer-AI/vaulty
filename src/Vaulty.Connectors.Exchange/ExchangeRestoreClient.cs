using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vaulty.Graph;
using Vaulty.Graph.Http;

namespace Vaulty.Connectors.Exchange;

/// <summary>An import session: a pre-authenticated URL on the Exchange host, valid until <see cref="ExpiresAt"/>.</summary>
public sealed record ImportSession(Uri ImportUrl, DateTimeOffset ExpiresAt);

public sealed record ImportedItem(string ItemId, string? ChangeKey);

/// <summary>
/// Restores into Exchange Online through the mailbox import API: items exported in full fidelity are imported as they were
/// (calendar items as existing objects, so no invitation or update is ever sent), into folders this client creates.
/// </summary>
public sealed class ExchangeRestoreClient(GraphClient graph, GraphDownloadClient preauthenticated)
{
    /// <summary>Import sessions are renewed this long before they expire.</summary>
    public static readonly TimeSpan SessionMargin = TimeSpan.FromMinutes(5);

    public async Task<ImportSession> CreateImportSessionAsync(GraphRequestContext context, string mailboxId, CancellationToken cancellationToken = default)
    {
        using var response = await graph.SendAsync(context, HttpMethod.Post,
            $"admin/exchange/mailboxes/{Uri.EscapeDataString(mailboxId)}/createImportSession", new StringContent("", Encoding.UTF8, "application/json"), null,
            cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        var url = new Uri(document.RootElement.GetProperty("importUrl").GetString()!);
        var expires = document.RootElement.TryGetProperty("expirationDateTime", out var e) && e.TryGetDateTimeOffset(out var at) ? at : DateTimeOffset.UtcNow.AddMinutes(30);
        return new ImportSession(url, expires);
    }

    /// <summary>Imports one item (its exported data) as a new item in the folder.</summary>
    public async Task<ImportedItem> ImportAsync(GraphRequestContext context, ImportSession session, string folderId, ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var body = new JsonObject { ["FolderId"] = folderId, ["Mode"] = "create", ["Data"] = Convert.ToBase64String(data.Span) };
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await preauthenticated.SendAsync(context, HttpMethod.Post, session.ImportUrl, content, cancellationToken).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw GraphException.FromBody(response.StatusCode, text);
        using var document = JsonDocument.Parse(text);
        return new ImportedItem(document.RootElement.GetProperty("itemId").GetString()!,
            document.RootElement.TryGetProperty("changeKey", out var key) ? key.GetString() : null);
    }

    /// <summary>The folders of a mailbox (to find a restore folder that exists already, or check that an original folder still exists).</summary>
    public async Task<IReadOnlyList<MailboxFolderInfo>> FoldersAsync(GraphRequestContext context, string mailboxId, CancellationToken cancellationToken = default)
    {
        var folders = new List<MailboxFolderInfo>();
        await foreach (var folder in new ExchangeClient(graph).FoldersAsync(context, mailboxId, cancellationToken).ConfigureAwait(false)) folders.Add(folder);
        return folders;
    }

    /// <summary>Creates a folder under <paramref name="parentId"/> (null: the top of the mailbox) and returns its id.</summary>
    public async Task<MailboxFolderInfo> CreateFolderAsync(GraphRequestContext context, string mailboxId, string? parentId, string name, string type,
        CancellationToken cancellationToken = default)
    {
        var path = parentId is null
            ? $"admin/exchange/mailboxes/{Uri.EscapeDataString(mailboxId)}/folders"
            : $"admin/exchange/mailboxes/{Uri.EscapeDataString(mailboxId)}/folders/{Uri.EscapeDataString(parentId)}/childFolders";
        var body = new JsonObject { ["displayName"] = name, ["type"] = type };
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await graph.SendAsync(context, HttpMethod.Post, path, content, null, cancellationToken).ConfigureAwait(false);
        var folder = JsonSerializer.Deserialize<MailboxFolderInfo>(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false))!;
        return folder;
    }

    public static bool IsExpired(ImportSession session, DateTimeOffset now) => now + SessionMargin >= session.ExpiresAt;

    public static bool IsConflict(GraphException exception) => exception?.Status == HttpStatusCode.Conflict;
}
