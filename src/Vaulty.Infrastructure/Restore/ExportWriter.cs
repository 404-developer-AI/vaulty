using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using MimeKit;

namespace Vaulty.Infrastructure.Restore;

/// <summary>One entry of the export manifest: what was written for an item, or why not.</summary>
public sealed record ExportEntry(Guid ItemId, string SourceId, string Kind, string? Path, string State, string? Detail);

/// <summary>
/// Writes an export as a zip in store mode straight into a stream (the upload to the export bucket): messages as EML,
/// events as ICS, contacts as VCF, files as they are, and a manifest.json with the metadata and result of every item.
/// Paths come from names in Microsoft 365 and are made safe: no absolute paths, no "..", no characters a file system refuses.
/// </summary>
public sealed class ExportWriter : IAsyncDisposable
{
    private readonly ZipArchive _zip;
    private readonly HashSet<string> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<object> _manifest = [];

    public ExportWriter(Stream output)
    {
        _zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8);
    }

    public int Entries { get; private set; }

    /// <summary>
    /// Adds one item. <paramref name="writeContent"/> streams the stored content into the given stream; it is used for files
    /// and for messages that were backed up as MIME.
    /// </summary>
    public async Task<ExportEntry> AddAsync(PendingItem item, Func<Stream, Task> writeContent, Func<Task<string?>> readPreview)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(writeContent);
        ArgumentNullException.ThrowIfNull(readPreview);
        using var metadata = JsonDocument.Parse(item.MetadataJson);
        var meta = metadata.RootElement;
        string? path = null;
        string state = "restored";
        string? detail = null;
        switch (item.Kind)
        {
            case "file" or "file_version":
            {
                var name = Text(meta, "name") ?? item.SourceId;
                if (item.Kind == "file_version") name = Versioned(name, Text(meta, "version"));
                path = Unique(Join(item.RelativePath, name));
                if (item.Content is null)
                {
                    (state, detail, path) = ("failed", "The file has no stored content.", null);
                    break;
                }
                await using (var entry = _zip.CreateEntry(path, CompressionLevel.NoCompression).Open()) await writeContent(entry).ConfigureAwait(false);
                break;
            }
            case "mail":
            {
                var subject = Text(meta, "subject");
                path = Unique(Join(item.RelativePath, $"{(string.IsNullOrWhiteSpace(subject) ? "(no subject)" : subject)} {Short(item.SourceId)}.eml"));
                await using var entry = _zip.CreateEntry(path, CompressionLevel.NoCompression).Open();
                if (item.LimitedFidelity && item.Content is not null)
                {
                    await writeContent(entry).ConfigureAwait(false); // the stored MIME, exactly as backed up
                }
                else
                {
                    // Full-fidelity items are stored in Exchange's own export format; the EML is rebuilt from the stored headers and body.
                    var message = Message(meta, await readPreview().ConfigureAwait(false), item.PreviewType);
                    await message.WriteToAsync(entry).ConfigureAwait(false);
                    detail = "Exported from the stored headers and body; attachments are restored with a restore, not in EML.";
                }
                break;
            }
            case "event":
            {
                var subject = Text(meta, "subject");
                path = Unique(Join(item.RelativePath, $"{(string.IsNullOrWhiteSpace(subject) ? "(no subject)" : subject)} {Short(item.SourceId)}.ics"));
                await using var entry = _zip.CreateEntry(path, CompressionLevel.NoCompression).Open();
                var bytes = Encoding.UTF8.GetBytes(Calendar(item, meta, await readPreview().ConfigureAwait(false)));
                await entry.WriteAsync(bytes).ConfigureAwait(false);
                break;
            }
            case "contact":
            {
                var name = Text(meta, "subject");
                path = Unique(Join(item.RelativePath, $"{(string.IsNullOrWhiteSpace(name) ? "(no name)" : name)} {Short(item.SourceId)}.vcf"));
                await using var entry = _zip.CreateEntry(path, CompressionLevel.NoCompression).Open();
                await entry.WriteAsync(Encoding.UTF8.GetBytes(Card(meta))).ConfigureAwait(false);
                break;
            }
            default:
                state = "skipped";
                detail = "This item type is listed in manifest.json only.";
                break;
        }
        if (path is not null) Entries++;
        _manifest.Add(new { item_id = item.ItemId, source_id = item.SourceId, kind = item.Kind, path, state, detail, metadata = meta.Clone() });
        return new ExportEntry(item.ItemId, item.SourceId, item.Kind, path, state, detail);
    }

    /// <summary>Writes manifest.json and the zip directory. The output stream stays open.</summary>
    public async Task FinishAsync()
    {
        await using (var entry = _zip.CreateEntry("manifest.json", CompressionLevel.NoCompression).Open())
        {
            await JsonSerializer.SerializeAsync(entry, _manifest, new JsonSerializerOptions { WriteIndented = true }).ConfigureAwait(false);
        }
        _zip.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        _zip.Dispose();
        return ValueTask.CompletedTask;
    }

    /// <summary>One path segment that is safe on Windows, macOS and Linux.</summary>
    public static string SafeSegment(string? name)
    {
        var builder = new StringBuilder();
        foreach (var c in name ?? "")
        {
            builder.Append(c is '"' or '*' or ':' or '<' or '>' or '?' or '/' or '\\' or '|' || char.IsControl(c) ? '_' : c);
        }
        var result = builder.ToString().Trim().TrimEnd('.', ' ');
        if (result.Length > 120) result = result[..120].TrimEnd('.', ' ');
        return result.Length == 0 || result is "." or ".." ? "_" : result;
    }

    public static string Join(string relativePath, string name)
    {
        var segments = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(SafeSegment).Append(SafeSegment(name));
        return string.Join('/', segments);
    }

    private string Unique(string path)
    {
        if (_names.Add(path)) return path;
        var extension = System.IO.Path.GetExtension(path);
        var stem = path[..^extension.Length];
        for (var n = 2; ; n++)
        {
            var candidate = $"{stem} ({n.ToString(CultureInfo.InvariantCulture)}){extension}";
            if (_names.Add(candidate)) return candidate;
        }
    }

    private static string Versioned(string name, string? version)
    {
        var extension = System.IO.Path.GetExtension(name);
        var stem = extension.Length < name.Length ? name[..^extension.Length] : name;
        return $"{stem} (version {version ?? "older"}){extension}";
    }

    private static string Short(string sourceId) => $"[{Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(sourceId)))[..8]}]";

    private static string? Text(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static IEnumerable<string> List(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!) : [];

    private static DateTimeOffset? Date(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.TryGetDateTimeOffset(out var d) ? d : null;

    private static MimeMessage Message(JsonElement meta, string? body, string? bodyType)
    {
        var message = new MimeMessage { Subject = Text(meta, "subject") ?? "" };
        if (Text(meta, "from") is { } from && MailboxAddress.TryParse(from, out var sender)) message.From.Add(sender);
        foreach (var to in List(meta, "to"))
        {
            if (MailboxAddress.TryParse(to, out var address)) message.To.Add(address);
        }
        if ((Date(meta, "received") ?? Date(meta, "created")) is { } date) message.Date = date;
        var builder = new BodyBuilder();
        if (bodyType == "text/html") builder.HtmlBody = body ?? "";
        else builder.TextBody = body ?? Text(meta, "preview") ?? "";
        message.Body = builder.ToMessageBody();
        return message;
    }

    private static string Calendar(PendingItem item, JsonElement meta, string? body)
    {
        static string Escape(string? value) => (value ?? "").Replace("\\", "\\\\", StringComparison.Ordinal).Replace(";", "\\;", StringComparison.Ordinal)
            .Replace(",", "\\,", StringComparison.Ordinal).Replace("\r", "", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
        static string Stamp(DateTimeOffset value) => value.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var start = Date(meta, "start") ?? Date(meta, "received") ?? Date(meta, "created") ?? item.ModifiedAt;
        var end = Date(meta, "end") ?? start.AddHours(1);
        var text = new StringBuilder();
        text.Append("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Vaulty//Export//EN\r\nBEGIN:VEVENT\r\n");
        text.Append(CultureInfo.InvariantCulture, $"UID:{Escape(item.SourceId)}\r\nDTSTAMP:{Stamp(item.ModifiedAt)}\r\nDTSTART:{Stamp(start)}\r\nDTEND:{Stamp(end)}\r\n");
        text.Append(CultureInfo.InvariantCulture, $"SUMMARY:{Escape(Text(meta, "subject"))}\r\n");
        if (Text(meta, "from") is { } organizer) text.Append(CultureInfo.InvariantCulture, $"ORGANIZER:mailto:{Escape(organizer)}\r\n");
        foreach (var attendee in List(meta, "to")) text.Append(CultureInfo.InvariantCulture, $"ATTENDEE:mailto:{Escape(attendee)}\r\n");
        var description = body is null ? Text(meta, "preview") : System.Text.RegularExpressions.Regex.Replace(body, "<[^>]*>", " ");
        if (!string.IsNullOrWhiteSpace(description)) text.Append(CultureInfo.InvariantCulture, $"DESCRIPTION:{Escape(description.Trim())}\r\n");
        text.Append("END:VEVENT\r\nEND:VCALENDAR\r\n");
        return text.ToString();
    }

    private static string Card(JsonElement meta)
    {
        static string Escape(string? value) => (value ?? "").Replace("\\", "\\\\", StringComparison.Ordinal).Replace(";", "\\;", StringComparison.Ordinal)
            .Replace(",", "\\,", StringComparison.Ordinal).Replace("\r", "", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
        var text = new StringBuilder("BEGIN:VCARD\r\nVERSION:3.0\r\n");
        text.Append(CultureInfo.InvariantCulture, $"FN:{Escape(Text(meta, "subject"))}\r\n");
        foreach (var email in List(meta, "to")) text.Append(CultureInfo.InvariantCulture, $"EMAIL:{Escape(email)}\r\n");
        text.Append("END:VCARD\r\n");
        return text.ToString();
    }
}
