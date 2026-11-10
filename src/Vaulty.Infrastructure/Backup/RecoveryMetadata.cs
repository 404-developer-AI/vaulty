using System.Globalization;
using System.Text;
using System.Text.Json;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Backup;

/// <summary>
/// What the database knows about an item version beyond its metadata, embedded in the sealed metadata under the reserved
/// key <c>_vaulty</c>, so object storage alone holds everything a restore or export needs (the recovery guarantee): the
/// reference to the separately stored preview (the body of a message), whether the content is a limited-fidelity MIME copy,
/// and the modification time. The key is removed again wherever metadata is shown or exported.
/// </summary>
public static class RecoveryMetadata
{
    public const string Key = "_vaulty";

    public sealed record Values(ItemContent? Preview, string? PreviewType, bool LimitedFidelity, DateTimeOffset? ModifiedAt);

    public static string Embed(string metadataJson, ItemContent? preview, string? previewType, bool limitedFidelity, DateTimeOffset? modifiedAt)
    {
        ArgumentNullException.ThrowIfNull(metadataJson);
        using var document = JsonDocument.Parse(metadataJson);
        if (document.RootElement.ValueKind != JsonValueKind.Object) return metadataJson;
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var property in document.RootElement.EnumerateObject().Where(p => p.Name != Key)) property.WriteTo(writer);
            writer.WriteStartObject(Key);
            if (modifiedAt is { } at) writer.WriteString("modified_at", at.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            if (limitedFidelity) writer.WriteBoolean("limited_fidelity", true);
            if (preview is not null)
            {
                writer.WriteStartObject("preview");
                writer.WriteNumber("size", preview.Size);
                writer.WriteString("hash", preview.ContentHashHex);
                if (previewType is not null) writer.WriteString("type", previewType);
                writer.WriteStartArray("chunks");
                foreach (var chunk in preview.Chunks) writer.WriteStringValue(Convert.ToHexStringLower(chunk.Value));
                writer.WriteEndArray();
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    public static Values Read(JsonElement metadata)
    {
        if (metadata.ValueKind != JsonValueKind.Object || !metadata.TryGetProperty(Key, out var v) || v.ValueKind != JsonValueKind.Object)
        {
            return new Values(null, null, false, null);
        }
        DateTimeOffset? modified = v.TryGetProperty("modified_at", out var m) && m.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(m.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;
        var limited = v.TryGetProperty("limited_fidelity", out var l) && l.ValueKind == JsonValueKind.True;
        ItemContent? preview = null;
        string? type = null;
        if (v.TryGetProperty("preview", out var p) && p.ValueKind == JsonValueKind.Object)
        {
            var chunks = p.GetProperty("chunks").EnumerateArray().Select(c => new ChunkId(Convert.FromHexString(c.GetString()!))).ToList();
            preview = new ItemContent(p.GetProperty("size").GetInt64(), Convert.FromHexString(p.GetProperty("hash").GetString()!), chunks);
            type = p.TryGetProperty("type", out var t) ? t.GetString() : null;
        }
        return new Values(preview, type, limited, modified);
    }

    /// <summary>The metadata without the reserved key, as shown to users and written into export manifests.</summary>
    public static JsonElement Strip(JsonElement metadata)
    {
        if (metadata.ValueKind != JsonValueKind.Object || !metadata.TryGetProperty(Key, out _)) return metadata.Clone();
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var property in metadata.EnumerateObject().Where(p => p.Name != Key)) property.WriteTo(writer);
            writer.WriteEndObject();
        }
        using var document = JsonDocument.Parse(buffer.ToArray());
        return document.RootElement.Clone();
    }
}
