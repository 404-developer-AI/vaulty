using System.Globalization;

namespace Vaulty.Web.Browse;

/// <summary>Names of protected object and item types, and exact counts, as the interface writes them.</summary>
public static class ObjectLabels
{
    public static string Kind(string kind, string? subKind) => (kind, subKind) switch
    {
        ("mailbox", "shared") => "Shared mailbox",
        ("mailbox", "room" or "equipment") => "Resource mailbox",
        ("mailbox", "archive") => "Archive mailbox",
        ("mailbox", _) => "Mailbox",
        ("drive", _) => "OneDrive",
        ("site", _) => "Site",
        ("team", _) => "Team",
        _ => kind,
    };

    public static string Item(string kind) => kind switch
    {
        "mail" => "Message",
        "event" => "Event",
        "contact" => "Contact",
        "task" => "Task",
        "file" => "File",
        "file_version" => "Version",
        "package" => "Notebook",
        "folder" => "Folder",
        _ => "Item",
    };

    /// <summary>"4,982 messages, 12 events" from the snapshot's counts, without the totals and folders.</summary>
    public static string Counts(IReadOnlyDictionary<string, long> counts)
    {
        var parts = counts.Where(c => c.Key is not ("items" or "folders" or "exceptions") && c.Value > 0)
            .OrderByDescending(c => c.Value)
            .Select(c => $"{c.Value.ToString("N0", CultureInfo.InvariantCulture)} {Plural(c.Key, c.Value)}");
        var text = string.Join(", ", parts);
        return text.Length > 0 ? text : $"{counts.GetValueOrDefault("items").ToString("N0", CultureInfo.InvariantCulture)} items";
    }

    private static string Plural(string kind, long count)
    {
        var word = kind switch
        {
            "mail" => "message",
            "file_version" => "older version",
            "package" => "notebook",
            _ => kind,
        };
        return count == 1 ? word : word + "s";
    }

    /// <summary>Why an item is missing from a snapshot, in plain words.</summary>
    public static string ExceptionReason(string code) => code switch
    {
        "too_large" => "Too large to back up",
        "hash_mismatch" => "Content did not match its checksum",
        "count_mismatch" => "Item count differs from Microsoft 365",
        "corrupt" => "Unreadable at the source",
        "not_found" => "Gone from the source during the backup",
        "cancelled" => "The backup was cancelled",
        "failed" => "The backup stopped",
        _ => "Could not be backed up",
    };

    /// <summary>What to do about a missing item, by reason.</summary>
    public static string ExceptionAdvice(string code) => code switch
    {
        "too_large" => "Microsoft Graph cannot download it. Keep it elsewhere or exclude its folder in the policy.",
        "hash_mismatch" or "corrupt" => "Vaulty tries again once a day. If it stays, check the item in Microsoft 365.",
        "count_mismatch" => "Usually items that changed during the backup; the next backup normally includes them.",
        "cancelled" or "failed" => "The next backup picks up where this one stopped.",
        _ => "Vaulty tries again once a day; the next snapshot shows whether it worked.",
    };

    public static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F0} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1024.0 / 1024:F1} MB",
        _ => $"{bytes / 1024.0 / 1024 / 1024:F1} GB",
    };
}
