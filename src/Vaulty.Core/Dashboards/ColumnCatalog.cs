namespace Vaulty.Core.Dashboards;

/// <param name="Required">Always shown: the name of what a row is and its status, so a layout can never hide a problem.</param>
/// <param name="Permission">Shown only to viewers holding it; the page loads its data only then.</param>
public sealed record ColumnInfo(string Key, string Name, string Description, bool Required = false, string? Permission = null);

/// <summary>
/// The columns each list can show, with stable keys. A column layout chooses which optional columns show and in which
/// order; the name and the status of a row always show. Layouts are linked to roles, never chosen per user.
/// </summary>
public static class ColumnCatalog
{
    public const string Customers = "customers";
    public const string Tenants = "tenants";
    public const string Objects = "objects";
    public const string Snapshots = "snapshots";
    public const string Jobs = "jobs";

    public static readonly IReadOnlyDictionary<string, (string Name, IReadOnlyList<ColumnInfo> Columns)> Lists =
        new Dictionary<string, (string, IReadOnlyList<ColumnInfo>)>(StringComparer.Ordinal)
        {
            [Customers] = ("Customers", [
                new("status", "Status", "The worst status of the customer's tenants.", Required: true),
                new("customer", "Customer", "Name and code.", Required: true),
                new("tags", "Tags", "The customer's tags."),
                new("tenants", "Tenants", "How many tenants are connected."),
                new("objects", "Protected objects", "How many protected objects per status."),
            ]),
            [Tenants] = ("Tenants of a customer", [
                new("tenant", "Tenant", "Name of the tenant.", Required: true),
                new("status", "Status", "The worst status of its protected objects.", Required: true),
                new("consent", "Consent", "Whether the app registration still has consent."),
                new("objects", "Protected objects", "How many protected objects."),
                new("checked", "Last permission check", "When Vaulty last checked the app's permissions."),
            ]),
            [Objects] = ("Protected objects of a tenant", [
                new("backup", "Back up", "Whether the object is backed up; switching it needs the permission to manage policies.",
                    Permission: Security.Permissions.PoliciesView),
                new("object", "Protected object", "Name and account.", Required: true),
                new("type", "Type", "Mailbox or OneDrive."),
                new("status", "Status", "Protection status with its reason.", Required: true),
                new("last_backup", "Last backup", "When the last snapshot finished."),
            ]),
            [Snapshots] = ("Snapshots of a protected object", [
                new("snapshot", "Snapshot", "When it was taken.", Required: true),
                new("status", "Status", "Succeeded, partial or failed.", Required: true),
                new("items", "Items", "The exact number of items."),
                new("verified", "Verified", "When the snapshot was last verified."),
            ]),
            [Jobs] = ("Jobs", [
                new("type", "Type", "Backup, restore, export or verification."),
                new("status", "Status", "How the job ended or that it runs.", Required: true),
                new("target", "Target", "What the job was for.", Required: true),
                new("started", "Started", "When it started."),
                new("finished", "Finished", "When it ended."),
                new("result", "Result", "Exact counts of the result."),
                new("request_id", "Request ID", "The id to give support."),
            ]),
        };

    public static IReadOnlyList<string> Default(string list) => Lists[list].Columns.Select(c => c.Key).ToList();

    public static ColumnInfo? Find(string list, string key) =>
        Lists.TryGetValue(list, out var entry) ? entry.Columns.FirstOrDefault(c => c.Key == key) : null;

    /// <summary>Problems of a layout in plain words; empty when it is valid.</summary>
    public static IReadOnlyList<string> Validate(string list, IReadOnlyList<string> columns)
    {
        ArgumentNullException.ThrowIfNull(columns);
        if (!Lists.TryGetValue(list, out var entry)) return [$"Unknown list \"{list}\"."];
        var problems = new List<string>();
        if (columns.Any(c => entry.Columns.All(k => k.Key != c))) problems.Add("A column is not one of this list.");
        if (columns.Distinct(StringComparer.Ordinal).Count() != columns.Count) problems.Add("A column is chosen twice.");
        foreach (var required in entry.Columns.Where(c => c.Required && !columns.Contains(c.Key))) problems.Add($"{required.Name} always shows.");
        return problems;
    }

    /// <summary>
    /// The columns to show: the layout's known columns in its order, without columns the viewer may not see, with every
    /// required column present (added in catalog order when a stored layout misses one).
    /// </summary>
    public static IReadOnlyList<string> Visible(string list, IReadOnlyList<string>? columns, Func<string, bool> has)
    {
        ArgumentNullException.ThrowIfNull(has);
        var entry = Lists[list];
        var chosen = (columns ?? Default(list)).Distinct(StringComparer.Ordinal)
            .Select(k => entry.Columns.FirstOrDefault(c => c.Key == k)).OfType<ColumnInfo>()
            .Where(c => c.Permission is null || has(c.Permission)).Select(c => c.Key).ToList();
        foreach (var required in entry.Columns.Where(c => c.Required && !chosen.Contains(c.Key)))
        {
            var index = entry.Columns.ToList().IndexOf(required);
            chosen.Insert(Math.Min(index, chosen.Count), required.Key);
        }
        return chosen;
    }
}
