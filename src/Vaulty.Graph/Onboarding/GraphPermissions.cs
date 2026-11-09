using Vaulty.Graph.Auth;
using Vaulty.Graph.Http;

namespace Vaulty.Graph.Onboarding;

/// <summary>One Microsoft Graph application permission Vaulty requests, and what it is for.</summary>
public sealed record GraphPermission(string Name, string Workload, bool ForRestore, string Purpose);

/// <summary>
/// The application permissions of the dedicated app (names checked against Microsoft Learn, November 2026: exportItems in
/// v1.0 needs MailboxItem.Export.All, import needs MailboxItem.ImportExport.All). Read permissions back up; write
/// permissions are only needed for restores.
/// </summary>
public static class GraphPermissions
{
    public static readonly IReadOnlyList<GraphPermission> All =
    [
        new("User.Read.All", "Directory", false, "Find users, shared and resource mailboxes, and OneDrives"),
        new("Group.Read.All", "Directory", false, "Find groups and their members"),
        new("Organization.Read.All", "Directory", false, "Read the tenant name and verified domains"),
        new("MailboxSettings.Read", "Exchange", false, "Read mailbox type, archive state and settings"),
        new("MailboxFolder.Read.All", "Exchange", false, "List the folders of a mailbox (mail, calendar, contacts, tasks)"),
        new("MailboxItem.Read.All", "Exchange", false, "Track new, changed and deleted items per folder (delta)"),
        new("MailboxItem.Export.All", "Exchange", false, "Export mailbox items in full fidelity"),
        new("Mail.Read", "Exchange", false, "Read mail folders and message metadata (delta)"),
        new("Calendars.Read", "Exchange", false, "Read calendars and events (delta)"),
        new("Contacts.Read", "Exchange", false, "Read contacts (delta)"),
        new("Tasks.Read.All", "Exchange", false, "Read tasks"),
        new("Files.Read.All", "OneDrive", false, "Read drives, files and versions"),
        new("MailboxItem.ImportExport.All", "Exchange", true, "Import mailbox items (restore)"),
        new("MailboxFolder.ReadWrite.All", "Exchange", true, "Create restore folders"),
        new("Mail.ReadWrite", "Exchange", true, "Create restore folders"),
        new("Calendars.ReadWrite", "Exchange", true, "Restore calendar items"),
        new("Contacts.ReadWrite", "Exchange", true, "Restore contacts"),
        new("Tasks.ReadWrite.All", "Exchange", true, "Restore tasks"),
        new("Files.ReadWrite.All", "OneDrive", true, "Restore files"),
    ];

    /// <summary>A granted permission that includes another (a ReadWrite permission includes its Read counterpart).</summary>
    private static readonly Dictionary<string, string[]> Implied = new(StringComparer.Ordinal)
    {
        ["MailboxItem.ImportExport.All"] = ["MailboxItem.Export.All"],
        ["MailboxItem.ReadWrite.All"] = ["MailboxItem.Read.All"],
        ["MailboxFolder.ReadWrite.All"] = ["MailboxFolder.Read.All"],
        ["Mail.ReadWrite"] = ["Mail.Read"],
        ["Calendars.ReadWrite"] = ["Calendars.Read"],
        ["Contacts.ReadWrite"] = ["Contacts.Read"],
        ["Tasks.ReadWrite.All"] = ["Tasks.Read.All"],
        ["Files.ReadWrite.All"] = ["Files.Read.All"],
        ["MailboxSettings.ReadWrite"] = ["MailboxSettings.Read"],
        ["User.ReadWrite.All"] = ["User.Read.All"],
        ["Directory.Read.All"] = ["User.Read.All", "Group.Read.All", "Organization.Read.All"],
    };

    public static ISet<string> Effective(IEnumerable<string> granted)
    {
        var result = new HashSet<string>(granted, StringComparer.Ordinal);
        foreach (var name in result.ToList())
        {
            if (Implied.TryGetValue(name, out var implied)) result.UnionWith(implied);
        }
        return result;
    }
}

public enum ProbeStatus
{
    Present,
    Missing,
}

public sealed record PermissionProbeLine(GraphPermission Permission, ProbeStatus Status);

public sealed record PermissionCheck(string Name, bool Passed, string Detail);

/// <summary>Result of probing a tenant: per permission present or missing, plus live calls that prove access works.</summary>
public sealed record PermissionProbeReport(IReadOnlyList<PermissionProbeLine> Permissions, IReadOnlyList<PermissionCheck> Checks)
{
    public bool BackupReady => Permissions.Where(p => !p.Permission.ForRestore).All(p => p.Status == ProbeStatus.Present) && Checks.All(c => c.Passed);
    public bool RestoreReady => BackupReady && Permissions.Where(p => p.Permission.ForRestore).All(p => p.Status == ProbeStatus.Present);
    public IEnumerable<string> Missing => Permissions.Where(p => p.Status == ProbeStatus.Missing).Select(p => p.Permission.Name);

    /// <summary>A readable report, one line per permission.</summary>
    public string ToText()
    {
        var lines = Permissions.Select(p =>
            $"{(p.Status == ProbeStatus.Present ? "present" : "missing"),-8} {p.Permission.Name,-30} {(p.Permission.ForRestore ? "restore" : "backup"),-8} {p.Permission.Purpose}");
        var checks = Checks.Select(c => $"{(c.Passed ? "ok" : "failed"),-8} {c.Name}: {c.Detail}");
        return string.Join('\n', lines.Concat(checks));
    }
}

/// <summary>Probes the app's permissions in a tenant: the roles in its app-only token, then a cheap call per workload.</summary>
public sealed class PermissionProbe(IGraphTokenProvider tokens, GraphClient graph)
{
    public async Task<PermissionProbeReport> ProbeAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        var token = await tokens.GetTokenAsync(tenantId, forceRefresh: true, cancellationToken).ConfigureAwait(false);
        var granted = GraphPermissions.Effective(token.Roles);
        var lines = GraphPermissions.All
            .Select(p => new PermissionProbeLine(p, granted.Contains(p.Name) ? ProbeStatus.Present : ProbeStatus.Missing)).ToList();

        var context = new GraphRequestContext(tenantId, Workload: "probe");
        var checks = new List<PermissionCheck>
        {
            await CheckAsync("Read the organization", () => graph.GetAsync(context, "organization?$select=id,displayName",
                GraphJson.Default.GraphCollectionGraphOrganization, null, cancellationToken)).ConfigureAwait(false),
            await CheckAsync("List users", () => graph.GetAsync(context, "users?$top=1&$select=id",
                GraphJson.Default.GraphCollectionGraphUser, null, cancellationToken)).ConfigureAwait(false),
        };
        return new PermissionProbeReport(lines, checks);
    }

    private static async Task<PermissionCheck> CheckAsync<T>(string name, Func<Task<T>> call)
    {
        try
        {
            await call().ConfigureAwait(false);
            return new PermissionCheck(name, true, "works");
        }
        catch (GraphException ex)
        {
            return new PermissionCheck(name, false, $"{(int)ex.Status} {ex.Code} (request-id {ex.RequestId})");
        }
    }
}
