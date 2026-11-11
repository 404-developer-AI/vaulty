namespace Vaulty.Core.Security;

/// <summary>One permission a role can hold.</summary>
/// <param name="Key">Stable key stored in the database; never renamed once released.</param>
/// <param name="Group">Heading the role editor shows it under.</param>
/// <param name="Label">Short name shown in the UI.</param>
/// <param name="Description">What the permission allows.</param>
/// <param name="Requires">Permissions a role must hold as well, so a role cannot change what it cannot see.</param>
/// <param name="RequiresMfa">Only a user with a second factor (passkey or authenticator app) can hold it.</param>
/// <param name="RequiresStepUp">Every use asks the user to confirm it's them.</param>
public sealed record PermissionInfo(
    string Key,
    string Group,
    string Label,
    string Description,
    IReadOnlyList<string> Requires,
    bool RequiresMfa = false,
    bool RequiresStepUp = false)
{
    /// <summary>Administration of the organization as a whole; never limited to customers.</summary>
    public bool OrganizationWide => Group == Permissions.AdministrationGroup;
}

/// <summary>
/// The catalog of everything a role can allow. This is the only list of permissions: a role holds exactly the keys stored
/// for it, and a permission can be limited to customers by the role assignment. Keys are stored, so they never change.
/// </summary>
public static class Permissions
{
    public const string CustomersGroup = "Customers and tenants";
    public const string BackupGroup = "Backups";
    public const string RestoreGroup = "Restores and exports";
    public const string ReportingGroup = "Reporting";
    public const string AdministrationGroup = "Administration";

    public const string CustomersView = "customers.view";
    public const string CustomersManage = "customers.manage";
    public const string CustomersDelete = "customers.delete";
    public const string TenantsConnect = "tenants.connect";
    public const string TenantsDelete = "tenants.delete";

    public const string PoliciesView = "policies.view";
    public const string PoliciesManage = "policies.manage";
    public const string RetentionManage = "retention.manage";
    public const string LegalHoldManage = "legalhold.manage";
    public const string BackupsRun = "backups.run";
    public const string SnapshotsBrowse = "snapshots.browse";

    public const string RestoreInPlace = "restore.inplace";
    public const string RestoreOtherLocation = "restore.otherlocation";
    public const string ExportCreate = "export.create";

    public const string JobsView = "jobs.view";
    public const string JobsCancel = "jobs.cancel";
    public const string ReportsView = "reports.view";
    public const string AuditView = "audit.view";

    public const string UsersManage = "users.manage";
    public const string RolesManage = "roles.manage";
    public const string SettingsManage = "settings.manage";
    public const string StorageManage = "storage.manage";
    public const string SignInManage = "signin.manage";

    public static readonly IReadOnlyList<PermissionInfo> All =
    [
        new(CustomersView, CustomersGroup, "View customers and tenants",
            "Customers, their tenants, protected objects and their status.", []),
        new(CustomersManage, CustomersGroup, "Manage customers", "Create and edit customers and their tags.", [CustomersView]),
        new(CustomersDelete, CustomersGroup, "Delete customers",
            "Request the deletion of a customer; a second administrator confirms after 30 days.", [CustomersView],
            RequiresMfa: true, RequiresStepUp: true),
        new(TenantsConnect, CustomersGroup, "Connect tenants",
            "Connect and disconnect tenants, rotate their certificate and run discovery.", [CustomersView],
            RequiresMfa: true, RequiresStepUp: true),
        new(TenantsDelete, CustomersGroup, "Delete tenants",
            "Request the deletion of a tenant; a second administrator confirms after 30 days.", [CustomersView],
            RequiresMfa: true, RequiresStepUp: true),

        new(PoliciesView, BackupGroup, "View policies", "Scope, frequency and retention of every policy.", [CustomersView]),
        new(PoliciesManage, BackupGroup, "Manage policies", "Create and edit policies and exclusions.", [PoliciesView]),
        new(RetentionManage, BackupGroup, "Change retention", "Change the retention of a policy.", [PoliciesView],
            RequiresMfa: true, RequiresStepUp: true),
        new(LegalHoldManage, BackupGroup, "Manage legal hold",
            "Place a protected object or tenant on legal hold, or release the hold.", [PoliciesView],
            RequiresMfa: true, RequiresStepUp: true),
        new(BackupsRun, BackupGroup, "Back up now", "Start a backup outside the policy schedule.", [CustomersView]),
        new(SnapshotsBrowse, BackupGroup, "Browse snapshots",
            "Browse and search snapshots and preview items.", [CustomersView], RequiresMfa: true),

        new(RestoreInPlace, RestoreGroup, "Restore in place",
            "Restore items to their original mailbox or drive.", [SnapshotsBrowse], RequiresMfa: true),
        new(RestoreOtherLocation, RestoreGroup, "Restore to another location",
            "Restore items to another mailbox, drive or folder.", [SnapshotsBrowse], RequiresMfa: true,
            RequiresStepUp: true),
        new(ExportCreate, RestoreGroup, "Export", "Export items and download the export.", [SnapshotsBrowse],
            RequiresMfa: true, RequiresStepUp: true),

        new(JobsView, ReportingGroup, "View jobs", "Backups, restores, exports and verifications with their results.",
            [CustomersView]),
        new(JobsCancel, ReportingGroup, "Cancel jobs", "Pause or cancel a running restore or export.", [JobsView]),
        new(ReportsView, ReportingGroup, "View reports", "Dashboard, tenant health and digests.", [CustomersView]),
        new(AuditView, ReportingGroup, "View audit log", "The audit log of the organization.", []),

        new(UsersManage, AdministrationGroup, "Manage users", "Invite, disable and reset users.", [],
            RequiresMfa: true, RequiresStepUp: true),
        new(RolesManage, AdministrationGroup, "Manage roles", "Create roles and assign them to users.", [],
            RequiresMfa: true, RequiresStepUp: true),
        new(SettingsManage, AdministrationGroup, "Manage settings", "SMTP, webhooks and other organization settings.", [],
            RequiresMfa: true, RequiresStepUp: true),
        new(StorageManage, AdministrationGroup, "Manage storage",
            "Configure the object storage account and rotate its keys.", [], RequiresMfa: true, RequiresStepUp: true),
        new(SignInManage, AdministrationGroup, "Manage sign-in",
            "Set up sign-in with Microsoft, link users to their Microsoft account and choose who handles the second factor.", [],
            RequiresMfa: true, RequiresStepUp: true),
    ];

    private static readonly Dictionary<string, PermissionInfo> ByKey = All.ToDictionary(p => p.Key, StringComparer.Ordinal);

    public static bool Exists(string key) => ByKey.ContainsKey(key);

    public static PermissionInfo Get(string key) =>
        ByKey.TryGetValue(key, out var info) ? info : throw new KeyNotFoundException($"Unknown permission '{key}'.");

    /// <summary>The permissions plus everything they require, transitively.</summary>
    public static IReadOnlySet<string> Closure(IEnumerable<string> keys)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        var stack = new Stack<string>(keys);
        while (stack.TryPop(out var key))
        {
            if (!result.Add(key)) continue;
            foreach (var required in Get(key).Requires) stack.Push(required);
        }
        return result;
    }

    /// <summary>True when holding these permissions needs a second factor.</summary>
    public static bool AnyRequiresMfa(IEnumerable<string> keys) => keys.Any(k => Get(k).RequiresMfa);
}

/// <summary>The default roles every organization starts with.</summary>
public static class BuiltInRoles
{
    public const string OrganizationAdmin = "Organization admin";
    public const string BackupOperator = "Backup operator";
    public const string RestoreOperator = "Restore operator";
    public const string ReadOnly = "Read-only";

    public static readonly IReadOnlyList<string> ReadOnlyPermissions =
    [
        Permissions.CustomersView, Permissions.PoliciesView, Permissions.JobsView, Permissions.ReportsView,
        Permissions.AuditView,
    ];

    public static readonly IReadOnlyList<string> RestoreOperatorPermissions =
    [
        Permissions.CustomersView, Permissions.SnapshotsBrowse, Permissions.RestoreInPlace,
        Permissions.RestoreOtherLocation, Permissions.ExportCreate, Permissions.JobsView, Permissions.JobsCancel,
    ];

    public static readonly IReadOnlyList<string> BackupOperatorPermissions =
    [
        .. ReadOnlyPermissions,
        Permissions.CustomersManage, Permissions.TenantsConnect, Permissions.PoliciesManage, Permissions.BackupsRun,
        Permissions.SnapshotsBrowse, Permissions.RestoreInPlace, Permissions.ExportCreate, Permissions.JobsCancel,
    ];

    public static readonly IReadOnlyList<string> OrganizationAdminPermissions = [.. Permissions.All.Select(p => p.Key)];

    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> All =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            [OrganizationAdmin] = OrganizationAdminPermissions,
            [BackupOperator] = BackupOperatorPermissions,
            [RestoreOperator] = RestoreOperatorPermissions,
            [ReadOnly] = ReadOnlyPermissions,
        };
}
