namespace Vaulty.Core.Domain;

/// <summary>
/// How many backups of one kind run at the same time for one tenant, so one large tenant never fills every worker. A
/// protected object waiting for a free place within this budget is queued, not missed.
/// </summary>
public static class BackupBudget
{
    public const int MailboxesPerTenant = 20;
    public const int DrivesPerTenant = 10;

    public static int For(string kind) => kind == "drive" ? DrivesPerTenant : MailboxesPerTenant;
}
