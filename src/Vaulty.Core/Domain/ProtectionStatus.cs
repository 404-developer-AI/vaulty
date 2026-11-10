namespace Vaulty.Core.Domain;

/// <summary>
/// What the platform shows for a protected object, tenant or customer. Ordered from best to worst: a tenant takes the worst
/// state of its objects, a customer the worst of its tenants. Partial is amber and never counts as protected; failed is
/// reserved for genuine failure (no snapshot could be committed, a snapshot far too old, consent lost, verification failed).
/// </summary>
public enum ProtectionStatus
{
    Protected = 0,
    SourceDeleted = 1,
    Paused = 2,
    NotRunYet = 3,
    Partial = 4,
    Failed = 5,
}

public sealed record ProtectionInput(
    string ObjectState,
    string? LastSnapshotState,
    DateTimeOffset? LastSnapshotAt,
    int FrequencyMinutes,
    string ConsentState,
    bool VerificationFailed,
    bool LastRunFailed);

public static class Protection
{
    /// <summary>The state of one protected object, with the reason shown next to it.</summary>
    public static (ProtectionStatus Status, string Reason) Of(ProtectionInput input, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.ObjectState == "source_deleted") return (ProtectionStatus.SourceDeleted, "The source no longer exists in Microsoft 365; snapshots are kept.");
        if (input.ObjectState is "paused") return (ProtectionStatus.Paused, "Backups are paused.");
        if (input.ObjectState is "not_protected") return (ProtectionStatus.NotRunYet, "Not protected yet.");
        if (input.ConsentState == "lost") return (ProtectionStatus.Failed, "Vaulty lost access to the tenant; backups cannot run.");
        if (input.VerificationFailed) return (ProtectionStatus.Failed, "Verification found a problem in stored data.");
        if (input.LastSnapshotAt is not { } at)
        {
            return input.LastRunFailed
                ? (ProtectionStatus.Failed, "No snapshot could be committed yet.")
                : (ProtectionStatus.NotRunYet, "Not run yet.");
        }
        var age = now - at;
        if (age > TimeSpan.FromMinutes(2.0 * input.FrequencyMinutes))
        {
            return (ProtectionStatus.Failed, $"The latest snapshot is {Age(age)} old, more than twice the backup interval.");
        }
        if (input.LastRunFailed) return (ProtectionStatus.Failed, "The latest backup could not commit a snapshot.");
        if (input.LastSnapshotState == "partial") return (ProtectionStatus.Partial, "The latest snapshot is missing items; each has a reason.");
        return (ProtectionStatus.Protected, "");
    }

    public static ProtectionStatus Worst(IEnumerable<ProtectionStatus> states)
    {
        ArgumentNullException.ThrowIfNull(states);
        var worst = ProtectionStatus.Protected;
        var any = false;
        foreach (var s in states)
        {
            any = true;
            if (s > worst) worst = s;
        }
        return any ? worst : ProtectionStatus.NotRunYet;
    }

    /// <summary>The CSS class of the status chip: amber for partial, red only for failed, gray for the neutral states.</summary>
    public static string CssClass(ProtectionStatus status) => status switch
    {
        ProtectionStatus.Protected => "protected",
        ProtectionStatus.Partial => "partial",
        ProtectionStatus.Failed => "failed",
        _ => "neutral",
    };

    public static string Label(ProtectionStatus status) => status switch
    {
        ProtectionStatus.Protected => "Protected",
        ProtectionStatus.Partial => "Partial",
        ProtectionStatus.Failed => "Failed",
        ProtectionStatus.SourceDeleted => "Source deleted",
        ProtectionStatus.Paused => "Paused",
        _ => "Not run yet",
    };

    public static string Age(TimeSpan age) => age.TotalHours < 1 ? $"{Math.Max(1, (int)age.TotalMinutes)} min"
        : age.TotalDays < 2 ? $"{(int)age.TotalHours} h" : $"{(int)age.TotalDays} days";
}
