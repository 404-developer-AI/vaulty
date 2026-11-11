using Vaulty.Core.Domain;

namespace Vaulty.Web;

/// <summary>
/// How every state reads in the interface: one tone per state (amber for partial, red only for genuine failure) and one
/// label, so a job, a restore and a snapshot in the same state look the same everywhere.
/// </summary>
public static class StatusText
{
    public static string JobTone(string state) => state switch
    {
        "succeeded" => "succeeded",
        "partial" => "partial",
        "failed" => "failed",
        "running" or "queued" or "planning" => "running",
        _ => "neutral",
    };

    public static string JobLabel(string state) => state switch
    {
        "queued" => "Queued",
        "planning" => "Planning",
        "running" => "Running",
        "paused" => "Paused",
        "succeeded" => "Succeeded",
        "partial" => "Partial",
        "failed" => "Failed",
        "cancelled" => "Cancelled",
        _ => state.Length > 0 ? char.ToUpperInvariant(state[0]) + state[1..].Replace('_', ' ') : state,
    };

    public static string JobKind(string kind) => kind switch
    {
        "discovery" => "Discovery",
        "backup" => "Backup",
        "restore" => "Restore",
        "export" => "Export",
        "verification" => "Verification",
        _ => "Clean-up",
    };

    public static string AlertTone(string severity) => severity switch
    {
        "critical" => "failed",
        "warning" => "partial",
        _ => "info",
    };

    public static string AlertLabel(string severity) => severity switch
    {
        "critical" => "Critical",
        "warning" => "Warning",
        _ => "Info",
    };

    /// <summary>What the user does about a protection state: the second half of every status message.</summary>
    public static string NextStep(ProtectionStatus status, string reason, string consentState) => status switch
    {
        _ when consentState == "lost" => "Check the permissions on the tenant's Connection tab; correct the IDs or rotate the certificate if the check fails.",
        ProtectionStatus.Partial => "Review the skipped items and their reasons on the protected object. Exclude them in the policy or fix them at the source.",
        ProtectionStatus.Failed when reason.Contains("Verification", StringComparison.Ordinal) =>
            "Open the tenant's latest verification job for the affected data and contact support with its request ID.",
        ProtectionStatus.Failed when reason.Contains("first backup", StringComparison.Ordinal) =>
            "Start a backup now. If it fails again, the Jobs page shows the error.",
        ProtectionStatus.Failed => "Start a backup now and follow it on the Jobs page; its error says what to fix.",
        ProtectionStatus.NotRunYet => "Nothing to do: the first backup starts on schedule.",
        _ => "",
    };

    /// <summary>The kind of a protected object in plain words.</summary>
    public static string ObjectKind(string kind, string? subKind) => Browse.ObjectLabels.Kind(kind, subKind);

    public static string Number(long value) => value.ToString("N0", System.Globalization.CultureInfo.InvariantCulture);

    public static string Plural(long count, string one, string? many = null) => $"{Number(count)} {(count == 1 ? one : many ?? one + "s")}";
}
