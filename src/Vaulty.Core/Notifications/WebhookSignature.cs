using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Vaulty.Core.Notifications;

/// <summary>
/// Webhook signatures. Every delivery carries <c>Vaulty-Signature: t=&lt;unix seconds&gt;,v1=&lt;hex&gt;</c>, where v1 is
/// HMAC-SHA256 with the webhook's secret over <c>"&lt;t&gt;." + body</c>. A receiver recomputes it over the raw body, compares in
/// constant time, rejects a timestamp outside its tolerance (five minutes by default) and remembers the
/// <c>Vaulty-Delivery</c> id to drop a replayed delivery. During a secret rotation the header holds one v1 per secret.
/// </summary>
public static class WebhookSignature
{
    public const string SignatureHeader = "Vaulty-Signature";
    public const string DeliveryHeader = "Vaulty-Delivery";
    public const string EventHeader = "Vaulty-Event";
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromMinutes(5);

    public static string Sign(ReadOnlySpan<byte> secret, long timestamp, ReadOnlySpan<byte> body) =>
        $"t={timestamp.ToString(CultureInfo.InvariantCulture)},v1={Convert.ToHexStringLower(Mac(secret, timestamp, body))}";

    /// <summary>True when the header is well formed, its timestamp lies within <paramref name="tolerance"/> of now and one v1 matches.</summary>
    public static bool Verify(ReadOnlySpan<byte> secret, string? header, ReadOnlySpan<byte> body, DateTimeOffset now, TimeSpan? tolerance = null)
    {
        if (string.IsNullOrWhiteSpace(header)) return false;
        long? timestamp = null;
        var candidates = new List<byte[]>();
        foreach (var part in header.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0) return false;
            var (key, value) = (part[..eq], part[(eq + 1)..]);
            if (key == "t" && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var t)) timestamp = t;
            else if (key == "v1" && value.Length == 64)
            {
                try
                {
                    candidates.Add(Convert.FromHexString(value));
                }
                catch (FormatException)
                {
                    return false;
                }
            }
        }
        if (timestamp is not { } ts || candidates.Count == 0) return false;
        var age = now - DateTimeOffset.FromUnixTimeSeconds(ts);
        if (age.Duration() > (tolerance ?? DefaultTolerance)) return false;
        var expected = Mac(secret, ts, body);
        var match = false;
        foreach (var candidate in candidates) match |= CryptographicOperations.FixedTimeEquals(candidate, expected);
        return match;
    }

    private static byte[] Mac(ReadOnlySpan<byte> secret, long timestamp, ReadOnlySpan<byte> body)
    {
        var prefix = Encoding.ASCII.GetBytes(timestamp.ToString(CultureInfo.InvariantCulture) + ".");
        var data = new byte[prefix.Length + body.Length];
        prefix.CopyTo(data, 0);
        body.CopyTo(data.AsSpan(prefix.Length));
        return HMACSHA256.HashData(secret, data);
    }
}

/// <summary>The events a webhook can subscribe to.</summary>
public static class NotificationKinds
{
    public const string BackupFailed = "backup.failed";
    public const string BackupPartial = "backup.partial";
    public const string BackupMissed = "backup.missed";
    public const string BackupDrift = "backup.drift";
    public const string ConsentLost = "tenant.consent_lost";
    public const string VerificationFailed = "verification.failed";
    public const string RestoreCompleted = "restore.completed";
    public const string TenantDeletionPending = "tenant.deletion_pending";

    public static readonly IReadOnlyList<(string Kind, string Description)> All =
    [
        (BackupFailed, "A backup could not commit a snapshot"),
        (BackupPartial, "A snapshot was committed with missing items"),
        (BackupMissed, "A scheduled backup did not start"),
        (BackupDrift, "A snapshot holds far fewer items than the previous one"),
        (ConsentLost, "Vaulty lost access to a tenant"),
        (VerificationFailed, "Verification found a problem in stored data"),
        (RestoreCompleted, "A restore or export finished"),
        (TenantDeletionPending, "Deletion of a tenant was requested"),
    ];

    public static bool Exists(string kind) => All.Any(k => k.Kind == kind);
}
