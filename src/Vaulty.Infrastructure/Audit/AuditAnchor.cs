using System.Text.Json;
using Dapper;
using Vaulty.Core.Abstractions;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Audit;

/// <summary>
/// The daily anchor of an organization's audit chain: the hash of the last event of the day, stored in the database and
/// as an immutable object. Anyone who rewrites the chain afterwards cannot make it match an anchor that is locked in
/// object storage.
/// </summary>
public static class AuditAnchor
{
    public static string ObjectKey(Guid organizationId, DateOnly date) =>
        $"organizations/{organizationId:D}/audit/anchors/{date:yyyy-MM-dd}.json";

    /// <summary>Writes the anchor for <paramref name="date"/> (UTC day). Returns false when the day had no events or was anchored.</summary>
    public static async Task<bool> WriteAsync(OrganizationSession session, IObjectStore store, DateOnly date, DateTimeOffset lockUntil,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(store);
        var exists = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT EXISTS (SELECT 1 FROM vaulty.audit_anchors WHERE organization_id = @org AND anchor_date = @date)",
            new { org = session.OrganizationId, date }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (exists) return false;

        var end = new DateTimeOffset(date.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero).AddDays(1);
        var last = await session.Connection.QuerySingleOrDefaultAsync<(long Seq, byte[] Hash)?>(new CommandDefinition(
            """
            SELECT seq, hash FROM vaulty.audit_events
             WHERE organization_id = @org AND occurred_at < @end ORDER BY seq DESC LIMIT 1
            """, new { org = session.OrganizationId, end }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (last is not { } anchor) return false;

        var key = ObjectKey(session.OrganizationId, date);
        var body = JsonSerializer.SerializeToUtf8Bytes(new
        {
            format = 1,
            organization_id = session.OrganizationId,
            date = date.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
            last_seq = anchor.Seq,
            hash = Convert.ToHexStringLower(anchor.Hash),
        });
        try
        {
            await store.PutAsync(key, new MemoryStream(body), new ObjectPutOptions(lockUntil), cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectAlreadyExistsException)
        {
            // Written by an earlier attempt that failed before the database row; the content is the same.
        }
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.audit_anchors (organization_id, anchor_date, last_seq, hash, object_key) VALUES (@org, @date, @seq, @hash, @key)",
            new { org = session.OrganizationId, date, seq = anchor.Seq, hash = anchor.Hash, key }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return true;
    }
}
