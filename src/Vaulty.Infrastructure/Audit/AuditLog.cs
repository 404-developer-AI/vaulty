using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Audit;

/// <summary>Writes audit events. The database fills in the hash chain; callers only describe what happened.</summary>
public static class AuditLog
{
    public static async Task<long> WriteAsync(OrganizationSession session, string actor, string action, string? target,
        object? details = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var json = details is null ? "{}" : details as string ?? JsonSerializer.Serialize(details);
        return await session.Connection.ExecuteScalarAsync<long>(new CommandDefinition(
            """
            INSERT INTO vaulty.audit_events (id, organization_id, actor, action, target, details)
            VALUES (@id, @org, @actor, @action, @target, @details::jsonb)
            RETURNING seq
            """,
            new { id = Guid.CreateVersion7(), org = session.OrganizationId, actor, action, target, details = json },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}

/// <summary>Result of verifying an organization's audit chain.</summary>
public sealed record AuditChainResult(bool Valid, long EventsChecked, long? FirstBrokenSeq, byte[]? LastHash);

/// <summary>
/// Recomputes the audit hash chain outside the database, so a tampered row (or a database that computes hashes
/// differently) is detected. The canonical form matches <c>vaulty.audit_canonical</c> in the schema.
/// </summary>
public static class AuditChainVerifier
{
    public static readonly byte[] Genesis = new byte[32];
    private const char Separator = '\u001f';

    public static string Canonical(Guid id, Guid organizationId, DateTimeOffset occurredAt, string actor, string action,
        string? target, string detailsJson)
    {
        var micros = (occurredAt.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;
        return string.Join(Separator, "vaulty-audit-v1", id.ToString(), organizationId.ToString(),
            micros.ToString(System.Globalization.CultureInfo.InvariantCulture), actor, action, target ?? string.Empty,
            detailsJson);
    }

    public static byte[] Hash(ReadOnlySpan<byte> previous, string canonical)
    {
        var text = Encoding.UTF8.GetBytes(canonical);
        var buffer = new byte[previous.Length + text.Length];
        previous.CopyTo(buffer);
        text.CopyTo(buffer.AsSpan(previous.Length));
        return SHA256.HashData(buffer);
    }

    public static async Task<AuditChainResult> VerifyAsync(OrganizationSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        await using var command = new NpgsqlCommand(
            """
            SELECT seq, id, organization_id, occurred_at, actor, action, target, details::text, prev_hash, hash
              FROM vaulty.audit_events WHERE organization_id = @org ORDER BY seq
            """, session.Connection, session.Transaction);
        command.Parameters.AddWithValue("org", session.OrganizationId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        var previous = Genesis;
        long count = 0;
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var seq = reader.GetInt64(0);
            var canonical = Canonical(reader.GetGuid(1), reader.GetGuid(2),
                new DateTimeOffset(reader.GetDateTime(3), TimeSpan.Zero), reader.GetString(4), reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6), reader.GetString(7));
            var storedPrevious = (byte[])reader[8];
            var storedHash = (byte[])reader[9];
            var expected = Hash(previous, canonical);
            if (!storedPrevious.AsSpan().SequenceEqual(previous) || !storedHash.AsSpan().SequenceEqual(expected))
            {
                return new AuditChainResult(false, count, seq, previous);
            }
            previous = storedHash;
            count++;
        }
        return new AuditChainResult(true, count, null, previous);
    }
}
