using Dapper;
using Npgsql;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Backup;

/// <summary>
/// What a running backup expects to store, written once it has prepared: the jobs page turns it into a progress bar and an
/// estimate. Only a first backup knows its size beforehand; an incremental run learns its changes as it goes.
/// </summary>
public static class JobProgress
{
    public static async Task SetExpectedAsync(NpgsqlDataSource dataSource, Guid organizationId, Guid jobId, long? items, long? bytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        if (jobId == Guid.Empty || (items is null && bytes is null)) return;
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.jobs SET progress = progress || jsonb_strip_nulls(jsonb_build_object('expected_items', @items::bigint, 'expected_bytes', @bytes::bigint))
             WHERE id = @jobId AND state IN ('queued', 'running')
            """, new { jobId, items, bytes }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>True for the first backup of a protected object: its whole source is copied, so its size is the work.</summary>
    public static async Task<bool> IsFirstBackupAsync(NpgsqlDataSource dataSource, Guid organizationId, Guid objectId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT NOT EXISTS (SELECT 1 FROM vaulty.snapshots WHERE protected_object_id = @objectId AND state IN ('committed', 'partial'))",
            new { objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
