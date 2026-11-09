using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Dapper;
using Npgsql;
using Vaulty.Infrastructure.Database;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Backup;

/// <summary>
/// The chunk index of one tenant in PostgreSQL (tables packs and chunk_index). Entries are written in one transaction per
/// pack, after the pack and its index file are stored. Lookups that found a chunk are cached
/// for the lifetime of the index object (one backup activity).
/// </summary>
public sealed class PostgresChunkIndex(NpgsqlDataSource dataSource, Guid organizationId, Guid tenantId) : IChunkIndex
{
    private readonly ConcurrentDictionary<ChunkId, ChunkLocation> _known = new();

    public async ValueTask<ChunkLocation?> FindAsync(ChunkId id, CancellationToken cancellationToken = default)
    {
        if (_known.TryGetValue(id, out var cached)) return cached;
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<(Guid PackId, string ObjectKey, long Offset, int Length, int PlaintextLength)?>(
            new CommandDefinition(
                """
                SELECT c.pack_id, p.object_key, c."offset", c.length, c.plaintext_length
                  FROM vaulty.chunk_index c JOIN vaulty.packs p ON p.id = c.pack_id
                 WHERE c.tenant_id = @tenantId AND c.chunk_hash = @hash AND p.state <> 'deleted'
                """, new { tenantId, hash = id.Value }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (row is not { } r) return null;
        var location = new ChunkLocation(id, RepositoryLayout.PackHashFromKey(r.ObjectKey), r.Offset, r.Length, r.PlaintextLength);
        _known[id] = location;
        return location;
    }

    public async Task AddAsync(PackInfo pack, IReadOnlyList<ChunkLocation> entries, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pack);
        ArgumentNullException.ThrowIfNull(entries);
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var packId = await session.Connection.ExecuteScalarAsync<Guid>(new CommandDefinition(
            """
            INSERT INTO vaulty.packs (id, organization_id, tenant_id, object_key, size, sha256, state, lock_until)
            VALUES (@id, @organizationId, @tenantId, @key, @size, @sha, 'staged', @lockUntil)
            ON CONFLICT (object_key) DO UPDATE SET lock_until = greatest(vaulty.packs.lock_until, excluded.lock_until)
            RETURNING id
            """, new { id = Guid.CreateVersion7(), organizationId, tenantId, key = pack.ObjectKey, size = pack.Size, sha = pack.Sha256, lockUntil = pack.LockUntil },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);

        // One statement with arrays; a chunk another writer stored meanwhile is skipped.
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.chunk_index (organization_id, tenant_id, chunk_hash, pack_id, "offset", length, plaintext_length)
            SELECT @organizationId, @tenantId, h, @packId, o, l, p FROM unnest(@hashes, @offsets, @lengths, @plain) AS t(h, o, l, p)
            ON CONFLICT (tenant_id, chunk_hash) DO NOTHING
            """,
            new
            {
                organizationId, tenantId, packId, hashes = entries.Select(e => e.Id.Value).ToArray(), offsets = entries.Select(e => e.Offset).ToArray(),
                lengths = entries.Select(e => e.Length).ToArray(), plain = entries.Select(e => e.PlaintextLength).ToArray(),
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        foreach (var entry in entries) _known[entry.Id] = entry;
    }

    public async IAsyncEnumerable<string> PackHashesAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var keys = await session.Connection.QueryAsync<string>(new CommandDefinition(
            "SELECT object_key FROM vaulty.packs WHERE tenant_id = @tenantId AND state <> 'deleted'", new { tenantId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        foreach (var key in keys) yield return RepositoryLayout.PackHashFromKey(key);
    }
}
