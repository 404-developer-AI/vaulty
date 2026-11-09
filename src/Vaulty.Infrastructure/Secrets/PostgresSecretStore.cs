using System.Collections.Concurrent;
using System.Security.Cryptography;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Crypto;

namespace Vaulty.Infrastructure.Secrets;

/// <summary>
/// <see cref="ISecretStore"/> on the <c>secrets</c> table. Values are sealed with <see cref="SecretCipher"/> (bound to
/// name, version and host) and cached in memory for a short time; the cache holds sealed rows, never plain values.
/// </summary>
public sealed class PostgresSecretStore(NpgsqlDataSource dataSource, SecretCipher cipher, TimeProvider clock,
    TimeSpan? cacheDuration = null) : ISecretStore
{
    private readonly TimeSpan _ttl = cacheDuration ?? TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<string, (DateTimeOffset At, SecretRow? Row)> _cache = new(StringComparer.Ordinal);

    internal sealed record SecretRow(string Name, int Version, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

    public async Task<Secret?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        var now = clock.GetUtcNow();
        if (!_cache.TryGetValue(name, out var cached) || now - cached.At > _ttl)
        {
            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            var row = await connection.QuerySingleOrDefaultAsync<SecretRow>(new CommandDefinition(
                "SELECT name, version, nonce, ciphertext, tag FROM vaulty.secrets WHERE name = @name ORDER BY version DESC LIMIT 1",
                new { name }, cancellationToken: cancellationToken)).ConfigureAwait(false);
            cached = (now, row);
            _cache[name] = cached;
        }
        return cached.Row is null ? null : Open(cached.Row);
    }

    public async Task<Secret?> GetAsync(string name, int version, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var row = await connection.QuerySingleOrDefaultAsync<SecretRow>(new CommandDefinition(
            "SELECT name, version, nonce, ciphertext, tag FROM vaulty.secrets WHERE name = @name AND version = @version",
            new { name, version }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row is null ? null : Open(row);
    }

    public async Task<int> SetAsync(string name, ReadOnlyMemory<byte> value, string actor, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        // Serialize writers of the same name so versions never collide.
        await connection.ExecuteAsync(new CommandDefinition("SELECT pg_advisory_xact_lock(hashtextextended('vaulty.secret:' || @name, 0))",
            new { name }, transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var version = 1 + await connection.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT coalesce(max(version), 0) FROM vaulty.secrets WHERE name = @name", new { name }, transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        var sealedSecret = cipher.Seal(name, version, value.Span);
        await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.secrets SET rotated_at = now() WHERE name = @name AND rotated_at IS NULL;
            INSERT INTO vaulty.secrets (name, version, nonce, ciphertext, tag, created_by)
            VALUES (@name, @version, @nonce, @ciphertext, @tag, @actor)
            """,
            new { name, version, nonce = sealedSecret.Nonce, ciphertext = sealedSecret.Ciphertext, tag = sealedSecret.Tag, actor },
            transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        _cache.TryRemove(name, out _);
        return version;
    }

    public async Task<int> PruneAsync(string name, int keep, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(keep, 1);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var removed = await connection.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM vaulty.secrets WHERE name = @name AND version NOT IN
                (SELECT version FROM vaulty.secrets WHERE name = @name ORDER BY version DESC LIMIT @keep)
            """, new { name, keep }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        _cache.TryRemove(name, out _);
        return removed;
    }

    public async Task<IReadOnlyList<SecretInfo>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<(string Name, int Version, DateTime CreatedAt, string CreatedBy)>(new CommandDefinition(
            "SELECT name, version, created_at, created_by FROM vaulty.secrets ORDER BY name, version",
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new SecretInfo(r.Name, r.Version, new DateTimeOffset(r.CreatedAt, TimeSpan.Zero), r.CreatedBy)).ToList();
    }

    private Secret Open(SecretRow row)
    {
        var plaintext = cipher.Open(row.Name, row.Version, new SealedSecret(row.Nonce, row.Ciphertext, row.Tag));
        try
        {
            return new Secret(row.Name, row.Version, plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

/// <summary>Called before each row is re-encrypted; tests use it to inject a failure halfway.</summary>
public delegate void RekeyProgress(string table, int rowIndex);

/// <summary>
/// Re-encrypts everything that depends on the master key, in one transaction: the secrets table, the data protection
/// key ring and the wrapped tenant data keys. Any failure rolls back, so the old master key keeps working.
/// </summary>
public static class MasterKeyRekey
{
    public sealed record Result(int Secrets, int DataProtectionKeys, int TenantKeys);

    public static async Task<Result> RekeyAsync(NpgsqlDataSource ownerDataSource, ReadOnlyMemory<byte> oldMasterKey,
        int oldVersion, ReadOnlyMemory<byte> newMasterKey, int newVersion, string hostId, RekeyProgress? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ownerDataSource);
        using var oldSecrets = new SecretCipher(oldMasterKey.Span, hostId);
        using var newSecrets = new SecretCipher(newMasterKey.Span, hostId);
        using var oldRing = new DataProtectionKeyCipher(oldMasterKey.Span);
        using var newRing = new DataProtectionKeyCipher(newMasterKey.Span);
        using var oldWrapper = new SoftwareKeyWrapper(oldMasterKey.Span, oldVersion);
        using var newWrapper = new SoftwareKeyWrapper(newMasterKey.Span, newVersion);

        await using var connection = await ownerDataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var secrets = (await connection.QueryAsync<PostgresSecretStore.SecretRow>(new CommandDefinition(
            "SELECT name, version, nonce, ciphertext, tag FROM vaulty.secrets ORDER BY name, version FOR UPDATE",
            transaction: transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        for (var i = 0; i < secrets.Count; i++)
        {
            progress?.Invoke("secrets", i);
            var row = secrets[i];
            var plaintext = oldSecrets.Open(row.Name, row.Version, new SealedSecret(row.Nonce, row.Ciphertext, row.Tag));
            var resealed = newSecrets.Seal(row.Name, row.Version, plaintext);
            CryptographicOperations.ZeroMemory(plaintext);
            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.secrets SET nonce = @n, ciphertext = @c, tag = @t WHERE name = @name AND version = @version",
                new { n = resealed.Nonce, c = resealed.Ciphertext, t = resealed.Tag, name = row.Name, version = row.Version },
                transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        var ring = (await connection.QueryAsync<(int Id, string FriendlyName, byte[] Sealed)>(new CommandDefinition(
            "SELECT id, friendly_name, sealed_xml FROM vaulty.data_protection_keys ORDER BY id FOR UPDATE",
            transaction: transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        for (var i = 0; i < ring.Count; i++)
        {
            progress?.Invoke("data_protection_keys", i);
            var xml = oldRing.Open(ring[i].Sealed, ring[i].FriendlyName);
            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.data_protection_keys SET sealed_xml = @x WHERE id = @id",
                new { x = newRing.Seal(xml, ring[i].FriendlyName), id = ring[i].Id }, transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        var keys = (await connection.QueryAsync<(Guid TenantId, int Version, byte[] WrappedKey)>(new CommandDefinition(
            "SELECT tenant_id, version, wrapped_key FROM vaulty.tenant_keys ORDER BY tenant_id, version FOR UPDATE",
            transaction: transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
        for (var i = 0; i < keys.Count; i++)
        {
            progress?.Invoke("tenant_keys", i);
            var context = new KeyWrapContext(keys[i].TenantId, keys[i].Version);
            var dek = oldWrapper.Unwrap(keys[i].WrappedKey, context);
            var rewrapped = newWrapper.Wrap(dek, context);
            CryptographicOperations.ZeroMemory(dek);
            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.tenant_keys SET wrapped_key = @w WHERE tenant_id = @t AND version = @v",
                new { w = rewrapped, t = keys[i].TenantId, v = keys[i].Version }, transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new Result(secrets.Count, ring.Count, keys.Count);
    }
}
