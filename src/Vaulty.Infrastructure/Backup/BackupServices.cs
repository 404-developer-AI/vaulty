using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Crypto;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Keys;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Infrastructure.Storage;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Backup;

/// <summary>The object store the workers write to (the worker identity on the backup bucket).</summary>
public interface IBackupStorage
{
    Task<IObjectStore> WorkerStoreAsync(CancellationToken cancellationToken = default);

    /// <summary>True when the connection test of the storage account passed (required before any backup is planned).</summary>
    Task<bool> ReadyAsync(CancellationToken cancellationToken = default);
}

/// <summary>The backup bucket through one storage identity: the worker identity by default, the garbage-collection identity in the gc service.</summary>
public sealed class S3BackupStorage(StorageClientFactory factory, StorageRole role = StorageRole.Worker) : IBackupStorage
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private (string AccessKeyId, IObjectStore Store)? _cached;

    public async Task<IObjectStore> WorkerStoreAsync(CancellationToken cancellationToken = default)
    {
        var settings = await factory.SettingsAsync(cancellationToken).ConfigureAwait(false)
                       ?? throw new InvalidOperationException("Object storage is not configured.");
        var keyId = settings.Identities[role].AccessKeyId;
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_cached is { } c && c.AccessKeyId == keyId) return c.Store;
            var store = await factory.CreateAsync(role, cancellationToken: cancellationToken).ConfigureAwait(false);
            _cached = (keyId, store);
            return store;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<bool> ReadyAsync(CancellationToken cancellationToken = default) =>
        (await factory.SettingsAsync(cancellationToken).ConfigureAwait(false))?.Ready == true;
}

/// <summary>
/// Unwrapped tenant keys for the workers, kept for a few minutes. Creates a tenant's first data key at its first backup
/// (wrapped in the database and as an immutable key file in object storage).
/// </summary>
public sealed class TenantKeyProvider(NpgsqlDataSource dataSource, IMasterKeySource masterKey, IBackupStorage storage, TimeProvider clock)
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan KeyFileLock = TimeSpan.FromDays(3650);
    private readonly ConcurrentDictionary<Guid, (DateTimeOffset At, byte[][] Keys, int[] Versions, HashSet<Guid> Shredded)> _cache = new();

    public async Task<RepositoryKeys> GetAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken = default)
    {
        if (!_cache.TryGetValue(tenantId, out var cached) || clock.GetUtcNow() - cached.At > CacheDuration)
        {
            var key = masterKey.ReadMasterKey();
            try
            {
                using var wrapper = new SoftwareKeyWrapper(key, masterKey.Version);
                var service = new TenantKeyService(wrapper, await storage.WorkerStoreAsync(cancellationToken).ConfigureAwait(false), clock);
                await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
                {
                    var exists = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
                        "SELECT EXISTS (SELECT 1 FROM vaulty.tenant_keys WHERE tenant_id = @tenantId)", new { tenantId }, session.Transaction,
                        cancellationToken: cancellationToken)).ConfigureAwait(false);
                    if (!exists)
                    {
                        await service.CreateAsync(session, tenantId, clock.GetUtcNow() + KeyFileLock, cancellationToken).ConfigureAwait(false);
                        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
                    }
                }
                await using var read = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
                using var loaded = await service.LoadAsync(read, tenantId, cancellationToken).ConfigureAwait(false);
                var versions = Enumerable.Range(1, loaded.CurrentVersion).ToArray();
                var shredded = (await read.Connection.QueryAsync<Guid>(new CommandDefinition(
                    "SELECT protected_object_id FROM vaulty.key_tombstones WHERE tenant_id = @tenantId AND confirmed_by IS NOT NULL", new { tenantId },
                    read.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToHashSet();
                cached = (clock.GetUtcNow(), versions.Select(v => loaded.DataKey(v).ToArray()).ToArray(), versions, shredded);
                _cache[tenantId] = cached;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
        return new RepositoryKeys(tenantId, cached.Versions.Zip(cached.Keys).ToDictionary(p => p.First, p => p.Second), cached.Shredded.Contains);
    }
}

public sealed record EffectivePolicy(int FrequencyMinutes, int RetentionDays, IReadOnlySet<string> ExcludedFolders, bool LegalHold)
{
    /// <summary>Object Lock lasts the retention plus 30 days of margin; a legal hold keeps data for at least ten years.</summary>
    public DateTimeOffset LockUntil(DateTimeOffset now) => now.AddDays((LegalHold ? Math.Max(RetentionDays, 3650) : RetentionDays) + 30);
}

/// <summary>The policy that applies to a protected object: its own, else its tenant's, else the defaults.</summary>
public static class PolicyResolver
{
    public static async Task<EffectivePolicy> ForObjectAsync(NpgsqlDataSource dataSource, Guid organizationId, Guid tenantId, Guid objectId,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<(int Frequency, int Retention, string Exclusions)?>(new CommandDefinition(
            """
            SELECT frequency_minutes, retention_days, exclusions::text FROM vaulty.policies
             WHERE tenant_id = @tenantId AND (protected_object_id = @objectId OR protected_object_id IS NULL)
             ORDER BY protected_object_id NULLS LAST LIMIT 1
            """, new { tenantId, objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var hold = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT o.legal_hold OR t.legal_hold FROM vaulty.protected_objects o JOIN vaulty.tenants t ON t.id = o.tenant_id WHERE o.id = @objectId",
            new { objectId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (row is { } r)
        {
            using var doc = JsonDocument.Parse(r.Exclusions);
            if (doc.RootElement.TryGetProperty("folders", out var folders) && folders.ValueKind == JsonValueKind.Array)
            {
                foreach (var f in folders.EnumerateArray()) if (f.GetString() is { } name) excluded.Add(name);
            }
            return new EffectivePolicy(r.Frequency, Math.Max(r.Retention, Policy.MinimumRetentionDays), excluded, hold);
        }
        return new EffectivePolicy(Policy.DefaultFrequencyMinutes, Policy.MinimumRetentionDays, excluded, hold);
    }
}
