using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Storage;
using Vaulty.Repository.Engine;

namespace Vaulty.Infrastructure.Browse;

/// <summary>
/// Backup data as the web app and API see it: the API identity on the backup bucket, which reads everything but writes only
/// tenant key files and can delete nothing.
/// </summary>
public sealed class ApiBackupStorage(StorageClientFactory factory) : IBackupStorage
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private (string AccessKeyId, IObjectStore Store)? _cached;

    public async Task<IObjectStore> WorkerStoreAsync(CancellationToken cancellationToken = default)
    {
        var settings = await factory.SettingsAsync(cancellationToken).ConfigureAwait(false)
                       ?? throw new InvalidOperationException("Object storage is not configured.");
        var keyId = settings.Identities[StorageRole.Api].AccessKeyId;
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_cached is { } c && c.AccessKeyId == keyId) return c.Store;
            var store = await factory.CreateAsync(StorageRole.Api, cancellationToken: cancellationToken).ConfigureAwait(false);
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

public sealed class RepositoryReaderFactory(NpgsqlDataSource dataSource, IBackupStorage storage, TenantKeyProvider keys) : IRepositoryReaderFactory
{
    public async Task<RepositoryReader> CreateAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken = default) =>
        new(await storage.WorkerStoreAsync(cancellationToken).ConfigureAwait(false), await keys.GetAsync(organizationId, tenantId, cancellationToken).ConfigureAwait(false),
            new PostgresChunkIndex(dataSource, organizationId, tenantId));
}
