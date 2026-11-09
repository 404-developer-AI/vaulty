using System.Security.Cryptography;
using Dapper;
using Npgsql;
using Vaulty.Core.Crypto;
using Vaulty.Core.Storage;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Keys;
using Vaulty.Integration.Tests.Database;
using Vaulty.Repository.Format;

namespace Vaulty.Integration.Tests.Keys;

public sealed class TenantKeyTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private async Task<(Guid Org, Guid Tenant)> SeedTenant()
    {
        var org = Guid.NewGuid();
        var customer = Guid.NewGuid();
        var tenant = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'O');
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C', 'C');
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name) VALUES (@tenant, @org, @customer, @entra, 'T');
            """, new { org, customer, tenant, entra = Guid.NewGuid() });
        return (org, tenant);
    }

    [PostgresFact]
    public async Task A_data_key_is_stored_wrapped_in_the_database_and_in_object_storage()
    {
        var (org, tenant) = await SeedTenant();
        var masterKey = RandomNumberGenerator.GetBytes(32);
        using var wrapper = new SoftwareKeyWrapper(masterKey);
        var store = new InMemoryObjectStore();
        var service = new TenantKeyService(wrapper, store, TimeProvider.System);
        await using var dataSource = VaultyDataSource.Create(db.Api);

        await using (var session = await OrganizationSession.BeginAsync(dataSource, org))
        {
            Assert.Equal(1, await service.CreateAsync(session, tenant, DateTimeOffset.UtcNow.AddYears(1)));
            await session.CommitAsync();
        }

        byte[] fromDatabase;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, org))
        {
            using var keys = await service.LoadAsync(session, tenant);
            fromDatabase = keys.DataKey(1).ToArray();
            Assert.Equal(1, await session.Connection.ExecuteScalarAsync<int>(
                "SELECT current_dek_version FROM vaulty.tenants WHERE id = @tenant", new { tenant }, session.Transaction));
        }

        using var fromStore = await TenantKeyService.LoadFromStoreAsync(store, wrapper, tenant);
        Assert.Equal(fromDatabase, fromStore.DataKey(1).ToArray());
        await Assert.ThrowsAsync<Vaulty.Core.Abstractions.ObjectLockedException>(() =>
            store.DeleteAsync(RepositoryLayout.DataKey(tenant, 1)));

        // Another host's master key cannot unwrap the stored key.
        using var otherWrapper = new SoftwareKeyWrapper(RandomNumberGenerator.GetBytes(32));
        await Assert.ThrowsAnyAsync<Exception>(() => TenantKeyService.LoadFromStoreAsync(store, otherWrapper, tenant));
    }

    [PostgresFact]
    public async Task The_daily_audit_anchor_is_written_once_and_locked()
    {
        var (org, _) = await SeedTenant();
        var store = new InMemoryObjectStore();
        await using var worker = VaultyDataSource.Create(db.Worker);
        await using (var session = await OrganizationSession.BeginAsync(worker, org))
        {
            for (var i = 0; i < 5; i++) await AuditLog.WriteAsync(session, "system", "test.event", null);
            await session.CommitAsync();
        }
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        await using (var session = await OrganizationSession.BeginAsync(worker, org))
        {
            Assert.True(await AuditAnchor.WriteAsync(session, store, today, DateTimeOffset.UtcNow.AddYears(7)));
            Assert.False(await AuditAnchor.WriteAsync(session, store, today, DateTimeOffset.UtcNow.AddYears(7)));
            await session.CommitAsync();
        }
        var head = await store.HeadAsync(AuditAnchor.ObjectKey(org, today));
        Assert.NotNull(head?.LockUntil);
    }
}
