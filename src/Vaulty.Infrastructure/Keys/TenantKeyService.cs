using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dapper;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Crypto;
using Vaulty.Infrastructure.Database;
using Vaulty.Repository.Format;

namespace Vaulty.Infrastructure.Keys;

/// <summary>The wrapped data key as stored in object storage (tenants/{id}/keys/dek-{version}.json).</summary>
public sealed record DataKeyFile(
    [property: JsonPropertyName("format")] int Format,
    [property: JsonPropertyName("tenant_id")] Guid TenantId,
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("wrapper_type")] int WrapperType,
    [property: JsonPropertyName("kek_version")] int KekVersion,
    [property: JsonPropertyName("wrapped_key")] string WrappedKey,
    [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt);

/// <summary>
/// Creates and loads tenant data keys. A new key is generated in memory, wrapped, and stored twice: in the database and
/// as an immutable file in object storage, so the tenant can be recovered without the database.
/// </summary>
public sealed class TenantKeyService(IKeyWrapper wrapper, IObjectStore store, TimeProvider clock)
{
    public async Task<int> CreateAsync(OrganizationSession session, Guid tenantId, DateTimeOffset lockUntil,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "SELECT pg_advisory_xact_lock(hashtextextended('vaulty.tenant-key:' || @tenantId::text, 0))",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var version = 1 + await session.Connection.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT coalesce(max(version), 0) FROM vaulty.tenant_keys WHERE tenant_id = @tenantId",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var dek = RandomNumberGenerator.GetBytes(KeyHierarchy.KeySize);
        byte[] wrapped;
        try
        {
            wrapped = await wrapper.WrapAsync(dek, new KeyWrapContext(tenantId, version), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }

        var header = SoftwareKeyWrapper.ReadHeader(wrapped);
        var file = new DataKeyFile(1, tenantId, version, header.WrapperType, header.KekVersion, Convert.ToBase64String(wrapped),
            clock.GetUtcNow());
        await store.PutAsync(RepositoryLayout.DataKey(tenantId, version), new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(file)),
            new ObjectPutOptions(lockUntil), cancellationToken).ConfigureAwait(false);

        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.tenant_keys (organization_id, tenant_id, version, wrapped_key) VALUES (@org, @tenantId, @version, @wrapped);
            UPDATE vaulty.tenants SET current_dek_version = @version WHERE id = @tenantId;
            """,
            new { org = session.OrganizationId, tenantId, version, wrapped }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return version;
    }

    /// <summary>Unwraps every data key version of a tenant and applies the tombstone list.</summary>
    public async Task<RepositoryKeys> LoadAsync(OrganizationSession session, Guid tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var rows = await session.Connection.QueryAsync<(int Version, byte[] WrappedKey)>(new CommandDefinition(
            "SELECT version, wrapped_key FROM vaulty.tenant_keys WHERE tenant_id = @tenantId ORDER BY version",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var shredded = (await session.Connection.QueryAsync<Guid>(new CommandDefinition(
            "SELECT protected_object_id FROM vaulty.key_tombstones WHERE tenant_id = @tenantId AND confirmed_by IS NOT NULL",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToHashSet();
        var keys = new Dictionary<int, byte[]>();
        try
        {
            foreach (var (version, wrappedKey) in rows)
            {
                keys[version] = await wrapper.UnwrapAsync(wrappedKey, new KeyWrapContext(tenantId, version), cancellationToken)
                    .ConfigureAwait(false);
            }
            if (keys.Count == 0) throw new InvalidOperationException($"Tenant {tenantId} has no data key.");
            return new RepositoryKeys(tenantId, keys, shredded.Contains);
        }
        finally
        {
            foreach (var key in keys.Values) CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Unwraps the data keys from the key files in object storage alone (recovery without the database).</summary>
    public static async Task<RepositoryKeys> LoadFromStoreAsync(IObjectStore store, IKeyWrapper wrapper, Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(wrapper);
        var keys = new Dictionary<int, byte[]>();
        try
        {
            await foreach (var info in store.ListAsync(RepositoryLayout.TenantPrefix(tenantId) + "keys/", cancellationToken).ConfigureAwait(false))
            {
                if (!info.Key.EndsWith(".json", StringComparison.Ordinal)) continue;
                await using var stream = await store.GetAsync(info.Key, null, cancellationToken).ConfigureAwait(false);
                var file = await JsonSerializer.DeserializeAsync<DataKeyFile>(stream, cancellationToken: cancellationToken).ConfigureAwait(false)
                           ?? throw new InvalidDataException($"{info.Key} is empty.");
                if (file.TenantId != tenantId) throw new InvalidDataException($"{info.Key} belongs to tenant {file.TenantId}.");
                try
                {
                    keys[file.Version] = await wrapper.UnwrapAsync(Convert.FromBase64String(file.WrappedKey),
                        new KeyWrapContext(tenantId, file.Version), cancellationToken).ConfigureAwait(false);
                }
                catch (CryptographicException) when (keys.ContainsKey(file.Version))
                {
                    // A copy of the same version wrapped with an older KEK; the newer copy already unwrapped.
                }
            }
            if (keys.Count == 0) throw new InvalidOperationException($"No usable data key for tenant {tenantId} in object storage.");
            return new RepositoryKeys(tenantId, keys);
        }
        finally
        {
            foreach (var key in keys.Values) CryptographicOperations.ZeroMemory(key);
        }
    }
}
