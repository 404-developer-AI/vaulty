using System.Security.Cryptography;
using System.Text;
using Dapper;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Vaulty.Core.Abstractions;
using Secret = Vaulty.Core.Abstractions.Secret;
using Vaulty.Core.Crypto;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Logging;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Integration.Tests.Database;

namespace Vaulty.Integration.Tests.Secrets;

public sealed class SecretStoreTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static readonly byte[] MasterKey = RandomNumberGenerator.GetBytes(32);

    private PostgresSecretStore Store(string hostId, byte[]? masterKey = null, NpgsqlDataSource? dataSource = null) =>
        new(dataSource ?? VaultyDataSource.Create(db.Api), new SecretCipher(masterKey ?? MasterKey, hostId), TimeProvider.System,
            TimeSpan.Zero);

    [PostgresFact]
    public async Task Versions_rotate_and_prune()
    {
        var store = Store("host-a");
        Assert.Equal(1, await store.SetAsync("smtp.password", "one"u8.ToArray(), "test"));
        Assert.Equal(2, await store.SetAsync("smtp.password", "two"u8.ToArray(), "test"));
        using (var latest = await store.GetAsync("smtp.password"))
        {
            Assert.Equal("two", latest!.RevealString());
            Assert.Equal(2, latest.Version);
        }
        using (var first = await store.GetAsync("smtp.password", 1)) Assert.Equal("one", first!.RevealString());
        Assert.Equal(1, await store.PruneAsync("smtp.password", keep: 1));
        Assert.Null(await store.GetAsync("smtp.password", 1));
        Assert.DoesNotContain(await store.ListAsync(), s => s.Name == "smtp.password" && s.Version == 1);
    }

    [PostgresFact]
    public async Task A_row_on_another_host_cannot_be_decrypted()
    {
        var name = "storage.worker." + Guid.NewGuid().ToString("N");
        await Store("host-a").SetAsync(name, "access-key-value"u8.ToArray(), "test");

        // Same database, same master key, other host id: the authenticated data differs.
        await Assert.ThrowsAnyAsync<CryptographicException>(() => Store("host-b").GetAsync(name));

        // Copying the row under another name does not work either.
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync(
            "INSERT INTO vaulty.secrets (name, version, nonce, ciphertext, tag, created_by) SELECT @copy, version, nonce, ciphertext, tag, 'x' FROM vaulty.secrets WHERE name = @name",
            new { name, copy = name + ".copy" });
        await Assert.ThrowsAnyAsync<CryptographicException>(() => Store("host-a").GetAsync(name + ".copy"));
    }

    [PostgresFact]
    public async Task Rekey_of_1000_secrets_with_a_failure_halfway_leaves_the_old_state_intact()
    {
        var rekeyDb = new PostgresDatabase();
        await rekeyDb.InitializeAsync();
        try
        {
            var oldKey = RandomNumberGenerator.GetBytes(32);
            var newKey = RandomNumberGenerator.GetBytes(32);
            await using var api = VaultyDataSource.Create(rekeyDb.Api);
            await using var owner = VaultyDataSource.Create(rekeyDb.Migrator);
            var oldStore = new PostgresSecretStore(api, new SecretCipher(oldKey, "host-a"), TimeProvider.System, TimeSpan.Zero);
            for (var i = 0; i < 1000; i++) await oldStore.SetAsync($"secret.{i:D4}", Encoding.UTF8.GetBytes($"value-{i}"), "test");

            var before = await Snapshot(owner);
            var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => MasterKeyRekey.RekeyAsync(owner, oldKey, 1,
                newKey, 2, "host-a", (table, row) =>
                {
                    if (table == "secrets" && row == 500) throw new InvalidOperationException("injected failure");
                }));
            Assert.Equal("injected failure", failure.Message);

            Assert.Equal(before, await Snapshot(owner));
            for (var i = 0; i < 1000; i += 37)
            {
                using var secret = await oldStore.GetAsync($"secret.{i:D4}");
                Assert.Equal($"value-{i}", secret!.RevealString());
            }

            var result = await MasterKeyRekey.RekeyAsync(owner, oldKey, 1, newKey, 2, "host-a");
            Assert.Equal(1000, result.Secrets);
            var newStore = new PostgresSecretStore(api, new SecretCipher(newKey, "host-a"), TimeProvider.System, TimeSpan.Zero);
            for (var i = 0; i < 1000; i += 37)
            {
                using var secret = await newStore.GetAsync($"secret.{i:D4}");
                Assert.Equal($"value-{i}", secret!.RevealString());
            }
            await Assert.ThrowsAnyAsync<CryptographicException>(() => oldStore.GetAsync("secret.0001"));
        }
        finally
        {
            await rekeyDb.DisposeAsync();
        }
    }

    [PostgresFact]
    public Task Rekey_rewraps_tenant_keys_and_the_data_protection_ring() => WithFreshDatabase(async fresh =>
    {
        var oldKey = RandomNumberGenerator.GetBytes(32);
        var newKey = RandomNumberGenerator.GetBytes(32);
        await using var owner = VaultyDataSource.Create(fresh.Migrator);
        var org = Guid.NewGuid();
        var tenant = Guid.NewGuid();
        var customer = Guid.NewGuid();
        var dek = RandomNumberGenerator.GetBytes(32);
        using var oldWrapper = new SoftwareKeyWrapper(oldKey, 1);
        await using (var connection = await owner.OpenConnectionAsync())
        {
            await connection.ExecuteAsync(
                """
                INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'O');
                INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C', 'C');
                INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name)
                    VALUES (@tenant, @org, @customer, @entra, 'T');
                INSERT INTO vaulty.tenant_keys (organization_id, tenant_id, version, wrapped_key) VALUES (@org, @tenant, 1, @wrapped);
                """,
                new { org, customer, tenant, entra = Guid.NewGuid(), wrapped = oldWrapper.Wrap(dek, new KeyWrapContext(tenant, 1)) });
        }

        var protectedText = ProtectWithRing(fresh, oldKey, out var unprotectWithNewKey);
        await MasterKeyRekey.RekeyAsync(owner, oldKey, 1, newKey, 2, "host-rekey");

        await using (var connection = await owner.OpenConnectionAsync())
        {
            var wrapped = await connection.ExecuteScalarAsync<byte[]>(
                "SELECT wrapped_key FROM vaulty.tenant_keys WHERE tenant_id = @tenant", new { tenant });
            using var newWrapper = new SoftwareKeyWrapper(newKey, 2);
            Assert.Equal(dek, newWrapper.Unwrap(wrapped!, new KeyWrapContext(tenant, 1)));
        }
        Assert.Equal("session-cookie", unprotectWithNewKey(newKey, protectedText));
    });

    [PostgresFact]
    public Task Data_protection_keys_are_stored_sealed_and_shared() => WithFreshDatabase(async fresh =>
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var protectedText = ProtectWithRing(fresh, key, out var unprotect);
        Assert.Equal("session-cookie", unprotect(key, protectedText));

        await using var owner = new NpgsqlConnection(fresh.Migrator);
        var stored = (await owner.QueryAsync<byte[]>("SELECT sealed_xml FROM vaulty.data_protection_keys")).ToList();
        Assert.NotEmpty(stored);
        Assert.All(stored, bytes => Assert.DoesNotContain("<key", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal));
    });

    private static async Task WithFreshDatabase(Func<PostgresDatabase, Task> test)
    {
        var fresh = new PostgresDatabase();
        await fresh.InitializeAsync();
        try
        {
            await test(fresh);
        }
        finally
        {
            await fresh.DisposeAsync();
        }
    }

    [Fact]
    public void A_secret_in_a_log_message_is_redacted()
    {
        var sink = new CapturingSink();
        using var logger = new LoggerConfiguration()
            .Destructure.With<SecretDestructuringPolicy>()
            .WriteTo.Sink(sink)
            .CreateLogger();
        using var secret = new Secret("storage.gc.secret", 1, "very-secret-value"u8);

        logger.Information("Loaded {Secret}", secret);
        logger.Information("Loaded {@Secret}", secret);
        logger.Information("Loaded {$Secret}", secret);
        logger.Information("Wrapped {@Holder}", new { Name = "x", Value = secret });

        Assert.Equal(4, sink.Messages.Count);
        Assert.All(sink.Messages, m =>
        {
            Assert.DoesNotContain("very-secret-value", m, StringComparison.Ordinal);
            Assert.Contains("[redacted]", m, StringComparison.Ordinal);
        });
    }

    private sealed class CapturingSink : ILogEventSink
    {
        public List<string> Messages { get; } = [];

        public void Emit(LogEvent logEvent) =>
            Messages.Add(logEvent.RenderMessage(System.Globalization.CultureInfo.InvariantCulture) + " " +
                         string.Join(" ", logEvent.Properties.Values.Select(v => v.ToString())));
    }

    /// <summary>Protects a value with a ring persisted in the test database; returns a function that unprotects it from a fresh provider.</summary>
    private static string ProtectWithRing(PostgresDatabase database, byte[] masterKey, out Func<byte[], string, string> unprotect)
    {
        var connectionString = database.Api;
        unprotect = (key, text) => Provider(connectionString, key).CreateProtector("test").Unprotect(text);
        return Provider(connectionString, masterKey).CreateProtector("test").Protect("session-cookie");
    }

    private static IDataProtectionProvider Provider(string connectionString, byte[] masterKey)
    {
        var services = new ServiceCollection();
        services.AddSingleton(VaultyDataSource.Create(connectionString));
        services.AddSingleton(new DataProtectionKeyCipher(masterKey));
        services.AddDataProtection().SetApplicationName("vaulty").PersistKeysToVaultyDatabase();
        return services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
    }

    private static async Task<string> Snapshot(NpgsqlDataSource owner)
    {
        await using var connection = await owner.OpenConnectionAsync();
        var rows = await connection.QueryAsync<(string Name, int Version, byte[] Ciphertext, byte[] Tag)>(
            "SELECT name, version, ciphertext, tag FROM vaulty.secrets ORDER BY name, version");
        return string.Join("\n", rows.Select(r => $"{r.Name}:{r.Version}:{Convert.ToHexString(r.Ciphertext)}:{Convert.ToHexString(r.Tag)}"));
    }
}
