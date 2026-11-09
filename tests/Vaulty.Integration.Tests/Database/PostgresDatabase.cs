using Npgsql;

namespace Vaulty.Integration.Tests.Database;

/// <summary>A test that needs PostgreSQL; skipped when VAULTY_TEST_PG is not set (CI always sets it).</summary>
public sealed class PostgresFactAttribute : FactAttribute
{
    public PostgresFactAttribute()
    {
        if (string.IsNullOrEmpty(PostgresDatabase.AdminConnectionString)) Skip = "VAULTY_TEST_PG is not set.";
    }
}

/// <summary>
/// A throwaway Vaulty database: the same roles, schema and default privileges as the installer creates
/// (deploy/install/postgres/roles.sql), then every migration applied as vaulty_migrator. Each role-specific connection
/// string switches to that role at connect time, so privileges and row-level security apply as in production.
/// </summary>
public sealed class PostgresDatabase : IAsyncLifetime
{
    public static string? AdminConnectionString => Environment.GetEnvironmentVariable("VAULTY_TEST_PG");

    public string Name { get; } = "vaulty_test_" + Guid.NewGuid().ToString("N")[..12];

    public string Migrator => As("vaulty_migrator");
    public string Api => As("vaulty_api");
    public string Worker => As("vaulty_worker");
    public string Gc => As("vaulty_gc");

    public string As(string role) => new NpgsqlConnectionStringBuilder(AdminConnectionString)
    {
        Database = Name,
        SearchPath = "vaulty",
        Options = $"-c role={role}",
        Pooling = true,
    }.ConnectionString;

    public string Admin => new NpgsqlConnectionStringBuilder(AdminConnectionString) { Database = Name }.ConnectionString;

    public async Task InitializeAsync()
    {
        if (string.IsNullOrEmpty(AdminConnectionString)) return;
        await using (var admin = new NpgsqlConnection(AdminConnectionString))
        {
            await admin.OpenAsync();
            await Execute(admin, """
                DO $$
                DECLARE r text;
                BEGIN
                    FOREACH r IN ARRAY ARRAY['vaulty_migrator', 'vaulty_api', 'vaulty_worker', 'vaulty_gc'] LOOP
                        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                            EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', r);
                        END IF;
                    END LOOP;
                END $$;
                """);
            await Execute(admin, $"CREATE DATABASE {Name} OWNER vaulty_migrator ENCODING 'UTF8' TEMPLATE template0");
        }

        await using (var db = new NpgsqlConnection(Admin))
        {
            await db.OpenAsync();
            await Execute(db, $"""
                REVOKE ALL ON DATABASE {Name} FROM PUBLIC;
                GRANT CONNECT ON DATABASE {Name} TO vaulty_migrator, vaulty_api, vaulty_worker, vaulty_gc;
                REVOKE ALL ON SCHEMA public FROM PUBLIC;
                CREATE SCHEMA vaulty AUTHORIZATION vaulty_migrator;
                GRANT USAGE ON SCHEMA vaulty TO vaulty_api, vaulty_worker, vaulty_gc;
                ALTER DEFAULT PRIVILEGES FOR ROLE vaulty_migrator IN SCHEMA vaulty
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vaulty_api, vaulty_worker;
                ALTER DEFAULT PRIVILEGES FOR ROLE vaulty_migrator IN SCHEMA vaulty
                    GRANT SELECT ON TABLES TO vaulty_gc;
                ALTER DEFAULT PRIVILEGES FOR ROLE vaulty_migrator IN SCHEMA vaulty
                    GRANT USAGE, SELECT ON SEQUENCES TO vaulty_api, vaulty_worker;
                """);
        }

        await Infrastructure.Database.DatabaseMigrator.MigrateAsync(Migrator);
    }

    public async Task DisposeAsync()
    {
        if (string.IsNullOrEmpty(AdminConnectionString)) return;
        NpgsqlConnection.ClearAllPools();
        await using var admin = new NpgsqlConnection(AdminConnectionString);
        await admin.OpenAsync();
        await Execute(admin, $"DROP DATABASE IF EXISTS {Name} WITH (FORCE)");
    }

    public static async Task Execute(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
