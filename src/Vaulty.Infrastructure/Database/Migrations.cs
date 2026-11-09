using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;

namespace Vaulty.Infrastructure.Database;

/// <summary>Reads the SQL files embedded in this assembly.</summary>
internal static class EmbeddedSql
{
    public static string Read(string name)
    {
        var resource = $"Vaulty.Sql.{name}.sql";
        using var stream = typeof(EmbeddedSql).Assembly.GetManifestResourceStream(resource)
                           ?? throw new InvalidOperationException($"Embedded SQL '{resource}' is missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

/// <summary>
/// Base class of the forward-only SQL migrations. Migrations are expand/contract: a release never needs a down step,
/// and rolling back the binaries keeps working on the expanded schema.
/// </summary>
public abstract class SqlMigration : Migration
{
    protected abstract string ScriptName { get; }

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        ArgumentNullException.ThrowIfNull(migrationBuilder);
        migrationBuilder.Sql(EmbeddedSql.Read(ScriptName));
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Vaulty migrations are forward-only.");
}

[DbContext(typeof(VaultyDbContext))]
[Migration("20261109000001_Initial")]
public sealed class InitialMigration : SqlMigration
{
    protected override string ScriptName => "0001_initial";
}

/// <summary>Applies the migrations and produces the migration script.</summary>
public static class DatabaseMigrator
{
    public const string HistoryTable = "ef_migrations_history";

    public static DbContextOptions<VaultyDbContext> Options(string connectionString)
    {
        var builder = new DbContextOptionsBuilder<VaultyDbContext>();
        Configure(builder, connectionString);
        return builder.Options;
    }

    public static void Configure(DbContextOptionsBuilder builder, string connectionString)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.UseNpgsql(connectionString, npgsql => npgsql.MigrationsHistoryTable(HistoryTable, VaultyDbContext.Schema))
            .UseSnakeCaseNamingConvention()
            // The model is mapped onto tables that the SQL migrations create, so EF's own model diff is always empty.
            .ConfigureWarnings(w => w.Ignore(RelationalEventId.PendingModelChangesWarning));
    }

    /// <summary>Applies every pending migration. Running it again is a no-op.</summary>
    public static async Task<IReadOnlyList<string>> MigrateAsync(string connectionString, CancellationToken cancellationToken = default)
    {
        await using var context = new VaultyDbContext(Options(connectionString));
        var pending = (await context.Database.GetPendingMigrationsAsync(cancellationToken).ConfigureAwait(false)).ToList();
        await context.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
        return pending;
    }

    /// <summary>The full migration script from an empty schema to the current version.</summary>
    public static string Script()
    {
        using var context = new VaultyDbContext(Options("Host=localhost;Database=vaulty"));
        return context.GetService<IMigrator>().GenerateScript();
    }

    public static IReadOnlyList<string> All()
    {
        using var context = new VaultyDbContext(Options("Host=localhost;Database=vaulty"));
        return context.Database.GetMigrations().ToList();
    }
}

/// <summary>Lets <c>dotnet ef migrations script</c> build the context without a running database.</summary>
public sealed class DesignTimeContextFactory : IDesignTimeDbContextFactory<VaultyDbContext>
{
    public VaultyDbContext CreateDbContext(string[] args) =>
        new(DatabaseMigrator.Options(Environment.GetEnvironmentVariable("VAULTY_DESIGN_PG") ?? "Host=localhost;Database=vaulty"));
}

/// <summary>Helpers for opening the Vaulty database as one of its roles.</summary>
public static class VaultyDataSource
{
    public static NpgsqlDataSource Create(string connectionString)
    {
        var builder = new NpgsqlDataSourceBuilder(connectionString);
        return builder.Build();
    }
}

[DbContext(typeof(VaultyDbContext))]
[Migration("20261109000002_DataProtection")]
public sealed class DataProtectionMigration : SqlMigration
{
    protected override string ScriptName => "0002_data_protection";
}

[DbContext(typeof(VaultyDbContext))]
[Migration("20261109000003_TenantKeysApi")]
public sealed class TenantKeysApiMigration : SqlMigration
{
    protected override string ScriptName => "0003_tenant_keys_api";
}

[DbContext(typeof(VaultyDbContext))]
[Migration("20261109000004_FolderCheckpoints")]
public sealed class FolderCheckpointsMigration : SqlMigration
{
    protected override string ScriptName => "0004_folder_checkpoints";
}

[DbContext(typeof(VaultyDbContext))]
[Migration("20261109000005_Identity")]
public sealed class IdentityMigration : SqlMigration
{
    protected override string ScriptName => "0005_identity";
}
