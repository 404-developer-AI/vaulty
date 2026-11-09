using Vaulty.Infrastructure.Database;

// Applies the database migrations. Runs as vaulty_migrator (systemd oneshot vaulty-migrate.service) over the local
// Unix socket with peer authentication, so no password exists anywhere.
//   vaulty-migrate            apply pending migrations
//   vaulty-migrate script     print the full migration script
//   vaulty-migrate list       list the migrations this build contains
var connectionString = Environment.GetEnvironmentVariable("VAULTY_MIGRATE_PG")
                       ?? "Host=/var/run/postgresql;Database=vaulty;Username=vaulty_migrator;Search Path=vaulty";

switch (args.FirstOrDefault())
{
    case "script":
        Console.Out.Write(DatabaseMigrator.Script());
        return 0;
    case "list":
        foreach (var migration in DatabaseMigrator.All()) Console.Out.WriteLine(migration);
        return 0;
    case null:
        var applied = await DatabaseMigrator.MigrateAsync(connectionString);
        Console.Out.WriteLine(applied.Count == 0
            ? "vaulty-migrate: the database is up to date."
            : $"vaulty-migrate: applied {applied.Count} migration(s): {string.Join(", ", applied)}");
        return 0;
    default:
        Console.Error.WriteLine("usage: vaulty-migrate [script|list]");
        return 2;
}
