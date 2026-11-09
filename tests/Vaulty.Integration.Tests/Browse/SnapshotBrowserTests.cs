using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Npgsql;
using NpgsqlTypes;
using Vaulty.Core.Security;
using Vaulty.Core.Storage;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Browse;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Integration.Tests.Backup;
using Vaulty.Integration.Tests.Database;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Browse;

internal sealed class StoreReaders(InMemoryObjectStore store, NpgsqlDataSource dataSource, TenantKeyProvider keys) : IRepositoryReaderFactory
{
    public async Task<RepositoryReader> CreateAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken = default) =>
        new(store, await keys.GetAsync(organizationId, tenantId, cancellationToken), new PostgresChunkIndex(dataSource, organizationId, tenantId));
}

/// <summary>Organizations, customers, tenants and protected objects with committed snapshots, seeded straight into the database.</summary>
internal sealed class BrowseSeed(PostgresDatabase db) : IAsyncDisposable
{
    public byte[] MasterKey { get; } = RandomNumberGenerator.GetBytes(32);
    public InMemoryObjectStore Store { get; } = new();
    public NpgsqlDataSource Api { get; } = VaultyDataSource.Create(db.Api);
    public NpgsqlDataSource Worker { get; } = VaultyDataSource.Create(db.Worker);

    public SnapshotBrowser Browser()
    {
        var keys = new TenantKeyProvider(Api, new StaticMasterKeySource(MasterKey), new MemoryBackupStorage(Store), TimeProvider.System);
        return new SnapshotBrowser(Api, keys, new StoreReaders(Store, Api, keys));
    }

    public async Task<RepositoryKeys> KeysAsync(Guid org, Guid tenant) =>
        await new TenantKeyProvider(Worker, new StaticMasterKeySource(MasterKey), new MemoryBackupStorage(Store), TimeProvider.System).GetAsync(org, tenant);

    public async Task<(Guid Org, Guid Customer, Guid Tenant)> TenantAsync(Guid? org = null, string customer = "C")
    {
        var o = org ?? Guid.NewGuid();
        var c = Guid.NewGuid();
        var t = Guid.NewGuid();
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.organizations (id, name) SELECT @o, 'O' WHERE NOT EXISTS (SELECT 1 FROM vaulty.organizations WHERE id = @o);
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@c, @o, @code, @customer);
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name, consent_state, client_id)
                VALUES (@t, @o, @c, @entra, @tenantName, 'granted', @client);
            """, new { o, c, t, code = customer, customer, tenantName = $"{customer} tenant", entra = Guid.NewGuid(), client = Guid.NewGuid() });
        return (o, c, t);
    }

    public async Task<(Guid Object, Guid Snapshot)> ObjectAsync(Guid org, Guid tenant, string kind, string name)
    {
        var id = Guid.NewGuid();
        var snapshot = Guid.CreateVersion7();
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.ExecuteAsync(
            """
            INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, sub_kind, source_id, display_name)
                VALUES (@id, @org, @tenant, @kind, 'user', @source, @name);
            INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id, state, started_at, committed_at, sequence, item_counts, manifest_root_hash)
                VALUES (@snapshot, @org, @tenant, @id, 'committed', now(), now(), 1, '{"mail": 1}', '\x00');
            """, new { id, org, tenant, kind, source = id.ToString("N"), name, snapshot });
        return (id, snapshot);
    }

    public sealed record SeedItem(string SourceId, string? Parent, string Kind, string Metadata, string? Search, long Size, DateTimeOffset Modified);

    /// <summary>Bulk insert of committed items of snapshot 1 (binary COPY).</summary>
    public async Task ItemsAsync(Guid org, Guid tenant, Guid objectId, Guid snapshot, IEnumerable<SeedItem> items)
    {
        var keys = await KeysAsync(org, tenant);
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.OpenAsync();
        var list = items.ToList();
        await using (var writer = await owner.BeginBinaryImportAsync(
            "COPY vaulty.items (organization_id, tenant_id, id, protected_object_id, first_snapshot_id, state, source_id, parent_source_id, kind, " +
            "sealed_metadata, size, modified_at, first_sequence) FROM STDIN (FORMAT BINARY)"))
        {
        foreach (var item in list)
        {
            await writer.StartRowAsync();
            await writer.WriteAsync(org, NpgsqlDbType.Uuid);
            await writer.WriteAsync(tenant, NpgsqlDbType.Uuid);
            await writer.WriteAsync(Guid.CreateVersion7(), NpgsqlDbType.Uuid);
            await writer.WriteAsync(objectId, NpgsqlDbType.Uuid);
            await writer.WriteAsync(snapshot, NpgsqlDbType.Uuid);
            await writer.WriteAsync("committed", NpgsqlDbType.Text);
            await writer.WriteAsync(item.SourceId, NpgsqlDbType.Text);
            if (item.Parent is null) await writer.WriteNullAsync(); else await writer.WriteAsync(item.Parent, NpgsqlDbType.Text);
            await writer.WriteAsync(item.Kind, NpgsqlDbType.Text);
            await writer.WriteAsync(MetadataSealer.Seal(keys, objectId, item.SourceId, item.Metadata), NpgsqlDbType.Bytea);
            await writer.WriteAsync(item.Size, NpgsqlDbType.Bigint);
            await writer.WriteAsync(item.Modified.UtcDateTime, NpgsqlDbType.TimestampTz);
            await writer.WriteAsync(1L, NpgsqlDbType.Bigint);
        }
        await writer.CompleteAsync();
        }
        // Search tokens are made by PostgreSQL, as in production.
        await owner.ExecuteAsync("CREATE TEMP TABLE seed_search (source_id text, search text)");
        await using (var writer = await owner.BeginBinaryImportAsync("COPY seed_search (source_id, search) FROM STDIN (FORMAT BINARY)"))
        {
            foreach (var item in list.Where(i => i.Search is not null))
            {
                await writer.StartRowAsync();
                await writer.WriteAsync(item.SourceId, NpgsqlDbType.Text);
                await writer.WriteAsync(SearchText.Normalize(item.Search) ?? "", NpgsqlDbType.Text);
            }
            await writer.CompleteAsync();
        }
        await owner.ExecuteAsync(
            """
            UPDATE vaulty.items i SET search_vector = to_tsvector('simple', s.search) FROM seed_search s
             WHERE i.tenant_id = @tenant AND i.protected_object_id = @objectId AND i.source_id = s.source_id;
            DROP TABLE seed_search;
            ANALYZE vaulty.items;
            """, new { tenant, objectId }, commandTimeout: 300);
    }

    public static UserAccess Access(Guid org, params Guid[] customers) => new(Guid.NewGuid(), org, true,
        new Dictionary<string, HashSet<Guid>?> { [Permissions.SnapshotsBrowse] = customers.Length == 0 ? null : customers.ToHashSet(), [Permissions.CustomersView] = null });

    public async ValueTask DisposeAsync()
    {
        await Api.DisposeAsync();
        await Worker.DisposeAsync();
    }
}

public sealed class SnapshotBrowserTests(PostgresDatabase db, ITestOutputHelper output) : IClassFixture<PostgresDatabase>
{
    private const double Budget = 300;

    [PostgresFact]
    public async Task Browsing_a_mailbox_of_50000_items_and_a_drive_of_20000_files_stays_under_300_ms_per_page()
    {
        await using var seed = new BrowseSeed(db);
        var (org, _, tenant) = await seed.TenantAsync();
        var (mailbox, mailSnapshot) = await seed.ObjectAsync(org, tenant, "mailbox", "Anna");
        var (drive, driveSnapshot) = await seed.ObjectAsync(org, tenant, "drive", "Anna OneDrive");
        var start = DateTimeOffset.UtcNow.AddYears(-3);

        var watch = Stopwatch.StartNew();
        string[] mailFolders = ["inbox", "sent", "archive", "calendar"];
        int[] perFolder = [30_000, 10_000, 8_000, 2_000];
        var mail = new List<BrowseSeed.SeedItem>();
        for (var f = 0; f < mailFolders.Length; f++)
        {
            mail.Add(new(mailFolders[f], "msgroot", "folder", JsonSerializer.Serialize(new { name = char.ToUpperInvariant(mailFolders[f][0]) + mailFolders[f][1..] }), null, 0, start));
            for (var i = 0; i < perFolder[f]; i++)
            {
                var subject = $"Invoice {i} for project {i % 97}";
                mail.Add(new($"{mailFolders[f]}-{i}", mailFolders[f], f == 3 ? "event" : "mail",
                    JsonSerializer.Serialize(new { subject, from = $"sender{i % 50}@contoso.example", to = new[] { "anna@contoso.example" } }),
                    $"{subject} sender{i % 50}@contoso.example", 4_000 + i, start.AddMinutes(i)));
            }
        }
        await seed.ItemsAsync(org, tenant, mailbox, mailSnapshot, mail);
        var files = new List<BrowseSeed.SeedItem>();
        for (var top = 0; top < 20; top++)
        {
            files.Add(new($"d{top}", "driveroot", "folder", JsonSerializer.Serialize(new { name = $"Department {top}" }), $"Department {top}", 0, start));
            for (var sub = 0; sub < 20; sub++)
            {
                var folder = $"d{top}-{sub}";
                files.Add(new(folder, $"d{top}", "folder", JsonSerializer.Serialize(new { name = $"Project {sub}" }), $"Project {sub}", 0, start));
                for (var i = 0; i < 50; i++)
                {
                    var name = $"Drawing {top}-{sub}-{i}.pdf";
                    files.Add(new($"{folder}-f{i}", folder, "file",
                        JsonSerializer.Serialize(new { name, path = $"/Department {top}/Project {sub}", mime_type = "application/pdf" }), name, 100_000 + i, start.AddHours(i)));
                }
            }
        }
        await seed.ItemsAsync(org, tenant, drive, driveSnapshot, files);
        output.WriteLine($"seeded {mail.Count} mailbox rows and {files.Count} drive rows in {watch.Elapsed.TotalSeconds:F1} s");

        var browser = seed.Browser();
        var access = BrowseSeed.Access(org);

        var tree = await Timed("mailbox folder tree", () => browser.FoldersAsync(access, mailbox, mailSnapshot));
        Assert.Equal(4, tree.Single().Children.Count);
        var first = await Timed("inbox, first page", () => browser.ItemsAsync(access, mailbox, mailSnapshot, "inbox", null));
        Assert.Equal(30_000, first.Total);
        Assert.Equal(SnapshotBrowser.PageSize, first.Items.Count);
        Assert.Equal($"Invoice 29999 for project {29999 % 97}", first.Items[0].Title);

        // Walk 50 pages deep: keyset paging keeps the last page as fast as the first.
        var cursor = first.NextCursor;
        var seen = first.Items.Select(i => i.Id).ToHashSet();
        var slowest = 0.0;
        for (var page = 1; page < 50; page++)
        {
            var w = Stopwatch.StartNew();
            var next = await browser.ItemsAsync(access, mailbox, mailSnapshot, "inbox", cursor);
            slowest = Math.Max(slowest, w.Elapsed.TotalMilliseconds);
            Assert.All(next.Items, i => Assert.True(seen.Add(i.Id), "an item appeared on two pages"));
            cursor = next.NextCursor;
        }
        output.WriteLine($"inbox pages 2-50: slowest {slowest:F0} ms");
        Assert.True(slowest < Budget, $"slowest page {slowest:F0} ms");

        var detail = await Timed("item detail", () => browser.ItemAsync(access, mailbox, mailSnapshot, first.Items[3].Id));
        Assert.Equal("anna@contoso.example", detail!.Fields["to"]);

        var driveTree = await Timed("drive folder tree (420 folders)", () => browser.FoldersAsync(access, drive, driveSnapshot));
        Assert.Equal(20, driveTree.Single().Children.Count);
        var folderPage = await Timed("drive folder page", () => browser.ItemsAsync(access, drive, driveSnapshot, "d7-3", null));
        Assert.Equal(50, folderPage.Total);
        Assert.All(folderPage.Items, i => Assert.True(i.HasPreview));

        // Every word must match (as a word or the beginning of one), in any order.
        var hits = await Timed("search over 70,000 items", () => browser.SearchAsync(access, "drawing 7-3-41"));
        Assert.Contains(hits, h => h.Title == "Drawing 7-3-41.pdf");
        Assert.All(hits, h =>
        {
            var words = h.Title[..^4].Split(' ', '-');
            Assert.Contains("Drawing", words);
            Assert.Contains(words, w => w.StartsWith('7'));
            Assert.Contains(words, w => w.StartsWith('3'));
            Assert.Contains(words, w => w.StartsWith("41", StringComparison.Ordinal));
        });
    }

    [PostgresFact]
    public async Task Search_and_browsing_respect_the_organization_and_the_users_customers()
    {
        await using var seed = new BrowseSeed(db);
        var (orgA, customer1, tenant1) = await seed.TenantAsync(customer: "Alpha");
        var (_, customer2, tenant2) = await seed.TenantAsync(orgA, "Beta");
        var (orgB, customer3, tenant3) = await seed.TenantAsync(customer: "Gamma");
        var objects = new List<(Guid Org, Guid Tenant, Guid Object, Guid Snapshot)>();
        foreach (var (org, tenant, name) in new[] { (orgA, tenant1, "Alpha mailbox"), (orgA, tenant2, "Beta mailbox"), (orgB, tenant3, "Gamma mailbox") })
        {
            var (obj, snap) = await seed.ObjectAsync(org, tenant, "mailbox", name);
            await seed.ItemsAsync(org, tenant, obj, snap,
            [
                new("inbox", "root", "folder", "{\"name\":\"Inbox\"}", null, 0, DateTimeOffset.UtcNow),
                new($"m-{name}", "inbox", "mail", JsonSerializer.Serialize(new { subject = $"Quarterly report {name}", from = "cfo@contoso.example" }),
                    $"Quarterly report {name} cfo@contoso.example", 10, DateTimeOffset.UtcNow),
            ]);
            objects.Add((org, tenant, obj, snap));
        }
        var browser = seed.Browser();

        var everything = await browser.SearchAsync(BrowseSeed.Access(orgA), "quarterly");
        Assert.Equal(["Quarterly report Alpha mailbox", "Quarterly report Beta mailbox"], everything.Select(h => h.Title).Order(StringComparer.Ordinal));

        var alphaOnly = await browser.SearchAsync(BrowseSeed.Access(orgA, customer1), "quarterly report");
        Assert.Equal("Quarterly report Alpha mailbox", Assert.Single(alphaOnly).Title);
        Assert.Equal("Alpha", alphaOnly[0].CustomerName);

        var other = await browser.SearchAsync(BrowseSeed.Access(orgB), "quarterly");
        Assert.Equal("Quarterly report Gamma mailbox", Assert.Single(other).Title);

        var noPermission = new UserAccess(Guid.NewGuid(), orgA, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.CustomersView] = null });
        Assert.Empty(await browser.SearchAsync(noPermission, "quarterly"));
        Assert.Empty(await browser.SearchAsync(BrowseSeed.Access(orgA), "-- ' ; DROP TABLE vaulty.items"));

        // Browsing: another customer's object is invisible, another organization's object does not exist for the user.
        var beta = objects[1];
        Assert.Null(await browser.ObjectAsync(BrowseSeed.Access(orgA, customer1), beta.Object));
        await Assert.ThrowsAsync<AccessException>(() => browser.ItemsAsync(BrowseSeed.Access(orgA, customer1), beta.Object, beta.Snapshot, "inbox", null));
        var gamma = objects[2];
        Assert.Null(await browser.ObjectAsync(BrowseSeed.Access(orgA), gamma.Object));
        Assert.NotNull(await browser.ObjectAsync(BrowseSeed.Access(orgB, customer3), gamma.Object));
        _ = customer2;
    }

    private async Task<T> Timed<T>(string name, Func<Task<T>> call)
    {
        await call(); // warm up: connection pool, plan cache, key cache
        var timings = new List<double>();
        T result = default!;
        for (var i = 0; i < 5; i++)
        {
            var watch = Stopwatch.StartNew();
            result = await call();
            timings.Add(watch.Elapsed.TotalMilliseconds);
        }
        timings.Sort();
        output.WriteLine($"{name}: median {timings[2]:F0} ms, slowest {timings[^1]:F0} ms");
        Assert.True(timings[^1] < Budget, $"{name} took {timings[^1]:F0} ms");
        return result;
    }
}
