using System.Diagnostics;
using Dapper;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Database;

/// <summary>
/// The cost of the user-scope policy on the largest table: the same queries on items as an organization session (workers,
/// every customer) and as a session limited to one customer. Prints the timings; fails only when the limited session is
/// unreasonably slower, so the number is seen at every run.
/// </summary>
[Collection(MeasurementsCollection.Name)]
public sealed class ScopeMeasurementTests(PostgresDatabase db, ITestOutputHelper output) : IClassFixture<PostgresDatabase>
{
    private const int Items = 200_000;

    [PostgresFact]
    public async Task The_scope_policy_on_items_costs_little_for_the_queries_the_web_runs()
    {
        var api = VaultyDataSource.Create(db.Api);
        var access = new AccessService(api);
        var org = await new OrganizationSetup(api, access).CreateOrganizationAsync("Measure", Guid.NewGuid());
        var (customer, tenant, other, otherTenant, objectId) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        await using (var owner = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(db.Migrator) { CommandTimeout = 600 }.ConnectionString))
        {
            await owner.ExecuteAsync(
                """
                INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'M1', 'Measured'), (@other, @org, 'M2', 'Other');
                INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name)
                VALUES (@tenant, @org, @customer, gen_random_uuid(), 'T'), (@otherTenant, @org, @other, gen_random_uuid(), 'U');
                INSERT INTO vaulty.items (organization_id, tenant_id, id, protected_object_id, first_snapshot_id, state, source_id, kind, size)
                SELECT @org, CASE WHEN g % 2 = 0 THEN @tenant ELSE @otherTenant END, gen_random_uuid(), @objectId, gen_random_uuid(), 'committed', 'src-' || g, 'mail', g
                  FROM generate_series(1, @items) g;
                ANALYZE vaulty.items;
                """, new { org, customer, tenant, other, otherTenant, objectId, items = Items });
        }
        var everything = new UserAccess(Guid.NewGuid(), org, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.CustomersView] = null });
        var limited = new UserAccess(Guid.NewGuid(), org, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.CustomersView] = [customer] });

        async Task<(double Page, double Count, long Rows)> MeasureAsync(UserAccess who)
        {
            // Warm up once, then the best of five, as the browse page runs these.
            double best1 = double.MaxValue, best2 = double.MaxValue;
            long rows = 0;
            for (var run = 0; run < 6; run++)
            {
                await using var session = await OrganizationSession.BeginAsync(api, who);
                var watch = Stopwatch.StartNew();
                await session.Connection.QueryAsync<Guid>(
                    "SELECT id FROM vaulty.items WHERE tenant_id = @tenant AND protected_object_id = @objectId ORDER BY source_id LIMIT 100",
                    new { tenant, objectId }, session.Transaction);
                var page = watch.Elapsed.TotalMilliseconds;
                watch.Restart();
                rows = await session.Connection.ExecuteScalarAsync<long>("SELECT count(*) FROM vaulty.items WHERE protected_object_id = @objectId",
                    new { objectId }, session.Transaction);
                var count = watch.Elapsed.TotalMilliseconds;
                if (run == 0) continue;
                best1 = Math.Min(best1, page);
                best2 = Math.Min(best2, count);
            }
            return (best1, best2, rows);
        }

        var all = await MeasureAsync(everything);
        var scoped = await MeasureAsync(limited);
        output.WriteLine($"items: {Items:N0} rows, half of them in the scoped tenant");
        output.WriteLine($"page of 100 in one tenant: organization session {all.Page:F1} ms, scoped session {scoped.Page:F1} ms");
        output.WriteLine($"count over the object:     organization session {all.Count:F1} ms ({all.Rows:N0} rows), scoped session {scoped.Count:F1} ms ({scoped.Rows:N0} rows)");

        Assert.Equal(Items, all.Rows);
        Assert.Equal(Items / 2, scoped.Rows);
        // Generous bounds for a busy test machine: the point is the printed numbers, not a benchmark.
        Assert.True(scoped.Page < Math.Max(50, all.Page * 10), $"A page took {scoped.Page:F1} ms in a scoped session.");
        Assert.True(scoped.Count < Math.Max(2000, all.Count * 10), $"A count took {scoped.Count:F1} ms in a scoped session.");
    }
}
