using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Vaulty.Core.Storage;
using Vaulty.Infrastructure.Database;
using Vaulty.Integration.Tests.Temporal;
using Vaulty.Workflows.Backup;

namespace Vaulty.Integration.Tests.Backup;

public sealed class SchedulerTests(TemporalFixture fixture) : IClassFixture<TemporalFixture>
{
    [TemporalFact]
    public async Task One_tenant_never_takes_more_than_its_budget_and_nothing_runs_before_storage_is_ready()
    {
        using var simulator = new MailboxSimulator(items: 1);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        for (var i = 0; i < 25; i++) await harness.SeedMailboxAsync();
        await using (var owner = new NpgsqlConnection(fixture.Database.Migrator))
        {
            await owner.ExecuteAsync("UPDATE vaulty.protected_objects SET next_run_at = now() - interval '1 minute' WHERE tenant_id = @tenant", new { tenant = harness.Tenant });
        }

        await using var dataSource = VaultyDataSource.Create(fixture.Database.Worker);
        var starter = new BackupStarter(fixture.Server.Client, dataSource);
        var notReady = new BackupScheduler(starter, new NotReadyStorage(), dataSource, TimeProvider.System, NullLogger<BackupScheduler>.Instance);
        Assert.Equal(0, await notReady.RunOnceAsync());

        var scheduler = new BackupScheduler(starter, harness.Storage, dataSource, TimeProvider.System, NullLogger<BackupScheduler>.Instance);
        Assert.Equal(20, await scheduler.RunOnceAsync());
        Assert.Equal(0, await scheduler.RunOnceAsync()); // the budget is full; the others wait their turn
    }

    private sealed class NotReadyStorage : Vaulty.Infrastructure.Backup.IBackupStorage
    {
        public Task<Vaulty.Core.Abstractions.IObjectStore> WorkerStoreAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<Vaulty.Core.Abstractions.IObjectStore>(new InMemoryObjectStore());
        public Task<bool> ReadyAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);
    }
}
