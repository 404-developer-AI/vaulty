using System.Text;
using Npgsql;
using Vaulty.Infrastructure.Backup;
using Vaulty.Infrastructure.Browse;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Integration.Tests.Backup;
using Vaulty.Integration.Tests.Temporal;

namespace Vaulty.Integration.Tests.Browse;

/// <summary>Real backups of a simulated mailbox, then browsing them as the web app does (API database role).</summary>
public sealed class BrowseEndToEndTests(TemporalFixture fixture) : IClassFixture<TemporalFixture>
{
    [TemporalFact]
    public async Task Each_snapshot_shows_the_mailbox_as_it_was_and_previews_are_sanitized()
    {
        using var simulator = new MailboxSimulator(items: 40, seed: 12);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();

        var (_, first) = await harness.BackupAsync(mailbox);
        var changed = simulator.Items.Values.First(i => i.FolderId == "f-inbox");
        var removed = simulator.Items.Values.First(i => i.FolderId == "f-inbox" && i.Id != changed.Id);
        simulator.Change(changed.Id);
        simulator.Remove(removed.Id);
        var added = simulator.Add("f-inbox");
        var (_, second) = await harness.BackupAsync(mailbox);

        await using var api = VaultyDataSource.Create(fixture.Database.Api);
        var keys = new TenantKeyProvider(api, new StaticMasterKeySource(harness.MasterKey), harness.Storage, TimeProvider.System);
        var browser = new SnapshotBrowser(api, keys, new StoreReaders(harness.Store, api, keys));
        var access = BrowseSeed.Access(harness.Org);

        var snapshots = await browser.SnapshotsAsync(access, mailbox);
        Assert.Equal([second, first], snapshots.Select(s => s.Id));
        var tree = await browser.FoldersAsync(access, mailbox, second);
        Assert.Equal(simulator.Folders.Select(f => f.Name).Order(StringComparer.Ordinal),
            tree.SelectMany(r => r.Children).Select(c => c.Name).Order(StringComparer.Ordinal));

        async Task<Dictionary<string, ItemRow>> InboxAsync(Guid snapshot)
        {
            var rows = new Dictionary<string, ItemRow>(StringComparer.Ordinal);
            string? cursor = null;
            do
            {
                var page = await browser.ItemsAsync(access, mailbox, snapshot, "f-inbox", cursor);
                foreach (var row in page.Items) rows.Add(row.SourceId, row);
                cursor = page.NextCursor;
            }
            while (cursor is not null);
            return rows;
        }

        var before = await InboxAsync(first);
        var after = await InboxAsync(second);
        Assert.Equal($"Subject of {changed.Id} v1", before[changed.Id].Title);
        Assert.Equal($"Subject of {changed.Id} v2", after[changed.Id].Title);
        Assert.Contains(removed.Id, before.Keys);
        Assert.DoesNotContain(removed.Id, after.Keys);
        Assert.DoesNotContain(added.Id, before.Keys);
        Assert.Contains(added.Id, after.Keys);
        Assert.Equal(simulator.CountIn("f-inbox"), after.Count);

        // The preview is the message body, sanitized: text kept, script and tracking image gone. Opening it is audited.
        var row = after[changed.Id];
        Assert.True(row.HasPreview);
        var preview = await browser.PreviewAsync(access, mailbox, second, row.Id);
        Assert.Equal("text/html", preview!.MediaType);
        var html = Encoding.UTF8.GetString(preview.Content);
        Assert.Contains($"Body of {changed.Id} v2", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tracker.example", html, StringComparison.Ordinal);
        var old = await browser.PreviewAsync(access, mailbox, first, before[changed.Id].Id);
        Assert.Contains($"Body of {changed.Id} v1", Encoding.UTF8.GetString(old!.Content), StringComparison.Ordinal);
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        await owner.OpenAsync();
        await using var count = new NpgsqlCommand("SELECT count(*) FROM vaulty.audit_events WHERE action = 'item.previewed' AND organization_id = @org", owner);
        count.Parameters.AddWithValue("org", harness.Org);
        Assert.Equal(2L, (long)(await count.ExecuteScalarAsync())!);

        // Search finds the current state only: the old subject is gone, the new one is found.
        var hits = await browser.SearchAsync(access, $"Subject {changed.Id}");
        Assert.Equal($"Subject of {changed.Id} v2", Assert.Single(hits).Title);
    }
}
