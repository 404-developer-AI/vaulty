using System.Diagnostics;
using System.IO.Compression;
using Dapper;
using Npgsql;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Restore;
using Vaulty.Integration.Tests.Backup;
using Vaulty.Integration.Tests.Temporal;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Restore;

public sealed class RestoreTests(TemporalFixture fixture, ITestOutputHelper output) : IClassFixture<TemporalFixture>
{
    private static readonly string Today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    private async Task<List<RestoreItemReport>> ItemsAsync(BackupHarness harness, Guid restoreId) =>
        (await harness.RestoreService().ReportAsync(harness.Access(), restoreId))!.Items.ToList();

    [TemporalFact]
    public async Task Mail_restored_to_the_restore_folder_is_imported_byte_for_byte_and_calendar_items_send_nothing()
    {
        using var simulator = new MailboxSimulator(items: 40, seed: 31);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();
        var (_, snapshot) = await harness.BackupAsync(mailbox);
        simulator.RequestLog.Clear();

        string[] folders = ["f-inbox", "f-calendar", "f-contacts"];
        var (restoreId, outcome) = await harness.RestoreAsync(mailbox, snapshot, new RestoreSelection([], folders));
        var expected = simulator.Items.Values.Where(i => folders.Contains(i.FolderId)).ToList();
        Assert.Equal("succeeded", outcome.State);
        Assert.Equal(expected.Count, outcome.ItemCounts["restored"]);

        // Every item arrives with exactly the bytes of its export, without a token on the import host.
        Assert.Equal(expected.Count, simulator.Imports.Count);
        Assert.All(simulator.Imports, i => Assert.False(i.HadAuthorization));
        Assert.All(simulator.Imports, i => Assert.Equal("create", i.Mode));
        Assert.Equal(expected.Select(e => Convert.ToHexString(e.Data)).Order(StringComparer.Ordinal),
            simulator.Imports.Select(i => Convert.ToHexString(i.Data)).Order(StringComparer.Ordinal));

        // Vaulty Restore / <date time> / <original folder>, each with the original folder's type.
        var root = Assert.Single(simulator.CreatedFolders, f => f.Name == RestoreActivitiesName);
        Assert.Equal(MailboxSimulator.RootFolderId, root.ParentId);
        var stamp = Assert.Single(simulator.CreatedFolders, f => f.ParentId == root.Id);
        Assert.StartsWith(Today, stamp.Name, StringComparison.Ordinal);
        var leaves = simulator.CreatedFolders.Where(f => f.ParentId == stamp.Id).ToDictionary(f => f.Name, f => f);
        Assert.Equal("IPF.Note", leaves["Inbox"].Type);
        Assert.Equal("IPF.Appointment", leaves["Calendar"].Type);
        Assert.Equal("IPF.Contact", leaves["Contacts"].Type);
        foreach (var import in simulator.Imports)
        {
            var source = expected.Single(e => e.Data.AsSpan().SequenceEqual(import.Data));
            var name = simulator.Folders.Single(f => f.Id == source.FolderId).Name;
            Assert.Equal(leaves[name].Id, import.FolderId);
        }

        // No invitation, update or message is sent: nothing but folder listing, folder creation and imports.
        Assert.DoesNotContain(simulator.RequestLog, r => r.Contains("/events", StringComparison.OrdinalIgnoreCase)
            || r.Contains("sendMail", StringComparison.OrdinalIgnoreCase) || r.Contains("/calendar", StringComparison.OrdinalIgnoreCase)
            || (r.StartsWith("POST", StringComparison.Ordinal) && r.Contains("/messages", StringComparison.OrdinalIgnoreCase)));
        Assert.All(simulator.RequestLog, r => Assert.True(r.Contains("importItem", StringComparison.Ordinal) || r.Contains("createImportSession", StringComparison.Ordinal)
            || r.Contains("/folders", StringComparison.Ordinal), r));

        var report = await ItemsAsync(harness, restoreId);
        Assert.All(report, i => Assert.Equal("restored", i.State));
        output.WriteLine($"{report.Count} items restored with {simulator.RequestLog.Count} requests");
    }

    [TemporalFact]
    public async Task Mail_goes_back_to_its_original_folder_or_to_another_mailbox_and_a_failing_item_makes_the_restore_partial()
    {
        using var simulator = new MailboxSimulator(items: 20, seed: 32);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        var other = await harness.SeedMailboxAsync("MBX:manager@contoso");
        harness.StartWorker();
        var (_, snapshot) = await harness.BackupAsync(mailbox);
        var entries = await harness.ReadSnapshotAsync(mailbox, snapshot, compareWithSource: false);
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        var picked = simulator.Items.Values.Take(3).ToList();
        var ids = (await owner.QueryAsync<Guid>("SELECT id FROM vaulty.items WHERE protected_object_id = @mailbox AND source_id = ANY(@sources)",
            new { mailbox, sources = picked.Select(p => p.Id).ToArray() })).ToList();

        var (_, original) = await harness.RestoreAsync(mailbox, snapshot, new RestoreSelection(ids, []), RestoreModes.Original);
        Assert.Equal("succeeded", original.State);
        Assert.Empty(simulator.CreatedFolders);
        Assert.Equal(picked.Select(p => p.FolderId).Order(StringComparer.Ordinal), simulator.Imports.Select(i => i.FolderId).Order(StringComparer.Ordinal));

        simulator.Imports.Clear();
        simulator.FailingImports.Add(picked[1].Id);
        var (restoreId, elsewhere) = await harness.RestoreAsync(mailbox, snapshot, new RestoreSelection(ids, []), RestoreModes.Other, other);
        Assert.Equal("partial", elsewhere.State);
        Assert.Equal(2, elsewhere.ItemCounts["restored"]);
        Assert.Equal(1, elsewhere.ItemCounts["failed"]);
        Assert.All(simulator.Imports, i => Assert.Equal("MBX:manager@contoso", i.MailboxId));
        Assert.All(simulator.CreatedFolders, f => Assert.Equal("MBX:manager@contoso", f.MailboxId));
        var failed = Assert.Single(await ItemsAsync(harness, restoreId), i => i.State == "failed");
        Assert.Equal(picked[1].Id, failed.SourceId);
        Assert.Contains("could not be imported", failed.Detail, StringComparison.Ordinal);
        _ = entries;
    }

    [TemporalFact]
    public async Task Files_are_restored_with_their_folders_contents_and_times_and_never_overwrite_without_a_choice()
    {
        using var simulator = new DriveSimulator(files: 30, seed: 8);
        var edited = simulator.Files.First(f => f.ParentId == DriveSimulator.RootId);
        simulator.Edit(edited.Id);
        await using var harness = new BackupHarness(fixture, simulator.Url, _ => null);
        await harness.SeedTenantAsync();
        var drive = await harness.SeedDriveAsync(DriveSimulator.DriveId);
        harness.StartWorker();
        var (_, snapshot) = await harness.DriveBackupAsync(drive);
        var documents = simulator.Folders.Single(f => f.Name == "Documents");
        var archive = simulator.Folders.Single(f => f.Name == "Archive");
        var underDocuments = simulator.Files.Where(f => f.ParentId == documents.Id || f.ParentId == archive.Id).ToList();

        // Restore folder: Vaulty Restore / <date time> / Documents / Archive, contents byte for byte, original times, no token.
        var (_, toFolder) = await harness.RestoreAsync(drive, snapshot, new RestoreSelection([], [documents.Id]));
        Assert.Equal("succeeded", toFolder.State);
        Assert.Equal(underDocuments.Count, simulator.Uploads.Count);
        foreach (var file in underDocuments)
        {
            var upload = Assert.Single(simulator.Uploads, u => u.RequestedName == file.Name);
            Assert.Equal(file.Data, upload.Data);
            Assert.False(upload.HadAuthorization);
            Assert.NotNull(upload.Modified);
            var parent = simulator.Nodes[upload.ParentId];
            Assert.Equal(file.ParentId == archive.Id ? "Archive" : "Documents", parent.Name);
        }
        var restoreRoot = Assert.Single(simulator.ChildrenOf(DriveSimulator.RootId), n => n.Name == RestoreActivitiesName);
        Assert.StartsWith(Today, Assert.Single(simulator.ChildrenOf(restoreRoot.Id)).Name, StringComparison.Ordinal);

        // In place: the file still exists, so the restored copy gets "(restored date)" in its name; nothing is replaced.
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        async Task<Guid> ItemAsync(string sourceId) => await owner.ExecuteScalarAsync<Guid>(
            "SELECT id FROM vaulty.items WHERE protected_object_id = @drive AND source_id = @sourceId", new { drive, sourceId });
        simulator.Uploads.Clear();
        var inPlace = underDocuments[0];
        var (_, renamed) = await harness.RestoreAsync(drive, snapshot, new RestoreSelection([await ItemAsync(inPlace.Id)], []), RestoreModes.Original);
        Assert.Equal("succeeded", renamed.State);
        var copy = Assert.Single(simulator.Uploads);
        Assert.Equal(inPlace.ParentId, copy.ParentId);
        Assert.Contains($"(restored {Today})", copy.StoredName, StringComparison.Ordinal);
        Assert.Equal(inPlace.Data, simulator.Nodes[inPlace.Id].Data);

        var (skipId, skipped) = await harness.RestoreAsync(drive, snapshot, new RestoreSelection([await ItemAsync(inPlace.Id)], []), RestoreModes.Original, conflict: "skip");
        Assert.Equal(1, skipped.ItemCounts["skipped"]);
        Assert.Single(simulator.Uploads);
        Assert.Equal("skipped", Assert.Single(await ItemsAsync(harness, skipId)).State);

        // A specific older version, next to its file.
        simulator.Uploads.Clear();
        var (_, version) = await harness.RestoreAsync(drive, snapshot, new RestoreSelection([await ItemAsync($"{edited.Id}@1.0")], []), RestoreModes.Original);
        Assert.Equal("succeeded", version.State);
        var restoredVersion = Assert.Single(simulator.Uploads);
        Assert.Equal(DriveSimulator.Content(edited.Id, 1, edited.Size), restoredVersion.Data);
        Assert.Equal(DriveSimulator.RootId, restoredVersion.ParentId);
    }

    [TemporalFact]
    public async Task Twenty_restores_of_ten_items_of_different_types_all_verify_and_stay_well_under_five_minutes()
    {
        using var mail = new MailboxSimulator(items: 80, seed: 41);
        using var files = new DriveSimulator(files: 80, seed: 42);
        await using var mailHarness = new BackupHarness(fixture, mail);
        await mailHarness.SeedTenantAsync();
        var mailbox = await mailHarness.SeedMailboxAsync();
        var manager = await mailHarness.SeedMailboxAsync("MBX:manager@contoso");
        mailHarness.StartWorker();
        var (_, mailSnapshot) = await mailHarness.BackupAsync(mailbox);
        await using var fileHarness = new BackupHarness(fixture, files.Url, _ => null);
        await fileHarness.SeedTenantAsync();
        var drive = await fileHarness.SeedDriveAsync(DriveSimulator.DriveId);
        fileHarness.StartWorker();
        var (_, driveSnapshot) = await fileHarness.DriveBackupAsync(drive);

        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        var mailItems = (await owner.QueryAsync<(Guid Id, string Kind)>("SELECT id, kind FROM vaulty.items WHERE protected_object_id = @mailbox AND kind <> 'folder' ORDER BY id",
            new { mailbox })).ToList();
        var fileItems = (await owner.QueryAsync<Guid>("SELECT id FROM vaulty.items WHERE protected_object_id = @drive AND kind = 'file' ORDER BY id", new { drive })).ToList();

        var durations = new List<double>();
        var restored = 0L;
        for (var run = 0; run < 20; run++)
        {
            var watch = Stopwatch.StartNew();
            RestoreOutcomeSummary result;
            if (run % 2 == 0)
            {
                var kind = new[] { "mail", "event", "contact" }[run / 2 % 3];
                var pick = mailItems.Where(i => i.Kind == kind).Select(i => i.Id).Concat(mailItems.Select(i => i.Id)).Distinct().Skip(run).Take(10).ToList();
                var mode = (run / 2 % 3) switch { 0 => RestoreModes.RestoreFolder, 1 => RestoreModes.Original, _ => RestoreModes.Other };
                var (_, outcome) = await mailHarness.RestoreAsync(mailbox, mailSnapshot, new RestoreSelection(pick, []), mode, mode == RestoreModes.Other ? manager : null);
                result = new(outcome.State, outcome.ItemCounts["restored"]);
            }
            else
            {
                var pick = fileItems.Skip(run * 3).Take(10).ToList();
                var mode = run % 4 == 1 ? RestoreModes.RestoreFolder : RestoreModes.Original;
                var (_, outcome) = await fileHarness.RestoreAsync(drive, driveSnapshot, new RestoreSelection(pick, []), mode);
                result = new(outcome.State, outcome.ItemCounts["restored"]);
            }
            durations.Add(watch.Elapsed.TotalSeconds);
            Assert.Equal("succeeded", result.State);
            Assert.Equal(10, result.Restored);
            restored += result.Restored;
        }
        // Verified: every import and upload carries exactly the backed-up bytes.
        Assert.All(mail.Imports, i => Assert.Contains(mail.Items.Values, s => s.Data.AsSpan().SequenceEqual(i.Data)));
        Assert.All(files.Uploads, u => Assert.Contains(files.Files, f => f.Uploaded is null && f.Data.AsSpan().SequenceEqual(u.Data)));
        durations.Sort();
        var p95 = durations[(int)Math.Ceiling(durations.Count * 0.95) - 1];
        output.WriteLine($"20 restores, {restored} items: median {durations[10]:F1} s, p95 {p95:F1} s, slowest {durations[^1]:F1} s");
        Assert.True(p95 < 300, $"p95 {p95:F0} s");
    }

    private sealed record RestoreOutcomeSummary(string State, long Restored);

    [TemporalFact]
    public async Task An_export_of_5000_items_streams_in_parts_and_its_link_works_exactly_once()
    {
        using var simulator = new MailboxSimulator(items: 0, seed: 51);
        for (var i = 0; i < 5000; i++) simulator.Add("f-inbox", 600 + i % 400);
        for (var i = 0; i < 30; i++) simulator.Add("f-contacts", 800);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();
        var watch = Stopwatch.StartNew();
        var (backup, snapshot) = await harness.BackupAsync(mailbox);
        Assert.False(backup.IsPartial);
        output.WriteLine($"backup of {simulator.Items.Count} items: {watch.Elapsed.TotalSeconds:F0} s");

        // Other processes use the temp folder too; an export spilled to disk would leave a file of megabytes there.
        var exportStarted = DateTime.UtcNow;
        watch.Restart();
        var (restoreId, outcome) = await harness.RestoreAsync(mailbox, snapshot, new RestoreSelection([], ["f-inbox"]), RestoreModes.Export);
        Assert.Equal("succeeded", outcome.State);
        Assert.Equal(5000, outcome.ItemCounts["restored"]);
        output.WriteLine($"export of 5,000 items: {watch.Elapsed.TotalSeconds:F1} s in {harness.ExportUploads.PartsUploaded} parts");
        Assert.True(harness.ExportUploads.PartsUploaded > 4, $"{harness.ExportUploads.PartsUploaded} parts");
        Assert.DoesNotContain(new DirectoryInfo(Path.GetTempPath()).EnumerateFiles("*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
            .Where(f => { try { return f.LastWriteTimeUtc >= exportStarted && f.Length >= 1024 * 1024; } catch (IOException) { return false; } }), f => true);

        var key = Assert.Single(harness.ExportStore.Keys);
        await using (var zipStream = await harness.ExportStore.GetAsync(key))
        using (var buffer = new MemoryStream())
        {
            await zipStream.CopyToAsync(buffer);
            buffer.Position = 0;
            using var zip = new ZipArchive(buffer, ZipArchiveMode.Read);
            Assert.Equal(5001, zip.Entries.Count);
            Assert.All(zip.Entries, e => Assert.Equal(e.Length, e.CompressedLength)); // store mode
            Assert.Equal(5000, zip.Entries.Count(e => e.FullName.StartsWith("Inbox/", StringComparison.Ordinal) && e.FullName.EndsWith(".eml", StringComparison.Ordinal)));
            using var reader = new StreamReader(zip.Entries.First(e => e.FullName.EndsWith(".eml", StringComparison.Ordinal)).Open());
            var eml = await reader.ReadToEndAsync();
            Assert.Contains("Subject: Subject of", eml, StringComparison.Ordinal);
            Assert.Contains("sender@contoso.example", eml, StringComparison.Ordinal);
            Assert.NotNull(zip.GetEntry("manifest.json"));
        }

        // The link: only for the user who asked, with the token, after "Confirm it's you", exactly once.
        var service = harness.RestoreService();
        await Assert.ThrowsAsync<StepUpRequiredException>(() => service.CreateLinkAsync(harness.Access(), stepUpFresh: false, restoreId));
        await Assert.ThrowsAsync<AccessException>(() => service.CreateLinkAsync(harness.Access(Guid.NewGuid()), stepUpFresh: true, restoreId));
        var (exportId, token) = await service.CreateLinkAsync(harness.Access(), stepUpFresh: true, restoreId);
        Assert.Null(await service.ClaimDownloadAsync(harness.Access(Guid.NewGuid()), true, exportId, token));
        Assert.Null(await service.ClaimDownloadAsync(harness.Access(), true, exportId, token + "x"));
        Assert.Null(await service.ClaimDownloadAsync(harness.Access(), false, exportId, token));
        Assert.Equal(key, (await service.ClaimDownloadAsync(harness.Access(), true, exportId, token))?.ObjectKey);
        Assert.Null(await service.ClaimDownloadAsync(harness.Access(), true, exportId, token));
        await Assert.ThrowsAsync<AccessException>(() => service.CreateLinkAsync(harness.Access(), stepUpFresh: true, restoreId));
    }

    [TemporalFact]
    public async Task A_restore_can_be_paused_resumed_and_cancelled_and_keeps_what_it_restored()
    {
        using var simulator = new DriveSimulator(files: 240, seed: 61);
        await using var harness = new BackupHarness(fixture, simulator.Url, _ => null);
        await harness.SeedTenantAsync();
        var drive = await harness.SeedDriveAsync(DriveSimulator.DriveId);
        harness.StartWorker();
        var (_, snapshot) = await harness.DriveBackupAsync(drive);

        var (restoreId, handle) = await harness.StartRestoreAsync(drive, snapshot, new RestoreSelection([], [DriveSimulator.RootId]));
        await handle.SignalAsync(w => w.PauseAsync());
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        async Task<string> StateAsync() => await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.restores WHERE id = @restoreId", new { restoreId }) ?? "";
        for (var i = 0; i < 100 && await StateAsync() != "paused"; i++) await Task.Delay(100);
        Assert.Equal("paused", await StateAsync());
        var pausedAt = simulator.Uploads.Count;
        await Task.Delay(1500);
        Assert.Equal(pausedAt, simulator.Uploads.Count);
        Assert.True(pausedAt < 240, "the restore finished before it could be paused");

        await handle.SignalAsync(w => w.ResumeAsync());
        for (var i = 0; i < 100 && simulator.Uploads.Count == pausedAt; i++) await Task.Delay(50);
        await handle.SignalAsync(w => w.CancelAsync());
        var outcome = await handle.GetResultAsync();
        Assert.Equal("cancelled", outcome.State);
        var report = await ItemsAsync(harness, restoreId);
        Assert.Equal(simulator.Uploads.Count, report.Count(i => i.State == "restored"));
        Assert.True(report.Count(i => i.State == "restored") > pausedAt);
        Assert.All(report.Where(i => i.State == "skipped"), i => Assert.Contains("cancelled", i.Detail, StringComparison.Ordinal));
        Assert.DoesNotContain(report, i => i.State == "pending");
        output.WriteLine($"paused after {pausedAt}, cancelled after {simulator.Uploads.Count} of {report.Count}");
    }

    [TemporalFact]
    public async Task Restores_and_exports_check_permissions_targets_and_confirmation()
    {
        using var simulator = new MailboxSimulator(items: 5, seed: 71);
        await using var harness = new BackupHarness(fixture, simulator);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        var drive = await harness.SeedDriveAsync("b!other-drive");
        harness.StartWorker();
        var (_, snapshot) = await harness.BackupAsync(mailbox);
        var service = harness.RestoreService();
        var all = new RestoreSelection([], ["f-inbox"]);

        await Assert.ThrowsAsync<StepUpRequiredException>(() => service.CreateAsync(harness.Access(), false, new(mailbox, snapshot, all, RestoreModes.Export, null, "rename")));
        await Assert.ThrowsAsync<StepUpRequiredException>(() => service.CreateAsync(harness.Access(), false, new(mailbox, snapshot, all, RestoreModes.Other, mailbox, "rename")));
        var browseOnly = harness.Access(null, Permissions.SnapshotsBrowse, Permissions.CustomersView);
        await Assert.ThrowsAsync<AccessException>(() => service.CreateAsync(browseOnly, true, new(mailbox, snapshot, all, RestoreModes.RestoreFolder, null, "rename")));
        var inPlaceOnly = harness.Access(null, Permissions.SnapshotsBrowse, Permissions.CustomersView, Permissions.RestoreInPlace);
        await Assert.ThrowsAsync<AccessException>(() => service.CreateAsync(inPlaceOnly, true, new(mailbox, snapshot, all, RestoreModes.Export, null, "rename")));
        await Assert.ThrowsAsync<ArgumentException>(() => service.CreateAsync(harness.Access(), true, new(mailbox, snapshot, all, RestoreModes.Other, drive, "rename")));
        await Assert.ThrowsAsync<ArgumentException>(() => service.CreateAsync(harness.Access(), true, new(mailbox, snapshot, new RestoreSelection([], []), RestoreModes.RestoreFolder, null, "rename")));
        await Assert.ThrowsAsync<ArgumentException>(() => service.CreateAsync(harness.Access(), true, new(mailbox, Guid.NewGuid(), all, RestoreModes.RestoreFolder, null, "rename")));
        var created = await service.CreateAsync(inPlaceOnly, false, new(mailbox, snapshot, all, RestoreModes.RestoreFolder, null, "rename"));
        await using var owner = new NpgsqlConnection(fixture.Database.Migrator);
        Assert.Equal("restore.requested", await owner.ExecuteScalarAsync<string>(
            "SELECT action FROM vaulty.audit_events WHERE target = @target ORDER BY seq DESC LIMIT 1", new { target = $"object:{mailbox}" }));
        Assert.Equal("queued", await owner.ExecuteScalarAsync<string>("SELECT state FROM vaulty.jobs WHERE id = @id", new { id = created.JobId }));
    }

    private const string RestoreActivitiesName = Vaulty.Workflows.Restore.RestoreActivities.RestoreFolderName;
}
