using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Vaulty.Core.Storage;
using Vaulty.Infrastructure.Restore;
using Vaulty.Integration.Tests.Backup;
using Vaulty.Integration.Tests.Temporal;
using Vaulty.Recover;
using Xunit.Abstractions;

namespace Vaulty.Integration.Tests.Recover;

/// <summary>
/// The recovery guarantee: object storage, the key files and the master key's recovery copy are enough to rebuild a tenant,
/// without the database, and the result is byte for byte what an export through the platform gives.
/// </summary>
public sealed class RecoverTests(TemporalFixture fixture, ITestOutputHelper output) : IClassFixture<TemporalFixture>
{
    private static async Task<Dictionary<string, string>> ZipAsync(InMemoryObjectStore store)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        await using var stream = await store.GetAsync(Assert.Single(store.Keys));
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer);
        buffer.Position = 0;
        using var zip = new ZipArchive(buffer, ZipArchiveMode.Read);
        foreach (var entry in zip.Entries.Where(e => e.FullName != "manifest.json"))
        {
            await using var content = entry.Open();
            result[entry.FullName] = Convert.ToHexString(await SHA256.HashDataAsync(content));
        }
        return result;
    }

    private static Dictionary<string, string> Files(string directory) =>
        Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Where(f => Path.GetFileName(f) != "manifest.json")
            .ToDictionary(f => Path.GetRelativePath(directory, f).Replace(Path.DirectorySeparatorChar, '/'), f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))),
                StringComparer.Ordinal);

    private static async Task<string[]> FoldersAsync(BackupHarness harness, Guid objectId)
    {
        await using var session = await Vaulty.Infrastructure.Database.OrganizationSession.BeginAsync(harness.DataSource, harness.Org);
        return (await session.Connection.QueryAsync<string>(
            "SELECT DISTINCT source_id FROM vaulty.items WHERE tenant_id = @tenant AND protected_object_id = @objectId AND kind IN ('folder', 'package')",
            new { tenant = harness.Tenant, objectId }, session.Transaction)).ToArray();
    }

    [TemporalFact]
    public async Task A_tenant_is_rebuilt_from_object_storage_alone_byte_for_byte_like_a_platform_export()
    {
        // A mailbox (mail, calendar, contacts) and a OneDrive in one tenant.
        using var mail = new MailboxSimulator(items: 60, seed: 61);
        await using var harness = new BackupHarness(fixture, mail);
        await harness.SeedTenantAsync();
        var mailbox = await harness.SeedMailboxAsync();
        harness.StartWorker();
        var (mailOutcome, mailSnapshot) = await harness.BackupAsync(mailbox);
        Assert.False(mailOutcome.IsPartial);
        // A second run, so recovery must pick the newest snapshot.
        mail.Add("f-inbox", 900);
        var (_, newestMail) = await harness.BackupAsync(mailbox);
        Assert.NotEqual(mailSnapshot, newestMail);

        var (_, exported) = await harness.RestoreAsync(mailbox, newestMail, new RestoreSelection([], await FoldersAsync(harness, mailbox)), RestoreModes.Export);
        Assert.Equal("succeeded", exported.State);
        var platform = await ZipAsync(harness.ExportStore);
        Assert.Contains(platform.Keys, k => k.EndsWith(".eml", StringComparison.Ordinal));
        Assert.Contains(platform.Keys, k => k.EndsWith(".ics", StringComparison.Ordinal));
        Assert.Contains(platform.Keys, k => k.EndsWith(".vcf", StringComparison.Ordinal));

        // Recovery: only the object store and the master key. No connection string anywhere.
        var outDir = Path.Combine(Path.GetTempPath(), "vaulty-recover-" + Guid.NewGuid().ToString("N"));
        try
        {
            var keyFile = Path.Combine(Path.GetTempPath(), "vaulty-recover-key-" + Guid.NewGuid().ToString("N"));
            await File.WriteAllTextAsync(keyFile, Convert.ToBase64String(harness.MasterKey));
            var storeCopy = Path.Combine(outDir + "-store");
            foreach (var key in harness.Store.Keys)
            {
                var path = Path.Combine(storeCopy, key.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                await File.WriteAllBytesAsync(path, harness.Store.Raw(key));
            }
            using var log = new StringWriter();
            using var errors = new StringWriter();
            var exit = await RecoverCommand.RunAsync(
                ["--tenant", harness.Tenant.ToString(), "--out", outDir, "--master-key-file", keyFile, "--store-dir", storeCopy], log, errors, _ => null);
            output.WriteLine(log.ToString());
            Assert.True(exit == 0, errors.ToString());
            File.Delete(keyFile);

            var recovered = Files(Path.Combine(outDir, mailbox.ToString("D"), newestMail.ToString("D")));
            Assert.Equal(platform.Keys.Order(StringComparer.Ordinal), recovered.Keys.Order(StringComparer.Ordinal));
            foreach (var (path, hash) in platform) Assert.True(hash == recovered[path], $"{path} differs from the platform export");

            using var report = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(outDir, "recovery-report.json")));
            var objects = report.RootElement.GetProperty("objects");
            Assert.Equal(1, objects.GetArrayLength());
            Assert.Equal(newestMail.ToString(), objects[0].GetProperty("snapshot_id").GetString());
            Assert.All(objects[0].GetProperty("items").EnumerateArray(), i => Assert.NotEqual("failed", i.GetProperty("state").GetString()));
            Assert.Contains("Data keys of tenant", log.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(outDir)) Directory.Delete(outDir, recursive: true);
            if (Directory.Exists(outDir + "-store")) Directory.Delete(outDir + "-store", recursive: true);
        }
    }

    [TemporalFact]
    public async Task Files_are_rebuilt_byte_for_byte_and_a_corrupted_chunk_is_reported_not_written()
    {
        using var simulator = new DriveSimulator(files: 40, seed: 5);
        await using var harness = new BackupHarness(fixture, simulator.Url, DriveBackupTests.Source(simulator));
        await harness.SeedTenantAsync();
        var drive = await harness.SeedDriveAsync(DriveSimulator.DriveId);
        harness.StartWorker();
        var (_, snapshot) = await harness.DriveBackupAsync(drive);
        var (_, exported) = await harness.RestoreAsync(drive, snapshot, new RestoreSelection([], await FoldersAsync(harness, drive)), RestoreModes.Export);
        Assert.Equal("succeeded", exported.State);
        var platform = await ZipAsync(harness.ExportStore);
        Assert.True(platform.Count >= 20, $"{platform.Count} files exported");

        var outDir = Path.Combine(Path.GetTempPath(), "vaulty-recover-" + Guid.NewGuid().ToString("N"));
        try
        {
            var report = await TenantRecovery.RunAsync(harness.Store, harness.MasterKey, new RecoveryRequest(harness.Tenant, outDir), TextWriter.Null);
            var recovered = Files(Path.Combine(outDir, drive.ToString("D"), snapshot.ToString("D")));
            // The export held the folders that were selected; recovery holds the whole drive, root files included.
            foreach (var (path, hash) in platform) Assert.True(recovered.TryGetValue(path, out var got) && got == hash, $"{path} differs from the platform export");
            Assert.Equal(simulator.Nodes.Values.Count(n => !n.IsFolder), recovered.Count);
            Assert.Equal(0, report.Failed);

            // Every file of the drive is in one or a few packs; damage one, and recovery reports the items it breaks.
            var pack = harness.Store.Keys.First(k => k.Contains("/packs/", StringComparison.Ordinal));
            harness.Store.CorruptBit(pack, harness.Store.Raw(pack).Length / 2, bit: 1);
            var again = Path.Combine(outDir, "again");
            var damaged = await TenantRecovery.RunAsync(harness.Store, harness.MasterKey, new RecoveryRequest(harness.Tenant, again), TextWriter.Null);
            Assert.True(damaged.Failed > 0, "a corrupted chunk went unnoticed");
            var written = Files(Path.Combine(again, drive.ToString("D"), snapshot.ToString("D")));
            Assert.Empty(Directory.EnumerateFiles(again, "*.partial", SearchOption.AllDirectories));
            // What was written is still exactly right; what failed is missing, never wrong.
            foreach (var (path, hash) in written) Assert.Equal(recovered[path], hash);
            Assert.Equal(recovered.Count - damaged.Failed, written.Count);

            // The wrong master key opens nothing.
            var wrong = await Assert.ThrowsAsync<RecoveryException>(() =>
                TenantRecovery.RunAsync(harness.Store, RandomNumberGenerator.GetBytes(32), new RecoveryRequest(harness.Tenant, Path.Combine(outDir, "wrong")), TextWriter.Null));
            Assert.Contains("cannot be unwrapped", wrong.Message, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(outDir)) Directory.Delete(outDir, recursive: true);
        }
    }

    [Fact]
    public async Task The_command_line_explains_itself_and_refuses_incomplete_options()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(0, await RecoverCommand.RunAsync(["--help"], output, error, _ => null));
        Assert.Contains("without the Vaulty database", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, await RecoverCommand.RunAsync(["--tenant", Guid.NewGuid().ToString()], output, error, _ => null));
        Assert.Contains("--out is required", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, await RecoverCommand.RunAsync(["--tenant", Guid.NewGuid().ToString(), "--out", "x", "--store-dir", "y", "--bucket", "b"], output, error, _ => null));
        Assert.Contains("not both", error.ToString(), StringComparison.Ordinal);
        Assert.Throws<NotSupportedException>(() => new DirectoryObjectStore(Path.GetTempPath()).DeleteAsync("tenants/x").GetAwaiter().GetResult());
    }
}
