using System.IO.Compression;
using Vaulty.Connectors.Drive;
using Vaulty.Infrastructure.Restore;

namespace Vaulty.Integration.Tests.Restore;

public sealed class ExportWriterTests
{
    [Theory]
    [InlineData("..", "_")]
    [InlineData(".", "_")]
    [InlineData("", "_")]
    [InlineData("report.  ", "report")]
    [InlineData("a<b>c:d\"e|f?g*h", "a_b_c_d_e_f_g_h")]
    [InlineData(@"C:\Windows\system.ini", "C__Windows_system.ini")]
    [InlineData("../../etc/passwd", ".._.._etc_passwd")]
    public void One_name_becomes_one_safe_segment(string name, string expected) => Assert.Equal(expected, ExportWriter.SafeSegment(name));

    [Theory]
    [InlineData("../../etc", "passwd")]
    [InlineData("/absolute/folder", "name.txt")]
    [InlineData("Inbox/./../..", "..")]
    public void Paths_from_Microsoft_365_never_leave_the_export(string folder, string name)
    {
        var path = ExportWriter.Join(folder, name);
        Assert.False(Path.IsPathRooted(path));
        Assert.All(path.Split('/'), segment => Assert.False(segment is ".." or "." or "", path));
    }

    [Fact]
    public async Task Duplicate_names_get_a_number_and_the_zip_uses_store_mode()
    {
        using var buffer = new MemoryStream();
        await using (var writer = new ExportWriter(buffer))
        {
            for (var i = 0; i < 3; i++)
            {
                var item = new PendingItem(Guid.NewGuid(), $"file-{i}", "file", "p", "Docs", null, 3, DateTimeOffset.UtcNow, "{\"name\":\"same.txt\"}",
                    new Vaulty.Repository.Format.ItemContent(3, [], []), null, null, false);
                await writer.AddAsync(item, s => s.WriteAsync("abc"u8.ToArray()).AsTask(), () => Task.FromResult<string?>(null));
            }
            await writer.FinishAsync();
        }
        buffer.Position = 0;
        using var zip = new ZipArchive(buffer, ZipArchiveMode.Read);
        Assert.Equal(["Docs/same (2).txt", "Docs/same (3).txt", "Docs/same.txt", "manifest.json"], zip.Entries.Select(e => e.FullName).Order(StringComparer.Ordinal));
        Assert.All(zip.Entries, e => Assert.Equal(e.Length, e.CompressedLength));
    }

    [Theory]
    [InlineData("Report.docx", "Report (restored 2026-11-09).docx")]
    [InlineData("archive.tar.gz", "archive.tar (restored 2026-11-09).gz")]
    [InlineData("README", "README (restored 2026-11-09)")]
    [InlineData(".gitignore", ".gitignore (restored 2026-11-09)")]
    public void A_restored_file_next_to_an_existing_one_says_so_in_its_name(string name, string expected) =>
        Assert.Equal(expected, DriveRestoreClient.RestoredName(name, new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero)));

    [Theory]
    [InlineData("..", "item")]
    [InlineData("name.", "name")]
    [InlineData("a:b", "a_b")]
    public void Drive_names_are_made_acceptable(string name, string expected) => Assert.Equal(expected, DriveRestoreClient.SafeName(name));
}
