using System.Text.Json;
using Temporalio.Common;
using Temporalio.Worker;
using Vaulty.Workflows.Backup;
using Vaulty.Workflows.Jobs;

namespace Vaulty.Integration.Tests.Temporal;

/// <summary>
/// A workflow that runs during an update is replayed on the new code. Every recorded history of an earlier version
/// (<c>Temporal/Histories/&lt;version&gt;/</c>) must replay on the current code without a nondeterminism error; a change that
/// breaks this belongs behind a marker in <see cref="Vaulty.Workflows.WorkflowPatches"/>.
/// </summary>
public sealed class WorkflowReplayTests
{
    private static readonly string Folder = Path.Combine(AppContext.BaseDirectory, "Temporal", "Histories");

    [Fact]
    public async Task Recorded_histories_of_earlier_versions_replay_on_the_current_code()
    {
        var files = Directory.GetFiles(Folder, "*.json", SearchOption.AllDirectories);
        Assert.NotEmpty(files);
        var replayer = new WorkflowReplayer(new WorkflowReplayerOptions { Interceptors = [new JobMirrorInterceptor()] }
            .AddWorkflow<MailboxBackupWorkflow>().AddWorkflow<FolderBackupWorkflow>()
            .AddWorkflow<DriveBackupWorkflow>().AddWorkflow<DriveSyncWorkflow>()
            .AddWorkflow<Vaulty.Workflows.Restore.RestoreWorkflow>());
        var failures = new List<string>();
        foreach (var file in files)
        {
            var json = await File.ReadAllTextAsync(file);
            var history = WorkflowHistory.FromJson(WorkflowIdOf(json), json);
            var result = await replayer.ReplayWorkflowAsync(history, throwOnReplayFailure: false);
            if (result.ReplayFailure is { } failure) failures.Add($"{Path.GetRelativePath(Folder, file)}: {failure.Message}");
        }
        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void Every_backup_workflow_type_has_a_recorded_history_of_the_latest_version()
    {
        var latest = Directory.GetDirectories(Folder).OrderBy(d => Version(Path.GetFileName(d))).Last();
        foreach (var type in new[] { "MailboxBackupWorkflow", "FolderBackupWorkflow", "DriveBackupWorkflow", "DriveSyncWorkflow", "RestoreWorkflow" })
        {
            Assert.True(File.Exists(Path.Combine(latest, $"{type}.json")), $"{type} has no history in {Path.GetFileName(latest)}");
        }
    }

    /// <summary>
    /// The workflow id the run had: child step ids are derived from it ("{id}/..."), so a replay under another id issues
    /// other commands. A run without child steps does not depend on its id.
    /// </summary>
    private static string WorkflowIdOf(string historyJson)
    {
        using var document = JsonDocument.Parse(historyJson);
        foreach (var e in document.RootElement.GetProperty("events").EnumerateArray())
        {
            if (e.TryGetProperty("startChildWorkflowExecutionInitiatedEventAttributes", out var child))
            {
                return child.GetProperty("workflowId").GetString()!.Split('/')[0];
            }
        }
        return "replay";
    }

    /// <summary>"v0.1.0-alpha.11" sorts after "v0.1.0-alpha.5".</summary>
    private static (int, int, int, int) Version(string name)
    {
        var parts = name.TrimStart('v').Split('-', 2);
        var core = parts[0].Split('.').Select(int.Parse).ToArray();
        var pre = parts.Length > 1 && int.TryParse(parts[1].Split('.').Last(), out var n) ? n : int.MaxValue;
        return (core[0], core[1], core[2], pre);
    }
}
