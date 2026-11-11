using System.Text.RegularExpressions;
using Temporalio.Client;

namespace Vaulty.Integration.Tests.Temporal;

/// <summary>
/// Records workflow histories for the replay test. With <c>VAULTY_CAPTURE_HISTORIES</c> set to a folder, every test
/// harness writes one completed history per workflow type of its task queue there (a type already present is kept). The
/// histories of a released version go to <c>Temporal/Histories/&lt;version&gt;/</c>; they hold test data only.
/// </summary>
internal static partial class HistoryCapture
{
    [GeneratedRegex(@"""identity"":\s*""[^""]*""")]
    private static partial Regex Identity();

    public static async Task CaptureAsync(ITemporalClient client, string queue)
    {
        var folder = Environment.GetEnvironmentVariable("VAULTY_CAPTURE_HISTORIES");
        if (string.IsNullOrEmpty(folder)) return;
        Directory.CreateDirectory(folder);
        await foreach (var run in client.ListWorkflowsAsync($"TaskQueue = '{queue}' AND ExecutionStatus = 'Completed'"))
        {
            var path = Path.Combine(folder, $"{run.WorkflowType}.json");
            if (File.Exists(path)) continue;
            var history = await client.GetWorkflowHandle(run.Id, run.RunId).FetchHistoryAsync();
            // The worker identity and sticky queue names carry the machine that ran the test; neither plays a part in a replay.
            var json = Identity().Replace(history.ToJson(), "\"identity\": \"test-worker\"")
                .Replace(Environment.MachineName, "test-host", StringComparison.OrdinalIgnoreCase);
            await File.WriteAllTextAsync(path, json);
        }
    }
}
