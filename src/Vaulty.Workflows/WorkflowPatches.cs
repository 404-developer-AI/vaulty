namespace Vaulty.Workflows;

/// <summary>
/// Markers for changes to workflow code. A workflow that is running during an update is replayed on the new code from its
/// recorded history, and fails (and retries without end) when the new code issues different commands than the history holds.
/// So every change that adds, removes or reorders an activity, local activity, timer or child workflow is put behind
/// <c>Workflow.Patched(marker)</c>: runs started on the old code take the old path, new runs the new one. A marker is only
/// removed once no run that started without it can still be open. The replay test checks recorded histories of earlier
/// versions against the current code.
/// </summary>
public static class WorkflowPatches
{
    /// <summary>A child workflow no longer writes the job of its parent (runs started before this mirrored it too).</summary>
    public const string ChildSkipsJobMirror = "child-skips-job-mirror";
}
