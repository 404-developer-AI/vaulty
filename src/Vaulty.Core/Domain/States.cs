namespace Vaulty.Core.Domain;

/// <summary>State of a snapshot. Stored as lower-case text.</summary>
public enum SnapshotState
{
    /// <summary>Data is being written; the snapshot is not visible and not restorable yet.</summary>
    Staged,
    /// <summary>Every item the source reported is in the snapshot and the new data was verified.</summary>
    Committed,
    /// <summary>Committed, but at least one item is missing with a known reason. Never shown as green.</summary>
    Partial,
    /// <summary>No snapshot could be committed.</summary>
    Failed,
    /// <summary>Retention ended and garbage collection removed the data.</summary>
    Expired,
}

/// <summary>State of a protected object.</summary>
public enum ProtectedObjectState
{
    Active,
    /// <summary>The source no longer exists in Microsoft 365; snapshots are kept within retention.</summary>
    SourceDeleted,
    Paused,
    /// <summary>Discovered, but not backed up yet (for example archive mailboxes that Graph cannot export).</summary>
    NotProtected,
}

public enum ProtectedObjectKind
{
    Mailbox,
    Drive,
    Site,
    Team,
    Directory,
}

public enum ItemState
{
    Staged,
    Committed,
}

public enum PackState
{
    Staged,
    Committed,
    Deleted,
}

public enum ConsentState
{
    Pending,
    Granted,
    Lost,
}

public enum TenantAuthMode
{
    /// <summary>An app registration inside the customer's tenant, authenticated with a certificate Vaulty generated.</summary>
    DedicatedApp,
    /// <summary>A multi-tenant app with admin consent (later).</summary>
    SharedApp,
}

public enum TenantState
{
    Active,
    /// <summary>Deletion requested; waits 30 days and a second administrator.</summary>
    DeletionRequested,
    Deleted,
}

public enum JobKind
{
    Discovery,
    Backup,
    Restore,
    Export,
    Verification,
    GarbageCollection,
}

public enum JobState
{
    Queued,
    Running,
    Succeeded,
    Partial,
    Failed,
    Cancelled,
}

/// <summary>Thrown when a state machine is asked for a transition it does not allow.</summary>
public sealed class InvalidStateTransitionException(string machine, string from, string to)
    : InvalidOperationException($"{machine}: transition from '{from}' to '{to}' is not allowed.");

/// <summary>The allowed transitions of the persisted state machines. The database stores the result; code asks here first.</summary>
public static class StateMachines
{
    private static readonly Dictionary<SnapshotState, SnapshotState[]> SnapshotTransitions = new()
    {
        [SnapshotState.Staged] = [SnapshotState.Committed, SnapshotState.Partial, SnapshotState.Failed],
        [SnapshotState.Committed] = [SnapshotState.Expired],
        [SnapshotState.Partial] = [SnapshotState.Expired],
        [SnapshotState.Failed] = [],
        [SnapshotState.Expired] = [],
    };

    private static readonly Dictionary<ProtectedObjectState, ProtectedObjectState[]> ObjectTransitions = new()
    {
        [ProtectedObjectState.NotProtected] = [ProtectedObjectState.Active, ProtectedObjectState.SourceDeleted],
        [ProtectedObjectState.Active] = [ProtectedObjectState.Paused, ProtectedObjectState.SourceDeleted],
        [ProtectedObjectState.Paused] = [ProtectedObjectState.Active, ProtectedObjectState.SourceDeleted],
        // A source that reappears (restored user) is protected again.
        [ProtectedObjectState.SourceDeleted] = [ProtectedObjectState.Active],
    };

    private static readonly Dictionary<JobState, JobState[]> JobTransitions = new()
    {
        [JobState.Queued] = [JobState.Running, JobState.Cancelled, JobState.Failed],
        [JobState.Running] = [JobState.Succeeded, JobState.Partial, JobState.Failed, JobState.Cancelled],
        [JobState.Succeeded] = [],
        [JobState.Partial] = [],
        [JobState.Failed] = [],
        [JobState.Cancelled] = [],
    };

    public static bool CanTransition(SnapshotState from, SnapshotState to) => SnapshotTransitions[from].Contains(to);

    public static bool CanTransition(ProtectedObjectState from, ProtectedObjectState to) =>
        ObjectTransitions[from].Contains(to);

    public static bool CanTransition(JobState from, JobState to) => JobTransitions[from].Contains(to);

    public static SnapshotState Transition(SnapshotState from, SnapshotState to) =>
        CanTransition(from, to) ? to : throw new InvalidStateTransitionException("snapshot", from.ToString(), to.ToString());

    public static ProtectedObjectState Transition(ProtectedObjectState from, ProtectedObjectState to) =>
        CanTransition(from, to)
            ? to
            : throw new InvalidStateTransitionException("protected object", from.ToString(), to.ToString());

    public static JobState Transition(JobState from, JobState to) =>
        CanTransition(from, to) ? to : throw new InvalidStateTransitionException("job", from.ToString(), to.ToString());

    /// <summary>A committed or partial snapshot can be restored; nothing else can.</summary>
    public static bool IsRestorable(SnapshotState state) => state is SnapshotState.Committed or SnapshotState.Partial;
}

/// <summary>Converts state enums to and from the snake_case text the database stores.</summary>
public static class StateText
{
    public static string ToText<T>(T value) where T : struct, Enum => ToSnake(value.ToString());

    public static T Parse<T>(string text) where T : struct, Enum =>
        Enum.Parse<T>(text.Replace("_", "", StringComparison.Ordinal), ignoreCase: true);

    private static string ToSnake(string name)
    {
        var sb = new System.Text.StringBuilder(name.Length + 4);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c))
            {
                if (i > 0) sb.Append('_');
                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }
}
