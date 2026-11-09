using Vaulty.Core.Domain;
using Vaulty.Core.Security;

namespace Vaulty.Core.Tests;

public class PermissionTests
{
    [Fact]
    public void Keys_are_unique_and_requirements_exist()
    {
        Assert.Equal(Permissions.All.Count, Permissions.All.Select(p => p.Key).Distinct(StringComparer.Ordinal).Count());
        foreach (var permission in Permissions.All)
        {
            Assert.Matches(@"^[a-z]+\.[a-z]+$", permission.Key);
            Assert.All(permission.Requires, r => Assert.True(Permissions.Exists(r), $"{permission.Key} requires unknown {r}"));
        }
    }

    [Fact]
    public void Built_in_roles_are_closed_under_their_requirements()
    {
        foreach (var (name, keys) in BuiltInRoles.All)
        {
            var closure = Permissions.Closure(keys);
            Assert.True(closure.SetEquals(keys), $"{name} misses a required permission");
        }
    }

    [Fact]
    public void Restore_and_export_require_mfa_and_other_location_requires_step_up()
    {
        Assert.True(Permissions.Get(Permissions.RestoreInPlace).RequiresMfa);
        Assert.True(Permissions.Get(Permissions.RestoreOtherLocation).RequiresStepUp);
        Assert.True(Permissions.Get(Permissions.ExportCreate).RequiresStepUp);
        Assert.False(Permissions.AnyRequiresMfa(BuiltInRoles.ReadOnlyPermissions));
        Assert.True(Permissions.AnyRequiresMfa(BuiltInRoles.RestoreOperatorPermissions));
    }
}

public class StateMachineTests
{
    [Fact]
    public void Snapshot_goes_from_staged_to_committed_partial_or_failed_only()
    {
        Assert.Equal(SnapshotState.Committed, StateMachines.Transition(SnapshotState.Staged, SnapshotState.Committed));
        Assert.Equal(SnapshotState.Partial, StateMachines.Transition(SnapshotState.Staged, SnapshotState.Partial));
        Assert.Throws<InvalidStateTransitionException>(() =>
            StateMachines.Transition(SnapshotState.Partial, SnapshotState.Committed));
        Assert.Throws<InvalidStateTransitionException>(() =>
            StateMachines.Transition(SnapshotState.Failed, SnapshotState.Committed));
        Assert.True(StateMachines.IsRestorable(SnapshotState.Partial));
        Assert.False(StateMachines.IsRestorable(SnapshotState.Staged));
    }

    [Fact]
    public void Source_deleted_object_can_return_and_jobs_never_reopen()
    {
        Assert.True(StateMachines.CanTransition(ProtectedObjectState.SourceDeleted, ProtectedObjectState.Active));
        Assert.False(StateMachines.CanTransition(JobState.Failed, JobState.Running));
    }

    [Theory]
    [InlineData(ProtectedObjectState.SourceDeleted, "source_deleted")]
    [InlineData(ProtectedObjectState.NotProtected, "not_protected")]
    [InlineData(ProtectedObjectState.Active, "active")]
    public void State_text_round_trips(ProtectedObjectState state, string text)
    {
        Assert.Equal(text, StateText.ToText(state));
        Assert.Equal(state, StateText.Parse<ProtectedObjectState>(text));
    }
}
