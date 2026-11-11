using Vaulty.Infrastructure.Access;
using Vaulty.Workflows.Tenants;

namespace Vaulty.Web.Account;

/// <summary>Pauses a restore or export through its workflow; it stops after the items in progress and waits.</summary>
public sealed class WorkflowRestorePauser(IWorkflowStarter workflows, ILogger<WorkflowRestorePauser> logger) : IRestorePauser
{
    public async Task PauseAsync(Guid restoreId, CancellationToken cancellationToken = default)
    {
        try
        {
            await workflows.SignalRestoreAsync(restoreId, "pause", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or Temporalio.Exceptions.TemporalException)
        {
            // The audit log already records the pause; an unreachable orchestrator is logged and the job page shows it running.
            logger.LogWarning("Pausing restore {RestoreId} after a change of access failed: {Error}", restoreId, ex.GetType().Name);
        }
    }
}
