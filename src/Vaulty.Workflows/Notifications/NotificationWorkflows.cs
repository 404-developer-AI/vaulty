using Temporalio.Activities;
using Temporalio.Workflows;
using Vaulty.Infrastructure.Notifications;

namespace Vaulty.Workflows.Notifications;

public sealed record NotificationSummary(int MissedRuns, int Deliveries, int Webhooks, int Mails, int Digests);

/// <summary>
/// Every minute: missed runs, webhook fan-out and delivery, alert mail and the daily digest. Each step is its own activity,
/// so a failing SMTP server never holds up webhooks, and a missed run is alerted within the grace period plus a minute.
/// </summary>
[Workflow]
public sealed class NotificationSweepWorkflow
{
    public const string Id = "notification-sweep";
    public const string Cron = "* * * * *";

    [WorkflowRun]
    public async Task<NotificationSummary> RunAsync()
    {
        var policy = ActivityPolicies.Database();
        var missed = await Safe(() => Workflow.ExecuteActivityAsync((NotificationActivities a) => a.MissedRunsAsync(), policy));
        var deliveries = await Safe(() => Workflow.ExecuteActivityAsync((NotificationActivities a) => a.FanOutAsync(), policy));
        var webhooks = await Safe(() => Workflow.ExecuteActivityAsync((NotificationActivities a) => a.WebhooksAsync(), ActivityPolicies.External(TimeSpan.FromMinutes(10))))
            ;
        var mails = await Safe(() => Workflow.ExecuteActivityAsync((NotificationActivities a) => a.MailAsync(), ActivityPolicies.External(TimeSpan.FromMinutes(10))))
            ;
        var digests = await Safe(() => Workflow.ExecuteActivityAsync((NotificationActivities a) => a.DigestAsync(), ActivityPolicies.External(TimeSpan.FromMinutes(20))))
            ;
        return new NotificationSummary(missed, deliveries, webhooks, mails, digests);
    }

    private static async Task<int> Safe(Func<Task<int>> step)
    {
        try
        {
            return await step();
        }
        catch (Temporalio.Exceptions.ActivityFailureException)
        {
            return -1; // the next minute tries again
        }
    }
}

public sealed class NotificationActivities(NotificationDispatcher dispatcher)
{
    [Activity("NotifyMissedRuns")]
    public Task<int> MissedRunsAsync() => dispatcher.FindMissedRunsAsync(ActivityExecutionContext.Current.CancellationToken);

    [Activity("NotifyFanOut")]
    public Task<int> FanOutAsync() => dispatcher.FanOutEventsAsync(ActivityExecutionContext.Current.CancellationToken);

    [Activity("NotifyWebhooks")]
    public Task<int> WebhooksAsync() => dispatcher.DeliverWebhooksAsync(ActivityExecutionContext.Current.CancellationToken);

    [Activity("NotifyMail")]
    public Task<int> MailAsync() => dispatcher.MailAlertsAsync(ActivityExecutionContext.Current.CancellationToken);

    [Activity("NotifyDigest")]
    public Task<int> DigestAsync() => dispatcher.SendDigestsAsync(ActivityExecutionContext.Current.CancellationToken);
}
