namespace Vaulty.Workflows;

/// <summary>
/// Keeps an activity alive during a step that cannot report progress itself, such as committing a snapshot: without a
/// heartbeat within the heartbeat timeout, Temporal declares the worker dead and starts the activity again while the
/// first attempt still runs. The start-to-close timeout of the activity still bounds a step that never ends.
/// </summary>
public static class Heartbeats
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(10);

    public static async Task<T> WhileRunningAsync<T>(Action heartbeat, Func<Task<T>> step, TimeSpan? interval = null)
    {
        ArgumentNullException.ThrowIfNull(heartbeat);
        ArgumentNullException.ThrowIfNull(step);
        using var stop = new CancellationTokenSource();
        var beating = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(interval ?? Interval);
            try
            {
                while (await timer.WaitForNextTickAsync(stop.Token).ConfigureAwait(false)) heartbeat();
            }
            catch (OperationCanceledException)
            {
                // The step finished.
            }
        });
        try
        {
            return await step().ConfigureAwait(false);
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(false);
            await beating.ConfigureAwait(false);
        }
    }
}
