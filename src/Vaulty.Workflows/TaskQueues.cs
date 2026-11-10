using Temporalio.Common;
using Temporalio.Exceptions;
using Temporalio.Workflows;

namespace Vaulty.Workflows;

/// <summary>Task queues; each worker host serves one or more of them.</summary>
public static class TaskQueues
{
    public const string Backup = "backup";
    public const string Restore = "restore";
    public const string Verify = "verify";
    public const string Gc = "gc";

    public static readonly IReadOnlyList<string> All = [Backup, Restore, Verify, Gc];

    /// <summary>The queues of the worker processes (worker database role and storage identity).</summary>
    public static readonly IReadOnlyList<string> ForWorkers = [Backup, Restore];

    /// <summary>The queues of the gc service: the only process with the garbage-collection role and identity.</summary>
    public static readonly IReadOnlyList<string> ForGc = [Verify, Gc];
}

/// <summary>Activity options shared by the workflows.</summary>
public static class ActivityPolicies
{
    /// <summary>
    /// For activities that call Graph or object storage: a heartbeat at least every 30 seconds (a dead worker is noticed
    /// quickly), exponential backoff with a cap, and Retry-After from the activity taking precedence (see
    /// <see cref="Throttled"/>). Expressed as attempts, not time, so a long outage ends the run as partial, not stuck.
    /// </summary>
    public static ActivityOptions External(TimeSpan? startToClose = null) => new()
    {
        StartToCloseTimeout = startToClose ?? TimeSpan.FromMinutes(30),
        HeartbeatTimeout = TimeSpan.FromSeconds(30),
        RetryPolicy = new RetryPolicy
        {
            InitialInterval = TimeSpan.FromSeconds(2),
            BackoffCoefficient = 2,
            MaximumInterval = TimeSpan.FromMinutes(10),
            MaximumAttempts = 20,
            NonRetryableErrorTypes = [ErrorTypes.NonRetryable],
        },
    };

    /// <summary>For short database-only activities.</summary>
    public static ActivityOptions Database() => new()
    {
        StartToCloseTimeout = TimeSpan.FromMinutes(2),
        RetryPolicy = new RetryPolicy { InitialInterval = TimeSpan.FromSeconds(1), MaximumInterval = TimeSpan.FromMinutes(1) },
    };

    /// <summary>
    /// Thrown by an activity that was throttled: the next attempt waits exactly <paramref name="retryAfter"/> instead of
    /// the policy's backoff.
    /// </summary>
    public static ApplicationFailureException Throttled(TimeSpan retryAfter, string? message = null) =>
        new(message ?? $"Throttled; retry after {retryAfter.TotalSeconds:F0} s.", ErrorTypes.Throttled, nextRetryDelay: retryAfter);
}

public static class ErrorTypes
{
    public const string Throttled = "Throttled";
    public const string NonRetryable = "NonRetryable";
}
