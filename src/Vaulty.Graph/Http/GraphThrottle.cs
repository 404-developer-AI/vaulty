using System.Collections.Concurrent;

namespace Vaulty.Graph.Http;

public sealed record GraphThrottleOptions
{
    /// <summary>Exchange allows four concurrent requests per mailbox per app.</summary>
    public int PerMailboxConcurrency { get; init; } = 4;

    /// <summary>Concurrent Graph requests of this process over all tenants.</summary>
    public int GlobalConcurrency { get; init; } = 256;

    /// <summary>Requests per second per tenant at start; adapts between the minimum and maximum.</summary>
    public double InitialTenantRate { get; init; } = 20;
    public double MinimumTenantRate { get; init; } = 0.5;
    public double MaximumTenantRate { get; init; } = 100;

    /// <summary>Rate added per successful request (additive increase) and factor applied on throttling (multiplicative decrease).</summary>
    public double RateIncrease { get; init; } = 0.1;
    public double RateDecreaseFactor { get; init; } = 0.5;

    /// <summary>
    /// Throttling responses within this window count as one event: concurrent requests that are throttled together lower
    /// the rate once, not once each.
    /// </summary>
    public TimeSpan DecreaseCooldown { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Attempts per request before the throttling response is returned to the caller.</summary>
    public int MaxAttempts { get; init; } = 100;

    /// <summary>Wait when a throttling response carries no Retry-After (doubled per attempt, capped).</summary>
    public TimeSpan DefaultBackoff { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan MaximumBackoff { get; init; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// Shared throttling state of all Graph traffic in a process: a global concurrency cap, four concurrent requests per
/// mailbox, and an adaptive token bucket per tenant that halves its rate on every throttling response and slowly grows
/// on success (AIMD). A Retry-After pauses the tenant (or the mailbox) for exactly that long.
/// </summary>
public sealed class GraphThrottle
{
    private readonly GraphThrottleOptions _options;
    private readonly TimeProvider _clock;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly SemaphoreSlim _global;
    private readonly ConcurrentDictionary<(Guid, string), SemaphoreSlim> _mailboxes = new();
    private readonly ConcurrentDictionary<(Guid, string), DateTimeOffset> _mailboxPauses = new();
    private readonly ConcurrentDictionary<Guid, TenantBucket> _tenants = new();

    public GraphThrottle(GraphThrottleOptions? options = null, TimeProvider? clock = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _options = options ?? new GraphThrottleOptions();
        _clock = clock ?? TimeProvider.System;
        _delay = delay ?? ((wait, ct) => Task.Delay(wait, _clock, ct));
        _global = new SemaphoreSlim(_options.GlobalConcurrency);
    }

    public GraphThrottleOptions Options => _options;

    internal Func<TimeSpan, CancellationToken, Task> Delay => _delay;

    public double CurrentRate(Guid tenantId) => Bucket(tenantId).Rate;

    public long ThrottledResponses(Guid tenantId) => Bucket(tenantId).Throttled;

    public long SuccessfulResponses(Guid tenantId) => Bucket(tenantId).Succeeded;

    /// <summary>Waits for a slot; dispose the lease when the response headers have been received.</summary>
    public async Task<IDisposable> AcquireAsync(GraphRequestContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var bucket = Bucket(context.TenantId);
        await bucket.TakeAsync(_clock, _delay, cancellationToken).ConfigureAwait(false);

        SemaphoreSlim? mailbox = null;
        if (context.Mailbox is { } m)
        {
            var key = (context.TenantId, m);
            while (_mailboxPauses.TryGetValue(key, out var until) && until > _clock.GetUtcNow())
            {
                await _delay(until - _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
            }
            mailbox = _mailboxes.GetOrAdd(key, _ => new SemaphoreSlim(_options.PerMailboxConcurrency));
            await mailbox.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        try
        {
            await _global.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            mailbox?.Release();
            throw;
        }
        return new Lease(_global, mailbox);
    }

    public void OnSuccess(GraphRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        Bucket(context.TenantId).Increase(_options);
    }

    /// <summary>Records a throttling response: lower the tenant rate and pause for the Retry-After.</summary>
    public void OnThrottled(GraphRequestContext context, TimeSpan wait)
    {
        ArgumentNullException.ThrowIfNull(context);
        var until = _clock.GetUtcNow() + wait;
        Bucket(context.TenantId).Decrease(_options, _clock.GetUtcNow(), context.Mailbox is null ? until : null);
        if (context.Mailbox is { } m)
        {
            _mailboxPauses.AddOrUpdate((context.TenantId, m), until, (_, existing) => existing > until ? existing : until);
        }
    }

    private TenantBucket Bucket(Guid tenantId) => _tenants.GetOrAdd(tenantId, _ => new TenantBucket(_options.InitialTenantRate));

    private sealed class Lease(SemaphoreSlim global, SemaphoreSlim? mailbox) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
            global.Release();
            mailbox?.Release();
        }
    }

    private sealed class TenantBucket(double rate)
    {
        private readonly Lock _lock = new();
        private double _tokens = 1;
        private DateTimeOffset _last = DateTimeOffset.MinValue;
        private DateTimeOffset _pausedUntil = DateTimeOffset.MinValue;
        private DateTimeOffset _lastDecrease = DateTimeOffset.MinValue;

        public double Rate { get; private set; } = rate;
        public long Throttled;
        public long Succeeded;

        public async Task TakeAsync(TimeProvider clock, Func<TimeSpan, CancellationToken, Task> delay, CancellationToken cancellationToken)
        {
            while (true)
            {
                TimeSpan wait;
                lock (_lock)
                {
                    var now = clock.GetUtcNow();
                    if (_last == DateTimeOffset.MinValue) _last = now;
                    _tokens = Math.Min(Math.Max(1, Rate), _tokens + (now - _last).TotalSeconds * Rate);
                    _last = now;
                    if (_pausedUntil > now)
                    {
                        wait = _pausedUntil - now;
                    }
                    else if (_tokens >= 1)
                    {
                        _tokens -= 1;
                        return;
                    }
                    else
                    {
                        wait = TimeSpan.FromSeconds((1 - _tokens) / Rate);
                    }
                }
                await delay(wait, cancellationToken).ConfigureAwait(false);
            }
        }

        public void Increase(GraphThrottleOptions options)
        {
            Interlocked.Increment(ref Succeeded);
            lock (_lock) Rate = Math.Min(options.MaximumTenantRate, Rate + options.RateIncrease);
        }

        public void Decrease(GraphThrottleOptions options, DateTimeOffset now, DateTimeOffset? pauseUntil)
        {
            Interlocked.Increment(ref Throttled);
            lock (_lock)
            {
                if (now - _lastDecrease >= options.DecreaseCooldown)
                {
                    Rate = Math.Max(options.MinimumTenantRate, Rate * options.RateDecreaseFactor);
                    _lastDecrease = now;
                }
                _tokens = Math.Min(_tokens, 0);
                if (pauseUntil is { } until && until > _pausedUntil) _pausedUntil = until;
            }
        }
    }
}
