using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using Vaulty.Core;
using Vaulty.Graph.Auth;

namespace Vaulty.Graph.Http;

/// <summary>Request decoration: the ISV user agent Microsoft asks for, and a client-request-id per attempt.</summary>
public sealed class DecorationHandler : DelegatingHandler
{
    public static string UserAgent { get; } = $"ISV|Steaan|Vaulty/{ProductInfo.Version}";

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Headers.Remove("User-Agent");
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
        request.Headers.Remove("client-request-id");
        request.Headers.TryAddWithoutValidation("client-request-id", Guid.NewGuid().ToString());
        return base.SendAsync(request, cancellationToken);
    }
}

/// <summary>Adds the app-only token of the request's tenant; on 401 refreshes the token once.</summary>
public sealed class AuthenticationHandler(IGraphTokenProvider tokens) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var context = GraphRequestContext.From(request);
        var token = await tokens.GetTokenAsync(context.TenantId, false, cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized || request.Content is not (null or ByteArrayContent)) return response;

        response.Dispose();
        token = await tokens.GetTokenAsync(context.TenantId, true, cancellationToken).ConfigureAwait(false);
        using var retry = await GraphRequests.CloneAsync(request, cancellationToken).ConfigureAwait(false);
        retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Throttling is normal behaviour, never an error: 429, 503 and 504 wait for Retry-After (exactly) or a capped
/// exponential backoff, lower the tenant's rate and try again. The caller only sees a throttling response after
/// <see cref="GraphThrottleOptions.MaxAttempts"/> attempts.
/// </summary>
public sealed class ThrottlingHandler(GraphThrottle throttle) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var context = GraphRequestContext.From(request);
        await GraphRequests.BufferContentAsync(request, cancellationToken).ConfigureAwait(false);
        for (var attempt = 1; ; attempt++)
        {
            using var attemptRequest = attempt == 1 ? null : await GraphRequests.CloneAsync(request, cancellationToken).ConfigureAwait(false);
            HttpResponseMessage response;
            using (await throttle.AcquireAsync(context, cancellationToken).ConfigureAwait(false))
            {
                response = await base.SendAsync(attemptRequest ?? request, cancellationToken).ConfigureAwait(false);
            }
            if (!IsThrottling(response.StatusCode) || attempt >= throttle.Options.MaxAttempts)
            {
                if (!IsThrottling(response.StatusCode)) throttle.OnSuccess(context);
                return response;
            }
            var wait = RetryAfter(response) ?? Backoff(attempt);
            GraphTelemetry.Throttled.Add(1, new KeyValuePair<string, object?>("workload", context.Workload),
                new KeyValuePair<string, object?>("status", (int)response.StatusCode));
            throttle.OnThrottled(context, wait);
            response.Dispose();
            await throttle.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
    }

    public static bool IsThrottling(HttpStatusCode status) =>
        status is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

    public static TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Headers.RetryAfter is not { } header) return null;
        if (header.Delta is { } delta) return delta < TimeSpan.Zero ? TimeSpan.Zero : delta;
        if (header.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            return wait < TimeSpan.Zero ? TimeSpan.Zero : wait;
        }
        return null;
    }

    private TimeSpan Backoff(int attempt)
    {
        var options = throttle.Options;
        var seconds = Math.Min(options.MaximumBackoff.TotalSeconds, options.DefaultBackoff.TotalSeconds * Math.Pow(2, attempt - 1));
        return TimeSpan.FromSeconds(seconds * (0.8 + Random.Shared.NextDouble() * 0.4));
    }
}

/// <summary>Per call: status, duration, bytes, throttled flag and Microsoft's request-id, without URLs or content.</summary>
public sealed class TelemetryHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var context = GraphRequestContext.From(request);
        using var activity = GraphTelemetry.Source.StartActivity("graph " + context.Workload, ActivityKind.Client);
        activity?.SetTag("vaulty.tenant", context.TenantId);
        var started = Stopwatch.GetTimestamp();
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var elapsed = Stopwatch.GetElapsedTime(started);
        var requestId = response.Headers.TryGetValues("request-id", out var values) ? values.FirstOrDefault() : null;
        activity?.SetTag("http.response.status_code", (int)response.StatusCode);
        activity?.SetTag("graph.request_id", requestId);
        var tags = new TagList { { "workload", context.Workload }, { "status", (int)response.StatusCode } };
        GraphTelemetry.Requests.Add(1, tags);
        GraphUsage.Record(context.TenantId, (int)response.StatusCode == 429);
        GraphTelemetry.Duration.Record(elapsed.TotalMilliseconds, tags);
        if (response.Content.Headers.ContentLength is { } length) GraphTelemetry.Bytes.Add(length, tags);
        return response;
    }
}

/// <summary>
/// Requests and throttled responses per tenant since the last drain, kept in memory and written to the database by the
/// worker host every minute (the 429 ratio of tenant health).
/// </summary>
public static class GraphUsage
{
    private static ConcurrentDictionary<Guid, Counts> _counts = new();

    public sealed class Counts
    {
        internal long RequestCount;
        internal long ThrottledCount;
        public long Requests => Interlocked.Read(ref RequestCount);
        public long Throttled => Interlocked.Read(ref ThrottledCount);
    }

    public static void Record(Guid tenantId, bool throttled)
    {
        if (tenantId == Guid.Empty) return;
        var counts = _counts.GetOrAdd(tenantId, _ => new Counts());
        Interlocked.Increment(ref counts.RequestCount);
        if (throttled) Interlocked.Increment(ref counts.ThrottledCount);
    }

    /// <summary>Everything counted since the previous drain; counting continues in a fresh set.</summary>
    public static IReadOnlyDictionary<Guid, (long Requests, long Throttled)> Drain()
    {
        var previous = Interlocked.Exchange(ref _counts, new ConcurrentDictionary<Guid, Counts>());
        return previous.ToDictionary(p => p.Key, p => (p.Value.Requests, p.Value.Throttled));
    }
}

public static class GraphTelemetry
{
    public static readonly ActivitySource Source = new("Vaulty.Graph");
    public static readonly Meter Meter = new("Vaulty.Graph");
    public static readonly Counter<long> Requests = Meter.CreateCounter<long>("vaulty.graph.requests");
    public static readonly Counter<long> Throttled = Meter.CreateCounter<long>("vaulty.graph.throttled");
    public static readonly Counter<long> Bytes = Meter.CreateCounter<long>("vaulty.graph.bytes", "By");
    public static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("vaulty.graph.duration", "ms");
}

internal static class GraphRequests
{
    /// <summary>Makes the request body replayable.</summary>
    public static async Task BufferContentAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Content is null or ByteArrayContent) return;
        var bytes = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var buffered = new ByteArrayContent(bytes);
        foreach (var header in request.Content.Headers) buffered.Headers.TryAddWithoutValidation(header.Key, header.Value);
        request.Content.Dispose();
        request.Content = buffered;
    }

    public static async Task<HttpRequestMessage> CloneAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri) { Version = request.Version };
        foreach (var header in request.Headers) clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        foreach (var option in request.Options) ((IDictionary<string, object?>)clone.Options)[option.Key] = option.Value;
        if (request.Content is not null)
        {
            var bytes = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            clone.Content = new ByteArrayContent(bytes);
            foreach (var header in request.Content.Headers) clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        return clone;
    }
}
