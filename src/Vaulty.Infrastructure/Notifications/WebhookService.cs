using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Notifications;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Retention;

namespace Vaulty.Infrastructure.Notifications;

public sealed record WebhookRow(Guid Id, string Name, string Url, IReadOnlyList<string> Events, bool Enabled, DateTimeOffset CreatedAt);

public sealed record DeliveryRow(Guid Id, string Kind, string State, int Attempts, int? LastStatus, string? LastError, DateTimeOffset CreatedAt,
    DateTimeOffset? DeliveredAt);

/// <summary>Webhooks of an organization (settings.manage). The signing secret is shown once, at creation or rotation.</summary>
public sealed class WebhookService(NpgsqlDataSource dataSource, ISecretStore secrets, WebhookOptions? options = null)
{
    public static string SecretName(Guid webhookId) => $"webhook.{webhookId}";

    public async Task<IReadOnlyList<WebhookRow>> ListAsync(UserAccess access, CancellationToken cancellationToken = default)
    {
        Require(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, string Name, string Url, string[] Events, bool Enabled, DateTime CreatedAt)>(new CommandDefinition(
            "SELECT id, name, url, events, enabled, created_at FROM vaulty.webhooks ORDER BY created_at", transaction: session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new WebhookRow(r.Id, r.Name, r.Url, r.Events, r.Enabled, new DateTimeOffset(DateTime.SpecifyKind(r.CreatedAt, DateTimeKind.Utc)))).ToList();
    }

    /// <summary>Creates a webhook and returns its signing secret (base64), which is not shown again.</summary>
    public async Task<(Guid Id, string Secret)> CreateAsync(UserAccess access, string name, string url, IReadOnlyCollection<string> events,
        CancellationToken cancellationToken = default)
    {
        Require(access);
        ArgumentNullException.ThrowIfNull(events);
        if (string.IsNullOrWhiteSpace(name)) throw new InvalidOperationException("Give the webhook a name.");
        if (WebhookSender.Validate(url?.Trim() ?? "", options?.AllowPrivateTargets == true) is { } problem) throw new InvalidOperationException(problem);
        if (events.Count == 0 || events.Any(e => !NotificationKinds.Exists(e))) throw new InvalidOperationException("Choose at least one event.");
        var id = Guid.CreateVersion7();
        var secret = await RotateSecretAsync(id, access, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO vaulty.webhooks (id, organization_id, name, url, events, created_by) VALUES (@id, @organization, @name, @url, @events, @user)",
            new { id, organization = access.OrganizationId, name = name.Trim(), url = url!.Trim(), events = events.Distinct().ToArray(), user = access.UserId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "webhook.created", $"webhook:{id}", new { name, events }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return (id, secret);
    }

    public async Task<string> RotateAsync(UserAccess access, Guid id, CancellationToken cancellationToken = default)
    {
        Require(access);
        await EnsureExistsAsync(access, id, cancellationToken).ConfigureAwait(false);
        var secret = await RotateSecretAsync(id, access, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "webhook.secret_rotated", $"webhook:{id}", null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return secret;
    }

    public async Task SetEnabledAsync(UserAccess access, Guid id, bool enabled, CancellationToken cancellationToken = default)
    {
        Require(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.webhooks SET enabled = @enabled WHERE id = @id", new { id, enabled },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", enabled ? "webhook.enabled" : "webhook.disabled", $"webhook:{id}", null, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(UserAccess access, Guid id, CancellationToken cancellationToken = default)
    {
        Require(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("DELETE FROM vaulty.webhooks WHERE id = @id", new { id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "webhook.deleted", $"webhook:{id}", null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Queues a test event for this webhook only; it is delivered within a minute like any other.</summary>
    public async Task SendTestAsync(UserAccess access, Guid id, CancellationToken cancellationToken = default)
    {
        Require(access);
        await EnsureExistsAsync(access, id, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var eventId = Guid.CreateVersion7();
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.notification_events (id, organization_id, kind, payload, dispatched_at)
            VALUES (@eventId, @organization, 'webhook.test', @payload::jsonb, now());
            INSERT INTO vaulty.webhook_deliveries (id, organization_id, webhook_id, event_id) VALUES (@deliveryId, @organization, @id, @eventId);
            """, new
            {
                eventId, organization = access.OrganizationId, id, deliveryId = Guid.CreateVersion7(),
                payload = JsonSerializer.Serialize(new { message = "Test delivery from Vaulty. Verify the signature with your secret." }),
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DeliveryRow>> DeliveriesAsync(UserAccess access, Guid id, CancellationToken cancellationToken = default)
    {
        Require(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, string Kind, string State, int Attempts, int? LastStatus, string? LastError, DateTime CreatedAt,
            DateTime? DeliveredAt)>(new CommandDefinition(
            """
            SELECT d.id, e.kind, d.state, d.attempts, d.last_status, d.last_error, d.created_at, d.delivered_at
              FROM vaulty.webhook_deliveries d JOIN vaulty.notification_events e ON e.id = d.event_id
             WHERE d.webhook_id = @id ORDER BY d.created_at DESC LIMIT 50
            """, new { id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new DeliveryRow(r.Id, r.Kind, r.State, r.Attempts, r.LastStatus, r.LastError, Utc(r.CreatedAt), r.DeliveredAt is { } d ? Utc(d) : null)).ToList();
    }

    private async Task<string> RotateSecretAsync(Guid id, UserAccess access, CancellationToken cancellationToken)
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        await secrets.SetAsync(SecretName(id), bytes, $"user:{access.UserId}", cancellationToken).ConfigureAwait(false);
        return Convert.ToBase64String(bytes);
    }

    private async Task EnsureExistsAsync(UserAccess access, Guid id, CancellationToken cancellationToken)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        if (!await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition("SELECT EXISTS (SELECT 1 FROM vaulty.webhooks WHERE id = @id)", new { id },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
        {
            throw new AccessException("This webhook does not exist.");
        }
    }

    private static void Require(UserAccess access)
    {
        ArgumentNullException.ThrowIfNull(access);
        if (!access.Allows(Permissions.SettingsManage)) throw new AccessException("You cannot manage webhooks.");
    }

    private static DateTimeOffset Utc(DateTime value) => new(DateTime.SpecifyKind(value, DateTimeKind.Utc));
}

public sealed record JobRow(Guid Id, string Kind, string State, Guid? TenantId, string? TenantName, Guid? ObjectId, string? ObjectName, string? WorkflowId,
    DateTimeOffset CreatedAt, DateTimeOffset? StartedAt, DateTimeOffset? FinishedAt, string ResultCounts, string? Error, long? ItemsSoFar = null,
    long? BytesSoFar = null, long? ExpectedItems = null, long? ExpectedBytes = null)
{
    /// <summary>
    /// How far a running backup is, and an estimate of the time left, from its own pace so far: that pace already reflects
    /// the bandwidth, the load of the host and the other backups running at the same time. Null when the size of the work is
    /// not known (an incremental run learns its changes as it goes) or when too little has happened to estimate.
    /// The fraction stays below one until the job has committed.
    /// </summary>
    public (double Fraction, TimeSpan? Remaining)? Progress(DateTimeOffset now)
    {
        if (State != "running" || StartedAt is not { } started) return null;
        double? fraction = ExpectedBytes is > 0 && BytesSoFar is { } bytes ? (double)bytes / ExpectedBytes.Value
            : ExpectedItems is > 0 && ItemsSoFar is { } items ? (double)items / ExpectedItems.Value
            : null;
        if (fraction is not { } f) return null;
        f = Math.Clamp(f, 0, 0.99);
        var elapsed = now - started;
        TimeSpan? remaining = f >= 0.02 && elapsed >= TimeSpan.FromMinutes(2) ? TimeSpan.FromTicks((long)(elapsed.Ticks * (1 - f) / f)) : null;
        return (f, remaining);
    }
}

/// <summary>The jobs page: the job mirror, newest first, limited to the user's customers.</summary>
public sealed class JobsService(NpgsqlDataSource dataSource)
{
    public const int PageSize = 100;

    /// <summary>Why a job record closed before its run began: one of the same object or tenant was running already.</summary>
    public const string BackupAlreadyRunning = "A backup of this object is already running.";
    public const string DiscoveryAlreadyRunning = "A discovery of this tenant is already running.";

    // A run that never began because another was going is no job anyone has to see; the record stays in the database.
    private static readonly string[] NeverRan = [BackupAlreadyRunning, DiscoveryAlreadyRunning];

    public async Task<IReadOnlyList<JobRow>> ListAsync(UserAccess access, string? state, string? kind, DateTimeOffset? before, string? search = null,
        Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        if (!access.Allows(Permissions.JobsView)) throw new AccessException("You cannot view jobs.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, string Kind, string State, Guid? TenantId, string? TenantName, Guid? CustomerId, Guid? ObjectId,
            string? ObjectName, string? WorkflowId, DateTime CreatedAt, DateTime? StartedAt, DateTime? FinishedAt, string ResultCounts, string? Error,
            long? ItemsSoFar, long? BytesSoFar, long? ExpectedItems, long? ExpectedBytes)>(new CommandDefinition(
            """
            SELECT j.id, j.kind, j.state, j.tenant_id, t.display_name, t.customer_id, j.protected_object_id, o.display_name, j.workflow_id,
                   j.created_at, j.started_at, j.finished_at, j.result_counts::text, j.error,
                   -- A running backup has no counts yet; the items it has stored so far show that it moves.
                   p.items AS items_so_far, p.bytes AS bytes_so_far,
                   (j.progress->>'expected_items')::bigint AS expected_items, (j.progress->>'expected_bytes')::bigint AS expected_bytes
              FROM vaulty.jobs j LEFT JOIN vaulty.tenants t ON t.id = j.tenant_id LEFT JOIN vaulty.protected_objects o ON o.id = j.protected_object_id
              LEFT JOIN LATERAL (SELECT count(*) AS items, coalesce(sum(i.size), 0)::bigint AS bytes
                                   FROM vaulty.items i JOIN vaulty.snapshots s ON s.id = i.first_snapshot_id
                                  WHERE j.state = 'running' AND j.kind = 'backup' AND i.tenant_id = j.tenant_id
                                    AND i.protected_object_id = j.protected_object_id AND i.state = 'staged' AND s.state = 'staged'
                                    AND i.kind NOT IN ('folder', 'file_version')) p ON j.state = 'running' AND j.kind = 'backup'
             WHERE (@state::text IS NULL OR j.state = @state) AND (@kind::text IS NULL OR j.kind = @kind) AND (@before::timestamptz IS NULL OR j.created_at < @before)
               AND (@tenantId::uuid IS NULL OR j.tenant_id = @tenantId)
               AND (@pattern::text IS NULL OR o.display_name ILIKE @pattern OR t.display_name ILIKE @pattern OR j.id::text ILIKE @pattern)
               AND NOT (j.state = 'cancelled' AND j.started_at IS NULL AND j.workflow_id IS NULL AND j.error = ANY(@neverRan))
             ORDER BY j.created_at DESC LIMIT @limit
            """, new { state, kind, before, tenantId, pattern = Pattern(search), neverRan = NeverRan, limit = PageSize * 2 }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Where(r => r.CustomerId is { } c ? access.Allows(Permissions.JobsView, c) : access.Allows(Permissions.JobsView, null))
            .Take(PageSize)
            .Select(r => new JobRow(r.Id, r.Kind, r.State, r.TenantId, r.TenantName, r.ObjectId, r.ObjectName, r.WorkflowId, Utc(r.CreatedAt)!.Value, Utc(r.StartedAt),
                Utc(r.FinishedAt), r.ResultCounts, r.Error, r.ItemsSoFar, r.BytesSoFar, r.ExpectedItems, r.ExpectedBytes)).ToList();
    }

    /// <summary>
    /// Requests cancellation of a backup or discovery job, by anyone who may run backups for its customer; audited. A job that
    /// has not started is cancelled here; for a running one the caller cancels its workflow run (returned), and the job
    /// mirror records the end. Restores have their own cancel on the restore page.
    /// </summary>
    public async Task<(string WorkflowId, string? RunId)?> CancelAsync(UserAccess access, Guid jobId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var job = await session.Connection.QuerySingleOrDefaultAsync<(string Kind, string State, Guid? CustomerId, string? WorkflowId, string? RunId)?>(
            new CommandDefinition(
                """
                SELECT j.kind, j.state, t.customer_id, j.workflow_id, j.workflow_run_id
                  FROM vaulty.jobs j LEFT JOIN vaulty.tenants t ON t.id = j.tenant_id WHERE j.id = @jobId
                """, new { jobId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (job is not { } j || !access.Allows(Permissions.BackupsRun, j.CustomerId)) throw new AccessException("You cannot cancel this job.");
        if (j.Kind is not ("backup" or "discovery")) throw new InvalidOperationException("Only backups and discoveries are cancelled here.");
        if (j.State is not ("queued" or "running")) throw new InvalidOperationException("This job has finished already.");
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "job.cancel_requested", $"job:{jobId}", new { kind = j.Kind }, cancellationToken)
            .ConfigureAwait(false);
        if (j.WorkflowId is null)
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.jobs SET state = 'cancelled', finished_at = now(), error = 'Cancelled before it started.' WHERE id = @jobId AND state = 'queued'",
                new { jobId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        else
        {
            // Kept with the job: the reconciler acts on it when the request cannot reach the run, or the run is stuck.
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "UPDATE vaulty.jobs SET cancel_requested_at = coalesce(cancel_requested_at, now()) WHERE id = @jobId",
                new { jobId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return j.WorkflowId is { } workflowId ? (workflowId, j.RunId) : null;
    }

    /// <summary>A search term as a LIKE pattern that matches it anywhere; its own wildcards are taken literally.</summary>
    private static string? Pattern(string? search) => string.IsNullOrWhiteSpace(search) ? null
        : "%" + search.Trim().Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal) + "%";

    private static DateTimeOffset? Utc(DateTime? value) => value is { } v ? new DateTimeOffset(DateTime.SpecifyKind(v, DateTimeKind.Utc)) : null;
}

/// <summary>Resolving an alert by hand (it stays in the history); anyone who may run backups for its customer.</summary>
public sealed class AlertService(NpgsqlDataSource dataSource, TimeProvider clock)
{
    public async Task ResolveAsync(UserAccess access, Guid alertId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access, cancellationToken).ConfigureAwait(false);
        var customer = await session.Connection.QuerySingleOrDefaultAsync<(Guid Id, Guid? CustomerId)?>(new CommandDefinition(
            "SELECT a.id, t.customer_id FROM vaulty.alerts a LEFT JOIN vaulty.tenants t ON t.id = a.tenant_id WHERE a.id = @alertId", new { alertId },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (customer is null || !(customer.Value.CustomerId is { } c ? access.Allows(Permissions.BackupsRun, c) : access.Allows(Permissions.SettingsManage)))
        {
            throw new AccessException("You cannot resolve this alert.");
        }
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.alerts SET resolved_at = @now, resolved_by = @user WHERE id = @alertId AND resolved_at IS NULL",
            new { alertId, now = clock.GetUtcNow(), user = access.UserId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "alert.resolved", $"alert:{alertId}", null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Writes the Graph request counts per tenant and hour (worker, every minute).</summary>
public sealed class GraphUsageStore(NpgsqlDataSource dataSource, TimeProvider clock)
{
    public async Task FlushAsync(IReadOnlyDictionary<Guid, (long Requests, long Throttled)> usage, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(usage);
        var now = clock.GetUtcNow();
        var hour = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero);
        foreach (var (tenantId, counts) in usage)
        {
            Guid? organization;
            await using (var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
            {
                organization = await connection.ExecuteScalarAsync<Guid?>(new CommandDefinition("SELECT vaulty.tenant_organization(@tenantId)", new { tenantId },
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
            if (organization is null) continue;
            await using var session = await OrganizationSession.BeginAsync(dataSource, organization.Value, cancellationToken).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO vaulty.graph_usage_hourly (organization_id, tenant_id, hour, requests, throttled) VALUES (@organization, @tenantId, @hour, @requests, @throttled)
                ON CONFLICT (tenant_id, hour) DO UPDATE SET requests = graph_usage_hourly.requests + excluded.requests,
                                                            throttled = graph_usage_hourly.throttled + excluded.throttled
                """, new { organization, tenantId, hour, requests = counts.Requests, throttled = counts.Throttled }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
