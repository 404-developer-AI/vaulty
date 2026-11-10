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
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
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
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
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
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", "webhook.secret_rotated", $"webhook:{id}", null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return secret;
    }

    public async Task SetEnabledAsync(UserAccess access, Guid id, bool enabled, CancellationToken cancellationToken = default)
    {
        Require(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.webhooks SET enabled = @enabled WHERE id = @id", new { id, enabled },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{access.UserId}", enabled ? "webhook.enabled" : "webhook.disabled", $"webhook:{id}", null, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(UserAccess access, Guid id, CancellationToken cancellationToken = default)
    {
        Require(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
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
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
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
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
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
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
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
    DateTimeOffset CreatedAt, DateTimeOffset? StartedAt, DateTimeOffset? FinishedAt, string ResultCounts, string? Error);

/// <summary>The jobs page: the job mirror, newest first, limited to the user's customers.</summary>
public sealed class JobsService(NpgsqlDataSource dataSource)
{
    public const int PageSize = 100;

    public async Task<IReadOnlyList<JobRow>> ListAsync(UserAccess access, string? state, string? kind, DateTimeOffset? before, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        if (!access.Allows(Permissions.JobsView)) throw new AccessException("You cannot view jobs.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, string Kind, string State, Guid? TenantId, string? TenantName, Guid? CustomerId, Guid? ObjectId,
            string? ObjectName, string? WorkflowId, DateTime CreatedAt, DateTime? StartedAt, DateTime? FinishedAt, string ResultCounts, string? Error)>(new CommandDefinition(
            """
            SELECT j.id, j.kind, j.state, j.tenant_id, t.display_name, t.customer_id, j.protected_object_id, o.display_name, j.workflow_id,
                   j.created_at, j.started_at, j.finished_at, j.result_counts::text, j.error
              FROM vaulty.jobs j LEFT JOIN vaulty.tenants t ON t.id = j.tenant_id LEFT JOIN vaulty.protected_objects o ON o.id = j.protected_object_id
             WHERE (@state::text IS NULL OR j.state = @state) AND (@kind::text IS NULL OR j.kind = @kind) AND (@before::timestamptz IS NULL OR j.created_at < @before)
             ORDER BY j.created_at DESC LIMIT @limit
            """, new { state, kind, before, limit = PageSize * 2 }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Where(r => r.CustomerId is { } c ? access.Allows(Permissions.JobsView, c) : access.Allows(Permissions.JobsView, null))
            .Take(PageSize)
            .Select(r => new JobRow(r.Id, r.Kind, r.State, r.TenantId, r.TenantName, r.ObjectId, r.ObjectName, r.WorkflowId, Utc(r.CreatedAt)!.Value, Utc(r.StartedAt),
                Utc(r.FinishedAt), r.ResultCounts, r.Error)).ToList();
    }

    private static DateTimeOffset? Utc(DateTime? value) => value is { } v ? new DateTimeOffset(DateTime.SpecifyKind(v, DateTimeKind.Utc)) : null;
}

/// <summary>Resolving an alert by hand (it stays in the history); anyone who may run backups for its customer.</summary>
public sealed class AlertService(NpgsqlDataSource dataSource, TimeProvider clock)
{
    public async Task ResolveAsync(UserAccess access, Guid alertId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var session = await OrganizationSession.BeginAsync(dataSource, access.OrganizationId, cancellationToken).ConfigureAwait(false);
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
