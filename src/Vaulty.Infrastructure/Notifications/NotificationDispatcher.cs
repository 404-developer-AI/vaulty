using System.Globalization;
using System.Net;
using System.Text;
using Dapper;
using Microsoft.Extensions.Logging;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Domain;
using Vaulty.Core.Notifications;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Platform;
using Vaulty.Infrastructure.Reporting;
using Vaulty.Infrastructure.Retention;
using Vaulty.Infrastructure.Storage;
using Vaulty.Infrastructure.Web;

namespace Vaulty.Infrastructure.Notifications;

public sealed record NotificationOptions
{
    /// <summary>A due backup that has not started this long after its planned time is a missed run.</summary>
    public TimeSpan MissedRunGrace { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Waits after the first, second, ... failed webhook delivery; after the last one the delivery is failed.</summary>
    public IReadOnlyList<TimeSpan> WebhookBackoff { get; init; } =
        [TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2), TimeSpan.FromHours(12)];

    /// <summary>The digest goes out once a day from this local hour (display time zone).</summary>
    public int DigestHour { get; init; } = 7;
}

/// <summary>
/// Runs every minute (worker): finds missed runs, fans notification events out to webhooks, delivers due webhooks with
/// retries, mails new alerts to the users who may see them, and sends the daily digest. Every step works per organization
/// under row-level security and is safe to repeat.
/// </summary>
public sealed class NotificationDispatcher(NpgsqlDataSource dataSource, IWebhookSender webhooks, IMailSender mail, ISecretStore secrets,
    PlatformSettings settings, VaultyHostOptions host, DashboardService dashboards, TimeProvider clock, ILogger<NotificationDispatcher> logger,
    NotificationOptions? options = null)
{
    private readonly NotificationOptions _options = options ?? new NotificationOptions();

    public async Task<int> FindMissedRunsAsync(CancellationToken cancellationToken = default)
    {
        var raised = 0;
        var now = clock.GetUtcNow();
        foreach (var organization in await OrganizationsAsync(cancellationToken).ConfigureAwait(false))
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false);
            var missed = await session.Connection.QueryAsync<(Guid Id, Guid TenantId, string Name, DateTime NextRunAt)>(new CommandDefinition(
                """
                SELECT o.id, o.tenant_id, o.display_name, o.next_run_at FROM vaulty.protected_objects o JOIN vaulty.tenants t ON t.id = o.tenant_id
                 WHERE o.state = 'active' AND t.state = 'active' AND t.consent_state = 'granted' AND o.next_run_at < @cutoff
                   AND NOT EXISTS (SELECT 1 FROM vaulty.snapshots s WHERE s.protected_object_id = o.id AND s.state = 'staged')
                """, new { cutoff = now - _options.MissedRunGrace }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            foreach (var o in missed)
            {
                var planned = new DateTimeOffset(DateTime.SpecifyKind(o.NextRunAt, DateTimeKind.Utc));
                if (await Alerts.RaiseAsync(session, o.TenantId, o.Id, NotificationKinds.BackupMissed, "warning",
                        $"The backup of {o.Name} planned for {planned.ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture)} UTC has not started. Check that object storage passed its connection test and look at the Jobs page; Vaulty keeps trying.",
                        new { planned }, cancellationToken).ConfigureAwait(false))
                {
                    raised++;
                }
            }
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        return raised;
    }

    public async Task<int> FanOutEventsAsync(CancellationToken cancellationToken = default)
    {
        var created = 0;
        foreach (var organization in await OrganizationsAsync(cancellationToken).ConfigureAwait(false))
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false);
            created += (int)await session.Connection.ExecuteScalarAsync<long>(new CommandDefinition(
                """
                WITH pending AS (
                    SELECT id, kind FROM vaulty.notification_events WHERE dispatched_at IS NULL ORDER BY created_at LIMIT 500 FOR UPDATE SKIP LOCKED
                ), deliveries AS (
                    INSERT INTO vaulty.webhook_deliveries (id, organization_id, webhook_id, event_id, next_attempt_at)
                    SELECT gen_random_uuid(), w.organization_id, w.id, p.id, @now
                      FROM pending p JOIN vaulty.webhooks w ON w.enabled AND p.kind = ANY(w.events)
                    ON CONFLICT (webhook_id, event_id) DO NOTHING
                    RETURNING 1
                ), marked AS (
                    UPDATE vaulty.notification_events e SET dispatched_at = @now FROM pending p WHERE e.id = p.id RETURNING 1
                )
                SELECT count(*) FROM deliveries
                """, new { now = clock.GetUtcNow() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        return created;
    }

    private sealed record Due(Guid Id, Guid WebhookId, string Url, Guid EventId, string Kind, DateTime CreatedAt, Guid? TenantId, Guid? ObjectId, string Payload,
        int Attempts);

    public async Task<int> DeliverWebhooksAsync(CancellationToken cancellationToken = default)
    {
        var delivered = 0;
        var display = await settings.GetAsync<DisplaySettings>(DisplaySettings.SettingKey, cancellationToken).ConfigureAwait(false) ?? DisplaySettings.Default;
        var timeout = TimeSpan.FromSeconds(Math.Clamp(display.WebhookTimeoutSeconds, 1, 60));
        foreach (var organization in await OrganizationsAsync(cancellationToken).ConfigureAwait(false))
        {
            List<Due> due;
            var now = clock.GetUtcNow();
            await using (var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false))
            {
                // Claim with a lease, so a crash mid-delivery retries later instead of never.
                due = (await session.Connection.QueryAsync<Due>(new CommandDefinition(
                    """
                    WITH claimed AS (
                        SELECT d.id FROM vaulty.webhook_deliveries d WHERE d.state = 'pending' AND d.next_attempt_at <= @now
                         ORDER BY d.next_attempt_at LIMIT 100 FOR UPDATE SKIP LOCKED
                    )
                    UPDATE vaulty.webhook_deliveries d SET next_attempt_at = @lease FROM claimed c, vaulty.webhooks w, vaulty.notification_events e
                     WHERE d.id = c.id AND w.id = d.webhook_id AND e.id = d.event_id
                    RETURNING d.id, d.webhook_id, w.url, e.id AS event_id, e.kind, e.created_at, e.tenant_id, e.protected_object_id AS object_id,
                              e.payload::text AS payload, d.attempts
                    """, new { now, lease = now.AddMinutes(5) }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
                await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            foreach (var d in due)
            {
                using var secret = await secrets.GetAsync(WebhookService.SecretName(d.WebhookId), cancellationToken).ConfigureAwait(false);
                var body = WebhookBody.Create(d.EventId, d.Kind, new DateTimeOffset(DateTime.SpecifyKind(d.CreatedAt, DateTimeKind.Utc)), d.TenantId, d.ObjectId, d.Payload);
                var result = secret is null
                    ? new WebhookResult(false, null, "The signing secret of this webhook is missing; create a new secret.")
                    : await webhooks.SendAsync(new Uri(d.Url), d.Kind, d.Id, body, secret.Reveal().ToArray(), timeout, cancellationToken).ConfigureAwait(false);
                var attempts = d.Attempts + 1;
                var finished = clock.GetUtcNow();
                var state = result.Delivered ? "delivered" : attempts > _options.WebhookBackoff.Count ? "failed" : "pending";
                var next = state == "pending" ? finished + _options.WebhookBackoff[attempts - 1] : finished;
                await using var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false);
                await session.Connection.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE vaulty.webhook_deliveries SET state = @state, attempts = @attempts, next_attempt_at = @next, last_status = @status,
                           last_error = @error, delivered_at = CASE WHEN @state = 'delivered' THEN @finished ELSE delivered_at END
                     WHERE id = @id
                    """, new { d.Id, state, attempts, next, status = result.Status, error = result.Error, finished }, session.Transaction,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
                await session.CommitAsync(cancellationToken).ConfigureAwait(false);
                if (result.Delivered) delivered++;
                else logger.LogWarning("Webhook delivery {DeliveryId} attempt {Attempt} failed: {Error}", d.Id, attempts, result.Error);
            }
        }
        return delivered;
    }

    private sealed record Recipient(Guid Id, string Email, string? DisplayName, Guid? CustomerId);

    public async Task<int> MailAlertsAsync(CancellationToken cancellationToken = default)
    {
        var sent = 0;
        var smtp = await settings.GetAsync<SmtpSettings>(SmtpSettings.SettingKey, cancellationToken).ConfigureAwait(false);
        foreach (var organization in await OrganizationsAsync(cancellationToken).ConfigureAwait(false))
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false);
            var alerts = (await session.Connection.QueryAsync<(Guid Id, string Severity, string Kind, string Message, Guid? TenantId, Guid? CustomerId, string? TenantName,
                string? CustomerName)>(new CommandDefinition(
                """
                SELECT a.id, a.severity, a.kind, a.message, a.tenant_id, t.customer_id, t.display_name, c.name
                  FROM vaulty.alerts a LEFT JOIN vaulty.tenants t ON t.id = a.tenant_id LEFT JOIN vaulty.customers c ON c.id = t.customer_id
                 WHERE a.notified_at IS NULL ORDER BY a.created_at LIMIT 200 FOR UPDATE OF a SKIP LOCKED
                """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
            foreach (var alert in alerts)
            {
                if (smtp is not null && alert.Severity != "info")
                {
                    foreach (var recipient in await RecipientsAsync(session, alert.CustomerId, "alert_mail", cancellationToken).ConfigureAwait(false))
                    {
                        try
                        {
                            await mail.SendAsync(AlertMail.Compose(recipient.Email, alert.Severity, alert.Message, alert.CustomerName, alert.TenantName,
                                Link(alert.TenantId is { } t ? $"/tenants/{t}" : "/")), cancellationToken).ConfigureAwait(false);
                            sent++;
                        }
                        catch (Exception ex) when (ex is MailKit.ServiceNotConnectedException or MailKit.Net.Smtp.SmtpCommandException or MailKit.Net.Smtp.SmtpProtocolException
                                                   or System.Net.Sockets.SocketException or IOException or MailKit.Security.AuthenticationException)
                        {
                            logger.LogWarning("Alert mail {AlertId} could not be sent: {Error}", alert.Id, ex.Message);
                        }
                    }
                }
                await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.alerts SET notified_at = @now WHERE id = @id",
                    new { now = clock.GetUtcNow(), id = alert.Id }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        return sent;
    }

    public async Task<int> SendDigestsAsync(CancellationToken cancellationToken = default)
    {
        var sent = 0;
        if (await settings.GetAsync<SmtpSettings>(SmtpSettings.SettingKey, cancellationToken).ConfigureAwait(false) is null) return 0;
        var display = await settings.GetAsync<DisplaySettings>(DisplaySettings.SettingKey, cancellationToken).ConfigureAwait(false) ?? DisplaySettings.Default;
        var zone = TimeZones.Resolve(display.TimeZone);
        var local = TimeZoneInfo.ConvertTime(clock.GetUtcNow(), zone);
        if (local.Hour < _options.DigestHour) return 0;
        var day = DateOnly.FromDateTime(local.DateTime);
        foreach (var organization in await OrganizationsAsync(cancellationToken).ConfigureAwait(false))
        {
            List<Recipient> recipients;
            await using (var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false))
            {
                var claimed = await session.Connection.ExecuteAsync(new CommandDefinition(
                    "INSERT INTO vaulty.digests (organization_id, day, sent_at) VALUES (@organization, @day, @now) ON CONFLICT DO NOTHING",
                    new { organization, day, now = clock.GetUtcNow() }, session.Transaction,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
                if (claimed == 0) continue;
                recipients = await RecipientsAsync(session, null, "digest_mail", cancellationToken, anyCustomer: true).ConfigureAwait(false);
                await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            foreach (var user in recipients.GroupBy(r => r.Id))
            {
                var customers = user.Any(r => r.CustomerId is null) ? null : user.Select(r => r.CustomerId!.Value).ToHashSet();
                var access = new UserAccess(user.Key, organization, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.CustomersView] = customers });
                var dashboard = await dashboards.LoadAsync(access, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (!dashboard.Customers.Any()) continue;
                try
                {
                    await mail.SendAsync(DigestMail.Compose(user.First().Email, day, dashboard, Link("/")), cancellationToken).ConfigureAwait(false);
                    sent++;
                }
                catch (Exception ex) when (ex is MailKit.ServiceNotConnectedException or MailKit.Net.Smtp.SmtpCommandException or MailKit.Net.Smtp.SmtpProtocolException
                                           or System.Net.Sockets.SocketException or IOException or MailKit.Security.AuthenticationException)
                {
                    logger.LogWarning("The daily digest could not be sent: {Error}", ex.Message);
                }
            }
            await using (var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false))
            {
                await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.digests SET recipients = @sent WHERE organization_id = @organization AND day = @day",
                    new { organization, day, sent }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
                await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        return sent;
    }

    /// <summary>Users who may see reports for the customer (or for any customer), with the given mail preference on.</summary>
    private static async Task<List<Recipient>> RecipientsAsync(OrganizationSession session, Guid? customerId, string preference, CancellationToken cancellationToken,
        bool anyCustomer = false)
    {
        var column = preference == "digest_mail" ? "u.digest_mail" : "u.alert_mail";
        return (await session.Connection.QueryAsync<Recipient>(new CommandDefinition(
            $"""
            SELECT DISTINCT u.id, u.email, u.display_name, a.customer_id FROM vaulty.users u
              JOIN vaulty.role_assignments a ON a.user_id = u.id JOIN vaulty.role_permissions p ON p.role_id = a.role_id
             WHERE p.permission = @permission AND u.disabled_at IS NULL AND u.email IS NOT NULL AND {column}
               AND (@any OR a.customer_id IS NULL OR a.customer_id = @customerId)
            """, new { permission = Permissions.ReportsView, customerId, any = anyCustomer }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToList();
    }

    private string Link(string path) => string.IsNullOrEmpty(host.PublicHost) ? path : $"https://{host.PublicHost}{path}";

    private async Task<List<Guid>> OrganizationsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return (await connection.QueryAsync<Guid>(new CommandDefinition("SELECT vaulty.active_organization_ids()", cancellationToken: cancellationToken))
            .ConfigureAwait(false)).ToList();
    }
}

/// <summary>Alert mail: what happened and what to do, plain text always, a simple card as HTML. Sender name is Vaulty.</summary>
public static class AlertMail
{
    public static MailMessage Compose(string to, string severity, string message, string? customer, string? tenant, string link)
    {
        var subject = Subject(message);
        var context = customer is null ? "" : tenant is null ? customer : $"{customer} · {tenant}";
        var text = new StringBuilder();
        if (context.Length > 0) text.AppendLine(context).AppendLine();
        text.AppendLine(message).AppendLine().AppendLine($"Open Vaulty: {link}");
        var accent = severity == "critical" ? "#DC2626" : "#D97706";
        var html = Card(accent, context, $"<p style=\"margin:0 0 16px\">{WebUtility.HtmlEncode(message)}</p>", link, "Open in Vaulty");
        return new MailMessage(to, subject, text.ToString(), html);
    }

    /// <summary>The first clause of the message: "Backup of Finance mailbox is partial".</summary>
    public static string Subject(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var end = message.IndexOfAny([':', '.']);
        var subject = end > 0 ? message[..end] : message;
        return subject.Length > 120 ? subject[..117] + "..." : subject;
    }

    internal static string Card(string accent, string context, string bodyHtml, string link, string button) =>
        $"""
        <!doctype html><html><body style="margin:0;padding:24px;background:#F5F5F4;font-family:Inter,Segoe UI,Arial,sans-serif;color:#1C1917">
        <table role="presentation" width="100%" style="max-width:560px;margin:0 auto;background:#FFFFFF;border:1px solid #E7E5E4;border-radius:12px">
        <tr><td style="padding:24px;border-top:4px solid {accent};border-radius:12px 12px 0 0">
        <div style="font-size:12px;color:#57534E;margin-bottom:8px">Vaulty{(context.Length > 0 ? " · " + WebUtility.HtmlEncode(context) : "")}</div>
        {bodyHtml}
        <a href="{WebUtility.HtmlEncode(link)}" style="display:inline-block;background:#0F766E;color:#FFFFFF;text-decoration:none;padding:10px 16px;border-radius:8px">{button}</a>
        </td></tr></table></body></html>
        """;
}

/// <summary>The daily digest: exact counts and every protected object that needs attention, worst first.</summary>
public static class DigestMail
{
    public static MailMessage Compose(string to, DateOnly day, Dashboard dashboard, string link)
    {
        ArgumentNullException.ThrowIfNull(dashboard);
        var counts = Counts(dashboard.Totals);
        var attention = dashboard.Customers.SelectMany(c => c.Tenants.SelectMany(t => t.Objects.Select(o => (Customer: c, Tenant: t, Object: o))))
            .Where(x => x.Object.Status is ProtectionStatus.Failed or ProtectionStatus.Partial)
            .OrderByDescending(x => x.Object.Status).ThenBy(x => x.Object.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var text = new StringBuilder();
        text.AppendLine($"Vaulty daily summary for {day.ToString("d MMM yyyy", CultureInfo.InvariantCulture)}").AppendLine();
        text.AppendLine(counts).AppendLine();
        if (attention.Count == 0) text.AppendLine("Nothing needs attention.");
        foreach (var x in attention.Take(25)) text.AppendLine($"- {Protection.Label(x.Object.Status)}: {x.Object.Name} ({x.Customer.Name} · {x.Tenant.Name}). {x.Object.Reason}");
        if (attention.Count > 25) text.AppendLine($"... and {attention.Count - 25} more on the dashboard.");
        if (dashboard.OpenAlerts.Count > 0) text.AppendLine().AppendLine($"{dashboard.OpenAlerts.Count} open alert{(dashboard.OpenAlerts.Count == 1 ? "" : "s")}.");
        text.AppendLine().AppendLine($"Open the dashboard: {link}");

        var rows = new StringBuilder();
        foreach (var x in attention.Take(25))
        {
            var color = x.Object.Status == ProtectionStatus.Failed ? "#DC2626" : "#D97706";
            rows.Append(CultureInfo.InvariantCulture, $"<tr><td style=\"padding:4px 8px 4px 0;color:{color};font-weight:600\">{Protection.Label(x.Object.Status)}</td>")
                .Append(CultureInfo.InvariantCulture, $"<td style=\"padding:4px 0\">{WebUtility.HtmlEncode(x.Object.Name)} <span style=\"color:#57534E\">({WebUtility.HtmlEncode(x.Customer.Name)} · {WebUtility.HtmlEncode(x.Tenant.Name)})</span></td></tr>");
        }
        var body = $"<p style=\"margin:0 0 12px;font-weight:600\">{WebUtility.HtmlEncode(counts)}</p>"
                   + (attention.Count == 0 ? "<p style=\"margin:0 0 16px\">Nothing needs attention.</p>" : $"<table style=\"margin:0 0 16px;font-size:14px\">{rows}</table>");
        var subject = attention.Count == 0
            ? "Daily summary: everything protected"
            : $"Daily summary: {attention.Count} protected object{(attention.Count == 1 ? " needs" : "s need")} attention";
        return new MailMessage(to, subject, text.ToString(), AlertMail.Card(attention.Count == 0 ? "#0F766E" : "#D97706", "", body, link, "Open the dashboard"));
    }

    public static string Counts(IReadOnlyDictionary<ProtectionStatus, int> totals)
    {
        ArgumentNullException.ThrowIfNull(totals);
        var parts = new[] { ProtectionStatus.Protected, ProtectionStatus.Partial, ProtectionStatus.Failed, ProtectionStatus.NotRunYet, ProtectionStatus.Paused, ProtectionStatus.SourceDeleted }
            .Where(s => totals.GetValueOrDefault(s) > 0)
            .Select(s => $"{totals[s]} {Protection.Label(s).ToLowerInvariant()}");
        var joined = string.Join(", ", parts);
        return joined.Length == 0 ? "No protected objects yet." : joined;
    }
}
