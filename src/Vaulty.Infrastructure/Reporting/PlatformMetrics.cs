using System.Globalization;
using System.Text;
using Dapper;
using Npgsql;
using Vaulty.Core.Domain;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Reporting;

/// <summary>
/// The platform gauges for <c>/metrics</c> (Prometheus text format), aggregated over every organization and without names or
/// identifiers of customers, tenants or objects: protected objects per status, the oldest latest snapshot, the oldest
/// verification, open alerts, jobs, pending webhook deliveries and Graph throttling in the last 24 hours.
/// </summary>
public sealed class PlatformMetrics(NpgsqlDataSource dataSource, DashboardService dashboards, TimeProvider clock)
{
    public async Task<string> CollectAsync(CancellationToken cancellationToken = default)
    {
        var now = clock.GetUtcNow();
        var statuses = new Dictionary<ProtectionStatus, long>();
        double oldestSnapshot = 0, oldestVerification = 0;
        long requests = 0, throttled = 0, alertsCritical = 0, alertsWarning = 0, jobsRunning = 0, jobsQueued = 0, webhooksPending = 0, tenants = 0;
        List<Guid> organizations;
        await using (var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        {
            organizations = (await connection.QueryAsync<Guid>(new CommandDefinition("SELECT vaulty.active_organization_ids()", cancellationToken: cancellationToken))
                .ConfigureAwait(false)).ToList();
        }
        foreach (var organization in organizations)
        {
            var everything = new UserAccess(Guid.Empty, organization, true, new Dictionary<string, HashSet<Guid>?> { [Permissions.CustomersView] = null });
            var dashboard = await dashboards.LoadAsync(everything, cancellationToken: cancellationToken).ConfigureAwait(false);
            foreach (var (status, count) in dashboard.Totals) statuses[status] = statuses.GetValueOrDefault(status) + count;
            foreach (var tenant in dashboard.Tenants)
            {
                tenants++;
                requests += tenant.Requests24h;
                throttled += tenant.Throttled24h;
                if (tenant.OldestLatestSnapshotAt is { } s) oldestSnapshot = Math.Max(oldestSnapshot, (now - s).TotalSeconds);
                if (tenant.Objects.Any(o => o.LastSnapshotAt is not null))
                {
                    oldestVerification = Math.Max(oldestVerification, tenant.LastVerificationAt is { } v ? (now - v).TotalSeconds : double.PositiveInfinity);
                }
            }
            alertsCritical += dashboard.OpenAlerts.Count(a => a.Severity == "critical");
            alertsWarning += dashboard.OpenAlerts.Count(a => a.Severity == "warning");
            await using var session = await OrganizationSession.BeginAsync(dataSource, organization, cancellationToken).ConfigureAwait(false);
            var jobs = await session.Connection.QuerySingleAsync<(long Running, long Queued, long Pending)>(new CommandDefinition(
                """
                SELECT (SELECT count(*) FROM vaulty.jobs WHERE state = 'running'), (SELECT count(*) FROM vaulty.jobs WHERE state = 'queued'),
                       (SELECT count(*) FROM vaulty.webhook_deliveries WHERE state = 'pending')
                """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            jobsRunning += jobs.Running;
            jobsQueued += jobs.Queued;
            webhooksPending += jobs.Pending;
        }

        var text = new StringBuilder();
        Gauge(text, "vaulty_protected_objects", "Protected objects by status of their latest snapshot.",
            Enum.GetValues<ProtectionStatus>().Select(s => ($"status=\"{Snake(s)}\"", (double)statuses.GetValueOrDefault(s))));
        Gauge(text, "vaulty_tenants", "Connected tenants.", [("", tenants)]);
        Gauge(text, "vaulty_latest_snapshot_age_max_seconds", "Age of the oldest latest snapshot of any protected object.", [("", oldestSnapshot)]);
        Gauge(text, "vaulty_verification_age_max_seconds", "Time since the oldest last verification of a tenant with snapshots (+Inf: never verified).",
            [("", oldestVerification)]);
        Gauge(text, "vaulty_alerts_open", "Open alerts by severity.", [("severity=\"critical\"", alertsCritical), ("severity=\"warning\"", alertsWarning)]);
        Gauge(text, "vaulty_jobs", "Jobs by state.", [("state=\"running\"", jobsRunning), ("state=\"queued\"", jobsQueued)]);
        Gauge(text, "vaulty_webhook_deliveries_pending", "Webhook deliveries waiting or retrying.", [("", webhooksPending)]);
        Gauge(text, "vaulty_graph_requests_24h", "Microsoft Graph requests in the last 24 hours.", [("", requests)]);
        Gauge(text, "vaulty_graph_throttled_24h", "Microsoft Graph responses 429 in the last 24 hours.", [("", throttled)]);
        return text.ToString();
    }

    private static string Snake(ProtectionStatus status) => status switch
    {
        ProtectionStatus.NotRunYet => "not_run_yet",
        ProtectionStatus.SourceDeleted => "source_deleted",
        _ => status.ToString().ToLowerInvariant(),
    };

    private static void Gauge(StringBuilder text, string name, string help, IEnumerable<(string Labels, double Value)> samples)
    {
        text.Append(CultureInfo.InvariantCulture, $"# HELP {name} {help}\n# TYPE {name} gauge\n");
        foreach (var (labels, value) in samples)
        {
            var formatted = double.IsPositiveInfinity(value) ? "+Inf" : value.ToString("0.###", CultureInfo.InvariantCulture);
            text.Append(CultureInfo.InvariantCulture, $"{name}{(labels.Length > 0 ? "{" + labels + "}" : "")} {formatted}\n");
        }
    }
}
