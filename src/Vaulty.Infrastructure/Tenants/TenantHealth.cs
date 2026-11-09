using Dapper;
using Microsoft.Identity.Client;
using Npgsql;
using Vaulty.Graph.Auth;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Tenants;

public enum HealthOutcome
{
    Healthy,
    /// <summary>Consent withdrawn, app disabled or deleted, certificate expired or permissions missing: no backup can run.</summary>
    ConsentLost,
    /// <summary>Microsoft or the network failed; the state stays as it was and the check runs again next hour.</summary>
    Unknown,
}

public sealed record HealthResult(HealthOutcome Outcome, string Detail, bool BecameLost);

/// <summary>
/// The hourly check of a tenant's connection: the certificate is valid, the app can still get a token, and the token
/// still carries every backup permission. A tenant that loses any of these is shown as "consent lost" and alerted on.
/// </summary>
public sealed class TenantHealthCheck(NpgsqlDataSource dataSource, IGraphTokenProvider tokens, TimeProvider clock)
{
    /// <summary>Identity platform error codes that mean the app itself is gone, disabled or no longer trusted.</summary>
    private static readonly string[] LostCodes =
    [
        "AADSTS7000112", // application disabled
        "AADSTS700016",  // application not found in the tenant
        "AADSTS700027",  // client assertion failed (certificate removed from the app)
        "AADSTS7000215", // invalid client secret
        "AADSTS65001",   // consent not granted
        "AADSTS90002",   // tenant not found
        "AADSTS700024",  // client assertion outside its time range
        "AADSTS7000222", // expired certificate or secret
    ];

    public static (HealthOutcome Outcome, string Detail) Classify(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var text = exception.Message;
        var code = LostCodes.FirstOrDefault(c => text.Contains(c, StringComparison.Ordinal));
        if (code is not null) return (HealthOutcome.ConsentLost, $"Microsoft refused the app ({code}).");
        if (exception is MsalServiceException { ErrorCode: "invalid_client" or "unauthorized_client" or "invalid_request" } msal)
        {
            return (HealthOutcome.ConsentLost, $"Microsoft refused the app ({msal.ErrorCode}).");
        }
        return (HealthOutcome.Unknown, "Microsoft could not be reached; the check runs again next hour.");
    }

    public async Task<HealthResult> CheckAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var tenant = await session.Connection.QuerySingleAsync<(string ConsentState, DateTime? CertificateExpiresAt)>(new CommandDefinition(
            "SELECT consent_state, certificate_expires_at FROM vaulty.tenants WHERE id = @tenantId FOR UPDATE", new { tenantId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);

        HealthOutcome outcome;
        string detail;
        var granted = Array.Empty<string>();
        if (tenant.CertificateExpiresAt is { } expires && DateTime.SpecifyKind(expires, DateTimeKind.Utc) <= clock.GetUtcNow().UtcDateTime)
        {
            (outcome, detail) = (HealthOutcome.ConsentLost, "The certificate expired. Rotate it on the tenant page.");
        }
        else
        {
            try
            {
                var token = await tokens.GetTokenAsync(tenantId, forceRefresh: true, cancellationToken).ConfigureAwait(false);
                granted = [.. GraphPermissions.Effective(token.Roles)];
                var missing = GraphPermissions.All.Where(p => !p.ForRestore && !granted.Contains(p.Name)).Select(p => p.Name).ToList();
                (outcome, detail) = missing.Count == 0
                    ? (HealthOutcome.Healthy, "The app works and holds every backup permission.")
                    : (HealthOutcome.ConsentLost, "Backup permissions were removed: " + string.Join(", ", missing) + ".");
            }
            catch (Exception ex) when (ex is MsalException or HttpRequestException or InvalidOperationException)
            {
                (outcome, detail) = Classify(ex);
            }
        }

        var becameLost = outcome == HealthOutcome.ConsentLost && tenant.ConsentState != "lost";
        var newState = outcome switch
        {
            HealthOutcome.Healthy => "granted",
            HealthOutcome.ConsentLost => "lost",
            _ => tenant.ConsentState,
        };
        var days = tenant.CertificateExpiresAt is { } e ? (int)(DateTime.SpecifyKind(e, DateTimeKind.Utc) - clock.GetUtcNow().UtcDateTime).TotalDays : (int?)null;
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.tenants SET consent_state = @newState, last_health_check_at = @now,
                   consent_lost_at = CASE WHEN @newState = 'lost' THEN coalesce(consent_lost_at, @now) WHEN @newState = 'granted' THEN NULL ELSE consent_lost_at END,
                   granted_permissions = CASE WHEN @outcome = 'healthy' OR @hasRoles THEN @granted::jsonb ELSE granted_permissions END,
                   health = jsonb_build_object('status', @outcome, 'detail', @detail, 'checked_at', @now, 'certificate_days_left', @days)
             WHERE id = @tenantId
            """,
            new
            {
                tenantId, newState, now = clock.GetUtcNow(), outcome = outcome.ToString().ToLowerInvariant(), detail, days,
                granted = System.Text.Json.JsonSerializer.Serialize(granted), hasRoles = granted.Length > 0,
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (becameLost)
        {
            await AuditLog.WriteAsync(session, "system:health", "tenant.consent_lost", $"tenant:{tenantId}", new { detail }, cancellationToken)
                .ConfigureAwait(false);
        }
        else if (outcome == HealthOutcome.Healthy && tenant.ConsentState == "lost")
        {
            await AuditLog.WriteAsync(session, "system:health", "tenant.consent_restored", $"tenant:{tenantId}", null, cancellationToken)
                .ConfigureAwait(false);
        }
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new HealthResult(outcome, detail, becameLost);
    }

    public async Task<IReadOnlyList<(Guid OrganizationId, Guid TenantId)>> ConnectedTenantsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return (await connection.QueryAsync<(Guid, Guid)>(new CommandDefinition("SELECT organization_id, tenant_id FROM vaulty.connected_tenants()",
            cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
    }
}
