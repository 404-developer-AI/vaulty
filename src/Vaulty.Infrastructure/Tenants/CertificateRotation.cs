using Dapper;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Graph;
using Vaulty.Graph.Auth;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Tenants;

/// <summary>Proves that a credential signs in (a token request with it); the default asks the identity platform through MSAL.</summary>
public interface ICredentialVerifier
{
    Task VerifyAsync(GraphCredential credential, CancellationToken cancellationToken = default);
}

public sealed class MsalCredentialVerifier : ICredentialVerifier
{
    public async Task VerifyAsync(GraphCredential credential, CancellationToken cancellationToken = default) =>
        await new MsalGraphProbe().AcquireAsync(credential, cancellationToken).ConfigureAwait(false);
}

/// <param name="Rotated">The new certificate is in use.</param>
/// <param name="FallbackScript">Set when Vaulty could not add the key itself: run this script, then confirm the rotation.</param>
public sealed record RotationOutcome(bool Rotated, bool OldKeyRemoved, string Message, string? FallbackScript = null);

/// <summary>
/// Rolls a tenant's certificate without an administrator: a new certificate is added to the app registration with addKey
/// and a proof signed by the current certificate (an application needs no permission to roll its own keys), the new
/// certificate must sign in before Vaulty switches to it, and only then the old key is removed with removeKey.
/// </summary>
public sealed class CertificateRotation(NpgsqlDataSource dataSource, ISecretStore secrets, DedicatedAppCredentialProvider credentials, GraphServices graph,
    AppRegistrationClient registrations, ICredentialVerifier verifier, TimeProvider clock, ILogger<CertificateRotation> logger)
{
    /// <summary>Vaulty renews a certificate this long before it expires.</summary>
    public static readonly TimeSpan RenewBefore = TimeSpan.FromDays(60);

    public int VerifyAttempts { get; init; } = 6;
    public TimeSpan VerifyWait { get; init; } = TimeSpan.FromSeconds(10);

    private TenantService Tenants => new(dataSource, secrets, credentials, graph, clock);

    private sealed record Row(string DisplayName, Guid? ClientId, Guid? ApplicationObjectId, string CertificateSecretName, Guid? CertificateKeyId,
        string? NextCertificateSecretName, Guid? NextCertificateKeyId);

    public async Task<RotationOutcome> RotateAsync(Guid organizationId, string actor, Guid tenantId, CancellationToken cancellationToken = default)
    {
        Row row;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            row = await session.Connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
                      """
                      SELECT display_name AS displayname, client_id AS clientid, application_object_id AS applicationobjectid,
                             certificate_secret_name AS certificatesecretname, certificate_key_id AS certificatekeyid,
                             next_certificate_secret_name AS nextcertificatesecretname, next_certificate_key_id AS nextcertificatekeyid
                        FROM vaulty.tenants WHERE id = @tenantId AND state <> 'deleted'
                      """, new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)
                  ?? throw new TenantException("This tenant does not exist.");
        }
        if (row.ClientId is not { } clientId) throw new TenantException("The tenant has no application ID yet.");

        // A rotation that stopped half-way continues with the certificate it had already made.
        TenantCertificateMaterial next;
        if (row.NextCertificateSecretName is { } nextName && await secrets.GetAsync(nextName, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            using (existing) next = TenantCertificate.FromPfx(existing.Reveal());
        }
        else
        {
            next = TenantCertificate.Create(row.DisplayName, clock);
            // Its own secret name: after an earlier rotation the current certificate may carry any earlier "next" name.
            var secretName = TenantService.CertificateSecret(tenantId, $".{next.Thumbprint.ToLowerInvariant()}");
            await secrets.SetAsync(secretName, next.Pfx, actor, cancellationToken).ConfigureAwait(false);
            await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vaulty.tenants SET next_certificate_secret_name = @secretName, next_certificate_thumbprint = @thumbprint,
                       next_certificate_expires_at = @expires, next_certificate_key_id = NULL WHERE id = @tenantId
                """, new { tenantId, secretName, thumbprint = next.Thumbprint, expires = next.NotAfter }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, actor, "tenant.certificate_rotation_started", $"tenant:{tenantId}", new { method = "add_key" }, cancellationToken)
                .ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            row = row with { NextCertificateKeyId = null };
        }

        if (row.ApplicationObjectId is not { } objectId)
        {
            return new RotationOutcome(false, false,
                "Vaulty does not know this app registration's object ID yet, so it cannot add the certificate itself. Run the script, or repair the connection once from the browser.",
                TenantService.RotationScript(clientId, next));
        }

        var nextKeyId = row.NextCertificateKeyId;
        if (nextKeyId is null)
        {
            try
            {
                var current = await credentials.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
                var token = await graph.Tokens.GetTokenAsync(tenantId, cancellationToken: cancellationToken).ConfigureAwait(false);
                nextKeyId = await registrations.AddKeyAsync(token.AccessToken, objectId, next,
                    CertificateJwt.KeyProof(current.Certificate, objectId, clock.GetUtcNow()), TenantService.AppName, cancellationToken).ConfigureAwait(false);
                await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
                await session.Connection.ExecuteAsync(new CommandDefinition("UPDATE vaulty.tenants SET next_certificate_key_id = @nextKeyId WHERE id = @tenantId",
                    new { tenantId, nextKeyId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
                await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is GraphException or Microsoft.Identity.Client.MsalException or HttpRequestException)
            {
                logger.LogWarning("addKey for a tenant certificate failed: {Error}", ex is GraphException g ? $"{(int)g.Status} {g.Code}" : ex.GetType().Name);
                return new RotationOutcome(false, false,
                    "Microsoft did not let Vaulty add the new certificate itself. Run the script in the tenant, then confirm the new certificate.",
                    TenantService.RotationScript(clientId, next));
            }
        }

        // The new certificate must sign in before it replaces the current one.
        var nextCredential = await credentials.GetNextAsync(tenantId, cancellationToken).ConfigureAwait(false);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await verifier.VerifyAsync(nextCredential, cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (Exception ex) when (ex is Microsoft.Identity.Client.MsalException or HttpRequestException or IdentityException)
            {
                if (attempt >= VerifyAttempts)
                {
                    return new RotationOutcome(false, false, "The new certificate was added but does not sign in yet. Vaulty tries again later; the current certificate stays in use.");
                }
                await Task.Delay(VerifyWait, cancellationToken).ConfigureAwait(false);
            }
        }

        var oldKeyId = row.CertificateKeyId;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false))
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vaulty.tenants SET certificate_secret_name = next_certificate_secret_name, certificate_thumbprint = next_certificate_thumbprint,
                       certificate_expires_at = next_certificate_expires_at, certificate_key_id = next_certificate_key_id,
                       next_certificate_secret_name = NULL, next_certificate_thumbprint = NULL, next_certificate_expires_at = NULL, next_certificate_key_id = NULL
                 WHERE id = @tenantId AND next_certificate_secret_name IS NOT NULL
                """, new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, actor, "tenant.certificate_rotated", $"tenant:{tenantId}", new { method = "add_key" }, cancellationToken)
                .ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        credentials.Invalidate(tenantId);

        if (oldKeyId is not { } old)
        {
            return new RotationOutcome(true, false, "The new certificate is in use. Vaulty does not know the old key's ID; it stops working on its end date, or remove it in Entra.");
        }
        try
        {
            var token = await graph.Tokens.GetTokenAsync(tenantId, forceRefresh: true, cancellationToken).ConfigureAwait(false);
            await registrations.RemoveKeyAsync(token.AccessToken, objectId, old, CertificateJwt.KeyProof(nextCredential.Certificate, objectId, clock.GetUtcNow()),
                cancellationToken).ConfigureAwait(false);
            await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, actor, "tenant.old_certificate_removed", $"tenant:{tenantId}", null, cancellationToken).ConfigureAwait(false);
            await session.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new RotationOutcome(true, true, "The new certificate is in use and the old one was removed from the app registration.");
        }
        catch (Exception ex) when (ex is GraphException or Microsoft.Identity.Client.MsalException or HttpRequestException)
        {
            logger.LogWarning("removeKey for an old tenant certificate failed: {Error}", ex is GraphException g ? $"{(int)g.Status} {g.Code}" : ex.GetType().Name);
            return new RotationOutcome(true, false, "The new certificate is in use. Microsoft did not remove the old one; it stops working on its end date, or remove it in Entra.");
        }
    }

    /// <summary>Tenants whose certificate Vaulty can roll itself and that expire within <see cref="RenewBefore"/>.</summary>
    public async Task<IReadOnlyList<(Guid OrganizationId, Guid TenantId)>> DueAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return (await connection.QueryAsync<(Guid, Guid)>(new CommandDefinition("SELECT organization_id, tenant_id FROM vaulty.tenants_due_for_rotation(@before)",
            new { before = clock.GetUtcNow() + RenewBefore }, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();
    }
}

/// <summary>Renews expiring certificates of tenants and of the setup app, a few times a day.</summary>
public sealed class CertificateRotationService(CertificateRotation rotation, SetupAppService setupApp, TimeProvider clock, ILogger<CertificateRotationService> logger)
    : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            await RunOnceAsync(stoppingToken).ConfigureAwait(false);
            await Task.Delay(Interval, stoppingToken).ConfigureAwait(false);
        }
    }

    public async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        try
        {
            foreach (var (organizationId, tenantId) in await rotation.DueAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    var outcome = await rotation.RotateAsync(organizationId, "system:rotation", tenantId, cancellationToken).ConfigureAwait(false);
                    logger.LogInformation("Certificate rotation of tenant {TenantId}: rotated {Rotated}, old key removed {Removed}", tenantId, outcome.Rotated,
                        outcome.OldKeyRemoved);
                }
                catch (Exception ex) when (ex is TenantException or InvalidOperationException or NpgsqlException)
                {
                    logger.LogWarning("Certificate rotation of tenant {TenantId} failed: {Error}", tenantId, ex.GetType().Name);
                }
            }
            var setup = await setupApp.GetAsync(cancellationToken).ConfigureAwait(false);
            if (setup.ApplicationObjectId is not null && setup.CertificateExpiresAt is { } expires && expires - clock.GetUtcNow() < CertificateRotation.RenewBefore)
            {
                await setupApp.RenewCertificateAsync("system:rotation", cancellationToken).ConfigureAwait(false);
                logger.LogInformation("The certificate of the Vaulty setup app was renewed.");
            }
        }
        catch (Exception ex) when (ex is TenantException or IdentityException or GraphException or HttpRequestException or NpgsqlException)
        {
            logger.LogWarning("Certificate renewal stopped: {Error}", ex.GetType().Name);
        }
    }
}
