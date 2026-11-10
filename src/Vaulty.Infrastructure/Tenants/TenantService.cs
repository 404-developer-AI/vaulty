using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Domain;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Tenants;

public sealed class TenantException(string message) : InvalidOperationException(message);

public sealed record CustomerRow(Guid Id, string Code, string Name, string[] Tags, int Tenants);

public sealed record TenantRow(Guid Id, Guid CustomerId, string CustomerName, Guid EntraTenantId, string DisplayName, string? DefaultDomain,
    Guid? ClientId, string ConsentState, DateTimeOffset? CertificateExpiresAt, DateTimeOffset? NextCertificateExpiresAt,
    DateTimeOffset? LastHealthCheckAt, string Health, string GrantedPermissions, int ProtectedObjects);

public sealed record ProtectedObjectRow(Guid Id, string Kind, string? SubKind, string SourceId, string DisplayName, string State,
    DateTimeOffset? SourceDeletedAt, DateTimeOffset? LastBackupAt, string? LastSnapshotState, string SourceDetails);

public sealed record PendingConnection(Guid Id, Guid CustomerId, string DisplayName, string CertificateThumbprint, DateTimeOffset CertificateExpiresAt,
    string Script, IReadOnlyList<string> ManualSteps, string CertificatePem);

/// <summary>Customers of an organization.</summary>
public sealed class CustomerService(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<CustomerRow>> ListAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        // Npgsql reports a text[] column as System.Array, which no record constructor matches: the rows are mapped here.
        var rows = await session.Connection.QueryAsync<(Guid Id, string Code, string Name, Array Tags, int Tenants)>(new CommandDefinition(
            """
            SELECT c.id, c.code, c.name, c.tags, (SELECT count(*)::int FROM vaulty.tenants t WHERE t.customer_id = c.id AND t.state <> 'deleted') AS tenants
              FROM vaulty.customers c WHERE c.deleted_at IS NULL ORDER BY lower(c.name)
            """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new CustomerRow(r.Id, r.Code, r.Name, r.Tags.Cast<string>().ToArray(), r.Tenants)).ToList();
    }

    public async Task<Guid> CreateAsync(Guid organizationId, Guid actor, string code, string name, IEnumerable<string> tags,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(name)) throw new TenantException("Enter a customer code and a customer name.");
        var id = Guid.CreateVersion7();
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        try
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO vaulty.customers (id, organization_id, code, name, tags) VALUES (@id, @organizationId, @code, @name, @tags)",
                new { id, organizationId, code = code.Trim(), name = name.Trim(), tags = Tags(tags) }, session.Transaction,
                cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            throw new TenantException($"A customer with code {code.Trim()} already exists.");
        }
        await AuditLog.WriteAsync(session, $"user:{actor}", "customer.created", $"customer:{id}", new { code, name }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return id;
    }

    public async Task UpdateAsync(Guid organizationId, Guid actor, Guid customerId, string name, IEnumerable<string> tags,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.customers SET name = @name, tags = @tags WHERE id = @customerId",
            new { customerId, name = name.Trim(), tags = Tags(tags) }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor}", "customer.updated", $"customer:{customerId}", new { name }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string[] Tags(IEnumerable<string> tags) =>
        tags.Select(t => t.Trim().ToLowerInvariant()).Where(t => t.Length is > 0 and <= 40).Distinct(StringComparer.Ordinal).ToArray();
}

/// <summary>Connecting tenants (dedicated app per tenant), probing their permissions, rotating their certificate, and listing them.</summary>
public sealed class TenantService(NpgsqlDataSource dataSource, ISecretStore secrets, DedicatedAppCredentialProvider credentials, GraphServices graph,
    TimeProvider clock)
{
    public const string AppName = "Vaulty";

    public static string CertificateSecret(Guid id, string suffix = "") => $"tenant.{id:N}.certificate{suffix}";

    /// <summary>Step 1: a certificate for the new app registration (private key straight into the secrets store) and the script.</summary>
    public async Task<PendingConnection> BeginConnectAsync(Guid organizationId, Guid actor, Guid customerId, string displayName,
        bool includeRestore = true, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(displayName)) throw new TenantException("Enter a name for the tenant.");
        var id = Guid.CreateVersion7();
        var certificate = TenantCertificate.Create(displayName, clock);
        var secretName = CertificateSecret(id, ".pending");
        await secrets.SetAsync(secretName, certificate.Pfx, $"user:{actor}", cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.pending_tenant_connections (id, organization_id, customer_id, display_name, certificate_secret_name,
                certificate_thumbprint, certificate_expires_at, created_by)
            VALUES (@id, @organizationId, @customerId, @displayName, @secretName, @thumbprint, @expires, @actor)
            """, new { id, organizationId, customerId, displayName = displayName.Trim(), secretName, thumbprint = certificate.Thumbprint,
                expires = certificate.NotAfter, actor }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor}", "tenant.connect_started", $"customer:{customerId}", new { displayName },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new PendingConnection(id, customerId, displayName.Trim(), certificate.Thumbprint, certificate.NotAfter,
            OnboardingScript.PowerShell(AppName, certificate, includeRestore), OnboardingScript.ManualSteps(AppName, includeRestore),
            OnboardingScript.CertificatePem(certificate));
    }

    /// <summary>
    /// Step 2: the tenant id and client id the administrator copied from the script. Refused when the tenant is already
    /// connected to Vaulty, by this or any other organization.
    /// </summary>
    public async Task<Guid> CompleteConnectAsync(Guid organizationId, Guid actor, Guid pendingId, Guid entraTenantId, Guid clientId,
        CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var pending = await session.Connection.QuerySingleOrDefaultAsync<(Guid CustomerId, string DisplayName, string SecretName, string Thumbprint, DateTime Expires)?>(
            new CommandDefinition(
                """
                SELECT customer_id, display_name, certificate_secret_name, certificate_thumbprint, certificate_expires_at
                  FROM vaulty.pending_tenant_connections WHERE id = @pendingId
                """, new { pendingId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)
            ?? throw new TenantException("This connection was not started or was already completed.");
        if (await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition("SELECT vaulty.entra_tenant_connected(@entraTenantId)",
                new { entraTenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false))
        {
            throw new TenantException("This Microsoft 365 tenant is already connected to Vaulty. Disconnect it there first.");
        }

        // Move the certificate from the pending name to the tenant's name.
        var tenantId = Guid.CreateVersion7();
        using (var certificate = await secrets.GetAsync(pending.SecretName, cancellationToken).ConfigureAwait(false)
                                 ?? throw new TenantException("The certificate of this connection is missing."))
        {
            await secrets.SetAsync(CertificateSecret(tenantId), certificate.Reveal().ToArray(), $"user:{actor}", cancellationToken).ConfigureAwait(false);
        }
        try
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name, auth_mode, client_id,
                    certificate_secret_name, certificate_thumbprint, certificate_expires_at, consent_state)
                VALUES (@tenantId, @organizationId, @customerId, @entraTenantId, @displayName, 'dedicated_app', @clientId,
                    @secretName, @thumbprint, @expires, 'pending');
                DELETE FROM vaulty.pending_tenant_connections WHERE id = @pendingId;
                INSERT INTO vaulty.policies (id, organization_id, tenant_id, name) VALUES (@policyId, @organizationId, @tenantId, 'Default');
                """,
                new
                {
                    tenantId, organizationId, pending.CustomerId, entraTenantId, pending.DisplayName, clientId,
                    secretName = CertificateSecret(tenantId), pending.Thumbprint, expires = DateTime.SpecifyKind(pending.Expires, DateTimeKind.Utc),
                    pendingId, policyId = Guid.CreateVersion7(),
                }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            throw new TenantException("This Microsoft 365 tenant is already connected to Vaulty. Disconnect it there first.");
        }
        await AuditLog.WriteAsync(session, $"user:{actor}", "tenant.connected", $"tenant:{tenantId}",
            new { entra_tenant_id = entraTenantId, client_id = clientId }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        await secrets.PruneAsync(pending.SecretName, 1, cancellationToken).ConfigureAwait(false);
        return tenantId;
    }

    /// <summary>Checks the app's permissions now and records the result; consent is "granted" once backup permissions work.</summary>
    public async Task<PermissionProbeReport> ProbeAsync(Guid organizationId, Guid actor, Guid tenantId, CancellationToken cancellationToken = default)
    {
        credentials.Invalidate(tenantId);
        var report = await graph.Probe().ProbeAsync(tenantId, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.tenants SET consent_state = CASE WHEN @ready THEN 'granted' ELSE consent_state END,
                   consent_lost_at = CASE WHEN @ready THEN NULL ELSE consent_lost_at END,
                   granted_permissions = @granted::jsonb, last_health_check_at = now(),
                   health = jsonb_build_object('status', CASE WHEN @ready THEN 'healthy' ELSE 'permissions_missing' END,
                                               'detail', @detail, 'checked_at', now())
             WHERE id = @tenantId
            """,
            new
            {
                tenantId, ready = report.BackupReady, detail = report.BackupReady ? "All backup permissions work." : "Missing: " + string.Join(", ", report.Missing),
                granted = JsonSerializer.Serialize(report.Permissions.Where(p => p.Status == ProbeStatus.Present).Select(p => p.Permission.Name)),
            }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor}", "tenant.probed", $"tenant:{tenantId}",
            new { backup_ready = report.BackupReady, restore_ready = report.RestoreReady, missing = report.Missing }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return report;
    }

    /// <summary>Rotation step 1: a new certificate and the script that adds its public key to the app registration.</summary>
    public async Task<string> BeginRotationAsync(Guid organizationId, Guid actor, Guid tenantId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var tenant = await session.Connection.QuerySingleAsync<(string DisplayName, Guid? ClientId)>(new CommandDefinition(
            "SELECT display_name, client_id FROM vaulty.tenants WHERE id = @tenantId", new { tenantId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        var certificate = TenantCertificate.Create(tenant.DisplayName, clock);
        var secretName = CertificateSecret(tenantId, ".next");
        await secrets.SetAsync(secretName, certificate.Pfx, $"user:{actor}", cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.tenants SET next_certificate_secret_name = @secretName, next_certificate_thumbprint = @thumbprint,
                   next_certificate_expires_at = @expires WHERE id = @tenantId
            """, new { tenantId, secretName, thumbprint = certificate.Thumbprint, expires = certificate.NotAfter }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor}", "tenant.certificate_rotation_started", $"tenant:{tenantId}", null, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return RotationScript(tenant.ClientId ?? Guid.Empty, certificate);
    }

    /// <summary>
    /// Rotation step 2: the new certificate must authenticate before it replaces the old one. Afterwards the old key can be
    /// removed from the app registration.
    /// </summary>
    public async Task CompleteRotationAsync(Guid organizationId, Guid actor, Guid tenantId, CancellationToken cancellationToken = default)
    {
        var next = await credentials.GetNextAsync(tenantId, cancellationToken).ConfigureAwait(false);
        var probe = new MsalGraphProbe();
        await probe.AcquireAsync(next, cancellationToken).ConfigureAwait(false);
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.tenants SET certificate_secret_name = next_certificate_secret_name, certificate_thumbprint = next_certificate_thumbprint,
                   certificate_expires_at = next_certificate_expires_at, next_certificate_secret_name = NULL, next_certificate_thumbprint = NULL,
                   next_certificate_expires_at = NULL
             WHERE id = @tenantId AND next_certificate_secret_name IS NOT NULL
            """, new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor}", "tenant.certificate_rotated", $"tenant:{tenantId}", null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        credentials.Invalidate(tenantId);
    }

    public static string RotationScript(Guid clientId, TenantCertificateMaterial certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return $$"""
            #Requires -Version 7.2
            # Adds Vaulty's new certificate to the app registration. The old certificate keeps working until you remove it.
            $ErrorActionPreference = 'Stop'
            Connect-MgGraph -Scopes 'Application.ReadWrite.All' -NoWelcome
            $App = Get-MgApplication -Filter "appId eq '{{clientId}}'"
            $Keys = @($App.KeyCredentials | ForEach-Object { @{ Type = $_.Type; Usage = $_.Usage; Key = $_.Key; DisplayName = $_.DisplayName; EndDateTime = $_.EndDateTime } })
            $Keys += @{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = [Convert]::FromBase64String('{{certificate.PublicCertificateBase64}}');
                        EndDateTime = [DateTime]::Parse('{{certificate.NotAfter.UtcDateTime:O}}').ToUniversalTime(); DisplayName = 'Vaulty {{certificate.NotAfter:yyyy-MM-dd}}' }
            Update-MgApplication -ApplicationId $App.Id -KeyCredentials $Keys
            Write-Host 'Done. Return to Vaulty and confirm the rotation; then remove the old certificate from the app registration.'
            """;
    }

    public sealed record PolicyView(int FrequencyMinutes, int RetentionDays, string[] ExcludedFolders);

    public async Task<PolicyView> PolicyAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<(int Frequency, int Retention, string Exclusions)?>(new CommandDefinition(
            "SELECT frequency_minutes, retention_days, exclusions::text FROM vaulty.policies WHERE tenant_id = @tenantId AND protected_object_id IS NULL",
            new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (row is not { } r) return new PolicyView(Policy.DefaultFrequencyMinutes, Policy.MinimumRetentionDays, []);
        using var doc = JsonDocument.Parse(r.Exclusions);
        var folders = doc.RootElement.TryGetProperty("folders", out var f) && f.ValueKind == JsonValueKind.Array
            ? f.EnumerateArray().Select(x => x.GetString()).OfType<string>().ToArray() : [];
        return new PolicyView(r.Frequency, r.Retention, folders);
    }

    /// <summary>Saves the tenant policy. Retention is at least 90 days; changing it is audited separately.</summary>
    public async Task SavePolicyAsync(Guid organizationId, Guid actor, Guid tenantId, PolicyView policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.RetentionDays < Policy.MinimumRetentionDays) throw new TenantException("Retention is at least 90 days.");
        if (policy.FrequencyMinutes is < 60 or > 10080) throw new TenantException("Back up every 1 to 168 hours.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var previous = await session.Connection.ExecuteScalarAsync<int?>(new CommandDefinition(
            "SELECT retention_days FROM vaulty.policies WHERE tenant_id = @tenantId AND protected_object_id IS NULL", new { tenantId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.policies (id, organization_id, tenant_id, name, frequency_minutes, retention_days, exclusions)
            VALUES (@id, @organizationId, @tenantId, 'Default', @FrequencyMinutes, @RetentionDays, @exclusions::jsonb)
            ON CONFLICT (tenant_id, coalesce(protected_object_id, '00000000-0000-0000-0000-000000000000'::uuid)) DO UPDATE SET
                frequency_minutes = excluded.frequency_minutes, retention_days = excluded.retention_days, exclusions = excluded.exclusions, updated_at = now()
            """, new { id = Guid.CreateVersion7(), organizationId, tenantId, policy.FrequencyMinutes, policy.RetentionDays,
                exclusions = JsonSerializer.Serialize(new { folders = policy.ExcludedFolders }) }, session.Transaction, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor}", previous != policy.RetentionDays ? "policy.retention_changed" : "policy.updated", $"tenant:{tenantId}",
            new { frequency_minutes = policy.FrequencyMinutes, retention_days = policy.RetentionDays, previous_retention_days = previous,
                excluded_folders = policy.ExcludedFolders }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<TenantRow>> ListAsync(Guid organizationId, Guid? customerId = null, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<TenantDbRow>(new CommandDefinition(
            """
            SELECT t.id, t.customer_id, c.name AS customer_name, t.entra_tenant_id, t.display_name, t.default_domain, t.client_id, t.consent_state,
                   t.certificate_expires_at, t.next_certificate_expires_at, t.last_health_check_at, t.health::text AS health,
                   t.granted_permissions::text AS granted_permissions,
                   (SELECT count(*)::int FROM vaulty.protected_objects o WHERE o.tenant_id = t.id) AS protected_objects
              FROM vaulty.tenants t JOIN vaulty.customers c ON c.id = t.customer_id
             WHERE t.state <> 'deleted' AND (@customerId IS NULL OR t.customer_id = @customerId)
             ORDER BY lower(c.name), lower(t.display_name)
            """, new { customerId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => r.ToRow()).ToList();
    }

    public async Task<IReadOnlyList<ProtectedObjectRow>> ProtectedObjectsAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var rows = await session.Connection.QueryAsync<(Guid Id, string Kind, string? SubKind, string SourceId, string DisplayName, string State,
            DateTime? SourceDeletedAt, DateTime? LastBackupAt, string? LastSnapshotState, string SourceDetails)>(new CommandDefinition(
            """
            SELECT o.id, o.kind, o.sub_kind, o.source_id, o.display_name, o.state, o.source_deleted_at, s.committed_at, s.state, o.source_details::text
              FROM vaulty.protected_objects o LEFT JOIN vaulty.snapshots s ON s.id = o.last_snapshot_id
             WHERE o.tenant_id = @tenantId ORDER BY o.kind, lower(o.display_name)
            """, new { tenantId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => new ProtectedObjectRow(r.Id, r.Kind, r.SubKind, r.SourceId, r.DisplayName, r.State, Utc(r.SourceDeletedAt),
            Utc(r.LastBackupAt), r.LastSnapshotState, r.SourceDetails)).ToList();
    }

    private static DateTimeOffset? Utc(DateTime? value) => value is { } v ? new DateTimeOffset(DateTime.SpecifyKind(v, DateTimeKind.Utc)) : null;

    private sealed class TenantDbRow
    {
        public Guid Id { get; set; }
        public Guid CustomerId { get; set; }
        public string CustomerName { get; set; } = "";
        public Guid EntraTenantId { get; set; }
        public string DisplayName { get; set; } = "";
        public string? DefaultDomain { get; set; }
        public Guid? ClientId { get; set; }
        public string ConsentState { get; set; } = "";
        public DateTime? CertificateExpiresAt { get; set; }
        public DateTime? NextCertificateExpiresAt { get; set; }
        public DateTime? LastHealthCheckAt { get; set; }
        public string Health { get; set; } = "{}";
        public string GrantedPermissions { get; set; } = "[]";
        public int ProtectedObjects { get; set; }

        public TenantRow ToRow() => new(Id, CustomerId, CustomerName, EntraTenantId, DisplayName, DefaultDomain, ClientId, ConsentState,
            Utc(CertificateExpiresAt), Utc(NextCertificateExpiresAt), Utc(LastHealthCheckAt), Health, GrantedPermissions, ProtectedObjects);
    }
}

/// <summary>Acquires a token with a specific credential (used to test a rotated certificate before switching to it).</summary>
internal sealed class MsalGraphProbe
{
    public async Task AcquireAsync(Graph.Auth.GraphCredential credential, CancellationToken cancellationToken)
    {
        var provider = new Graph.Auth.MsalGraphTokenProvider(new SingleCredential(credential));
        await provider.GetTokenAsync(Guid.Empty, true, cancellationToken).ConfigureAwait(false);
    }

    private sealed class SingleCredential(Graph.Auth.GraphCredential credential) : Graph.Auth.IGraphCredentialProvider
    {
        public Task<Graph.Auth.GraphCredential> GetAsync(Guid tenantId, CancellationToken cancellationToken = default) => Task.FromResult(credential);
    }
}
