using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Microsoft.Extensions.Logging;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Graph;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Infrastructure.Tenants;

public enum SignInPurpose
{
    /// <summary>Create the app registration in a customer's tenant (target: the pending connection).</summary>
    Connect,
    /// <summary>Repair the app registration of a connected tenant (target: the tenant).</summary>
    Repair,
    /// <summary>Read the setup app's own registration in the home tenant (target: none).</summary>
    SetupCheck,
}

/// <summary>A sign-in Vaulty sent an administrator to; held in memory until Microsoft redirects back (at most ten minutes).</summary>
public sealed record SignInRequest(string State, SignInPurpose Purpose, Guid OrganizationId, Guid UserId, Guid TargetId, string Authority,
    Uri RedirectUri, string CodeVerifier, string Nonce, string ReturnPath, bool IncludeRestore, DateTimeOffset ExpiresAt);

/// <summary>
/// Pending sign-ins, keyed by an unguessable state value that is bound to the Vaulty user and the connection it started for.
/// Each state works once. Kept in memory only: a restart means starting the sign-in again, and nothing is left behind.
/// </summary>
public sealed class MicrosoftSignIns(TimeProvider clock)
{
    public static readonly TimeSpan Validity = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<string, SignInRequest> _requests = new(StringComparer.Ordinal);

    public SignInRequest Create(SignInPurpose purpose, Guid organizationId, Guid userId, Guid targetId, string authority, Uri redirectUri, string returnPath,
        bool includeRestore)
    {
        Sweep();
        var request = new SignInRequest(CertificateJwt.Base64Url(RandomNumberGenerator.GetBytes(32)), purpose, organizationId, userId, targetId, authority,
            redirectUri, Pkce.NewVerifier(), CertificateJwt.Base64Url(RandomNumberGenerator.GetBytes(16)), returnPath, includeRestore, clock.GetUtcNow() + Validity);
        _requests[request.State] = request;
        return request;
    }

    /// <summary>The request for a state, removed so it cannot be used again; null when unknown, used or expired.</summary>
    public SignInRequest? Take(string? state)
    {
        if (string.IsNullOrEmpty(state) || !_requests.TryRemove(state, out var request)) return null;
        return request.ExpiresAt > clock.GetUtcNow() ? request : null;
    }

    private void Sweep()
    {
        var now = clock.GetUtcNow();
        foreach (var (state, request) in _requests)
        {
            if (request.ExpiresAt <= now) _requests.TryRemove(state, out _);
        }
    }
}

public enum SetupRunState
{
    Running,
    Succeeded,
    Failed,
}

/// <summary>What the page shows of a browser set-up: the steps done, the outcome, and where to go next. Never the token.</summary>
/// <param name="TargetId">The pending connection (connect) or the tenant (repair) the run is for.</param>
public sealed record SetupRunView(Guid Id, SignInPurpose Purpose, SetupRunState State, IReadOnlyList<string> Done, string? Current, string? Message,
    IReadOnlyList<string> Warnings, Guid? TenantId, Guid TargetId, bool IncludeRestore);

/// <summary>Settings of a browser set-up that tests shorten.</summary>
public sealed record BrowserConnectionOptions
{
    /// <summary>How often and how long apart the permission check of a new app is tried before Vaulty leaves it to the tenant page.</summary>
    public int ProbeAttempts { get; init; } = 8;
    public TimeSpan ProbeWait { get; init; } = TimeSpan.FromSeconds(20);
}

/// <summary>
/// Runs what an administrator's sign-in allows: creating or repairing the dedicated app registration in the customer's
/// tenant, or checking the setup app. The delegated token lives in this object only while the run lasts and is dropped
/// at the end; it is never written to the database, the secrets store, a log or the audit log. Each step of a new
/// connection is recorded on the pending connection, so signing in again resumes where an interrupted run stopped.
/// </summary>
public sealed class BrowserConnection(NpgsqlDataSource dataSource, ISecretStore secrets, DedicatedAppCredentialProvider credentials, GraphServices graph,
    SetupAppService setupApp, IdentityClient identity, AppRegistrationClient registrations, MicrosoftSignIns signIns, TimeProvider clock,
    ILogger<BrowserConnection> logger, BrowserConnectionOptions? options = null)
{
    private readonly ConcurrentDictionary<Guid, Run> _runs = new();
    private readonly ConcurrentDictionary<Guid, Guid> _activeTargets = new();
    private readonly BrowserConnectionOptions _options = options ?? new BrowserConnectionOptions();

    private TenantService Tenants => new(dataSource, secrets, credentials, graph, clock);

    /// <summary>Where to send the administrator to sign in. The setup app must be ready (Settings → Microsoft 365).</summary>
    public async Task<Uri> BeginAsync(SignInPurpose purpose, Guid organizationId, Guid userId, Guid targetId, Uri redirectUri, string returnPath,
        bool includeRestore, string? tenantHint = null, bool consent = true, CancellationToken cancellationToken = default)
    {
        var setup = await setupApp.GetAsync(cancellationToken).ConfigureAwait(false);
        if (setup.ClientId is not { } clientId) throw new TenantException("The Vaulty setup app is not set up yet. Set it up under Settings > Microsoft 365.");
        if (purpose != SignInPurpose.SetupCheck && !setup.Ready)
        {
            throw new TenantException("The Vaulty setup app is not ready. Finish its checks under Settings > Microsoft 365, or use the script.");
        }
        var authority = purpose == SignInPurpose.SetupCheck ? setup.HomeTenantId!.Value.ToString()
            : string.IsNullOrWhiteSpace(tenantHint) ? "organizations" : NormalizeTenant(tenantHint);
        var request = signIns.Create(purpose, organizationId, userId, targetId, authority, redirectUri, returnPath, includeRestore);
        return identity.AuthorizationUrl(authority, clientId, redirectUri, request.State, request.Nonce, Pkce.Challenge(request.CodeVerifier), consent);
    }

    /// <summary>A customer tenant domain or id for a GDAP sign-in from a partner tenant.</summary>
    public static string NormalizeTenant(string hint)
    {
        var value = hint.Trim().ToLowerInvariant();
        if (Guid.TryParse(value, out var id)) return id.ToString();
        if (Uri.CheckHostName(value) == UriHostNameType.Dns && value.Contains('.', StringComparison.Ordinal)) return value;
        throw new TenantException("Enter the customer's tenant as a domain such as contoso.onmicrosoft.com, or as its tenant ID.");
    }

    /// <summary>
    /// Microsoft redirected back. Redeems the code (PKCE, the setup app's certificate), checks the nonce, and starts the run.
    /// Returns the path the browser continues on; the run id is in its query string.
    /// </summary>
    public async Task<string> CompleteSignInAsync(string? state, string? code, string? error, string? errorDescription, CancellationToken cancellationToken = default)
    {
        var request = signIns.Take(state);
        if (request is null) return "/connect/microsoft/expired";
        if (!string.IsNullOrEmpty(error) || string.IsNullOrEmpty(code))
        {
            return ContinueAt(request, Failed(request, SignInErrors.Explain(error, errorDescription)));
        }
        DelegatedToken token;
        try
        {
            var setup = await setupApp.GetAsync(cancellationToken).ConfigureAwait(false);
            using var certificate = await setupApp.LoadCertificateAsync(SetupAppSettings.CertificateSecretName, cancellationToken).ConfigureAwait(false);
            token = await identity.RedeemCodeAsync(request.Authority, setup.ClientId!.Value, certificate, request.RedirectUri, code, request.CodeVerifier,
                cancellationToken).ConfigureAwait(false);
        }
        catch (IdentityException ex)
        {
            return ContinueAt(request, Failed(request, SignInErrors.Explain(ex.Error, ex.Description)));
        }
        catch (Exception ex) when (ex is HttpRequestException or TenantException or FormatException or JsonException)
        {
            return ContinueAt(request, Failed(request, ex is TenantException ? ex.Message : "Microsoft could not be reached or answered unexpectedly. Start again."));
        }
        if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.UTF8.GetBytes(token.User.Nonce ?? ""), System.Text.Encoding.UTF8.GetBytes(request.Nonce)))
        {
            return ContinueAt(request, Failed(request, "The sign-in could not be verified. Start again."));
        }
        return ContinueAt(request, Start(request, token));
    }

    private static string ContinueAt(SignInRequest request, Guid runId) =>
        $"{request.ReturnPath}{(request.ReturnPath.Contains('?', StringComparison.Ordinal) ? "&" : "?")}run={runId}";

    /// <summary>The state of a run, for the Vaulty user who started it only.</summary>
    public SetupRunView? Get(Guid runId, Guid userId) =>
        _runs.TryGetValue(runId, out var run) && run.Request.UserId == userId ? run.View() : null;

    /// <summary>Waits for a run to end (tests and callers that do not poll).</summary>
    public async Task<SetupRunView> WaitAsync(Guid runId, Guid userId)
    {
        if (!_runs.TryGetValue(runId, out var run) || run.Request.UserId != userId) throw new TenantException("This set-up does not exist.");
        await run.Completion.ConfigureAwait(false);
        return run.View();
    }

    private Guid Failed(SignInRequest request, string message)
    {
        var run = new Run(request, null);
        run.Fail(message);
        run.Finish();
        _runs[run.Id] = run;
        return run.Id;
    }

    private Guid Start(SignInRequest request, DelegatedToken token)
    {
        var run = new Run(request, token);
        _runs[run.Id] = run;
        if (request.Purpose != SignInPurpose.SetupCheck && !_activeTargets.TryAdd(request.TargetId, run.Id))
        {
            run.DropToken();
            run.Fail("A set-up of this tenant is already running. Wait for it to finish.");
            run.Finish();
            return run.Id;
        }
        _ = Task.Run(() => ExecuteAsync(run));
        return run.Id;
    }

    private async Task ExecuteAsync(Run run)
    {
        try
        {
            switch (run.Request.Purpose)
            {
                case SignInPurpose.Connect:
                    await ConnectAsync(run).ConfigureAwait(false);
                    break;
                case SignInPurpose.Repair:
                    await RepairAsync(run).ConfigureAwait(false);
                    break;
                default:
                    run.Step("Reading the setup app registration");
                    var result = await setupApp.CheckRegistrationAsync(run.Token, run.Request.RedirectUri, $"user:{run.Request.UserId}").ConfigureAwait(false);
                    run.Succeed(result.Ready ? "Every required check passed. Tenants can now be connected from the browser." : "Some checks need attention; see below.");
                    break;
            }
        }
        catch (StopException ex)
        {
            run.Fail(ex.Message);
            await AuditFailureAsync(run, ex.Message).ConfigureAwait(false);
        }
        catch (GraphException ex)
        {
            logger.LogWarning("Browser set-up {Purpose} stopped: Graph {Status} {Code} (request-id {RequestId})", run.Request.Purpose, (int)ex.Status, ex.Code,
                ex.RequestId);
            run.Fail($"Microsoft Graph refused a step ({(int)ex.Status} {ex.Code}): {ex.Message.Split(": ", 2).Last()} Sign in again to continue where it stopped.");
            await AuditFailureAsync(run, $"{(int)ex.Status} {ex.Code}").ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TenantException or InvalidOperationException or NpgsqlException)
        {
            logger.LogWarning("Browser set-up {Purpose} stopped: {Error}", run.Request.Purpose, ex.GetType().Name);
            run.Fail(ex is TenantException ? ex.Message : "The set-up stopped before it finished. Sign in again to continue where it stopped.");
            await AuditFailureAsync(run, ex.GetType().Name).ConfigureAwait(false);
        }
        finally
        {
            run.DropToken();
            if (run.Request.Purpose != SignInPurpose.SetupCheck) _activeTargets.TryRemove(run.Request.TargetId, out _);
            run.Finish();
        }
    }

    private async Task AuditFailureAsync(Run run, string reason)
    {
        if (run.Request.Purpose == SignInPurpose.SetupCheck) return;
        try
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, run.Request.OrganizationId).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, $"user:{run.Request.UserId}",
                run.Request.Purpose == SignInPurpose.Connect ? "tenant.connect_failed" : "tenant.repair_failed",
                run.Request.Purpose == SignInPurpose.Connect ? $"pending_connection:{run.Request.TargetId}" : $"tenant:{run.Request.TargetId}",
                new { reason, step = run.Current }).ConfigureAwait(false);
            await session.CommitAsync().ConfigureAwait(false);
        }
        catch (NpgsqlException)
        {
        }
    }

    private sealed class StopException(string message) : Exception(message);

    // ---------------------------------------------------------------- connect

    private sealed record PendingRow(Guid CustomerId, string DisplayName, string SecretName, string Thumbprint, bool IncludeRestore, string Step,
        Guid? EntraTenantId, Guid? ApplicationObjectId, Guid? ClientId, Guid? CertificateKeyId, Guid CreatedBy);

    private async Task<PendingRow> PendingAsync(Guid organizationId, Guid pendingId)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId).ConfigureAwait(false);
        return await session.Connection.QuerySingleOrDefaultAsync<PendingRow>(new CommandDefinition(
                   """
                   SELECT customer_id AS customerid, display_name AS displayname, certificate_secret_name AS secretname, certificate_thumbprint AS thumbprint,
                          include_restore AS includerestore, step, entra_tenant_id AS entratenantid, application_object_id AS applicationobjectid,
                          client_id AS clientid, certificate_key_id AS certificatekeyid, created_by AS createdby
                     FROM vaulty.pending_tenant_connections WHERE id = @pendingId
                   """, new { pendingId }, session.Transaction)).ConfigureAwait(false)
               ?? throw new StopException("This connection was already completed or cancelled. Start a new one from the customer page.");
    }

    private async Task RecordAsync(Guid organizationId, Guid pendingId, string step, object values, string action, object auditDetails, Guid actor)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId).ConfigureAwait(false);
        var json = JsonSerializer.Serialize(values);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.pending_tenant_connections p SET step = @step, updated_at = now(),
                   entra_tenant_id = coalesce((v ->> 'entra_tenant_id')::uuid, p.entra_tenant_id),
                   application_object_id = CASE WHEN v ? 'application_object_id' THEN (v ->> 'application_object_id')::uuid ELSE p.application_object_id END,
                   client_id = CASE WHEN v ? 'client_id' THEN (v ->> 'client_id')::uuid ELSE p.client_id END,
                   certificate_key_id = CASE WHEN v ? 'certificate_key_id' THEN (v ->> 'certificate_key_id')::uuid ELSE p.certificate_key_id END
              FROM (SELECT @values::jsonb AS v) x
             WHERE p.id = @pendingId
            """, new { pendingId, step, values = json }, session.Transaction)).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{actor}", action, $"pending_connection:{pendingId}", auditDetails).ConfigureAwait(false);
        await session.CommitAsync().ConfigureAwait(false);
    }

    private async Task ConnectAsync(Run run)
    {
        var request = run.Request;
        var token = run.Token;
        var user = token.User;
        run.Step("Checking the tenant and your account");
        var pending = await PendingAsync(request.OrganizationId, request.TargetId).ConfigureAwait(false);
        if (pending.CreatedBy != request.UserId) throw new StopException("This connection was started by another Vaulty user.");
        if (pending.EntraTenantId is { } started && started != user.TenantId)
        {
            await RemoveSetupAppAsync(run, quiet: true).ConfigureAwait(false);
            throw new StopException($"You signed in to tenant {user.TenantId}, but this connection started in tenant {started}. Sign in with an account of that tenant.");
        }
        if (await TenantConnectedAsync(request.OrganizationId, user.TenantId).ConfigureAwait(false))
        {
            await RemoveSetupAppAsync(run, quiet: true).ConfigureAwait(false);
            throw new StopException("This Microsoft 365 tenant is already connected to Vaulty. Nothing was changed in the tenant.");
        }
        if (!user.MayGrantPermissions)
        {
            await RemoveSetupAppAsync(run, quiet: true).ConfigureAwait(false);
            throw new StopException($"{user.UserName} is not a Global Administrator or Privileged Role Administrator of the tenant, so it cannot grant the permissions. Nothing was changed in the tenant; sign in with an administrator.");
        }
        await RecordAsync(request.OrganizationId, request.TargetId, pending.Step == "started" ? "signed_in" : pending.Step,
            new { entra_tenant_id = user.TenantId }, "tenant.connect_signed_in",
            new { entra_tenant_id = user.TenantId, administrator = user.UserName }, request.UserId).ConfigureAwait(false);

        var resource = await registrations.GraphResourceAsync(token.AccessToken).ConfigureAwait(false);
        var roleIds = RoleIds(resource, pending.IncludeRestore);
        using var secret = await secrets.GetAsync(pending.SecretName).ConfigureAwait(false) ?? throw new StopException("The certificate of this connection is missing.");
        var certificate = TenantCertificate.FromPfx(secret.Reveal());

        // The app registration: created once; a resumed run finds it by the object id it recorded.
        run.Step("Creating the app registration \"Vaulty\"");
        var app = pending.ClientId is { } knownClient ? await registrations.ApplicationAsync(token.AccessToken, knownClient).ConfigureAwait(false) : null;
        Guid objectId, clientId;
        Guid? keyId;
        if (app is not null && app.ObjectId == pending.ApplicationObjectId)
        {
            (objectId, clientId, keyId) = (app.ObjectId, app.AppId, pending.CertificateKeyId ?? app.KeyFor(certificate.Thumbprint)?.KeyId);
        }
        else
        {
            var named = await registrations.ApplicationsNamedAsync(token.AccessToken, TenantService.AppName).ConfigureAwait(false);
            if (named.Count > 0)
            {
                await RemoveSetupAppAsync(run, quiet: true).ConfigureAwait(false);
                throw new StopException($"An app registration named \"{TenantService.AppName}\" already exists in this tenant (application ID {named[0].AppId}). If it is an earlier Vaulty app, connect with the script's ID step, or remove it in Entra (App registrations) and start again.");
            }
            var created = await registrations.CreateApplicationAsync(token.AccessToken, TenantService.AppName, roleIds, certificate).ConfigureAwait(false);
            (objectId, clientId, keyId) = (created.ObjectId, created.AppId, created.KeyId);
            await RecordAsync(request.OrganizationId, request.TargetId, "app_created",
                new { application_object_id = objectId, client_id = clientId, certificate_key_id = keyId }, "tenant.connect_app_created",
                new { client_id = clientId, application_object_id = objectId }, request.UserId).ConfigureAwait(false);
        }

        run.Step("Creating the enterprise application");
        var servicePrincipal = await registrations.CreateServicePrincipalAsync(token.AccessToken, clientId).ConfigureAwait(false);
        await RecordAsync(request.OrganizationId, request.TargetId, "service_principal_created", new { }, "tenant.connect_service_principal_created",
            new { client_id = clientId }, request.UserId).ConfigureAwait(false);

        run.Step("Granting admin consent for the permissions");
        try
        {
            await GrantAsync(token.AccessToken, resource.ServicePrincipalId, servicePrincipal, roleIds).ConfigureAwait(false);
        }
        catch (GraphException ex) when (ex.Status is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
        {
            // The account could create an app but not grant application permissions: take the half-made app away again.
            await registrations.DeleteApplicationAsync(token.AccessToken, objectId).ConfigureAwait(false);
            await RecordAsync(request.OrganizationId, request.TargetId, "signed_in",
                new { application_object_id = (Guid?)null, client_id = (Guid?)null, certificate_key_id = (Guid?)null }, "tenant.connect_app_removed",
                new { client_id = clientId, reason = "permissions could not be granted" }, request.UserId).ConfigureAwait(false);
            await RemoveSetupAppAsync(run, quiet: true).ConfigureAwait(false);
            throw new StopException($"{user.UserName} may not grant application permissions in this tenant, so Vaulty removed the app it had just created. Sign in as a Global Administrator or Privileged Role Administrator.");
        }
        await RecordAsync(request.OrganizationId, request.TargetId, "permissions_granted", new { }, "tenant.connect_permissions_granted",
            new { client_id = clientId, permissions = roleIds.Count }, request.UserId).ConfigureAwait(false);

        run.Step("Saving the connection");
        var tenantId = await Tenants.CompleteConnectAsync(request.OrganizationId, request.UserId, request.TargetId, user.TenantId, clientId, default,
            new CreatedAppDetails(objectId, keyId, user.UserName)).ConfigureAwait(false);
        run.TenantId = tenantId;

        await FinishAsync(run, tenantId).ConfigureAwait(false);
        run.Succeed("The tenant is connected.");
    }

    private static List<Guid> RoleIds(GraphResourceApp resource, bool includeRestore)
    {
        var wanted = GraphPermissions.All.Where(p => includeRestore || !p.ForRestore).Select(p => p.Name).ToList();
        var missing = wanted.Where(w => resource.ApplicationRoles.All(r => r.Value != w)).ToList();
        if (missing.Count > 0) throw new StopException("Microsoft Graph has no application permission named " + string.Join(", ", missing) + ".");
        return wanted.Select(w => resource.ApplicationRoles.First(r => r.Value == w).Id).ToList();
    }

    private async Task GrantAsync(string token, Guid resourceId, Guid servicePrincipal, IReadOnlyList<Guid> roleIds)
    {
        var assigned = await registrations.AssignedRolesAsync(token, servicePrincipal, resourceId).ConfigureAwait(false);
        foreach (var role in roleIds.Where(r => !assigned.Contains(r)))
        {
            try
            {
                await registrations.AssignRoleAsync(token, resourceId, servicePrincipal, role).ConfigureAwait(false);
            }
            catch (GraphException ex) when (ex.Status == HttpStatusCode.Conflict)
            {
                // Already assigned (a concurrent or earlier run).
            }
        }
    }

    private async Task<bool> TenantConnectedAsync(Guid organizationId, Guid entraTenantId)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId).ConfigureAwait(false);
        return await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition("SELECT vaulty.entra_tenant_connected(@entraTenantId)",
            new { entraTenantId }, session.Transaction)).ConfigureAwait(false);
    }

    /// <summary>The permission check of the new or repaired app (Microsoft can take minutes), then the setup app leaves the tenant.</summary>
    private async Task FinishAsync(Run run, Guid tenantId)
    {
        run.Step("Checking the permissions of the app");
        var ready = false;
        for (var attempt = 1; attempt <= _options.ProbeAttempts && !ready; attempt++)
        {
            try
            {
                ready = (await Tenants.ProbeAsync(run.Request.OrganizationId, run.Request.UserId, tenantId).ConfigureAwait(false)).BackupReady;
            }
            catch (Exception ex) when (ex is Microsoft.Identity.Client.MsalException or HttpRequestException or InvalidOperationException or GraphException)
            {
                ready = false;
            }
            if (!ready && attempt < _options.ProbeAttempts) await Task.Delay(_options.ProbeWait).ConfigureAwait(false);
        }
        if (!ready) run.Warn("Microsoft has not activated the new app yet. Check permissions on the tenant page in a few minutes.");
        await RemoveSetupAppAsync(run, quiet: false).ConfigureAwait(false);
    }

    /// <summary>Removes the setup app's enterprise application (and so its consent) from the customer's tenant.</summary>
    private async Task RemoveSetupAppAsync(Run run, bool quiet)
    {
        run.Step("Removing the Vaulty setup app from the tenant");
        var setup = await setupApp.GetAsync().ConfigureAwait(false);
        try
        {
            if (setup.ClientId is { } setupClient && setup.HomeTenantId != run.Token.User.TenantId)
            {
                await registrations.DeleteServicePrincipalAsync(run.Token.AccessToken, setupClient).ConfigureAwait(false);
            }
            if (!quiet) await AuditStepAsync(run, "tenant.setup_app_removed", new { entra_tenant_id = run.Token.User.TenantId }).ConfigureAwait(false);
        }
        catch (GraphException ex)
        {
            logger.LogWarning("The setup app could not be removed from a tenant: Graph {Status} {Code}", (int)ex.Status, ex.Code);
            run.Warn($"Vaulty could not remove the \"{SetupAppSettings.DisplayName}\" enterprise application from the tenant. Remove it in Entra under Enterprise applications; the connection itself works.");
        }
    }

    private async Task AuditStepAsync(Run run, string action, object details)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, run.Request.OrganizationId).ConfigureAwait(false);
        var target = run.TenantId is { } t ? $"tenant:{t}" : run.Request.Purpose == SignInPurpose.Repair ? $"tenant:{run.Request.TargetId}" : $"pending_connection:{run.Request.TargetId}";
        await AuditLog.WriteAsync(session, $"user:{run.Request.UserId}", action, target, details).ConfigureAwait(false);
        await session.CommitAsync().ConfigureAwait(false);
    }

    // ---------------------------------------------------------------- repair

    private sealed record TenantRowForRepair(Guid EntraTenantId, Guid? ClientId, string CertificateSecretName, string CertificateThumbprint,
        string? NextCertificateSecretName, string State);

    private async Task RepairAsync(Run run)
    {
        var request = run.Request;
        var token = run.Token;
        var user = token.User;
        run.TenantId = request.TargetId;
        run.Step("Checking the tenant and your account");
        TenantRowForRepair tenant;
        await using (var session = await OrganizationSession.BeginAsync(dataSource, request.OrganizationId).ConfigureAwait(false))
        {
            tenant = await session.Connection.QuerySingleOrDefaultAsync<TenantRowForRepair>(new CommandDefinition(
                         """
                         SELECT entra_tenant_id AS entratenantid, client_id AS clientid, certificate_secret_name AS certificatesecretname,
                                certificate_thumbprint AS certificatethumbprint, next_certificate_secret_name AS nextcertificatesecretname, state
                           FROM vaulty.tenants WHERE id = @id
                         """, new { id = request.TargetId }, session.Transaction)).ConfigureAwait(false)
                     ?? throw new StopException("This tenant does not exist.");
        }
        if (tenant.State == "deleted") throw new StopException("This tenant is deleted.");
        if (tenant.EntraTenantId != user.TenantId)
        {
            await RemoveSetupAppAsync(run, quiet: true).ConfigureAwait(false);
            throw new StopException($"You signed in to tenant {user.TenantId}, but this Vaulty tenant is {tenant.EntraTenantId}. Sign in with an account of that tenant.");
        }
        if (!user.MayGrantPermissions)
        {
            await RemoveSetupAppAsync(run, quiet: true).ConfigureAwait(false);
            throw new StopException($"{user.UserName} is not a Global Administrator or Privileged Role Administrator of the tenant. Nothing was changed; sign in with an administrator.");
        }
        await AuditStepAsync(run, "tenant.repair_signed_in", new { administrator = user.UserName }).ConfigureAwait(false);

        var resource = await registrations.GraphResourceAsync(token.AccessToken).ConfigureAwait(false);
        var roleIds = RoleIds(resource, request.IncludeRestore);
        using var secret = await secrets.GetAsync(tenant.CertificateSecretName).ConfigureAwait(false) ?? throw new StopException("The tenant certificate is missing.");
        var certificate = TenantCertificate.FromPfx(secret.Reveal());
        TenantCertificateMaterial? next = null;
        if (tenant.NextCertificateSecretName is { } nextName)
        {
            using var nextSecret = await secrets.GetAsync(nextName).ConfigureAwait(false);
            if (nextSecret is not null) next = TenantCertificate.FromPfx(nextSecret.Reveal());
        }

        run.Step("Checking the app registration");
        var app = tenant.ClientId is { } client ? await registrations.ApplicationAsync(token.AccessToken, client).ConfigureAwait(false) : null;
        if (app is null)
        {
            // The app is gone: create it again with the tenant's certificate, and point the tenant at the new application ID.
            var named = await registrations.ApplicationsNamedAsync(token.AccessToken, TenantService.AppName).ConfigureAwait(false);
            if (named.Count > 0)
            {
                throw new StopException($"The app registration Vaulty used is gone, and another app named \"{TenantService.AppName}\" exists (application ID {named[0].AppId}). Correct the application ID on the Connection tab, or remove that app in Entra and repair again.");
            }
            run.Step("Creating the app registration \"Vaulty\" again");
            var created = await registrations.CreateApplicationAsync(token.AccessToken, TenantService.AppName, roleIds, certificate).ConfigureAwait(false);
            await Tenants.CorrectConnectionAsync(request.OrganizationId, request.UserId, request.TargetId, tenant.EntraTenantId, created.AppId).ConfigureAwait(false);
            await AuditStepAsync(run, "tenant.repair_app_created", new { client_id = created.AppId }).ConfigureAwait(false);
            app = await registrations.ApplicationAsync(token.AccessToken, created.AppId).ConfigureAwait(false)
                  ?? new ApplicationRegistration(created.ObjectId, created.AppId, TenantService.AppName, "AzureADMyOrg", [],
                      [new RegisteredKey(created.KeyId ?? Guid.Empty, certificate.Thumbprint, certificate.NotAfter)], 0, [], null);
        }
        else
        {
            var patch = new JsonObject();
            if (app.KeyFor(certificate.Thumbprint) is null)
            {
                // Vaulty's certificate is missing from the app (removed in Entra): the app then only carries Vaulty's keys.
                var keys = new JsonArray(AppRegistrationClient.KeyCredential(certificate, TenantService.AppName));
                if (next is not null) keys.Add(AppRegistrationClient.KeyCredential(next, TenantService.AppName));
                patch["keyCredentials"] = keys;
            }
            var graphId = Guid.Parse(OnboardingScript.GraphAppId);
            var requested = app.RequiredAccess.Where(a => a.ResourceAppId == graphId && a.Type == "Role").Select(a => a.Id).ToHashSet();
            if (!roleIds.All(requested.Contains))
            {
                patch["requiredResourceAccess"] = RequiredAccessWith(app, roleIds);
            }
            if (patch.Count > 0)
            {
                run.Step("Updating the app registration");
                await registrations.UpdateApplicationAsync(token.AccessToken, app.ObjectId, patch).ConfigureAwait(false);
                await AuditStepAsync(run, "tenant.repair_app_updated", new { certificate = patch.ContainsKey("keyCredentials"), permissions = patch.ContainsKey("requiredResourceAccess") })
                    .ConfigureAwait(false);
                app = await registrations.ApplicationAsync(token.AccessToken, app.AppId).ConfigureAwait(false) ?? app;
            }
        }

        run.Step("Granting admin consent for the permissions");
        var servicePrincipal = await registrations.CreateServicePrincipalAsync(token.AccessToken, app.AppId).ConfigureAwait(false);
        await GrantAsync(token.AccessToken, resource.ServicePrincipalId, servicePrincipal, roleIds).ConfigureAwait(false);

        await using (var session = await OrganizationSession.BeginAsync(dataSource, request.OrganizationId).ConfigureAwait(false))
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vaulty.tenants SET application_object_id = @objectId, certificate_key_id = @keyId,
                       next_certificate_key_id = coalesce(@nextKeyId, next_certificate_key_id)
                 WHERE id = @id
                """, new
                {
                    id = request.TargetId, objectId = app.ObjectId, keyId = app.KeyFor(certificate.Thumbprint)?.KeyId,
                    nextKeyId = next is null ? null : app.KeyFor(next.Thumbprint)?.KeyId,
                }, session.Transaction)).ConfigureAwait(false);
            await AuditLog.WriteAsync(session, $"user:{request.UserId}", "tenant.repaired", $"tenant:{request.TargetId}",
                new { client_id = app.AppId, administrator = user.UserName, restore = request.IncludeRestore }).ConfigureAwait(false);
            await session.CommitAsync().ConfigureAwait(false);
        }
        credentials.Invalidate(request.TargetId);
        await FinishAsync(run, request.TargetId).ConfigureAwait(false);
        run.Succeed("The connection is repaired.");
    }

    private static JsonArray RequiredAccessWith(ApplicationRegistration app, IEnumerable<Guid> roleIds)
    {
        var graphId = Guid.Parse(OnboardingScript.GraphAppId);
        var result = new JsonArray();
        foreach (var group in app.RequiredAccess.Where(a => a.ResourceAppId != graphId).GroupBy(a => a.ResourceAppId))
        {
            result.Add(new JsonObject
            {
                ["resourceAppId"] = group.Key.ToString(),
                ["resourceAccess"] = new JsonArray(group.Select(a => (JsonNode)new JsonObject { ["id"] = a.Id.ToString(), ["type"] = a.Type }).ToArray()),
            });
        }
        var graphAccess = app.RequiredAccess.Where(a => a.ResourceAppId == graphId).Select(a => (a.Id, a.Type))
            .Concat(roleIds.Select(r => (Id: r, Type: "Role"))).Distinct().ToList();
        result.Add(new JsonObject
        {
            ["resourceAppId"] = OnboardingScript.GraphAppId,
            ["resourceAccess"] = new JsonArray(graphAccess.Select(a => (JsonNode)new JsonObject { ["id"] = a.Id.ToString(), ["type"] = a.Type }).ToArray()),
        });
        return result;
    }

    // ---------------------------------------------------------------- run state

    private sealed class Run(SignInRequest request, DelegatedToken? token)
    {
        private readonly object _lock = new();
        private readonly List<string> _done = [];
        private readonly List<string> _warnings = [];
        private DelegatedToken? _token = token;
        private SetupRunState _state = SetupRunState.Running;
        private string? _message;
        private readonly TaskCompletionSource _finished = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Guid Id { get; } = Guid.NewGuid();
        public SignInRequest Request { get; } = request;
        public string? Current { get; private set; }
        public Guid? TenantId { get; set; }
        public Task Completion => _finished.Task;

        public DelegatedToken Token => _token ?? throw new InvalidOperationException("The sign-in of this set-up has ended.");

        public void Step(string name)
        {
            lock (_lock)
            {
                if (Current is not null && !_done.Contains(Current, StringComparer.Ordinal)) _done.Add(Current);
                Current = name;
            }
        }

        public void Warn(string text)
        {
            lock (_lock) _warnings.Add(text);
        }

        public void Succeed(string message)
        {
            lock (_lock)
            {
                if (Current is not null && !_done.Contains(Current, StringComparer.Ordinal)) _done.Add(Current);
                Current = null;
                (_state, _message) = (SetupRunState.Succeeded, message);
            }
        }

        public void Fail(string message)
        {
            lock (_lock) (_state, _message) = (SetupRunState.Failed, message);
        }

        public void DropToken() => _token = null;

        public void Finish()
        {
            if (_state == SetupRunState.Running) Fail("The set-up stopped before it finished. Sign in again to continue where it stopped.");
            _finished.TrySetResult();
        }

        public SetupRunView View()
        {
            lock (_lock) return new SetupRunView(Id, Request.Purpose, _state, [.. _done], Current, _message, [.. _warnings], TenantId, Request.TargetId,
                Request.IncludeRestore);
        }
    }
}
