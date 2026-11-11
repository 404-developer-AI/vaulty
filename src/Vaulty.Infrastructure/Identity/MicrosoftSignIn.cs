using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Domain;
using Vaulty.Core.Security;
using Vaulty.Graph;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Retention;
using Vaulty.Infrastructure.Tenants;

namespace Vaulty.Infrastructure.Identity;

/// <summary>A refusal while setting up or using sign-in with Microsoft, in one sentence the administrator can act on.</summary>
public sealed class SignInSetupException(string message) : InvalidOperationException(message);

/// <summary>
/// Sign-in with Microsoft for one organization: the "Vaulty sign-in" app registration in the organization's own tenant,
/// with a certificate whose private key is in the secret store. It asks for who a person is and for nothing in the
/// tenant; the optional application permissions only feed the user picker and the multi-factor check.
/// </summary>
public sealed record MicrosoftSignInSettings
{
    public const string DisplayName = "Vaulty sign-in";
    public const string CallbackPath = "/account/microsoft/callback";

    public Guid? TenantId { get; init; }
    public Guid? ClientId { get; init; }
    /// <summary>The object id of the app registration (its overview page); lets Vaulty renew the certificate itself.</summary>
    public Guid? ApplicationObjectId { get; init; }
    public string? CertificateThumbprint { get; init; }
    public DateTimeOffset? CertificateExpiresAt { get; init; }
    public Guid? CertificateKeyId { get; init; }

    public bool Enabled { get; init; }
    /// <summary>The tenant asks linked users for their second factor; Vaulty asks none of its own (the developer's decision).</summary>
    public bool MicrosoftHandlesSecondFactor { get; init; } = true;
    /// <summary>Only Microsoft sign-in, except for local Organization admins kept for emergencies.</summary>
    public bool SignInOnly { get; init; }

    public bool CredentialWorks { get; init; }
    public string? CredentialDetail { get; init; }
    public DateTimeOffset? CredentialCheckedAt { get; init; }
    /// <summary>The application permissions the app holds, read from its own token.</summary>
    public IReadOnlyList<string> GrantedPermissions { get; init; } = [];
    public TenantMfaPosture MfaPosture { get; init; } = TenantMfaPosture.Unknown;
    public DateTimeOffset? SignInCheckedAt { get; init; }
    public IReadOnlyList<SetupCheck> SignInChecks { get; init; } = [];

    /// <summary>The certificate works and a test sign-in passed every required check.</summary>
    public bool Ready => TenantId is not null && ClientId is not null && CertificateThumbprint is not null && CredentialWorks
                         && SignInChecks.Count > 0 && SignInChecks.Where(c => c.Required).All(c => c.Passed);

    public bool CanPickUsers => GrantedPermissions.Contains(SignInAppPermissions.UserReadAll, StringComparer.OrdinalIgnoreCase);

    public static string CertificateSecretName(Guid organizationId) => $"organization.{organizationId:N}.signin.certificate";

    public static string NextCertificateSecretName(Guid organizationId) => $"organization.{organizationId:N}.signin.certificate.next";

    /// <summary>The redirect URI of this Vaulty: the public host name when the installer set one, otherwise the address in use.</summary>
    public static Uri RedirectUri(string? publicHost, Uri currentBase)
    {
        ArgumentNullException.ThrowIfNull(currentBase);
        var root = publicHost is { Length: > 0 } host ? new Uri($"https://{host}/") : new Uri(currentBase.GetLeftPart(UriPartial.Authority) + "/");
        return new Uri(root, CallbackPath);
    }
}

/// <summary>A Vaulty user's link to an Entra account.</summary>
public sealed record MicrosoftLink(Guid TenantId, Guid ObjectId, string? Account);

/// <summary>Settings, certificate, links and the sign-in rules of Microsoft sign-in per organization.</summary>
public sealed class MicrosoftSignInService(NpgsqlDataSource dataSource, ISecretStore secrets, IdentityClient identity, AppRegistrationClient registrations,
    TimeProvider clock)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public MicrosoftEndpoints Endpoints => identity.Endpoints;

    // ---- settings -------------------------------------------------------------------------------------------------------

    public async Task<MicrosoftSignInSettings> GetAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        return await ReadAsync(session, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<MicrosoftSignInSettings> ReadAsync(OrganizationSession session, CancellationToken cancellationToken)
    {
        var row = await session.Connection.QuerySingleOrDefaultAsync<(Guid? TenantId, bool Enabled, bool Delegated, bool SignInOnly, string Settings)?>(
            new CommandDefinition(
                """
                SELECT entra_tenant_id, enabled, microsoft_handles_second_factor, sign_in_only, settings::text FROM vaulty.microsoft_sign_in
                 WHERE organization_id = vaulty.current_organization_id()
                """, transaction: session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (row is not { } r) return new MicrosoftSignInSettings();
        var stored = JsonSerializer.Deserialize<MicrosoftSignInSettings>(r.Settings, Json) ?? new MicrosoftSignInSettings();
        // The columns are what sign-in and the second-factor rule read; they win over the copy in the document.
        return stored with { TenantId = r.TenantId, Enabled = r.Enabled, MicrosoftHandlesSecondFactor = r.Delegated, SignInOnly = r.SignInOnly };
    }

    private static async Task WriteAsync(OrganizationSession session, MicrosoftSignInSettings settings, CancellationToken cancellationToken)
    {
        try
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO vaulty.microsoft_sign_in (organization_id, entra_tenant_id, enabled, microsoft_handles_second_factor, sign_in_only, settings, updated_at)
                VALUES (vaulty.current_organization_id(), @tenant, @enabled, @delegated, @signInOnly, @settings::jsonb, now())
                ON CONFLICT (organization_id) DO UPDATE SET entra_tenant_id = excluded.entra_tenant_id, enabled = excluded.enabled,
                    microsoft_handles_second_factor = excluded.microsoft_handles_second_factor, sign_in_only = excluded.sign_in_only,
                    settings = excluded.settings, updated_at = now()
                """, new
                {
                    tenant = settings.TenantId, enabled = settings.Enabled, delegated = settings.MicrosoftHandlesSecondFactor,
                    signInOnly = settings.SignInOnly, settings = JsonSerializer.Serialize(settings, Json),
                }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            throw new SignInSetupException("This Microsoft tenant already signs in to another Vaulty organization.");
        }
    }

    private async Task<MicrosoftSignInSettings> ChangeAsync(Guid organizationId, string actor, string change, Func<MicrosoftSignInSettings, MicrosoftSignInSettings> apply,
        object? details, CancellationToken cancellationToken, Func<OrganizationSession, MicrosoftSignInSettings, MicrosoftSignInSettings, Task>? after = null)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("SELECT pg_advisory_xact_lock(hashtext('signin:' || @org))",
            new { org = organizationId.ToString() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var current = await ReadAsync(session, cancellationToken).ConfigureAwait(false);
        var next = apply(current);
        await WriteAsync(session, next, cancellationToken).ConfigureAwait(false);
        if (after is not null) await after(session, current, next).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, actor, "signin.configured", $"organization:{organizationId}", new { change, details }, cancellationToken)
            .ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
        return next;
    }

    /// <summary>A new certificate for the sign-in app. The app must then get the new public key and the checks run again.</summary>
    public async Task<MicrosoftSignInSettings> CreateCertificateAsync(Guid organizationId, string actor, CancellationToken cancellationToken = default)
    {
        var certificate = TenantCertificate.Create(MicrosoftSignInSettings.DisplayName, clock);
        var name = MicrosoftSignInSettings.CertificateSecretName(organizationId);
        await secrets.SetAsync(name, certificate.Pfx, actor, cancellationToken).ConfigureAwait(false);
        await secrets.PruneAsync(name, 1, cancellationToken).ConfigureAwait(false);
        return await ChangeAsync(organizationId, actor, "certificate", s => s with
        {
            CertificateThumbprint = certificate.Thumbprint, CertificateExpiresAt = certificate.NotAfter, CertificateKeyId = null,
            CredentialWorks = false, CredentialCheckedAt = null, CredentialDetail = null, SignInChecks = [], SignInCheckedAt = null,
        }, new { thumbprint = certificate.Thumbprint }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<byte[]?> PublicCertificateAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        using var secret = await secrets.GetAsync(MicrosoftSignInSettings.CertificateSecretName(organizationId), cancellationToken).ConfigureAwait(false);
        return secret is null ? null : TenantCertificate.FromPfx(secret.Reveal()).PublicCertificate;
    }

    /// <summary>
    /// Saves the ids from the Entra admin center and checks the certificate. A different tenant switches sign-in off: links
    /// to accounts of the old tenant stop working at once, because a link counts only for the tenant the organization uses.
    /// </summary>
    public async Task<MicrosoftSignInSettings> SaveIdsAsync(Guid organizationId, Guid clientId, Guid tenantId, Guid? applicationObjectId, string actor,
        CancellationToken cancellationToken = default)
    {
        if (clientId == Guid.Empty || tenantId == Guid.Empty) throw new SignInSetupException("Enter the application ID and the directory (tenant) ID.");
        await ChangeAsync(organizationId, actor, "ids", s =>
        {
            var changed = s.ClientId != clientId || s.TenantId != tenantId;
            return s with
            {
                ClientId = clientId, TenantId = tenantId, ApplicationObjectId = applicationObjectId ?? (changed ? null : s.ApplicationObjectId),
                Enabled = s.Enabled && s.TenantId == tenantId && s.ClientId == clientId,
                SignInChecks = changed ? [] : s.SignInChecks, SignInCheckedAt = changed ? null : s.SignInCheckedAt,
            };
        }, new { client_id = clientId, tenant_id = tenantId }, cancellationToken, async (session, before, after) =>
        {
            if (before.Enabled && !after.Enabled) await EndLinkedSessionsAsync(session, cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
        return await TestCredentialAsync(organizationId, actor, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Check 1: the certificate gets an app-only token in the tenant (proves the application ID, the tenant and the
    /// certificate). The token's roles show which optional permissions the app holds; with Policy.Read.All Vaulty also
    /// reads whether the tenant requires multi-factor authentication.
    /// </summary>
    public async Task<MicrosoftSignInSettings> TestCredentialAsync(Guid organizationId, string actor, CancellationToken cancellationToken = default)
    {
        var current = await GetAsync(organizationId, cancellationToken).ConfigureAwait(false);
        if (current.ClientId is not { } clientId || current.TenantId is not { } tenant) throw new SignInSetupException("Enter the application ID and the tenant ID first.");
        bool works;
        string detail;
        IReadOnlyList<string> granted = [];
        var posture = TenantMfaPosture.Unknown;
        try
        {
            using var certificate = await LoadCertificateAsync(organizationId, cancellationToken).ConfigureAwait(false);
            var (token, _) = await identity.AppOnlyTokenAsync(tenant.ToString(), clientId, certificate, cancellationToken).ConfigureAwait(false);
            granted = SignInAppPermissions.Granted(token).Where(SignInAppPermissions.Optional.Contains).Order(StringComparer.Ordinal).ToList();
            if (granted.Contains(SignInAppPermissions.PolicyReadAll))
            {
                try
                {
                    posture = await registrations.MfaPostureAsync(token, cancellationToken).ConfigureAwait(false);
                }
                catch (GraphException)
                {
                    posture = TenantMfaPosture.Unknown;
                }
            }
            (works, detail) = (true, "The certificate signs in to the app.");
        }
        catch (IdentityException ex)
        {
            (works, detail) = (false, SignInErrors.ExplainSignIn(ex.Error, ex.Description));
        }
        catch (HttpRequestException)
        {
            (works, detail) = (false, "Microsoft could not be reached. Try again.");
        }
        return await ChangeAsync(organizationId, actor, "credential_checked", s => s with
        {
            CredentialWorks = works, CredentialDetail = detail, CredentialCheckedAt = clock.GetUtcNow(), GrantedPermissions = granted, MfaPosture = posture,
        }, new { works, granted, mfa = posture.ToString() }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Check 2: what a test sign-in of an administrator proved (redirect URI, tenant, member account, claims).</summary>
    public Task<MicrosoftSignInSettings> RecordSignInCheckAsync(Guid organizationId, string actor, IReadOnlyList<SetupCheck> checks,
        CancellationToken cancellationToken = default) =>
        ChangeAsync(organizationId, actor, "sign_in_checked", s => s with { SignInChecks = checks, SignInCheckedAt = clock.GetUtcNow() },
            new { passed = checks.Where(c => c.Required).All(c => c.Passed) }, cancellationToken);

    /// <summary>The checks a test sign-in yields, passed or failed, in words an administrator can act on.</summary>
    public static IReadOnlyList<SetupCheck> SignInChecksFrom(MicrosoftAccount? account, string? refusal)
    {
        if (account is null)
        {
            return [new SetupCheck("Test sign-in", false, true, refusal ?? "The sign-in did not complete.")];
        }
        return
        [
            new("Redirect URI", true, true, "Microsoft sent the sign-in back to this Vaulty."),
            new("Tenant", true, true, "The account belongs to the tenant of the sign-in app."),
            new("Member account", true, true, $"{account.Account ?? "The account"} is a member of the tenant, not a guest."),
            // "Confirm it's you" checks that the Microsoft sign-in behind it is fresh; Entra only reports when with this optional claim.
            new("Sign-in time in the token", account.AuthenticatedAt is not null, true, account.AuthenticatedAt is not null
                ? "The token says when the person signed in, so \"Confirm it's you\" can check that the sign-in is fresh."
                : "Add the optional claim auth_time to the ID token under Token configuration, then run the test sign-in again."),
            new("Multi-factor in the token", account.MfaProven, false, account.MfaProven
                ? "Microsoft reported a second factor for this sign-in."
                : "The token does not say whether Microsoft asked for a second factor; that is normal for Entra ID. The multi-factor check above tells what the tenant requires."),
        ];
    }

    /// <summary>
    /// Switches sign-in with Microsoft on or off, and chooses who handles the second factor and whether only Microsoft
    /// sign-in is allowed. Every change that takes something away ends the sessions it affects (their security stamp changes).
    /// </summary>
    public Task<MicrosoftSignInSettings> SetOptionsAsync(Guid organizationId, string actor, bool enabled, bool microsoftHandlesSecondFactor, bool signInOnly,
        CancellationToken cancellationToken = default) =>
        ChangeAsync(organizationId, actor, "options", s =>
        {
            if (enabled && !s.Ready) throw new SignInSetupException("Finish the checks first: the certificate and a test sign-in must pass.");
            if (signInOnly && !enabled) throw new SignInSetupException("Microsoft sign-in only needs sign-in with Microsoft switched on.");
            return s with { Enabled = enabled, MicrosoftHandlesSecondFactor = microsoftHandlesSecondFactor, SignInOnly = signInOnly };
        }, new { enabled, microsoft_handles_second_factor = microsoftHandlesSecondFactor, sign_in_only = signInOnly }, cancellationToken, async (session, before, after) =>
        {
            if (after.SignInOnly && !before.SignInOnly && await BreakGlassCountAsync(session, cancellationToken).ConfigureAwait(false) == 0)
            {
                throw new SignInSetupException(
                    "Keep at least one local Organization admin with a passkey for emergencies before you allow only Microsoft sign-in.");
            }
            var linkedLoseAccess = before.Enabled && !after.Enabled || before.MicrosoftHandlesSecondFactor && !after.MicrosoftHandlesSecondFactor;
            if (linkedLoseAccess) await EndLinkedSessionsAsync(session, cancellationToken).ConfigureAwait(false);
            if (after.SignInOnly && !before.SignInOnly) await EndLocalSessionsAsync(session, cancellationToken).ConfigureAwait(false);
        });

    private static Task EndLinkedSessionsAsync(OrganizationSession session, CancellationToken cancellationToken) =>
        session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.users SET security_stamp = replace(gen_random_uuid()::text, '-', '') WHERE entra_object_id IS NOT NULL",
            transaction: session.Transaction, cancellationToken: cancellationToken));

    private static Task EndLocalSessionsAsync(OrganizationSession session, CancellationToken cancellationToken) =>
        session.Connection.ExecuteAsync(new CommandDefinition(
            $"UPDATE vaulty.users u SET security_stamp = replace(gen_random_uuid()::text, '-', '') WHERE u.entra_object_id IS NULL AND NOT ({BreakGlassCondition})",
            new { adminRole = BuiltInRoles.OrganizationAdmin }, session.Transaction, cancellationToken: cancellationToken));

    // ---- break-glass ------------------------------------------------------------------------------------------------------

    /// <summary>A local account (not linked) holding the built-in Organization admin role for every customer.</summary>
    private const string BreakGlassCondition =
        """
        u.entra_object_id IS NULL AND u.disabled_at IS NULL AND EXISTS (
            SELECT 1 FROM vaulty.role_assignments a JOIN vaulty.roles r ON r.id = a.role_id
             WHERE a.user_id = u.id AND a.customer_id IS NULL AND r.built_in AND r.name = @adminRole)
        """;

    private static Task<int> BreakGlassCountAsync(OrganizationSession session, CancellationToken cancellationToken) =>
        session.Connection.ExecuteScalarAsync<int>(new CommandDefinition(
            $"SELECT count(*)::int FROM vaulty.users u WHERE {BreakGlassCondition} AND EXISTS (SELECT 1 FROM vaulty.user_passkeys p WHERE p.user_id = u.id)",
            new { adminRole = BuiltInRoles.OrganizationAdmin }, session.Transaction, cancellationToken: cancellationToken));

    /// <summary>
    /// Whether a local sign-in (password or passkey) of this user is allowed: always, unless the organization allows only
    /// Microsoft sign-in; then only for a local Organization admin, and that use raises an alert for every administrator.
    /// A linked user signs in with Microsoft only, so the tenant's Conditional Access and off-boarding always apply.
    /// </summary>
    public async Task<LocalSignInDecision> LocalSignInAsync(User user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        var linked = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT entra_object_id IS NOT NULL FROM vaulty.users WHERE id = @id", new { id = user.Id }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        var settings = await ReadAsync(session, cancellationToken).ConfigureAwait(false);
        if (linked && settings.Enabled) return LocalSignInDecision.UseMicrosoft;
        if (!settings.Enabled || !settings.SignInOnly) return LocalSignInDecision.Allowed;
        var breakGlass = await session.Connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            $"SELECT EXISTS (SELECT 1 FROM vaulty.users u WHERE u.id = @id AND {BreakGlassCondition})",
            new { id = user.Id, adminRole = BuiltInRoles.OrganizationAdmin }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return breakGlass ? LocalSignInDecision.BreakGlass : LocalSignInDecision.MicrosoftOnly;
    }

    /// <summary>A local administrator signed in while only Microsoft sign-in is allowed: every administrator gets an alert.</summary>
    public async Task RaiseBreakGlassAlertAsync(User user, string method, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId, cancellationToken).ConfigureAwait(false);
        // A new alert for every use: the open one of a previous use is closed first, so the use is never folded into it.
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.alerts SET resolved_at = now() WHERE kind = @kind AND resolved_at IS NULL", new { kind = SignInAlerts.BreakGlass },
            session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await Alerts.RaiseAsync(session, null, null, SignInAlerts.BreakGlass, "critical",
            $"{user.UserName} signed in with a local account ({method}) while only Microsoft sign-in is allowed. Check that this was an emergency.",
            new { user = user.Id, method }, cancellationToken).ConfigureAwait(false);
        await AuditLog.WriteAsync(session, $"user:{user.Id}", "login.break_glass", $"user:{user.Id}", new { method }, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    // ---- links ------------------------------------------------------------------------------------------------------------

    public async Task<MicrosoftLink?> LinkOfAsync(Guid organizationId, Guid userId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var row = await session.Connection.QuerySingleOrDefaultAsync<(Guid? TenantId, Guid? ObjectId, string? Account)?>(new CommandDefinition(
            "SELECT entra_tenant_id, entra_object_id, entra_account FROM vaulty.users WHERE id = @userId", new { userId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row is { TenantId: { } t, ObjectId: { } o } r ? new MicrosoftLink(t, o, r.Account) : null;
    }

    /// <summary>
    /// Links a user to an Entra account of the organization's tenant. Refused when the account is linked to another user,
    /// or when the user is the last local Organization admin: one local administrator stays for emergencies.
    /// The user's sessions end (security stamp), because from now on the user signs in with Microsoft only.
    /// </summary>
    public async Task LinkAsync(Guid organizationId, string actor, Guid userId, Guid objectId, string? account, CancellationToken cancellationToken = default)
    {
        if (objectId == Guid.Empty) throw new SignInSetupException("Enter the object ID of the Microsoft account.");
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition("SELECT pg_advisory_xact_lock(hashtext('signin:' || @org))",
            new { org = organizationId.ToString() }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var settings = await ReadAsync(session, cancellationToken).ConfigureAwait(false);
        if (settings.TenantId is not { } tenant || !settings.Ready) throw new SignInSetupException("Set up sign-in with Microsoft under Settings > Sign-in first.");
        var user = await session.Connection.QuerySingleOrDefaultAsync<(Guid Id, Guid? ObjectId, bool BreakGlass)?>(new CommandDefinition(
            $"SELECT u.id, u.entra_object_id, {BreakGlassCondition} FROM vaulty.users u WHERE u.id = @userId AND u.disabled_at IS NULL",
            new { userId, adminRole = BuiltInRoles.OrganizationAdmin }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false)
            ?? throw new SignInSetupException("The user does not exist.");
        if (user.ObjectId == objectId) return;
        if (user.ObjectId is not null) throw new SignInSetupException("The user is linked to another Microsoft account. Unlink it first.");
        if (user.BreakGlass && await session.Connection.ExecuteScalarAsync<int>(new CommandDefinition(
                $"SELECT count(*)::int FROM vaulty.users u WHERE {BreakGlassCondition}", new { adminRole = BuiltInRoles.OrganizationAdmin },
                session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false) <= 1)
        {
            throw new SignInSetupException("This is the last local Organization admin. Keep it as a local account for emergencies, or make another user Organization admin first.");
        }
        try
        {
            await session.Connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vaulty.users SET entra_tenant_id = @tenant, entra_object_id = @objectId, entra_account = @account, entra_linked_at = now(),
                       security_stamp = replace(gen_random_uuid()::text, '-', '')
                 WHERE id = @userId
                """, new { tenant, objectId, account = Trim(account, 320), userId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            throw new SignInSetupException("This Microsoft account is already linked to another Vaulty user.");
        }
        await AuditLog.WriteAsync(session, actor, "user.linked", $"user:{userId}", new { entra_tenant_id = tenant, entra_object_id = objectId, account = Trim(account, 320) },
            cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Removes the link; the user's sessions end at once (security stamp).</summary>
    public async Task UnlinkAsync(Guid organizationId, string actor, Guid userId, CancellationToken cancellationToken = default)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        var removed = await session.Connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE vaulty.users SET entra_tenant_id = NULL, entra_object_id = NULL, entra_account = NULL, entra_linked_at = NULL,
                   security_stamp = replace(gen_random_uuid()::text, '-', '')
             WHERE id = @userId AND entra_object_id IS NOT NULL
            """, new { userId }, session.Transaction, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (removed > 0) await AuditLog.WriteAsync(session, actor, "user.unlinked", $"user:{userId}", null, cancellationToken).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The name of the account as Microsoft shows it now (an account name can change; the object id never does).</summary>
    public async Task RefreshAccountNameAsync(Guid organizationId, Guid userId, string? account, CancellationToken cancellationToken = default)
    {
        if (Trim(account, 320) is not { } name) return;
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId, cancellationToken).ConfigureAwait(false);
        await session.Connection.ExecuteAsync(new CommandDefinition(
            "UPDATE vaulty.users SET entra_account = @name WHERE id = @userId AND entra_account IS DISTINCT FROM @name", new { name, userId }, session.Transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        await session.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The user an Entra account is linked to, in the organization whose switched-on sign-in uses that tenant.</summary>
    public async Task<(Guid UserId, Guid OrganizationId)?> FindLinkedUserAsync(Guid tenantId, Guid objectId, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.QuerySingleOrDefaultAsync<(Guid UserId, Guid OrganizationId)?>(new CommandDefinition(
            "SELECT user_id, organization_id FROM vaulty.microsoft_user(@tenantId, @objectId)", new { tenantId, objectId },
            cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>The organizations whose sign-in with Microsoft is switched on, for the sign-in page.</summary>
    public async Task<IReadOnlyList<(Guid OrganizationId, MicrosoftSignInSettings Settings)>> EnabledAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<(Guid OrganizationId, Guid TenantId, bool SignInOnly, string Settings)>(new CommandDefinition(
            "SELECT organization_id, entra_tenant_id, sign_in_only, settings::text FROM vaulty.microsoft_sign_in_enabled()",
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => (r.OrganizationId, (JsonSerializer.Deserialize<MicrosoftSignInSettings>(r.Settings, Json) ?? new MicrosoftSignInSettings())
            with { TenantId = r.TenantId, Enabled = true, SignInOnly = r.SignInOnly })).ToList();
    }

    // ---- directory ----------------------------------------------------------------------------------------------------------

    /// <summary>Members of the tenant for the user picker; needs User.Read.All on the sign-in app.</summary>
    public async Task<IReadOnlyList<DirectoryMember>> SearchMembersAsync(Guid organizationId, string text, CancellationToken cancellationToken = default)
    {
        var token = await DirectoryTokenAsync(organizationId, cancellationToken).ConfigureAwait(false);
        return await registrations.SearchMembersAsync(token, text, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>One member of the tenant; null for a guest or an unknown object id. Needs User.Read.All.</summary>
    public async Task<DirectoryMember?> MemberAsync(Guid organizationId, Guid objectId, CancellationToken cancellationToken = default)
    {
        var token = await DirectoryTokenAsync(organizationId, cancellationToken).ConfigureAwait(false);
        return await registrations.MemberAsync(token, objectId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> DirectoryTokenAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        var settings = await GetAsync(organizationId, cancellationToken).ConfigureAwait(false);
        if (!settings.CanPickUsers || settings.ClientId is not { } clientId || settings.TenantId is not { } tenant)
        {
            throw new SignInSetupException("The sign-in app cannot read users: give it the application permission User.Read.All, or enter the object ID.");
        }
        using var certificate = await LoadCertificateAsync(organizationId, cancellationToken).ConfigureAwait(false);
        return (await identity.AppOnlyTokenAsync(tenant.ToString(), clientId, certificate, cancellationToken).ConfigureAwait(false)).AccessToken;
    }

    // ---- certificate renewal --------------------------------------------------------------------------------------------------

    /// <summary>Renews the certificate itself: addKey with a proof signed by the current certificate, then removeKey of the old one.</summary>
    public async Task<string> RenewCertificateAsync(Guid organizationId, string actor, CancellationToken cancellationToken = default)
    {
        var current = await GetAsync(organizationId, cancellationToken).ConfigureAwait(false);
        if (current.ClientId is not { } clientId || current.TenantId is not { } tenant || current.ApplicationObjectId is not { } objectId)
        {
            throw new SignInSetupException("Enter the object ID of the app registration, so Vaulty can renew its certificate.");
        }
        var next = TenantCertificate.Create(MicrosoftSignInSettings.DisplayName, clock);
        await secrets.SetAsync(MicrosoftSignInSettings.NextCertificateSecretName(organizationId), next.Pfx, actor, cancellationToken).ConfigureAwait(false);
        Guid? newKeyId;
        using (var certificate = await LoadCertificateAsync(organizationId, cancellationToken).ConfigureAwait(false))
        {
            var (token, _) = await identity.AppOnlyTokenAsync(tenant.ToString(), clientId, certificate, cancellationToken).ConfigureAwait(false);
            newKeyId = await registrations.AddKeyAsync(token, objectId, next, CertificateJwt.KeyProof(certificate, objectId, clock.GetUtcNow()),
                MicrosoftSignInSettings.DisplayName, cancellationToken).ConfigureAwait(false);
        }
        using (var fresh = TenantCertificate.Load(next.Pfx))
        {
            await SetupAppService.RetryAsync(() => identity.AppOnlyTokenAsync(tenant.ToString(), clientId, fresh, cancellationToken), cancellationToken)
                .ConfigureAwait(false);
        }
        var oldKeyId = current.CertificateKeyId;
        var name = MicrosoftSignInSettings.CertificateSecretName(organizationId);
        await secrets.SetAsync(name, next.Pfx, actor, cancellationToken).ConfigureAwait(false);
        await ChangeAsync(organizationId, actor, "certificate_renewed", s => s with
        {
            CertificateThumbprint = next.Thumbprint, CertificateExpiresAt = next.NotAfter, CertificateKeyId = newKeyId, CredentialWorks = true,
            CredentialCheckedAt = clock.GetUtcNow(), CredentialDetail = "The renewed certificate signs in to the app.",
        }, new { thumbprint = next.Thumbprint }, cancellationToken).ConfigureAwait(false);
        await secrets.PruneAsync(name, 1, cancellationToken).ConfigureAwait(false);
        if (oldKeyId is not { } old) return "The certificate was renewed. Remove the old certificate from the app registration in Entra.";
        try
        {
            using var fresh = TenantCertificate.Load(next.Pfx);
            var (token, _) = await identity.AppOnlyTokenAsync(tenant.ToString(), clientId, fresh, cancellationToken).ConfigureAwait(false);
            await registrations.RemoveKeyAsync(token, objectId, old, CertificateJwt.KeyProof(fresh, objectId, clock.GetUtcNow()), cancellationToken).ConfigureAwait(false);
            return "The certificate was renewed and the old one removed from the app registration.";
        }
        catch (GraphException)
        {
            return "The certificate was renewed. Microsoft did not remove the old certificate; it stops working on its end date, or remove it in Entra.";
        }
    }

    public async Task<X509Certificate2> LoadCertificateAsync(Guid organizationId, CancellationToken cancellationToken = default)
    {
        using var secret = await secrets.GetAsync(MicrosoftSignInSettings.CertificateSecretName(organizationId), cancellationToken).ConfigureAwait(false)
                           ?? throw new SignInSetupException("The certificate of the Vaulty sign-in app is missing. Create one under Settings > Sign-in.");
        return TenantCertificate.Load(secret.Reveal());
    }

    /// <summary>Whether a user has a second factor: their own passkey or authenticator app, or a link while the tenant handles it.</summary>
    public const string SecondFactorSql =
        """
        EXISTS (SELECT 1 FROM vaulty.users WHERE id = @userId AND two_factor_enabled AND authenticator_key IS NOT NULL)
        OR EXISTS (SELECT 1 FROM vaulty.user_passkeys WHERE user_id = @userId)
        OR EXISTS (SELECT 1 FROM vaulty.users u JOIN vaulty.microsoft_sign_in s
                     ON s.organization_id = u.organization_id AND s.enabled AND s.microsoft_handles_second_factor AND s.entra_tenant_id = u.entra_tenant_id
                    WHERE u.id = @userId AND u.entra_object_id IS NOT NULL)
        """;

    private static string? Trim(string? value, int max) => string.IsNullOrWhiteSpace(value) ? null : value.Length <= max ? value.Trim() : value.Trim()[..max];
}

public enum LocalSignInDecision
{
    Allowed,
    /// <summary>A local Organization admin while only Microsoft sign-in is allowed: allowed, with an alert.</summary>
    BreakGlass,
    /// <summary>The user is linked: sign in with Microsoft.</summary>
    UseMicrosoft,
    /// <summary>Only Microsoft sign-in is allowed and the user is not an emergency administrator.</summary>
    MicrosoftOnly,
}

public static class SignInAlerts
{
    public const string BreakGlass = "signin.break_glass";
}

public enum MicrosoftLoginPurpose
{
    /// <summary>A person signs in to Vaulty.</summary>
    SignIn,
    /// <summary>A signed-in local user links their own Microsoft account.</summary>
    Link,
    /// <summary>A linked user confirms it's them ("Confirm it's you") with a fresh Microsoft sign-in.</summary>
    StepUp,
    /// <summary>An administrator checks the sign-in app with a test sign-in.</summary>
    Check,
}

/// <summary>A sign-in Vaulty sent the browser to; held in memory until Microsoft redirects back (at most ten minutes).</summary>
/// <param name="BindingHash">SHA-256 of a random value in a cookie of the browser that started it: only that browser can finish it.</param>
public sealed record MicrosoftLoginRequest(string State, MicrosoftLoginPurpose Purpose, Guid OrganizationId, Guid? UserId, Guid TenantId, Guid ClientId,
    Uri RedirectUri, string CodeVerifier, string Nonce, byte[] BindingHash, string ReturnPath, DateTimeOffset StartedAt, DateTimeOffset ExpiresAt);

/// <summary>What a finished sign-in proved, handed from the callback to the page that continues it. Never a token.</summary>
public sealed record MicrosoftLoginResult(MicrosoftLoginPurpose Purpose, Guid OrganizationId, Guid? UserId, MicrosoftAccount? Account, string? Error,
    string ReturnPath);

/// <summary>
/// The authorization code flow with PKCE for signing in to Vaulty. A request is bound to the browser that started it (a
/// cookie whose hash is in the request) and to the Vaulty user for linking and step-up. The callback redeems the code with
/// the sign-in app's certificate, applies <see cref="SignInTokenRules"/>, and keeps only the account it proved, as a
/// one-time ticket for the same browser. Codes, tokens and the binding value are never stored or logged.
/// </summary>
public sealed class MicrosoftLogins(MicrosoftSignInService signIn, IdentityClient identity, TimeProvider clock)
{
    public static readonly TimeSpan Validity = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan TicketValidity = TimeSpan.FromMinutes(2);
    /// <summary>How recent the Microsoft sign-in behind a "Confirm it's you" must be.</summary>
    public static readonly TimeSpan FreshSignIn = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, MicrosoftLoginRequest> _requests = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (MicrosoftLoginResult Result, byte[] BindingHash, DateTimeOffset ExpiresAt)> _tickets = new(StringComparer.Ordinal);

    public static string NewBindingValue() => CertificateJwt.Base64Url(RandomNumberGenerator.GetBytes(32));

    private static byte[] Hash(string? value) => SHA256.HashData(Encoding.UTF8.GetBytes(value ?? ""));

    /// <summary>
    /// The Microsoft sign-in page to send the browser to. A sign-in to Vaulty uses the one organization whose sign-in with
    /// Microsoft is switched on; the other purposes use the organization of the signed-in user.
    /// </summary>
    public async Task<Uri> BeginAsync(MicrosoftLoginPurpose purpose, Guid? organizationId, Guid? userId, Uri redirectUri, string returnPath, string bindingValue,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        Guid org;
        MicrosoftSignInSettings settings;
        if (purpose == MicrosoftLoginPurpose.SignIn)
        {
            // One organization per Vaulty today (setup closes after the first); with more, the sign-in page would first ask which.
            var enabled = await signIn.EnabledAsync(cancellationToken).ConfigureAwait(false);
            if (enabled.Count != 1) throw new SignInSetupException("Sign-in with Microsoft is not available. Sign in with your Vaulty account.");
            (org, settings) = enabled[0];
        }
        else
        {
            org = organizationId ?? throw new ArgumentException("An organization is required.", nameof(organizationId));
            if (userId is null) throw new ArgumentException("A user is required.", nameof(userId));
            settings = await signIn.GetAsync(org, cancellationToken).ConfigureAwait(false);
            if (purpose == MicrosoftLoginPurpose.StepUp && !settings.Enabled) throw new SignInSetupException("Sign-in with Microsoft is switched off.");
            if (purpose == MicrosoftLoginPurpose.Link && !settings.Ready) throw new SignInSetupException("Sign-in with Microsoft is not set up yet.");
            if (purpose == MicrosoftLoginPurpose.Check && !settings.CredentialWorks) throw new SignInSetupException("Check the certificate first.");
        }
        if (settings.ClientId is not { } clientId || settings.TenantId is not { } tenant) throw new SignInSetupException("Sign-in with Microsoft is not set up yet.");
        Sweep();
        var now = clock.GetUtcNow();
        var request = new MicrosoftLoginRequest(CertificateJwt.Base64Url(RandomNumberGenerator.GetBytes(32)), purpose, org, userId, tenant, clientId, redirectUri,
            Pkce.NewVerifier(), CertificateJwt.Base64Url(RandomNumberGenerator.GetBytes(16)), Hash(bindingValue), returnPath, now, now + Validity);
        _requests[request.State] = request;
        return identity.SignInAuthorizationUrl(tenant.ToString(), clientId, redirectUri, request.State, request.Nonce, Pkce.Challenge(request.CodeVerifier),
            fresh: purpose == MicrosoftLoginPurpose.StepUp);
    }

    /// <summary>
    /// Microsoft redirected back. Returns a one-time ticket for the browser that started the sign-in, or null when the state
    /// is unknown, used, expired or was started by another browser (then nothing is redeemed).
    /// </summary>
    public async Task<string?> CompleteAsync(string? state, string? code, string? error, string? errorDescription, string? bindingValue,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(state) || !_requests.TryRemove(state, out var request) || request.ExpiresAt <= clock.GetUtcNow()) return null;
        if (!CryptographicOperations.FixedTimeEquals(Hash(bindingValue), request.BindingHash)) return null;
        MicrosoftLoginResult result;
        if (!string.IsNullOrEmpty(error) || string.IsNullOrEmpty(code))
        {
            result = Fail(request, SignInErrors.ExplainSignIn(error, errorDescription));
        }
        else
        {
            try
            {
                using var certificate = await signIn.LoadCertificateAsync(request.OrganizationId, cancellationToken).ConfigureAwait(false);
                var claims = await identity.RedeemSignInCodeAsync(request.TenantId.ToString(), request.ClientId, certificate, request.RedirectUri, code,
                    request.CodeVerifier, cancellationToken).ConfigureAwait(false);
                var outcome = SignInTokenRules.Check(claims, identity.Endpoints.AuthorityHost, request.TenantId, request.ClientId, request.Nonce, clock.GetUtcNow());
                result = outcome.Account is { } account
                    ? request.Purpose == MicrosoftLoginPurpose.StepUp && !Fresh(account)
                        ? Fail(request, "Microsoft did not ask for your credentials again. Start again.")
                        : new MicrosoftLoginResult(request.Purpose, request.OrganizationId, request.UserId, account, null, request.ReturnPath)
                    : Fail(request, outcome.Refusal!);
            }
            catch (IdentityException ex)
            {
                result = Fail(request, SignInErrors.ExplainSignIn(ex.Error, ex.Description));
            }
            catch (Exception ex) when (ex is HttpRequestException or SignInSetupException or FormatException or JsonException or TaskCanceledException)
            {
                result = Fail(request, ex is SignInSetupException ? ex.Message : "Microsoft could not be reached or answered unexpectedly. Start again.");
            }
        }
        var ticket = CertificateJwt.Base64Url(RandomNumberGenerator.GetBytes(32));
        _tickets[ticket] = (result, request.BindingHash, clock.GetUtcNow() + TicketValidity);
        return ticket;
    }

    private bool Fresh(MicrosoftAccount account) => account.AuthenticatedAt is { } at && clock.GetUtcNow() - at <= FreshSignIn;

    private static MicrosoftLoginResult Fail(MicrosoftLoginRequest request, string message) =>
        new(request.Purpose, request.OrganizationId, request.UserId, null, message, request.ReturnPath);

    /// <summary>The result of a ticket, once, for the browser it was issued to.</summary>
    public MicrosoftLoginResult? Redeem(string? ticket, string? bindingValue)
    {
        if (string.IsNullOrEmpty(ticket) || !_tickets.TryRemove(ticket, out var entry) || entry.ExpiresAt <= clock.GetUtcNow()) return null;
        return CryptographicOperations.FixedTimeEquals(Hash(bindingValue), entry.BindingHash) ? entry.Result : null;
    }

    private void Sweep()
    {
        var now = clock.GetUtcNow();
        foreach (var (state, request) in _requests)
        {
            if (request.ExpiresAt <= now) _requests.TryRemove(state, out _);
        }
        foreach (var (ticket, entry) in _tickets)
        {
            if (entry.ExpiresAt <= now) _tickets.TryRemove(ticket, out _);
        }
    }
}
