using Vaulty.Core.Abstractions;
using Vaulty.Graph.Onboarding;
using Vaulty.Infrastructure.Storage;

namespace Vaulty.Infrastructure.Tenants;

/// <summary>One check of the "Vaulty setup" app registration, in words an administrator can act on.</summary>
/// <param name="Required">A failed required check blocks connecting from the browser; an optional one is a warning.</param>
public sealed record SetupCheck(string Name, bool Passed, bool Required, string Detail);

/// <summary>
/// The "Vaulty setup" app: a multi-tenant app registration in the platform owner's own tenant with delegated permissions
/// only. It gives Vaulty no access to any data by itself; an administrator who signs in lets Vaulty create the dedicated
/// app in that administrator's tenant, for the duration of that sign-in. Not secret; the certificate is in the secrets store.
/// </summary>
public sealed record SetupAppSettings
{
    public const string SettingKey = "microsoft.setup_app";
    public const string CertificateSecretName = "platform.setup_app.certificate";
    public const string NextCertificateSecretName = "platform.setup_app.certificate.next";
    public const string DisplayName = "Vaulty setup";

    public Guid? ClientId { get; init; }
    public Guid? HomeTenantId { get; init; }
    public Guid? ApplicationObjectId { get; init; }
    public string? CertificateThumbprint { get; init; }
    public DateTimeOffset? CertificateExpiresAt { get; init; }
    public Guid? CertificateKeyId { get; init; }
    public DateTimeOffset? CredentialCheckedAt { get; init; }
    public bool CredentialWorks { get; init; }
    public string? CredentialDetail { get; init; }
    public DateTimeOffset? RegistrationCheckedAt { get; init; }
    public IReadOnlyList<SetupCheck> RegistrationChecks { get; init; } = [];

    /// <summary>The certificate works, the registration was read with a test sign-in, and every required check passed.</summary>
    public bool Ready => ClientId is not null && HomeTenantId is not null && CertificateThumbprint is not null && CredentialWorks
                         && RegistrationChecks.Count > 0 && RegistrationChecks.Where(c => c.Required).All(c => c.Passed);
}

/// <summary>The assistant for the "Vaulty setup" app: its certificate, its ids, and the two checks.</summary>
public sealed class SetupAppService(PlatformSettings settings, ISecretStore secrets, IdentityClient identity, AppRegistrationClient registrations,
    TimeProvider clock)
{
    public const string CallbackPath = "/connect/microsoft/callback";

    /// <summary>The redirect URI of this Vaulty: the public host name when the installer set one, otherwise the address in use.</summary>
    public static Uri RedirectUri(string? publicHost, Uri currentBase)
    {
        ArgumentNullException.ThrowIfNull(currentBase);
        var root = publicHost is { Length: > 0 } host ? new Uri($"https://{host}/") : new Uri(currentBase.GetLeftPart(UriPartial.Authority) + "/");
        return new Uri(root, CallbackPath);
    }

    public async Task<SetupAppSettings> GetAsync(CancellationToken cancellationToken = default) =>
        await settings.GetAsync<SetupAppSettings>(SetupAppSettings.SettingKey, cancellationToken).ConfigureAwait(false) ?? new SetupAppSettings();

    /// <summary>A new certificate for the setup app. Replaces the current one: the app must then get the new public key.</summary>
    public async Task<SetupAppSettings> CreateCertificateAsync(string actor, CancellationToken cancellationToken = default)
    {
        var certificate = TenantCertificate.Create(SetupAppSettings.DisplayName, clock);
        await secrets.SetAsync(SetupAppSettings.CertificateSecretName, certificate.Pfx, actor, cancellationToken).ConfigureAwait(false);
        await secrets.PruneAsync(SetupAppSettings.CertificateSecretName, 1, cancellationToken).ConfigureAwait(false);
        var current = await GetAsync(cancellationToken).ConfigureAwait(false);
        var next = current with
        {
            CertificateThumbprint = certificate.Thumbprint, CertificateExpiresAt = certificate.NotAfter, CertificateKeyId = null,
            CredentialWorks = false, CredentialCheckedAt = null, CredentialDetail = null, RegistrationChecks = [], RegistrationCheckedAt = null,
        };
        await settings.SetAsync(SetupAppSettings.SettingKey, next, actor, cancellationToken).ConfigureAwait(false);
        return next;
    }

    /// <summary>The public part of the certificate, to upload to the app registration.</summary>
    public async Task<byte[]?> PublicCertificateAsync(CancellationToken cancellationToken = default)
    {
        using var secret = await secrets.GetAsync(SetupAppSettings.CertificateSecretName, cancellationToken).ConfigureAwait(false);
        return secret is null ? null : TenantCertificate.FromPfx(secret.Reveal()).PublicCertificate;
    }

    /// <summary>Saves the ids from the Entra admin center and checks that the certificate signs in.</summary>
    public async Task<SetupAppSettings> SaveIdsAsync(Guid clientId, Guid homeTenantId, string actor, CancellationToken cancellationToken = default)
    {
        if (clientId == Guid.Empty || homeTenantId == Guid.Empty) throw new TenantException("Enter the application ID and the tenant ID.");
        var current = await GetAsync(cancellationToken).ConfigureAwait(false);
        var changed = current.ClientId != clientId || current.HomeTenantId != homeTenantId;
        var next = current with
        {
            ClientId = clientId, HomeTenantId = homeTenantId,
            ApplicationObjectId = changed ? null : current.ApplicationObjectId,
            RegistrationChecks = changed ? [] : current.RegistrationChecks,
            RegistrationCheckedAt = changed ? null : current.RegistrationCheckedAt,
        };
        await settings.SetAsync(SetupAppSettings.SettingKey, next, actor, cancellationToken).ConfigureAwait(false);
        return await TestCredentialAsync(actor, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Check 1: the certificate gets an app-only token in the home tenant (proves the application ID and the certificate).</summary>
    public async Task<SetupAppSettings> TestCredentialAsync(string actor, CancellationToken cancellationToken = default)
    {
        var current = await GetAsync(cancellationToken).ConfigureAwait(false);
        if (current.ClientId is not { } clientId || current.HomeTenantId is not { } home) throw new TenantException("Enter the application ID and the tenant ID first.");
        bool works;
        string detail;
        try
        {
            using var certificate = await LoadCertificateAsync(SetupAppSettings.CertificateSecretName, cancellationToken).ConfigureAwait(false);
            await identity.AppOnlyTokenAsync(home.ToString(), clientId, certificate, cancellationToken).ConfigureAwait(false);
            (works, detail) = (true, "The certificate signs in to the app.");
        }
        catch (IdentityException ex)
        {
            (works, detail) = (false, SignInErrors.Explain(ex.Error, ex.Description));
        }
        catch (HttpRequestException)
        {
            (works, detail) = (false, "Microsoft could not be reached. Try again.");
        }
        var next = current with { CredentialWorks = works, CredentialDetail = detail, CredentialCheckedAt = clock.GetUtcNow() };
        await settings.SetAsync(SetupAppSettings.SettingKey, next, actor, cancellationToken).ConfigureAwait(false);
        return next;
    }

    /// <summary>
    /// Check 2, run with the token of a test sign-in in the home tenant: reads the app registration and reports each setting.
    /// Changes nothing in Entra.
    /// </summary>
    public async Task<SetupAppSettings> CheckRegistrationAsync(DelegatedToken token, Uri redirectUri, string actor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(redirectUri);
        var current = await GetAsync(cancellationToken).ConfigureAwait(false);
        if (current.ClientId is not { } clientId || current.HomeTenantId is not { } home) throw new TenantException("Enter the application ID and the tenant ID first.");
        var checks = new List<SetupCheck>();
        Guid? objectId = null;
        Guid? keyId = null;
        if (token.User.TenantId != home)
        {
            checks.Add(new SetupCheck("Signed in to the home tenant", false, true,
                $"You signed in to tenant {token.User.TenantId}, not to the tenant of the app ({home}). Sign in with an account of that tenant."));
        }
        else
        {
            var app = await registrations.ApplicationAsync(token.AccessToken, clientId, cancellationToken).ConfigureAwait(false);
            if (app is null)
            {
                checks.Add(new SetupCheck("App registration found", false, true, $"No app registration with application ID {clientId} exists in the tenant."));
            }
            else
            {
                objectId = app.ObjectId;
                var graph = await registrations.GraphResourceAsync(token.AccessToken, cancellationToken).ConfigureAwait(false);
                checks.AddRange(EvaluateRegistration(app, graph, redirectUri, current.CertificateThumbprint, token.User.DirectoryRoles is not null));
                keyId = current.CertificateThumbprint is { } t ? app.KeyFor(t)?.KeyId : null;
            }
        }
        var next = current with
        {
            RegistrationChecks = checks, RegistrationCheckedAt = clock.GetUtcNow(),
            ApplicationObjectId = objectId ?? current.ApplicationObjectId, CertificateKeyId = keyId ?? current.CertificateKeyId,
        };
        await settings.SetAsync(SetupAppSettings.SettingKey, next, actor, cancellationToken).ConfigureAwait(false);
        return next;
    }

    /// <summary>The settings of the setup app registration, one check each.</summary>
    public static IReadOnlyList<SetupCheck> EvaluateRegistration(ApplicationRegistration app, GraphResourceApp graph, Uri redirectUri, string? thumbprint,
        bool directoryRolesInToken)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(redirectUri);
        var graphId = Guid.Parse(OnboardingScript.GraphAppId);
        var delegated = app.RequiredAccess.Where(a => a.ResourceAppId == graphId && a.Type == "Scope").Select(a => a.Id).ToHashSet();
        var wanted = new[] { "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" };
        var missing = wanted.Where(w => graph.DelegatedScopes.FirstOrDefault(s => s.Value == w) is not { } scope || !delegated.Contains(scope.Id)).ToList();
        var applicationPermissions = app.RequiredAccess.Count(a => a.Type == "Role");
        return
        [
            new("Accounts in any organizational directory", app.SignInAudience == "AzureADMultipleOrgs", true,
                app.SignInAudience == "AzureADMultipleOrgs"
                    ? "The app is multi-tenant."
                    : $"Supported account types is {app.SignInAudience ?? "not set"}. Choose \"Accounts in any organizational directory\" under Authentication."),
            new("Redirect URI", app.RedirectUris.Contains(redirectUri.ToString(), StringComparer.Ordinal), true,
                app.RedirectUris.Contains(redirectUri.ToString(), StringComparer.Ordinal)
                    ? $"{redirectUri} is registered as a Web redirect URI."
                    : $"Add {redirectUri} as a redirect URI of type Web under Authentication."),
            new("Delegated permissions", missing.Count == 0, true,
                missing.Count == 0
                    ? "Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All (delegated) are requested."
                    : "Add these delegated Microsoft Graph permissions under API permissions: " + string.Join(", ", missing) + "."),
            new("No application permissions", applicationPermissions == 0, true,
                applicationPermissions == 0
                    ? "The app asks for no application permissions, so it holds no access of its own."
                    : "Remove the application permissions from the setup app; it needs delegated permissions only."),
            new("Certificate", thumbprint is not null && app.KeyFor(thumbprint) is not null, true,
                thumbprint is not null && app.KeyFor(thumbprint) is not null
                    ? "Vaulty's certificate is uploaded."
                    : "Upload the certificate you downloaded from this page under Certificates & secrets."),
            new("No secret", app.PasswordCount == 0, true,
                app.PasswordCount == 0 ? "The app has no secret." : "Delete the secrets of the setup app under Certificates & secrets; Vaulty signs in with its certificate only."),
            new("Directory roles in the token", directoryRolesInToken, false,
                directoryRolesInToken
                    ? "Vaulty sees the administrator's roles at sign-in and stops early for an account that cannot grant permissions."
                    : "Optional: under Token configuration, add a groups claim with Directory roles. Vaulty then stops before changing anything when the account is not an administrator."),
        ];
    }

    /// <summary>Renews the setup app's certificate itself: addKey with a proof signed by the current certificate, then removeKey.</summary>
    public async Task<string> RenewCertificateAsync(string actor, CancellationToken cancellationToken = default)
    {
        var current = await GetAsync(cancellationToken).ConfigureAwait(false);
        if (current.ClientId is not { } clientId || current.HomeTenantId is not { } home || current.ApplicationObjectId is not { } objectId)
        {
            throw new TenantException("Run the test sign-in first, so Vaulty knows the app registration.");
        }
        var next = TenantCertificate.Create(SetupAppSettings.DisplayName, clock);
        await secrets.SetAsync(SetupAppSettings.NextCertificateSecretName, next.Pfx, actor, cancellationToken).ConfigureAwait(false);
        Guid? newKeyId;
        using (var certificate = await LoadCertificateAsync(SetupAppSettings.CertificateSecretName, cancellationToken).ConfigureAwait(false))
        {
            var (token, _) = await identity.AppOnlyTokenAsync(home.ToString(), clientId, certificate, cancellationToken).ConfigureAwait(false);
            newKeyId = await registrations.AddKeyAsync(token, objectId, next, CertificateJwt.KeyProof(certificate, objectId, clock.GetUtcNow()),
                SetupAppSettings.DisplayName, cancellationToken).ConfigureAwait(false);
        }
        // The new certificate must sign in before it replaces the old one.
        using (var fresh = TenantCertificate.Load(next.Pfx))
        {
            await RetryAsync(() => identity.AppOnlyTokenAsync(home.ToString(), clientId, fresh, cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        var oldKeyId = current.CertificateKeyId;
        await secrets.SetAsync(SetupAppSettings.CertificateSecretName, next.Pfx, actor, cancellationToken).ConfigureAwait(false);
        await settings.SetAsync(SetupAppSettings.SettingKey, current with
        {
            CertificateThumbprint = next.Thumbprint, CertificateExpiresAt = next.NotAfter, CertificateKeyId = newKeyId, CredentialWorks = true,
            CredentialCheckedAt = clock.GetUtcNow(), CredentialDetail = "The renewed certificate signs in to the app.",
        }, actor, cancellationToken).ConfigureAwait(false);
        await secrets.PruneAsync(SetupAppSettings.CertificateSecretName, 1, cancellationToken).ConfigureAwait(false);
        if (oldKeyId is not { } old) return "The certificate was renewed. Remove the old certificate from the app registration in Entra.";
        try
        {
            using var fresh = TenantCertificate.Load(next.Pfx);
            var (token, _) = await identity.AppOnlyTokenAsync(home.ToString(), clientId, fresh, cancellationToken).ConfigureAwait(false);
            await registrations.RemoveKeyAsync(token, objectId, old, CertificateJwt.KeyProof(fresh, objectId, clock.GetUtcNow()), cancellationToken).ConfigureAwait(false);
            return "The certificate was renewed and the old one removed from the app registration.";
        }
        catch (Graph.GraphException)
        {
            return "The certificate was renewed. Microsoft did not remove the old certificate; it stops working on its end date, or remove it in Entra.";
        }
    }

    public async Task<System.Security.Cryptography.X509Certificates.X509Certificate2> LoadCertificateAsync(string secretName, CancellationToken cancellationToken)
    {
        using var secret = await secrets.GetAsync(secretName, cancellationToken).ConfigureAwait(false)
                           ?? throw new TenantException("The certificate of the Vaulty setup app is missing. Create one under Settings > Microsoft 365.");
        return TenantCertificate.Load(secret.Reveal());
    }

    /// <summary>Microsoft can take a little while before a new key signs in.</summary>
    internal static async Task RetryAsync(Func<Task> call, CancellationToken cancellationToken, int attempts = 6, TimeSpan? wait = null)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await call().ConfigureAwait(false);
                return;
            }
            catch (IdentityException) when (attempt < attempts)
            {
                await Task.Delay(wait ?? TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
