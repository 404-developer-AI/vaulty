using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Npgsql;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Crypto;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Identity;
using Vaulty.Infrastructure.Secrets;

namespace Vaulty.Infrastructure.Web;

/// <summary>Claim types Vaulty adds to the sign-in cookie.</summary>
public static class VaultyClaims
{
    public const string Organization = "vaulty:org";
    /// <summary>Unix seconds of the interactive sign-in; the session ends 8 hours later whatever the activity.</summary>
    public const string AuthTime = "vaulty:auth_time";
    /// <summary>"1" when the user has a second factor (passkey or authenticator app).</summary>
    public const string Mfa = "vaulty:mfa";
    /// <summary>Unix seconds of the last "Confirm it's you".</summary>
    public const string StepUp = "vaulty:stepup";
    /// <summary>How the session signed in: "microsoft" for sign-in with Microsoft; absent for a local account.</summary>
    public const string Method = "vaulty:method";
    /// <summary>
    /// Where the second factor of a Microsoft sign-in came from: "entra" when the token proved it, "delegated" when the
    /// organization leaves it to its tenant. Absent when Vaulty asked its own.
    /// </summary>
    public const string MfaSource = "vaulty:mfa_source";

    /// <summary>The HttpContext item a sign-in sets so the claims factory adds the method and the second-factor source.</summary>
    public const string SignInItem = "vaulty:signin";
    /// <summary>Set by a sign-in that proved the user just now (authenticator code, passkey, fresh Microsoft sign-in).</summary>
    public const string ProvenNowItem = "vaulty:proven-now";
}

/// <summary>What a sign-in with Microsoft hands to the claims factory for the new session.</summary>
/// <param name="ProvenNow">The user signed in at Microsoft just now, instead of reusing an older Microsoft session.</param>
public sealed record MicrosoftSessionFacts(string? MfaSource, bool ProvenNow = false);

public static class VaultyPolicies
{
    public const string PermissionPrefix = "perm:";
    /// <summary>Signed in, with or without a second factor (only the MFA set-up pages use it).</summary>
    public const string SignedIn = "signed-in";

    public static string Permission(string key) => PermissionPrefix + key;
}

public sealed class VaultyHostOptions
{
    public string DatabaseConnectionString { get; set; } = "Host=/var/run/postgresql;Database=vaulty;Username=vaulty_api";
    public string HostId { get; set; } = Environment.MachineName;
    /// <summary>The public host name; passkeys are bound to it.</summary>
    public string? PublicHost { get; set; }
    public int MasterKeyVersion { get; set; } = 1;
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan AbsoluteTimeout = TimeSpan.FromHours(8);
    /// <summary>How long a confirmation ("Confirm it's you", or a sign-in that proved the user) covers sensitive actions.</summary>
    public static readonly TimeSpan StepUpValidity = TimeSpan.FromMinutes(30);
}

public static class VaultyWebSetup
{
    /// <summary>Database, master key, secrets store and the data protection ring (shared by web and API).</summary>
    public static VaultyHostOptions AddVaultyCore(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment,
        IMasterKeySource? masterKeySource = null)
    {
        var options = services.AddVaultyData(configuration, environment, "vaulty_api", masterKeySource);
        services.AddSingleton(sp =>
        {
            var key = sp.GetRequiredService<IMasterKeySource>().ReadMasterKey();
            try
            {
                return new DataProtectionKeyCipher(key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        });
        services.AddDataProtection().SetApplicationName("vaulty").PersistKeysToVaultyDatabase();
        services.AddSingleton<AccessService>();
        return options;
    }

    /// <summary>Database, master key, secrets store, settings and Microsoft Graph: what every Vaulty process needs.</summary>
    public static VaultyHostOptions AddVaultyData(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment,
        string databaseRole, IMasterKeySource? masterKeySource = null)
    {
        var options = new VaultyHostOptions
        {
            DatabaseConnectionString = configuration["Vaulty:Database:ConnectionString"]
                                       ?? $"Host=/var/run/postgresql;Database=vaulty;Username={databaseRole}",
            HostId = configuration["Vaulty:HostId"] ?? Environment.MachineName,
            PublicHost = configuration["Vaulty:PublicHost"],
            MasterKeyVersion = configuration.GetValue("Vaulty:MasterKeyVersion", 1),
        };
        services.AddSingleton(options);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(_ => VaultyDataSource.Create(options.DatabaseConnectionString));
        var keySource = masterKeySource ?? MasterKeys.Resolve(allowDevelopmentKey: environment.IsDevelopment(), options.MasterKeyVersion);
        services.AddSingleton(keySource);
        services.AddSingleton(_ =>
        {
            var key = keySource.ReadMasterKey();
            try
            {
                return new SecretCipher(key, options.HostId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        });
        services.AddSingleton<ISecretStore>(sp => new PostgresSecretStore(sp.GetRequiredService<NpgsqlDataSource>(),
            sp.GetRequiredService<SecretCipher>(), sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<Storage.PlatformSettings>();
        services.AddSingleton<Storage.StorageClientFactory>();
        services.AddSingleton<Tenants.DedicatedAppCredentialProvider>();
        services.AddSingleton<Graph.Auth.IGraphTokenProvider>(sp =>
            new Graph.Auth.MsalGraphTokenProvider(sp.GetRequiredService<Tenants.DedicatedAppCredentialProvider>()));
        services.AddSingleton(sp => new Tenants.GraphServices(sp.GetRequiredService<Graph.Auth.IGraphTokenProvider>()));
        return options;
    }

    /// <summary>Identity with passkeys and TOTP, the session cookie and permission-based authorization.</summary>
    public static void AddVaultyIdentity(this IServiceCollection services, VaultyHostOptions hostOptions)
    {
        ArgumentNullException.ThrowIfNull(hostOptions);
        services.AddAuthentication(o =>
            {
                o.DefaultScheme = IdentityConstants.ApplicationScheme;
                o.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddIdentityCookies();
        services.AddIdentityCore<User>(o =>
            {
                o.Password.RequiredLength = 12;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireDigit = false;
                o.Lockout.MaxFailedAccessAttempts = 5;
                o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                o.Lockout.AllowedForNewUsers = true;
                o.SignIn.RequireConfirmedAccount = false;
                o.User.RequireUniqueEmail = false;
                o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddUserStore<VaultyUserStore>()
            .AddSignInManager<VaultySignInManager>()
            // Only the authenticator app as a code-based factor: no SMS, no e-mail codes.
            .AddTokenProvider<AuthenticatorTokenProvider<User>>(TokenOptions.DefaultAuthenticatorProvider)
            .AddTokenProvider<DataProtectorTokenProvider<User>>(TokenOptions.DefaultProvider)
            .AddClaimsPrincipalFactory<VaultyClaimsFactory>();

        services.Configure<IdentityPasskeyOptions>(o =>
        {
            if (hostOptions.PublicHost is { Length: > 0 } host) o.ServerDomain = host;
            o.UserVerificationRequirement = "required";
            o.ResidentKeyRequirement = "required";
        });
        services.Configure<SecurityStampValidatorOptions>(o =>
        {
            o.ValidationInterval = TimeSpan.FromMinutes(1);
            o.OnRefreshingPrincipal = KeepSessionClaims;
        });
        services.ConfigureApplicationCookie(o =>
        {
            o.Cookie.Name = "__Host-vaulty";
            o.Cookie.HttpOnly = true;
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.Path = "/";
            o.ExpireTimeSpan = VaultyHostOptions.IdleTimeout;
            o.SlidingExpiration = true;
            o.LoginPath = "/account/login";
            o.LogoutPath = "/account/logout";
            o.AccessDeniedPath = "/access-denied";
            var stampValidation = o.Events.OnValidatePrincipal;
            o.Events.OnValidatePrincipal = async context =>
            {
                // Absolute session lifetime: 8 hours after the interactive sign-in, whatever the activity.
                var authTime = context.Principal?.FindFirst(VaultyClaims.AuthTime)?.Value;
                var clock = context.HttpContext.RequestServices.GetRequiredService<TimeProvider>();
                if (!long.TryParse(authTime, out var seconds) ||
                    clock.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(seconds) > VaultyHostOptions.AbsoluteTimeout)
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme).ConfigureAwait(false);
                    return;
                }
                await SecurityStampValidator.ValidatePrincipalAsync(context).ConfigureAwait(false);
            };
            _ = stampValidation;
            o.Events.OnRedirectToLogin = context => ApiAwareRedirect(context, StatusCodes.Status401Unauthorized);
            o.Events.OnRedirectToAccessDenied = context => ApiAwareRedirect(context, StatusCodes.Status403Forbidden);
        });
        services.ConfigureExternalCookie(o =>
        {
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.Cookie.SameSite = SameSiteMode.Lax;
        });

        services.AddScoped<CurrentAccess>();
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PermissionHandler>();
        services.AddAuthorization(o =>
        {
            // Everything requires a signed-in user with a second factor unless a page or endpoint says otherwise.
            var withSecondFactor = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().RequireClaim(VaultyClaims.Mfa, "1").Build();
            o.FallbackPolicy = withSecondFactor;
            // [Authorize] without a policy also requires the second factor.
            o.DefaultPolicy = withSecondFactor;
            o.AddPolicy(VaultyPolicies.SignedIn, p => p.RequireAuthenticatedUser());
        });
    }

    /// <summary>Claims of the session itself, not of the user: a refresh of the principal must keep them as they were.</summary>
    private static readonly string[] SessionClaims = [VaultyClaims.AuthTime, VaultyClaims.Method, VaultyClaims.MfaSource, VaultyClaims.StepUp];

    /// <summary>
    /// The security stamp check rebuilds the principal while the request has no user yet, so the claims factory cannot
    /// see the session it refreshes. Without this the 8-hour limit would restart at every check, and a Microsoft
    /// sign-in would lose how it signed in. The user's own claims (roles, second factor) are rebuilt from the database.
    /// </summary>
    public static Task KeepSessionClaims(SecurityStampRefreshingPrincipalContext context)
    {
        if (context.CurrentPrincipal is not { } current || context.NewPrincipal?.Identity is not ClaimsIdentity identity) return Task.CompletedTask;
        foreach (var type in SessionClaims)
        {
            foreach (var claim in identity.FindAll(type).ToList()) identity.RemoveClaim(claim);
            if (current.FindFirst(type) is { } kept) identity.AddClaim(new Claim(type, kept.Value));
        }
        // A token that proved a second factor counts for the session it started (see VaultyClaimsFactory).
        if (current.FindFirst(VaultyClaims.MfaSource)?.Value == "entra" && !identity.HasClaim(VaultyClaims.Mfa, "1"))
        {
            identity.AddClaim(new Claim(VaultyClaims.Mfa, "1"));
        }
        return Task.CompletedTask;
    }

    private static Task ApiAwareRedirect(Microsoft.AspNetCore.Authentication.RedirectContext<CookieAuthenticationOptions> context, int status)
    {
        if (context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = status;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    }

    public static bool HasFreshStepUp(ClaimsPrincipal user, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(clock);
        return long.TryParse(user.FindFirst(VaultyClaims.StepUp)?.Value, out var seconds) &&
               clock.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(seconds) <= VaultyHostOptions.StepUpValidity;
    }

    public static Guid? OrganizationId(ClaimsPrincipal user) =>
        Guid.TryParse(user?.FindFirst(VaultyClaims.Organization)?.Value, out var id) ? id : null;

    public static Guid? UserId(ClaimsPrincipal user) =>
        Guid.TryParse(user?.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id) ? id : null;
}

/// <summary>Adds organization, MFA state, sign-in time and (when present) the step-up time to the principal.</summary>
public sealed class VaultyClaimsFactory(UserManager<User> users, IOptions<IdentityOptions> options, NpgsqlDataSource dataSource,
    IHttpContextAccessor http, TimeProvider clock) : UserClaimsPrincipalFactory<User>(users, options)
{
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(User user)
    {
        ArgumentNullException.ThrowIfNull(user);
        var identity = await base.GenerateClaimsAsync(user).ConfigureAwait(false);
        identity.AddClaim(new Claim(VaultyClaims.Organization, user.OrganizationId.ToString()));
        // A refreshed sign-in keeps the original sign-in time, method and second-factor source; a new sign-in starts over.
        var existing = http.HttpContext?.User;
        var same = existing?.Identity?.IsAuthenticated == true && VaultyWebSetup.UserId(existing) == user.Id;
        string? method;
        string? mfaSource;
        if (http.HttpContext?.Items[VaultyClaims.SignInItem] is MicrosoftSessionFacts microsoft)
        {
            (method, mfaSource) = ("microsoft", microsoft.MfaSource);
        }
        else
        {
            (method, mfaSource) = same ? (existing!.FindFirst(VaultyClaims.Method)?.Value, existing.FindFirst(VaultyClaims.MfaSource)?.Value) : (null, null);
        }
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId).ConfigureAwait(false);
        // "delegated" counts through HasMfaAsync only, so switching it off takes effect at the next check of the session;
        // a token that proved a second factor counts for the session it started.
        if (await AccessService.HasMfaAsync(session, user.Id).ConfigureAwait(false) || mfaSource == "entra") identity.AddClaim(new Claim(VaultyClaims.Mfa, "1"));
        if (method is not null) identity.AddClaim(new Claim(VaultyClaims.Method, method));
        if (mfaSource is not null) identity.AddClaim(new Claim(VaultyClaims.MfaSource, mfaSource));
        var keep = same ? existing!.FindFirst(VaultyClaims.AuthTime)?.Value : null;
        var now = clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        identity.AddClaim(new Claim(VaultyClaims.AuthTime, keep ?? now));
        // A new sign-in that proved the user just now counts as a confirmation, so sensitive actions right after signing in
        // do not ask again. A password alone, a recovery code or a reused Microsoft session does not count.
        var provenNow = http.HttpContext?.Items[VaultyClaims.ProvenNowItem] is true ||
                        http.HttpContext?.Items[VaultyClaims.SignInItem] is MicrosoftSessionFacts { ProvenNow: true, MfaSource: not null };
        if (!same && provenNow) identity.AddClaim(new Claim(VaultyClaims.StepUp, now));
        return identity;
    }
}

/// <summary>The sign-in manager, with the step a sign-in with Microsoft takes when Vaulty asks its own second factor.</summary>
public sealed class VaultySignInManager(UserManager<User> userManager, IHttpContextAccessor contextAccessor, IUserClaimsPrincipalFactory<User> claimsFactory,
    IOptions<IdentityOptions> optionsAccessor, Microsoft.Extensions.Logging.ILogger<SignInManager<User>> logger, IAuthenticationSchemeProvider schemes,
    IUserConfirmation<User> confirmation)
    : SignInManager<User>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
{
    /// <summary>
    /// Signs in a user Microsoft identified. With a second factor from Microsoft (<paramref name="mfaSource"/>) the session
    /// starts at once; otherwise a user with a passkey or authenticator app continues on the second-factor page, exactly as
    /// after a password.
    /// </summary>
    public async Task<SignInResult> MicrosoftSignInAsync(User user, string? mfaSource, bool provenNow = false)
    {
        ArgumentNullException.ThrowIfNull(user);
        Context.Items[VaultyClaims.SignInItem] = new MicrosoftSessionFacts(mfaSource, provenNow);
        if (!await CanSignInAsync(user).ConfigureAwait(false)) return SignInResult.NotAllowed;
        if (await UserManager.IsLockedOutAsync(user).ConfigureAwait(false)) return SignInResult.LockedOut;
        return await SignInOrTwoFactorAsync(user, isPersistent: false, loginProvider: null, bypassTwoFactor: mfaSource is not null).ConfigureAwait(false);
    }
}

/// <summary>The access of the signed-in user, loaded once per request or circuit.</summary>
public sealed class CurrentAccess(AccessService access, IHttpContextAccessor http)
{
    private UserAccess? _access;

    public async Task<UserAccess> GetAsync(ClaimsPrincipal? principal = null)
    {
        if (_access is not null) return _access;
        var user = principal ?? http.HttpContext?.User ?? new ClaimsPrincipal();
        var org = VaultyWebSetup.OrganizationId(user);
        var id = VaultyWebSetup.UserId(user);
        _access = org is { } o && id is { } u ? await access.GetAccessAsync(o, u).ConfigureAwait(false) : UserAccess.None(Guid.Empty, Guid.Empty);
        return _access;
    }

    public void Invalidate() => _access = null;
}

public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    public string Permission { get; } = permission;
}

/// <summary>Turns "perm:&lt;key&gt;" into a policy: signed in, second factor, and the permission for at least one customer.</summary>
public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options) : DefaultAuthorizationPolicyProvider(options)
{
    public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        ArgumentNullException.ThrowIfNull(policyName);
        if (!policyName.StartsWith(VaultyPolicies.PermissionPrefix, StringComparison.Ordinal))
        {
            return await base.GetPolicyAsync(policyName).ConfigureAwait(false);
        }
        var key = policyName[VaultyPolicies.PermissionPrefix.Length..];
        if (!Core.Security.Permissions.Exists(key)) throw new InvalidOperationException($"Unknown permission policy '{policyName}'.");
        return new AuthorizationPolicyBuilder().RequireAuthenticatedUser().RequireClaim(VaultyClaims.Mfa, "1")
            .AddRequirements(new PermissionRequirement(key)).Build();
    }
}

public sealed class PermissionHandler(CurrentAccess current) : AuthorizationHandler<PermissionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);
        var access = await current.GetAsync(context.User).ConfigureAwait(false);
        if (access.Allows(requirement.Permission)) context.Succeed(requirement);
    }
}

/// <summary>The scheme and client address as the reverse proxy on the same host saw them.</summary>
public static class ProxyHeaders
{
    /// <summary>
    /// Vaulty listens on loopback behind Caddy, which terminates TLS. Without this every request looks like plain HTTP:
    /// redirects point to http:// and the Secure-only cookies fail. Only loopback proxies are trusted (the default).
    /// </summary>
    public static IApplicationBuilder UseVaultyForwardedHeaders(this IApplicationBuilder app) => app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
    });
}

/// <summary>Security headers and a strict Content Security Policy with a per-response nonce.</summary>
public static class SecurityHeaders
{
    public const string NonceItemKey = "vaulty-csp-nonce";

    public static IApplicationBuilder UseVaultySecurityHeaders(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        context.Items[NonceItemKey] = nonce;
        context.Response.OnStarting(static state =>
        {
            var ctx = (HttpContext)state;
            if (ctx.Response.ContentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) == true)
            {
                ctx.Response.Headers.CacheControl = "no-store";
            }
            return Task.CompletedTask;
        }, context);
        var headers = context.Response.Headers;
        headers["Content-Security-Policy"] = ContentSecurityPolicy(nonce);
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";
        if (context.Request.IsHttps) headers.StrictTransportSecurity = "max-age=31536000; includeSubDomains";
        await next().ConfigureAwait(false);
    });

    /// <summary>
    /// Browsers apply form-action to the redirects that follow a form post as well, so the Microsoft sign-in host has to
    /// be allowed: the sign-in, link and step-up forms post to Vaulty, which answers with a redirect to Microsoft.
    /// </summary>
    public static string ContentSecurityPolicy(string nonce) =>
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self' https://login.microsoftonline.com; " +
        $"script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; " +
        "connect-src 'self' wss: ws:; frame-src 'self'; worker-src 'self'";
}
