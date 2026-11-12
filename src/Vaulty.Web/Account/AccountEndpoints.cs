using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using Vaulty.Core.Domain;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Identity;
using Vaulty.Infrastructure.Web;

namespace Vaulty.Web.Account;

/// <summary>Writes account events (sign-in, MFA, step-up) to the organization's audit log.</summary>
public sealed class AccountAudit(NpgsqlDataSource dataSource, ILogger<AccountAudit> logger)
{
    public async Task WriteAsync(User? user, string action, object? details = null)
    {
        if (user is null)
        {
            // Unknown user name: no organization to log to; the application log records it without the name.
            logger.LogWarning("Account event {Action} for an unknown user", action);
            return;
        }
        await using var session = await OrganizationSession.BeginAsync(dataSource, user.OrganizationId);
        await AuditLog.WriteAsync(session, $"user:{user.Id}", action, $"user:{user.Id}", details);
        await session.CommitAsync();
    }

    /// <summary>An event of a sign-in that reached an organization but no user of it (an account that is not linked).</summary>
    public async Task WriteOrganizationAsync(Guid organizationId, string action, object? details = null)
    {
        await using var session = await OrganizationSession.BeginAsync(dataSource, organizationId);
        await AuditLog.WriteAsync(session, "anonymous:microsoft", action, $"organization:{organizationId}", details);
        await session.CommitAsync();
    }
}

/// <summary>
/// Sign-in, second factor, passkeys, MFA enrollment, step-up ("Confirm it's you"), sign-out and first-administrator setup.
/// Form posts are protected by antiforgery automatically; JSON calls send the token in a header.
/// </summary>
public static class AccountEndpoints
{
    public const string RecoveryCodesCookie = "__Host-vaulty-codes";
    private static readonly TimeSpan RecoveryCodesLifetime = TimeSpan.FromMinutes(2);

    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        var account = app.MapGroup("/account");
        account.MapPost("/login", LoginAsync).AllowAnonymous();
        account.MapPost("/login/second-factor", SecondFactorAsync).AllowAnonymous();
        account.MapPost("/passkey/request-options", PasskeyRequestOptionsAsync).AllowAnonymous();
        account.MapPost("/passkey/login", PasskeyLoginAsync).AllowAnonymous();
        account.MapPost("/passkey/creation-options", PasskeyCreationOptionsAsync).RequireAuthorization(VaultyPolicies.SignedIn);
        account.MapPost("/passkey/register", PasskeyRegisterAsync).RequireAuthorization(VaultyPolicies.SignedIn);
        account.MapPost("/mfa/totp", EnrollTotpAsync).RequireAuthorization(VaultyPolicies.SignedIn);
        account.MapPost("/stepup/totp", StepUpTotpAsync).RequireAuthorization();
        account.MapPost("/stepup/passkey", StepUpPasskeyAsync).RequireAuthorization();
        account.MapPost("/logout", LogoutAsync).RequireAuthorization(VaultyPolicies.SignedIn);
        app.MapPost("/setup", SetupAsync).AllowAnonymous();
    }

    public sealed record PasskeyCredential(string Credential, string? Name);

    private static async Task<IResult> LoginAsync([FromForm] string username, [FromForm] string password, [FromForm] string? returnUrl,
        SignInManager<User> signIn, UserManager<User> users, AccountAudit audit, MicrosoftSignInService microsoft)
    {
        var user = await users.FindByNameAsync(username ?? "");
        var decision = user is null ? LocalSignInDecision.Allowed : await microsoft.LocalSignInAsync(user);
        if (decision is LocalSignInDecision.UseMicrosoft or LocalSignInDecision.MicrosoftOnly)
        {
            if (await users.IsLockedOutAsync(user!)) return Results.Redirect($"/account/login?error=locked&returnUrl={Safe(returnUrl)}");
            // Answered only once the password is right, so the answer reveals nothing about the account to a guesser.
            var correct = await users.CheckPasswordAsync(user!, password ?? "");
            await audit.WriteAsync(user, correct ? "login.refused" : "login.failed",
                new { method = "password", reason = decision == LocalSignInDecision.UseMicrosoft ? "linked" : "microsoft_only" });
            if (!correct)
            {
                // A wrong password counts towards the lockout exactly as on the normal path.
                await users.AccessFailedAsync(user!);
                return Results.Redirect($"/account/login?error=invalid&returnUrl={Safe(returnUrl)}");
            }
            return Results.Redirect($"/account/login?error={(decision == LocalSignInDecision.UseMicrosoft ? "use-microsoft" : "microsoft-only")}&returnUrl={Safe(returnUrl)}");
        }
        var result = await signIn.PasswordSignInAsync(username ?? "", password ?? "", isPersistent: false, lockoutOnFailure: true);
        if (result.RequiresTwoFactor) return Results.Redirect($"/account/login/second-factor?returnUrl={Safe(returnUrl)}");
        if (result.Succeeded)
        {
            if (decision == LocalSignInDecision.BreakGlass) await microsoft.RaiseBreakGlassAlertAsync(user!, "password");
            await audit.WriteAsync(user, "login.succeeded", new { method = "password", mfa = false });
            // Without a second factor the user can only enroll one.
            return Results.Redirect("/account/mfa-setup");
        }
        await audit.WriteAsync(user, result.IsLockedOut ? "login.locked_out" : "login.failed", new { method = "password" });
        return Results.Redirect($"/account/login?error={(result.IsLockedOut ? "locked" : "invalid")}&returnUrl={Safe(returnUrl)}");
    }

    private static async Task<IResult> SecondFactorAsync([FromForm] string code, [FromForm] bool? recovery, [FromForm] string? returnUrl,
        SignInManager<User> signIn, AccountAudit audit, MicrosoftSignInService microsoft)
    {
        var user = await signIn.GetTwoFactorAuthenticationUserAsync();
        if (user is null) return Results.Redirect("/account/login?error=expired");
        var cleaned = (code ?? "").Replace(" ", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal);
        if (recovery != true) signIn.Context.Items[VaultyClaims.ProvenNowItem] = true;
        var result = recovery == true
            ? await signIn.TwoFactorRecoveryCodeSignInAsync(cleaned)
            : await signIn.TwoFactorAuthenticatorSignInAsync(cleaned, isPersistent: false, rememberClient: false);
        if (result.Succeeded)
        {
            if (await microsoft.LocalSignInAsync(user) == LocalSignInDecision.BreakGlass) await microsoft.RaiseBreakGlassAlertAsync(user, "password");
            await audit.WriteAsync(user, "login.succeeded", new { method = recovery == true ? "recovery_code" : "totp", mfa = true });
            return Results.Redirect(Safe(returnUrl));
        }
        await audit.WriteAsync(user, result.IsLockedOut ? "login.locked_out" : "login.second_factor_failed", new { method = "totp" });
        return Results.Redirect($"/account/login/second-factor?error=invalid&returnUrl={Safe(returnUrl)}");
    }

    /// <summary>Options for navigator.credentials.get: the pending two-factor user, or discoverable credentials for passwordless sign-in.</summary>
    private static async Task<IResult> PasskeyRequestOptionsAsync(HttpContext context, SignInManager<User> signIn, IAntiforgery antiforgery)
    {
        await antiforgery.ValidateRequestAsync(context);
        var user = await signIn.GetTwoFactorAuthenticationUserAsync();
        var options = await signIn.MakePasskeyRequestOptionsAsync(user);
        return Results.Content(options, "application/json");
    }

    private static async Task<IResult> PasskeyLoginAsync(HttpContext context, [FromBody] PasskeyCredential body, SignInManager<User> signIn,
        UserManager<User> users, IAntiforgery antiforgery, AccountAudit audit, MicrosoftSignInService microsoft)
    {
        await antiforgery.ValidateRequestAsync(context);
        // A passkey after a password or a Microsoft sign-in is a second factor; on its own it is a local sign-in.
        var secondFactor = await signIn.GetTwoFactorAuthenticationUserAsync() is not null;
        signIn.Context.Items[VaultyClaims.ProvenNowItem] = true;
        var result = await signIn.PasskeySignInAsync(body.Credential);
        if (!result.Succeeded)
        {
            await audit.WriteAsync(null, "login.passkey_failed");
            return Results.Json(new { ok = false, error = result.IsLockedOut ? "locked" : "invalid" }, statusCode: 401);
        }
        var user = await users.GetUserAsync(context.User) ?? await signIn.UserManager.FindByIdAsync(
            signIn.Context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "");
        var decision = user is null || secondFactor ? LocalSignInDecision.Allowed : await microsoft.LocalSignInAsync(user);
        if (decision is LocalSignInDecision.UseMicrosoft or LocalSignInDecision.MicrosoftOnly)
        {
            await signIn.SignOutAsync();
            await audit.WriteAsync(user, "login.refused", new { method = "passkey", reason = decision == LocalSignInDecision.UseMicrosoft ? "linked" : "microsoft_only" });
            return Results.Json(new { ok = false, error = decision == LocalSignInDecision.UseMicrosoft ? "use-microsoft" : "microsoft-only" }, statusCode: 403);
        }
        if (decision == LocalSignInDecision.BreakGlass) await microsoft.RaiseBreakGlassAlertAsync(user!, "passkey");
        await audit.WriteAsync(user, "login.succeeded", new { method = "passkey", mfa = true });
        return Results.Json(new { ok = true });
    }

    private static async Task<IResult> PasskeyCreationOptionsAsync(HttpContext context, SignInManager<User> signIn, UserManager<User> users,
        IAntiforgery antiforgery)
    {
        await antiforgery.ValidateRequestAsync(context);
        var user = await users.GetUserAsync(context.User);
        if (user is null) return Results.Unauthorized();
        var options = await signIn.MakePasskeyCreationOptionsAsync(new PasskeyUserEntity
        {
            Id = user.Id.ToString(),
            Name = user.UserName,
            DisplayName = user.DisplayName ?? user.UserName,
        });
        return Results.Content(options, "application/json");
    }

    private static async Task<IResult> PasskeyRegisterAsync(HttpContext context, [FromBody] PasskeyCredential body, SignInManager<User> signIn,
        UserManager<User> users, IAntiforgery antiforgery, OrganizationSetup setup, AccountAudit audit)
    {
        await antiforgery.ValidateRequestAsync(context);
        var user = await users.GetUserAsync(context.User);
        if (user is null) return Results.Unauthorized();
        var attestation = await signIn.PerformPasskeyAttestationAsync(body.Credential);
        if (!attestation.Succeeded) return Results.Json(new { ok = false, error = attestation.Failure.Message }, statusCode: 400);
        attestation.Passkey.Name = string.IsNullOrWhiteSpace(body.Name) ? "Passkey" : body.Name.Trim()[..Math.Min(body.Name.Trim().Length, 60)];
        var added = await users.AddOrUpdatePasskeyAsync(user, attestation.Passkey);
        if (!added.Succeeded) return Results.Json(new { ok = false, error = "The passkey could not be saved." }, statusCode: 400);
        await FinishMfaEnrollmentAsync(user, users, signIn, setup, audit, "passkey");
        return Results.Json(new { ok = true });
    }

    private static async Task<IResult> EnrollTotpAsync(HttpContext context, [FromForm] string code, SignInManager<User> signIn,
        UserManager<User> users, OrganizationSetup setup, AccountAudit audit, IDataProtectionProvider protection)
    {
        var user = await users.GetUserAsync(context.User);
        if (user is null) return Results.Unauthorized();
        var cleaned = (code ?? "").Replace(" ", "", StringComparison.Ordinal);
        if (!await users.VerifyTwoFactorTokenAsync(user, users.Options.Tokens.AuthenticatorTokenProvider, cleaned))
        {
            return Results.Redirect("/account/mfa-setup?error=code");
        }
        var codes = (await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))?.ToList() ?? [];
        await FinishMfaEnrollmentAsync(user, users, signIn, setup, audit, "totp");
        // The codes are shown once, on the next page; they travel in a short-lived encrypted cookie, never in a URL.
        var protector = protection.CreateProtector("vaulty.recovery-codes").ToTimeLimitedDataProtector();
        context.Response.Cookies.Append(RecoveryCodesCookie, protector.Protect(JsonSerializer.Serialize(codes), RecoveryCodesLifetime),
            new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/", MaxAge = RecoveryCodesLifetime });
        return Results.Redirect("/account/recovery-codes");
    }

    /// <summary>A second factor exists now: require it at sign-in, refresh the session, finish the first administrator.</summary>
    private static async Task FinishMfaEnrollmentAsync(User user, UserManager<User> users, SignInManager<User> signIn, OrganizationSetup setup,
        AccountAudit audit, string method)
    {
        if (!user.TwoFactorEnabled) await users.SetTwoFactorEnabledAsync(user, true);
        await users.UpdateSecurityStampAsync(user);
        await audit.WriteAsync(user, "mfa.enrolled", new { method });
        await setup.CompleteFirstAdminAsync(user.OrganizationId, user.Id);
        await signIn.RefreshSignInAsync(user);
    }

    private static async Task<IResult> StepUpTotpAsync(HttpContext context, [FromForm] string code, [FromForm] string? returnUrl,
        SignInManager<User> signIn, UserManager<User> users, AccountAudit audit, TimeProvider clock)
    {
        var user = await users.GetUserAsync(context.User);
        if (user is null) return Results.Unauthorized();
        if (user.AuthenticatorKey is null ||
            !await users.VerifyTwoFactorTokenAsync(user, users.Options.Tokens.AuthenticatorTokenProvider, (code ?? "").Replace(" ", "", StringComparison.Ordinal)))
        {
            await audit.WriteAsync(user, "stepup.failed", new { method = "totp" });
            return Results.Redirect($"/account/confirm?error=code&returnUrl={Safe(returnUrl)}");
        }
        await ConfirmedAsync(user, signIn, audit, clock, "totp");
        return Results.Redirect(Safe(returnUrl));
    }

    private static async Task<IResult> StepUpPasskeyAsync(HttpContext context, [FromBody] PasskeyCredential body, SignInManager<User> signIn,
        UserManager<User> users, IAntiforgery antiforgery, AccountAudit audit, TimeProvider clock)
    {
        await antiforgery.ValidateRequestAsync(context);
        var user = await users.GetUserAsync(context.User);
        if (user is null) return Results.Unauthorized();
        var assertion = await signIn.PerformPasskeyAssertionAsync(body.Credential);
        if (!assertion.Succeeded || assertion.User.Id != user.Id)
        {
            await audit.WriteAsync(user, "stepup.failed", new { method = "passkey" });
            return Results.Json(new { ok = false }, statusCode: 401);
        }
        await users.AddOrUpdatePasskeyAsync(user, assertion.Passkey);
        await ConfirmedAsync(user, signIn, audit, clock, "passkey");
        return Results.Json(new { ok = true });
    }

    private static async Task ConfirmedAsync(User user, SignInManager<User> signIn, AccountAudit audit, TimeProvider clock, string method)
    {
        await signIn.SignInWithClaimsAsync(user, isPersistent: false,
            [new Claim(VaultyClaims.StepUp, clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture))]);
        await audit.WriteAsync(user, "stepup.confirmed", new { method });
    }

    private static async Task<IResult> LogoutAsync(HttpContext context, SignInManager<User> signIn, UserManager<User> users, AccountAudit audit)
    {
        var user = await users.GetUserAsync(context.User);
        await signIn.SignOutAsync();
        await audit.WriteAsync(user, "logout");
        return Results.Redirect("/account/login");
    }

    private static async Task<IResult> SetupAsync([FromForm] string token, [FromForm] string organization, [FromForm] string email,
        [FromForm] string? displayName, [FromForm] string password, [FromForm] string confirm, SetupTokens tokens, OrganizationSetup setup,
        UserManager<User> users, SignInManager<User> signIn, AccountAudit audit)
    {
        if (!await tokens.ValidateAsync(token)) return Results.Redirect("/setup?error=token");
        if (string.IsNullOrWhiteSpace(organization) || string.IsNullOrWhiteSpace(email) || !email.Contains('@', StringComparison.Ordinal))
        {
            return Results.Redirect($"/setup?token={Uri.EscapeDataString(token)}&error=fields");
        }
        if (password != confirm) return Results.Redirect($"/setup?token={Uri.EscapeDataString(token)}&error=confirm");

        var user = new User
        {
            Id = Guid.CreateVersion7(),
            UserName = email.Trim(),
            NormalizedUserName = users.NormalizeName(email.Trim()),
            Email = email.Trim(),
            NormalizedEmail = users.NormalizeEmail(email.Trim()),
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? null : displayName.Trim(),
        };
        // Check the password before anything is created: setup closes as soon as an organization exists.
        foreach (var validator in users.PasswordValidators)
        {
            var check = await validator.ValidateAsync(users, user, password ?? "");
            if (!check.Succeeded)
            {
                return Results.Redirect($"/setup?token={Uri.EscapeDataString(token)}&error=password&detail={Uri.EscapeDataString(check.Errors.First().Description)}");
            }
        }
        user.OrganizationId = await setup.CreateOrganizationAsync(organization, user.Id);
        var created = await users.CreateAsync(user, password!);
        if (!created.Succeeded) return Results.Problem("The first administrator could not be created.");
        await tokens.ConsumeAsync();
        await audit.WriteAsync(user, "user.created", new { first_admin = true });
        await signIn.SignInAsync(user, isPersistent: false);
        return Results.Redirect("/account/mfa-setup");
    }

    /// <summary>Only local return URLs.</summary>
    public static string Safe(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal) &&
        !returnUrl.StartsWith("/\\", StringComparison.Ordinal)
            ? returnUrl
            : "/";
}
