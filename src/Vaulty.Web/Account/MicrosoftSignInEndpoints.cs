using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Vaulty.Core.Domain;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Identity;
using Vaulty.Infrastructure.Web;

namespace Vaulty.Web.Account;

/// <summary>A message for the sign-in page, protected and valid five minutes, so a link cannot put arbitrary text on it.</summary>
public sealed class SignInMessages(IDataProtectionProvider protection)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    private readonly ITimeLimitedDataProtector _protector = protection.CreateProtector("vaulty.signin-message").ToTimeLimitedDataProtector();

    public string Protect(string message) => _protector.Protect(message, Lifetime);

    public string? Unprotect(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        try
        {
            return _protector.Unprotect(value);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }
}

/// <summary>
/// Sign-in with Microsoft: starting it (sign-in, linking an account, "Confirm it's you", the administrator's test
/// sign-in), the callback Microsoft redirects to, and the page that finishes it.
/// </summary>
public static class MicrosoftSignInEndpoints
{
    /// <summary>
    /// Binds a started sign-in to this browser. SameSite=Lax, because the callback is a top-level navigation from Microsoft
    /// and must carry it; it holds a random value only, and the request keeps its hash.
    /// </summary>
    public const string BindingCookie = "__Host-vaulty-ms";

    public static void MapMicrosoftSignInEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/account/microsoft");
        group.MapPost("/start", StartAsync).AllowAnonymous();
        group.MapPost("/link", LinkAsync).RequireAuthorization(VaultyPolicies.SignedIn);
        group.MapPost("/stepup", StepUpAsync).RequireAuthorization();
        group.MapGet("/check", CheckAsync).RequireAuthorization(VaultyPolicies.Permission(Permissions.SignInManage));
        // Anonymous on purpose: Microsoft's redirect carries no SameSite=Strict session cookie. The one-time state and the
        // binding cookie identify the sign-in; the page that finishes it is opened by this page itself (same site).
        group.MapGet("/callback", CallbackAsync).AllowAnonymous();
        group.MapGet("/finish", FinishAsync).AllowAnonymous();
        app.MapGet("/settings/sign-in/certificate.cer", async (HttpContext context, MicrosoftSignInService signIn) =>
            VaultyWebSetup.OrganizationId(context.User) is { } org && await signIn.PublicCertificateAsync(org) is { } certificate
                ? Results.File(certificate, "application/pkix-cert", "vaulty-sign-in.cer")
                : Results.NotFound())
            .RequireAuthorization(VaultyPolicies.Permission(Permissions.SignInManage));
    }

    private static Uri Redirect(HttpContext context, VaultyHostOptions host) =>
        MicrosoftSignInSettings.RedirectUri(host.PublicHost, new Uri($"{context.Request.Scheme}://{context.Request.Host}/"));

    private static async Task<IResult> BeginAsync(HttpContext context, MicrosoftLogins logins, VaultyHostOptions host, MicrosoftLoginPurpose purpose,
        string returnPath, string failurePath)
    {
        var binding = MicrosoftLogins.NewBindingValue();
        try
        {
            var url = await logins.BeginAsync(purpose, VaultyWebSetup.OrganizationId(context.User), VaultyWebSetup.UserId(context.User), Redirect(context, host),
                returnPath, binding, context.RequestAborted);
            context.Response.Cookies.Append(BindingCookie, binding, new CookieOptions
            {
                HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/", MaxAge = MicrosoftLogins.Validity,
            });
            return Results.Redirect(url.ToString());
        }
        catch (SignInSetupException ex)
        {
            var messages = context.RequestServices.GetRequiredService<SignInMessages>();
            return Results.Redirect(With(failurePath, "detail", messages.Protect(ex.Message)));
        }
    }

    private static Task<IResult> StartAsync(HttpContext context, [FromForm] string? returnUrl, MicrosoftLogins logins, VaultyHostOptions host) =>
        BeginAsync(context, logins, host, MicrosoftLoginPurpose.SignIn, AccountEndpoints.Safe(returnUrl), "/account/login?error=microsoft");

    private static Task<IResult> LinkAsync(HttpContext context, MicrosoftLogins logins, VaultyHostOptions host) =>
        BeginAsync(context, logins, host, MicrosoftLoginPurpose.Link, "/account/microsoft", "/account/microsoft?error=1");

    private static Task<IResult> StepUpAsync(HttpContext context, [FromForm] string? returnUrl, MicrosoftLogins logins, VaultyHostOptions host) =>
        BeginAsync(context, logins, host, MicrosoftLoginPurpose.StepUp, AccountEndpoints.Safe(returnUrl),
            $"/account/confirm?returnUrl={Uri.EscapeDataString(AccountEndpoints.Safe(returnUrl))}&error=microsoft");

    private static Task<IResult> CheckAsync(HttpContext context, MicrosoftLogins logins, VaultyHostOptions host, TimeProvider clock)
    {
        // The test sign-in changes the settings, so it needs a recent "Confirm it's you" like every other change there.
        if (!VaultyWebSetup.HasFreshStepUp(context.User, clock))
        {
            return Task.FromResult(Results.Redirect($"/account/confirm?returnUrl={Uri.EscapeDataString("/account/microsoft/check")}"));
        }
        return BeginAsync(context, logins, host, MicrosoftLoginPurpose.Check, "/settings/sign-in", "/settings/sign-in?error=1");
    }

    private static async Task<IResult> CallbackAsync(HttpContext context, MicrosoftLogins logins, ILoggerFactory loggers)
    {
        var query = context.Request.Query;
        var ticket = await logins.CompleteAsync(query["state"], query["code"], query["error"], query["error_description"], context.Request.Cookies[BindingCookie],
            context.RequestAborted);
        if (ticket is null)
        {
            loggers.CreateLogger("Vaulty.SignIn").LogWarning("Microsoft sign-in callback with an unknown, used or foreign state");
            return Continue("/account/login?error=expired");
        }
        return Continue($"/account/microsoft/finish?ticket={Uri.EscapeDataString(ticket)}");
    }

    private static async Task<IResult> FinishAsync(HttpContext context, [FromQuery] string? ticket, MicrosoftLogins logins, MicrosoftSignInService signIn,
        VaultySignInManager signInManager, UserManager<User> users, AccountAudit audit, SignInMessages messages, CurrentAccess current, TimeProvider clock)
    {
        var result = logins.Redeem(ticket, context.Request.Cookies[BindingCookie]);
        context.Response.Cookies.Delete(BindingCookie, new CookieOptions { Secure = true, Path = "/", SameSite = SameSiteMode.Lax });
        if (result is null) return Results.Redirect("/account/login?error=expired");
        return result.Purpose switch
        {
            MicrosoftLoginPurpose.SignIn => await SignInAsync(result, signIn, signInManager, users, audit, messages),
            MicrosoftLoginPurpose.Link => await FinishLinkAsync(context, result, signIn, signInManager, messages),
            MicrosoftLoginPurpose.StepUp => await FinishStepUpAsync(context, result, signIn, signInManager, users, audit, messages, clock),
            _ => await FinishCheckAsync(context, result, signIn, current),
        };
    }

    private static async Task<IResult> SignInAsync(MicrosoftLoginResult result, MicrosoftSignInService signIn, VaultySignInManager signInManager,
        UserManager<User> users, AccountAudit audit, SignInMessages messages)
    {
        IResult Refuse(string message) => Results.Redirect($"/account/login?error=microsoft&detail={Uri.EscapeDataString(messages.Protect(message))}");
        if (result.Account is not { } account) return Refuse(result.Error ?? "The sign-in with Microsoft did not complete. Start again.");
        var found = await signIn.FindLinkedUserAsync(account.TenantId, account.ObjectId);
        if (found is not { } linked)
        {
            await audit.WriteOrganizationAsync(result.OrganizationId, "login.failed",
                new { method = "microsoft", reason = "not_linked", entra_object_id = account.ObjectId, account = account.Account });
            return Refuse($"{account.Account ?? "This Microsoft account"} is not linked to a Vaulty user. Ask an administrator of Vaulty to add you.");
        }
        var user = await users.FindByIdAsync(linked.UserId.ToString());
        if (user is null) return Refuse("This Vaulty user is disabled.");
        var settings = await signIn.GetAsync(user.OrganizationId);
        var mfaSource = account.MfaProven ? "entra" : settings.MicrosoftHandlesSecondFactor ? "delegated" : null;
        var outcome = await signInManager.MicrosoftSignInAsync(user, mfaSource);
        var details = new { method = "microsoft", mfa = mfaSource ?? "vaulty", amr = account.Methods, acr = account.AuthenticationClass };
        if (outcome.RequiresTwoFactor)
        {
            await audit.WriteAsync(user, "login.microsoft_verified", details);
            return Results.Redirect($"/account/login/second-factor?returnUrl={Uri.EscapeDataString(result.ReturnPath)}");
        }
        if (!outcome.Succeeded)
        {
            await audit.WriteAsync(user, outcome.IsLockedOut ? "login.locked_out" : "login.failed", new { method = "microsoft" });
            return Refuse(outcome.IsLockedOut ? "Too many failed attempts. Try again in 15 minutes." : "This Vaulty user cannot sign in.");
        }
        await signIn.RefreshAccountNameAsync(user.OrganizationId, user.Id, account.Account);
        await audit.WriteAsync(user, "login.succeeded", details);
        // Without a second factor from Microsoft or of its own, the user can only add one.
        return Results.Redirect(mfaSource is null && !user.TwoFactorEnabled ? "/account/mfa-setup" : result.ReturnPath);
    }

    private static async Task<IResult> FinishLinkAsync(HttpContext context, MicrosoftLoginResult result, MicrosoftSignInService signIn,
        VaultySignInManager signInManager, SignInMessages messages)
    {
        IResult Refuse(string message) => Results.Redirect($"/account/microsoft?detail={Uri.EscapeDataString(messages.Protect(message))}");
        if (VaultyWebSetup.UserId(context.User) is not { } userId || userId != result.UserId) return Refuse("The sign-in belongs to another Vaulty user. Start again.");
        if (result.Account is not { } account) return Refuse(result.Error ?? "The sign-in with Microsoft did not complete. Start again.");
        try
        {
            await signIn.LinkAsync(result.OrganizationId, $"user:{userId}", userId, account.ObjectId, account.Account);
        }
        catch (SignInSetupException ex)
        {
            return Refuse(ex.Message);
        }
        // From now on this account signs in with Microsoft only.
        await signInManager.SignOutAsync();
        return Results.Redirect("/account/login?linked=1");
    }

    private static async Task<IResult> FinishStepUpAsync(HttpContext context, MicrosoftLoginResult result, MicrosoftSignInService signIn,
        VaultySignInManager signInManager, UserManager<User> users, AccountAudit audit, SignInMessages messages, TimeProvider clock)
    {
        var back = $"/account/confirm?returnUrl={Uri.EscapeDataString(result.ReturnPath)}";
        IResult Refuse(string message) => Results.Redirect($"{back}&error=microsoft&detail={Uri.EscapeDataString(messages.Protect(message))}");
        var user = await users.GetUserAsync(context.User);
        if (user is null || user.Id != result.UserId) return Refuse("The sign-in belongs to another Vaulty user. Start again.");
        if (result.Account is not { } account)
        {
            await audit.WriteAsync(user, "stepup.failed", new { method = "microsoft" });
            return Refuse(result.Error ?? "The sign-in with Microsoft did not complete. Start again.");
        }
        var link = await signIn.LinkOfAsync(user.OrganizationId, user.Id);
        if (link is null || link.TenantId != account.TenantId || link.ObjectId != account.ObjectId)
        {
            await audit.WriteAsync(user, "stepup.failed", new { method = "microsoft", reason = "other_account" });
            return Refuse("You signed in with another Microsoft account than the one linked to your Vaulty user.");
        }
        await signInManager.SignInWithClaimsAsync(user, isPersistent: false,
            [new Claim(VaultyClaims.StepUp, clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture))]);
        await audit.WriteAsync(user, "stepup.confirmed", new { method = "microsoft", amr = account.Methods });
        return Results.Redirect(result.ReturnPath);
    }

    private static async Task<IResult> FinishCheckAsync(HttpContext context, MicrosoftLoginResult result, MicrosoftSignInService signIn, CurrentAccess current)
    {
        if (VaultyWebSetup.UserId(context.User) is not { } userId || userId != result.UserId ||
            !(await current.GetAsync(context.User)).Allows(Permissions.SignInManage))
        {
            return Results.Redirect("/settings/sign-in?error=1");
        }
        await signIn.RecordSignInCheckAsync(result.OrganizationId, $"user:{userId}", MicrosoftSignInService.SignInChecksFrom(result.Account, result.Error));
        return Results.Redirect("/settings/sign-in?checked=1");
    }

    private static string With(string path, string name, string value) =>
        $"{path}{(path.Contains('?', StringComparison.Ordinal) ? "&" : "?")}{name}={Uri.EscapeDataString(value)}";

    /// <summary>A same-site navigation to the next page (a redirect would keep the cross-site origin and drop the cookie).</summary>
    private static IResult Continue(string path)
    {
        if (!path.StartsWith('/') || path.StartsWith("//", StringComparison.Ordinal)) path = "/";
        var encoded = WebUtility.HtmlEncode(path);
        var html = $"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url={encoded}"><title>Vaulty</title></head>
            <body style="font-family: system-ui, sans-serif; padding: 2rem">
            <p>Signed in with Microsoft. <a href="{encoded}">Continue in Vaulty</a>.</p>
            </body></html>
            """;
        return Results.Content(html, "text/html; charset=utf-8");
    }
}
