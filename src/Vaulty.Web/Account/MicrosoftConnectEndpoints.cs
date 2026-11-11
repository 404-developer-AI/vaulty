using System.Net;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Tenants;

namespace Vaulty.Web.Account;

/// <summary>
/// Where Microsoft sends the administrator back after signing in to connect or repair a tenant, and the download of the
/// setup app's public certificate.
/// </summary>
public static class MicrosoftConnectEndpoints
{
    public static void MapMicrosoftConnectEndpoints(this IEndpointRouteBuilder app)
    {
        // Anonymous on purpose: the session cookie is SameSite=Strict, so a navigation that comes from Microsoft carries
        // none. The state value identifies the Vaulty user and works once; the page the browser continues on is opened by
        // this page itself, so the cookie is sent there, and that page shows the run to its own user only.
        app.MapGet(SetupAppService.CallbackPath, async (HttpContext context, BrowserConnection connection) =>
        {
            var query = context.Request.Query;
            var next = await connection.CompleteSignInAsync(query["state"], query["code"], query["error"], query["error_description"],
                context.RequestAborted).ConfigureAwait(false);
            return Continue(next);
        }).AllowAnonymous();

        app.MapGet("/settings/microsoft/certificate.cer", async (SetupAppService setup, CancellationToken cancellationToken) =>
            await setup.PublicCertificateAsync(cancellationToken).ConfigureAwait(false) is { } certificate
                ? Results.File(certificate, "application/pkix-cert", "vaulty-setup.cer")
                : Results.NotFound())
            .RequireAuthorization("perm:" + Permissions.SettingsManage);
    }

    /// <summary>A same-site navigation to the next page (a redirect would keep the cross-site origin and drop the cookie).</summary>
    private static IResult Continue(string path)
    {
        if (!path.StartsWith('/') || path.StartsWith("//", StringComparison.Ordinal)) path = "/";
        var encoded = WebUtility.HtmlEncode(path);
        var html = $"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url={encoded}"><title>Vaulty</title></head>
            <body style="font-family: system-ui, sans-serif; padding: 2rem">
            <p>Signed in. <a href="{encoded}">Continue in Vaulty</a>.</p>
            </body></html>
            """;
        return Results.Content(html, "text/html; charset=utf-8");
    }
}
