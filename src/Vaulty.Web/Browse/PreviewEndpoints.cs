using System.Text;
using Microsoft.AspNetCore.Mvc;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Browse;
using Vaulty.Infrastructure.Web;

namespace Vaulty.Web.Browse;

/// <summary>
/// Serves item previews for the iframe in the snapshot browser. Every response carries its own Content Security Policy:
/// no scripts, nothing loaded from elsewhere, and (except for PDF, which the browser's viewer must render) a CSP sandbox.
/// </summary>
public static class PreviewEndpoints
{
    public const string HtmlPolicy =
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox";
    public const string FilePolicy = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'; sandbox";
    public const string PdfPolicy = "default-src 'none'; frame-ancestors 'self'";

    public static void MapPreviewEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/preview/{objectId:guid}/{snapshotId:guid}/{itemId:guid}", async (Guid objectId, Guid snapshotId, Guid itemId,
                HttpContext context, [FromServices] SnapshotBrowser browser, [FromServices] CurrentAccess current) =>
            {
                var access = await current.GetAsync(context.User);
                ItemPreview? preview;
                try
                {
                    preview = await browser.PreviewAsync(access, objectId, snapshotId, itemId, context.RequestAborted);
                }
                catch (AccessException)
                {
                    return Results.NotFound();
                }
                if (preview is null) return Results.NotFound();
                var headers = context.Response.Headers;
                headers["Content-Security-Policy"] = preview.MediaType switch
                {
                    "text/html" => HtmlPolicy,
                    "application/pdf" => PdfPolicy,
                    _ => FilePolicy,
                };
                headers["X-Frame-Options"] = "SAMEORIGIN";
                headers.CacheControl = "no-store";
                headers.ContentDisposition = $"inline; filename=\"{SafeFileName(preview.FileName)}\"";
                var type = preview.MediaType.StartsWith("text/", StringComparison.Ordinal) ? $"{preview.MediaType}; charset=utf-8" : preview.MediaType;
                return Results.Bytes(preview.Content, type);
            })
            .RequireAuthorization("perm:" + Permissions.SnapshotsBrowse);
    }

    /// <summary>ASCII letters, digits and a few safe characters only, so the header can never be broken by a name.</summary>
    public static string SafeFileName(string name)
    {
        var builder = new StringBuilder();
        foreach (var c in name)
        {
            builder.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or ' ' ? c : '_');
            if (builder.Length >= 100) break;
        }
        return builder.Length == 0 ? "item" : builder.ToString();
    }
}
