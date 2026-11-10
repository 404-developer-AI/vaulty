using Microsoft.AspNetCore.Mvc;
using Vaulty.Core.Security;
using Vaulty.Infrastructure.Restore;
using Vaulty.Infrastructure.Web;

namespace Vaulty.Web.Browse;

/// <summary>
/// The one-time download of an export: only the user who asked for it, with the link's token, after a recent
/// "Confirm it's you", once, within 24 hours. The zip is streamed from the export bucket and removed afterwards.
/// </summary>
public static class ExportEndpoints
{
    public static void MapExportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/exports/{exportId:guid}/download", async (Guid exportId, [FromQuery(Name = "t")] string? token, HttpContext context,
                [FromServices] RestoreService restores, [FromServices] CurrentAccess current, [FromServices] IExportStorage storage,
                [FromServices] TimeProvider clock, [FromServices] ILoggerFactory logs) =>
            {
                var access = await current.GetAsync(context.User);
                var fresh = VaultyWebSetup.HasFreshStepUp(context.User, clock);
                if (!fresh && token is not null)
                {
                    var back = $"/exports/{exportId}/download?t={Uri.EscapeDataString(token)}";
                    return Results.Redirect($"/account/confirm?returnUrl={Uri.EscapeDataString(back)}");
                }
                var claimed = token is null ? null : await restores.ClaimDownloadAsync(access, fresh, exportId, token, context.RequestAborted);
                if (claimed is not { } export)
                {
                    return Results.Problem("This download link is not valid: it was used already, has expired or belongs to someone else.",
                        statusCode: StatusCodes.Status410Gone);
                }
                var store = await storage.StoreAsync(context.RequestAborted);
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers.ContentDisposition = $"attachment; filename=\"vaulty-export-{export.RestoreId:N}.zip\"";
                context.Response.ContentType = "application/zip";
                context.Response.ContentLength = export.Size;
                await using (var zip = await store.GetAsync(export.ObjectKey, null, context.RequestAborted))
                {
                    await zip.CopyToAsync(context.Response.Body, context.RequestAborted);
                }
                try
                {
                    await store.DeleteAsync(export.ObjectKey, CancellationToken.None);
                }
                catch (Core.Abstractions.ObjectStoreException ex)
                {
                    // The bucket's one-day lifecycle removes it anyway.
                    logs.CreateLogger("Vaulty.Exports").LogWarning(ex, "Export {ExportId} could not be removed after download", exportId);
                }
                return Results.Empty;
            })
            .RequireAuthorization("perm:" + Permissions.ExportCreate);
    }
}
