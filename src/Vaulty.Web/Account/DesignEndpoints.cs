using Vaulty.Core.Security;
using Vaulty.Infrastructure.Reporting;
using Vaulty.Infrastructure.Web;

namespace Vaulty.Web.Account;

/// <summary>Downloads of the dashboard designer: a dashboard as a JSON file.</summary>
public static class DesignEndpoints
{
    public static void MapDesignEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/settings/dashboards/{id:guid}/export", async (Guid id, HttpContext context, DashboardDesignService designs) =>
        {
            if (VaultyWebSetup.OrganizationId(context.User) is not { } org) return Results.NotFound();
            try
            {
                var json = await designs.ExportAsync(org, id, context.RequestAborted);
                return Results.File(System.Text.Encoding.UTF8.GetBytes(json), "application/json", "vaulty-dashboard.json");
            }
            catch (DesignException)
            {
                return Results.NotFound();
            }
        }).RequireAuthorization(VaultyPolicies.Permission(Permissions.DashboardsManage));
    }
}
