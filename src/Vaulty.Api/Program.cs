using Dapper;
using Npgsql;
using Serilog;
using Serilog.Formatting.Compact;
using Vaulty.Core;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Logging;
using Vaulty.Infrastructure.Web;

// The REST API (/api/v1). Phase 1: health checks, the OpenAPI document and the signed-in user's access; the public API
// with API keys follows later. Shares the session cookie with the web app through the common key ring.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSystemd();
builder.Host.UseSerilog((_, configuration) => configuration
    .MinimumLevel.Information()
    .Destructure.With<SecretDestructuringPolicy>()
    .Enrich.FromLogContext()
    .WriteTo.Console(new CompactJsonFormatter()));

var hostOptions = builder.Services.AddVaultyCore(builder.Configuration, builder.Environment);
builder.Services.AddHttpContextAccessor();
builder.Services.AddVaultyIdentity(hostOptions);
builder.Services.AddOpenApi("v1", o => o.AddDocumentTransformer((document, _, _) =>
{
    document.Info.Title = "Vaulty API";
    document.Info.Version = ProductInfo.Version;
    return Task.CompletedTask;
}));

var app = builder.Build();
app.UseVaultySecurityHeaders();
app.UseAuthentication();
app.UseAuthorization();

var api = app.MapGroup("/api/v1");
api.MapGet("/healthz", () => Results.Ok(new { status = "ok", version = ProductInfo.Version })).AllowAnonymous();
api.MapGet("/healthz/ready", async (NpgsqlDataSource dataSource, CancellationToken cancellationToken) =>
{
    try
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await connection.ExecuteScalarAsync<int>(new CommandDefinition("SELECT 1", cancellationToken: cancellationToken));
        return Results.Ok(new { status = "ready" });
    }
    catch (NpgsqlException)
    {
        return Results.Json(new { status = "database unavailable" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}).AllowAnonymous();
app.MapOpenApi("/api/v1/openapi.json").AllowAnonymous();
api.MapGet("/me", async (HttpContext context, CurrentAccess access) =>
{
    var current = await access.GetAsync(context.User);
    return Results.Ok(new { user = current.UserId, organization = current.OrganizationId, permissions = current.Permissions.Order() });
}).RequireAuthorization();

await app.RunAsync();

public partial class Program;
