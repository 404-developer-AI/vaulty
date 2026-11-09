using MudBlazor.Services;
using Serilog;
using Serilog.Formatting.Compact;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Logging;
using Vaulty.Infrastructure.Web;
using Vaulty.Web.Account;
using Vaulty.Web.Components;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSystemd();
builder.Host.UseSerilog((context, configuration) => configuration
    .MinimumLevel.Information()
    .Destructure.With<SecretDestructuringPolicy>()
    .Enrich.FromLogContext()
    .WriteTo.Console(new CompactJsonFormatter()));

var hostOptions = builder.Services.AddVaultyCore(builder.Configuration, builder.Environment);
builder.Services.AddHttpContextAccessor();
builder.Services.AddVaultyIdentity(hostOptions);
builder.Services.AddScoped<SetupTokens>();
builder.Services.AddScoped<OrganizationSetup>();
builder.Services.AddScoped<AccountAudit>();
builder.Services.AddScoped<UserDirectory>();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddMudServices();
builder.Services.AddAntiforgery(o =>
{
    o.Cookie.Name = "__Host-vaulty-af";
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.HeaderName = "X-Vaulty-Antiforgery";
});

var app = builder.Build();

// Development helper: print a setup token for the first administrator (the installer does this on a server).
if (args.Contains("--issue-setup-token"))
{
    using var scope = app.Services.CreateScope();
    var tokens = scope.ServiceProvider.GetRequiredService<SetupTokens>();
    Console.WriteLine($"/setup?token={await tokens.IssueAsync("cli")}");
    return;
}

if (!app.Environment.IsDevelopment()) app.UseExceptionHandler("/error", createScopeForErrors: true);
app.UseVaultySecurityHeaders();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapAccountEndpoints();
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode(o => o.ContentSecurityFrameAncestorsPolicy = null);

await app.RunAsync();

public partial class Program;
