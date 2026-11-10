using MudBlazor.Services;
using Serilog;
using Serilog.Formatting.Compact;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Logging;
using Vaulty.Infrastructure.Platform;
using Vaulty.Infrastructure.Storage;
using Vaulty.Infrastructure.Tenants;
using Vaulty.Infrastructure.Web;
using Vaulty.Web.Account;
using Vaulty.Web.Components;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddVaultyConfigFile();
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
builder.Services.AddScoped<StorageSetupAssistant>();
builder.Services.AddSingleton<IMailSender, SmtpMailSender>();
builder.Services.AddScoped<CustomerService>();
builder.Services.AddScoped<TenantService>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Browse.ApiBackupStorage>();
builder.Services.AddSingleton(sp => new Vaulty.Infrastructure.Backup.TenantKeyProvider(sp.GetRequiredService<Npgsql.NpgsqlDataSource>(),
    sp.GetRequiredService<Vaulty.Infrastructure.Secrets.IMasterKeySource>(), sp.GetRequiredService<Vaulty.Infrastructure.Browse.ApiBackupStorage>(),
    sp.GetRequiredService<TimeProvider>()));
builder.Services.AddSingleton<Vaulty.Infrastructure.Browse.IRepositoryReaderFactory>(sp => new Vaulty.Infrastructure.Browse.RepositoryReaderFactory(
    sp.GetRequiredService<Npgsql.NpgsqlDataSource>(), sp.GetRequiredService<Vaulty.Infrastructure.Browse.ApiBackupStorage>(),
    sp.GetRequiredService<Vaulty.Infrastructure.Backup.TenantKeyProvider>()));
builder.Services.AddSingleton<Vaulty.Infrastructure.Browse.SnapshotBrowser>();
builder.Services.AddScoped<Vaulty.Web.DisplayTime>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Restore.RestoreService>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Retention.TenantDeletion>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Retention.LegalHold>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Reporting.DashboardService>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Notifications.AlertService>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Notifications.JobsService>();
builder.Services.AddSingleton(new Vaulty.Infrastructure.Notifications.WebhookOptions());
builder.Services.AddSingleton<Vaulty.Infrastructure.Notifications.WebhookService>();
builder.Services.AddSingleton<Vaulty.Infrastructure.Restore.IExportStorage>(sp => new Vaulty.Infrastructure.Restore.S3ExportStorage(
    sp.GetRequiredService<Vaulty.Infrastructure.Storage.StorageClientFactory>(), Vaulty.Infrastructure.Storage.StorageRole.Api));
var temporal = new Lazy<Task<Temporalio.Client.ITemporalClient>>(async () => await Temporalio.Client.TemporalClient.ConnectAsync(
    new Temporalio.Client.TemporalClientConnectOptions(builder.Configuration["Vaulty:Temporal:Address"] ?? "127.0.0.1:7233")
    {
        Namespace = builder.Configuration["Vaulty:Temporal:Namespace"] ?? "vaulty",
    }));
builder.Services.AddSingleton<Vaulty.Workflows.Tenants.IWorkflowStarter>(sp => new Vaulty.Workflows.Tenants.TemporalWorkflowStarter(
    () => temporal.Value, sp.GetRequiredService<Npgsql.NpgsqlDataSource>()));
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
Vaulty.Web.Browse.PreviewEndpoints.MapPreviewEndpoints(app);
Vaulty.Web.Browse.ExportEndpoints.MapExportEndpoints(app);
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode(o => o.ContentSecurityFrameAncestorsPolicy = null);

await app.RunAsync();

public partial class Program;
