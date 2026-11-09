using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Formatting.Compact;
using Temporalio.Client;
using Temporalio.Extensions.Hosting;
using Temporalio.Extensions.OpenTelemetry;
using Vaulty.Core;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Logging;
using Vaulty.Infrastructure.Web;
using Vaulty.Workflows.Tenants;
using Vaulty.Workflows.Backup;
using Vaulty.Infrastructure.Backup;
using Vaulty.Workflows;
using Vaulty.Workflows.Jobs;
using Vaulty.Workflows.Synthetic;

namespace Vaulty.Workers;

/// <summary>Settings under Vaulty:Workers, Vaulty:Temporal and Vaulty:Database.</summary>
public sealed class WorkerSettings
{
    public string TemporalAddress { get; set; } = "127.0.0.1:7233";
    public string TemporalNamespace { get; set; } = "vaulty";
    /// <summary>Peer authentication over the local socket: no password in any configuration.</summary>
    public string DatabaseConnectionString { get; set; } = "Host=/var/run/postgresql;Database=vaulty;Username=vaulty_worker";
    public IReadOnlyList<string> Queues { get; set; } = TaskQueues.All;
    /// <summary>Registers the synthetic test workflows. Never set in production.</summary>
    public bool Synthetic { get; set; }
    public int MaxConcurrentActivities { get; set; } = 50;
    public int MaxConcurrentWorkflowTasks { get; set; } = 100;
}

public static class WorkerHost
{
    public static IHost Build(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddSystemd();
        var settings = new WorkerSettings
        {
            TemporalAddress = builder.Configuration["Vaulty:Temporal:Address"] ?? "127.0.0.1:7233",
            TemporalNamespace = builder.Configuration["Vaulty:Temporal:Namespace"] ?? "vaulty",
            DatabaseConnectionString = builder.Configuration["Vaulty:Database:ConnectionString"]
                                       ?? "Host=/var/run/postgresql;Database=vaulty;Username=vaulty_worker",
            Synthetic = builder.Configuration.GetValue("Vaulty:Workers:Synthetic", false),
            Queues = builder.Configuration["Vaulty:Workers:Queues"]?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     ?? TaskQueues.All,
        };

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Destructure.With<SecretDestructuringPolicy>()
            .Enrich.FromLogContext()
            .WriteTo.Console(new CompactJsonFormatter())
            .CreateLogger();
        builder.Services.AddSerilog();

        builder.Configuration["Vaulty:Database:ConnectionString"] = settings.DatabaseConnectionString;
        builder.Services.AddVaultyData(builder.Configuration, builder.Environment, "vaulty_worker");
        builder.Services.AddSingleton(settings);

        builder.Services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService("vaulty-worker", serviceVersion: ProductInfo.Version))
            .WithTracing(tracing =>
            {
                tracing.AddSource(TracingInterceptor.ClientSource.Name, TracingInterceptor.WorkflowsSource.Name,
                    TracingInterceptor.ActivitiesSource.Name);
                if (!string.IsNullOrEmpty(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"])) tracing.AddOtlpExporter();
            });

        builder.Services.AddTemporalClient(options =>
        {
            options.TargetHost = settings.TemporalAddress;
            options.Namespace = settings.TemporalNamespace;
            options.Interceptors = [new TracingInterceptor()];
        });

        foreach (var queue in settings.Queues)
        {
            var worker = builder.Services.AddHostedTemporalWorker(queue)
                .ConfigureOptions(o =>
                {
                    o.Interceptors = [new JobMirrorInterceptor()];
                    o.MaxConcurrentActivities = settings.MaxConcurrentActivities;
                    o.MaxConcurrentWorkflowTasks = settings.MaxConcurrentWorkflowTasks;
                    // A killed worker's sticky workflow tasks move to another worker quickly.
                    o.StickyQueueScheduleToStartTimeout = TimeSpan.FromSeconds(2);
                })
                .AddScopedActivities<JobActivities>();
            if (queue == TaskQueues.Backup)
            {
                worker.AddScopedActivities<MailboxActivities>()
                    .AddWorkflow<MailboxBackupWorkflow>()
                    .AddWorkflow<FolderBackupWorkflow>();
                worker.AddScopedActivities<DriveActivities>()
                    .AddWorkflow<DriveBackupWorkflow>()
                    .AddWorkflow<DriveSyncWorkflow>();
                worker.AddScopedActivities<TenantActivities>()
                    .AddWorkflow<DiscoveryWorkflow>()
                    .AddWorkflow<TenantHealthWorkflow>();
            }
            if (settings.Synthetic && queue == TaskQueues.Backup)
            {
                worker.AddScopedActivities<SyntheticActivities>()
                    .AddWorkflow<SyntheticObjectBackupWorkflow>()
                    .AddWorkflow<SyntheticFolderSyncWorkflow>()
                    .AddWorkflow<SyntheticFanOutWorkflow>()
                    .AddWorkflow<SyntheticNoopWorkflow>()
                    .AddWorkflow<SyntheticHeartbeatProbeWorkflow>()
                    .AddWorkflow<SyntheticThrottleProbeWorkflow>();
            }
        }

        builder.Services.AddSingleton<BackupStore>();
        builder.Services.AddSingleton<IBackupStorage, S3BackupStorage>();
        builder.Services.AddSingleton<TenantKeyProvider>();
        builder.Services.AddSingleton<BackupStarter>();
        if (settings.Queues.Contains(TaskQueues.Backup))
        {
            builder.Services.AddHostedService<RecurringWorkflows>();
            if (!settings.Synthetic) builder.Services.AddHostedService<BackupScheduler>();
        }
        return builder.Build();
    }
}

/// <summary>Starts the recurring (cron) workflows once; a running instance is left alone.</summary>
public sealed class RecurringWorkflows(ITemporalClient client, ILogger<RecurringWorkflows> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await client.StartWorkflowAsync((TenantHealthWorkflow w) => w.RunAsync(),
                new WorkflowOptions(TenantHealthWorkflow.Id, TaskQueues.Backup) { CronSchedule = TenantHealthWorkflow.Cron }).ConfigureAwait(false);
        }
        catch (Temporalio.Exceptions.WorkflowAlreadyStartedException)
        {
            logger.LogDebug("The tenant health check is already scheduled");
        }
    }
}
