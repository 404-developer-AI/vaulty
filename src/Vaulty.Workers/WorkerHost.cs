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
    /// <summary>"worker" (backups and restores) or "gc" (verification and garbage collection, own database role and storage identity).</summary>
    public string Role { get; set; } = "worker";
    public IReadOnlyList<string> Queues { get; set; } = TaskQueues.ForWorkers;
    public bool IsGc => Role == "gc";
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
        var role = builder.Configuration["role"] ?? builder.Configuration["Vaulty:Workers:Role"] ?? "worker";
        if (role is not ("worker" or "gc")) throw new InvalidOperationException($"Unknown worker role '{role}'; use worker or gc.");
        var databaseRole = role == "gc" ? "vaulty_gc" : "vaulty_worker";
        var settings = new WorkerSettings
        {
            Role = role,
            TemporalAddress = builder.Configuration["Vaulty:Temporal:Address"] ?? "127.0.0.1:7233",
            TemporalNamespace = builder.Configuration["Vaulty:Temporal:Namespace"] ?? "vaulty",
            DatabaseConnectionString = builder.Configuration["Vaulty:Database:ConnectionString"]
                                       ?? $"Host=/var/run/postgresql;Database=vaulty;Username={databaseRole}",
            Synthetic = builder.Configuration.GetValue("Vaulty:Workers:Synthetic", false),
            Queues = builder.Configuration["Vaulty:Workers:Queues"]?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     ?? (role == "gc" ? TaskQueues.ForGc : TaskQueues.ForWorkers),
        };
        // The gc queues need the gc role and identity, the others must never run with them.
        if (settings.Queues.Any(q => TaskQueues.ForGc.Contains(q) != settings.IsGc))
        {
            throw new InvalidOperationException("The verify and gc queues run only in the gc role, the backup and restore queues only in the worker role.");
        }

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Destructure.With<SecretDestructuringPolicy>()
            .Enrich.FromLogContext()
            .WriteTo.Console(new CompactJsonFormatter())
            .CreateLogger();
        builder.Services.AddSerilog();

        builder.Configuration["Vaulty:Database:ConnectionString"] = settings.DatabaseConnectionString;
        builder.Services.AddVaultyData(builder.Configuration, builder.Environment, databaseRole);
        builder.Services.AddSingleton(settings);

        builder.Services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService(settings.IsGc ? "vaulty-gc" : "vaulty-worker", serviceVersion: ProductInfo.Version))
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
            if (queue == TaskQueues.Restore)
            {
                worker.AddScopedActivities<Vaulty.Workflows.Restore.RestoreActivities>()
                    .AddWorkflow<Vaulty.Workflows.Restore.RestoreWorkflow>();
            }
            if (queue == TaskQueues.Verify)
            {
                worker.AddScopedActivities<Vaulty.Workflows.Retention.VerificationActivities>()
                    .AddWorkflow<Vaulty.Workflows.Retention.VerificationSweepWorkflow>();
            }
            if (queue == TaskQueues.Gc)
            {
                worker.AddScopedActivities<Vaulty.Workflows.Retention.GcActivities>()
                    .AddWorkflow<Vaulty.Workflows.Retention.GcSweepWorkflow>();
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

        builder.Services.AddSingleton<TenantKeyProvider>();
        if (settings.IsGc)
        {
            builder.Services.AddSingleton<IBackupStorage>(sp => new S3BackupStorage(
                sp.GetRequiredService<Vaulty.Infrastructure.Storage.StorageClientFactory>(), Vaulty.Infrastructure.Storage.StorageRole.Gc));
            builder.Services.AddSingleton(new Vaulty.Infrastructure.Retention.VerificationOptions());
            builder.Services.AddSingleton(new Vaulty.Infrastructure.Retention.GcOptions());
            builder.Services.AddSingleton<Vaulty.Infrastructure.Retention.VerificationService>();
            builder.Services.AddSingleton<Vaulty.Infrastructure.Retention.GarbageCollector>();
            builder.Services.AddSingleton<Vaulty.Infrastructure.Retention.TenantDeletion>();
            builder.Services.AddHostedService<RecurringWorkflows>();
            return builder.Build();
        }
        builder.Services.AddSingleton<BackupStore>();
        builder.Services.AddSingleton<IBackupStorage, S3BackupStorage>();
        builder.Services.AddSingleton<Vaulty.Infrastructure.Restore.RestoreStore>();
        builder.Services.AddSingleton<Vaulty.Infrastructure.Restore.IExportStorage>(sp => new Vaulty.Infrastructure.Restore.S3ExportStorage(
            sp.GetRequiredService<Vaulty.Infrastructure.Storage.StorageClientFactory>(), Vaulty.Infrastructure.Storage.StorageRole.Worker));
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
public sealed class RecurringWorkflows(ITemporalClient client, WorkerSettings settings, ILogger<RecurringWorkflows> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (settings.IsGc)
        {
            await StartAsync("verification sweep", () => client.StartWorkflowAsync((Vaulty.Workflows.Retention.VerificationSweepWorkflow w) => w.RunAsync(),
                new WorkflowOptions(Vaulty.Workflows.Retention.VerificationSweepWorkflow.Id, TaskQueues.Verify)
                {
                    CronSchedule = Vaulty.Workflows.Retention.VerificationSweepWorkflow.Cron,
                })).ConfigureAwait(false);
            await StartAsync("garbage collection", () => client.StartWorkflowAsync((Vaulty.Workflows.Retention.GcSweepWorkflow w) => w.RunAsync(),
                new WorkflowOptions(Vaulty.Workflows.Retention.GcSweepWorkflow.Id, TaskQueues.Gc) { CronSchedule = Vaulty.Workflows.Retention.GcSweepWorkflow.Cron }))
                .ConfigureAwait(false);
            return;
        }
        await StartAsync("tenant health check", () => client.StartWorkflowAsync((TenantHealthWorkflow w) => w.RunAsync(),
            new WorkflowOptions(TenantHealthWorkflow.Id, TaskQueues.Backup) { CronSchedule = TenantHealthWorkflow.Cron })).ConfigureAwait(false);
    }

    private async Task StartAsync(string name, Func<Task> start)
    {
        try
        {
            await start().ConfigureAwait(false);
        }
        catch (Temporalio.Exceptions.WorkflowAlreadyStartedException)
        {
            logger.LogDebug("The {Name} is already scheduled", name);
        }
    }
}
