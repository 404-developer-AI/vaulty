using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Temporalio.Client;

namespace Vaulty.Integration.Tests.Temporal;

/// <summary>A test that needs the Temporal CLI and PostgreSQL; skipped when either is missing (CI has both).</summary>
public sealed class TemporalFactAttribute : FactAttribute
{
    public TemporalFactAttribute()
    {
        if (string.IsNullOrEmpty(Database.PostgresDatabase.AdminConnectionString)) Skip = "VAULTY_TEST_PG is not set.";
        else if (TemporalDevServer.FindCli() is null) Skip = "The Temporal CLI (temporal) is not installed.";
    }
}

/// <summary>A Temporal CLI dev server on free ports with an in-memory database, one per test class.</summary>
public sealed class TemporalDevServer : IAsyncLifetime
{
    public const string Namespace = "vaulty";
    private Process? _process;

    public int Port { get; } = FreePort();
    public string Address => $"127.0.0.1:{Port}";
    public TemporalClient Client { get; private set; } = null!;

    public static string? FindCli()
    {
        var configured = Environment.GetEnvironmentVariable("VAULTY_TEMPORAL_CLI");
        if (!string.IsNullOrEmpty(configured) && File.Exists(configured)) return configured;
        var name = OperatingSystem.IsWindows() ? "temporal.exe" : "temporal";
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            var candidate = Path.Combine(dir, name);
            if (File.Exists(candidate)) return candidate;
        }
        if (OperatingSystem.IsWindows())
        {
            var packages = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WinGet", "Packages");
            if (Directory.Exists(packages))
            {
                return Directory.EnumerateDirectories(packages, "Temporal.TemporalCLI*")
                    .Select(d => Path.Combine(d, name)).FirstOrDefault(File.Exists);
            }
        }
        return null;
    }

    public async Task InitializeAsync()
    {
        var cli = FindCli();
        if (cli is null || string.IsNullOrEmpty(Database.PostgresDatabase.AdminConnectionString)) return;
        var start = new ProcessStartInfo(cli)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var arg in new[]
                 {
                     "server", "start-dev", "--headless", "--ip", "127.0.0.1", "--port", Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                     "--ui-port", FreePort().ToString(System.Globalization.CultureInfo.InvariantCulture), "--namespace", Namespace,
                     "--log-level", "error",
                     // Enough concurrent children for the fan-out measurement.
                     "--dynamic-config-value", "limit.numPendingChildExecutions.error=10000",
                 })
        {
            start.ArgumentList.Add(arg);
        }
        _process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the Temporal dev server.");
        _process.OutputDataReceived += (_, _) => { };
        _process.ErrorDataReceived += (_, _) => { };
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (true)
        {
            try
            {
                Client = await TemporalClient.ConnectAsync(new TemporalClientConnectOptions(Address) { Namespace = Namespace });
                await Client.WorkflowService.GetSystemInfoAsync(new());
                await foreach (var _ in Client.ListWorkflowsAsync("")) break;
                return;
            }
            catch (Exception) when (DateTime.UtcNow < deadline)
            {
                await Task.Delay(500);
            }
        }
    }

    public Task DisposeAsync()
    {
        if (_process is { HasExited: false })
        {
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(10_000);
        }
        _process?.Dispose();
        return Task.CompletedTask;
    }

    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
