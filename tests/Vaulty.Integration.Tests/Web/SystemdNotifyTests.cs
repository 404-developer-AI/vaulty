using System.Diagnostics;
using System.Security.Cryptography;

namespace Vaulty.Integration.Tests.Web;

/// <summary>A test that needs Linux with systemd and passwordless sudo (the CI runner); skipped elsewhere.</summary>
public sealed class SystemdFactAttribute : FactAttribute
{
    public SystemdFactAttribute()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists("/usr/bin/systemd-run")) Skip = "Needs Linux with systemd.";
        else if (SystemdNotifyTests.Run("sudo", "-n", "true").ExitCode != 0) Skip = "Needs passwordless sudo.";
    }
}

/// <summary>
/// The services run as Type=notify units. systemd only marks such a unit active after the process sends READY=1, so a
/// transient Type=notify unit that becomes active proves the notification works.
/// </summary>
[Collection("Measurements")]
public sealed class SystemdNotifyTests
{
    [SystemdFact]
    public void The_api_and_web_hosts_report_ready_to_systemd()
    {
        var dotnet = Run("which", "dotnet").Output.Trim();
        foreach (var assembly in new[] { typeof(Vaulty.Api.ApiMarker).Assembly, typeof(Vaulty.Web.WebMarker).Assembly })
        {
            // Known to stall now and then on a loaded CI runner before the host logs anything; one more attempt, then fail.
            if (!StartsAsNotifyUnit(dotnet, assembly.Location, out _)) Assert.True(StartsAsNotifyUnit(dotnet, assembly.Location, out var detail), detail);
        }
    }

    private static bool StartsAsNotifyUnit(string dotnet, string assemblyPath, out string detail)
    {
        {
            var unit = $"vaulty-notify-test-{Guid.NewGuid():N}";
            var start = Run("sudo", "systemd-run", $"--unit={unit}", "--collect", "-p", "Type=notify", "-p", "TimeoutStartSec=120",
                "--setenv=DOTNET_ENVIRONMENT=Development", "--setenv=DOTNET_CLI_HOME=/tmp", "--setenv=ASPNETCORE_URLS=http://127.0.0.1:0",
                $"--setenv=VAULTY_DEV_MASTER_KEY={Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}",
                "--setenv=Vaulty__Database__ConnectionString=Host=/nonexistent-socket-directory;Database=none;Timeout=2",
                dotnet, assemblyPath);
            try
            {
                var journal = Run("sudo", "journalctl", "-u", unit, "-n", "60", "--no-pager").Output;
                var active = Run("systemctl", "is-active", unit).Output.Trim();
                detail = $"systemd-run exit {start.ExitCode}, unit {active}: {start.Output}{Environment.NewLine}{journal}";
                return start.ExitCode == 0 && active == "active";
            }
            finally
            {
                Run("sudo", "systemctl", "stop", unit);
            }
        }
    }

    internal static (int ExitCode, string Output) Run(string file, params string[] args)
    {
        var info = new ProcessStartInfo(file) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) info.ArgumentList.Add(a);
        using var process = Process.Start(info)!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit(300_000);
        return (process.ExitCode, output);
    }
}
