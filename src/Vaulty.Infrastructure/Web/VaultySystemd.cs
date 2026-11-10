using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Systemd;

namespace Vaulty.Infrastructure.Web;

/// <summary>
/// systemd integration that also works under ProtectProc=invisible. The stock detection reads /proc/1/comm to see whether
/// the parent is systemd; that file is hidden in a hardened unit, so the service would never send READY=1. A unit started
/// by systemd always has NOTIFY_SOCKET (Type=notify), which is what this checks in addition.
/// </summary>
public static class VaultySystemd
{
    public static IServiceCollection AddVaultySystemd(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSystemd();
        if (!SystemdHelpers.IsSystemdService() && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NOTIFY_SOCKET")))
        {
            services.AddSingleton<ISystemdNotifier, SystemdNotifier>();
            services.AddSingleton<IHostLifetime, SystemdLifetime>();
        }
        return services;
    }
}
