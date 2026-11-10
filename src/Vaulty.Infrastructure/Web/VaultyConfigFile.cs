using Microsoft.Extensions.Configuration;

namespace Vaulty.Infrastructure.Web;

/// <summary>
/// The host configuration written by the installer: <c>$VAULTY_CONFIG_DIR/vaulty.json</c> (never contains a secret). Its
/// "Vaulty" section has the same keys as the configuration of every service (PublicHost, HostId, Workers, ...).
/// </summary>
public static class VaultyConfigFile
{
    public const string FileName = "vaulty.json";
    public const string DirectoryVariable = "VAULTY_CONFIG_DIR";

    public static IConfigurationBuilder AddVaultyConfigFile(this IConfigurationBuilder configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var directory = Environment.GetEnvironmentVariable(DirectoryVariable);
        if (string.IsNullOrEmpty(directory)) return configuration;
        return configuration.AddJsonFile(Path.Combine(directory, FileName), optional: true, reloadOnChange: false);
    }
}
