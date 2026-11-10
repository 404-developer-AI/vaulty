namespace Vaulty.Cli;

/// <summary>Where everything lives on a Vaulty host.</summary>
public static class Paths
{
    public const string Root = "/opt/vaulty";
    public const string Releases = "/opt/vaulty/releases";
    public const string Current = "/opt/vaulty/current";
    public const string Previous = "/opt/vaulty/previous";
    public const string Etc = "/etc/vaulty";
    public const string Config = "/etc/vaulty/vaulty.json";
    public const string Credentials = "/etc/vaulty/credentials";
    public const string Lock = "/etc/vaulty/install.lock";
    public const string Lib = "/var/lib/vaulty";
    public const string State = "/var/lib/vaulty/state";
    public const string InstallState = "/var/lib/vaulty/state/install.json";
    public const string PendingReport = "/var/lib/vaulty/state/pending-report.cred";
    public const string Staging = "/var/lib/vaulty/staging";
    public const string Data = "/srv/vaulty-data";
    public const string PgData = "/srv/vaulty-data/postgresql/17/main";
    public const string PgConf = "/etc/postgresql/17/main";
    public const string Units = "/etc/systemd/system";

    /// <summary>Joins host paths with '/', whatever platform the CLI was built or tested on.</summary>
    public static string Join(params string[] parts) =>
        string.Join('/', parts.Select((p, i) => i == 0 ? p.TrimEnd('/') : p.Trim('/')).Where(p => p.Length > 0 || parts.Length == 1));

    public static string Parent(string path) => path[..path.TrimEnd('/').LastIndexOf('/')];

    public static string Credential(string name) => $"{Credentials}/{name}.cred";

    public static readonly string[] ServiceUsers = ["vaulty-web", "vaulty-api", "vaulty-worker", "vaulty-gc", "vaulty-migrator"];

    public static readonly string[] UnitTemplates =
    [
        "vaulty.target", "vaulty-migrate.service", "vaulty-web.service", "vaulty-api.service", "vaulty-worker@.service", "vaulty-gc.service",
        "vaulty-temporal.service", "vaulty-update-check.service", "vaulty-update-check.timer",
    ];

    /// <summary>The Vaulty services in start order (temporal first, gc last); stop order is the reverse.</summary>
    public static IReadOnlyList<string> Services(int workers) =>
        ["vaulty-temporal.service", "vaulty-api.service", "vaulty-web.service", .. Enumerable.Range(1, workers).Select(i => $"vaulty-worker@{i}.service"), "vaulty-gc.service"];
}
