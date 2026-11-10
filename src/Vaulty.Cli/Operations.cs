using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Vaulty.Cli;

/// <summary>The health check after an install or update (§5.3 step 12).</summary>
public static class Health
{
    public static async Task<IReadOnlyList<string>> CheckAsync(IHostShell shell, int workers, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(shell);
        var until = DateTimeOffset.UtcNow + timeout;
        List<string> failures;
        do
        {
            failures = [];
            foreach (var unit in Paths.Services(workers))
            {
                var active = await shell.RunAsync("systemctl", ["is-active", unit], cancellationToken: ct).ConfigureAwait(false);
                if (active.Output.Trim() != "active") failures.Add($"{unit} is {active.Output.Trim()}");
            }
            foreach (var (name, url) in new[] { ("web", "http://127.0.0.1:5000/healthz"), ("api", "http://127.0.0.1:5001/api/v1/healthz/ready") })
            {
                var answer = await shell.RunAsync("curl", ["-fsS", "--max-time", "5", url], cancellationToken: ct).ConfigureAwait(false);
                if (!answer.Succeeded) failures.Add($"{name} health endpoint does not answer");
            }
            var temporal = await shell.RunAsync("docker", ["exec", "vaulty-temporal", "temporal", "operator", "cluster", "health", "--address", "127.0.0.1:7233"],
                cancellationToken: ct).ConfigureAwait(false);
            if (!temporal.Output.Contains("SERVING", StringComparison.Ordinal)) failures.Add("Temporal is not serving");
            var valkey = await shell.RunAsync("sh", ["-c", "REDISCLI_AUTH=\"$(systemd-creds decrypt --name=valkey /etc/vaulty/credentials/valkey.cred -)\" docker exec -e REDISCLI_AUTH vaulty-valkey valkey-cli ping"],
                cancellationToken: ct).ConfigureAwait(false);
            if (!valkey.Output.Contains("PONG", StringComparison.Ordinal)) failures.Add("Valkey does not answer");
            foreach (var (user, role) in new[] { ("vaulty-web", "vaulty_api"), ("vaulty-worker", "vaulty_worker"), ("vaulty-gc", "vaulty_gc") })
            {
                var select = await shell.RunAsync("runuser", ["-u", user, "--", "psql", "-h", "/var/run/postgresql", "-d", "vaulty", "-U", role, "-tAc", "SELECT 1"],
                    cancellationToken: ct).ConfigureAwait(false);
                if (select.Output.Trim() != "1") failures.Add($"PostgreSQL role {role} cannot connect");
            }
            if (failures.Count == 0 || DateTimeOffset.UtcNow > until) break;
            await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
        }
        while (true);
        return failures;
    }
}

/// <summary>The installation report (deploy/install/report.template.txt); without secrets for vaulty report.</summary>
public static class Reports
{
    public static async Task<string> RenderAsync(InstallContext c, string path, bool includeSecrets, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(c);
        var v = new Dictionary<string, string>(c.Values, StringComparer.Ordinal)
        {
            ["GENERATED_AT"] = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture),
            ["HOSTNAME"] = c.Host.Hostname,
            ["PROFILE"] = c.Answers.Profile,
            ["ENVIRONMENT"] = c.Answers.Environment,
            ["VERSION"] = c.Version,
            ["REPORT_PATH"] = path,
            ["FQDN"] = c.Answers.Fqdn,
            ["RELEASE_DIR"] = c.ReleaseDirectory,
            ["PG_DATA_DIRECTORY"] = Paths.PgData,
            ["DATA_DISK_SUMMARY"] = c.Answers.DataDisk is { } d ? $"{d}{(c.Answers.Luks ? c.Host.Tpm2 ? ", LUKS2, TPM2-bound" : ", LUKS2, passphrase only" : "")}" : "system disk",
            ["TPM_SUMMARY"] = c.Host.Tpm2 ? "present; master key and data disk bound to it" : "not present; master key bound to the host key only (weaker, see vaulty status)",
            ["FIREWALL_SUMMARY"] = $"ufw active: 22 (limit{(c.Answers.SshAllowFrom is { } f ? $", from {f}" : "")}), 80, 443",
            ["UNATTENDED_UPGRADES_SUMMARY"] = "unattended-upgrades for security updates, reboot window 04:00",
            ["SIGNATURE_SUMMARY"] = c.SignatureVerified ? "verified with cosign (release workflow of the public repository, issuer GitHub Actions)"
                : "NOT verified (VAULTY_SKIP_SIGNATURE_CHECK was set; development only)",
        };
        v.TryAdd("PGBACKREST_SUMMARY", "not configured");
        v["HARDENING_SUMMARY"] = await Doctor.HardeningSummaryAsync(c.Shell, c.Workers, ct).ConfigureAwait(false);
        v["SERVICES_TABLE"] = await ServicesTableAsync(c.Shell, c.Workers, ct).ConfigureAwait(false);
        const string Hidden = "(shown once at installation; rotate with vaulty secrets)";
        var s = c.Secrets;
        v["MASTER_KEY_BASE64"] = includeSecrets && s.MasterKey.Length > 0 ? s.MasterKey : Hidden;
        v["MASTER_KEY_WORDS"] = includeSecrets && s.MasterKey.Length > 0 ? KeyWords.Encode(Convert.FromBase64String(s.MasterKey)) : Hidden;
        v["LUKS_RECOVERY_PASSPHRASE"] = includeSecrets ? s.LuksPassphrase ?? "(no encrypted data disk)" : Hidden;
        v["TEMPORAL_DB_PASSWORD"] = includeSecrets ? s.TemporalPassword : Hidden;
        v["VALKEY_PASSWORD"] = includeSecrets ? s.ValkeyPassword : Hidden;
        v["PGBACKREST_CIPHER_PASS"] = includeSecrets ? s.PgBackRestCipher ?? "(pgBackRest not configured)" : Hidden;
        v["SETUP_TOKEN"] = includeSecrets && s.SetupToken is not null ? s.SetupToken : "(used or expired; ask an administrator for an invitation)";
        v["SETUP_TOKEN_EXPIRES"] = s.SetupTokenExpires?.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) ?? "-";
        var template = c.Shell.ReadFile(c.Template("report.template.txt"));
        var report = Templates.Render(template, v, "report");
        return includeSecrets ? report : Regex.Replace(report, @"(?ms)^SECRETS\n.*?(?=^DATABASE)", "SECRETS\n  Not shown again. Rotate with vaulty secrets rotate or vaulty secrets rekey.\n\n");
    }

    public static async Task<string> ServicesTableAsync(IHostShell shell, int workers, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(shell);
        List<(string Unit, string User, string Listen)> rows =
        [
            ("vaulty-web", "vaulty-web", "127.0.0.1:5000"), ("vaulty-api", "vaulty-api", "127.0.0.1:5001"),
            .. Enumerable.Range(1, workers).Select(i => ($"vaulty-worker@{i}", "vaulty-worker", "-")),
            ("vaulty-gc", "vaulty-gc", "-"), ("vaulty-temporal", "(docker)", "127.0.0.1:7233 / 8233"),
            ("postgresql@17-main", "postgres", "unix socket, 127.0.0.1:5432"), ("caddy", "caddy", "0.0.0.0:80, 0.0.0.0:443"),
        ];
        var text = new StringBuilder();
        foreach (var (unit, user, listen) in rows)
        {
            var state = (await shell.RunAsync("systemctl", ["is-active", unit], cancellationToken: ct).ConfigureAwait(false)).Output.Trim();
            text.Append(CultureInfo.InvariantCulture, $"  {unit,-24}{(state.Length == 0 ? "unknown" : state),-12}{user,-18}{listen}\n");
        }
        return text.ToString().TrimEnd('\n');
    }

    /// <summary>The installation context of an installed host, from /etc/vaulty/vaulty.json and the current release.</summary>
    public static async Task<InstallContext> InstalledAsync(IHostShell shell, TextWriter log, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(shell);
        if (!shell.FileExists(Paths.Config)) throw new InstallException("Vaulty is not installed on this host.");
        using var config = JsonDocument.Parse(shell.ReadFile(Paths.Config));
        var install = config.RootElement.GetProperty("Install");
        string? Text(string name) => install.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
        var answers = new InstallAnswers
        {
            Profile = Text("Profile") ?? "all-in-one",
            Environment = config.RootElement.GetProperty("Vaulty").GetProperty("Environment").GetString() ?? "production",
            Fqdn = Text("Fqdn") ?? "",
            AdminEmail = Text("AdminEmail") ?? "",
            DataDisk = Text("DataDisk"),
            Luks = install.TryGetProperty("Luks", out var l) && l.GetBoolean(),
            Workers = install.GetProperty("Workers").GetInt32(),
            AutoUpdate = Text("AutoUpdate") ?? "none",
        };
        var host = await HostProbe.ReadAsync(shell, ct).ConfigureAwait(false);
        var release = shell.ReadLink(Paths.Current) ?? throw new InstallException($"{Paths.Current} is not a link to a release.");
        var context = new InstallContext(shell, answers, host, release, Path.GetFileName(release), log)
        {
            SignatureVerified = install.TryGetProperty("SignatureVerified", out var sv) && sv.GetBoolean(),
        };
        foreach (var (k, value) in Tuning.Values(host, context.Workers)) context.Values[k] = value;
        context.Values["FQDN"] = answers.Fqdn;
        return context;
    }
}

public static class HostProbe
{
    public static async Task<HostFacts> ReadAsync(IHostShell shell, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(shell);
        var os = shell.FileExists("/etc/os-release") ? SimpleYamlOsRelease(shell.ReadFile("/etc/os-release")) : new Dictionary<string, string>();
        var memory = shell.FileExists("/proc/meminfo") ? shell.ReadFile("/proc/meminfo") : "";
        var kb = Regex.Match(memory, @"MemTotal:\s+(\d+)") is { Success: true } m ? long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) : 0;
        var cpus = (await shell.RunAsync("nproc", [], cancellationToken: ct).ConfigureAwait(false)).Output.Trim();
        var arch = (await shell.RunAsync("uname", ["-m"], cancellationToken: ct).ConfigureAwait(false)).Output.Trim();
        var hostname = (await shell.RunAsync("hostname", ["-f"], cancellationToken: ct).ConfigureAwait(false)).Output.Trim();
        var tpm = (await shell.RunAsync("systemd-creds", ["has-tpm2", "--quiet"], cancellationToken: ct).ConfigureAwait(false)).Succeeded;
        return new HostFacts(hostname.Length > 0 ? hostname : Environment.MachineName, int.TryParse(cpus, out var n) ? n : Environment.ProcessorCount, kb / 1024, tpm,
            os.GetValueOrDefault("ID", ""), os.GetValueOrDefault("VERSION_ID", ""), arch);
    }

    private static Dictionary<string, string> SimpleYamlOsRelease(string text) =>
        text.Split('\n').Select(l => l.Split('=', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0].Trim(), p => p[1].Trim().Trim('"'), StringComparer.Ordinal);
}

/// <summary>vaulty doctor: the baseline of §8 and §14, reported as findings.</summary>
public static partial class Doctor
{
    public static async Task<IReadOnlyList<string>> CheckAsync(IHostShell shell, int workers, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(shell);
        var findings = new List<string>();
        foreach (var (file, what) in new[] { (Paths.Config, "the host configuration"), ($"{Paths.Current}/compose/temporal.compose.yml", "the Compose file") })
        {
            if (shell.FileExists(file) && SecretLike().IsMatch(shell.ReadFile(file))) findings.Add($"{what} ({file}) contains something that looks like a secret");
        }
        foreach (var unit in Paths.Services(workers).Where(u => u != "vaulty-temporal.service"))
        {
            var environment = (await shell.RunAsync("systemctl", ["show", "-p", "Environment", unit], cancellationToken: ct).ConfigureAwait(false)).Output;
            if (SecretLike().IsMatch(environment)) findings.Add($"{unit} has a secret in its environment");
        }
        foreach (var (unit, score) in await ScoresAsync(shell, workers, ct).ConfigureAwait(false))
        {
            if (score > 2.0) findings.Add($"{unit}: systemd-analyze security exposure {score.ToString("0.0", CultureInfo.InvariantCulture)} (more than 2.0)");
        }
        var mode = (await shell.RunAsync("stat", ["-c", "%a", Paths.Credentials], cancellationToken: ct).ConfigureAwait(false)).Output.Trim();
        if (mode is not ("700" or "")) findings.Add($"{Paths.Credentials} has mode {mode}, expected 700");
        foreach (var report in (await shell.RunAsync("sh", ["-c", "ls /root/vaulty-install-report-*.txt 2>/dev/null"], cancellationToken: ct).ConfigureAwait(false))
                 .Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var reportMode = (await shell.RunAsync("stat", ["-c", "%a", report], cancellationToken: ct).ConfigureAwait(false)).Output.Trim();
            if (reportMode != "600") findings.Add($"{report} has mode {reportMode}, expected 600");
        }
        var hba = shell.FileExists($"{Paths.PgConf}/pg_hba.conf") ? shell.ReadFile($"{Paths.PgConf}/pg_hba.conf") : "";
        if (Regex.IsMatch(hba, @"(?m)^\s*host\s+\S+\s+\S+\s+(?!127\.0\.0\.1/32|0\.0\.0\.0/0|::/0)\S+\s+(trust|md5|password|scram)")) findings.Add("pg_hba.conf allows connections from beyond loopback");
        if (Regex.IsMatch(hba, @"(?m)^\s*\S+\s+\S+\s+\S+.*\btrust\b")) findings.Add("pg_hba.conf contains trust authentication");
        var ufw = (await shell.RunAsync("ufw", ["status"], cancellationToken: ct).ConfigureAwait(false)).Output;
        if (!ufw.Contains("Status: active", StringComparison.Ordinal)) findings.Add("the firewall (ufw) is not active");
        return findings;
    }

    public static async Task<IReadOnlyList<(string Unit, double Score)>> ScoresAsync(IHostShell shell, int workers, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(shell);
        var result = new List<(string, double)>();
        foreach (var unit in Paths.Services(workers).Where(u => u != "vaulty-temporal.service"))
        {
            var output = (await shell.RunAsync("systemd-analyze", ["security", "--no-pager", unit], cancellationToken: ct).ConfigureAwait(false)).Output;
            if (Exposure().Match(output) is { Success: true } m) result.Add((unit, double.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)));
        }
        return result;
    }

    public static async Task<string> HardeningSummaryAsync(IHostShell shell, int workers, CancellationToken ct)
    {
        var scores = await ScoresAsync(shell, workers, ct).ConfigureAwait(false);
        if (scores.Count == 0) return "not measured";
        var worst = scores.MaxBy(s => s.Score);
        return worst.Score <= 2.0
            ? $"systemd-analyze security: every Vaulty unit 2.0 or better (worst {worst.Score.ToString("0.0", CultureInfo.InvariantCulture)})"
            : $"systemd-analyze security: {worst.Unit} at {worst.Score.ToString("0.0", CultureInfo.InvariantCulture)} (above 2.0; see vaulty doctor)";
    }

    [GeneratedRegex(@"(?i)(password|passwd|secret|requirepass|api[_-]?key|access[_-]?key|private[_-]?key)\s*[""']?\s*[:=]\s*[""']?[^\s""',}{]{6,}|-----BEGIN [A-Z ]*PRIVATE KEY")]
    private static partial Regex SecretLike();

    [GeneratedRegex(@"Overall exposure level for \S+:\s*([0-9]+\.[0-9])")]
    private static partial Regex Exposure();
}
