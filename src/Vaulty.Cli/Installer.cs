using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Vaulty.Cli;

/// <summary>The secrets the report shows once. Kept between a failed run and its --resume only as an encrypted systemd credential.</summary>
public sealed class ReportSecrets
{
    public string MasterKey { get; set; } = "";
    public string? LuksPassphrase { get; set; }
    public string TemporalPassword { get; set; } = "";
    public string ValkeyPassword { get; set; } = "";
    public string? PgBackRestCipher { get; set; }
    public string? SetupToken { get; set; }
    public DateTimeOffset? SetupTokenExpires { get; set; }
}

public sealed class InstallContext(IHostShell shell, InstallAnswers answers, HostFacts host, string releaseDirectory, string version, TextWriter log)
{
    public IHostShell Shell { get; } = shell;
    public InstallAnswers Answers { get; } = answers;
    public HostFacts Host { get; } = host;
    public string ReleaseDirectory { get; } = releaseDirectory;
    public string Version { get; } = version;
    public TextWriter Log { get; } = log;
    public ReportSecrets Secrets { get; set; } = new();
    public bool SignatureVerified { get; init; }
    public int Workers => Answers.Workers ?? Tuning.DefaultWorkers(Host.Vcpu);
    public bool UseDataDisk => Answers.DataDisk is not null;
    public string CredentialKey => Host.Tpm2 ? "host+tpm2" : "host";
    public Dictionary<string, string> Values { get; } = new(StringComparer.Ordinal);

    public string Template(string relative) => Paths.Join(ReleaseDirectory, "templates", relative);
}

public interface IInstallStep
{
    string Name { get; }
    Task RunAsync(InstallContext context, CancellationToken cancellationToken);
}

/// <summary>
/// The installation (§5.3 of the installation design): every step is idempotent, completed steps are recorded, and a
/// failed run stops with everything it started stopped again, to be continued with <c>vaulty install --resume</c>.
/// </summary>
public sealed class Installer(IReadOnlyList<IInstallStep>? steps = null)
{
    public IReadOnlyList<IInstallStep> Steps { get; } = steps ?? InstallSteps.All;

    public async Task<int> RunAsync(InstallContext context, bool resume, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var shell = context.Shell;
        var completed = resume && shell.FileExists(Paths.InstallState)
            ? JsonSerializer.Deserialize<List<string>>(shell.ReadFile(Paths.InstallState)) ?? []
            : [];
        if (!resume && shell.FileExists(Paths.Config)) throw new InstallException("Vaulty is already installed on this host; use vaulty update.");
        if (!resume && shell.FileExists(Paths.InstallState)) throw new InstallException("An earlier installation did not finish; continue it with vaulty install --resume.");
        if (resume && shell.FileExists(Paths.PendingReport))
        {
            var text = await shell.RunCheckedAsync("systemd-creds", ["decrypt", "--name=pending-report", Paths.PendingReport, "-"], cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            context.Secrets = JsonSerializer.Deserialize<ReportSecrets>(text) ?? new ReportSecrets();
        }
        foreach (var (key, value) in Tuning.Values(context.Host, context.Workers)) context.Values[key] = value;

        shell.CreateDirectory(Paths.State, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        foreach (var step in Steps)
        {
            if (completed.Contains(step.Name))
            {
                await context.Log.WriteLineAsync($"  [done] {step.Name}").ConfigureAwait(false);
                continue;
            }
            await context.Log.WriteLineAsync($"  [....] {step.Name}").ConfigureAwait(false);
            try
            {
                await step.RunAsync(context, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is InstallException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception
                                       or JsonException or KeyNotFoundException)
            {
                await context.Log.WriteLineAsync($"  [fail] {step.Name}: {ex.Message}").ConfigureAwait(false);
                await SaveAsync(context, completed, cancellationToken).ConfigureAwait(false);
                await StopVaultyAsync(shell, context.Workers, cancellationToken).ConfigureAwait(false);
                await context.Log.WriteLineAsync("The installation stopped; nothing of Vaulty is left running. Fix the cause above, then run: vaulty install --resume")
                    .ConfigureAwait(false);
                return 1;
            }
            completed.Add(step.Name);
            await SaveAsync(context, completed, cancellationToken).ConfigureAwait(false);
        }
        shell.DeleteFile(Paths.InstallState);
        if (shell.FileExists(Paths.PendingReport)) shell.DeleteFile(Paths.PendingReport);
        return 0;
    }

    private static async Task SaveAsync(InstallContext context, List<string> completed, CancellationToken cancellationToken)
    {
        context.Shell.WriteFile(Paths.InstallState, JsonSerializer.Serialize(completed), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        if (context.Secrets.MasterKey.Length == 0) return;
        await context.Shell.RunCheckedAsync("systemd-creds", ["encrypt", "--name=pending-report", $"--with-key={context.CredentialKey}", "-", Paths.PendingReport],
            JsonSerializer.Serialize(context.Secrets), cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public static async Task StopVaultyAsync(IHostShell shell, int workers, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(shell);
        foreach (var unit in Paths.Services(workers).Reverse())
        {
            await shell.RunAsync("systemctl", ["stop", unit], cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }

    public static string Random(int bytes) => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(bytes));
}

public static class InstallSteps
{
    public static IReadOnlyList<IInstallStep> All { get; } =
    [
        new Step("preflight", Preflight),
        new Step("os packages and firewall", OsAsync),
        new Step("users and directories", UsersAsync),
        new Step("data disk", DataDiskAsync),
        new Step("credentials", CredentialsAsync),
        new Step("postgresql", PostgresAsync),
        new Step("pgbackrest", PgBackRestAsync),
        new Step("docker", DockerAsync),
        new Step("release", ReleaseAsync),
        new Step("temporal and valkey", TemporalAsync),
        new Step("vaulty services", ServicesAsync),
        new Step("caddy", CaddyAsync),
        new Step("first administrator", FirstAdminAsync),
        new Step("health check", HealthAsync),
        new Step("report", ReportAsync),
    ];

    private sealed class Step(string name, Func<InstallContext, CancellationToken, Task> run) : IInstallStep
    {
        public string Name { get; } = name;
        public Task RunAsync(InstallContext context, CancellationToken cancellationToken) => run(context, cancellationToken);
    }

    private const UnixFileMode Rw = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode RwR = Rw | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
    private const UnixFileMode Rwx = Rw | UnixFileMode.UserExecute;
    private const UnixFileMode RwxRx = Rwx | UnixFileMode.GroupRead | UnixFileMode.GroupExecute;
    private const UnixFileMode Public = RwxRx | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    private static Task Apt(InstallContext c, CancellationToken ct, params string[] packages) =>
        c.Shell.RunCheckedAsync("apt-get", ["install", "-y", "-qq", "--no-install-recommends", .. packages], cancellationToken: ct);

    internal static async Task Preflight(InstallContext c, CancellationToken ct)
    {
        var h = c.Host;
        if (h.OsId != "ubuntu" || h.OsVersion != "24.04") throw new InstallException($"Ubuntu 24.04 LTS is required (found {h.OsId} {h.OsVersion}).");
        if (h.Architecture != "x86_64") throw new InstallException($"x86-64 is required (found {h.Architecture}).");
        if (h.Vcpu < 4) throw new InstallException($"At least 4 vCPU are required (found {h.Vcpu}).");
        if (h.RamMb < 7 * 1024) throw new InstallException($"At least 8 GB of memory is required (found {h.RamMb} MB).");
        var problems = c.Answers.Validate(h.Vcpu);
        if (problems.Count > 0) throw new InstallException("The answers are not valid: " + string.Join(" ", problems));
        foreach (var port in new[] { 80, 443 })
        {
            var listening = await c.Shell.RunAsync("ss", ["-ltnH", $"sport = :{port}"], cancellationToken: ct).ConfigureAwait(false);
            if (listening.Output.Trim().Length > 0 && !listening.Output.Contains("caddy", StringComparison.Ordinal))
            {
                throw new InstallException($"Port {port} is in use by another program; Vaulty needs 80 and 443.");
            }
        }
        if (!h.Tpm2) await c.Log.WriteLineAsync("  WARNING: no TPM 2.0; the master key is bound to this host's key only. This is shown in the report and in vaulty status.").ConfigureAwait(false);
    }

    internal static async Task OsAsync(InstallContext c, CancellationToken ct)
    {
        await c.Shell.RunCheckedAsync("apt-get", ["update", "-qq"], cancellationToken: ct).ConfigureAwait(false);
        await Apt(c, ct, "unattended-upgrades", "ufw", "fail2ban", "needrestart", "cryptsetup", "ca-certificates", "curl", "gnupg", "postgresql-common", "tar").ConfigureAwait(false);
        c.Shell.WriteFile("/etc/apt/apt.conf.d/52vaulty-unattended-upgrades",
            "Unattended-Upgrade::Allowed-Origins { \"${distro_id}:${distro_codename}-security\"; };\nUnattended-Upgrade::Automatic-Reboot \"true\";\nUnattended-Upgrade::Automatic-Reboot-Time \"04:00\";\n", RwR);
        c.Shell.WriteFile("/etc/needrestart/conf.d/50-vaulty.conf", "$nrconf{restart} = 'a';\n", RwR);
        c.Shell.WriteFile("/etc/sysctl.d/60-vaulty.conf",
            "kernel.yama.ptrace_scope = 1\nfs.protected_hardlinks = 1\nfs.protected_symlinks = 1\nfs.protected_fifos = 2\nfs.protected_regular = 2\nnet.ipv4.conf.all.rp_filter = 1\nvm.swappiness = 10\n", RwR);
        await c.Shell.RunCheckedAsync("sysctl", ["--system"], cancellationToken: ct).ConfigureAwait(false);
        string[] ssh = c.Answers.SshAllowFrom is { } from ? ["limit", "from", from, "to", "any", "port", "22", "proto", "tcp"] : ["limit", "22/tcp"];
        foreach (var rule in new[] { new[] { "default", "deny", "incoming" }, ["default", "allow", "outgoing"], ssh, ["allow", "80/tcp"], ["allow", "443/tcp"], ["--force", "enable"] })
        {
            await c.Shell.RunCheckedAsync("ufw", rule, cancellationToken: ct).ConfigureAwait(false);
        }
        await c.Shell.SystemctlAsync("enable", "--now", "fail2ban", "unattended-upgrades").ConfigureAwait(false);
        if (c.Answers.TimeZone is { } zone) await c.Shell.RunCheckedAsync("timedatectl", ["set-timezone", zone], cancellationToken: ct).ConfigureAwait(false);
    }

    internal static async Task UsersAsync(InstallContext c, CancellationToken ct)
    {
        if (!(await c.Shell.RunAsync("getent", ["group", "vaulty"], cancellationToken: ct).ConfigureAwait(false)).Succeeded)
        {
            await c.Shell.RunCheckedAsync("groupadd", ["--system", "vaulty"], cancellationToken: ct).ConfigureAwait(false);
        }
        foreach (var user in Paths.ServiceUsers)
        {
            if ((await c.Shell.RunAsync("id", ["-u", user], cancellationToken: ct).ConfigureAwait(false)).Succeeded) continue;
            await c.Shell.RunCheckedAsync("useradd", ["--system", "--gid", "vaulty", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", user],
                cancellationToken: ct).ConfigureAwait(false);
        }
        c.Shell.CreateDirectory(Paths.Etc, RwxRx);
        c.Shell.CreateDirectory(Paths.Credentials, Rwx);
        c.Shell.CreateDirectory(Paths.Releases, Public);
        c.Shell.CreateDirectory(Paths.Lib, RwxRx);
        c.Shell.CreateDirectory(Paths.State, Rwx);
        await c.Shell.RunCheckedAsync("chgrp", ["vaulty", Paths.Etc, Paths.Lib], cancellationToken: ct).ConfigureAwait(false);
    }

    internal static async Task DataDiskAsync(InstallContext c, CancellationToken ct)
    {
        if (c.Answers.DataDisk is not { } device)
        {
            c.Shell.CreateDirectory(Paths.Data, Public);
        }
        else if (!(await c.Shell.RunAsync("findmnt", ["-n", Paths.Data], cancellationToken: ct).ConfigureAwait(false)).Succeeded)
        {
            var target = device;
            if (c.Answers.Luks)
            {
                c.Secrets.LuksPassphrase ??= string.Join('-', Enumerable.Range(0, 6).Select(_ => Installer.Random(3)));
                if (!(await c.Shell.RunAsync("cryptsetup", ["isLuks", device], cancellationToken: ct).ConfigureAwait(false)).Succeeded)
                {
                    await c.Shell.RunCheckedAsync("cryptsetup", ["luksFormat", "--batch-mode", "--type", "luks2", "--cipher", "aes-xts-plain64", "--key-size", "512",
                        "--pbkdf", "argon2id", "--key-file", "-", device], c.Secrets.LuksPassphrase, cancellationToken: ct).ConfigureAwait(false);
                }
                if (c.Host.Tpm2)
                {
                    await c.Shell.RunCheckedAsync("systemd-cryptenroll", ["--tpm2-device=auto", "--tpm2-pcrs=7", $"--unlock-key-file=/dev/stdin", device],
                        c.Secrets.LuksPassphrase, cancellationToken: ct).ConfigureAwait(false);
                }
                await c.Shell.RunAsync("cryptsetup", ["open", "--key-file", "-", device, "vaulty-data"], c.Secrets.LuksPassphrase, cancellationToken: ct).ConfigureAwait(false);
                target = "/dev/mapper/vaulty-data";
                var uuid = (await c.Shell.RunCheckedAsync("blkid", ["-s", "UUID", "-o", "value", device], cancellationToken: ct).ConfigureAwait(false)).Trim();
                c.Shell.WriteFile("/etc/crypttab", Upsert(c, "/etc/crypttab", "vaulty-data", $"vaulty-data UUID={uuid} none luks,discard{(c.Host.Tpm2 ? ",tpm2-device=auto" : "")}"), Rw);
            }
            if (!(await c.Shell.RunAsync("blkid", [target], cancellationToken: ct).ConfigureAwait(false)).Succeeded)
            {
                await c.Shell.RunCheckedAsync("mkfs.ext4", ["-q", "-L", "vaulty-data", target], cancellationToken: ct).ConfigureAwait(false);
            }
            c.Shell.CreateDirectory(Paths.Data, Public);
            c.Shell.WriteFile("/etc/fstab", Upsert(c, "/etc/fstab", Paths.Data, $"{target} {Paths.Data} ext4 defaults,noatime,nofail 0 2"), RwR);
            await c.Shell.RunCheckedAsync("mount", [Paths.Data], cancellationToken: ct).ConfigureAwait(false);
        }
        c.Shell.CreateDirectory(Paths.Staging, RwxRx | UnixFileMode.GroupWrite);
        await c.Shell.RunCheckedAsync("chgrp", ["vaulty", Paths.Staging], cancellationToken: ct).ConfigureAwait(false);
    }

    private static string Upsert(InstallContext c, string file, string key, string line)
    {
        var lines = (c.Shell.FileExists(file) ? c.Shell.ReadFile(file) : "").Split('\n').Where(l => l.Length > 0 && !l.Contains(key, StringComparison.Ordinal));
        return string.Join('\n', lines.Append(line)) + "\n";
    }

    internal static async Task CredentialsAsync(InstallContext c, CancellationToken ct)
    {
        async Task Create(string name, Func<string> value, Action<string> remember)
        {
            if (c.Shell.FileExists(Paths.Credential(name))) return;
            var secret = value();
            await c.Shell.RunCheckedAsync("systemd-creds", ["encrypt", $"--name={name}", $"--with-key={c.CredentialKey}", "-", Paths.Credential(name)], secret,
                cancellationToken: ct).ConfigureAwait(false);
            remember(secret);
        }
        // The master key exists in plain form only in memory and, once, in the report (recovery copy).
        await Create("master-key", () => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), v => c.Secrets.MasterKey = v).ConfigureAwait(false);
        await Create("temporal-db", () => Installer.Random(24), v => c.Secrets.TemporalPassword = v).ConfigureAwait(false);
        await Create("valkey", () => Installer.Random(24), v => c.Secrets.ValkeyPassword = v).ConfigureAwait(false);
    }

    internal static async Task PostgresAsync(InstallContext c, CancellationToken ct)
    {
        if (!c.Shell.FileExists("/usr/lib/postgresql/17/bin/postgres"))
        {
            await c.Shell.RunCheckedAsync("/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh", ["-y"], cancellationToken: ct).ConfigureAwait(false);
            // The package must not create its default cluster: Vaulty's cluster lives on the data disk with checksums.
            c.Shell.WriteFile("/etc/postgresql-common/createcluster.d/50-vaulty.conf", "create_main_cluster = false\n", RwR);
            await Apt(c, ct, "postgresql-17", "postgresql-client-17", "pgbackrest").ConfigureAwait(false);
        }
        if (!c.Shell.DirectoryExists(Paths.PgConf))
        {
            // The data disk root stays traversable (0755, root); PostgreSQL's own tree is 0700 and owned by postgres.
            await c.Shell.RunCheckedAsync("chmod", ["0755", Paths.Data], cancellationToken: ct).ConfigureAwait(false);
            c.Shell.CreateDirectory(Paths.Parent(Paths.PgData), Rwx);
            await c.Shell.RunCheckedAsync("chown", ["-R", "postgres:postgres", $"{Paths.Data}/postgresql"], cancellationToken: ct).ConfigureAwait(false);
            await c.Shell.RunCheckedAsync("chmod", ["-R", "0700", $"{Paths.Data}/postgresql"], cancellationToken: ct).ConfigureAwait(false);
            await c.Shell.RunCheckedAsync("pg_createcluster", ["17", "main", "-p", "5432", "-d", Paths.PgData, "--", "--data-checksums", "--encoding=UTF8", "--locale=C.UTF-8"],
                cancellationToken: ct).ConfigureAwait(false);
        }
        c.Values["PG_DATA_DIRECTORY"] = Paths.PgData;
        foreach (var (template, target) in new[]
                 {
                     ("postgres/postgresql.vaulty.conf.template", $"{Paths.PgConf}/conf.d/50-vaulty.conf"),
                     ("postgres/pg_hba.conf.template", $"{Paths.PgConf}/pg_hba.conf"),
                     ("postgres/pg_ident.conf.template", $"{Paths.PgConf}/pg_ident.conf"),
                 })
        {
            c.Shell.WriteFile(target, Templates.Render(c.Shell.ReadFile(c.Template(template)), c.Values, template), Rw | UnixFileMode.GroupRead);
            await c.Shell.RunCheckedAsync("chown", ["postgres:postgres", target], cancellationToken: ct).ConfigureAwait(false);
        }
        await c.Shell.SystemctlAsync("enable", "postgresql@17-main").ConfigureAwait(false);
        await c.Shell.SystemctlAsync("restart", "postgresql@17-main").ConfigureAwait(false);
        await WaitForPostgresAsync(c, ct).ConfigureAwait(false);
        var exists = await c.Shell.RunAsync("runuser", ["-u", "postgres", "--", "psql", "-tAc", "SELECT 1 FROM pg_roles WHERE rolname = 'vaulty_migrator'"],
            cancellationToken: ct).ConfigureAwait(false);
        if (exists.Output.Trim() != "1")
        {
            if (c.Secrets.TemporalPassword.Length == 0) throw new InstallException("The Temporal database password is missing; remove the temporal-db credential and resume.");
            // The password reaches psql on standard input, never on a command line.
            var script = $"\\set temporal_password '''{c.Secrets.TemporalPassword}'''\n" + c.Shell.ReadFile(c.Template("postgres/roles.sql"));
            await c.Shell.RunCheckedAsync("runuser", ["-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-q", "-f", "-"], script, cancellationToken: ct)
                .ConfigureAwait(false);
        }
    }

    private static async Task WaitForPostgresAsync(InstallContext c, CancellationToken ct)
    {
        try
        {
            await WaitAsync(c, "PostgreSQL", async () => (await c.Shell.RunAsync("pg_isready", ["-t", "5", "-q", "-h", "/var/run/postgresql"], cancellationToken: ct)
                .ConfigureAwait(false)).Succeeded, TimeSpan.FromSeconds(90), ct).ConfigureAwait(false);
        }
        catch (InstallException)
        {
            var clusters = await c.Shell.RunAsync("pg_lsclusters", [], cancellationToken: ct).ConfigureAwait(false);
            var journal = await c.Shell.RunAsync("journalctl", ["-u", "postgresql@17-main", "-n", "30", "--no-pager"], cancellationToken: ct).ConfigureAwait(false);
            var log = await c.Shell.RunAsync("sh", ["-c", "tail -n 30 /var/log/postgresql/postgresql-17-main.log 2>/dev/null"], cancellationToken: ct).ConfigureAwait(false);
            throw new InstallException($"PostgreSQL did not start. {clusters.Output} {journal.Output} {log.Output}");
        }
    }

    internal static async Task PgBackRestAsync(InstallContext c, CancellationToken ct)
    {
        if (c.Answers.PgBackRest is not { } p)
        {
            c.Values["PGBACKREST_SUMMARY"] = "not configured (no point-in-time recovery until it is set up)";
            return;
        }
        c.Secrets.PgBackRestCipher ??= Installer.Random(32);
        foreach (var (name, value) in new[] { ("pgbackrest-s3", $"{p.AccessKey}\n{p.SecretKey}"), ("pgbackrest-cipher", c.Secrets.PgBackRestCipher) })
        {
            if (c.Shell.FileExists(Paths.Credential(name))) continue;
            await c.Shell.RunCheckedAsync("systemd-creds", ["encrypt", $"--name={name}", $"--with-key={c.CredentialKey}", "-", Paths.Credential(name)], value,
                cancellationToken: ct).ConfigureAwait(false);
        }
        var host = p.Endpoint.Replace("https://", "", StringComparison.Ordinal);
        c.Shell.WriteFile("/etc/pgbackrest/pgbackrest.conf", string.Join('\n',
            "[global]", "repo1-type=s3", $"repo1-s3-endpoint={host}", $"repo1-s3-region={p.Region}", $"repo1-s3-bucket={p.Bucket}", "repo1-path=/pgbackrest",
            "repo1-cipher-type=aes-256-cbc", $"repo1-retention-full={p.RetentionFull}", "start-fast=y", "compress-type=zst", "",
            "[vaulty]", $"pg1-path={Paths.PgData}", "") , Rw | UnixFileMode.GroupRead);
        c.Shell.CreateDirectory("/etc/systemd/system/postgresql@17-main.service.d", Public);
        c.Shell.WriteFile("/etc/systemd/system/postgresql@17-main.service.d/vaulty-credentials.conf",
            c.Shell.ReadFile(c.Template("systemd/postgresql-credentials.conf")), RwR);
        c.Shell.WriteFile($"{Paths.PgConf}/conf.d/60-vaulty-archive.conf",
            $"archive_mode = on\narchive_command = '{Paths.Current}/bin/vaulty-pgbackrest archive-push %p'\narchive_timeout = 300\n", Rw | UnixFileMode.GroupRead);
        await c.Shell.SystemctlAsync("daemon-reload").ConfigureAwait(false);
        await c.Shell.SystemctlAsync("restart", "postgresql@17-main").ConfigureAwait(false);
        await c.Shell.RunCheckedAsync($"{c.ReleaseDirectory}/bin/vaulty-pgbackrest", ["stanza-create"], cancellationToken: ct).ConfigureAwait(false);
        c.Values["PGBACKREST_SUMMARY"] = $"pgBackRest to bucket {p.Bucket} ({p.Region}), {p.RetentionFull} full backups kept, archive_timeout 300 s";
    }

    internal static async Task DockerAsync(InstallContext c, CancellationToken ct)
    {
        if (!c.Shell.FileExists("/usr/bin/docker"))
        {
            c.Shell.CreateDirectory("/etc/apt/keyrings", Public);
            await c.Shell.RunCheckedAsync("curl", ["-fsSL", "-o", "/etc/apt/keyrings/docker.asc", "https://download.docker.com/linux/ubuntu/gpg"], cancellationToken: ct)
                .ConfigureAwait(false);
            c.Shell.WriteFile("/etc/apt/sources.list.d/docker.list",
                "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n", RwR);
            await c.Shell.RunCheckedAsync("apt-get", ["update", "-qq"], cancellationToken: ct).ConfigureAwait(false);
            await Apt(c, ct, "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin").ConfigureAwait(false);
        }
        c.Shell.CreateDirectory("/etc/docker", Public);
        c.Shell.WriteFile("/etc/docker/daemon.json",
            "{\n  \"live-restore\": true,\n  \"log-driver\": \"json-file\",\n  \"log-opts\": { \"max-size\": \"20m\", \"max-file\": \"5\" },\n  \"no-new-privileges\": true,\n  \"icc\": false\n}\n", RwR);
        await c.Shell.SystemctlAsync("enable", "docker").ConfigureAwait(false);
        await c.Shell.SystemctlAsync("restart", "docker").ConfigureAwait(false);
    }

    internal static Task ReleaseAsync(InstallContext c, CancellationToken ct)
    {
        c.Shell.Symlink(Paths.Current, c.ReleaseDirectory);
        return Task.CompletedTask;
    }

    /// <summary>Image versions and digests the release was tested with (compose/images.json, written by the release workflow).</summary>
    public static void AddImages(IHostShell shell, string releaseDirectory, IDictionary<string, string> values)
    {
        ArgumentNullException.ThrowIfNull(shell);
        ArgumentNullException.ThrowIfNull(values);
        using var images = JsonDocument.Parse(shell.ReadFile(Paths.Join(releaseDirectory, "compose", "images.json")));
        foreach (var (name, key) in new[] { ("temporal", "TEMPORAL"), ("temporal-ui", "TEMPORAL_UI"), ("valkey", "VALKEY"), ("admin-tools", "TEMPORAL_ADMIN_TOOLS") })
        {
            var image = images.RootElement.GetProperty(name);
            var digest = image.GetProperty("digest").GetString() ?? "";
            if (!digest.StartsWith("sha256:", StringComparison.Ordinal)) throw new InstallException($"The release has no pinned digest for {name}.");
            values[$"{key}_VERSION"] = image.GetProperty("version").GetString() ?? "";
            values[$"{key}_DIGEST"] = digest;
        }
    }

    public static void RenderCompose(InstallContext c, string releaseDirectory)
    {
        AddImages(c.Shell, releaseDirectory, c.Values);
        // The release ships the Compose file with placeholders; the first render keeps that original as .template.
        var compose = Paths.Join(releaseDirectory, "compose", "temporal.compose.yml");
        var template = compose + ".template";
        if (!c.Shell.FileExists(template)) c.Shell.WriteFile(template, c.Shell.ReadFile(compose), RwR);
        c.Shell.WriteFile(compose, Templates.Render(c.Shell.ReadFile(template), c.Values, "temporal.compose.yml"), RwR);
    }

    internal static async Task TemporalAsync(InstallContext c, CancellationToken ct)
    {
        RenderCompose(c, c.ReleaseDirectory);
        var tools = $"temporalio/admin-tools:{c.Values["TEMPORAL_ADMIN_TOOLS_VERSION"]}@{c.Values["TEMPORAL_ADMIN_TOOLS_DIGEST"]}";
        var password = await DecryptAsync(c.Shell, "temporal-db", ct).ConfigureAwait(false);
        foreach (var (database, schema) in new[] { ("temporal", "temporal"), ("temporal_visibility", "visibility") })
        {
            // The password reaches the one-off container as process environment only (the documented exception for containers).
            var environment = new Dictionary<string, string> { ["SQL_PASSWORD"] = password };
            // The schema tool talks to PostgreSQL only; five minutes is ample, and a stuck tool must not hold the installer.
            // The image's entrypoint only sleeps; the tool is chosen with --entrypoint.
            string[] common = ["300", "docker", "run", "--rm", "--network", "host", "-e", "SQL_PASSWORD", "--entrypoint", "temporal-sql-tool", tools, "--plugin", "postgres12", "--ep", "127.0.0.1", "-p", "5432",
                "-u", "temporal", "--db", database];
            var version = await c.Shell.RunAsync("timeout", [.. common, "describe-schema"], environment: environment, cancellationToken: ct).ConfigureAwait(false);
            if (!version.Succeeded || version.Output.Contains("0.0", StringComparison.Ordinal) || version.Output.Trim().Length == 0)
            {
                await c.Shell.RunAsync("timeout", [.. common, "setup-schema", "-v", "0.0"], environment: environment, cancellationToken: ct).ConfigureAwait(false);
            }
            await c.Shell.RunCheckedAsync("timeout", [.. common, "update-schema", "-d", $"/etc/temporal/schema/postgresql/v12/{schema}/versioned"], environment: environment,
                cancellationToken: ct).ConfigureAwait(false);
        }
        await InstallUnitsAsync(c, c.ReleaseDirectory, ct).ConfigureAwait(false);
        await c.Shell.SystemctlAsync("enable", "--now", "vaulty-temporal.service").ConfigureAwait(false);
        await WaitAsync(c, "Temporal", async () => (await c.Shell.RunAsync("timeout", TemporalCli(c.Values, "operator", "cluster", "health"), cancellationToken: ct)
            .ConfigureAwait(false)).Output.Contains("SERVING", StringComparison.Ordinal), TimeSpan.FromMinutes(5), ct).ConfigureAwait(false);
        var described = await c.Shell.RunAsync("timeout", TemporalCli(c.Values, "operator", "namespace", "describe", "--namespace", "vaulty"), cancellationToken: ct)
            .ConfigureAwait(false);
        if (!described.Succeeded)
        {
            await c.Shell.RunCheckedAsync("timeout", TemporalCli(c.Values, "operator", "namespace", "create", "--namespace", "vaulty", "--retention", "30d"),
                cancellationToken: ct).ConfigureAwait(false);
        }
    }

    /// <summary>The Temporal CLI of the pinned admin-tools image, against the local server, for at most 30 seconds (arguments for coreutils timeout).</summary>
    public static string[] TemporalCli(IReadOnlyDictionary<string, string> values, params string[] args)
    {
        ArgumentNullException.ThrowIfNull(values);
        var tools = $"temporalio/admin-tools:{values["TEMPORAL_ADMIN_TOOLS_VERSION"]}@{values["TEMPORAL_ADMIN_TOOLS_DIGEST"]}";
        return ["30", "docker", "run", "--rm", "--network", "host", "--entrypoint", "temporal", tools, .. args, "--address", "127.0.0.1:7233"];
    }

    public static async Task<string> DecryptAsync(IHostShell shell, string name, CancellationToken ct) =>
        (await shell.RunCheckedAsync("systemd-creds", ["decrypt", $"--name={name}", Paths.Credential(name), "-"], cancellationToken: ct).ConfigureAwait(false)).Trim();

    /// <summary>The unit files of a release, rendered with this host's limits, and the non-secret host configuration.</summary>
    public static async Task InstallUnitsAsync(InstallContext c, string releaseDirectory, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(c);
        foreach (var unit in Paths.UnitTemplates)
        {
            var template = Paths.Join(releaseDirectory, "templates", "systemd", unit);
            c.Shell.WriteFile(Paths.Join(Paths.Units, unit), Templates.Render(c.Shell.ReadFile(template), c.Values, unit), RwR);
        }
        c.Shell.WriteFile(Paths.Config, ConfigJson(c), Rw | UnixFileMode.GroupRead);
        await c.Shell.RunCheckedAsync("chgrp", ["vaulty", Paths.Config], cancellationToken: ct).ConfigureAwait(false);
        await c.Shell.SystemctlAsync("daemon-reload").ConfigureAwait(false);
    }

    public static string ConfigJson(InstallContext c)
    {
        ArgumentNullException.ThrowIfNull(c);
        var config = new JsonObject
        {
            ["Vaulty"] = new JsonObject
            {
                ["PublicHost"] = c.Answers.Fqdn,
                ["HostId"] = c.Host.Hostname,
                ["Environment"] = c.Answers.Environment,
                ["Temporal"] = new JsonObject { ["Address"] = "127.0.0.1:7233", ["Namespace"] = "vaulty" },
            },
            ["Install"] = new JsonObject
            {
                ["Profile"] = c.Answers.Profile,
                ["Fqdn"] = c.Answers.Fqdn,
                ["AdminEmail"] = c.Answers.AdminEmail,
                ["Workers"] = c.Workers,
                ["DataDisk"] = c.Answers.DataDisk,
                ["Luks"] = c.UseDataDisk && c.Answers.Luks,
                ["Tpm2"] = c.Host.Tpm2,
                ["PgBackRest"] = c.Answers.PgBackRest is not null,
                ["AutoUpdate"] = c.Answers.AutoUpdate,
                ["InstalledVersion"] = c.Version,
                ["SignatureVerified"] = c.SignatureVerified,
            },
        };
        return config.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n";
    }

    internal static async Task ServicesAsync(InstallContext c, CancellationToken ct)
    {
        await InstallUnitsAsync(c, c.ReleaseDirectory, ct).ConfigureAwait(false);
        await c.Shell.SystemctlAsync("start", "vaulty-migrate.service").ConfigureAwait(false);
        await c.Shell.SystemctlAsync("enable", "vaulty.target", "vaulty-update-check.timer").ConfigureAwait(false);
        foreach (var unit in Paths.Services(c.Workers)) await c.Shell.SystemctlAsync("enable", "--now", unit).ConfigureAwait(false);
    }

    internal static async Task CaddyAsync(InstallContext c, CancellationToken ct)
    {
        if (!c.Shell.FileExists("/usr/bin/caddy"))
        {
            await c.Shell.RunCheckedAsync("sh", ["-c",
                "curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"],
                cancellationToken: ct).ConfigureAwait(false);
            c.Shell.WriteFile("/etc/apt/sources.list.d/caddy-stable.list",
                "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main\n", RwR);
            await c.Shell.RunCheckedAsync("apt-get", ["update", "-qq"], cancellationToken: ct).ConfigureAwait(false);
            await Apt(c, ct, "caddy").ConfigureAwait(false);
        }
        c.Values["FQDN"] = c.Answers.Fqdn;
        c.Values["ACME_EMAIL"] = c.Answers.AdminEmail;
        c.Values["ACME_CA"] = c.Answers.Environment == "production"
            ? "https://acme-v02.api.letsencrypt.org/directory"
            : "https://acme-staging-v02.api.letsencrypt.org/directory";
        c.Shell.WriteFile("/etc/caddy/Caddyfile", Templates.Render(c.Shell.ReadFile(c.Template("caddy/Caddyfile.template")), c.Values, "Caddyfile"), RwR);
        await c.Shell.SystemctlAsync("enable", "caddy").ConfigureAwait(false);
        await c.Shell.SystemctlAsync("reload-or-restart", "caddy").ConfigureAwait(false);
    }

    internal static async Task FirstAdminAsync(InstallContext c, CancellationToken ct)
    {
        if (c.Secrets.SetupToken is not null) return;
        // Issued by the CLI itself running as the web user with the master key credential, exactly like the web app.
        var output = await c.Shell.RunCheckedAsync("systemd-run", ["--quiet", "--wait", "--pipe", "--collect", "--uid=vaulty-web", "--gid=vaulty",
            $"--property=LoadCredentialEncrypted=master-key:{Paths.Credential("master-key")}", "--setenv=VAULTY_CONFIG_DIR=/etc/vaulty",
            $"{Paths.Current}/bin/vaulty", "internal", "setup-token"], cancellationToken: ct).ConfigureAwait(false);
        var token = output.Trim().Split('\n').Last().Trim();
        if (token.Length < 20) throw new InstallException("The first-administrator token could not be issued.");
        c.Secrets.SetupToken = token;
        c.Secrets.SetupTokenExpires = DateTimeOffset.UtcNow.AddHours(24);
    }

    internal static async Task HealthAsync(InstallContext c, CancellationToken ct)
    {
        var failures = await Health.CheckAsync(c.Shell, c.Workers, TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        if (failures.Count > 0) throw new InstallException("Health check failed: " + string.Join("; ", failures));
    }

    internal static async Task ReportAsync(InstallContext c, CancellationToken ct)
    {
        var path = $"/root/vaulty-install-report-{DateTimeOffset.UtcNow:yyyyMMdd-HHmm}.txt";
        var report = await Reports.RenderAsync(c, path, includeSecrets: true, ct).ConfigureAwait(false);
        c.Shell.WriteFile(path, report, Rw);
        await c.Log.WriteLineAsync().ConfigureAwait(false);
        await c.Log.WriteLineAsync(report).ConfigureAwait(false);
        await c.Log.WriteLineAsync($"The report above is saved to {path} (mode 0600). Store it in your password manager, then delete it.").ConfigureAwait(false);
        c.Shell.WriteFile($"{Paths.State}/version", c.Version + "\n", RwR);
    }

    public static async Task WaitAsync(InstallContext c, string what, Func<Task<bool>> ready, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(ready);
        var until = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            if (await ready().ConfigureAwait(false)) return;
            if (DateTimeOffset.UtcNow > until) throw new InstallException($"{what} did not become ready within {timeout.TotalSeconds:F0} seconds.");
            await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
        }
    }
}
