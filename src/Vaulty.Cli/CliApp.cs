using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Spectre.Console;

namespace Vaulty.Cli;

public static class CliApp
{
    public const string Usage = """
        vaulty: install, update and manage a Vaulty host (Ubuntu 24.04 LTS, run as root).

          vaulty install [--answers <file>] [--resume]        wizard and installation
          vaulty update [--check] [--to <version>] [--rollback] [--accept-format-change] [--force]
          vaulty status [--json]                              units, versions, TPM, disk, restart needed
          vaulty doctor                                       configuration, permissions, hardening, no secrets in files
          vaulty report                                       the installation report without secrets
          vaulty secrets list | set <name> | rotate <name> | prune <name> [--keep <n>] | rekey
          vaulty master-key restore                           a new master key credential from the recovery copy
          vaulty db backup-now | verify | restore --target-time <time>
          vaulty logs [<unit>] [--since <time>]
          vaulty uninstall [--purge --confirm <hostname>]
        """;

    public static async Task<int> RunAsync(string[] args, IHostShell shell, TextWriter output, TextWriter error, CancellationToken ct = default, bool checkRoot = true)
    {
        ArgumentNullException.ThrowIfNull(args);
        var command = args.FirstOrDefault();
        var rest = args.Skip(1).ToArray();
        try
        {
            if (command is "internal") return await Internal.RunAsync(rest, output, ct).ConfigureAwait(false);
            if (command is null or "--help" or "-h" or "help")
            {
                await output.WriteLineAsync(Usage).ConfigureAwait(false);
                return command is null ? 2 : 0;
            }
            if (checkRoot && Environment.UserName != "root")
            {
                await error.WriteLineAsync("vaulty must run as root (sudo vaulty ...).").ConfigureAwait(false);
                return 1;
            }
            return command switch
            {
                "bootstrap" => await BootstrapAsync(rest, shell, output, ct).ConfigureAwait(false),
                "install" => await InstallAsync(rest, shell, output, Option(rest, "--release-dir") ?? CurrentRelease(), ct).ConfigureAwait(false),
                "update" => await UpdateAsync(rest, shell, output, ct).ConfigureAwait(false),
                "status" => await StatusAsync(rest, shell, output, ct).ConfigureAwait(false),
                "doctor" => await DoctorAsync(shell, output, ct).ConfigureAwait(false),
                "report" => await ReportAsync(shell, output, ct).ConfigureAwait(false),
                "secrets" => await SecretsAsync(rest, shell, output, ct).ConfigureAwait(false),
                "master-key" when rest.FirstOrDefault() == "restore" => await MasterKeyRestoreAsync(shell, output, ct).ConfigureAwait(false),
                "db" => await DatabaseAsync(rest, shell, output, ct).ConfigureAwait(false),
                "logs" => await LogsAsync(rest, shell, output, ct).ConfigureAwait(false),
                "uninstall" => await UninstallAsync(rest, shell, output, ct).ConfigureAwait(false),
                _ => await UnknownAsync(command, error).ConfigureAwait(false),
            };
        }
        catch (InstallException ex)
        {
            await error.WriteLineAsync($"vaulty: {ex.Message}").ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> UnknownAsync(string command, TextWriter error)
    {
        await error.WriteLineAsync($"Unknown command '{command}'.\n\n{Usage}").ConfigureAwait(false);
        return 2;
    }

    internal static string? Option(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static bool Flag(string[] args, string name) => args.Contains(name, StringComparer.Ordinal);

    private static string CurrentRelease() => Path.GetDirectoryName(Path.GetDirectoryName(Environment.ProcessPath ?? "")) ?? Paths.Current;

    private static async Task<int> BootstrapAsync(string[] args, IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var release = Option(args, "--release-dir") ?? CurrentRelease();
        if (shell.FileExists(Paths.Config)) return await new Updater(shell, output).UpdateAsync(release, null, Flag(args, "--accept-format-change"), Flag(args, "--force"), ct).ConfigureAwait(false);
        return await InstallAsync(args, shell, output, release, ct).ConfigureAwait(false);
    }

    private static async Task<int> InstallAsync(string[] args, IHostShell shell, TextWriter output, string release, CancellationToken ct)
    {
        var host = await HostProbe.ReadAsync(shell, ct).ConfigureAwait(false);
        var resume = Flag(args, "--resume");
        InstallAnswers answers;
        var file = Option(args, "--answers");
        if (file is not null)
        {
            var mode = (await shell.RunCheckedAsync("stat", ["-c", "%a %U", file], cancellationToken: ct).ConfigureAwait(false)).Trim();
            if (mode != "600 root") throw new InstallException($"The answers file must be owned by root with mode 0600 (it is {mode}).");
            answers = InstallAnswers.Parse(shell.ReadFile(file));
        }
        else if (resume && shell.FileExists($"{Paths.State}/answers.json"))
        {
            answers = JsonSerializer.Deserialize<InstallAnswers>(shell.ReadFile($"{Paths.State}/answers.json")) ?? throw new InstallException("The saved answers are unreadable.");
        }
        else
        {
            answers = Wizard(host);
        }
        // Without secrets, so a resumed run asks nothing again; the secrets of SMTP and pgBackRest are stored right away.
        shell.CreateDirectory(Paths.State, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        shell.WriteFile($"{Paths.State}/answers.json", JsonSerializer.Serialize(answers with { Smtp = null }), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var verified = Environment.GetEnvironmentVariable(Updater.SkipSignatureVariable) != "1";
        var context = new InstallContext(shell, answers, host, release, Path.GetFileName(release.TrimEnd('/')), output) { SignatureVerified = verified };
        await output.WriteLineAsync($"Installing Vaulty {context.Version} ({answers.Profile}, {answers.Environment}) on {host.Hostname}").ConfigureAwait(false);
        var result = await new Installer().RunAsync(context, resume, ct).ConfigureAwait(false);
        if (result == 0)
        {
            if (answers.Smtp is { } smtp) await Internal.ViaServiceAsync(shell, ["smtp", smtp.Host, smtp.Port.ToString(CultureInfo.InvariantCulture), smtp.UserName ?? "", smtp.From],
                smtp.Password, ct).ConfigureAwait(false);
            if (file is not null) shell.DeleteFile(file);
            shell.DeleteFile($"{Paths.State}/answers.json");
        }
        return result;
    }

    private static InstallAnswers Wizard(HostFacts host)
    {
        if (!AnsiConsole.Profile.Capabilities.Interactive) throw new InstallException("No terminal for the wizard; give an answers file with --answers.");
        AnsiConsole.MarkupLine("[bold]Vaulty installation[/]  Everything else is set up later in the web interface.");
        var fqdn = AnsiConsole.Prompt(new TextPrompt<string>("Host name (FQDN) of this Vaulty:").DefaultValue(host.Hostname)
            .Validate(v => Uri.CheckHostName(v) is UriHostNameType.Dns ? ValidationResult.Success() : ValidationResult.Error("Enter a host name such as backup.example.com.")));
        var email = AnsiConsole.Prompt(new TextPrompt<string>("E-mail address for certificates and the first administrator:")
            .Validate(v => System.Net.Mail.MailAddress.TryCreate(v, out _) ? ValidationResult.Success() : ValidationResult.Error("Enter an e-mail address.")));
        var environment = AnsiConsole.Prompt(new SelectionPrompt<string>().Title("Environment:").AddChoices("production", "staging", "development"));
        var disk = AnsiConsole.Prompt(new TextPrompt<string>("Data disk for PostgreSQL (block device, or empty for the system disk):").AllowEmpty());
        var workers = AnsiConsole.Prompt(new TextPrompt<int>("Worker instances:").DefaultValue(Tuning.DefaultWorkers(host.Vcpu))
            .Validate(n => n >= 1 && n <= host.Vcpu ? ValidationResult.Success() : ValidationResult.Error($"Between 1 and {host.Vcpu}.")));
        SmtpAnswers? smtp = null;
        if (AnsiConsole.Confirm("Set up e-mail (SMTP) now?", false))
        {
            smtp = new SmtpAnswers(AnsiConsole.Ask<string>("SMTP host:"), AnsiConsole.Ask("SMTP port:", 587), AnsiConsole.Prompt(new TextPrompt<string>("User name:").AllowEmpty()),
                AnsiConsole.Prompt(new TextPrompt<string>("Password:").Secret().AllowEmpty()), AnsiConsole.Ask<string>("Sender (Vaulty <vaulty@example.com>):"));
        }
        var answers = new InstallAnswers
        {
            Fqdn = fqdn, AdminEmail = email, Environment = environment, DataDisk = disk.Length == 0 ? null : disk, Workers = workers, Smtp = smtp,
        };
        AnsiConsole.MarkupLine($"[bold]Summary[/]: {fqdn}, {environment}, data on {(answers.DataDisk ?? "the system disk")}{(answers.DataDisk is null ? "" : " (LUKS)")}, {workers} workers, SMTP {(smtp is null ? "later" : smtp.Host)}");
        if (!AnsiConsole.Confirm("Install now?")) throw new InstallException("Cancelled; nothing was changed.");
        return answers;
    }

    private static async Task<int> UpdateAsync(string[] args, IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var updater = new Updater(shell, output);
        if (Flag(args, "--rollback")) return await updater.RollbackAsync(ct).ConfigureAwait(false);
        if (Flag(args, "--check"))
        {
            var latest = await updater.LatestAsync(ct).ConfigureAwait(false);
            var current = shell.FileExists($"{Paths.State}/version") ? shell.ReadFile($"{Paths.State}/version").Trim() : "unknown";
            var message = latest is null ? "The latest release could not be determined." : latest == current ? $"Vaulty {current} is the latest release." : $"Vaulty {latest} is available (installed: {current}). Run: vaulty update";
            await output.WriteLineAsync(message).ConfigureAwait(false);
            if (Flag(args, "--notify")) shell.WriteFile($"{Paths.State}/update-check.json", JsonSerializer.Serialize(new { checked_at = DateTimeOffset.UtcNow, current, latest }),
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            return 0;
        }
        return await updater.UpdateAsync(Option(args, "--release-dir"), Option(args, "--to"), Flag(args, "--accept-format-change"), Flag(args, "--force"), ct).ConfigureAwait(false);
    }

    private static async Task<int> StatusAsync(string[] args, IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var context = await Reports.InstalledAsync(shell, output, ct).ConfigureAwait(false);
        var units = new JsonObject();
        foreach (var unit in Paths.Services(context.Workers).Append("postgresql@17-main.service").Append("caddy.service"))
        {
            units[unit] = (await shell.RunAsync("systemctl", ["is-active", unit], cancellationToken: ct).ConfigureAwait(false)).Output.Trim();
        }
        var status = new JsonObject
        {
            ["version"] = context.Version,
            ["previous"] = shell.ReadLink(Paths.Previous) is { } p ? Path.GetFileName(p) : null,
            ["fqdn"] = context.Answers.Fqdn,
            ["tpm2"] = context.Host.Tpm2,
            ["key_wrapper"] = "software key wrapper (master key on this host)",
            ["units"] = units,
            ["restart_needed"] = shell.FileExists("/var/run/reboot-required"),
            ["disk"] = (await shell.RunAsync("df", ["-h", "--output=target,used,avail,pcent", "/", Paths.Data], cancellationToken: ct).ConfigureAwait(false)).Output.Trim(),
            ["signature_verified"] = context.SignatureVerified,
        };
        if (Flag(args, "--json"))
        {
            await output.WriteLineAsync(status.ToJsonString(new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);
            return 0;
        }
        await output.WriteLineAsync($"Vaulty {context.Version} on {context.Answers.Fqdn}{(context.Host.Tpm2 ? "" : "   WARNING: no TPM 2.0, master key bound to the host key only")}").ConfigureAwait(false);
        await output.WriteLineAsync("Key wrapper: software key wrapper (the master key on this host protects the tenant keys)").ConfigureAwait(false);
        foreach (var (unit, state) in units) await output.WriteLineAsync($"  {unit,-32} {state}").ConfigureAwait(false);
        if (shell.FileExists("/var/run/reboot-required")) await output.WriteLineAsync("A restart of the host is needed for security updates.").ConfigureAwait(false);
        await output.WriteLineAsync(status["disk"]!.GetValue<string>()).ConfigureAwait(false);
        return units.All(u => u.Value!.GetValue<string>() == "active") ? 0 : 3;
    }

    private static async Task<int> DoctorAsync(IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var context = await Reports.InstalledAsync(shell, output, ct).ConfigureAwait(false);
        var findings = await Doctor.CheckAsync(shell, context.Workers, ct).ConfigureAwait(false);
        foreach (var (unit, score) in await Doctor.ScoresAsync(shell, context.Workers, ct).ConfigureAwait(false))
        {
            await output.WriteLineAsync($"  {unit,-32} exposure {score.ToString("0.0", CultureInfo.InvariantCulture)}").ConfigureAwait(false);
        }
        foreach (var finding in findings) await output.WriteLineAsync($"  FINDING: {finding}").ConfigureAwait(false);
        await output.WriteLineAsync(findings.Count == 0 ? "No findings." : $"{findings.Count} finding(s).").ConfigureAwait(false);
        return findings.Count == 0 ? 0 : 1;
    }

    private static async Task<int> ReportAsync(IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var context = await Reports.InstalledAsync(shell, output, ct).ConfigureAwait(false);
        await output.WriteLineAsync(await Reports.RenderAsync(context, "(not saved)", includeSecrets: false, ct).ConfigureAwait(false)).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> SecretsAsync(string[] args, IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var action = args.FirstOrDefault() ?? "list";
        switch (action)
        {
            case "list":
                await output.WriteLineAsync(await Internal.ViaServiceAsync(shell, ["secrets", "list"], null, ct).ConfigureAwait(false)).ConfigureAwait(false);
                return 0;
            case "set" or "rotate" when args.Length >= 2:
                var value = action == "rotate" && args.Length < 3 ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                    : AnsiConsole.Prompt(new TextPrompt<string>($"Value of {args[1]}:").Secret());
                await output.WriteLineAsync(await Internal.ViaServiceAsync(shell, ["secrets", "set", args[1]], value, ct).ConfigureAwait(false)).ConfigureAwait(false);
                return 0;
            case "prune" when args.Length >= 2:
                await output.WriteLineAsync(await Internal.ViaServiceAsync(shell, ["secrets", "prune", args[1], Option(args, "--keep") ?? "2"], null, ct).ConfigureAwait(false))
                    .ConfigureAwait(false);
                return 0;
            case "rekey":
                return await RekeyAsync(shell, output, ct).ConfigureAwait(false);
            default:
                throw new InstallException("Use: vaulty secrets list | set <name> | rotate <name> | prune <name> [--keep <n>] | rekey");
        }
    }

    private static async Task<int> RekeyAsync(IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var context = await Reports.InstalledAsync(shell, output, ct).ConfigureAwait(false);
        var config = JsonNode.Parse(shell.ReadFile(Paths.Config))!;
        var version = config["Vaulty"]!["MasterKeyVersion"]?.GetValue<int>() ?? 1;
        var fresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await Installer.StopVaultyAsync(shell, context.Workers, ct).ConfigureAwait(false);
        // Re-encrypts secrets, the data protection ring and wrapped tenant keys in one transaction, as the schema owner.
        await Internal.ViaServiceAsync(shell, ["rekey", version.ToString(CultureInfo.InvariantCulture), (version + 1).ToString(CultureInfo.InvariantCulture)], fresh, ct,
            user: "vaulty-migrator").ConfigureAwait(false);
        await shell.RunCheckedAsync("systemd-creds", ["encrypt", "--name=master-key", $"--with-key={context.CredentialKey}", "-", Paths.Credential("master-key")], fresh,
            cancellationToken: ct).ConfigureAwait(false);
        config["Vaulty"]!["MasterKeyVersion"] = version + 1;
        shell.WriteFile(Paths.Config, config.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        foreach (var unit in Paths.Services(context.Workers)) await shell.RunAsync("systemctl", ["start", unit], cancellationToken: ct).ConfigureAwait(false);
        await output.WriteLineAsync($"New master key (version {version + 1}). Store this recovery copy now; it is not shown again:\n  base64: {fresh}\n  words:  {KeyWords.Encode(Convert.FromBase64String(fresh))}")
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> MasterKeyRestoreAsync(IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var copy = AnsiConsole.Prompt(new TextPrompt<string>("Recovery copy of the master key (base64 or the 32 words):").Secret());
        var key = KeyWords.Decode(copy);
        try
        {
            var tpm = (await shell.RunAsync("systemd-creds", ["has-tpm2", "--quiet"], cancellationToken: ct).ConfigureAwait(false)).Succeeded;
            shell.CreateDirectory(Paths.Credentials, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await shell.RunCheckedAsync("systemd-creds", ["encrypt", "--name=master-key", $"--with-key={(tpm ? "host+tpm2" : "host")}", "-", Paths.Credential("master-key")],
                Convert.ToBase64String(key), cancellationToken: ct).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        await output.WriteLineAsync($"The master key credential is written to {Paths.Credential("master-key")}. Start the services: systemctl start vaulty.target").ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> DatabaseAsync(string[] args, IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var context = await Reports.InstalledAsync(shell, output, ct).ConfigureAwait(false);
        var pgbackrest = $"{Paths.Current}/bin/vaulty-pgbackrest";
        switch (args.FirstOrDefault())
        {
            case "backup-now":
                await output.WriteLineAsync(await shell.RunCheckedAsync(pgbackrest, ["backup", "--type=full"], cancellationToken: ct).ConfigureAwait(false)).ConfigureAwait(false);
                return 0;
            case "verify":
                await output.WriteLineAsync(await shell.RunCheckedAsync(pgbackrest, ["check"], cancellationToken: ct).ConfigureAwait(false)).ConfigureAwait(false);
                return 0;
            case "restore" when Option(args, "--target-time") is { } time:
                await Installer.StopVaultyAsync(shell, context.Workers, ct).ConfigureAwait(false);
                await shell.SystemctlAsync("stop", "postgresql@17-main").ConfigureAwait(false);
                await shell.RunCheckedAsync(pgbackrest, ["restore", "--delta", "--type=time", $"--target={time}", "--target-action=promote"], cancellationToken: ct).ConfigureAwait(false);
                await shell.SystemctlAsync("start", "postgresql@17-main").ConfigureAwait(false);
                foreach (var unit in Paths.Services(context.Workers)) await shell.RunAsync("systemctl", ["start", unit], cancellationToken: ct).ConfigureAwait(false);
                var failures = await Health.CheckAsync(shell, context.Workers, TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
                await output.WriteLineAsync(failures.Count == 0 ? $"Restored to {time}; healthy." : "Restored, but: " + string.Join("; ", failures)).ConfigureAwait(false);
                return failures.Count == 0 ? 0 : 1;
            default:
                throw new InstallException("Use: vaulty db backup-now | verify | restore --target-time \"2026-11-09 14:00:00+00\"");
        }
    }

    private static async Task<int> LogsAsync(string[] args, IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var unit = args.FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal) && a != Option(args, "--since")) ?? "vaulty-*";
        var result = await shell.RunAsync("journalctl", ["-u", unit, "--since", Option(args, "--since") ?? "-1h", "--no-pager", "-o", "short-iso"], cancellationToken: ct)
            .ConfigureAwait(false);
        await output.WriteLineAsync(Redaction.Apply(result.Output)).ConfigureAwait(false);
        return result.ExitCode;
    }

    private static async Task<int> UninstallAsync(string[] args, IHostShell shell, TextWriter output, CancellationToken ct)
    {
        var purge = Flag(args, "--purge");
        var host = await HostProbe.ReadAsync(shell, ct).ConfigureAwait(false);
        if (purge && Option(args, "--confirm") != host.Hostname)
        {
            throw new InstallException($"--purge deletes the database, all configuration and the data disk contents. Confirm with --confirm {host.Hostname}.");
        }
        var workers = 64;
        foreach (var unit in Paths.Services(workers).Reverse().Append("vaulty-update-check.timer").Append("vaulty-migrate.service").Append("vaulty.target"))
        {
            await shell.RunAsync("systemctl", ["disable", "--now", unit], cancellationToken: ct).ConfigureAwait(false);
        }
        await shell.RunAsync("docker", ["compose", "-p", "vaulty", "down", "--volumes", "--remove-orphans"], cancellationToken: ct).ConfigureAwait(false);
        foreach (var unit in Paths.UnitTemplates) if (shell.FileExists(Paths.Join(Paths.Units, unit))) shell.DeleteFile(Paths.Join(Paths.Units, unit));
        await shell.SystemctlAsync("daemon-reload").ConfigureAwait(false);
        shell.DeleteDirectory(Paths.Root);
        if (!purge)
        {
            await output.WriteLineAsync("Vaulty services and binaries are removed. Configuration, credentials, the database and data stay; remove them with --purge.").ConfigureAwait(false);
            return 0;
        }
        await shell.RunAsync("pg_dropcluster", ["--stop", "17", "main"], cancellationToken: ct).ConfigureAwait(false);
        shell.DeleteDirectory("/etc/systemd/system/postgresql@17-main.service.d");
        await shell.RunAsync("rm", ["-f", "/etc/caddy/Caddyfile", "/etc/pgbackrest/pgbackrest.conf", "/etc/sysctl.d/60-vaulty.conf",
            "/etc/apt/apt.conf.d/52vaulty-unattended-upgrades", "/etc/needrestart/conf.d/50-vaulty.conf", "/etc/postgresql-common/createcluster.d/50-vaulty.conf"],
            cancellationToken: ct).ConfigureAwait(false);
        await shell.RunAsync("systemctl", ["stop", "caddy"], cancellationToken: ct).ConfigureAwait(false);
        if ((await shell.RunAsync("findmnt", ["-n", Paths.Data], cancellationToken: ct).ConfigureAwait(false)).Succeeded)
        {
            await shell.RunAsync("umount", [Paths.Data], cancellationToken: ct).ConfigureAwait(false);
            await shell.RunAsync("cryptsetup", ["close", "vaulty-data"], cancellationToken: ct).ConfigureAwait(false);
        }
        await shell.RunAsync("sed", ["-i", "/vaulty-data/d", "/etc/fstab", "/etc/crypttab"], cancellationToken: ct).ConfigureAwait(false);
        foreach (var directory in new[] { Paths.Etc, Paths.Lib, Paths.Data }) shell.DeleteDirectory(directory);
        foreach (var user in Paths.ServiceUsers) await shell.RunAsync("userdel", [user], cancellationToken: ct).ConfigureAwait(false);
        await shell.RunAsync("groupdel", ["vaulty"], cancellationToken: ct).ConfigureAwait(false);
        await output.WriteLineAsync("Vaulty is removed from this host, with its users, units, configuration, credentials and data. Installation reports in /root are yours to delete.")
            .ConfigureAwait(false);
        return 0;
    }
}
