using System.Text.Json;
using Vaulty.Cli;

namespace Vaulty.Integration.Tests.Cli;

/// <summary>A host in memory: files, links and scripted process results; every command is recorded with its input.</summary>
internal sealed class FakeHost : IHostShell
{
    public const string Release = "/opt/vaulty/releases/0.1.0";
    public const string NextRelease = "/opt/vaulty/releases/0.1.1";
    public static readonly string SetupToken = new('c', 40);
    private static readonly string Repository = FindRepository();

    public Dictionary<string, string> Files { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, string> Links { get; } = new(StringComparer.Ordinal);
    public HashSet<string> Directories { get; } = new(StringComparer.Ordinal);
    public List<(string File, string[] Args, string? Input, IReadOnlyDictionary<string, string>? Environment)> Commands { get; } = [];
    public Func<string, string[], ProcessResult?> Script { get; set; } = (_, _) => null;

    public FakeHost()
    {
        foreach (var release in new[] { Release, NextRelease })
        {
            Directories.Add(release);
            Files[$"{release}/compose/images.json"] = """
                {"temporal":{"version":"1.29.1","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},
                 "temporal-ui":{"version":"2.40.1","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"},
                 "valkey":{"version":"8.1.3","digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333"},
                 "admin-tools":{"version":"1.29.1","digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444"}}
                """;
        }
        Files["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        Files["/proc/meminfo"] = "MemTotal:       16384000 kB\n";
    }

    private static string FindRepository()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            if (File.Exists(Path.Combine(d.FullName, "Vaulty.slnx"))) return d.FullName;
        }
        throw new InvalidOperationException("repository root not found");
    }

    /// <summary>A release directory reads the real templates of the repository: templates/ and compose/ come from deploy/install.</summary>
    private static string? FromRepository(string path)
    {
        foreach (var release in new[] { Release, NextRelease })
        {
            if (!path.StartsWith(release + "/", StringComparison.Ordinal)) continue;
            var rest = path[(release.Length + 1)..];
            if (rest.StartsWith("templates/", StringComparison.Ordinal)) rest = rest["templates/".Length..];
            var file = Path.Combine(Repository, "deploy", "install", rest.Replace('/', Path.DirectorySeparatorChar));
            return File.Exists(file) ? File.ReadAllText(file) : null;
        }
        return null;
    }

    public Task<ProcessResult> RunAsync(string file, IReadOnlyList<string> args, string? input = null, IReadOnlyDictionary<string, string>? environment = null,
        CancellationToken cancellationToken = default)
    {
        if (file == "timeout") return RunAsync(args[1], args.Skip(2).ToList(), input, environment, cancellationToken); // coreutils timeout <seconds> <command>
        var a = args.ToArray();
        Commands.Add((file, a, input, environment));
        var scripted = Script(file, a);
        if (scripted is not null) return Task.FromResult(scripted);
        // systemd-creds keeps what it encrypts (as plain text in this fake) and gives it back on decrypt.
        if (file == "systemd-creds" && a[0] == "encrypt") { Files[a[^1]] = input ?? ""; return Task.FromResult(new ProcessResult(0, "", "")); }
        if (file == "systemd-creds" && a[0] == "decrypt") return Task.FromResult(Files.TryGetValue(a[^2], out var plain) ? new ProcessResult(0, plain, "") : new ProcessResult(1, "", "no such credential"));
        var output = (file, a.FirstOrDefault()) switch
        {
            ("nproc", _) => "8",
            ("uname", _) => "x86_64",
            ("hostname", _) => "vaulty-test.example.com",
            ("systemctl", "is-active") => "active",
            ("docker", "run") when a.Contains("health") => "SERVING",
            ("sh", "-c") when a[1].Contains("valkey-cli", StringComparison.Ordinal) => "PONG",
            ("runuser", _) when a.Contains("SELECT 1") => "1",
            ("runuser", _) when a.Contains("count(*)", StringComparer.Ordinal) || a.Any(x => x.Contains("count(*)", StringComparison.Ordinal)) => "0",
            ("systemd-run", _) when a.Contains("setup-token") => SetupToken,
            ("stat", _) => "700",
            ("ufw", "status") => "Status: active",
            ("systemd-analyze", _) => $"→ Overall exposure level for {a.Last()}: 1.8 OK",
            ("systemd-creds", "has-tpm2") => "",
            _ => "",
        };
        var exit = (file, a.FirstOrDefault()) switch
        {
            ("getent", _) or ("id", _) or ("findmnt", _) or ("blkid", _) or ("cryptsetup", "isLuks") => 1,
            ("systemd-creds", "has-tpm2") => 1,
            ("docker", "run") when a.Contains("describe-schema") => 1,
            ("docker", "run") when a.Contains("describe") && a.Contains("namespace") => 1,
            _ => 0,
        };
        return Task.FromResult(new ProcessResult(exit, output, ""));
    }

    public bool FileExists(string path) => Files.ContainsKey(path) || FromRepository(path) is not null;
    public bool DirectoryExists(string path) => Directories.Contains(path);
    public string ReadFile(string path) => Files.TryGetValue(path, out var c) ? c : FromRepository(path) ?? throw new FileNotFoundException(path);
    public void WriteFile(string path, string content, UnixFileMode mode) { Files[path] = content; Modes[path] = mode; }
    public Dictionary<string, UnixFileMode> Modes { get; } = new(StringComparer.Ordinal);
    public void CreateDirectory(string path, UnixFileMode mode) => Directories.Add(path);
    public void DeleteFile(string path) => Files.Remove(path);
    public void DeleteDirectory(string path) { Directories.Remove(path); foreach (var f in Files.Keys.Where(k => k.StartsWith(path + "/", StringComparison.Ordinal)).ToList()) Files.Remove(f); }
    public void Symlink(string link, string target) => Links[link] = target;
    public string? ReadLink(string path) => Links.GetValueOrDefault(path);
    public IReadOnlyList<string> ListDirectories(string path) => Directories.Where(d => Path.GetDirectoryName(d)?.Replace('\\', '/') == path).ToList();

    public IEnumerable<string> CommandLines => Commands.Select(c => $"{c.File} {string.Join(' ', c.Args)}");
}

public sealed class CliTests
{
    private static readonly InstallAnswers Answers = new() { Fqdn = "backup.example.com", AdminEmail = "admin@example.com", Environment = "staging", Workers = 2 };
    private static readonly HostFacts Host = new("vaulty-test.example.com", 8, 16000, false, "ubuntu", "24.04", "x86_64");

    private static InstallContext Context(FakeHost host, TextWriter? log = null, InstallAnswers? answers = null) =>
        new(host, answers ?? Answers, Host, FakeHost.Release, "0.1.0", log ?? TextWriter.Null) { SignatureVerified = true };

    [Fact]
    public void The_example_answers_file_parses_and_validates()
    {
        var host = new FakeHost();
        var answers = InstallAnswers.Parse(host.ReadFile($"{FakeHost.Release}/answers.example.yaml"));
        Assert.Equal(("backup.example.com", "admin@example.com", "/dev/sdb", 4, "Europe/Brussels"), (answers.Fqdn, answers.AdminEmail, answers.DataDisk, answers.Workers!.Value, answers.TimeZone));
        Assert.Equal("Vaulty <vaulty@example.com>", answers.Smtp!.From);
        Assert.Equal(30, answers.PgBackRest!.RetentionFull);
        Assert.Empty(answers.Validate(8));
        Assert.NotEmpty((answers with { Fqdn = "not a host" }).Validate(8));
        Assert.NotEmpty((answers with { AutoUpdate = "patch" }).Validate(8)); // production
        Assert.NotEmpty((answers with { Workers = 9 }).Validate(8));
    }

    [Fact]
    public async Task A_full_installation_runs_every_step_renders_every_template_and_never_puts_a_secret_on_a_command_line()
    {
        var host = new FakeHost();
        using var log = new StringWriter();
        var result = await new Installer().RunAsync(Context(host, log), resume: false);
        Assert.True(result == 0, log.ToString());

        // Every template of the release rendered completely.
        foreach (var unit in Paths.UnitTemplates) Assert.Empty(Templates.PlaceholdersOf(host.Files[$"/etc/systemd/system/{unit}"]));
        foreach (var file in new[] { "/etc/caddy/Caddyfile", $"{Paths.PgConf}/conf.d/50-vaulty.conf", $"{Paths.PgConf}/pg_hba.conf", $"{Paths.PgConf}/pg_ident.conf",
                     $"{FakeHost.Release}/compose/temporal.compose.yml" })
        {
            Assert.Empty(Templates.PlaceholdersOf(host.Files[file]));
        }
        Assert.Contains("@sha256:1111", host.Files[$"{FakeHost.Release}/compose/temporal.compose.yml"], StringComparison.Ordinal);
        Assert.Contains("backup.example.com", host.Files["/etc/caddy/Caddyfile"], StringComparison.Ordinal);
        // A staging host is opened in ordinary browsers: it gets the trusted CA, not the Let's Encrypt staging CA.
        Assert.Contains("acme_ca https://acme-v02.api.letsencrypt.org/directory", host.Files["/etc/caddy/Caddyfile"], StringComparison.Ordinal);
        Assert.Contains("  [ ok ] report", log.ToString(), StringComparison.Ordinal);

        // The report: written 0600, with the one-time secrets and the first-administrator link.
        var report = Assert.Single(host.Files, f => f.Key.StartsWith("/root/vaulty-install-report-", StringComparison.Ordinal));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, host.Modes[report.Key]);
        Assert.Empty(Templates.PlaceholdersOf(report.Value));
        Assert.Contains($"https://backup.example.com/setup?token={FakeHost.SetupToken}", report.Value, StringComparison.Ordinal);
        var masterKey = host.Commands.Single(c => c.File == "systemd-creds" && c.Args[0] == "encrypt" && c.Args.Contains("--name=master-key")).Input!;
        Assert.Contains(masterKey, report.Value, StringComparison.Ordinal);
        Assert.Contains("not present; master key bound to the host key only", report.Value, StringComparison.Ordinal);

        // vaulty.json holds no secret; secrets travel on standard input or as a one-off container environment, never as arguments.
        var temporalPassword = host.Commands.Single(c => c.File == "systemd-creds" && c.Args[0] == "encrypt" && c.Args.Contains("--name=temporal-db")).Input!;
        var valkeyPassword = host.Commands.Single(c => c.File == "systemd-creds" && c.Args[0] == "encrypt" && c.Args.Contains("--name=valkey")).Input!;
        foreach (var secret in new[] { masterKey, temporalPassword, valkeyPassword })
        {
            Assert.DoesNotContain(host.CommandLines, line => line.Contains(secret, StringComparison.Ordinal));
            Assert.DoesNotContain(secret, host.Files[Paths.Config], StringComparison.Ordinal);
        }
        Assert.Contains(host.Commands, c => c.File == "runuser" && c.Input is { } i && i.Contains("temporal_password", StringComparison.Ordinal) && i.Contains(temporalPassword, StringComparison.Ordinal));
        using (var config = JsonDocument.Parse(host.Files[Paths.Config]))
        {
            Assert.Equal("backup.example.com", config.RootElement.GetProperty("Vaulty").GetProperty("PublicHost").GetString());
        }

        // Order: migrations before the services; temporal before api, web, workers and gc.
        var lines = host.CommandLines.ToList();
        int At(string text) => lines.FindIndex(l => l.Contains(text, StringComparison.Ordinal));
        Assert.True(At("start vaulty-migrate.service") < At("enable --now vaulty-api.service"));
        Assert.True(At("enable --now vaulty-temporal.service") < At("enable --now vaulty-api.service"));
        Assert.True(At("enable --now vaulty-worker@2.service") < At("enable --now vaulty-gc.service"));
        Assert.Equal(FakeHost.Release, host.Links[Paths.Current]);
        // systemd refuses to start a unit whose ReadWritePaths do not exist.
        foreach (var unit in Paths.UnitTemplates)
        {
            foreach (var line in host.Files[$"/etc/systemd/system/{unit}"].Split(Environment.NewLine.Last()).Where(l => l.StartsWith("ReadWritePaths=", StringComparison.Ordinal)))
            {
                foreach (var path in line["ReadWritePaths=".Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries)) Assert.True(host.DirectoryExists(path), $"{unit}: {path} is not created");
            }
        }
        Assert.False(host.FileExists(Paths.InstallState));
        Assert.False(host.FileExists(Paths.PendingReport));
    }

    [Fact]
    public async Task A_failed_step_stops_everything_and_resume_continues_where_it_stopped()
    {
        var host = new FakeHost();
        var failCaddy = true;
        host.Script = (file, args) => failCaddy && file == "apt-get" && args.Contains("caddy") ? new ProcessResult(100, "", "E: Unable to locate package caddy") : null;
        using var log = new StringWriter();
        Assert.Equal(1, await new Installer().RunAsync(Context(host, log), resume: false));
        Assert.Contains("[fail] caddy", log.ToString(), StringComparison.Ordinal);
        Assert.Contains("vaulty install --resume", log.ToString(), StringComparison.Ordinal);
        Assert.Contains(host.CommandLines, l => l == "systemctl stop vaulty-web.service");
        var completed = JsonSerializer.Deserialize<List<string>>(host.Files[Paths.InstallState])!;
        Assert.Contains("vaulty services", completed);
        Assert.DoesNotContain("caddy", completed);
        Assert.True(host.FileExists(Paths.PendingReport));
        // The report secrets of the first run are kept (encrypted) for the resumed run.
        var pending = host.Commands.Last(c => c.Args.Contains("--name=pending-report") && c.Args[0] == "encrypt").Input!;
        // A new run without --resume is refused while an unfinished installation exists.
        await Assert.ThrowsAsync<InstallException>(() => new Installer().RunAsync(Context(host), resume: false));

        failCaddy = false;
        host.Commands.Clear();
        host.Script = (_, _) => null;
        using var again = new StringWriter();
        Assert.Equal(0, await new Installer().RunAsync(Context(host, again), resume: true));
        Assert.Contains("[done] postgresql", again.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(host.CommandLines, l => l.StartsWith("pg_createcluster", StringComparison.Ordinal));
        Assert.DoesNotContain(host.Commands, c => c.Args.Contains("--name=master-key"));
        var report = Assert.Single(host.Files, f => f.Key.StartsWith("/root/vaulty-install-report-", StringComparison.Ordinal)).Value;
        Assert.Contains(JsonSerializer.Deserialize<ReportSecrets>(pending)!.MasterKey, report, StringComparison.Ordinal);
    }

    private static async Task<FakeHost> InstalledAsync()
    {
        var host = new FakeHost();
        Assert.Equal(0, await new Installer().RunAsync(Context(host), resume: false));
        host.Commands.Clear();
        return host;
    }

    [Fact]
    public async Task An_update_switches_after_migrating_and_a_failing_health_check_rolls_back()
    {
        var host = await InstalledAsync();
        using var log = new StringWriter();
        var updater = new Updater(host, log) { HealthTimeout = TimeSpan.Zero };
        Assert.Equal(0, await updater.UpdateAsync(FakeHost.NextRelease, null, false, false));
        Assert.Equal(FakeHost.NextRelease, host.Links[Paths.Current]);
        Assert.Equal(FakeHost.Release, host.Links[Paths.Previous]);
        var lines = host.CommandLines.ToList();
        int At(string text) => lines.FindIndex(l => l.Contains(text, StringComparison.Ordinal));
        Assert.True(At("stop vaulty-worker@1.service") < At("stop vaulty-web.service"), "workers stop first");
        Assert.True(At($"{FakeHost.NextRelease}/bin/vaulty-migrate") < At("start vaulty-api.service"), "migrations run with the new binaries before the start");
        Assert.Contains($"{FakeHost.NextRelease}/compose", host.Files.Keys.First(k => k.EndsWith("temporal.compose.yml", StringComparison.Ordinal) && k.StartsWith(FakeHost.NextRelease, StringComparison.Ordinal)), StringComparison.Ordinal);

        // A release whose web service does not come up: rolled back to the previous one automatically.
        host.Links[Paths.Current] = FakeHost.Release;
        host.Links.Remove(Paths.Previous);
        host.Script = (file, args) => file == "curl" && args.Contains("http://127.0.0.1:5000/healthz") && host.Links[Paths.Current] == FakeHost.NextRelease
            ? new ProcessResult(7, "", "connection refused") : null;
        using var failing = new StringWriter();
        Assert.Equal(2, await new Updater(host, failing) { HealthTimeout = TimeSpan.Zero }.UpdateAsync(FakeHost.NextRelease, null, false, false));
        Assert.Equal(FakeHost.Release, host.Links[Paths.Current]);
        Assert.Contains("Rolled back to 0.1.0; it is healthy.", failing.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_update_refuses_a_format_change_without_consent_and_while_a_restore_runs()
    {
        var host = await InstalledAsync();
        host.Files[$"{FakeHost.NextRelease}/release.json"] = """{"version":"0.1.1","format_change":true}""";
        using var log = new StringWriter();
        Assert.Equal(1, await new Updater(host, log).UpdateAsync(FakeHost.NextRelease, null, false, false));
        Assert.Contains("--accept-format-change", log.ToString(), StringComparison.Ordinal);
        host.Files.Remove($"{FakeHost.NextRelease}/release.json");
        host.Script = (file, args) => file == "runuser" && args.Any(a => a.Contains("restore", StringComparison.Ordinal)) ? new ProcessResult(0, "2", "") : null;
        Assert.Equal(1, await new Updater(host, log).UpdateAsync(FakeHost.NextRelease, null, false, false));
        Assert.Contains("restore(s) or export(s) are running", log.ToString(), StringComparison.Ordinal);
        Assert.Equal(FakeHost.Release, host.Links[Paths.Current]);
    }

    [Fact]
    public async Task Doctor_finds_secrets_in_files_weak_units_and_open_database_access()
    {
        var host = await InstalledAsync();
        Assert.Empty(await Doctor.CheckAsync(host, 2, CancellationToken.None));
        host.Files[Paths.Config] = host.Files[Paths.Config].Replace("\"Install\": {", "\"Install\": {\n    \"SmtpPassword\": \"hunter2-example\",", StringComparison.Ordinal);
        host.Files[$"{Paths.PgConf}/pg_hba.conf"] += "\nhost all all 10.0.0.0/8 scram-sha-256\n";
        host.Script = (file, args) => file == "systemd-analyze" && args.Last() == "vaulty-web.service" ? new ProcessResult(0, "→ Overall exposure level for vaulty-web.service: 4.7 OK", "") : null;
        var findings = await Doctor.CheckAsync(host, 2, CancellationToken.None);
        Assert.Contains(findings, f => f.Contains("looks like a secret", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Contains("beyond loopback", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Contains("vaulty-web.service: systemd-analyze security exposure 4.7", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Uninstall_purge_needs_the_hostname_and_removes_users_units_and_data()
    {
        var host = await InstalledAsync();
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(1, await CliApp.RunAsync(["uninstall", "--purge"], host, output, error, checkRoot: false));
        Assert.Contains("--confirm vaulty-test.example.com", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, await CliApp.RunAsync(["uninstall", "--purge", "--confirm", "vaulty-test.example.com"], host, output, error, checkRoot: false));
        Assert.DoesNotContain(host.Files.Keys, k => k.StartsWith("/etc/systemd/system/vaulty", StringComparison.Ordinal) || k.StartsWith(Paths.Etc, StringComparison.Ordinal));
        foreach (var user in Paths.ServiceUsers) Assert.Contains($"userdel {user}", host.CommandLines);
        Assert.Contains("pg_dropcluster --stop 17 main", host.CommandLines);
    }

    [Fact]
    public void The_recovery_words_encode_every_byte_and_decode_back()
    {
        Assert.Equal(256, KeyWords.Count);
        Assert.Equal(256, KeyWords.Distinct);
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var words = KeyWords.Encode(key);
        Assert.Equal(8, words.Split("  ").Length);
        Assert.Equal(key, KeyWords.Decode(words));
        Assert.Equal(key, KeyWords.Decode(Convert.ToBase64String(key)));
        Assert.Throws<InstallException>(() => KeyWords.Decode("not a key"));
        Assert.Equal("password=[redacted] token: [redacted]", Redaction.Apply("password=abc123 token: xyz"));
    }

    [Fact]
    public void Tuning_gives_postgres_a_quarter_and_never_starves_a_small_host()
    {
        var small = Tuning.Values(Host with { RamMb = 8192, Vcpu = 4 }, 2);
        Assert.Equal("2GB", small["SHARED_BUFFERS"]);
        Assert.Equal("6GB", small["EFFECTIVE_CACHE_SIZE"]);
        var large = Tuning.Values(Host with { RamMb = 32768, Vcpu = 8 }, 4);
        Assert.Equal("8GB", large["SHARED_BUFFERS"]);
        Assert.Equal(4, Tuning.DefaultWorkers(8));
        Assert.Equal(1, Tuning.DefaultWorkers(1));
    }
}
