using System.Text.Json;

namespace Vaulty.Cli;

/// <summary>
/// vaulty update (§12): verify, stop in order, migrate with the new binaries, switch the release link, start in order,
/// health check; on failure switch back, start the previous release and check again.
/// </summary>
public sealed class Updater(IHostShell shell, TextWriter log)
{
    public const string BaseUrlVariable = "VAULTY_RELEASE_BASE_URL";
    public const string SkipSignatureVariable = "VAULTY_SKIP_SIGNATURE_CHECK";
    public const string Repository = "404-developer-AI/vaulty";

    public TimeSpan HealthTimeout { get; init; } = TimeSpan.FromSeconds(120);

    public async Task<int> UpdateAsync(string? releaseDirectory, string? version, bool acceptFormatChange, bool force, CancellationToken ct = default)
    {
        var context = await Reports.InstalledAsync(shell, log, ct).ConfigureAwait(false);
        var current = context.ReleaseDirectory;
        var target = releaseDirectory ?? await DownloadAsync(version ?? "latest", ct).ConfigureAwait(false);
        if (string.Equals(Path.GetFullPath(target), Path.GetFullPath(current), StringComparison.Ordinal))
        {
            await log.WriteLineAsync($"Vaulty {context.Version} is already installed.").ConfigureAwait(false);
            return 0;
        }
        var notes = Paths.Join(target, "release.json");
        if (shell.FileExists(notes))
        {
            using var release = JsonDocument.Parse(shell.ReadFile(notes));
            if (release.RootElement.TryGetProperty("format_change", out var change) && change.GetBoolean() && !acceptFormatChange)
            {
                await log.WriteLineAsync("This release changes the repository format. Read the release notes, then run again with --accept-format-change.").ConfigureAwait(false);
                return 1;
            }
        }
        var restores = await shell.RunAsync("runuser", ["-u", "vaulty-worker", "--", "psql", "-h", "/var/run/postgresql", "-d", "vaulty", "-U", "vaulty_worker", "-tAc",
            "SELECT count(*) FROM vaulty.jobs WHERE kind IN ('restore', 'export') AND state = 'running'"], cancellationToken: ct).ConfigureAwait(false);
        if (restores.Output.Trim() is { Length: > 0 } running && running != "0" && !force)
        {
            await log.WriteLineAsync($"{running} restore(s) or export(s) are running. Wait for them, or update with --force.").ConfigureAwait(false);
            return 1;
        }

        await log.WriteLineAsync($"Updating {context.Version} -> {Path.GetFileName(target)}").ConfigureAwait(false);
        await StopAsync(context.Workers, ct).ConfigureAwait(false);
        var migrated = await shell.RunAsync("systemd-run", ["--quiet", "--wait", "--pipe", "--collect", "--uid=vaulty-migrator", "--gid=vaulty",
            Paths.Join(target, "bin", "vaulty-migrate")], cancellationToken: ct).ConfigureAwait(false);
        if (!migrated.Succeeded)
        {
            // Nothing switched yet: the previous release starts again unchanged (migrations are transactional).
            await log.WriteLineAsync($"The database migration failed; staying on {context.Version}: {Redaction.Apply(migrated.Error.Trim())}").ConfigureAwait(false);
            await StartAsync(context, current, ct).ConfigureAwait(false);
            return 1;
        }
        shell.Symlink(Paths.Previous, current);
        shell.Symlink(Paths.Current, target);
        var next = new InstallContext(shell, context.Answers, context.Host, target, Path.GetFileName(target), log) { SignatureVerified = context.SignatureVerified };
        foreach (var (k, v) in context.Values) next.Values[k] = v;
        await StartAsync(next, target, ct).ConfigureAwait(false);
        var failures = await Health.CheckAsync(shell, context.Workers, HealthTimeout, ct).ConfigureAwait(false);
        if (failures.Count == 0)
        {
            foreach (var old in shell.ListDirectories(Paths.Releases).Where(r => r != target && r != current)) shell.DeleteDirectory(old);
            shell.WriteFile($"{Paths.State}/version", next.Version + "\n", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            await log.WriteLineAsync($"Vaulty {next.Version} is running; {context.Version} is kept for vaulty update --rollback.").ConfigureAwait(false);
            return 0;
        }

        await log.WriteLineAsync("The new release failed its health check: " + string.Join("; ", failures)).ConfigureAwait(false);
        var journal = await shell.RunAsync("journalctl", ["-u", "vaulty-*", "--since", "-5min", "-n", "40", "--no-pager"], cancellationToken: ct).ConfigureAwait(false);
        await log.WriteLineAsync(Redaction.Apply(journal.Output)).ConfigureAwait(false);
        await RollBackAsync(context, current, ct).ConfigureAwait(false);
        return 2;
    }

    public async Task<int> RollbackAsync(CancellationToken ct = default)
    {
        var context = await Reports.InstalledAsync(shell, log, ct).ConfigureAwait(false);
        var previous = shell.ReadLink(Paths.Previous) ?? throw new InstallException("There is no previous release to roll back to.");
        await StopAsync(context.Workers, ct).ConfigureAwait(false);
        await RollBackAsync(context, previous, ct).ConfigureAwait(false);
        return 0;
    }

    private async Task RollBackAsync(InstallContext context, string release, CancellationToken ct)
    {
        await StopAsync(context.Workers, ct).ConfigureAwait(false);
        shell.Symlink(Paths.Current, release);
        var back = new InstallContext(shell, context.Answers, context.Host, release, Path.GetFileName(release), log) { SignatureVerified = context.SignatureVerified };
        foreach (var (k, v) in context.Values) back.Values[k] = v;
        await StartAsync(back, release, ct).ConfigureAwait(false);
        var failures = await Health.CheckAsync(shell, context.Workers, HealthTimeout, ct).ConfigureAwait(false);
        shell.WriteFile($"{Paths.State}/version", back.Version + "\n", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        await log.WriteLineAsync(failures.Count == 0
            ? $"Rolled back to {back.Version}; it is healthy."
            : $"Rolled back to {back.Version}, but it is not healthy either: {string.Join("; ", failures)}").ConfigureAwait(false);
    }

    /// <summary>Workers first (they hand running activities back to Temporal), then gc, api and web; Caddy keeps answering.</summary>
    private async Task StopAsync(int workers, CancellationToken ct)
    {
        foreach (var unit in Enumerable.Range(1, workers).Select(i => $"vaulty-worker@{i}.service").Append("vaulty-gc.service").Append("vaulty-api.service").Append("vaulty-web.service"))
        {
            await shell.RunAsync("systemctl", ["stop", unit], cancellationToken: ct).ConfigureAwait(false);
        }
    }

    private async Task StartAsync(InstallContext context, string release, CancellationToken ct)
    {
        InstallSteps.RenderCompose(context, release);
        await InstallSteps.InstallUnitsAsync(context, release, ct).ConfigureAwait(false);
        await InstallSteps.RenderCaddyAsync(context, ct).ConfigureAwait(false);
        await shell.RunAsync("systemctl", ["restart", "vaulty-temporal.service"], cancellationToken: ct).ConfigureAwait(false);
        foreach (var unit in Paths.Services(context.Workers).Skip(1))
        {
            await shell.RunAsync("systemctl", ["start", unit], cancellationToken: ct).ConfigureAwait(false);
        }
    }

    /// <summary>Downloads a release like get-vaulty.sh: tarball, SHA256SUMS and its cosign bundle, verified before anything is unpacked.</summary>
    public async Task<string> DownloadAsync(string version, CancellationToken ct)
    {
        if (version == "latest") version = await LatestAsync(ct).ConfigureAwait(false) ?? throw new InstallException("The latest release could not be determined.");
        version = version.TrimStart('v');
        if (version.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_'))) throw new InstallException($"Invalid version '{version}'.");
        var directory = Paths.Join(Paths.Releases, version);
        if (shell.FileExists(Paths.Join(directory, "bin", "vaulty"))) return directory;
        var baseUrl = (Environment.GetEnvironmentVariable(BaseUrlVariable) ?? $"https://github.com/{Repository}/releases/download") + $"/v{version}";
        var work = $"/tmp/vaulty-update-{Guid.NewGuid():N}";
        shell.CreateDirectory(work, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var tarball = $"vaulty-{version}-linux-x64.tar.gz";
            foreach (var file in new[] { tarball, "SHA256SUMS", "SHA256SUMS.sigstore.json" })
            {
                if (file.EndsWith(".json", StringComparison.Ordinal) && Environment.GetEnvironmentVariable(SkipSignatureVariable) == "1") continue;
                await shell.RunCheckedAsync("curl", ["-fsSL", "-o", $"{work}/{file}", $"{baseUrl}/{file}"], cancellationToken: ct).ConfigureAwait(false);
            }
            if (Environment.GetEnvironmentVariable(SkipSignatureVariable) == "1")
            {
                await log.WriteLineAsync("WARNING: signature verification is DISABLED (VAULTY_SKIP_SIGNATURE_CHECK=1). Never on a production host.").ConfigureAwait(false);
            }
            else
            {
                await shell.RunCheckedAsync("cosign", ["verify-blob", "--bundle", $"{work}/SHA256SUMS.sigstore.json",
                    "--certificate-identity-regexp", $"^https://github.com/{Repository}/\\.github/workflows/release\\.yml@refs/tags/v",
                    "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", $"{work}/SHA256SUMS"], cancellationToken: ct).ConfigureAwait(false);
            }
            await shell.RunCheckedAsync("sh", ["-c", $"cd '{work}' && grep -E '  {tarball}$' SHA256SUMS | sha256sum -c --quiet -"], cancellationToken: ct).ConfigureAwait(false);
            shell.CreateDirectory(directory + ".partial", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead
                                                       | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            await shell.RunCheckedAsync("tar", ["-xzf", $"{work}/{tarball}", "-C", directory + ".partial", "--strip-components=1"], cancellationToken: ct).ConfigureAwait(false);
            await shell.RunCheckedAsync("mv", [directory + ".partial", directory], cancellationToken: ct).ConfigureAwait(false);
            return directory;
        }
        finally
        {
            shell.DeleteDirectory(work);
        }
    }

    public async Task<string?> LatestAsync(CancellationToken ct)
    {
        var answer = await shell.RunAsync("curl", ["-fsSL", "-H", "Accept: application/vnd.github+json", $"https://api.github.com/repos/{Repository}/releases/latest"],
            cancellationToken: ct).ConfigureAwait(false);
        if (!answer.Succeeded) return null;
        using var release = JsonDocument.Parse(answer.Output);
        return release.RootElement.GetProperty("tag_name").GetString()?.TrimStart('v');
    }
}
