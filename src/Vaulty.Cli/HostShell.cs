using System.Diagnostics;
using System.Text;

namespace Vaulty.Cli;

public sealed record ProcessResult(int ExitCode, string Output, string Error)
{
    public bool Succeeded => ExitCode == 0;
}

public sealed class InstallException(string message) : Exception(message);

/// <summary>
/// Everything the CLI does to the host goes through this interface: processes and files. The real implementation runs on
/// Ubuntu as root; tests use a recording fake, so the order and idempotency of every step is tested without a VM.
/// </summary>
public interface IHostShell
{
    Task<ProcessResult> RunAsync(string file, IReadOnlyList<string> args, string? input = null, IReadOnlyDictionary<string, string>? environment = null,
        CancellationToken cancellationToken = default);

    bool FileExists(string path);
    bool DirectoryExists(string path);
    string ReadFile(string path);
    void WriteFile(string path, string content, UnixFileMode mode);
    void CreateDirectory(string path, UnixFileMode mode);
    void DeleteFile(string path);
    void DeleteDirectory(string path);

    /// <summary>Points <paramref name="link"/> at <paramref name="target"/> atomically (a new link renamed over the old one).</summary>
    void Symlink(string link, string target);

    string? ReadLink(string path);
    IReadOnlyList<string> ListDirectories(string path);
}

public static class HostShellExtensions
{
    public static async Task<string> RunCheckedAsync(this IHostShell shell, string file, IReadOnlyList<string> args, string? input = null,
        IReadOnlyDictionary<string, string>? environment = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(shell);
        var result = await shell.RunAsync(file, args, input, environment, cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            var detail = string.IsNullOrWhiteSpace(result.Error) ? result.Output : result.Error;
            throw new InstallException($"{file} {string.Join(' ', args.Take(4))} failed ({result.ExitCode}): {Redaction.Apply(detail.Trim())}");
        }
        return result.Output;
    }

    public static Task<string> SystemctlAsync(this IHostShell shell, params string[] args) => shell.RunCheckedAsync("systemctl", args);
}

/// <summary>The host as root on Ubuntu 24.04.</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
public sealed class LinuxHostShell : IHostShell
{
    public static readonly TimeSpan MaxDuration = TimeSpan.FromMinutes(20);

    public async Task<ProcessResult> RunAsync(string file, IReadOnlyList<string> args, string? input = null, IReadOnlyDictionary<string, string>? environment = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        var start = new ProcessStartInfo(file)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        start.Environment["DEBIAN_FRONTEND"] = "noninteractive";
        start.Environment["LC_ALL"] = "C.UTF-8";
        if (environment is not null) foreach (var (k, v) in environment) start.Environment[k] = v;
        var verbose = Environment.GetEnvironmentVariable("VAULTY_INSTALL_VERBOSE") == "1";
        var started = Stopwatch.GetTimestamp();
        if (verbose) await Console.Error.WriteLineAsync($"      $ {Redaction.Apply(file + " " + string.Join(' ', args))}").ConfigureAwait(false);
        using var process = Process.Start(start) ?? throw new InstallException($"{file} could not be started.");
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        if (input is not null) await process.StandardInput.WriteAsync(input.AsMemory(), cancellationToken).ConfigureAwait(false);
        process.StandardInput.Close();
        // No step may hang the installer: a command that takes longer than this is stopped and reported.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(MaxDuration);
        try
        {
            await process.WaitForExitAsync(limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            process.Kill(entireProcessTree: true);
            return new ProcessResult(124, "", $"{file} did not finish within {MaxDuration.TotalMinutes:F0} minutes and was stopped.");
        }
        var result = new ProcessResult(process.ExitCode, await output.ConfigureAwait(false), await error.ConfigureAwait(false));
        if (verbose)
        {
            await Console.Error.WriteLineAsync($"        exit {result.ExitCode} after {Stopwatch.GetElapsedTime(started).TotalSeconds:F1} s"
                + (result.Succeeded ? "" : $": {Redaction.Apply(result.Error.Trim())}")).ConfigureAwait(false);
        }
        return result;
    }

    public bool FileExists(string path) => File.Exists(path);
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public string ReadFile(string path) => File.ReadAllText(path);

    public void WriteFile(string path, string content, UnixFileMode mode)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".vaulty-new";
        // Created with the final mode before any byte is written, then renamed over the old file.
        using (var stream = new FileStream(temporary, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = mode }))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
        {
            writer.Write(content);
        }
        File.SetUnixFileMode(temporary, mode);
        File.Move(temporary, path, overwrite: true);
    }

    public void CreateDirectory(string path, UnixFileMode mode) => Directory.CreateDirectory(path, mode);
    public void DeleteFile(string path) => File.Delete(path);

    public void DeleteDirectory(string path)
    {
        if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
    }

    public void Symlink(string link, string target)
    {
        var temporary = link + ".vaulty-new";
        if (File.Exists(temporary) || Directory.Exists(temporary)) File.Delete(temporary);
        File.CreateSymbolicLink(temporary, target);
        // rename(2) replaces the old link atomically; File.Move treats a link to a directory as a directory.
        if (Rename(temporary, link) != 0) throw new InstallException($"{link} could not be switched to {target} (errno {System.Runtime.InteropServices.Marshal.GetLastPInvokeError()}).");
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "rename", SetLastError = true)]
    private static extern int Rename([System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)] string oldPath,
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)] string newPath);

    public string? ReadLink(string path) => new FileInfo(path).LinkTarget;

    public IReadOnlyList<string> ListDirectories(string path) => Directory.Exists(path) ? Directory.GetDirectories(path) : [];
}

/// <summary>Removes values that look like secrets from text shown to the operator or written to logs.</summary>
public static class Redaction
{
    private static readonly System.Text.RegularExpressions.Regex Patterns = new(
        @"(?i)(password|passwd|pwd|secret|token|requirepass|cipher-pass|access[_-]?key)(\s*[=:]\s*|\s+)(\S+)",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    public static string Apply(string text) => Patterns.Replace(text ?? "", m => $"{m.Groups[1].Value}{m.Groups[2].Value}[redacted]");
}
