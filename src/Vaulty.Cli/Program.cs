using Vaulty.Cli;

// vaulty: installer, updater and host management for an all-in-one Vaulty host (Ubuntu 24.04, run as root).
if (OperatingSystem.IsWindows())
{
    await Console.Error.WriteLineAsync("vaulty runs on Ubuntu 24.04 LTS only.").ConfigureAwait(false);
    return 1;
}
return await CliApp.RunAsync(args, new LinuxHostShell(), Console.Out, Console.Error).ConfigureAwait(false);
