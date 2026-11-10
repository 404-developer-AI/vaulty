using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using MimeKit;
using Vaulty.Core.Crypto;
using Vaulty.Infrastructure.Access;
using Vaulty.Infrastructure.Database;
using Vaulty.Infrastructure.Platform;
using Vaulty.Infrastructure.Secrets;
using Vaulty.Infrastructure.Storage;

namespace Vaulty.Cli;

/// <summary>
/// Work that needs the database and the master key. Root never opens the database itself: the CLI starts a copy of
/// itself with systemd-run as a service user (peer authentication maps it to exactly one role) with the master key as
/// that unit's credential, the same way the services run.
/// </summary>
public static class Internal
{
    public static Task<string> ViaServiceAsync(IHostShell shell, IReadOnlyList<string> args, string? input, CancellationToken ct, string user = "vaulty-web") =>
        shell.RunCheckedAsync("systemd-run", ["--quiet", "--wait", "--pipe", "--collect", $"--uid={user}", "--gid=vaulty",
            $"--property=LoadCredentialEncrypted=master-key:{Paths.Credential("master-key")}", "--setenv=VAULTY_CONFIG_DIR=/etc/vaulty",
            $"{Paths.Current}/bin/vaulty", "internal", .. args], input, cancellationToken: ct);

    public static async Task<int> RunAsync(string[] args, TextWriter output, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(args);
        using var config = JsonDocument.Parse(await File.ReadAllTextAsync(Paths.Join(Environment.GetEnvironmentVariable("VAULTY_CONFIG_DIR") ?? Paths.Etc, "vaulty.json"), ct)
            .ConfigureAwait(false));
        var vaulty = config.RootElement.GetProperty("Vaulty");
        var hostId = vaulty.TryGetProperty("HostId", out var h) ? h.GetString() ?? Environment.MachineName : Environment.MachineName;
        var version = vaulty.TryGetProperty("MasterKeyVersion", out var v) ? v.GetInt32() : 1;
        var role = Environment.UserName == "vaulty-migrator" ? "vaulty_migrator" : "vaulty_api";
        await using var dataSource = VaultyDataSource.Create($"Host=/var/run/postgresql;Database=vaulty;Username={role}");
        var masterKey = MasterKeys.Resolve(allowDevelopmentKey: false, version).ReadMasterKey();
        try
        {
            using var cipher = new SecretCipher(masterKey, hostId);
            var secrets = new PostgresSecretStore(dataSource, cipher, TimeProvider.System);
            switch (args.FirstOrDefault())
            {
                case "setup-token":
                    await output.WriteLineAsync(await new SetupTokens(secrets, dataSource, TimeProvider.System).IssueAsync("system:installer", ct).ConfigureAwait(false))
                        .ConfigureAwait(false);
                    return 0;
                case "secrets" when args.ElementAtOrDefault(1) == "list":
                    foreach (var s in await secrets.ListAsync(ct).ConfigureAwait(false))
                    {
                        await output.WriteLineAsync($"{s.Name,-40} v{s.Version,-4} {s.CreatedAt:yyyy-MM-dd HH:mm} {s.CreatedBy}").ConfigureAwait(false);
                    }
                    return 0;
                case "secrets" when args.ElementAtOrDefault(1) == "set" && args.Length >= 3:
                    var value = (await Console.In.ReadToEndAsync(ct).ConfigureAwait(false)).TrimEnd('\n');
                    var number = await secrets.SetAsync(args[2], System.Text.Encoding.UTF8.GetBytes(value), "system:cli", ct).ConfigureAwait(false);
                    await output.WriteLineAsync($"{args[2]} is now version {number}.").ConfigureAwait(false);
                    return 0;
                case "secrets" when args.ElementAtOrDefault(1) == "prune" && args.Length >= 4:
                    var removed = await secrets.PruneAsync(args[2], int.Parse(args[3], CultureInfo.InvariantCulture), ct).ConfigureAwait(false);
                    await output.WriteLineAsync($"{removed} older version(s) of {args[2]} removed.").ConfigureAwait(false);
                    return 0;
                case "smtp" when args.Length >= 5:
                    var from = MailboxAddress.Parse(args[4]);
                    var password = (await Console.In.ReadToEndAsync(ct).ConfigureAwait(false)).TrimEnd('\n');
                    await new PlatformSettings(dataSource).SetAsync(SmtpSettings.SettingKey, new SmtpSettings(args[1], int.Parse(args[2], CultureInfo.InvariantCulture),
                        int.Parse(args[2], CultureInfo.InvariantCulture) == 465 ? "ssl" : "starttls", args[3].Length == 0 ? null : args[3], from.Address,
                        string.IsNullOrEmpty(from.Name) ? "Vaulty" : from.Name), "system:installer", ct).ConfigureAwait(false);
                    if (password.Length > 0) await secrets.SetAsync(SmtpSettings.PasswordSecret, System.Text.Encoding.UTF8.GetBytes(password), "system:installer", ct).ConfigureAwait(false);
                    await output.WriteLineAsync("SMTP is set up; send a test message from Settings in the web interface.").ConfigureAwait(false);
                    return 0;
                case "rekey" when args.Length >= 3:
                    var fresh = Convert.FromBase64String((await Console.In.ReadToEndAsync(ct).ConfigureAwait(false)).Trim());
                    try
                    {
                        var result = await MasterKeyRekey.RekeyAsync(dataSource, masterKey, int.Parse(args[1], CultureInfo.InvariantCulture), fresh,
                            int.Parse(args[2], CultureInfo.InvariantCulture), hostId, cancellationToken: ct).ConfigureAwait(false);
                        await output.WriteLineAsync($"Re-encrypted {result.Secrets} secrets, {result.DataProtectionKeys} data protection keys and {result.TenantKeys} tenant keys.")
                            .ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(fresh);
                    }
                    return 0;
                default:
                    await output.WriteLineAsync("internal: unknown operation").ConfigureAwait(false);
                    return 2;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }
}
