using System.Security.Cryptography;

namespace Vaulty.Infrastructure.Secrets;

/// <summary>
/// The host master key: the one secret that lives outside the encrypted secrets store. On a server it is a systemd
/// credential, decrypted by systemd (TPM2 and host key) into a private ramfs for the service. In development it comes
/// from <c>VAULTY_DEV_MASTER_KEY</c> or a per-user file outside the repository.
/// </summary>
public interface IMasterKeySource
{
    /// <summary>A copy of the 32-byte master key. The caller wipes it after use.</summary>
    byte[] ReadMasterKey();

    /// <summary>Increases with every rekey; recorded in wrapped keys so the right KEK is used.</summary>
    int Version { get; }

    /// <summary>Where the key came from, for status output (never the key).</summary>
    string Description { get; }
}

/// <summary>A fixed key, for tests and the recovery CLI (which gets the recovery copy from the operator).</summary>
public sealed class StaticMasterKeySource(byte[] key, int version = 1, string description = "provided") : IMasterKeySource
{
    private readonly byte[] _key = MasterKeys.Validate(key);

    public int Version { get; } = version;
    public string Description { get; } = description;
    public byte[] ReadMasterKey() => (byte[])_key.Clone();
}

/// <summary>Reads <c>$CREDENTIALS_DIRECTORY/master-key</c>, provided by systemd LoadCredentialEncrypted=.</summary>
public sealed class SystemdCredentialMasterKeySource(string credentialsDirectory, int version) : IMasterKeySource
{
    public const string CredentialName = "master-key";

    public int Version { get; } = version;
    public string Description => "systemd credential";

    public byte[] ReadMasterKey() => MasterKeys.Parse(File.ReadAllBytes(Path.Combine(credentialsDirectory, CredentialName)));
}

/// <summary>Development only: <c>VAULTY_DEV_MASTER_KEY</c> (base64) or a per-user key file created on first use.</summary>
public sealed class DevelopmentMasterKeySource : IMasterKeySource
{
    public const string EnvironmentVariable = "VAULTY_DEV_MASTER_KEY";
    private readonly string? _path;

    public DevelopmentMasterKeySource(string? path = null)
    {
        _path = path ?? DefaultPath();
    }

    public int Version => 1;
    public string Description => Environment.GetEnvironmentVariable(EnvironmentVariable) is { Length: > 0 }
        ? "development key from the environment"
        : $"development key file {_path}";

    public static string DefaultPath()
    {
        var root = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        return Path.Combine(root, "Vaulty", "dev-master-key");
    }

    public byte[] ReadMasterKey()
    {
        var fromEnvironment = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (!string.IsNullOrEmpty(fromEnvironment)) return MasterKeys.Parse(System.Text.Encoding.ASCII.GetBytes(fromEnvironment));

        var path = _path!;
        if (!File.Exists(path))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var key = RandomNumberGenerator.GetBytes(32);
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(path, options))
            {
                stream.Write(System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(key)));
            }
            return key;
        }
        return MasterKeys.Parse(File.ReadAllBytes(path));
    }
}

public static class MasterKeys
{
    /// <summary>Accepts 32 raw bytes or their base64 text (with optional surrounding white space).</summary>
    public static byte[] Parse(byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (content.Length == 32) return content;
        var text = System.Text.Encoding.ASCII.GetString(content).Trim();
        try
        {
            return Validate(Convert.FromBase64String(text));
        }
        catch (FormatException)
        {
            throw new CryptographicException("The master key is neither 32 bytes nor base64 of 32 bytes.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    public static byte[] Validate(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.Length == 32 ? key : throw new CryptographicException("The master key must be 32 bytes.");
    }

    /// <summary>
    /// Picks the master key source: the systemd credential when the service runs under systemd with one, otherwise the
    /// development key, but only when <paramref name="allowDevelopmentKey"/> is set (never in production).
    /// </summary>
    public static IMasterKeySource Resolve(bool allowDevelopmentKey, int version = 1)
    {
        var credentials = Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY");
        if (!string.IsNullOrEmpty(credentials) && File.Exists(Path.Combine(credentials, SystemdCredentialMasterKeySource.CredentialName)))
        {
            return new SystemdCredentialMasterKeySource(credentials, version);
        }
        if (allowDevelopmentKey) return new DevelopmentMasterKeySource();
        throw new InvalidOperationException(
            "No master key: the service must run under systemd with LoadCredentialEncrypted=master-key.");
    }
}
