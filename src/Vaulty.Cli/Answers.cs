using System.Globalization;

namespace Vaulty.Cli;

/// <summary>
/// The answers of the wizard, from the prompts or from an answers file (deploy/install/answers.example.yaml). The file
/// format is the small YAML subset that example uses: <c>key: value</c>, one level of nested blocks, comments.
/// </summary>
public sealed record InstallAnswers
{
    public string Profile { get; init; } = "all-in-one";
    public string Environment { get; init; } = "production";
    public string Fqdn { get; init; } = "";
    public string AdminEmail { get; init; } = "";
    public string? TimeZone { get; init; }
    public string? DataDisk { get; init; }
    public bool Luks { get; init; } = true;
    public int? Workers { get; init; }
    public string? SshAllowFrom { get; init; }
    public PgBackRestAnswers? PgBackRest { get; init; }
    public SmtpAnswers? Smtp { get; init; }
    public string AutoUpdate { get; init; } = "none";

    public IReadOnlyList<string> Validate(int vcpu)
    {
        var problems = new List<string>();
        if (Profile != "all-in-one") problems.Add($"profile '{Profile}' is not available yet; use all-in-one.");
        if (Environment is not ("production" or "staging" or "development")) problems.Add("environment must be production, staging or development.");
        if (Uri.CheckHostName(Fqdn) is UriHostNameType.Unknown || Fqdn.Length == 0) problems.Add("fqdn must be a host name, for example backup.example.com.");
        if (!System.Net.Mail.MailAddress.TryCreate(AdminEmail, out _)) problems.Add("admin_email must be an e-mail address.");
        if (Workers is { } w && (w < 1 || w > Math.Max(1, vcpu))) problems.Add($"workers.instances must be between 1 and {Math.Max(1, vcpu)}.");
        if (DataDisk is { } disk && !disk.StartsWith("/dev/", StringComparison.Ordinal)) problems.Add("data_disk.device must be a block device such as /dev/sdb.");
        if (AutoUpdate is not ("none" or "patch")) problems.Add("update.auto must be none or patch.");
        if (AutoUpdate == "patch" && Environment == "production") problems.Add("automatic patch updates are for staging only.");
        if (PgBackRest is { } p && (p.Bucket.Length == 0 || p.AccessKey.Length == 0 || p.SecretKey.Length == 0)) problems.Add("pgbackrest needs bucket, access_key and secret_key.");
        if (Smtp is { } s && (s.Host.Length == 0 || s.From.Length == 0)) problems.Add("smtp needs host and from.");
        return problems;
    }

    public static InstallAnswers Parse(string text)
    {
        var values = SimpleYaml.Parse(text);
        string? Get(string key) => values.TryGetValue(key, out var v) && v.Length > 0 ? v : null;
        int? Int(string key) => Get(key) is { } v ? int.Parse(v, CultureInfo.InvariantCulture) : null;
        bool Bool(string key, bool fallback) => Get(key) is { } v ? v is "true" or "yes" : fallback;
        return new InstallAnswers
        {
            Profile = Get("profile") ?? "all-in-one",
            Environment = Get("environment") ?? "production",
            Fqdn = Get("fqdn") ?? "",
            AdminEmail = Get("admin_email") ?? "",
            TimeZone = Get("timezone"),
            DataDisk = Get("data_disk.device"),
            Luks = Bool("data_disk.luks", true),
            Workers = Int("workers.instances"),
            SshAllowFrom = Get("firewall.ssh_allow_from"),
            PgBackRest = Get("pgbackrest.bucket") is null ? null : new PgBackRestAnswers(Get("pgbackrest.s3_endpoint") ?? "", Get("pgbackrest.s3_region") ?? "",
                Get("pgbackrest.bucket")!, Get("pgbackrest.access_key") ?? "", Get("pgbackrest.secret_key") ?? "", Int("pgbackrest.retention_full") ?? 30),
            Smtp = Get("smtp.host") is null ? null : new SmtpAnswers(Get("smtp.host")!, Int("smtp.port") ?? 587, Get("smtp.username"), Get("smtp.password"),
                Get("smtp.from") ?? ""),
            AutoUpdate = Get("update.auto") ?? "none",
        };
    }
}

public sealed record PgBackRestAnswers(string Endpoint, string Region, string Bucket, string AccessKey, string SecretKey, int RetentionFull);

public sealed record SmtpAnswers(string Host, int Port, string? UserName, string? Password, string From);

public static class SimpleYaml
{
    /// <summary>Flattens "block:\n  key: value" to "block.key". Values may be quoted; "#" starts a comment outside quotes.</summary>
    public static Dictionary<string, string> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        string? block = null;
        var number = 0;
        foreach (var raw in text.Replace("\r", "", StringComparison.Ordinal).Split('\n'))
        {
            number++;
            var line = StripComment(raw).TrimEnd();
            if (line.Trim().Length == 0) continue;
            var indented = char.IsWhiteSpace(line[0]);
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0) throw new InstallException($"answers file line {number}: expected 'key: value'.");
            var key = line[..colon].Trim();
            var value = Unquote(line[(colon + 1)..].Trim());
            if (!indented)
            {
                if (value.Length == 0) { block = key; continue; }
                block = null;
                result[key] = value;
            }
            else
            {
                if (block is null) throw new InstallException($"answers file line {number}: indented key outside a block.");
                result[$"{block}.{key}"] = value;
            }
        }
        return result;
    }

    private static string StripComment(string line)
    {
        var quote = '\0';
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quote != '\0') { if (c == quote) quote = '\0'; continue; }
            if (c is '"' or '\'') quote = c;
            else if (c == '#' && (i == 0 || char.IsWhiteSpace(line[i - 1]))) return line[..i];
        }
        return line;
    }

    private static string Unquote(string value) =>
        value.Length >= 2 && ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')) ? value[1..^1] : value;
}
