using System.Text.Json;
using System.Text.Json.Serialization;
using Dapper;
using Npgsql;
using Vaulty.Core.Abstractions;

namespace Vaulty.Infrastructure.Storage;

/// <summary>The three storage identities: least privilege per service.</summary>
public enum StorageRole
{
    /// <summary>Web and API: read backup data for restores, write tenant key files, read and write exports.</summary>
    Api,
    /// <summary>Workers: write with Object Lock, read; never delete, never change a lock.</summary>
    Worker,
    /// <summary>Garbage collection: delete objects whose lock expired, on the backup bucket only.</summary>
    Gc,
}

public sealed record StorageIdentity(
    [property: JsonPropertyName("user_name")] string? UserName,
    [property: JsonPropertyName("access_key_id")] string AccessKeyId);

public sealed record StorageCheck(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("passed")] bool Passed,
    [property: JsonPropertyName("detail")] string Detail);

public sealed record StorageTestResult(
    [property: JsonPropertyName("tested_at")] DateTimeOffset TestedAt,
    [property: JsonPropertyName("checks")] IReadOnlyList<StorageCheck> Checks,
    [property: JsonPropertyName("throttled_responses")] int ThrottledResponses)
{
    [JsonIgnore] public bool Passed => Checks.Count > 0 && Checks.All(c => c.Passed);
}

/// <summary>
/// Where Vaulty stores data: the provider endpoint, the two buckets and the access key ids per identity. Not secret: the
/// secret keys are in the secrets store under <see cref="SecretName"/>.
/// </summary>
public sealed record StorageSettings(
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("service_url")] string ServiceUrl,
    [property: JsonPropertyName("backup_bucket")] string BackupBucket,
    [property: JsonPropertyName("export_bucket")] string ExportBucket,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("identities")] IReadOnlyDictionary<StorageRole, StorageIdentity> Identities,
    [property: JsonPropertyName("last_test")] StorageTestResult? LastTest)
{
    public const string SettingKey = "storage";

    public static string SecretName(StorageRole role) => $"storage.{role.ToString().ToLowerInvariant()}.secret_key";

    /// <summary>A first backup can only be planned when every connection check passed.</summary>
    [JsonIgnore] public bool Ready => LastTest is { Passed: true };

    public string ServiceUrlFor(string region) => WasabiRegions.ServiceUrl(region);
}

public static class WasabiRegions
{
    /// <summary>Wasabi regions in the EU.</summary>
    public static readonly IReadOnlyDictionary<string, string> Eu = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["eu-central-1"] = "Amsterdam",
        ["eu-central-2"] = "Frankfurt",
        ["eu-west-1"] = "London",
        ["eu-west-2"] = "Paris",
        ["eu-south-1"] = "Milan",
    };

    public static string ServiceUrl(string region) => $"https://s3.{region}.wasabisys.com";

    public const string IamUrl = "https://iam.wasabisys.com";
}

/// <summary>Reads and writes rows of vaulty.platform_settings.</summary>
public sealed class PlatformSettings(NpgsqlDataSource dataSource)
{
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) } };

    public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var json = await connection.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT value::text FROM vaulty.platform_settings WHERE key = @key", new { key }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return json is null ? default : JsonSerializer.Deserialize<T>(json, Json);
    }

    public async Task SetAsync<T>(string key, T value, string actor, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vaulty.platform_settings (key, value, updated_by) VALUES (@key, @value::jsonb, @actor)
            ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now(), updated_by = excluded.updated_by
            """, new { key, value = JsonSerializer.Serialize(value, Json), actor }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Json);
}

/// <summary>Builds the object store of one storage identity from the settings and the secrets store.</summary>
public sealed class StorageClientFactory(PlatformSettings settings, ISecretStore secrets, TimeProvider clock)
{
    public async Task<StorageSettings?> SettingsAsync(CancellationToken cancellationToken = default) =>
        await settings.GetAsync<StorageSettings>(StorageSettings.SettingKey, cancellationToken).ConfigureAwait(false);

    public async Task<S3ObjectStore> CreateAsync(StorageRole role, bool exportBucket = false, CancellationToken cancellationToken = default)
    {
        var current = await SettingsAsync(cancellationToken).ConfigureAwait(false)
                      ?? throw new InvalidOperationException("Object storage is not configured yet (Settings → Storage).");
        using var secret = await secrets.GetAsync(StorageSettings.SecretName(role), cancellationToken).ConfigureAwait(false)
                           ?? throw new InvalidOperationException($"The {role} storage key is missing.");
        return new S3ObjectStore(new S3StoreSettings(current.ServiceUrl, current.Region, exportBucket ? current.ExportBucket : current.BackupBucket,
            current.Identities[role].AccessKeyId), secret, clock);
    }
}
