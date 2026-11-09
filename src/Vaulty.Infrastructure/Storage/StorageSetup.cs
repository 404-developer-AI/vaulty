using System.Net;
using System.Text.RegularExpressions;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Logging;
using Vaulty.Core.Abstractions;

namespace Vaulty.Infrastructure.Storage;

/// <summary>Endpoints of the storage provider; tests point them at WireMock.</summary>
public sealed record StorageEndpoints(string S3ServiceUrl, string IamServiceUrl)
{
    public static StorageEndpoints Wasabi(string region) => new(WasabiRegions.ServiceUrl(region), WasabiRegions.IamUrl);
}

public sealed record SetupStep(string Description, bool Done);

public sealed class StorageSetupException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// The storage setup assistant: with one administrative key it creates the backup bucket (Object Lock and versioning,
/// which only work when set at creation), the export bucket (lifecycle of one day), and one IAM user per storage identity
/// with a least-privilege policy and an access key. The identity keys go to the secrets store; the administrative key is
/// only used in memory for the duration of the call.
/// </summary>
public sealed partial class StorageSetupAssistant(ISecretStore secrets, PlatformSettings settings, ILogger<StorageSetupAssistant> logger)
{
    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,40}[a-z0-9]$")]
    private static partial Regex PrefixPattern();

    public static (string Backup, string Export) BucketNames(string prefix) => ($"{prefix}-backup", $"{prefix}-export");

    public async Task<IReadOnlyList<SetupStep>> RunAsync(string region, string bucketPrefix, string adminAccessKeyId, Secret adminSecretKey,
        string actor, StorageEndpoints? endpoints = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adminSecretKey);
        if (!WasabiRegions.Eu.ContainsKey(region)) throw new StorageSetupException($"Region {region} is not an EU region.");
        if (!PrefixPattern().IsMatch(bucketPrefix)) throw new StorageSetupException("Use 3 to 42 lower-case letters, digits and hyphens for the bucket prefix.");
        endpoints ??= StorageEndpoints.Wasabi(region);
        var (backup, export) = BucketNames(bucketPrefix);
        var steps = new List<SetupStep>();
        var credentials = new BasicAWSCredentials(adminAccessKeyId, adminSecretKey.RevealString());
        using var s3 = new AmazonS3Client(credentials, new AmazonS3Config
        {
            ServiceURL = endpoints.S3ServiceUrl,
            AuthenticationRegion = region,
            ForcePathStyle = true,
            RequestChecksumCalculation = RequestChecksumCalculation.WHEN_REQUIRED,
            ResponseChecksumValidation = ResponseChecksumValidation.WHEN_REQUIRED,
        });
        using var iam = new AmazonIdentityManagementServiceClient(credentials, new AmazonIdentityManagementServiceConfig
        {
            ServiceURL = endpoints.IamServiceUrl,
            AuthenticationRegion = "us-east-1",
        });

        try
        {
            await CreateBucketAsync(s3, backup, objectLock: true, cancellationToken).ConfigureAwait(false);
            await s3.PutBucketVersioningAsync(new PutBucketVersioningRequest
            {
                BucketName = backup,
                VersioningConfig = new S3BucketVersioningConfig { Status = VersionStatus.Enabled },
            }, cancellationToken).ConfigureAwait(false);
            steps.Add(new SetupStep($"Backup bucket {backup} with Object Lock and versioning", true));

            await CreateBucketAsync(s3, export, objectLock: false, cancellationToken).ConfigureAwait(false);
            await s3.PutLifecycleConfigurationAsync(new PutLifecycleConfigurationRequest
            {
                BucketName = export,
                Configuration = new LifecycleConfiguration
                {
                    Rules =
                    [
                        new LifecycleRule
                        {
                            Id = "vaulty-exports-expire",
                            Status = LifecycleRuleStatus.Enabled,
                            Filter = new LifecycleFilter { LifecycleFilterPredicate = new LifecyclePrefixPredicate { Prefix = "" } },
                            Expiration = new LifecycleRuleExpiration { Days = 1 },
                            AbortIncompleteMultipartUpload = new LifecycleRuleAbortIncompleteMultipartUpload { DaysAfterInitiation = 1 },
                        },
                    ],
                },
            }, cancellationToken).ConfigureAwait(false);
            steps.Add(new SetupStep($"Export bucket {export}, exports removed after one day", true));

            var identities = new Dictionary<StorageRole, StorageIdentity>();
            foreach (var role in Enum.GetValues<StorageRole>())
            {
                var userName = $"{bucketPrefix}-{role.ToString().ToLowerInvariant()}";
                try
                {
                    await iam.CreateUserAsync(new CreateUserRequest { UserName = userName }, cancellationToken).ConfigureAwait(false);
                }
                catch (EntityAlreadyExistsException)
                {
                    // A previous attempt created the user; its policy and key are set again below.
                }
                await iam.PutUserPolicyAsync(new PutUserPolicyRequest
                {
                    UserName = userName,
                    PolicyName = $"vaulty-{role.ToString().ToLowerInvariant()}",
                    PolicyDocument = StoragePolicies.For(role, backup, export),
                }, cancellationToken).ConfigureAwait(false);
                var key = await iam.CreateAccessKeyAsync(new CreateAccessKeyRequest { UserName = userName }, cancellationToken).ConfigureAwait(false);
                await secrets.SetAsync(StorageSettings.SecretName(role), System.Text.Encoding.UTF8.GetBytes(key.AccessKey.SecretAccessKey), actor,
                    cancellationToken).ConfigureAwait(false);
                identities[role] = new StorageIdentity(userName, key.AccessKey.AccessKeyId);
                steps.Add(new SetupStep($"Identity {userName} with its policy and access key", true));
            }

            await settings.SetAsync(StorageSettings.SettingKey, new StorageSettings("wasabi", region, endpoints.S3ServiceUrl, backup, export,
                "assistant", identities, null), actor, cancellationToken).ConfigureAwait(false);
            logger.LogInformation("Storage setup assistant created buckets and {Count} identities", identities.Count);
            return steps;
        }
        catch (AmazonServiceException ex)
        {
            throw new StorageSetupException($"The storage provider refused a step ({ex.ErrorCode ?? ex.StatusCode.ToString()}). " +
                $"Done so far: {string.Join("; ", steps.Select(s => s.Description))}.", ex);
        }
    }

    /// <summary>The manual route: existing buckets and one key pair per identity, entered by the administrator.</summary>
    public async Task SaveManualAsync(string region, string backupBucket, string exportBucket,
        IReadOnlyDictionary<StorageRole, (string AccessKeyId, Secret SecretKey)> keys, string actor, string? serviceUrl = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (!WasabiRegions.Eu.ContainsKey(region)) throw new StorageSetupException($"Region {region} is not an EU region.");
        if (keys.Count != 3) throw new StorageSetupException("Enter a key for each of the three identities.");
        foreach (var (role, (_, secret)) in keys)
        {
            await secrets.SetAsync(StorageSettings.SecretName(role), secret.Reveal().ToArray(), actor, cancellationToken).ConfigureAwait(false);
        }
        await settings.SetAsync(StorageSettings.SettingKey, new StorageSettings("wasabi", region, serviceUrl ?? WasabiRegions.ServiceUrl(region),
            backupBucket, exportBucket, "manual", keys.ToDictionary(k => k.Key, k => new StorageIdentity(null, k.Value.AccessKeyId)), null),
            actor, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Replaces the key of one identity. With the assistant's administrative key: a new key is created, stored and tested,
    /// then the old one is deleted. In manual mode the administrator supplies the new key pair.
    /// </summary>
    public async Task RotateAsync(StorageRole role, string adminAccessKeyId, Secret adminSecretKey, string actor, StorageEndpoints? endpoints = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adminSecretKey);
        var current = await settings.GetAsync<StorageSettings>(StorageSettings.SettingKey, cancellationToken).ConfigureAwait(false)
                      ?? throw new StorageSetupException("Storage is not configured.");
        var identity = current.Identities[role];
        if (identity.UserName is null) throw new StorageSetupException("This identity was entered by hand; enter its new key instead.");
        endpoints ??= StorageEndpoints.Wasabi(current.Region);
        using var iam = new AmazonIdentityManagementServiceClient(new BasicAWSCredentials(adminAccessKeyId, adminSecretKey.RevealString()),
            new AmazonIdentityManagementServiceConfig { ServiceURL = endpoints.IamServiceUrl, AuthenticationRegion = "us-east-1" });
        var created = await iam.CreateAccessKeyAsync(new CreateAccessKeyRequest { UserName = identity.UserName }, cancellationToken).ConfigureAwait(false);
        await secrets.SetAsync(StorageSettings.SecretName(role), System.Text.Encoding.UTF8.GetBytes(created.AccessKey.SecretAccessKey), actor,
            cancellationToken).ConfigureAwait(false);
        var identities = current.Identities.ToDictionary(i => i.Key, i => i.Value);
        identities[role] = identity with { AccessKeyId = created.AccessKey.AccessKeyId };
        await settings.SetAsync(StorageSettings.SettingKey, current with { Identities = identities, LastTest = null }, actor, cancellationToken)
            .ConfigureAwait(false);
        await iam.DeleteAccessKeyAsync(new DeleteAccessKeyRequest { UserName = identity.UserName, AccessKeyId = identity.AccessKeyId },
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task CreateBucketAsync(AmazonS3Client s3, string bucket, bool objectLock, CancellationToken cancellationToken)
    {
        try
        {
            await s3.PutBucketAsync(new PutBucketRequest { BucketName = bucket, ObjectLockEnabledForBucket = objectLock, UseClientRegion = true },
                cancellationToken).ConfigureAwait(false);
        }
        catch (AmazonS3Exception ex) when (ex.ErrorCode == "BucketAlreadyOwnedByYou")
        {
            // Our own bucket from an earlier attempt; the connection test checks its Object Lock configuration.
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.Conflict)
        {
            throw new StorageSetupException($"The bucket name {bucket} is taken. Choose another prefix.", ex);
        }
    }
}
