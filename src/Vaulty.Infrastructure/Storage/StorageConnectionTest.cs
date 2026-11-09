using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Vaulty.Core.Abstractions;

namespace Vaulty.Infrastructure.Storage;

/// <summary>Bucket-level inspection and object access per identity, so the connection test can run against fakes too.</summary>
public interface IStorageInspector : IDisposable
{
    Task<bool> CanListAsync(StorageRole role, string bucket, CancellationToken cancellationToken);
    Task<bool> ObjectLockEnabledAsync(string bucket, CancellationToken cancellationToken);
    Task<bool> VersioningEnabledAsync(string bucket, CancellationToken cancellationToken);
    IObjectStore BackupStore(StorageRole role);
    int ThrottledResponses { get; }
}

/// <summary>
/// The six checks every storage configuration must pass before a first backup can be planned. Each result is shown
/// separately; one red check blocks planning.
/// </summary>
public sealed class StorageConnectionTest(TimeProvider clock, Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    public const string TestPrefix = "vaulty-connection-test/";
    public static readonly TimeSpan TestLock = TimeSpan.FromSeconds(5);
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? ((d, ct) => Task.Delay(d, clock, ct));

    public async Task<StorageTestResult> RunAsync(StorageSettings settings, IStorageInspector inspector, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(inspector);
        var checks = new List<StorageCheck>
        {
            await CheckAsync("Every identity reaches its buckets", async () =>
            {
                var missing = new List<string>();
                foreach (var (role, bucket) in new[]
                         {
                             (StorageRole.Api, settings.BackupBucket), (StorageRole.Api, settings.ExportBucket),
                             (StorageRole.Worker, settings.BackupBucket), (StorageRole.Worker, settings.ExportBucket),
                             (StorageRole.Gc, settings.BackupBucket),
                         })
                {
                    if (!await inspector.CanListAsync(role, bucket, cancellationToken).ConfigureAwait(false)) missing.Add($"{role} → {bucket}");
                }
                return missing.Count == 0 ? (true, "all reachable") : (false, "not reachable: " + string.Join(", ", missing));
            }).ConfigureAwait(false),
            await CheckAsync("Object Lock on the backup bucket", async () =>
            {
                var backup = await inspector.ObjectLockEnabledAsync(settings.BackupBucket, cancellationToken).ConfigureAwait(false);
                var export = await inspector.ObjectLockEnabledAsync(settings.ExportBucket, cancellationToken).ConfigureAwait(false);
                return (backup && !export, $"backup bucket {(backup ? "locked" : "NOT locked")}, export bucket {(export ? "locked (must not be)" : "not locked")}");
            }).ConfigureAwait(false),
            await CheckAsync("Versioning on the backup bucket", async () =>
            {
                var on = await inspector.VersioningEnabledAsync(settings.BackupBucket, cancellationToken).ConfigureAwait(false);
                return (on, on ? "enabled" : "disabled");
            }).ConfigureAwait(false),
        };

        var key = TestPrefix + Guid.NewGuid().ToString("N");
        var lockUntil = clock.GetUtcNow() + TestLock;
        checks.Add(await CheckAsync("The worker writes with a lock", async () =>
        {
            await inspector.BackupStore(StorageRole.Worker).PutAsync(key, new MemoryStream("vaulty connection test"u8.ToArray()),
                new ObjectPutOptions(lockUntil), cancellationToken).ConfigureAwait(false);
            var head = await inspector.BackupStore(StorageRole.Worker).HeadAsync(key, cancellationToken).ConfigureAwait(false);
            return (head is not null, head is null ? "written but not found" : $"locked until {lockUntil:u}");
        }).ConfigureAwait(false));

        checks.Add(await CheckAsync("The worker cannot delete", async () =>
        {
            try
            {
                await inspector.BackupStore(StorageRole.Worker).DeleteAsync(key, cancellationToken).ConfigureAwait(false);
                var stillThere = await inspector.BackupStore(StorageRole.Gc).HeadAsync(key, cancellationToken).ConfigureAwait(false);
                return (stillThere is not null, stillThere is null ? "the worker deleted the object" : "delete had no effect");
            }
            catch (ObjectLockedException)
            {
                // Only the lock stopped it: the identity itself has the right to delete, which it must not have.
                return (false, "the worker has delete rights; only the Object Lock refused");
            }
            catch (Exception ex) when (ex is ObjectStoreAccessDeniedException or AmazonServiceException)
            {
                return (true, "refused for lack of rights, as required");
            }
        }).ConfigureAwait(false));

        checks.Add(await CheckAsync("Garbage collection deletes an expired object", async () =>
        {
            var wait = lockUntil - clock.GetUtcNow() + TimeSpan.FromSeconds(1);
            if (wait > TimeSpan.Zero) await _delay(wait, cancellationToken).ConfigureAwait(false);
            await inspector.BackupStore(StorageRole.Gc).DeleteAsync(key, cancellationToken).ConfigureAwait(false);
            var gone = await inspector.BackupStore(StorageRole.Gc).HeadAsync(key, cancellationToken).ConfigureAwait(false) is null;
            return (gone, gone ? "deleted after the lock expired" : "the object is still there");
        }).ConfigureAwait(false));

        return new StorageTestResult(clock.GetUtcNow(), checks, inspector.ThrottledResponses);
    }

    private static async Task<StorageCheck> CheckAsync(string name, Func<Task<(bool Passed, string Detail)>> check)
    {
        try
        {
            var (passed, detail) = await check().ConfigureAwait(false);
            return new StorageCheck(name, passed, detail);
        }
        catch (Exception ex) when (ex is AmazonServiceException or ObjectStoreException or HttpRequestException)
        {
            return new StorageCheck(name, false, ex is AmazonServiceException aws ? $"{aws.StatusCode} {aws.ErrorCode}" : ex.GetType().Name);
        }
    }
}

/// <summary>The real inspector: one S3 client per identity from the settings and the secrets store.</summary>
public sealed class S3StorageInspector : IStorageInspector
{
    private readonly Dictionary<StorageRole, AmazonS3Client> _clients = [];
    private readonly Dictionary<StorageRole, S3ObjectStore> _stores = [];

    private S3StorageInspector()
    {
    }

    public static async Task<S3StorageInspector> CreateAsync(StorageSettings settings, ISecretStore secrets, TimeProvider clock,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(secrets);
        var inspector = new S3StorageInspector();
        foreach (var (role, identity) in settings.Identities)
        {
            using var secret = await secrets.GetAsync(StorageSettings.SecretName(role), cancellationToken).ConfigureAwait(false)
                               ?? throw new InvalidOperationException($"The {role} key is missing from the secrets store.");
            inspector._clients[role] = new AmazonS3Client(new BasicAWSCredentials(identity.AccessKeyId, secret.RevealString()), new AmazonS3Config
            {
                ServiceURL = settings.ServiceUrl,
                AuthenticationRegion = settings.Region,
                ForcePathStyle = true,
                RequestChecksumCalculation = RequestChecksumCalculation.WHEN_REQUIRED,
                ResponseChecksumValidation = ResponseChecksumValidation.WHEN_REQUIRED,
            });
            inspector._stores[role] = new S3ObjectStore(new S3StoreSettings(settings.ServiceUrl, settings.Region, settings.BackupBucket,
                identity.AccessKeyId), secret, clock);
        }
        return inspector;
    }

    public int ThrottledResponses => _stores.Values.Sum(s => s.ThrottledResponses);

    public async Task<bool> CanListAsync(StorageRole role, string bucket, CancellationToken cancellationToken)
    {
        try
        {
            await _clients[role].ListObjectsV2Async(new ListObjectsV2Request { BucketName = bucket, MaxKeys = 1 }, cancellationToken)
                .ConfigureAwait(false);
            return true;
        }
        catch (AmazonS3Exception)
        {
            return false;
        }
    }

    public async Task<bool> ObjectLockEnabledAsync(string bucket, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _clients[StorageRole.Worker].GetObjectLockConfigurationAsync(
                new GetObjectLockConfigurationRequest { BucketName = bucket }, cancellationToken).ConfigureAwait(false);
            return response.ObjectLockConfiguration?.ObjectLockEnabled == ObjectLockEnabled.Enabled;
        }
        catch (AmazonS3Exception ex) when (ex.ErrorCode == "ObjectLockConfigurationNotFoundError")
        {
            return false;
        }
    }

    public async Task<bool> VersioningEnabledAsync(string bucket, CancellationToken cancellationToken)
    {
        var response = await _clients[StorageRole.Worker].GetBucketVersioningAsync(new GetBucketVersioningRequest { BucketName = bucket },
            cancellationToken).ConfigureAwait(false);
        return response.VersioningConfig?.Status == VersionStatus.Enabled;
    }

    public IObjectStore BackupStore(StorageRole role) => _stores[role];

    public void Dispose()
    {
        foreach (var client in _clients.Values) client.Dispose();
        foreach (var store in _stores.Values) store.Dispose();
    }
}
