using System.Text.Json;

namespace Vaulty.Infrastructure.Storage;

/// <summary>
/// The IAM policies of the three storage identities. Each allows only what its service does; deletes and lock changes are
/// denied explicitly to the identities that must never use them, so a mistake in an allow list cannot grant them.
/// Uploads with a retention date need s3:PutObjectRetention; in compliance mode a retention can only be extended, never
/// shortened or removed, by anyone.
/// </summary>
public static class StoragePolicies
{
    private static readonly string[] NeverForWriters =
    [
        "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketVersioning", "s3:PutBucketPolicy", "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration",
    ];

    public static string For(StorageRole role, string backupBucket, string exportBucket) => role switch
    {
        StorageRole.Api => Document(
            Allow(["s3:ListBucket", "s3:GetBucketLocation"], Bucket(backupBucket), Bucket(exportBucket)),
            Allow(["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"], Objects(backupBucket)),
            // Connecting a tenant writes its wrapped data key file.
            Allow(["s3:PutObject", "s3:PutObjectRetention"], $"arn:aws:s3:::{backupBucket}/tenants/*/keys/*"),
            Allow(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Objects(exportBucket)),
            Deny(NeverForWriters.Where(a => a != "s3:DeleteObject").ToArray(), Bucket(backupBucket), Objects(backupBucket)),
            Deny(["s3:DeleteObject"], Objects(backupBucket))),
        StorageRole.Worker => Document(
            Allow(["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"],
                Bucket(backupBucket), Bucket(exportBucket)),
            Allow(["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:PutObject", "s3:PutObjectRetention"], Objects(backupBucket)),
            Allow(["s3:GetObject", "s3:PutObject"], Objects(exportBucket)),
            Deny(NeverForWriters, Bucket(backupBucket), Objects(backupBucket))),
        StorageRole.Gc => Document(
            Allow(["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation"], Bucket(backupBucket)),
            Allow(["s3:GetObject", "s3:GetObjectRetention", "s3:DeleteObject", "s3:DeleteObjectVersion"], Objects(backupBucket)),
            Deny(["s3:PutObject", "s3:PutObjectRetention", "s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration",
                "s3:PutBucketVersioning", "s3:DeleteBucket"], Bucket(backupBucket), Objects(backupBucket))),
        _ => throw new ArgumentOutOfRangeException(nameof(role)),
    };

    private static string Bucket(string bucket) => $"arn:aws:s3:::{bucket}";

    private static string Objects(string bucket) => $"arn:aws:s3:::{bucket}/*";

    private static object Allow(string[] actions, params string[] resources) => new { Effect = "Allow", Action = actions, Resource = resources };

    private static object Deny(string[] actions, params string[] resources) => new { Effect = "Deny", Action = actions, Resource = resources };

    private static string Document(params object[] statements) =>
        JsonSerializer.Serialize(new { Version = "2012-10-17", Statement = statements });
}
