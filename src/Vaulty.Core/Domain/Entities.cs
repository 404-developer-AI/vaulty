namespace Vaulty.Core.Domain;

// Persisted entities. Every entity below an organization carries OrganizationId so row-level security can filter it
// without a join; entities below a tenant also carry TenantId. Column names are the snake_case of the property names.

/// <summary>One managed service provider (or IT team) using Vaulty. Never sees another organization.</summary>
public sealed class Organization
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public string Settings { get; set; } = "{}";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
}

/// <summary>A person who signs in to Vaulty. Belongs to exactly one organization.</summary>
public sealed class User
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public required string UserName { get; set; }
    public required string NormalizedUserName { get; set; }
    public string? Email { get; set; }
    public string? NormalizedEmail { get; set; }
    public bool EmailConfirmed { get; set; }
    public string? DisplayName { get; set; }
    public string? PasswordHash { get; set; }
    public string SecurityStamp { get; set; } = Guid.NewGuid().ToString("N");
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("N");
    public bool TwoFactorEnabled { get; set; }
    public string? AuthenticatorKey { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public bool LockoutEnabled { get; set; } = true;
    public int AccessFailedCount { get; set; }
    /// <summary>SHA-256 (hex) of each unused recovery code; the codes themselves are shown once and never stored.</summary>
    public string[] RecoveryCodes { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }
}

/// <summary>A named set of permissions inside an organization.</summary>
public sealed class Role
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public bool BuiltIn { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>One permission key held by a role.</summary>
public sealed class RolePermission
{
    public Guid OrganizationId { get; set; }
    public Guid RoleId { get; set; }
    public required string Permission { get; set; }
}

/// <summary>A role given to a user, for the whole organization or limited to one customer.</summary>
public sealed class RoleAssignment
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid UserId { get; set; }
    public Guid RoleId { get; set; }
    /// <summary>Null: every customer of the organization.</summary>
    public Guid? CustomerId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A customer of the organization, identified by a customer code and a customer name.</summary>
public sealed class Customer
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public required string Code { get; set; }
    public required string Name { get; set; }
    public List<string> Tags { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
}

/// <summary>One Microsoft 365 / Entra ID tenant connected to a customer.</summary>
public sealed class Tenant
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid CustomerId { get; set; }
    /// <summary>The Entra tenant id. Unique across all organizations: a tenant is connected to one organization only.</summary>
    public Guid EntraTenantId { get; set; }
    public required string DisplayName { get; set; }
    public string? DefaultDomain { get; set; }
    public TenantAuthMode AuthMode { get; set; } = TenantAuthMode.DedicatedApp;
    public Guid? ClientId { get; set; }
    /// <summary>Name of the secret that holds the certificate with its private key.</summary>
    public string? CertificateSecretName { get; set; }
    public string? CertificateThumbprint { get; set; }
    public DateTimeOffset? CertificateExpiresAt { get; set; }
    public ConsentState ConsentState { get; set; } = ConsentState.Pending;
    public string GrantedPermissions { get; set; } = "[]";
    public string Health { get; set; } = "{}";
    public DateTimeOffset? LastHealthCheckAt { get; set; }
    public int? CurrentDekVersion { get; set; }
    public TenantState State { get; set; } = TenantState.Active;
    public DateTimeOffset? DeletionRequestedAt { get; set; }
    public Guid? DeletionRequestedBy { get; set; }
    public Guid? DeletionConfirmedBy { get; set; }
    public bool LegalHold { get; set; }
    public string? NextCertificateSecretName { get; set; }
    public string? NextCertificateThumbprint { get; set; }
    public DateTimeOffset? NextCertificateExpiresAt { get; set; }
    public DateTimeOffset? ConsentLostAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Scope, frequency and retention for a tenant or one protected object; the most specific one applies.</summary>
public sealed class Policy
{
    public const int MinimumRetentionDays = 90;
    public const int DefaultFrequencyMinutes = 360;

    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public Guid? ProtectedObjectId { get; set; }
    public required string Name { get; set; }
    public string ScopeRules { get; set; } = "{}";
    public string Exclusions { get; set; } = "{}";
    public int FrequencyMinutes { get; set; } = DefaultFrequencyMinutes;
    public int RetentionDays { get; set; } = MinimumRetentionDays;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>One thing Vaulty backs up: a mailbox, drive, site, team or the directory.</summary>
public sealed class ProtectedObject
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public ProtectedObjectKind Kind { get; set; }
    /// <summary>The Graph id of the source (user id, drive id, ...).</summary>
    public required string SourceId { get; set; }
    public required string DisplayName { get; set; }
    public string? SubKind { get; set; }
    public ProtectedObjectState State { get; set; } = ProtectedObjectState.Active;
    public DateTimeOffset? SourceDeletedAt { get; set; }
    public Guid? LastSnapshotId { get; set; }
    public DateTimeOffset? NextRunAt { get; set; }
    /// <summary>Delta tokens per folder or drive, saved only after a snapshot commits.</summary>
    public string DeltaState { get; set; } = "{}";
    /// <summary>Mailbox id and type, drive id, archive state.</summary>
    public string SourceDetails { get; set; } = "{}";
    public bool LegalHold { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>The point-in-time result of one backup of one protected object.</summary>
public sealed class Snapshot
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public Guid ProtectedObjectId { get; set; }
    public SnapshotState State { get; set; } = SnapshotState.Staged;
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? CommittedAt { get; set; }
    public string ItemCounts { get; set; } = "{}";
    /// <summary>Items that are missing from a partial snapshot, each with its reason.</summary>
    public string Exceptions { get; set; } = "[]";
    public byte[]? ManifestRootHash { get; set; }
    public string? ObjectKey { get; set; }
    public DateTimeOffset? LockUntil { get; set; }
    public DateTimeOffset? VerifiedAt { get; set; }
}

/// <summary>One email, event, contact, task, file or folder inside a protected object.</summary>
public sealed class Item
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public Guid ProtectedObjectId { get; set; }
    /// <summary>The snapshot in which this version of the item was first seen.</summary>
    public Guid FirstSnapshotId { get; set; }
    /// <summary>The first snapshot in which the item no longer existed at the source.</summary>
    public Guid? DeletedInSnapshotId { get; set; }
    public ItemState State { get; set; } = ItemState.Staged;
    public required string SourceId { get; set; }
    public string? ParentSourceId { get; set; }
    public required string Kind { get; set; }
    /// <summary>Encrypted metadata (subject, names, paths); never stored as plain text.</summary>
    public byte[]? SealedMetadata { get; set; }
    public string Flags { get; set; } = "{}";
    public byte[]? ContentHash { get; set; }
    public long Size { get; set; }
    public DateTimeOffset? ModifiedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Where one chunk of a tenant is stored.</summary>
public sealed class ChunkIndexEntry
{
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public required byte[] ChunkHash { get; set; }
    public Guid PackId { get; set; }
    public long Offset { get; set; }
    public int Length { get; set; }
    public int PlaintextLength { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>One pack file in object storage: a run of encrypted chunks.</summary>
public sealed class Pack
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public required string ObjectKey { get; set; }
    public long Size { get; set; }
    public byte[]? Sha256 { get; set; }
    public PackState State { get; set; } = PackState.Staged;
    public DateTimeOffset LockUntil { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>One execution of a backup, restore, export or verification; mirrors the workflow engine for the UI.</summary>
public sealed class Job
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid? TenantId { get; set; }
    public Guid? ProtectedObjectId { get; set; }
    public JobKind Kind { get; set; }
    public JobState State { get; set; } = JobState.Queued;
    public string? WorkflowId { get; set; }
    public string? WorkflowRunId { get; set; }
    public Guid? RequestedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public string Progress { get; set; } = "{}";
    public string ResultCounts { get; set; } = "{}";
    public string? Error { get; set; }
}

/// <summary>One line of the append-only audit log. The database computes the hash chain.</summary>
public sealed class AuditEvent
{
    public long Seq { get; set; }
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public required string Actor { get; set; }
    public required string Action { get; set; }
    public string? Target { get; set; }
    public string Details { get; set; } = "{}";
    public byte[]? PrevHash { get; set; }
    public byte[]? Hash { get; set; }
}

/// <summary>A tenant's data encryption key, wrapped by the key encryption key. Never stored unwrapped.</summary>
public sealed class TenantKey
{
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public int Version { get; set; }
    public required byte[] WrappedKey { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Protected objects whose derived key was destroyed (crypto-shredding).</summary>
public sealed class KeyTombstone
{
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public Guid ProtectedObjectId { get; set; }
    public Guid RequestedBy { get; set; }
    public Guid? ConfirmedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Daily usage per customer, for billing and reports.</summary>
public sealed class UsageDaily
{
    public Guid OrganizationId { get; set; }
    public Guid CustomerId { get; set; }
    public DateOnly Date { get; set; }
    public int ProtectedUsers { get; set; }
    public long BytesStored { get; set; }
    public int Exports { get; set; }
}
