using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Vaulty.Core.Domain;

namespace Vaulty.Infrastructure.Database;

/// <summary>
/// EF Core context for CRUD on the Vaulty schema. The schema itself is created by the SQL migrations in
/// <c>Database/Sql</c> (row-level security, partitions and grants are not expressible in the EF model), so every entity
/// is excluded from EF's own migration diff. Hot paths (items, chunk index) use Dapper on the same connections.
/// </summary>
public sealed class VaultyDbContext(DbContextOptions<VaultyDbContext> options) : DbContext(options)
{
    public const string Schema = "vaulty";

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<RoleAssignment> RoleAssignments => Set<RoleAssignment>();
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<TenantKey> TenantKeys => Set<TenantKey>();
    public DbSet<KeyTombstone> KeyTombstones => Set<KeyTombstone>();
    public DbSet<Policy> Policies => Set<Policy>();
    public DbSet<ProtectedObject> ProtectedObjects => Set<ProtectedObject>();
    public DbSet<Snapshot> Snapshots => Set<Snapshot>();
    public DbSet<Item> Items => Set<Item>();
    public DbSet<ChunkIndexEntry> ChunkIndex => Set<ChunkIndexEntry>();
    public DbSet<Pack> Packs => Set<Pack>();
    public DbSet<Job> Jobs => Set<Job>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<UsageDaily> UsageDaily => Set<UsageDaily>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);

        Table<Organization>(modelBuilder, "organizations").Property(e => e.Settings).HasColumnType("jsonb");
        Table<User>(modelBuilder, "users");
        Table<Role>(modelBuilder, "roles");
        Table<RolePermission>(modelBuilder, "role_permissions").HasKey(e => new { e.RoleId, e.Permission });
        Table<RoleAssignment>(modelBuilder, "role_assignments");
        Table<Customer>(modelBuilder, "customers");

        var tenant = Table<Tenant>(modelBuilder, "tenants");
        tenant.Property(e => e.AuthMode).HasConversion(StateConverter<TenantAuthMode>());
        tenant.Property(e => e.ConsentState).HasConversion(StateConverter<ConsentState>());
        tenant.Property(e => e.State).HasConversion(StateConverter<TenantState>());
        tenant.Property(e => e.GrantedPermissions).HasColumnType("jsonb");
        tenant.Property(e => e.Health).HasColumnType("jsonb");

        Table<TenantKey>(modelBuilder, "tenant_keys").HasKey(e => new { e.TenantId, e.Version });
        Table<KeyTombstone>(modelBuilder, "key_tombstones").HasKey(e => new { e.TenantId, e.ProtectedObjectId });

        var policy = Table<Policy>(modelBuilder, "policies");
        policy.Property(e => e.ScopeRules).HasColumnType("jsonb");
        policy.Property(e => e.Exclusions).HasColumnType("jsonb");

        var po = Table<ProtectedObject>(modelBuilder, "protected_objects");
        po.Property(e => e.Kind).HasConversion(StateConverter<ProtectedObjectKind>());
        po.Property(e => e.State).HasConversion(StateConverter<ProtectedObjectState>());
        po.Property(e => e.DeltaState).HasColumnType("jsonb");

        var snapshot = Table<Snapshot>(modelBuilder, "snapshots");
        snapshot.Property(e => e.State).HasConversion(StateConverter<SnapshotState>());
        snapshot.Property(e => e.ItemCounts).HasColumnType("jsonb");
        snapshot.Property(e => e.Exceptions).HasColumnType("jsonb");

        var item = Table<Item>(modelBuilder, "items");
        item.HasKey(e => new { e.TenantId, e.Id });
        item.Property(e => e.State).HasConversion(StateConverter<ItemState>());
        item.Property(e => e.Flags).HasColumnType("jsonb");

        Table<ChunkIndexEntry>(modelBuilder, "chunk_index").HasKey(e => new { e.TenantId, e.ChunkHash });

        Table<Pack>(modelBuilder, "packs").Property(e => e.State).HasConversion(StateConverter<PackState>());

        var job = Table<Job>(modelBuilder, "jobs");
        job.Property(e => e.Kind).HasConversion(StateConverter<JobKind>());
        job.Property(e => e.State).HasConversion(StateConverter<JobState>());
        job.Property(e => e.Progress).HasColumnType("jsonb");
        job.Property(e => e.ResultCounts).HasColumnType("jsonb");

        var audit = Table<AuditEvent>(modelBuilder, "audit_events");
        audit.HasKey(e => e.Seq);
        audit.Property(e => e.Seq).ValueGeneratedOnAdd();
        audit.Property(e => e.Details).HasColumnType("jsonb");
        // Computed by the database trigger.
        audit.Property(e => e.PrevHash).ValueGeneratedOnAdd();
        audit.Property(e => e.Hash).ValueGeneratedOnAdd();

        Table<UsageDaily>(modelBuilder, "usage_daily").HasKey(e => new { e.OrganizationId, e.CustomerId, e.Date });
    }

    private static EntityTypeBuilder<T> Table<T>(ModelBuilder modelBuilder, string name) where T : class
    {
        var builder = modelBuilder.Entity<T>();
        builder.ToTable(name, Schema, t => t.ExcludeFromMigrations());
        return builder;
    }

    private static ValueConverter<T, string> StateConverter<T>() where T : struct, Enum =>
        new(v => StateText.ToText(v), v => StateText.Parse<T>(v));
}
