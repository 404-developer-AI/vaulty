using Dapper;
using Npgsql;
using Vaulty.Infrastructure.Audit;
using Vaulty.Infrastructure.Database;

namespace Vaulty.Integration.Tests.Database;

public sealed class SchemaTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static readonly string[] OrganizationTables =
    [
        "organizations", "users", "roles", "role_permissions", "role_assignments", "customers", "tenants", "tenant_keys",
        "key_tombstones", "protected_objects", "policies", "snapshots", "items", "chunk_index", "packs", "jobs",
        "usage_daily", "audit_events", "audit_anchors",
    ];

    [PostgresFact]
    public async Task Migrations_are_idempotent_and_script_is_complete()
    {
        var second = await DatabaseMigrator.MigrateAsync(db.Migrator);
        Assert.Empty(second);

        var script = DatabaseMigrator.Script();
        Assert.Contains("CREATE TABLE vaulty.items", script, StringComparison.Ordinal);
        Assert.Contains("ENABLE ROW LEVEL SECURITY", script, StringComparison.Ordinal);
        Assert.Contains(DatabaseMigrator.HistoryTable, script, StringComparison.Ordinal);

        await using var connection = new NpgsqlConnection(db.Migrator);
        var partitions = await connection.ExecuteScalarAsync<int>(
            "SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhparent WHERE c.relname IN ('items', 'chunk_index')");
        Assert.Equal(128, partitions);
    }

    [PostgresFact]
    public async Task Every_organization_table_has_row_level_security()
    {
        await using var connection = new NpgsqlConnection(db.Migrator);
        var withoutRls = (await connection.QueryAsync<string>(
            """
            SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'vaulty' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
               AND NOT c.relrowsecurity AND c.relname NOT IN ('secrets', @history)
            """, new { history = DatabaseMigrator.HistoryTable })).ToList();
        Assert.Empty(withoutRls);

        var bypass = await connection.ExecuteScalarAsync<int>(
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'vaulty%' AND (rolbypassrls OR rolsuper)");
        Assert.Equal(0, bypass);
    }

    [PostgresFact]
    public async Task Organization_A_never_sees_rows_of_organization_B()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        await SeedOrganization(a);
        await SeedOrganization(b);

        foreach (var role in new[] { db.Api, db.Worker, db.Gc })
        {
            await using var dataSource = VaultyDataSource.Create(role);
            await using var session = await OrganizationSession.BeginAsync(dataSource, a);
            foreach (var table in OrganizationTables)
            {
                if (!await CanSelect(session, table)) continue;
                var column = table == "organizations" ? "id" : "organization_id";
                var foreign = await session.Connection.ExecuteScalarAsync<long>(
                    $"SELECT count(*) FROM vaulty.{table} WHERE {column} <> @a", new { a }, session.Transaction);
                var own = await session.Connection.ExecuteScalarAsync<long>(
                    $"SELECT count(*) FROM vaulty.{table}", transaction: session.Transaction);
                Assert.True(foreign == 0, $"{table}: {foreign} row(s) of another organization visible");
                Assert.True(own > 0, $"{table}: own rows not visible");
            }
        }

        // Without an organization in the session nothing is visible at all.
        await using var api = new NpgsqlConnection(db.Api);
        await api.OpenAsync();
        foreach (var table in OrganizationTables)
        {
            Assert.Equal(0, await api.ExecuteScalarAsync<long>($"SELECT count(*) FROM vaulty.{table}"));
        }
    }

    [PostgresFact]
    public async Task Writing_a_row_for_another_organization_is_refused()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        await SeedOrganization(a);
        await SeedOrganization(b);

        await using var dataSource = VaultyDataSource.Create(db.Api);
        await using var session = await OrganizationSession.BeginAsync(dataSource, a);
        var error = await Assert.ThrowsAsync<PostgresException>(() => session.Connection.ExecuteAsync(
            "INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@id, @b, 'X1', 'Other')",
            new { id = Guid.NewGuid(), b }, session.Transaction));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [PostgresFact]
    public async Task Audit_events_are_append_only_and_the_chain_validates_over_10000_events()
    {
        var a = Guid.NewGuid();
        await SeedOrganization(a);

        await using var dataSource = VaultyDataSource.Create(db.Api);
        await using (var session = await OrganizationSession.BeginAsync(dataSource, a))
        {
            for (var i = 0; i < 10_000; i++)
            {
                await AuditLog.WriteAsync(session, $"user:{i % 7}", "test.event", $"target:{i}",
                    new { index = i, note = "quote \" and unicode é" });
            }
            await session.CommitAsync();
        }

        await using (var session = await OrganizationSession.BeginAsync(dataSource, a))
        {
            var result = await AuditChainVerifier.VerifyAsync(session);
            Assert.True(result.Valid);
            Assert.Equal(10_001, result.EventsChecked); // plus the seeded event
        }

        await using (var session = await OrganizationSession.BeginAsync(dataSource, a))
        {
            var update = await Assert.ThrowsAsync<PostgresException>(() =>
                session.Connection.ExecuteAsync("UPDATE vaulty.audit_events SET actor = 'x'", transaction: session.Transaction));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, update.SqlState);
        }

        await using (var session = await OrganizationSession.BeginAsync(dataSource, a))
        {
            var delete = await Assert.ThrowsAsync<PostgresException>(() =>
                session.Connection.ExecuteAsync("DELETE FROM vaulty.audit_events", transaction: session.Transaction));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, delete.SqlState);
        }

        // Even the schema owner cannot change or remove an event: the trigger refuses.
        await using var owner = new NpgsqlConnection(db.Migrator);
        await owner.OpenAsync();
        var ownerUpdate = await Assert.ThrowsAsync<PostgresException>(() =>
            owner.ExecuteAsync("UPDATE vaulty.audit_events SET actor = 'x'"));
        Assert.Contains("append-only", ownerUpdate.MessageText, StringComparison.Ordinal);
        await Assert.ThrowsAsync<PostgresException>(() => owner.ExecuteAsync("DELETE FROM vaulty.audit_events"));
        await Assert.ThrowsAsync<PostgresException>(() => owner.ExecuteAsync("TRUNCATE vaulty.audit_events"));
    }

    [PostgresFact]
    public async Task A_tampered_audit_event_breaks_the_chain()
    {
        var a = Guid.NewGuid();
        await SeedOrganization(a);
        await using var dataSource = VaultyDataSource.Create(db.Api);
        await using (var session = await OrganizationSession.BeginAsync(dataSource, a))
        {
            for (var i = 0; i < 20; i++) await AuditLog.WriteAsync(session, "user:1", "test.event", null, new { i });
            await session.CommitAsync();
        }

        // Only a superuser that disables the trigger can tamper; the verifier still notices.
        await using (var admin = new NpgsqlConnection(db.Admin))
        {
            await admin.OpenAsync();
            await admin.ExecuteAsync(
                """
                ALTER TABLE vaulty.audit_events DISABLE TRIGGER audit_events_append_only;
                UPDATE vaulty.audit_events SET actor = 'user:2'
                 WHERE seq = (SELECT seq FROM vaulty.audit_events WHERE organization_id = @a ORDER BY seq OFFSET 10 LIMIT 1);
                ALTER TABLE vaulty.audit_events ENABLE TRIGGER audit_events_append_only;
                """, new { a });
        }

        await using var check = await OrganizationSession.BeginAsync(dataSource, a);
        var result = await AuditChainVerifier.VerifyAsync(check);
        Assert.False(result.Valid);
        Assert.Equal(10, result.EventsChecked); // the seeded event and nine more are intact
    }

    [PostgresFact]
    public async Task Api_role_cannot_run_ddl()
    {
        await using var api = new NpgsqlConnection(db.Api);
        await api.OpenAsync();
        var create = await Assert.ThrowsAsync<PostgresException>(() =>
            api.ExecuteAsync("CREATE TABLE vaulty.evil (id int)"));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, create.SqlState);
        var alter = await Assert.ThrowsAsync<PostgresException>(() =>
            api.ExecuteAsync("ALTER TABLE vaulty.customers DISABLE ROW LEVEL SECURITY"));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, alter.SqlState);
        var drop = await Assert.ThrowsAsync<PostgresException>(() => api.ExecuteAsync("DROP TABLE vaulty.items"));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, drop.SqlState);
        var publicSchema = await Assert.ThrowsAsync<PostgresException>(() =>
            api.ExecuteAsync("CREATE TABLE public.evil (id int)"));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, publicSchema.SqlState);
    }

    [PostgresFact]
    public async Task Gc_role_cannot_write_items()
    {
        var a = Guid.NewGuid();
        await SeedOrganization(a);
        await using var dataSource = VaultyDataSource.Create(db.Gc);
        foreach (var sql in new[]
                 {
                     "INSERT INTO vaulty.items (organization_id, tenant_id, id, protected_object_id, first_snapshot_id, source_id, kind) SELECT organization_id, tenant_id, gen_random_uuid(), protected_object_id, first_snapshot_id, 'x', 'mail' FROM vaulty.items LIMIT 1",
                     "UPDATE vaulty.items SET size = 1",
                     "DELETE FROM vaulty.items",
                     "INSERT INTO vaulty.chunk_index (organization_id, tenant_id, chunk_hash, pack_id, \"offset\", length, plaintext_length) SELECT organization_id, tenant_id, sha256('x'::bytea), pack_id, 0, 1, 1 FROM vaulty.chunk_index LIMIT 1",
                     "DELETE FROM vaulty.tenant_keys",
                 })
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, a);
            var error = await Assert.ThrowsAsync<PostgresException>(() =>
                session.Connection.ExecuteAsync(sql, transaction: session.Transaction));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
    }

    [PostgresFact]
    public async Task Workers_cannot_delete_backup_metadata()
    {
        var a = Guid.NewGuid();
        await SeedOrganization(a);
        await using var dataSource = VaultyDataSource.Create(db.Worker);
        foreach (var table in new[] { "items", "chunk_index", "packs", "snapshots", "tenant_keys", "audit_events" })
        {
            await using var session = await OrganizationSession.BeginAsync(dataSource, a);
            var error = await Assert.ThrowsAsync<PostgresException>(() =>
                session.Connection.ExecuteAsync($"DELETE FROM vaulty.{table}", transaction: session.Transaction));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
    }

    [PostgresFact]
    public async Task A_tenant_cannot_be_connected_to_two_organizations()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var entra = await SeedOrganization(a);
        await SeedOrganization(b);

        await using var dataSource = VaultyDataSource.Create(db.Api);
        await using var session = await OrganizationSession.BeginAsync(dataSource, b);
        Assert.True(await session.Connection.ExecuteScalarAsync<bool>(
            "SELECT vaulty.entra_tenant_connected(@entra)", new { entra }, session.Transaction));
        var customer = await session.Connection.ExecuteScalarAsync<Guid>(
            "SELECT id FROM vaulty.customers LIMIT 1", transaction: session.Transaction);
        var error = await Assert.ThrowsAsync<PostgresException>(() => session.Connection.ExecuteAsync(
            "INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name) VALUES (@id, @b, @customer, @entra, 'x')",
            new { id = Guid.NewGuid(), b, customer, entra }, session.Transaction));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, error.SqlState);
    }

    /// <summary>One row in every organization table, written as the schema owner. Returns the Entra tenant id.</summary>
    private async Task<Guid> SeedOrganization(Guid org)
    {
        var entra = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(db.Migrator);
        await connection.OpenAsync();
        await connection.ExecuteAsync(
            """
            INSERT INTO vaulty.organizations (id, name) VALUES (@org, 'Organization');
            INSERT INTO vaulty.users (id, organization_id, user_name, normalized_user_name, security_stamp, concurrency_stamp)
                VALUES (@user, @org, @uname, upper(@uname), 's', 'c');
            INSERT INTO vaulty.roles (id, organization_id, name) VALUES (@role, @org, 'Read-only');
            INSERT INTO vaulty.role_permissions (organization_id, role_id, permission) VALUES (@org, @role, 'customers.view');
            INSERT INTO vaulty.customers (id, organization_id, code, name) VALUES (@customer, @org, 'C001', 'Customer');
            INSERT INTO vaulty.role_assignments (id, organization_id, user_id, role_id, customer_id)
                VALUES (@assignment, @org, @user, @role, @customer);
            INSERT INTO vaulty.tenants (id, organization_id, customer_id, entra_tenant_id, display_name)
                VALUES (@tenant, @org, @customer, @entra, 'Tenant');
            INSERT INTO vaulty.tenant_keys (organization_id, tenant_id, version, wrapped_key) VALUES (@org, @tenant, 1, '\x00');
            INSERT INTO vaulty.protected_objects (id, organization_id, tenant_id, kind, source_id, display_name)
                VALUES (@object, @org, @tenant, 'mailbox', @source, 'Mailbox');
            INSERT INTO vaulty.key_tombstones (organization_id, tenant_id, protected_object_id, requested_by)
                VALUES (@org, @tenant, @object, @user);
            INSERT INTO vaulty.policies (id, organization_id, tenant_id, name) VALUES (@policy, @org, @tenant, 'Default');
            INSERT INTO vaulty.snapshots (id, organization_id, tenant_id, protected_object_id) VALUES (@snapshot, @org, @tenant, @object);
            INSERT INTO vaulty.items (organization_id, tenant_id, id, protected_object_id, first_snapshot_id, source_id, kind)
                VALUES (@org, @tenant, @item, @object, @snapshot, 'item-1', 'mail');
            INSERT INTO vaulty.packs (id, organization_id, tenant_id, object_key, size, lock_until)
                VALUES (@pack, @org, @tenant, @packKey, 1, now() + interval '1 day');
            INSERT INTO vaulty.chunk_index (organization_id, tenant_id, chunk_hash, pack_id, "offset", length, plaintext_length)
                VALUES (@org, @tenant, sha256(convert_to(@source, 'UTF8')), @pack, 0, 1, 1);
            INSERT INTO vaulty.jobs (id, organization_id, kind) VALUES (@job, @org, 'backup');
            INSERT INTO vaulty.usage_daily (organization_id, customer_id, date) VALUES (@org, @customer, current_date);
            INSERT INTO vaulty.audit_events (id, organization_id, actor, action) VALUES (@audit, @org, 'system', 'organization.created');
            INSERT INTO vaulty.audit_anchors (organization_id, anchor_date, last_seq, hash) VALUES (@org, current_date, 1, '\x00');
            """,
            new
            {
                org, entra, user = Guid.NewGuid(), uname = "user-" + org.ToString("N"), role = Guid.NewGuid(),
                customer = Guid.NewGuid(), assignment = Guid.NewGuid(), tenant = Guid.NewGuid(), @object = Guid.NewGuid(),
                source = "source-" + org.ToString("N"), policy = Guid.NewGuid(), snapshot = Guid.NewGuid(),
                item = Guid.NewGuid(), pack = Guid.NewGuid(), packKey = "tenants/" + org.ToString("N") + "/packs/1",
                job = Guid.NewGuid(), audit = Guid.NewGuid(),
            });
        return entra;
    }

    private static async Task<bool> CanSelect(OrganizationSession session, string table) =>
        await session.Connection.ExecuteScalarAsync<bool>(
            "SELECT has_table_privilege(current_user, 'vaulty.' || @table, 'SELECT')", new { table }, session.Transaction);
}
