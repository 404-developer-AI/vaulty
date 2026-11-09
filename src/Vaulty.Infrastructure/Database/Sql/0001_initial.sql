-- Vaulty schema, version 1. Runs as vaulty_migrator, the owner of schema vaulty.
--
-- Isolation: every table that holds organization data has organization_id and row-level security. The application
-- sets the organization per transaction with set_config('vaulty.organization_id', <uuid>, true) (SET LOCAL). Without
-- that setting every policy evaluates to false, so a forgotten filter returns nothing instead of another
-- organization's rows. RLS is enabled but not forced: the owner (vaulty_migrator) is not subject to it, which lets the
-- few SECURITY DEFINER functions below answer narrow cross-organization questions. Application roles never own a table
-- and never have BYPASSRLS.

CREATE OR REPLACE FUNCTION vaulty.current_organization_id() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT NULLIF(current_setting('vaulty.organization_id', true), '')::uuid $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Organizations, users, roles
-- ---------------------------------------------------------------------------------------------------------------------
CREATE TABLE vaulty.organizations (
    id          uuid PRIMARY KEY,
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    settings    jsonb NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);

CREATE TABLE vaulty.users (
    id                    uuid PRIMARY KEY,
    organization_id       uuid NOT NULL REFERENCES vaulty.organizations (id),
    user_name             text NOT NULL,
    normalized_user_name  text NOT NULL UNIQUE,
    email                 text,
    normalized_email      text,
    email_confirmed       boolean NOT NULL DEFAULT false,
    display_name          text,
    password_hash         text,
    security_stamp        text NOT NULL,
    concurrency_stamp     text NOT NULL,
    two_factor_enabled    boolean NOT NULL DEFAULT false,
    authenticator_key     text,
    lockout_end           timestamptz,
    lockout_enabled       boolean NOT NULL DEFAULT true,
    access_failed_count   integer NOT NULL DEFAULT 0,
    created_at            timestamptz NOT NULL DEFAULT now(),
    disabled_at           timestamptz,
    UNIQUE (organization_id, id)
);
CREATE INDEX ix_users_org_email ON vaulty.users (organization_id, normalized_email);

CREATE TABLE vaulty.roles (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description      text,
    built_in         boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, id)
);

CREATE TABLE vaulty.role_permissions (
    organization_id  uuid NOT NULL,
    role_id          uuid NOT NULL,
    permission       text NOT NULL CHECK (permission ~ '^[a-z]+\.[a-z]+$'),
    PRIMARY KEY (role_id, permission),
    FOREIGN KEY (organization_id, role_id) REFERENCES vaulty.roles (organization_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------------------------------------------
-- Customers and tenants
-- ---------------------------------------------------------------------------------------------------------------------
CREATE TABLE vaulty.customers (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    code             text NOT NULL CHECK (length(code) BETWEEN 1 AND 40),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    tags             text[] NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz,
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX ux_customers_code ON vaulty.customers (organization_id, lower(code)) WHERE deleted_at IS NULL;

CREATE TABLE vaulty.role_assignments (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    user_id          uuid NOT NULL,
    role_id          uuid NOT NULL,
    customer_id      uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, user_id) REFERENCES vaulty.users (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, role_id) REFERENCES vaulty.roles (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, customer_id) REFERENCES vaulty.customers (organization_id, id)
);
CREATE UNIQUE INDEX ux_role_assignments ON vaulty.role_assignments
    (user_id, role_id, coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE vaulty.tenants (
    id                        uuid PRIMARY KEY,
    organization_id           uuid NOT NULL,
    customer_id               uuid NOT NULL,
    -- A Microsoft 365 tenant can be connected to one organization only: this constraint is global on purpose.
    entra_tenant_id           uuid NOT NULL UNIQUE,
    display_name              text NOT NULL,
    default_domain            text,
    auth_mode                 text NOT NULL DEFAULT 'dedicated_app' CHECK (auth_mode IN ('dedicated_app', 'shared_app')),
    client_id                 uuid,
    certificate_secret_name   text,
    certificate_thumbprint    text,
    certificate_expires_at    timestamptz,
    consent_state             text NOT NULL DEFAULT 'pending' CHECK (consent_state IN ('pending', 'granted', 'lost')),
    granted_permissions       jsonb NOT NULL DEFAULT '[]',
    health                    jsonb NOT NULL DEFAULT '{}',
    last_health_check_at      timestamptz,
    current_dek_version       integer,
    state                     text NOT NULL DEFAULT 'active'
                                  CHECK (state IN ('active', 'deletion_requested', 'deleted')),
    deletion_requested_at     timestamptz,
    deletion_requested_by     uuid,
    deletion_confirmed_by     uuid,
    legal_hold                boolean NOT NULL DEFAULT false,
    created_at                timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, customer_id) REFERENCES vaulty.customers (organization_id, id),
    -- The second administrator must be another person.
    CHECK (deletion_confirmed_by IS NULL OR deletion_confirmed_by <> deletion_requested_by)
);

CREATE TABLE vaulty.tenant_keys (
    organization_id  uuid NOT NULL,
    tenant_id        uuid NOT NULL,
    version          integer NOT NULL CHECK (version > 0),
    wrapped_key      bytea NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version),
    FOREIGN KEY (organization_id, tenant_id) REFERENCES vaulty.tenants (organization_id, id)
);

CREATE TABLE vaulty.key_tombstones (
    organization_id      uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    protected_object_id  uuid NOT NULL,
    requested_by         uuid NOT NULL,
    confirmed_by         uuid,
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, protected_object_id),
    FOREIGN KEY (organization_id, tenant_id) REFERENCES vaulty.tenants (organization_id, id),
    CHECK (confirmed_by IS NULL OR confirmed_by <> requested_by)
);

-- ---------------------------------------------------------------------------------------------------------------------
-- Policies, protected objects, snapshots
-- ---------------------------------------------------------------------------------------------------------------------
CREATE TABLE vaulty.protected_objects (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL,
    tenant_id          uuid NOT NULL,
    kind               text NOT NULL CHECK (kind IN ('mailbox', 'drive', 'site', 'team', 'directory')),
    sub_kind           text,
    source_id          text NOT NULL,
    display_name       text NOT NULL,
    state              text NOT NULL DEFAULT 'active'
                           CHECK (state IN ('active', 'source_deleted', 'paused', 'not_protected')),
    source_deleted_at  timestamptz,
    last_snapshot_id   uuid,
    next_run_at        timestamptz,
    delta_state        jsonb NOT NULL DEFAULT '{}',
    legal_hold         boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (tenant_id, kind, source_id),
    FOREIGN KEY (organization_id, tenant_id) REFERENCES vaulty.tenants (organization_id, id)
);
CREATE INDEX ix_protected_objects_due ON vaulty.protected_objects (next_run_at) WHERE state = 'active';

CREATE TABLE vaulty.policies (
    id                   uuid PRIMARY KEY,
    organization_id      uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    protected_object_id  uuid,
    name                 text NOT NULL,
    scope_rules          jsonb NOT NULL DEFAULT '{}',
    exclusions           jsonb NOT NULL DEFAULT '{}',
    frequency_minutes    integer NOT NULL DEFAULT 360 CHECK (frequency_minutes BETWEEN 15 AND 10080),
    -- The storage provider bills every object for at least 90 days; shorter retention saves nothing.
    retention_days       integer NOT NULL DEFAULT 90 CHECK (retention_days >= 90),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, tenant_id) REFERENCES vaulty.tenants (organization_id, id),
    FOREIGN KEY (organization_id, protected_object_id) REFERENCES vaulty.protected_objects (organization_id, id)
);
CREATE UNIQUE INDEX ux_policies_scope ON vaulty.policies
    (tenant_id, coalesce(protected_object_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE vaulty.snapshots (
    id                   uuid PRIMARY KEY,
    organization_id      uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    protected_object_id  uuid NOT NULL,
    state                text NOT NULL DEFAULT 'staged'
                             CHECK (state IN ('staged', 'committed', 'partial', 'failed', 'expired')),
    started_at           timestamptz NOT NULL DEFAULT now(),
    committed_at         timestamptz,
    item_counts          jsonb NOT NULL DEFAULT '{}',
    exceptions           jsonb NOT NULL DEFAULT '[]',
    manifest_root_hash   bytea,
    object_key           text,
    lock_until           timestamptz,
    verified_at          timestamptz,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, protected_object_id) REFERENCES vaulty.protected_objects (organization_id, id),
    -- A committed or partial snapshot always has its root hash and commit time.
    CHECK (state NOT IN ('committed', 'partial') OR (manifest_root_hash IS NOT NULL AND committed_at IS NOT NULL))
);
CREATE INDEX ix_snapshots_object ON vaulty.snapshots (protected_object_id, started_at DESC);

-- ---------------------------------------------------------------------------------------------------------------------
-- Items and chunk index: hash-partitioned on tenant_id (64 partitions). Queries always include tenant_id.
-- ---------------------------------------------------------------------------------------------------------------------
CREATE TABLE vaulty.items (
    organization_id         uuid NOT NULL,
    tenant_id               uuid NOT NULL,
    id                      uuid NOT NULL,
    protected_object_id     uuid NOT NULL,
    first_snapshot_id       uuid NOT NULL,
    deleted_in_snapshot_id  uuid,
    state                   text NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'committed')),
    source_id               text NOT NULL,
    parent_source_id        text,
    kind                    text NOT NULL,
    sealed_metadata         bytea,
    flags                   jsonb NOT NULL DEFAULT '{}',
    content_hash            bytea,
    size                    bigint NOT NULL DEFAULT 0 CHECK (size >= 0),
    modified_at             timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    -- Idempotent writes: one row per source item version per snapshot.
    UNIQUE (tenant_id, protected_object_id, source_id, first_snapshot_id)
) PARTITION BY HASH (tenant_id);
CREATE INDEX ix_items_parent ON vaulty.items (tenant_id, protected_object_id, parent_source_id);

CREATE TABLE vaulty.chunk_index (
    organization_id   uuid NOT NULL,
    tenant_id         uuid NOT NULL,
    chunk_hash        bytea NOT NULL CHECK (length(chunk_hash) = 32),
    pack_id           uuid NOT NULL,
    "offset"          bigint NOT NULL CHECK ("offset" >= 0),
    length            integer NOT NULL CHECK (length > 0),
    plaintext_length  integer NOT NULL CHECK (plaintext_length >= 0),
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chunk_hash)
) PARTITION BY HASH (tenant_id);
CREATE INDEX ix_chunk_index_pack ON vaulty.chunk_index (tenant_id, pack_id);

DO $$
BEGIN
    FOR i IN 0..63 LOOP
        EXECUTE format('CREATE TABLE vaulty.items_p%s PARTITION OF vaulty.items FOR VALUES WITH (MODULUS 64, REMAINDER %s)',
                       lpad(i::text, 2, '0'), i);
        EXECUTE format('CREATE TABLE vaulty.chunk_index_p%s PARTITION OF vaulty.chunk_index FOR VALUES WITH (MODULUS 64, REMAINDER %s)',
                       lpad(i::text, 2, '0'), i);
    END LOOP;
END $$;

CREATE TABLE vaulty.packs (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    tenant_id        uuid NOT NULL,
    object_key       text NOT NULL UNIQUE,
    size             bigint NOT NULL CHECK (size >= 0),
    sha256           bytea,
    state            text NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'committed', 'deleted')),
    lock_until       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, tenant_id) REFERENCES vaulty.tenants (organization_id, id)
);
CREATE INDEX ix_packs_tenant ON vaulty.packs (tenant_id, state);

-- ---------------------------------------------------------------------------------------------------------------------
-- Jobs, usage
-- ---------------------------------------------------------------------------------------------------------------------
CREATE TABLE vaulty.jobs (
    id                   uuid PRIMARY KEY,
    organization_id      uuid NOT NULL REFERENCES vaulty.organizations (id),
    tenant_id            uuid,
    protected_object_id  uuid,
    kind                 text NOT NULL
                             CHECK (kind IN ('discovery', 'backup', 'restore', 'export', 'verification', 'garbage_collection')),
    state                text NOT NULL DEFAULT 'queued'
                             CHECK (state IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled')),
    workflow_id          text,
    workflow_run_id      text,
    requested_by         uuid,
    created_at           timestamptz NOT NULL DEFAULT now(),
    started_at           timestamptz,
    finished_at          timestamptz,
    progress             jsonb NOT NULL DEFAULT '{}',
    result_counts        jsonb NOT NULL DEFAULT '{}',
    error                text
);
CREATE INDEX ix_jobs_org_created ON vaulty.jobs (organization_id, created_at DESC);
CREATE UNIQUE INDEX ux_jobs_workflow ON vaulty.jobs (workflow_id) WHERE workflow_id IS NOT NULL;

CREATE TABLE vaulty.usage_daily (
    organization_id  uuid NOT NULL,
    customer_id      uuid NOT NULL,
    date             date NOT NULL,
    protected_users  integer NOT NULL DEFAULT 0,
    bytes_stored     bigint NOT NULL DEFAULT 0,
    exports          integer NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, customer_id, date),
    FOREIGN KEY (organization_id, customer_id) REFERENCES vaulty.customers (organization_id, id)
);

-- ---------------------------------------------------------------------------------------------------------------------
-- Secrets: host-level, encrypted with a key derived from the host master key; no organization data in clear text.
-- ---------------------------------------------------------------------------------------------------------------------
CREATE TABLE vaulty.secrets (
    name        text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._:-]{0,199}$'),
    version     integer NOT NULL CHECK (version > 0),
    nonce       bytea NOT NULL CHECK (length(nonce) = 12),
    ciphertext  bytea NOT NULL,
    tag         bytea NOT NULL CHECK (length(tag) = 16),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL,
    rotated_at  timestamptz,
    PRIMARY KEY (name, version)
);

-- ---------------------------------------------------------------------------------------------------------------------
-- Audit log: append-only, hash-chained per organization.
-- hash = sha256(prev_hash || canonical text), canonical text = fields joined by U+001F (see vaulty.audit_canonical).
-- The first event of an organization chains to 32 zero bytes.
-- ---------------------------------------------------------------------------------------------------------------------
CREATE TABLE vaulty.audit_events (
    seq              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id               uuid NOT NULL UNIQUE,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    occurred_at      timestamptz NOT NULL DEFAULT now(),
    actor            text NOT NULL,
    action           text NOT NULL,
    target           text,
    details          jsonb NOT NULL DEFAULT '{}',
    prev_hash        bytea NOT NULL,
    hash             bytea NOT NULL
);
CREATE INDEX ix_audit_events_org_seq ON vaulty.audit_events (organization_id, seq);

CREATE TABLE vaulty.audit_anchors (
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    anchor_date      date NOT NULL,
    last_seq         bigint NOT NULL,
    hash             bytea NOT NULL,
    object_key       text,
    written_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, anchor_date)
);

CREATE OR REPLACE FUNCTION vaulty.audit_canonical(
    p_id uuid, p_organization_id uuid, p_occurred_at timestamptz, p_actor text, p_action text, p_target text,
    p_details jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT concat_ws(chr(31),
        'vaulty-audit-v1',
        p_id::text,
        p_organization_id::text,
        -- Microseconds since the Unix epoch: independent of time zone and display format.
        (floor(extract(epoch FROM p_occurred_at) * 1000000))::bigint::text,
        p_actor,
        p_action,
        coalesce(p_target, ''),
        p_details::text)
$$;

CREATE OR REPLACE FUNCTION vaulty.audit_events_chain() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    previous bytea;
BEGIN
    -- One writer per organization at a time, so the chain never forks.
    PERFORM pg_advisory_xact_lock(hashtextextended('vaulty.audit:' || NEW.organization_id::text, 0));
    SELECT a.hash INTO previous
      FROM vaulty.audit_events a
     WHERE a.organization_id = NEW.organization_id
     ORDER BY a.seq DESC
     LIMIT 1;
    NEW.occurred_at := date_trunc('microseconds', coalesce(NEW.occurred_at, now()));
    NEW.prev_hash := coalesce(previous, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);
    NEW.hash := sha256(NEW.prev_hash || convert_to(
        vaulty.audit_canonical(NEW.id, NEW.organization_id, NEW.occurred_at, NEW.actor, NEW.action, NEW.target,
                               NEW.details), 'UTF8'));
    RETURN NEW;
END $$;

CREATE TRIGGER audit_events_chain BEFORE INSERT ON vaulty.audit_events
    FOR EACH ROW EXECUTE FUNCTION vaulty.audit_events_chain();

CREATE OR REPLACE FUNCTION vaulty.refuse_change() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'vaulty: % on % is not allowed; the table is append-only', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON vaulty.audit_events
    FOR EACH ROW EXECUTE FUNCTION vaulty.refuse_change();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON vaulty.audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION vaulty.refuse_change();
CREATE TRIGGER audit_anchors_append_only BEFORE UPDATE OR DELETE ON vaulty.audit_anchors
    FOR EACH ROW EXECUTE FUNCTION vaulty.refuse_change();
CREATE TRIGGER audit_anchors_no_truncate BEFORE TRUNCATE ON vaulty.audit_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION vaulty.refuse_change();

-- ---------------------------------------------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['users', 'roles', 'role_permissions', 'role_assignments', 'customers', 'tenants',
                             'tenant_keys', 'key_tombstones', 'protected_objects', 'policies', 'snapshots', 'items',
                             'chunk_index', 'packs', 'jobs', 'usage_daily', 'audit_events', 'audit_anchors'] LOOP
        EXECUTE format('ALTER TABLE vaulty.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY organization_isolation ON vaulty.%I USING (organization_id = vaulty.current_organization_id()) '
            'WITH CHECK (organization_id = vaulty.current_organization_id())', t);
    END LOOP;
END $$;

ALTER TABLE vaulty.organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON vaulty.organizations
    USING (id = vaulty.current_organization_id()) WITH CHECK (id = vaulty.current_organization_id());

-- ---------------------------------------------------------------------------------------------------------------------
-- Grants: start from nothing, then give each role only what it needs.
-- ---------------------------------------------------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA vaulty FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA vaulty FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vaulty FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.current_organization_id() TO vaulty_api, vaulty_worker, vaulty_gc;
GRANT EXECUTE ON FUNCTION vaulty.audit_canonical(uuid, uuid, timestamptz, text, text, text, jsonb)
    TO vaulty_api, vaulty_worker, vaulty_gc;
GRANT EXECUTE ON FUNCTION vaulty.audit_events_chain() TO vaulty_api, vaulty_worker, vaulty_gc;
GRANT EXECUTE ON FUNCTION vaulty.refuse_change() TO vaulty_api, vaulty_worker, vaulty_gc;

-- Web and API
GRANT SELECT, INSERT, UPDATE ON vaulty.organizations TO vaulty_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON vaulty.users, vaulty.roles, vaulty.role_permissions, vaulty.role_assignments,
    vaulty.policies TO vaulty_api;
GRANT SELECT, INSERT, UPDATE ON vaulty.customers, vaulty.tenants, vaulty.protected_objects, vaulty.jobs,
    vaulty.secrets, vaulty.key_tombstones TO vaulty_api;
GRANT SELECT ON vaulty.snapshots, vaulty.items, vaulty.chunk_index, vaulty.packs, vaulty.tenant_keys, vaulty.usage_daily,
    vaulty.audit_anchors TO vaulty_api;
GRANT SELECT, INSERT ON vaulty.audit_events TO vaulty_api;
GRANT DELETE ON vaulty.secrets TO vaulty_api;

-- Workers
GRANT SELECT ON vaulty.organizations, vaulty.customers, vaulty.policies, vaulty.secrets, vaulty.key_tombstones,
    vaulty.users TO vaulty_worker;
GRANT SELECT, UPDATE ON vaulty.tenants TO vaulty_worker;
GRANT SELECT, INSERT, UPDATE ON vaulty.protected_objects, vaulty.snapshots, vaulty.items, vaulty.packs, vaulty.jobs,
    vaulty.usage_daily TO vaulty_worker;
GRANT SELECT, INSERT ON vaulty.chunk_index, vaulty.tenant_keys, vaulty.audit_events, vaulty.audit_anchors TO vaulty_worker;

-- Garbage collection: reads what it must keep, marks snapshots and packs, removes index rows of deleted packs.
-- It cannot write items, chunk index rows or keys.
GRANT SELECT ON vaulty.organizations, vaulty.tenants, vaulty.protected_objects, vaulty.policies, vaulty.items,
    vaulty.tenant_keys, vaulty.secrets TO vaulty_gc;
GRANT SELECT, UPDATE ON vaulty.snapshots, vaulty.packs TO vaulty_gc;
GRANT SELECT, DELETE ON vaulty.chunk_index TO vaulty_gc;
GRANT SELECT, INSERT, UPDATE ON vaulty.jobs TO vaulty_gc;
GRANT SELECT, INSERT ON vaulty.audit_events TO vaulty_gc;

-- Partitions are reached only through their parent table, where RLS applies.
DO $$
DECLARE
    p text;
BEGIN
    FOR p IN SELECT c.relname FROM pg_class c JOIN pg_inherits i ON i.inhrelid = c.oid
              JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'vaulty' AND c.relkind = 'r' LOOP
        EXECUTE format('REVOKE ALL ON vaulty.%I FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc', p);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Narrow cross-organization functions (SECURITY DEFINER, owned by vaulty_migrator, fixed search_path).
-- ---------------------------------------------------------------------------------------------------------------------

-- Sign-in: find the organization of a user name before an organization context exists.
CREATE OR REPLACE FUNCTION vaulty.find_user_organization(p_normalized_user_name text)
    RETURNS TABLE (user_id uuid, organization_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT u.id, u.organization_id FROM vaulty.users u
     WHERE u.normalized_user_name = p_normalized_user_name AND u.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION vaulty.find_user_organization(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.find_user_organization(text) TO vaulty_api;

-- Scheduler: protected objects due for a backup, across organizations; identifiers only.
CREATE OR REPLACE FUNCTION vaulty.due_protected_objects(p_now timestamptz, p_limit integer)
    RETURNS TABLE (organization_id uuid, tenant_id uuid, protected_object_id uuid, next_run_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT o.organization_id, o.tenant_id, o.id, o.next_run_at
      FROM vaulty.protected_objects o
      JOIN vaulty.tenants t ON t.id = o.tenant_id
     WHERE o.state = 'active' AND t.state = 'active' AND t.consent_state = 'granted'
       AND o.next_run_at IS NOT NULL AND o.next_run_at <= p_now
     ORDER BY o.next_run_at
     LIMIT greatest(p_limit, 0)
$$;
REVOKE ALL ON FUNCTION vaulty.due_protected_objects(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.due_protected_objects(timestamptz, integer) TO vaulty_worker;

-- Background jobs that walk every organization (health checks, anchors, verification): organization ids only.
CREATE OR REPLACE FUNCTION vaulty.active_organization_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$ SELECT id FROM vaulty.organizations WHERE deleted_at IS NULL ORDER BY id $$;
REVOKE ALL ON FUNCTION vaulty.active_organization_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.active_organization_ids() TO vaulty_api, vaulty_worker, vaulty_gc;

-- Which organization a tenant belongs to; used by workers that receive only a tenant id.
CREATE OR REPLACE FUNCTION vaulty.tenant_organization(p_tenant_id uuid) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$ SELECT organization_id FROM vaulty.tenants WHERE id = p_tenant_id $$;
REVOKE ALL ON FUNCTION vaulty.tenant_organization(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.tenant_organization(uuid) TO vaulty_api, vaulty_worker, vaulty_gc;

-- Whether a Microsoft 365 tenant is already connected anywhere (connecting it twice is refused).
CREATE OR REPLACE FUNCTION vaulty.entra_tenant_connected(p_entra_tenant_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$ SELECT EXISTS (SELECT 1 FROM vaulty.tenants WHERE entra_tenant_id = p_entra_tenant_id AND state <> 'deleted') $$;
REVOKE ALL ON FUNCTION vaulty.entra_tenant_connected(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.entra_tenant_connected(uuid) TO vaulty_api;
