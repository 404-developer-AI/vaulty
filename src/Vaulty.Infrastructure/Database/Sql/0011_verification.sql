-- Verification, alerts, garbage collection and tenant deletion.

-- Alerts: what needs a person (verification failures, drift, consent lost, ...). Delivery (mail, webhooks) reads these.
CREATE TABLE vaulty.alerts (
    id                   uuid PRIMARY KEY,
    organization_id      uuid NOT NULL REFERENCES vaulty.organizations (id),
    tenant_id            uuid,
    protected_object_id  uuid,
    kind                 text NOT NULL,
    severity             text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    message              text NOT NULL,
    details              jsonb NOT NULL DEFAULT '{}',
    created_at           timestamptz NOT NULL DEFAULT now(),
    resolved_at          timestamptz,
    resolved_by          uuid
);
CREATE INDEX ix_alerts_open ON vaulty.alerts (organization_id, created_at DESC) WHERE resolved_at IS NULL;

-- One verification run per tenant: packs scrubbed, items drilled, snapshots checked, and what failed.
CREATE TABLE vaulty.verification_runs (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES vaulty.organizations (id),
    tenant_id          uuid NOT NULL,
    started_at         timestamptz NOT NULL DEFAULT now(),
    finished_at        timestamptz,
    packs_scrubbed     integer NOT NULL DEFAULT 0,
    items_drilled      integer NOT NULL DEFAULT 0,
    snapshots_checked  integer NOT NULL DEFAULT 0,
    failures           jsonb NOT NULL DEFAULT '[]'
);
CREATE INDEX ix_verification_runs_tenant ON vaulty.verification_runs (tenant_id, started_at DESC);

ALTER TABLE vaulty.packs ADD COLUMN last_scrubbed_at timestamptz, ADD COLUMN scrub_failed_at timestamptz;

-- Garbage collection runs: the plan (dry run) and what was removed.
CREATE TABLE vaulty.gc_runs (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES vaulty.organizations (id),
    tenant_id          uuid NOT NULL,
    dry_run            boolean NOT NULL,
    started_at         timestamptz NOT NULL DEFAULT now(),
    finished_at        timestamptz,
    state              text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'succeeded', 'refused', 'failed')),
    snapshots_expired  integer NOT NULL DEFAULT 0,
    packs_deleted      integer NOT NULL DEFAULT 0,
    bytes_deleted      bigint NOT NULL DEFAULT 0,
    report             jsonb NOT NULL DEFAULT '{}'
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['alerts', 'verification_runs', 'gc_runs'] LOOP
        EXECUTE format('ALTER TABLE vaulty.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY organization_isolation ON vaulty.%I USING (organization_id = vaulty.current_organization_id()) '
                       'WITH CHECK (organization_id = vaulty.current_organization_id())', t);
        EXECUTE format('REVOKE ALL ON vaulty.%I FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc', t);
    END LOOP;
END $$;

-- Verification and garbage collection run in the gc service under its own role: the only role that removes data.
GRANT SELECT, INSERT, UPDATE ON vaulty.alerts TO vaulty_gc;
GRANT SELECT, INSERT ON vaulty.alerts TO vaulty_worker;
GRANT SELECT, INSERT, UPDATE ON vaulty.alerts TO vaulty_api;
GRANT SELECT, INSERT, UPDATE ON vaulty.verification_runs, vaulty.gc_runs TO vaulty_gc;
GRANT SELECT ON vaulty.verification_runs, vaulty.gc_runs TO vaulty_api;
-- Garbage collection removes the database rows of item versions that only expired snapshots held.
GRANT DELETE ON vaulty.items TO vaulty_gc;
GRANT SELECT ON vaulty.customers, vaulty.key_tombstones TO vaulty_gc;
