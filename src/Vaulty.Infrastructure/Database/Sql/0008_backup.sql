-- Backup bookkeeping.

-- The chunks of an item's content (32-byte ids, concatenated) for restores without reading manifests, and the change key
-- that tells whether the source item changed since its last version.
ALTER TABLE vaulty.items
    ADD COLUMN content_chunks bytea,
    ADD COLUMN change_key text,
    ADD COLUMN limited_fidelity boolean NOT NULL DEFAULT false;
CREATE INDEX ix_items_current ON vaulty.items (tenant_id, protected_object_id, source_id) WHERE deleted_in_snapshot_id IS NULL;

-- Snapshots are ordered per protected object; membership of an item version in a snapshot uses this order.
ALTER TABLE vaulty.snapshots ADD COLUMN sequence bigint;
CREATE UNIQUE INDEX ux_snapshots_sequence ON vaulty.snapshots (protected_object_id, sequence) WHERE sequence IS NOT NULL;

-- Items that failed, with the error, to report partial snapshots and to recognize poison items (same error three times).
CREATE TABLE vaulty.item_failures (
    organization_id      uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    protected_object_id  uuid NOT NULL,
    source_id            text NOT NULL,
    folder_id            text,
    error_code           text NOT NULL,
    item_type            text,
    error_detail         text,
    failure_count        integer NOT NULL DEFAULT 1,
    first_failed_at      timestamptz NOT NULL DEFAULT now(),
    last_failed_at       timestamptz NOT NULL DEFAULT now(),
    last_snapshot_id     uuid,
    resolved_at          timestamptz,
    PRIMARY KEY (protected_object_id, source_id),
    FOREIGN KEY (organization_id, protected_object_id) REFERENCES vaulty.protected_objects (organization_id, id)
);
ALTER TABLE vaulty.item_failures ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON vaulty.item_failures
    USING (organization_id = vaulty.current_organization_id()) WITH CHECK (organization_id = vaulty.current_organization_id());
REVOKE ALL ON vaulty.item_failures FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT, UPDATE ON vaulty.item_failures TO vaulty_worker;
GRANT SELECT ON vaulty.item_failures TO vaulty_api;

-- New delta links per folder, written by the folder sync and copied to the protected object only after the commit.
ALTER TABLE vaulty.folder_checkpoints ADD COLUMN delta_link text, ADD COLUMN completed boolean NOT NULL DEFAULT false,
    ADD COLUMN resynced boolean NOT NULL DEFAULT false;

-- Running backups per tenant, for the scheduler's budgets (identifiers only).
CREATE OR REPLACE FUNCTION vaulty.running_backups()
    RETURNS TABLE (tenant_id uuid, kind text, running bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT j.tenant_id, o.kind, count(*) FROM vaulty.jobs j JOIN vaulty.protected_objects o ON o.id = j.protected_object_id
     WHERE j.kind = 'backup' AND j.state IN ('queued', 'running') GROUP BY j.tenant_id, o.kind
$$;
REVOKE ALL ON FUNCTION vaulty.running_backups() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.running_backups() TO vaulty_worker;

-- Removals seen during a backup; applied to the items only when the snapshot commits.
CREATE TABLE vaulty.pending_removals (
    organization_id      uuid NOT NULL,
    tenant_id            uuid NOT NULL,
    snapshot_id          uuid NOT NULL,
    protected_object_id  uuid NOT NULL,
    source_id            text NOT NULL,
    PRIMARY KEY (snapshot_id, source_id),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES vaulty.snapshots (organization_id, id)
);
ALTER TABLE vaulty.pending_removals ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON vaulty.pending_removals
    USING (organization_id = vaulty.current_organization_id()) WITH CHECK (organization_id = vaulty.current_organization_id());
REVOKE ALL ON vaulty.pending_removals FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT ON vaulty.pending_removals TO vaulty_worker;
