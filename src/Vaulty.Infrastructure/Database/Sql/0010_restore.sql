-- Restores and exports: the plan, the result per item (kept one year) and one-time export links.

CREATE TABLE vaulty.restores (
    id                    uuid PRIMARY KEY,
    organization_id       uuid NOT NULL REFERENCES vaulty.organizations (id),
    tenant_id             uuid NOT NULL,
    protected_object_id   uuid NOT NULL,
    snapshot_id           uuid NOT NULL,
    job_id                uuid NOT NULL,
    kind                  text NOT NULL CHECK (kind IN ('restore', 'export')),
    -- Where to and how: restore folder, original location or another protected object; conflict behaviour for files.
    target_mode           text NOT NULL CHECK (target_mode IN ('restore_folder', 'original', 'other', 'export')),
    target_object_id      uuid,
    conflict              text NOT NULL DEFAULT 'rename' CHECK (conflict IN ('rename', 'skip', 'overwrite')),
    selection             jsonb NOT NULL,
    state                 text NOT NULL DEFAULT 'planning'
                              CHECK (state IN ('planning', 'running', 'paused', 'succeeded', 'partial', 'failed', 'cancelled')),
    requested_by          uuid NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    finished_at           timestamptz,
    report_expires_at     timestamptz NOT NULL DEFAULT now() + interval '1 year',
    counts                jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_restores_object ON vaulty.restores (organization_id, protected_object_id, created_at DESC);

CREATE TABLE vaulty.restore_items (
    organization_id   uuid NOT NULL,
    restore_id        uuid NOT NULL REFERENCES vaulty.restores (id),
    item_id           uuid NOT NULL,
    source_id         text NOT NULL,
    kind              text NOT NULL,
    -- Path inside the selection (folder names), used for restore folders and zip entries.
    relative_path     text NOT NULL DEFAULT '',
    -- Folder class of the original folder (IPF.Note, IPF.Appointment, ...), so a restore folder holds the right item type.
    folder_type       text,
    state             text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'restored', 'skipped', 'failed')),
    target_id         text,
    detail            text,
    finished_at       timestamptz,
    PRIMARY KEY (restore_id, item_id)
);
CREATE INDEX ix_restore_items_pending ON vaulty.restore_items (restore_id, item_id) WHERE state = 'pending';

CREATE TABLE vaulty.exports (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL REFERENCES vaulty.organizations (id),
    restore_id        uuid NOT NULL REFERENCES vaulty.restores (id),
    object_key        text NOT NULL,
    size              bigint NOT NULL,
    sha256            bytea NOT NULL,
    -- SHA-256 of the link token, set when the user creates the link; the token itself is shown once and never stored.
    token_hash        bytea,
    created_by        uuid NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    downloaded_at     timestamptz
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['restores', 'restore_items', 'exports'] LOOP
        EXECUTE format('ALTER TABLE vaulty.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY organization_isolation ON vaulty.%I USING (organization_id = vaulty.current_organization_id()) '
                       'WITH CHECK (organization_id = vaulty.current_organization_id())', t);
        EXECUTE format('REVOKE ALL ON vaulty.%I FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc', t);
    END LOOP;
END $$;

-- The web app plans restores and hands out export links; workers carry them out and record the results.
GRANT SELECT, INSERT, UPDATE ON vaulty.restores TO vaulty_api;
GRANT SELECT ON vaulty.restore_items TO vaulty_api;
GRANT SELECT, UPDATE ON vaulty.exports TO vaulty_api;
GRANT SELECT, UPDATE ON vaulty.restores TO vaulty_worker;
GRANT SELECT, INSERT, UPDATE ON vaulty.restore_items TO vaulty_worker;
GRANT SELECT, INSERT ON vaulty.exports TO vaulty_worker;
-- Reports older than a year are removed by garbage collection.
GRANT SELECT, DELETE ON vaulty.restores, vaulty.restore_items, vaulty.exports TO vaulty_gc;
