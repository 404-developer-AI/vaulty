-- Page checkpoints of folder and drive synchronization: a restarted activity or workflow resumes after the last stored page.
CREATE TABLE vaulty.folder_checkpoints (
    organization_id  uuid NOT NULL,
    tenant_id        uuid NOT NULL,
    snapshot_id      uuid NOT NULL,
    folder_id        text NOT NULL,
    next_page        integer NOT NULL DEFAULT 0 CHECK (next_page >= 0),
    page_cursor      text,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (snapshot_id, folder_id),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES vaulty.snapshots (organization_id, id)
);
ALTER TABLE vaulty.folder_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON vaulty.folder_checkpoints
    USING (organization_id = vaulty.current_organization_id()) WITH CHECK (organization_id = vaulty.current_organization_id());
REVOKE ALL ON vaulty.folder_checkpoints FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT, UPDATE ON vaulty.folder_checkpoints TO vaulty_worker;
GRANT SELECT ON vaulty.folder_checkpoints TO vaulty_api;
