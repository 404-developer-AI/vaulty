-- Snapshot browsing, search and previews.

-- Point-in-time membership without joins: an item version belongs to snapshot S of its protected object when it is
-- committed, first_sequence <= S and (deleted_sequence IS NULL OR deleted_sequence > S).
-- search_vector: tokens of the searchable metadata (subject, sender, file name, path); the source fields themselves stay
-- encrypted in sealed_metadata. The preview columns point at a separately stored preview (the HTML body of a message).
ALTER TABLE vaulty.items
    ADD COLUMN first_sequence bigint,
    ADD COLUMN deleted_sequence bigint,
    ADD COLUMN search_vector tsvector,
    ADD COLUMN preview_chunks bytea,
    ADD COLUMN preview_hash bytea,
    ADD COLUMN preview_size bigint,
    ADD COLUMN preview_type text;

UPDATE vaulty.items i SET first_sequence = s.sequence FROM vaulty.snapshots s WHERE s.id = i.first_snapshot_id;
UPDATE vaulty.items i SET deleted_sequence = s.sequence FROM vaulty.snapshots s WHERE s.id = i.deleted_in_snapshot_id;
UPDATE vaulty.items SET modified_at = created_at WHERE modified_at IS NULL;
ALTER TABLE vaulty.items ALTER COLUMN modified_at SET DEFAULT now(), ALTER COLUMN modified_at SET NOT NULL;

-- One page of a folder, newest first, read from the index alone.
CREATE INDEX ix_items_browse ON vaulty.items (tenant_id, protected_object_id, parent_source_id, modified_at DESC, id DESC)
    INCLUDE (state, first_sequence, deleted_sequence, kind);
CREATE INDEX ix_items_search ON vaulty.items USING gin (search_vector);
-- The folder tree of a snapshot without reading its items.
CREATE INDEX ix_items_folders ON vaulty.items (tenant_id, protected_object_id) INCLUDE (state, first_sequence, deleted_sequence) WHERE kind = 'folder';
