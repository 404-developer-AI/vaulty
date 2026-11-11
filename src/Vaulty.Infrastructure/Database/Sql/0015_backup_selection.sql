-- Which mailboxes and drives are backed up is chosen per protected object. An excluded object gets no new backups; its
-- snapshots are kept until their retention ends. Per tenant, newly discovered objects are either backed up at once or
-- wait to be selected (the default).
ALTER TABLE vaulty.protected_objects DROP CONSTRAINT protected_objects_state_check;
ALTER TABLE vaulty.protected_objects ADD CONSTRAINT protected_objects_state_check
    CHECK (state IN ('active', 'source_deleted', 'paused', 'not_protected', 'excluded'));
ALTER TABLE vaulty.tenants ADD COLUMN protect_new_objects boolean NOT NULL DEFAULT false;
