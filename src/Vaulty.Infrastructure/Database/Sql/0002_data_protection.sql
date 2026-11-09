-- ASP.NET Data Protection key ring (host-level, sealed with a key derived from the host master key).
CREATE TABLE vaulty.data_protection_keys (
    id             integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    friendly_name  text NOT NULL UNIQUE,
    sealed_xml     bytea NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON vaulty.data_protection_keys FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT ON vaulty.data_protection_keys TO vaulty_api;
