-- Platform settings that are not secret (storage account layout, SMTP host, display time zone, webhook defaults).
-- Secrets (access keys, SMTP password) are in vaulty.secrets; a value here never contains one.
CREATE TABLE vaulty.platform_settings (
    key         text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{0,63}$'),
    value       jsonb NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL
);
REVOKE ALL ON vaulty.platform_settings FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT, UPDATE ON vaulty.platform_settings TO vaulty_api;
GRANT SELECT ON vaulty.platform_settings TO vaulty_worker, vaulty_gc;
