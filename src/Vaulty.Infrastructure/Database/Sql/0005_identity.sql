-- Identity: passkeys, hashed recovery codes, and the narrow lookups that sign-in needs before an organization is known.

ALTER TABLE vaulty.users ADD COLUMN recovery_codes text[] NOT NULL DEFAULT '{}';   -- SHA-256 hex of each unused code

CREATE TABLE vaulty.user_passkeys (
    organization_id     uuid NOT NULL,
    user_id             uuid NOT NULL,
    credential_id       bytea NOT NULL,
    public_key          bytea NOT NULL,
    name                text,
    created_at          timestamptz NOT NULL,
    sign_count          bigint NOT NULL DEFAULT 0,
    transports          text[],
    is_user_verified    boolean NOT NULL,
    is_backup_eligible  boolean NOT NULL,
    is_backed_up        boolean NOT NULL,
    attestation_object  bytea NOT NULL,
    client_data_json    bytea NOT NULL,
    PRIMARY KEY (user_id, credential_id),
    FOREIGN KEY (organization_id, user_id) REFERENCES vaulty.users (organization_id, id) ON DELETE CASCADE
);
-- A credential id identifies one passkey globally (sign-in looks it up before the organization is known).
CREATE UNIQUE INDEX ux_user_passkeys_credential ON vaulty.user_passkeys (credential_id);
ALTER TABLE vaulty.user_passkeys ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON vaulty.user_passkeys
    USING (organization_id = vaulty.current_organization_id()) WITH CHECK (organization_id = vaulty.current_organization_id());
REVOKE ALL ON vaulty.user_passkeys FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT, UPDATE, DELETE ON vaulty.user_passkeys TO vaulty_api;

-- The organization of a user id (cookie validation receives only the user id).
CREATE OR REPLACE FUNCTION vaulty.user_organization(p_user_id uuid) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$ SELECT organization_id FROM vaulty.users WHERE id = p_user_id AND disabled_at IS NULL $$;
REVOKE ALL ON FUNCTION vaulty.user_organization(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.user_organization(uuid) TO vaulty_api;

-- The user of a passkey credential id (passwordless sign-in).
CREATE OR REPLACE FUNCTION vaulty.passkey_user(p_credential_id bytea)
    RETURNS TABLE (user_id uuid, organization_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT p.user_id, p.organization_id FROM vaulty.user_passkeys p
      JOIN vaulty.users u ON u.id = p.user_id AND u.disabled_at IS NULL
     WHERE p.credential_id = p_credential_id
$$;
REVOKE ALL ON FUNCTION vaulty.passkey_user(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.passkey_user(bytea) TO vaulty_api;

-- First-administrator setup is only possible while no organization exists.
CREATE OR REPLACE FUNCTION vaulty.organization_count() RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$ SELECT count(*) FROM vaulty.organizations $$;
REVOKE ALL ON FUNCTION vaulty.organization_count() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.organization_count() TO vaulty_api;
