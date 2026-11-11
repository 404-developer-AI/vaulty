-- Connecting a tenant from the browser: Vaulty creates the app registration itself after an administrator of the
-- customer's tenant signs in. Each step is recorded on the pending connection so an interrupted set-up resumes where it
-- stopped and never creates a second app registration. No token is ever stored.
ALTER TABLE vaulty.pending_tenant_connections
    ADD COLUMN include_restore        boolean NOT NULL DEFAULT true,
    ADD COLUMN method                 text NOT NULL DEFAULT 'script' CHECK (method IN ('script', 'browser')),
    ADD COLUMN step                   text NOT NULL DEFAULT 'started'
        CHECK (step IN ('started', 'signed_in', 'app_created', 'service_principal_created', 'permissions_granted')),
    ADD COLUMN entra_tenant_id        uuid,
    ADD COLUMN application_object_id  uuid,
    ADD COLUMN client_id              uuid,
    ADD COLUMN certificate_key_id     uuid,
    ADD COLUMN updated_at             timestamptz NOT NULL DEFAULT now();
GRANT UPDATE ON vaulty.pending_tenant_connections TO vaulty_api;

-- The object id of the app registration lets Vaulty roll its certificate itself (addKey with a proof signed by the
-- current certificate); the key ids let it remove the old certificate afterwards.
ALTER TABLE vaulty.tenants
    ADD COLUMN application_object_id    uuid,
    ADD COLUMN certificate_key_id       uuid,
    ADD COLUMN next_certificate_key_id  uuid;

-- Tenants whose certificate Vaulty can roll itself and that expire before the given moment (identifiers only).
CREATE OR REPLACE FUNCTION vaulty.tenants_due_for_rotation(p_before timestamptz)
    RETURNS TABLE (organization_id uuid, tenant_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT organization_id, id FROM vaulty.tenants
     WHERE state = 'active' AND client_id IS NOT NULL AND application_object_id IS NOT NULL
       AND certificate_expires_at < p_before
     ORDER BY certificate_expires_at
$$;
REVOKE ALL ON FUNCTION vaulty.tenants_due_for_rotation(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.tenants_due_for_rotation(timestamptz) TO vaulty_api;
