-- Connecting a tenant happens in two steps: Vaulty generates a certificate (pending connection), the administrator creates
-- the app registration in the customer's tenant and enters its ids; only then the tenant row exists.
CREATE TABLE vaulty.pending_tenant_connections (
    id                       uuid PRIMARY KEY,
    organization_id          uuid NOT NULL,
    customer_id              uuid NOT NULL,
    display_name             text NOT NULL,
    certificate_secret_name  text NOT NULL,
    certificate_thumbprint   text NOT NULL,
    certificate_expires_at   timestamptz NOT NULL,
    created_by               uuid NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, customer_id) REFERENCES vaulty.customers (organization_id, id)
);
ALTER TABLE vaulty.pending_tenant_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON vaulty.pending_tenant_connections
    USING (organization_id = vaulty.current_organization_id()) WITH CHECK (organization_id = vaulty.current_organization_id());
REVOKE ALL ON vaulty.pending_tenant_connections FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT, DELETE ON vaulty.pending_tenant_connections TO vaulty_api;

-- Certificate rotation: the next certificate is tested before it replaces the current one.
ALTER TABLE vaulty.tenants
    ADD COLUMN next_certificate_secret_name text,
    ADD COLUMN next_certificate_thumbprint  text,
    ADD COLUMN next_certificate_expires_at  timestamptz,
    ADD COLUMN consent_lost_at              timestamptz;

-- Source details of a protected object (mailbox id and type, drive id, archive state, licences).
ALTER TABLE vaulty.protected_objects ADD COLUMN source_details jsonb NOT NULL DEFAULT '{}';

-- Health checks run over all tenants: identifiers of connected tenants only.
CREATE OR REPLACE FUNCTION vaulty.connected_tenants()
    RETURNS TABLE (organization_id uuid, tenant_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$ SELECT organization_id, id FROM vaulty.tenants WHERE state = 'active' AND client_id IS NOT NULL ORDER BY id $$;
REVOKE ALL ON FUNCTION vaulty.connected_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.connected_tenants() TO vaulty_worker, vaulty_api;
