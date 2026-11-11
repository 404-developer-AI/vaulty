-- Sign-in with Microsoft Entra ID for the people of an organization. One app registration per organization, in the
-- organization's own Microsoft tenant, authenticated with a certificate (its private key is in the secret store). A
-- user is linked to exactly one Entra account by tenant id and object id, never by e-mail address. No token is stored.

CREATE TABLE vaulty.microsoft_sign_in (
    organization_id  uuid PRIMARY KEY REFERENCES vaulty.organizations (id),
    entra_tenant_id  uuid,
    enabled          boolean NOT NULL DEFAULT false,
    -- The organization's tenant asks linked users for their second factor; Vaulty asks none of its own.
    microsoft_handles_second_factor  boolean NOT NULL DEFAULT true,
    -- Only Microsoft sign-in, except for local Organization admins kept for emergencies (break-glass).
    sign_in_only     boolean NOT NULL DEFAULT false,
    settings         jsonb NOT NULL DEFAULT '{}',
    updated_at       timestamptz NOT NULL DEFAULT now()
);
-- A Microsoft tenant signs in to one organization only.
CREATE UNIQUE INDEX ux_microsoft_sign_in_tenant ON vaulty.microsoft_sign_in (entra_tenant_id) WHERE entra_tenant_id IS NOT NULL;
ALTER TABLE vaulty.microsoft_sign_in ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON vaulty.microsoft_sign_in
    USING (organization_id = vaulty.current_organization_id()) WITH CHECK (organization_id = vaulty.current_organization_id());
REVOKE ALL ON vaulty.microsoft_sign_in FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc;
GRANT SELECT, INSERT, UPDATE ON vaulty.microsoft_sign_in TO vaulty_api;

ALTER TABLE vaulty.users
    ADD COLUMN entra_tenant_id  uuid,
    ADD COLUMN entra_object_id  uuid,
    ADD COLUMN entra_account    text CHECK (length(entra_account) <= 320),
    ADD COLUMN entra_linked_at  timestamptz,
    ADD CONSTRAINT ck_users_entra_link CHECK ((entra_tenant_id IS NULL) = (entra_object_id IS NULL));
-- One Entra account belongs to one Vaulty user.
CREATE UNIQUE INDEX ux_users_entra ON vaulty.users (entra_tenant_id, entra_object_id) WHERE entra_object_id IS NOT NULL;

-- The sign-in configurations that are switched on, for the sign-in page (no secrets: the certificate is in the secret store).
CREATE OR REPLACE FUNCTION vaulty.microsoft_sign_in_enabled()
    RETURNS TABLE (organization_id uuid, entra_tenant_id uuid, sign_in_only boolean, settings jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT s.organization_id, s.entra_tenant_id, s.sign_in_only, s.settings FROM vaulty.microsoft_sign_in s
      JOIN vaulty.organizations o ON o.id = s.organization_id AND o.deleted_at IS NULL
     WHERE s.enabled AND s.entra_tenant_id IS NOT NULL
$$;
REVOKE ALL ON FUNCTION vaulty.microsoft_sign_in_enabled() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.microsoft_sign_in_enabled() TO vaulty_api;

-- The user linked to an Entra account, only in the organization whose switched-on sign-in uses that tenant.
CREATE OR REPLACE FUNCTION vaulty.microsoft_user(p_tenant_id uuid, p_object_id uuid)
    RETURNS TABLE (user_id uuid, organization_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT u.id, u.organization_id FROM vaulty.users u
      JOIN vaulty.microsoft_sign_in s ON s.organization_id = u.organization_id AND s.enabled AND s.entra_tenant_id = p_tenant_id
     WHERE u.entra_tenant_id = p_tenant_id AND u.entra_object_id = p_object_id AND u.disabled_at IS NULL
$$;
REVOKE ALL ON FUNCTION vaulty.microsoft_user(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.microsoft_user(uuid, uuid) TO vaulty_api;

-- New permission of the catalog. Built-in roles hold exactly the permissions stored for them, so the built-in
-- Organization admin role of every existing organization receives it here; custom roles never gain a permission by themselves.
INSERT INTO vaulty.role_permissions (organization_id, role_id, permission)
SELECT organization_id, id, 'signin.manage' FROM vaulty.roles WHERE built_in AND name = 'Organization admin'
ON CONFLICT DO NOTHING;
