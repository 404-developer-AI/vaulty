-- Roles decide what a user may do, groups decide where: which customers and tenants. A role never gives access to a
-- customer and a group never gives a permission. The scope of a user is the union of the groups the user is in; without
-- a group a user sees nothing. The rules are evaluated in one place, vaulty.user_scope, which web and workers both use,
-- and the web sets the result on each session so row-level security limits every query to it.

CREATE TABLE vaulty.user_groups (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description      text CHECK (length(description) <= 500),
    -- Every customer, also the ones added later, minus the excludes of this group.
    all_customers    boolean NOT NULL DEFAULT false,
    -- The group new users join; at most one per organization, and it cannot be deleted.
    is_default       boolean NOT NULL DEFAULT false,
    version          integer NOT NULL DEFAULT 1,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX ux_user_groups_name ON vaulty.user_groups (organization_id, lower(name));
CREATE UNIQUE INDEX ux_user_groups_default ON vaulty.user_groups (organization_id) WHERE is_default;

CREATE TABLE vaulty.user_group_rules (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    group_id         uuid NOT NULL,
    kind             text NOT NULL CHECK (kind IN ('include', 'exclude')),
    customer_id      uuid,
    tenant_id        uuid REFERENCES vaulty.tenants (id) ON DELETE CASCADE,
    tag              text CHECK (length(tag) BETWEEN 1 AND 60),
    CHECK (num_nonnulls(customer_id, tenant_id, tag) = 1),
    FOREIGN KEY (organization_id, group_id) REFERENCES vaulty.user_groups (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, customer_id) REFERENCES vaulty.customers (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ux_user_group_rules ON vaulty.user_group_rules (group_id, kind, customer_id, tenant_id, tag) NULLS NOT DISTINCT;

-- An Entra security group of the organization's own tenant that gives roles and groups at every Microsoft sign-in.
CREATE TABLE vaulty.entra_group_mappings (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    entra_group_id   uuid NOT NULL,
    display_name     text CHECK (length(display_name) <= 256),
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, entra_group_id)
);
CREATE TABLE vaulty.entra_group_mapping_roles (
    organization_id  uuid NOT NULL,
    mapping_id       uuid NOT NULL,
    role_id          uuid NOT NULL,
    PRIMARY KEY (mapping_id, role_id),
    FOREIGN KEY (organization_id, mapping_id) REFERENCES vaulty.entra_group_mappings (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, role_id) REFERENCES vaulty.roles (organization_id, id) ON DELETE CASCADE
);
CREATE TABLE vaulty.entra_group_mapping_groups (
    organization_id  uuid NOT NULL,
    mapping_id       uuid NOT NULL,
    group_id         uuid NOT NULL,
    PRIMARY KEY (mapping_id, group_id),
    FOREIGN KEY (organization_id, mapping_id) REFERENCES vaulty.entra_group_mappings (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, group_id) REFERENCES vaulty.user_groups (organization_id, id) ON DELETE CASCADE
);

CREATE TABLE vaulty.user_group_members (
    organization_id  uuid NOT NULL,
    group_id         uuid NOT NULL,
    user_id          uuid NOT NULL,
    -- Set when the membership comes from an Entra group mapping; a manual membership has none and stays.
    mapping_id       uuid,
    added_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (organization_id, group_id) REFERENCES vaulty.user_groups (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, user_id) REFERENCES vaulty.users (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, mapping_id) REFERENCES vaulty.entra_group_mappings (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX ix_user_group_members_user ON vaulty.user_group_members (user_id);

-- A role given by an Entra group mapping is recognisable and removed when the mapping no longer applies.
ALTER TABLE vaulty.role_assignments ADD COLUMN mapping_id uuid,
    ADD FOREIGN KEY (organization_id, mapping_id) REFERENCES vaulty.entra_group_mappings (organization_id, id) ON DELETE CASCADE;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['user_groups', 'user_group_rules', 'user_group_members', 'entra_group_mappings', 'entra_group_mapping_roles',
                             'entra_group_mapping_groups'] LOOP
        EXECUTE format('ALTER TABLE vaulty.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY organization_isolation ON vaulty.%I USING (organization_id = vaulty.current_organization_id()) '
            'WITH CHECK (organization_id = vaulty.current_organization_id())', t);
        EXECUTE format('REVOKE ALL ON vaulty.%I FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON vaulty.%I TO vaulty_api', t);
        EXECUTE format('GRANT SELECT ON vaulty.%I TO vaulty_worker', t);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- The scope of a user
-- ---------------------------------------------------------------------------------------------------------------------

-- True when one of the user's groups covers every customer without an exclude.
CREATE OR REPLACE FUNCTION vaulty.user_sees_everything(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, vaulty
AS $$
    SELECT EXISTS (
        SELECT 1 FROM vaulty.user_groups g JOIN vaulty.user_group_members m ON m.group_id = g.id
         WHERE m.user_id = p_user AND g.all_customers
           AND NOT EXISTS (SELECT 1 FROM vaulty.user_group_rules r WHERE r.group_id = g.id AND r.kind = 'exclude'))
$$;

-- What a user sees: one row per whole customer (tenant_id NULL, whole true; its tenants, also future ones, included) and
-- one row per tenant of a customer the user sees only partly (whole false). Within one group the excludes win over the
-- includes; across groups the union counts. A customer included through a tag follows the tag.
CREATE OR REPLACE FUNCTION vaulty.user_scope(p_user uuid)
    RETURNS TABLE (customer_id uuid, tenant_id uuid, whole boolean)
    LANGUAGE sql STABLE SET search_path = pg_catalog, vaulty
AS $$
    WITH g AS (
        SELECT gr.id, gr.all_customers FROM vaulty.user_groups gr JOIN vaulty.user_group_members m ON m.group_id = gr.id WHERE m.user_id = p_user
    ), r AS (
        SELECT r.* FROM vaulty.user_group_rules r WHERE r.group_id IN (SELECT id FROM g)
    ), c AS (
        SELECT id, tags FROM vaulty.customers WHERE deleted_at IS NULL
    ), inc_c AS (
        SELECT g.id AS gid, c.id AS cid FROM g JOIN c ON g.all_customers
        UNION SELECT r.group_id, r.customer_id FROM r WHERE r.kind = 'include' AND r.customer_id IS NOT NULL
        UNION SELECT r.group_id, c.id FROM r JOIN c ON r.tag = ANY (c.tags) WHERE r.kind = 'include' AND r.tag IS NOT NULL
    ), exc_c AS (
        SELECT r.group_id AS gid, r.customer_id AS cid FROM r WHERE r.kind = 'exclude' AND r.customer_id IS NOT NULL
        UNION SELECT r.group_id, c.id FROM r JOIN c ON r.tag = ANY (c.tags) WHERE r.kind = 'exclude' AND r.tag IS NOT NULL
    ), exc_t AS (
        SELECT r.group_id AS gid, r.tenant_id AS tid FROM r WHERE r.kind = 'exclude' AND r.tenant_id IS NOT NULL
    ), whole AS (
        SELECT DISTINCT i.cid FROM inc_c i
         WHERE i.cid IN (SELECT id FROM c)
           AND NOT EXISTS (SELECT 1 FROM exc_c e WHERE e.gid = i.gid AND e.cid = i.cid)
           AND NOT EXISTS (SELECT 1 FROM exc_t x JOIN vaulty.tenants t ON t.id = x.tid WHERE x.gid = i.gid AND t.customer_id = i.cid)
    ), vis AS (
        SELECT i.gid, t.customer_id AS cid, t.id AS tid FROM inc_c i JOIN vaulty.tenants t ON t.customer_id = i.cid
         WHERE NOT EXISTS (SELECT 1 FROM exc_c e WHERE e.gid = i.gid AND e.cid = i.cid)
        UNION
        SELECT r.group_id, t.customer_id, t.id FROM r JOIN vaulty.tenants t ON t.id = r.tenant_id
         WHERE r.kind = 'include' AND t.customer_id IN (SELECT id FROM c)
           AND NOT EXISTS (SELECT 1 FROM exc_c e WHERE e.gid = r.group_id AND e.cid = t.customer_id)
    )
    SELECT w.cid, NULL::uuid, true FROM whole w
    UNION ALL
    SELECT DISTINCT v.cid, v.tid, false FROM vis v
     WHERE v.cid NOT IN (SELECT cid FROM whole)
       AND NOT EXISTS (SELECT 1 FROM exc_t x WHERE x.gid = v.gid AND x.tid = v.tid)
$$;

-- Whether a user sees (part of) a customer: for alert mail and access lists.
CREATE OR REPLACE FUNCTION vaulty.user_sees_customer(p_user uuid, p_customer uuid) RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, vaulty
AS $$
    SELECT vaulty.user_sees_everything(p_user) OR EXISTS (SELECT 1 FROM vaulty.user_scope(p_user) s WHERE s.customer_id = p_customer)
$$;

GRANT EXECUTE ON FUNCTION vaulty.user_sees_everything(uuid), vaulty.user_scope(uuid), vaulty.user_sees_customer(uuid, uuid) TO vaulty_api, vaulty_worker;

-- ---------------------------------------------------------------------------------------------------------------------
-- Row-level security on the scope. A web session of a user sets vaulty.scope_restricted = '1' and three lists: the whole
-- customers, the customers seen partly, and every tenant the user sees (the tenants of whole customers included, listed
-- when the session starts). A session without it (workers, GC, system tasks) is limited to its organization only. The
-- policies are RESTRICTIVE: they narrow the organization policy, never widen it. Each list is read once per query (the
-- scalar subqueries become init plans), so the policy costs one array test per row; measured in the scope test.
-- ---------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION vaulty.scope_restricted() RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT coalesce(current_setting('vaulty.scope_restricted', true), '') = '1' $$;

CREATE OR REPLACE FUNCTION vaulty.scope_list(p_name text) RETURNS uuid[]
    LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT coalesce(nullif(current_setting(p_name, true), ''), '{}')::uuid[] $$;

CREATE POLICY user_scope ON vaulty.customers AS RESTRICTIVE
    USING (NOT (SELECT vaulty.scope_restricted()) OR id = ANY ((SELECT vaulty.scope_list('vaulty.scope_whole'))::uuid[])
           OR id = ANY ((SELECT vaulty.scope_list('vaulty.scope_customers'))::uuid[]))
    WITH CHECK (NOT (SELECT vaulty.scope_restricted()) OR id = ANY ((SELECT vaulty.scope_list('vaulty.scope_whole'))::uuid[])
           OR id = ANY ((SELECT vaulty.scope_list('vaulty.scope_customers'))::uuid[]));
-- A tenant created later for a whole customer is in scope through its customer.
CREATE POLICY user_scope ON vaulty.tenants AS RESTRICTIVE
    USING (NOT (SELECT vaulty.scope_restricted()) OR id = ANY ((SELECT vaulty.scope_list('vaulty.scope_tenants'))::uuid[])
           OR customer_id = ANY ((SELECT vaulty.scope_list('vaulty.scope_whole'))::uuid[]))
    WITH CHECK (NOT (SELECT vaulty.scope_restricted()) OR id = ANY ((SELECT vaulty.scope_list('vaulty.scope_tenants'))::uuid[])
           OR customer_id = ANY ((SELECT vaulty.scope_list('vaulty.scope_whole'))::uuid[]));

-- Every other table that belongs to a tenant or a customer. The rules and assignments of access itself are not scoped.
DO $$
DECLARE
    t record;
    tenant_rule constant text := 'NOT (SELECT vaulty.scope_restricted()) OR tenant_id IS NULL OR tenant_id = ANY ((SELECT vaulty.scope_list(''vaulty.scope_tenants''))::uuid[])';
    customer_rule constant text := 'NOT (SELECT vaulty.scope_restricted()) OR customer_id IS NULL '
        'OR customer_id = ANY ((SELECT vaulty.scope_list(''vaulty.scope_whole''))::uuid[]) OR customer_id = ANY ((SELECT vaulty.scope_list(''vaulty.scope_customers''))::uuid[])';
BEGIN
    FOR t IN
        SELECT c.table_name, bool_or(c.column_name = 'tenant_id') AS has_tenant
          FROM information_schema.columns c
          JOIN pg_class k ON k.relname = c.table_name AND k.relnamespace = 'vaulty'::regnamespace AND k.relkind IN ('r', 'p')
         WHERE c.table_schema = 'vaulty' AND c.column_name IN ('tenant_id', 'customer_id')
           AND c.table_name NOT IN ('customers', 'tenants', 'role_assignments', 'user_group_rules')
           -- partitions inherit the policy of their parent
           AND NOT k.relispartition
         GROUP BY c.table_name
    LOOP
        EXECUTE format('ALTER TABLE vaulty.%I ENABLE ROW LEVEL SECURITY', t.table_name);
        IF t.has_tenant THEN
            EXECUTE format('CREATE POLICY user_scope ON vaulty.%I AS RESTRICTIVE USING (%s) WITH CHECK (%s)', t.table_name, tenant_rule, tenant_rule);
        ELSE
            EXECUTE format('CREATE POLICY user_scope ON vaulty.%I AS RESTRICTIVE USING (%s) WITH CHECK (%s)', t.table_name, customer_rule, customer_rule);
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Existing organizations: a default group "All customers" with every user, except users whose roles were limited to
-- customers. Those get a group of exactly those customers instead, so the change neither widens nor narrows what they see
-- (a user with both limited and unlimited roles keeps the limited scope: never wider). The old column stays for old
-- binaries during a rollback, which then still read the limits; this version no longer writes it.
-- ---------------------------------------------------------------------------------------------------------------------

INSERT INTO vaulty.user_groups (id, organization_id, name, description, all_customers, is_default)
SELECT gen_random_uuid(), o.id, 'All customers', 'Every customer of the organization. New users join this group.', true, true
  FROM vaulty.organizations o;

INSERT INTO vaulty.user_groups (id, organization_id, name, description, all_customers)
SELECT gen_random_uuid(), u.organization_id, left('Customers of ' || u.user_name, 100), 'Made from the customer limits of the user''s roles.', false
  FROM vaulty.users u WHERE EXISTS (SELECT 1 FROM vaulty.role_assignments a WHERE a.user_id = u.id AND a.customer_id IS NOT NULL);

INSERT INTO vaulty.user_group_rules (id, organization_id, group_id, kind, customer_id)
SELECT DISTINCT ON (g.id, a.customer_id) gen_random_uuid(), a.organization_id, g.id, 'include', a.customer_id
  FROM vaulty.role_assignments a JOIN vaulty.users u ON u.id = a.user_id
  JOIN vaulty.user_groups g ON g.organization_id = u.organization_id AND g.name = left('Customers of ' || u.user_name, 100) AND NOT g.is_default
 WHERE a.customer_id IS NOT NULL;

INSERT INTO vaulty.user_group_members (organization_id, group_id, user_id)
SELECT u.organization_id, g.id, u.id FROM vaulty.users u
  JOIN vaulty.user_groups g ON g.organization_id = u.organization_id
       AND CASE WHEN EXISTS (SELECT 1 FROM vaulty.role_assignments a WHERE a.user_id = u.id AND a.customer_id IS NOT NULL)
                THEN g.name = left('Customers of ' || u.user_name, 100) AND NOT g.is_default
                ELSE g.is_default END;

-- A new user joins the default group of the organization.
CREATE OR REPLACE FUNCTION vaulty.join_default_group() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
BEGIN
    INSERT INTO vaulty.user_group_members (organization_id, group_id, user_id)
    SELECT NEW.organization_id, g.id, NEW.id FROM vaulty.user_groups g WHERE g.organization_id = NEW.organization_id AND g.is_default
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END $$;
CREATE TRIGGER users_join_default_group AFTER INSERT ON vaulty.users FOR EACH ROW EXECUTE FUNCTION vaulty.join_default_group();

-- New permissions of the catalog, for the built-in Organization admin role of every existing organization.
INSERT INTO vaulty.role_permissions (organization_id, role_id, permission)
SELECT r.organization_id, r.id, p.permission FROM vaulty.roles r CROSS JOIN (VALUES ('groups.manage'), ('access.view')) p (permission)
 WHERE r.built_in AND r.name = 'Organization admin'
ON CONFLICT DO NOTHING;
