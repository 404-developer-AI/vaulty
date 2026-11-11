-- Dashboards and column layouts, shared within an organization and linked to roles. A user gets the first published one
-- by priority that is linked to one of the user's roles; otherwise the default from the code. Neither ever widens what a
-- user sees: tiles and columns need their own permissions, and their data is read in the user's own session.

CREATE TABLE vaulty.dashboards (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES vaulty.organizations (id),
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    description        text CHECK (length(description) <= 500),
    priority           integer NOT NULL,
    published_layout   jsonb,
    draft_layout       jsonb,
    published_version  integer NOT NULL DEFAULT 0,
    published_at       timestamptz,
    published_by       uuid,
    -- Every change raises it; a change made on an older version is refused (optimistic concurrency).
    version            integer NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         uuid,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, priority) DEFERRABLE INITIALLY IMMEDIATE
);
CREATE UNIQUE INDEX ux_dashboards_name ON vaulty.dashboards (organization_id, lower(name));

CREATE TABLE vaulty.dashboard_roles (
    organization_id  uuid NOT NULL,
    dashboard_id     uuid NOT NULL,
    role_id          uuid NOT NULL,
    PRIMARY KEY (dashboard_id, role_id),
    FOREIGN KEY (organization_id, dashboard_id) REFERENCES vaulty.dashboards (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, role_id) REFERENCES vaulty.roles (organization_id, id) ON DELETE CASCADE
);

CREATE TABLE vaulty.dashboard_versions (
    organization_id  uuid NOT NULL,
    dashboard_id     uuid NOT NULL,
    version          integer NOT NULL,
    layout           jsonb NOT NULL,
    published_at     timestamptz NOT NULL DEFAULT now(),
    published_by     uuid,
    PRIMARY KEY (dashboard_id, version),
    FOREIGN KEY (organization_id, dashboard_id) REFERENCES vaulty.dashboards (organization_id, id) ON DELETE CASCADE
);

CREATE TABLE vaulty.column_layouts (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    list             text NOT NULL CHECK (list IN ('customers', 'tenants', 'objects', 'snapshots', 'jobs')),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    priority         integer NOT NULL,
    columns          text[] NOT NULL,
    version          integer NOT NULL DEFAULT 1,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    updated_by       uuid,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, list, priority) DEFERRABLE INITIALLY IMMEDIATE
);
CREATE UNIQUE INDEX ux_column_layouts_name ON vaulty.column_layouts (organization_id, list, lower(name));

CREATE TABLE vaulty.column_layout_roles (
    organization_id  uuid NOT NULL,
    layout_id        uuid NOT NULL,
    role_id          uuid NOT NULL,
    PRIMARY KEY (layout_id, role_id),
    FOREIGN KEY (organization_id, layout_id) REFERENCES vaulty.column_layouts (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, role_id) REFERENCES vaulty.roles (organization_id, id) ON DELETE CASCADE
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['dashboards', 'dashboard_roles', 'dashboard_versions', 'column_layouts', 'column_layout_roles'] LOOP
        EXECUTE format('ALTER TABLE vaulty.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY organization_isolation ON vaulty.%I USING (organization_id = vaulty.current_organization_id()) '
            'WITH CHECK (organization_id = vaulty.current_organization_id())', t);
        EXECUTE format('REVOKE ALL ON vaulty.%I FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON vaulty.%I TO vaulty_api', t);
    END LOOP;
END $$;

INSERT INTO vaulty.role_permissions (organization_id, role_id, permission)
SELECT r.organization_id, r.id, p.permission FROM vaulty.roles r CROSS JOIN (VALUES ('dashboards.manage'), ('columns.manage')) p (permission)
 WHERE r.built_in AND r.name = 'Organization admin'
ON CONFLICT DO NOTHING;
