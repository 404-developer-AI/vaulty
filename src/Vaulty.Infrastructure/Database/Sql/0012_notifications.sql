-- Notifications: alert mail, webhooks, the daily digest, and Graph usage per tenant for tenant health.

-- An alert is mailed once; open alerts stay visible on the dashboard until resolved.
ALTER TABLE vaulty.alerts ADD COLUMN notified_at timestamptz;
CREATE INDEX ix_alerts_unnotified ON vaulty.alerts (created_at) WHERE notified_at IS NULL;
CREATE INDEX ix_alerts_object_open ON vaulty.alerts (protected_object_id, kind) WHERE resolved_at IS NULL;

-- Per user: whether alert mail and the daily digest are wanted (only users who may see reports receive them).
ALTER TABLE vaulty.users ADD COLUMN alert_mail boolean NOT NULL DEFAULT true, ADD COLUMN digest_mail boolean NOT NULL DEFAULT true;

-- Outbox of events for webhooks (backup.failed, backup.partial, tenant.consent_lost, verification.failed, restore.completed, ...).
CREATE TABLE vaulty.notification_events (
    id                   uuid PRIMARY KEY,
    organization_id      uuid NOT NULL REFERENCES vaulty.organizations (id),
    kind                 text NOT NULL,
    tenant_id            uuid,
    protected_object_id  uuid,
    payload              jsonb NOT NULL DEFAULT '{}',
    created_at           timestamptz NOT NULL DEFAULT now(),
    dispatched_at        timestamptz
);
CREATE INDEX ix_notification_events_pending ON vaulty.notification_events (created_at) WHERE dispatched_at IS NULL;

-- Webhook endpoints. The signing secret is in the secrets store under "webhook.<id>", never in this table.
CREATE TABLE vaulty.webhooks (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    name             text NOT NULL,
    url              text NOT NULL CHECK (url ~ '^https?://'),
    events           text[] NOT NULL,
    enabled          boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    created_by       uuid
);

CREATE TABLE vaulty.webhook_deliveries (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    webhook_id       uuid NOT NULL REFERENCES vaulty.webhooks (id) ON DELETE CASCADE,
    event_id         uuid NOT NULL REFERENCES vaulty.notification_events (id),
    state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_status      integer,
    last_error       text,
    delivered_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (webhook_id, event_id)
);
CREATE INDEX ix_webhook_deliveries_due ON vaulty.webhook_deliveries (next_attempt_at) WHERE state = 'pending';
CREATE INDEX ix_webhook_deliveries_hook ON vaulty.webhook_deliveries (webhook_id, created_at DESC);

-- Graph requests and throttled responses per tenant and hour (the 429 ratio of tenant health).
CREATE TABLE vaulty.graph_usage_hourly (
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    tenant_id        uuid NOT NULL,
    hour             timestamptz NOT NULL,
    requests         bigint NOT NULL DEFAULT 0,
    throttled        bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, hour)
);

-- Digests sent, so a restarted worker never sends one twice.
CREATE TABLE vaulty.digests (
    organization_id  uuid NOT NULL REFERENCES vaulty.organizations (id),
    day              date NOT NULL,
    sent_at          timestamptz NOT NULL DEFAULT now(),
    recipients       integer NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, day)
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['notification_events', 'webhooks', 'webhook_deliveries', 'graph_usage_hourly', 'digests'] LOOP
        EXECUTE format('ALTER TABLE vaulty.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY organization_isolation ON vaulty.%I USING (organization_id = vaulty.current_organization_id()) '
                       'WITH CHECK (organization_id = vaulty.current_organization_id())', t);
        EXECUTE format('REVOKE ALL ON vaulty.%I FROM PUBLIC, vaulty_api, vaulty_worker, vaulty_gc', t);
    END LOOP;
END $$;

-- Events come from backups, restores and health checks (worker), verification (gc) and the web app.
GRANT SELECT, INSERT, UPDATE ON vaulty.notification_events TO vaulty_worker;
GRANT INSERT ON vaulty.notification_events TO vaulty_gc, vaulty_api;
GRANT SELECT ON vaulty.notification_events TO vaulty_api;
-- The web app manages webhooks; the workers deliver.
GRANT SELECT, INSERT, UPDATE, DELETE ON vaulty.webhooks TO vaulty_api;
GRANT SELECT ON vaulty.webhooks TO vaulty_worker;
GRANT SELECT, INSERT, UPDATE ON vaulty.webhook_deliveries TO vaulty_worker;
GRANT SELECT, INSERT ON vaulty.webhook_deliveries TO vaulty_api;
GRANT SELECT, INSERT, UPDATE ON vaulty.graph_usage_hourly TO vaulty_worker;
GRANT SELECT ON vaulty.graph_usage_hourly TO vaulty_api;
GRANT SELECT, INSERT, UPDATE ON vaulty.digests TO vaulty_worker;
-- The digest is built from the same dashboard as the web app.
GRANT SELECT ON vaulty.verification_runs TO vaulty_worker;
GRANT SELECT ON vaulty.digests TO vaulty_api;
-- The workers resolve alerts (a successful backup closes its open backup alerts) and mail them.
GRANT UPDATE ON vaulty.alerts TO vaulty_worker;
-- Recipients: users who may see reports.
GRANT SELECT ON vaulty.role_assignments, vaulty.role_permissions TO vaulty_worker;
GRANT UPDATE (alert_mail, digest_mail) ON vaulty.users TO vaulty_api;
