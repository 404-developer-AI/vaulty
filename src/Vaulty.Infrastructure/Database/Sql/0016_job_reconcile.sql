-- When someone asked to stop a job. The reconciler forwards the request to the job's current workflow run when the
-- original request could not reach it, and stops a run that is stuck and can no longer process the request itself.
ALTER TABLE vaulty.jobs ADD COLUMN cancel_requested_at timestamptz;

-- Requests made before this column existed are in the audit log.
UPDATE vaulty.jobs j SET cancel_requested_at = a.occurred_at
  FROM (SELECT target, max(occurred_at) AS occurred_at FROM vaulty.audit_events WHERE action = 'job.cancel_requested' GROUP BY target) a
 WHERE a.target = 'job:' || j.id::text AND j.state IN ('queued', 'running');

-- Jobs that are still open, across organizations, for the reconciler that compares them with the workflow engine
-- (identifiers and timestamps only).
CREATE OR REPLACE FUNCTION vaulty.unfinished_jobs(p_started_before timestamptz)
    RETURNS TABLE (organization_id uuid, id uuid, kind text, tenant_id uuid, protected_object_id uuid, workflow_id text,
                   workflow_run_id text, started_at timestamptz, cancel_requested_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, vaulty
AS $$
    SELECT j.organization_id, j.id, j.kind, j.tenant_id, j.protected_object_id, j.workflow_id, j.workflow_run_id, j.started_at, j.cancel_requested_at
      FROM vaulty.jobs j
     WHERE j.state = 'running' AND j.workflow_id IS NOT NULL AND j.kind IN ('backup', 'discovery') AND j.started_at < p_started_before
     ORDER BY j.started_at
     LIMIT 500
$$;
REVOKE ALL ON FUNCTION vaulty.unfinished_jobs(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vaulty.unfinished_jobs(timestamptz) TO vaulty_worker;
