-- A job mirrors one workflow run. The workflow id of a backup is the same for every run of a protected object (so two
-- runs never overlap), so it cannot be unique across jobs: every run after the first failed to record its start and
-- never began. The run id is what identifies a job's workflow run.
DROP INDEX vaulty.ux_jobs_workflow;
CREATE INDEX ix_jobs_workflow ON vaulty.jobs (workflow_id) WHERE workflow_id IS NOT NULL;
CREATE UNIQUE INDEX ux_jobs_workflow_run ON vaulty.jobs (workflow_run_id) WHERE workflow_run_id IS NOT NULL;
