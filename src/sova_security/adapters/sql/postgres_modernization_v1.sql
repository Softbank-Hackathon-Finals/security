-- Security-owned artifacts and revocations. Execution/approval remain host-owned.
CREATE TABLE IF NOT EXISTS sova_control.security_artifacts_v1 (
    tenant_id text NOT NULL,
    application_id text NOT NULL,
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
    artifact_kind text NOT NULL,
    environment_id text NOT NULL,
    resource_id text NOT NULL,
    envelope jsonb NOT NULL,
    registered_by text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,application_id,artifact_digest)
);
CREATE TABLE IF NOT EXISTS sova_control.security_artifact_events_v1 (
    tenant_id text NOT NULL,
    application_id text NOT NULL,
    artifact_digest text NOT NULL,
    revision bigint NOT NULL CHECK (revision IN (1,2)),
    event_kind text NOT NULL CHECK (event_kind IN ('registered','revoked')),
    actor_id text NOT NULL,
    reason text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,application_id,artifact_digest,revision),
    FOREIGN KEY (tenant_id,application_id,artifact_digest)
      REFERENCES sova_control.security_artifacts_v1,
    CHECK ((revision=1 AND event_kind='registered') OR (revision=2 AND event_kind='revoked'))
);
CREATE UNIQUE INDEX IF NOT EXISTS security_rehearsal_request_id_v1
 ON sova_control.security_artifacts_v1
 (tenant_id,application_id,(envelope #>> '{value,request_id}'))
 WHERE artifact_kind='rehearsal-request.v1';
ALTER TABLE sova_control.security_artifacts_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.security_artifacts_v1 FORCE ROW LEVEL SECURITY;
ALTER TABLE sova_control.security_artifact_events_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.security_artifact_events_v1 FORCE ROW LEVEL SECURITY;
DO $migration$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control'
    AND tablename='security_artifacts_v1' AND policyname='tenant_scope') THEN
  CREATE POLICY tenant_scope ON sova_control.security_artifacts_v1
   USING (tenant_id=current_setting('sova.tenant_id',true))
   WITH CHECK (tenant_id=current_setting('sova.tenant_id',true));
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control'
    AND tablename='security_artifact_events_v1' AND policyname='tenant_scope') THEN
  CREATE POLICY tenant_scope ON sova_control.security_artifact_events_v1
   USING (tenant_id=current_setting('sova.tenant_id',true))
   WITH CHECK (tenant_id=current_setting('sova.tenant_id',true));
 END IF;
END
$migration$;
REVOKE ALL ON sova_control.security_artifacts_v1 FROM PUBLIC;
REVOKE ALL ON sova_control.security_artifact_events_v1 FROM PUBLIC;
