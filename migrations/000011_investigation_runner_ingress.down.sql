BEGIN;

SET LOCAL lock_timeout = '5s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

LOCK TABLE runner_scope_bindings, runner_registrations, runner_certificates,
    tool_invocations, investigation_task_attempts, investigations, evidence,
    runner_evidence_receipts, investigation_idempotency_records, environments,
    workspaces IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM investigation_task_attempts)
       OR EXISTS (SELECT 1 FROM runner_evidence_receipts WHERE schema_version = 'runner-evidence.v2') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe investigation runner ingress rollback: durable attempt or v2 receipt history remains';
    END IF;
END;
$$;

DROP TRIGGER investigation_task_attempts_completion_projection_guard ON investigation_task_attempts;
DROP FUNCTION validate_investigation_task_attempt_completion();

DROP TRIGGER runner_evidence_receipts_insert_guard ON runner_evidence_receipts;
DROP FUNCTION validate_runner_evidence_receipt_insert();

ALTER TABLE runner_evidence_receipts
    DROP CONSTRAINT runner_evidence_receipts_attempt_fence_fk,
    DROP CONSTRAINT runner_evidence_receipts_schema_ck,
    DROP CONSTRAINT runner_evidence_receipts_identity_ck;

ALTER TABLE runner_evidence_receipts DROP COLUMN lease_epoch;

ALTER TABLE runner_evidence_receipts
    ADD CONSTRAINT runner_evidence_receipts_identity_ck CHECK (
        octet_length(runner_id) BETWEEN 1 AND 256 AND
        left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        scope_revision > 0 AND
        octet_length(certificate_sha256) = 64 AND certificate_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(connector_id) BETWEEN 1 AND 128 AND
        left(connector_id, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
        connector_id COLLATE "C" !~ '[^a-z0-9_.-]' AND
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        left(idempotency_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
        idempotency_key COLLATE "C" !~ '[^a-z0-9._:/-]' AND
        octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(receipt_hash) = 64 AND receipt_hash COLLATE "C" !~ '[^a-f0-9]' AND
        schema_version = 'runner-evidence.v1' AND
        received_at > '-infinity'::timestamptz AND received_at < 'infinity'::timestamptz
    );

CREATE OR REPLACE FUNCTION validate_runner_evidence_receipt_insert() RETURNS trigger AS $$
BEGIN
    NEW.received_at := clock_timestamp();

    PERFORM 1
    FROM runner_scope_bindings AS binding
    WHERE binding.tenant_id = NEW.tenant_id
      AND binding.runner_id = NEW.runner_id
      AND binding.workspace_id = NEW.workspace_id
      AND binding.environment_id = NEW.environment_id
    FOR SHARE OF binding;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt requires its current exact scope binding',
            CONSTRAINT = 'runner_evidence_receipts_scope_guard';
    END IF;

    PERFORM 1
    FROM runner_registrations AS registration
    WHERE registration.tenant_id = NEW.tenant_id
      AND registration.runner_id = NEW.runner_id
      AND registration.enabled = true
      AND registration.runner_pool = 'READ'
      AND registration.scope_revision = NEW.scope_revision
    FOR SHARE OF registration;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt requires an enabled current READ registration',
            CONSTRAINT = 'runner_evidence_receipts_registration_guard';
    END IF;

    PERFORM 1
    FROM runner_certificates AS certificate
    WHERE certificate.tenant_id = NEW.tenant_id
      AND certificate.runner_id = NEW.runner_id
      AND certificate.certificate_sha256 = NEW.certificate_sha256
      AND certificate.status = 'ACTIVE'
      AND certificate.not_before <= NEW.received_at
      AND certificate.not_after > NEW.received_at
    FOR SHARE OF certificate;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt requires its current ACTIVE certificate',
            CONSTRAINT = 'runner_evidence_receipts_certificate_guard';
    END IF;

    PERFORM 1
    FROM tool_invocations AS task
    JOIN investigations AS investigation
      ON investigation.tenant_id = task.tenant_id
     AND investigation.workspace_id = task.workspace_id
     AND investigation.id = task.investigation_id
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.tool_name = NEW.connector_id
      AND task.runtime_schema_version = 'investigation-runtime.v1'
      AND task.completed_at IS NOT NULL
      AND investigation.runtime_schema_version = 'investigation-runtime.v1'
      AND investigation.status IN ('RUNNING', 'PARTIAL', 'COMPLETED')
      AND (
        (NEW.evidence_id IS NOT NULL AND NEW.content_hash IS NOT NULL AND NEW.failure_code IS NULL AND
         task.status = 'EVIDENCE' AND task.evidence_id = NEW.evidence_id AND
         task.output_hash = NEW.content_hash AND task.failure_code IS NULL) OR
        (NEW.evidence_id IS NULL AND NEW.content_hash IS NULL AND NEW.failure_code IS NOT NULL AND
         task.status IN ('FAILED', 'CANCELLED') AND task.evidence_id IS NULL AND
         task.output_hash IS NULL AND task.failure_code = NEW.failure_code)
      )
    FOR SHARE OF task;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt does not match the committed terminal task result',
            CONSTRAINT = 'runner_evidence_receipts_task_result_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER runner_evidence_receipts_insert_guard
    BEFORE INSERT ON runner_evidence_receipts
    FOR EACH ROW EXECUTE FUNCTION validate_runner_evidence_receipt_insert();

DROP TRIGGER investigation_task_attempts_no_truncate ON investigation_task_attempts;
DROP TRIGGER investigation_task_attempts_no_delete ON investigation_task_attempts;
DROP TRIGGER investigation_task_attempts_lifecycle_guard ON investigation_task_attempts;
DROP TRIGGER investigation_task_attempts_insert_guard ON investigation_task_attempts;
DROP FUNCTION reject_investigation_task_attempt_removal();
DROP FUNCTION enforce_investigation_task_attempt_lifecycle();
DROP FUNCTION validate_investigation_task_attempt_insert();
DROP TABLE investigation_task_attempts;

COMMIT;
