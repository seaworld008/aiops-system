BEGIN;

SET LOCAL lock_timeout = '5s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

LOCK TABLE investigations, tool_invocations, investigation_task_attempts,
    runner_evidence_receipts, investigation_idempotency_records
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1
        FROM investigation_task_attempts
        WHERE status IN ('LEASED', 'RUNNING')
    ) OR EXISTS (SELECT 1
        FROM investigations
        WHERE plan_schema_version IS NOT NULL
           OR plan_manifest_digest IS NOT NULL OR plan_registry_digest IS NOT NULL
           OR plan_profile_digest IS NOT NULL OR plan_tasks_hash IS NOT NULL
    ) OR EXISTS (SELECT 1
        FROM tool_invocations
        WHERE read_runtime_schema_version IS NOT NULL
           OR connector_digest IS NOT NULL OR target_digest IS NOT NULL
           OR executor_digest IS NOT NULL OR runtime_digest IS NOT NULL OR runtime_bound_at IS NOT NULL
    ) OR EXISTS (SELECT 1
        FROM investigation_task_attempts
        WHERE request_hash_version IS NOT NULL OR receipt_hash_version IS NOT NULL
           OR plan_schema_version IS NOT NULL OR read_runtime_schema_version IS NOT NULL
           OR plan_manifest_digest IS NOT NULL OR plan_registry_digest IS NOT NULL
           OR plan_profile_digest IS NOT NULL OR plan_tasks_hash IS NOT NULL
           OR connector_digest IS NOT NULL OR target_digest IS NOT NULL
           OR executor_digest IS NOT NULL OR runtime_digest IS NOT NULL OR runtime_bound_at IS NOT NULL
    ) OR EXISTS (SELECT 1
        FROM runner_evidence_receipts
        WHERE schema_version = 'runner-evidence.v3'
           OR request_hash_version IS NOT NULL OR receipt_hash_version IS NOT NULL
           OR plan_schema_version IS NOT NULL OR read_runtime_schema_version IS NOT NULL
           OR plan_manifest_digest IS NOT NULL OR plan_registry_digest IS NOT NULL
           OR plan_profile_digest IS NOT NULL OR plan_tasks_hash IS NOT NULL
           OR connector_digest IS NOT NULL OR target_digest IS NOT NULL
           OR executor_digest IS NOT NULL OR runtime_digest IS NOT NULL OR runtime_bound_at IS NOT NULL
    ) OR EXISTS (SELECT 1
        FROM investigation_idempotency_records
        WHERE operation = 'create_investigation'
          AND request_hash_version = 'investigation.create.v2'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe investigation runtime binding rollback: durable binding state remains';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_runner_evidence_receipt_insert() RETURNS trigger AS $$
DECLARE
    receipt_at timestamptz;
    authenticated_certificate_status text;
    authenticated_certificate_not_before timestamptz;
    authenticated_certificate_not_after timestamptz;
BEGIN
    IF NEW.schema_version <> 'runner-evidence.v2' OR NEW.lease_epoch IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new runner evidence receipts require authenticated v2 attempt evidence',
            CONSTRAINT = 'runner_evidence_receipts_insert_guard';
    END IF;

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

    SELECT certificate.status, certificate.not_before, certificate.not_after
    INTO authenticated_certificate_status, authenticated_certificate_not_before, authenticated_certificate_not_after
    FROM runner_certificates AS certificate
    WHERE certificate.tenant_id = NEW.tenant_id
      AND certificate.runner_id = NEW.runner_id
      AND certificate.certificate_sha256 = NEW.certificate_sha256
    FOR SHARE OF certificate;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt requires its registered certificate',
            CONSTRAINT = 'runner_evidence_receipts_certificate_guard';
    END IF;

    PERFORM 1
    FROM tool_invocations AS task
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.tool_name = NEW.connector_id
      AND task.runtime_schema_version = 'investigation-runtime.v1'
      AND task.completed_at IS NOT NULL
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

    PERFORM 1
    FROM investigation_task_attempts AS attempt
    WHERE attempt.tenant_id = NEW.tenant_id
      AND attempt.workspace_id = NEW.workspace_id
      AND attempt.environment_id = NEW.environment_id
      AND attempt.investigation_id = NEW.investigation_id
      AND attempt.task_id = NEW.task_id
      AND attempt.lease_epoch = NEW.lease_epoch
      AND attempt.runner_id = NEW.runner_id
      AND attempt.scope_revision = NEW.scope_revision
      AND attempt.certificate_sha256 = NEW.certificate_sha256
      AND attempt.status = 'COMPLETED'
      AND attempt.request_hash = NEW.request_hash
      AND attempt.receipt_hash = NEW.receipt_hash
    FOR SHARE OF attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt does not match its completed read attempt fence',
            CONSTRAINT = 'runner_evidence_receipts_attempt_guard';
    END IF;

    PERFORM 1
    FROM investigations AS investigation
    WHERE investigation.tenant_id = NEW.tenant_id
      AND investigation.workspace_id = NEW.workspace_id
      AND investigation.id = NEW.investigation_id
      AND investigation.environment_id_snapshot = NEW.environment_id
      AND investigation.runtime_schema_version = 'investigation-runtime.v1'
      AND investigation.status IN ('RUNNING', 'PARTIAL', 'COMPLETED')
    FOR SHARE OF investigation;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt requires its committed exact-environment investigation',
            CONSTRAINT = 'runner_evidence_receipts_parent_guard';
    END IF;

    receipt_at := clock_timestamp();
    IF authenticated_certificate_status <> 'ACTIVE' OR
       authenticated_certificate_not_before > receipt_at OR
       authenticated_certificate_not_after <= receipt_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt requires its current ACTIVE certificate',
            CONSTRAINT = 'runner_evidence_receipts_certificate_guard';
    END IF;
    NEW.received_at := receipt_at;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE FUNCTION validate_investigation_task_attempt_completion() RETURNS trigger AS $$
BEGIN
    IF NEW.status <> 'COMPLETED' THEN
        RETURN NULL;
    END IF;
    PERFORM 1
    FROM runner_evidence_receipts AS receipt
    WHERE receipt.tenant_id = NEW.tenant_id
      AND receipt.workspace_id = NEW.workspace_id
      AND receipt.environment_id = NEW.environment_id
      AND receipt.investigation_id = NEW.investigation_id
      AND receipt.task_id = NEW.task_id
      AND receipt.runner_id = NEW.runner_id
      AND receipt.scope_revision = NEW.scope_revision
      AND receipt.certificate_sha256 = NEW.certificate_sha256
      AND receipt.schema_version = 'runner-evidence.v2'
      AND receipt.lease_epoch = NEW.lease_epoch
      AND receipt.request_hash = NEW.request_hash
      AND receipt.receipt_hash = NEW.receipt_hash
    FOR SHARE OF receipt;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'completed investigation task attempt requires its immutable v2 receipt',
            CONSTRAINT = 'investigation_task_attempts_completion_projection_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

ALTER TABLE runner_evidence_receipts
    DROP CONSTRAINT runner_evidence_receipts_runtime_attempt_fence_fk,
    DROP CONSTRAINT runner_evidence_receipts_schema_ck,
    DROP CONSTRAINT runner_evidence_receipts_identity_ck;

ALTER TABLE runner_evidence_receipts
    DROP COLUMN request_hash_version,
    DROP COLUMN receipt_hash_version,
    DROP COLUMN plan_schema_version,
    DROP COLUMN plan_manifest_digest,
    DROP COLUMN plan_registry_digest,
    DROP COLUMN plan_profile_digest,
    DROP COLUMN plan_tasks_hash,
    DROP COLUMN read_runtime_schema_version,
    DROP COLUMN connector_digest,
    DROP COLUMN target_digest,
    DROP COLUMN executor_digest,
    DROP COLUMN runtime_digest,
    DROP COLUMN runtime_bound_at;

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
        schema_version IN ('runner-evidence.v1', 'runner-evidence.v2') AND
        received_at > '-infinity'::timestamptz AND received_at < 'infinity'::timestamptz
    ),
    ADD CONSTRAINT runner_evidence_receipts_schema_ck CHECK (
        (schema_version = 'runner-evidence.v1' AND lease_epoch IS NULL) OR
        (schema_version = 'runner-evidence.v2' AND lease_epoch IS NOT NULL AND lease_epoch > 0)
    );

DROP TRIGGER investigation_task_attempts_runtime_binding_immutable ON investigation_task_attempts;
DROP FUNCTION reject_investigation_task_attempt_runtime_binding_mutation();
DROP TRIGGER investigation_task_attempts_runtime_binding_guard ON investigation_task_attempts;
DROP FUNCTION bind_investigation_task_attempt_runtime();

ALTER TABLE investigation_task_attempts
    DROP CONSTRAINT investigation_task_attempts_runtime_receipt_fence_uk,
    DROP CONSTRAINT investigation_task_attempts_runtime_binding_fk,
    DROP CONSTRAINT investigation_task_attempts_plan_binding_fk,
    DROP CONSTRAINT investigation_task_attempts_runtime_binding_ck;

ALTER TABLE investigation_task_attempts
    DROP COLUMN request_hash_version,
    DROP COLUMN receipt_hash_version,
    DROP COLUMN plan_schema_version,
    DROP COLUMN plan_manifest_digest,
    DROP COLUMN plan_registry_digest,
    DROP COLUMN plan_profile_digest,
    DROP COLUMN plan_tasks_hash,
    DROP COLUMN read_runtime_schema_version,
    DROP COLUMN connector_digest,
    DROP COLUMN target_digest,
    DROP COLUMN executor_digest,
    DROP COLUMN runtime_digest,
    DROP COLUMN runtime_bound_at;

DROP TRIGGER tool_invocations_runtime_binding_immutable ON tool_invocations;
DROP FUNCTION reject_tool_invocation_runtime_binding_mutation();
DROP TRIGGER tool_invocations_runtime_binding_insert_guard ON tool_invocations;
DROP FUNCTION require_new_tool_invocation_runtime_binding();
DROP INDEX tool_invocations_claimable_binding_idx;

ALTER TABLE tool_invocations
    DROP CONSTRAINT tool_invocations_runtime_binding_scope_uk,
    DROP CONSTRAINT tool_invocations_read_runtime_binding_ck,
    DROP COLUMN read_runtime_schema_version,
    DROP COLUMN connector_digest,
    DROP COLUMN target_digest,
    DROP COLUMN executor_digest,
    DROP COLUMN runtime_digest,
    DROP COLUMN runtime_bound_at;

DROP TRIGGER investigation_idempotency_create_v2_insert_guard ON investigation_idempotency_records;
DROP FUNCTION require_new_investigation_create_ledger_v2();

DROP TRIGGER investigations_plan_binding_immutable ON investigations;
DROP FUNCTION reject_investigation_plan_binding_mutation();
DROP TRIGGER investigations_plan_binding_insert_guard ON investigations;
DROP FUNCTION require_new_investigation_plan_binding();

ALTER TABLE investigations
    DROP CONSTRAINT investigations_plan_binding_scope_uk,
    DROP CONSTRAINT investigations_plan_binding_ck,
    DROP CONSTRAINT investigations_runtime_shape_ck,
    DROP COLUMN plan_schema_version,
    DROP COLUMN plan_manifest_digest,
    DROP COLUMN plan_registry_digest,
    DROP COLUMN plan_profile_digest,
    DROP COLUMN plan_tasks_hash;

ALTER TABLE investigations
    ADD CONSTRAINT investigations_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND model_status IS NULL AND idempotency_key IS NULL AND
            request_hash IS NULL AND request_hash_version IS NULL AND failure_code IS NULL AND
            model_failure_code IS NULL AND started_at IS NULL AND updated_at IS NULL AND
            service_id_snapshot IS NULL AND environment_id_snapshot IS NULL AND mapping_status_snapshot IS NULL
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            model_status IS NOT NULL AND idempotency_key IS NOT NULL AND
            request_hash IS NOT NULL AND request_hash_version IS NOT NULL AND
            updated_at IS NOT NULL AND mapping_status_snapshot IS NOT NULL AND
            model_status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED') AND
            octet_length(idempotency_key) BETWEEN 1 AND 128 AND
            left(idempotency_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            idempotency_key COLLATE "C" !~ '[^a-z0-9._:/-]' AND
            octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
            request_hash_version = 'investigation.create.v1' AND
            mapping_status_snapshot IN ('EXACT', 'AMBIGUOUS', 'UNRESOLVED') AND
            (
                (mapping_status_snapshot = 'EXACT' AND service_id_snapshot IS NOT NULL AND environment_id_snapshot IS NOT NULL) OR
                mapping_status_snapshot IN ('AMBIGUOUS', 'UNRESOLVED')
            ) AND
            window_start > '-infinity'::timestamptz AND window_start < 'infinity'::timestamptz AND
            window_end > '-infinity'::timestamptz AND window_end < 'infinity'::timestamptz AND
            window_start <= window_end AND
            created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
            updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
            updated_at >= created_at AND
            (started_at IS NULL OR (started_at >= created_at AND started_at <= updated_at)) AND
            (completed_at IS NULL OR (completed_at >= created_at AND completed_at <= updated_at)) AND
            (completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at) AND
            (
                (status NOT IN ('FAILED', 'CANCELLED') AND failure_code IS NULL) OR
                (
                    status IN ('FAILED', 'CANCELLED') AND failure_code IS NOT NULL AND
                    octet_length(failure_code) BETWEEN 1 AND 128 AND
                    left(failure_code, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
                    failure_code COLLATE "C" !~ '[^a-z0-9_.-]'
                )
            ) AND
            (
                (model_status <> 'FAILED' AND model_failure_code IS NULL) OR
                (
                    model_status = 'FAILED' AND model_failure_code IS NOT NULL AND
                    octet_length(model_failure_code) BETWEEN 1 AND 128 AND
                    left(model_failure_code, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
                    model_failure_code COLLATE "C" !~ '[^a-z0-9_.-]'
                )
            )
        )
    );

ALTER TABLE investigation_idempotency_records
    DROP CONSTRAINT investigation_idempotency_records_identity_ck,
    ADD CONSTRAINT investigation_idempotency_records_identity_ck CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        left(idempotency_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
        idempotency_key COLLATE "C" !~ '[^a-z0-9._:/-]' AND
        operation IN (
            'create_investigation', 'complete_task', 'start_model',
            'finalize_investigation', 'fail_investigation', 'record_feedback'
        ) AND
        octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
        (
            (operation = 'create_investigation' AND request_hash_version = 'investigation.create.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'complete_task' AND request_hash_version = 'investigation.complete-task.v1' AND resource_type = 'RUNNER_EVIDENCE_RECEIPT') OR
            (operation = 'start_model' AND request_hash_version = 'investigation.start-model.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'finalize_investigation' AND request_hash_version = 'investigation.finalize.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'fail_investigation' AND request_hash_version = 'investigation.fail.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'record_feedback' AND request_hash_version = 'investigation.feedback.v1' AND resource_type = 'FEEDBACK')
        ) AND
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz
    );

COMMIT;
