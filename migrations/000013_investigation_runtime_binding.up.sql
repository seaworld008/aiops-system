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

ALTER TABLE investigations
    ADD COLUMN plan_schema_version text,
    ADD COLUMN plan_manifest_digest text,
    ADD COLUMN plan_registry_digest text,
    ADD COLUMN plan_profile_digest text,
    ADD COLUMN plan_tasks_hash text;

DO $$
BEGIN
    IF EXISTS (SELECT 1
        FROM investigation_task_attempts
        WHERE status IN ('LEASED', 'RUNNING')
    ) OR EXISTS (SELECT 1
        FROM investigations
        WHERE runtime_schema_version = 'investigation-runtime.v1'
          AND status IN ('QUEUED', 'RUNNING')
          AND plan_schema_version IS NULL
          AND request_hash_version = 'investigation.create.v1'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe investigation runtime binding upgrade: active unbound investigation state remains';
    END IF;
END;
$$;

ALTER TABLE investigations DROP CONSTRAINT investigations_runtime_shape_ck;

ALTER TABLE investigations
    ADD CONSTRAINT investigations_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND model_status IS NULL AND idempotency_key IS NULL AND
            request_hash IS NULL AND request_hash_version IS NULL AND failure_code IS NULL AND
            model_failure_code IS NULL AND started_at IS NULL AND updated_at IS NULL AND
            service_id_snapshot IS NULL AND environment_id_snapshot IS NULL AND mapping_status_snapshot IS NULL
        ) OR (
            runtime_schema_version IS NOT NULL AND runtime_schema_version = 'investigation-runtime.v1' AND
            model_status IS NOT NULL AND idempotency_key IS NOT NULL AND
            request_hash IS NOT NULL AND request_hash_version IS NOT NULL AND
            updated_at IS NOT NULL AND mapping_status_snapshot IS NOT NULL AND
            model_status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED') AND
            octet_length(idempotency_key) BETWEEN 1 AND 128 AND
            left(idempotency_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            idempotency_key COLLATE "C" !~ '[^a-z0-9._:/-]' AND
            octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
            request_hash_version IN ('investigation.create.v1', 'investigation.create.v2') AND
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
    ),
    ADD CONSTRAINT investigations_plan_binding_ck CHECK (
        (
            runtime_schema_version IS NULL AND
            plan_schema_version IS NULL AND plan_manifest_digest IS NULL AND
            plan_registry_digest IS NULL AND plan_profile_digest IS NULL AND plan_tasks_hash IS NULL
        ) OR (
            runtime_schema_version IS NOT NULL AND runtime_schema_version = 'investigation-runtime.v1' AND
            (
                (
                    plan_schema_version IS NULL AND plan_manifest_digest IS NULL AND
                    plan_registry_digest IS NULL AND plan_profile_digest IS NULL AND plan_tasks_hash IS NULL AND
                    request_hash_version = 'investigation.create.v1'
                ) OR (
                    plan_schema_version IS NOT NULL AND plan_schema_version = 'investigation-plan-manifest.v1' AND
                    plan_manifest_digest IS NOT NULL AND plan_registry_digest IS NOT NULL AND
                    plan_profile_digest IS NOT NULL AND plan_tasks_hash IS NOT NULL AND
                    octet_length(plan_manifest_digest) = 64 AND plan_manifest_digest COLLATE "C" !~ '[^a-f0-9]' AND
                    octet_length(plan_registry_digest) = 64 AND plan_registry_digest COLLATE "C" !~ '[^a-f0-9]' AND
                    octet_length(plan_profile_digest) = 64 AND plan_profile_digest COLLATE "C" !~ '[^a-f0-9]' AND
                    octet_length(plan_tasks_hash) = 64 AND plan_tasks_hash COLLATE "C" !~ '[^a-f0-9]' AND
                    request_hash_version = 'investigation.create.v2'
                )
            )
        )
    ),
    ADD CONSTRAINT investigations_plan_binding_scope_uk UNIQUE (
        tenant_id, workspace_id, id, plan_schema_version, plan_manifest_digest,
        plan_registry_digest, plan_profile_digest, plan_tasks_hash
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
            (
                operation = 'create_investigation' AND
                request_hash_version IN ('investigation.create.v1', 'investigation.create.v2') AND
                resource_type = 'INVESTIGATION'
            ) OR
            (operation = 'complete_task' AND request_hash_version = 'investigation.complete-task.v1' AND resource_type = 'RUNNER_EVIDENCE_RECEIPT') OR
            (operation = 'start_model' AND request_hash_version = 'investigation.start-model.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'finalize_investigation' AND request_hash_version = 'investigation.finalize.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'fail_investigation' AND request_hash_version = 'investigation.fail.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'record_feedback' AND request_hash_version = 'investigation.feedback.v1' AND resource_type = 'FEEDBACK')
        ) AND
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz
    );

CREATE OR REPLACE FUNCTION require_new_investigation_create_ledger_v2() RETURNS trigger AS $$
BEGIN
    IF NEW.operation = 'create_investigation' THEN
        IF NEW.request_hash_version IS DISTINCT FROM 'investigation.create.v2' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'new investigation create ledgers require v2 semantics',
                CONSTRAINT = 'investigation_idempotency_create_v2_insert_guard';
        END IF;
        PERFORM 1
        FROM investigations AS investigation
        WHERE investigation.tenant_id = NEW.tenant_id
          AND investigation.workspace_id = NEW.workspace_id
          AND investigation.id = NEW.resource_id
          AND investigation.runtime_schema_version = 'investigation-runtime.v1'
          AND investigation.request_hash_version = 'investigation.create.v2'
          AND investigation.plan_schema_version = 'investigation-plan-manifest.v1'
        FOR SHARE OF investigation;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'new investigation create ledgers require their bound v2 investigation',
                CONSTRAINT = 'investigation_idempotency_create_v2_parent_guard';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_idempotency_create_v2_insert_guard
    BEFORE INSERT ON investigation_idempotency_records
    FOR EACH ROW EXECUTE FUNCTION require_new_investigation_create_ledger_v2();

CREATE OR REPLACE FUNCTION require_new_investigation_plan_binding() RETURNS trigger AS $$
BEGIN
    IF NEW.runtime_schema_version = 'investigation-runtime.v1' AND (
        NEW.request_hash_version IS DISTINCT FROM 'investigation.create.v2' OR
        NEW.plan_schema_version IS DISTINCT FROM 'investigation-plan-manifest.v1' OR
        NEW.plan_manifest_digest IS NULL OR NEW.plan_registry_digest IS NULL OR
        NEW.plan_profile_digest IS NULL OR NEW.plan_tasks_hash IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new runtime investigations require a complete v2 plan binding',
            CONSTRAINT = 'investigations_plan_binding_insert_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigations_plan_binding_insert_guard
    BEFORE INSERT ON investigations
    FOR EACH ROW EXECUTE FUNCTION require_new_investigation_plan_binding();

CREATE OR REPLACE FUNCTION reject_investigation_plan_binding_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.plan_schema_version IS DISTINCT FROM NEW.plan_schema_version OR
       OLD.plan_manifest_digest IS DISTINCT FROM NEW.plan_manifest_digest OR
       OLD.plan_registry_digest IS DISTINCT FROM NEW.plan_registry_digest OR
       OLD.plan_profile_digest IS DISTINCT FROM NEW.plan_profile_digest OR
       OLD.plan_tasks_hash IS DISTINCT FROM NEW.plan_tasks_hash THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation plan binding is immutable',
            CONSTRAINT = 'investigations_plan_binding_immutable_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigations_plan_binding_immutable
    BEFORE UPDATE ON investigations
    FOR EACH ROW EXECUTE FUNCTION reject_investigation_plan_binding_mutation();

ALTER TABLE tool_invocations
    ADD COLUMN read_runtime_schema_version text,
    ADD COLUMN connector_digest text,
    ADD COLUMN target_digest text,
    ADD COLUMN executor_digest text,
    ADD COLUMN runtime_digest text,
    ADD COLUMN runtime_bound_at timestamptz,
    ADD CONSTRAINT tool_invocations_read_runtime_binding_ck CHECK (
        (
            runtime_schema_version IS NULL AND
            read_runtime_schema_version IS NULL AND connector_digest IS NULL AND target_digest IS NULL AND
            executor_digest IS NULL AND runtime_digest IS NULL AND runtime_bound_at IS NULL
        ) OR (
            runtime_schema_version IS NOT NULL AND runtime_schema_version = 'investigation-runtime.v1' AND
            (
                (
                    read_runtime_schema_version IS NULL AND connector_digest IS NULL AND target_digest IS NULL AND
                    executor_digest IS NULL AND runtime_digest IS NULL AND runtime_bound_at IS NULL
                ) OR (
                    read_runtime_schema_version IS NOT NULL AND read_runtime_schema_version = 'read-task-runtime-binding.v1' AND
                    connector_digest IS NOT NULL AND target_digest IS NOT NULL AND
                    executor_digest IS NOT NULL AND runtime_digest IS NOT NULL AND runtime_bound_at IS NOT NULL AND
                    octet_length(connector_digest) = 64 AND connector_digest COLLATE "C" !~ '[^a-f0-9]' AND
                    octet_length(target_digest) = 64 AND target_digest COLLATE "C" !~ '[^a-f0-9]' AND
                    octet_length(executor_digest) = 64 AND executor_digest COLLATE "C" !~ '[^a-f0-9]' AND
                    octet_length(runtime_digest) = 64 AND runtime_digest COLLATE "C" !~ '[^a-f0-9]' AND
                    tool_name COLLATE "C" ~ '^[a-z0-9][a-z0-9_.-]{0,59}-v1-[a-f0-9]{64}$' AND
                    right(tool_name, 64) = connector_digest AND
                    runtime_bound_at > '-infinity'::timestamptz AND runtime_bound_at < 'infinity'::timestamptz AND
                    runtime_bound_at = created_at
                )
            )
        )
    ),
    ADD CONSTRAINT tool_invocations_runtime_binding_scope_uk UNIQUE (
        tenant_id, workspace_id, investigation_id, id, read_runtime_schema_version,
        connector_digest, target_digest, executor_digest, runtime_digest, runtime_bound_at
    );

CREATE OR REPLACE FUNCTION require_new_tool_invocation_runtime_binding() RETURNS trigger AS $$
BEGIN
    IF NEW.runtime_schema_version = 'investigation-runtime.v1' THEN
        IF NEW.read_runtime_schema_version IS DISTINCT FROM 'read-task-runtime-binding.v1' OR
           NEW.connector_digest IS NULL OR NEW.target_digest IS NULL OR NEW.executor_digest IS NULL OR
           NEW.runtime_digest IS NULL OR NEW.runtime_bound_at IS NULL OR
           NEW.runtime_bound_at IS DISTINCT FROM NEW.created_at OR
           right(NEW.tool_name, 64) IS DISTINCT FROM NEW.connector_digest THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'new runtime read tasks require a complete trusted runtime binding',
                CONSTRAINT = 'tool_invocations_runtime_binding_insert_guard';
        END IF;

        PERFORM 1
        FROM investigations AS parent
        WHERE parent.tenant_id = NEW.tenant_id
          AND parent.workspace_id = NEW.workspace_id
          AND parent.id = NEW.investigation_id
          AND parent.runtime_schema_version = 'investigation-runtime.v1'
          AND parent.request_hash_version = 'investigation.create.v2'
          AND parent.plan_schema_version = 'investigation-plan-manifest.v1'
        FOR SHARE OF parent;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'new runtime read tasks require their bound v2 investigation',
                CONSTRAINT = 'tool_invocations_runtime_binding_parent_guard';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER tool_invocations_runtime_binding_insert_guard
    BEFORE INSERT ON tool_invocations
    FOR EACH ROW EXECUTE FUNCTION require_new_tool_invocation_runtime_binding();

CREATE INDEX tool_invocations_claimable_binding_idx
    ON tool_invocations (workspace_id, investigation_id, position, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1'
      AND status = 'QUEUED'
      AND read_runtime_schema_version = 'read-task-runtime-binding.v1';

CREATE OR REPLACE FUNCTION reject_tool_invocation_runtime_binding_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.read_runtime_schema_version IS DISTINCT FROM NEW.read_runtime_schema_version OR
       OLD.connector_digest IS DISTINCT FROM NEW.connector_digest OR
       OLD.target_digest IS DISTINCT FROM NEW.target_digest OR
       OLD.executor_digest IS DISTINCT FROM NEW.executor_digest OR
       OLD.runtime_digest IS DISTINCT FROM NEW.runtime_digest OR
       OLD.runtime_bound_at IS DISTINCT FROM NEW.runtime_bound_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'read task runtime binding is immutable',
            CONSTRAINT = 'tool_invocations_runtime_binding_immutable_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER tool_invocations_runtime_binding_immutable
    BEFORE UPDATE ON tool_invocations
    FOR EACH ROW EXECUTE FUNCTION reject_tool_invocation_runtime_binding_mutation();

ALTER TABLE investigation_task_attempts
    ADD COLUMN request_hash_version text,
    ADD COLUMN receipt_hash_version text;

ALTER TABLE investigation_task_attempts
    ADD COLUMN plan_schema_version text,
    ADD COLUMN plan_manifest_digest text,
    ADD COLUMN plan_registry_digest text,
    ADD COLUMN plan_profile_digest text,
    ADD COLUMN plan_tasks_hash text,
    ADD COLUMN read_runtime_schema_version text,
    ADD COLUMN connector_digest text,
    ADD COLUMN target_digest text,
    ADD COLUMN executor_digest text,
    ADD COLUMN runtime_digest text,
    ADD COLUMN runtime_bound_at timestamptz,
    ADD CONSTRAINT investigation_task_attempts_runtime_binding_ck CHECK (
        (
            plan_schema_version IS NULL AND plan_manifest_digest IS NULL AND plan_registry_digest IS NULL AND
            plan_profile_digest IS NULL AND plan_tasks_hash IS NULL AND
            read_runtime_schema_version IS NULL AND connector_digest IS NULL AND target_digest IS NULL AND
            executor_digest IS NULL AND runtime_digest IS NULL AND runtime_bound_at IS NULL AND
            request_hash_version IS NULL AND receipt_hash_version IS NULL
        ) OR (
            plan_schema_version IS NOT NULL AND plan_schema_version = 'investigation-plan-manifest.v1' AND
            plan_manifest_digest IS NOT NULL AND plan_registry_digest IS NOT NULL AND
            plan_profile_digest IS NOT NULL AND plan_tasks_hash IS NOT NULL AND
            octet_length(plan_manifest_digest) = 64 AND plan_manifest_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(plan_registry_digest) = 64 AND plan_registry_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(plan_profile_digest) = 64 AND plan_profile_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(plan_tasks_hash) = 64 AND plan_tasks_hash COLLATE "C" !~ '[^a-f0-9]' AND
            read_runtime_schema_version IS NOT NULL AND read_runtime_schema_version = 'read-task-runtime-binding.v1' AND
            connector_digest IS NOT NULL AND target_digest IS NOT NULL AND
            executor_digest IS NOT NULL AND runtime_digest IS NOT NULL AND runtime_bound_at IS NOT NULL AND
            octet_length(connector_digest) = 64 AND connector_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(target_digest) = 64 AND target_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(executor_digest) = 64 AND executor_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(runtime_digest) = 64 AND runtime_digest COLLATE "C" !~ '[^a-f0-9]' AND
            runtime_bound_at > '-infinity'::timestamptz AND runtime_bound_at < 'infinity'::timestamptz AND
            (
                (
                    status = 'COMPLETED' AND
                    request_hash_version IS NOT NULL AND receipt_hash_version IS NOT NULL AND
                    request_hash_version = 'read-task-completion-request.v3' AND
                    receipt_hash_version = 'read-task-completion-receipt.v3'
                ) OR (
                    status <> 'COMPLETED' AND request_hash_version IS NULL AND receipt_hash_version IS NULL
                )
            )
        )
    ),
    ADD CONSTRAINT investigation_task_attempts_plan_binding_fk
        FOREIGN KEY (
            tenant_id, workspace_id, investigation_id, plan_schema_version,
            plan_manifest_digest, plan_registry_digest, plan_profile_digest, plan_tasks_hash
        ) REFERENCES investigations (
            tenant_id, workspace_id, id, plan_schema_version,
            plan_manifest_digest, plan_registry_digest, plan_profile_digest, plan_tasks_hash
        ) ON DELETE RESTRICT,
    ADD CONSTRAINT investigation_task_attempts_runtime_binding_fk
        FOREIGN KEY (
            tenant_id, workspace_id, investigation_id, task_id, read_runtime_schema_version,
            connector_digest, target_digest, executor_digest, runtime_digest, runtime_bound_at
        ) REFERENCES tool_invocations (
            tenant_id, workspace_id, investigation_id, id, read_runtime_schema_version,
            connector_digest, target_digest, executor_digest, runtime_digest, runtime_bound_at
        ) ON DELETE RESTRICT,
    ADD CONSTRAINT investigation_task_attempts_runtime_receipt_fence_uk UNIQUE (
        tenant_id, workspace_id, investigation_id, task_id, lease_epoch,
        runner_id, scope_revision, certificate_sha256,
        request_hash, request_hash_version, receipt_hash, receipt_hash_version,
        plan_schema_version, plan_manifest_digest, plan_registry_digest, plan_profile_digest, plan_tasks_hash,
        read_runtime_schema_version, connector_digest, target_digest, executor_digest, runtime_digest, runtime_bound_at
    );

CREATE OR REPLACE FUNCTION bind_investigation_task_attempt_runtime() RETURNS trigger AS $$
DECLARE
    trusted_plan_schema_version text;
    trusted_plan_manifest_digest text;
    trusted_plan_registry_digest text;
    trusted_plan_profile_digest text;
    trusted_plan_tasks_hash text;
    trusted_runtime_schema_version text;
    trusted_connector_digest text;
    trusted_target_digest text;
    trusted_executor_digest text;
    trusted_runtime_digest text;
    trusted_runtime_bound_at timestamptz;
BEGIN
    SELECT
        task.read_runtime_schema_version, task.connector_digest, task.target_digest,
        task.executor_digest, task.runtime_digest, task.runtime_bound_at
    INTO
        trusted_runtime_schema_version, trusted_connector_digest, trusted_target_digest,
        trusted_executor_digest, trusted_runtime_digest, trusted_runtime_bound_at
    FROM tool_invocations AS task
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.runtime_schema_version = 'investigation-runtime.v1'
      AND task.read_runtime_schema_version = 'read-task-runtime-binding.v1'
    FOR SHARE OF task;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new investigation task attempt requires a complete trusted runtime binding',
            CONSTRAINT = 'investigation_task_attempts_runtime_binding_guard';
    END IF;

    SELECT
        parent.plan_schema_version, parent.plan_manifest_digest, parent.plan_registry_digest,
        parent.plan_profile_digest, parent.plan_tasks_hash
    INTO
        trusted_plan_schema_version, trusted_plan_manifest_digest, trusted_plan_registry_digest,
        trusted_plan_profile_digest, trusted_plan_tasks_hash
    FROM investigations AS parent
    WHERE parent.tenant_id = NEW.tenant_id
      AND parent.workspace_id = NEW.workspace_id
      AND parent.id = NEW.investigation_id
      AND parent.runtime_schema_version = 'investigation-runtime.v1'
      AND parent.plan_schema_version = 'investigation-plan-manifest.v1'
    FOR SHARE OF parent;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new investigation task attempt requires a complete trusted plan binding',
            CONSTRAINT = 'investigation_task_attempts_runtime_binding_guard';
    END IF;

    NEW.plan_schema_version := trusted_plan_schema_version;
    NEW.plan_manifest_digest := trusted_plan_manifest_digest;
    NEW.plan_registry_digest := trusted_plan_registry_digest;
    NEW.plan_profile_digest := trusted_plan_profile_digest;
    NEW.plan_tasks_hash := trusted_plan_tasks_hash;
    NEW.read_runtime_schema_version := trusted_runtime_schema_version;
    NEW.connector_digest := trusted_connector_digest;
    NEW.target_digest := trusted_target_digest;
    NEW.executor_digest := trusted_executor_digest;
    NEW.runtime_digest := trusted_runtime_digest;
    NEW.runtime_bound_at := trusted_runtime_bound_at;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_task_attempts_runtime_binding_guard
    BEFORE INSERT ON investigation_task_attempts
    FOR EACH ROW EXECUTE FUNCTION bind_investigation_task_attempt_runtime();

CREATE OR REPLACE FUNCTION reject_investigation_task_attempt_runtime_binding_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.plan_schema_version IS DISTINCT FROM NEW.plan_schema_version OR
       OLD.plan_manifest_digest IS DISTINCT FROM NEW.plan_manifest_digest OR
       OLD.plan_registry_digest IS DISTINCT FROM NEW.plan_registry_digest OR
       OLD.plan_profile_digest IS DISTINCT FROM NEW.plan_profile_digest OR
       OLD.plan_tasks_hash IS DISTINCT FROM NEW.plan_tasks_hash OR
       OLD.read_runtime_schema_version IS DISTINCT FROM NEW.read_runtime_schema_version OR
       OLD.connector_digest IS DISTINCT FROM NEW.connector_digest OR
       OLD.target_digest IS DISTINCT FROM NEW.target_digest OR
       OLD.executor_digest IS DISTINCT FROM NEW.executor_digest OR
       OLD.runtime_digest IS DISTINCT FROM NEW.runtime_digest OR
       OLD.runtime_bound_at IS DISTINCT FROM NEW.runtime_bound_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation task attempt runtime binding is immutable',
            CONSTRAINT = 'investigation_task_attempts_runtime_binding_immutable_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_task_attempts_runtime_binding_immutable
    BEFORE UPDATE ON investigation_task_attempts
    FOR EACH ROW EXECUTE FUNCTION reject_investigation_task_attempt_runtime_binding_mutation();

ALTER TABLE runner_evidence_receipts
    ADD COLUMN request_hash_version text,
    ADD COLUMN receipt_hash_version text;

ALTER TABLE runner_evidence_receipts
    ADD COLUMN plan_schema_version text,
    ADD COLUMN plan_manifest_digest text,
    ADD COLUMN plan_registry_digest text,
    ADD COLUMN plan_profile_digest text,
    ADD COLUMN plan_tasks_hash text,
    ADD COLUMN read_runtime_schema_version text,
    ADD COLUMN connector_digest text,
    ADD COLUMN target_digest text,
    ADD COLUMN executor_digest text,
    ADD COLUMN runtime_digest text,
    ADD COLUMN runtime_bound_at timestamptz,
    DROP CONSTRAINT runner_evidence_receipts_identity_ck,
    DROP CONSTRAINT runner_evidence_receipts_schema_ck,
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
        schema_version IN ('runner-evidence.v1', 'runner-evidence.v2', 'runner-evidence.v3') AND
        received_at > '-infinity'::timestamptz AND received_at < 'infinity'::timestamptz
    ),
    ADD CONSTRAINT runner_evidence_receipts_schema_ck CHECK (
        (
            schema_version = 'runner-evidence.v1' AND lease_epoch IS NULL AND
            request_hash_version IS NULL AND receipt_hash_version IS NULL AND
            plan_schema_version IS NULL AND plan_manifest_digest IS NULL AND plan_registry_digest IS NULL AND
            plan_profile_digest IS NULL AND plan_tasks_hash IS NULL AND
            read_runtime_schema_version IS NULL AND connector_digest IS NULL AND target_digest IS NULL AND
            executor_digest IS NULL AND runtime_digest IS NULL AND runtime_bound_at IS NULL
        ) OR (
            schema_version = 'runner-evidence.v2' AND lease_epoch IS NOT NULL AND lease_epoch > 0 AND
            request_hash_version IS NULL AND receipt_hash_version IS NULL AND
            plan_schema_version IS NULL AND plan_manifest_digest IS NULL AND plan_registry_digest IS NULL AND
            plan_profile_digest IS NULL AND plan_tasks_hash IS NULL AND
            read_runtime_schema_version IS NULL AND connector_digest IS NULL AND target_digest IS NULL AND
            executor_digest IS NULL AND runtime_digest IS NULL AND runtime_bound_at IS NULL
        ) OR (
            schema_version = 'runner-evidence.v3' AND lease_epoch IS NOT NULL AND lease_epoch > 0 AND
            request_hash_version IS NOT NULL AND receipt_hash_version IS NOT NULL AND
            request_hash_version = 'read-task-completion-request.v3' AND
            receipt_hash_version = 'read-task-completion-receipt.v3' AND
            plan_schema_version IS NOT NULL AND plan_schema_version = 'investigation-plan-manifest.v1' AND
            plan_manifest_digest IS NOT NULL AND plan_registry_digest IS NOT NULL AND
            plan_profile_digest IS NOT NULL AND plan_tasks_hash IS NOT NULL AND
            octet_length(plan_manifest_digest) = 64 AND plan_manifest_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(plan_registry_digest) = 64 AND plan_registry_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(plan_profile_digest) = 64 AND plan_profile_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(plan_tasks_hash) = 64 AND plan_tasks_hash COLLATE "C" !~ '[^a-f0-9]' AND
            read_runtime_schema_version IS NOT NULL AND read_runtime_schema_version = 'read-task-runtime-binding.v1' AND
            connector_digest IS NOT NULL AND target_digest IS NOT NULL AND
            executor_digest IS NOT NULL AND runtime_digest IS NOT NULL AND runtime_bound_at IS NOT NULL AND
            octet_length(connector_digest) = 64 AND connector_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(target_digest) = 64 AND target_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(executor_digest) = 64 AND executor_digest COLLATE "C" !~ '[^a-f0-9]' AND
            octet_length(runtime_digest) = 64 AND runtime_digest COLLATE "C" !~ '[^a-f0-9]' AND
            runtime_bound_at > '-infinity'::timestamptz AND runtime_bound_at < 'infinity'::timestamptz
        )
    ),
    ADD CONSTRAINT runner_evidence_receipts_runtime_attempt_fence_fk
        FOREIGN KEY (
            tenant_id, workspace_id, investigation_id, task_id, lease_epoch,
            runner_id, scope_revision, certificate_sha256,
            request_hash, request_hash_version, receipt_hash, receipt_hash_version,
            plan_schema_version, plan_manifest_digest, plan_registry_digest, plan_profile_digest, plan_tasks_hash,
            read_runtime_schema_version, connector_digest, target_digest, executor_digest, runtime_digest, runtime_bound_at
        ) REFERENCES investigation_task_attempts (
            tenant_id, workspace_id, investigation_id, task_id, lease_epoch,
            runner_id, scope_revision, certificate_sha256,
            request_hash, request_hash_version, receipt_hash, receipt_hash_version,
            plan_schema_version, plan_manifest_digest, plan_registry_digest, plan_profile_digest, plan_tasks_hash,
            read_runtime_schema_version, connector_digest, target_digest, executor_digest, runtime_digest, runtime_bound_at
        ) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION validate_runner_evidence_receipt_insert() RETURNS trigger AS $$
DECLARE
    receipt_at timestamptz;
    authenticated_certificate_status text;
    authenticated_certificate_not_before timestamptz;
    authenticated_certificate_not_after timestamptz;
    trusted_plan_schema_version text;
    trusted_plan_manifest_digest text;
    trusted_plan_registry_digest text;
    trusted_plan_profile_digest text;
    trusted_plan_tasks_hash text;
    trusted_runtime_schema_version text;
    trusted_connector_digest text;
    trusted_target_digest text;
    trusted_executor_digest text;
    trusted_runtime_digest text;
    trusted_runtime_bound_at timestamptz;
    trusted_request_hash_version text;
    trusted_receipt_hash_version text;
BEGIN
    IF NEW.schema_version <> 'runner-evidence.v3' OR NEW.lease_epoch IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new runner evidence receipts require authenticated v3 runtime evidence',
            CONSTRAINT = 'runner_evidence_receipts_insert_guard';
    END IF;
    IF NEW.request_hash_version IS DISTINCT FROM 'read-task-completion-request.v3' OR
       NEW.receipt_hash_version IS DISTINCT FROM 'read-task-completion-receipt.v3' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new runner evidence receipt requires exact v3 completion hash versions',
            CONSTRAINT = 'runner_evidence_receipts_hash_version_guard';
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

    SELECT
        task.read_runtime_schema_version, task.connector_digest, task.target_digest,
        task.executor_digest, task.runtime_digest, task.runtime_bound_at
    INTO
        trusted_runtime_schema_version, trusted_connector_digest, trusted_target_digest,
        trusted_executor_digest, trusted_runtime_digest, trusted_runtime_bound_at
    FROM tool_invocations AS task
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.tool_name = NEW.connector_id
      AND task.runtime_schema_version = 'investigation-runtime.v1'
      AND task.read_runtime_schema_version = 'read-task-runtime-binding.v1'
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
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt does not match a bound terminal read task result',
            CONSTRAINT = 'runner_evidence_receipts_task_result_guard';
    END IF;

    SELECT
        attempt.plan_schema_version, attempt.plan_manifest_digest, attempt.plan_registry_digest,
        attempt.plan_profile_digest, attempt.plan_tasks_hash,
        attempt.request_hash_version, attempt.receipt_hash_version
    INTO
        trusted_plan_schema_version, trusted_plan_manifest_digest, trusted_plan_registry_digest,
        trusted_plan_profile_digest, trusted_plan_tasks_hash,
        trusted_request_hash_version, trusted_receipt_hash_version
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
      AND attempt.request_hash_version = 'read-task-completion-request.v3'
      AND attempt.receipt_hash = NEW.receipt_hash
      AND attempt.receipt_hash_version = 'read-task-completion-receipt.v3'
      AND attempt.read_runtime_schema_version = trusted_runtime_schema_version
      AND attempt.connector_digest = trusted_connector_digest
      AND attempt.target_digest = trusted_target_digest
      AND attempt.executor_digest = trusted_executor_digest
      AND attempt.runtime_digest = trusted_runtime_digest
      AND attempt.runtime_bound_at = trusted_runtime_bound_at
    FOR SHARE OF attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt does not match its completed runtime-bound attempt fence',
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
      AND investigation.plan_schema_version = trusted_plan_schema_version
      AND investigation.plan_manifest_digest = trusted_plan_manifest_digest
      AND investigation.plan_registry_digest = trusted_plan_registry_digest
      AND investigation.plan_profile_digest = trusted_plan_profile_digest
      AND investigation.plan_tasks_hash = trusted_plan_tasks_hash
    FOR SHARE OF investigation;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'runner evidence receipt requires its exact runtime-bound investigation',
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

    NEW.plan_schema_version := trusted_plan_schema_version;
    NEW.plan_manifest_digest := trusted_plan_manifest_digest;
    NEW.plan_registry_digest := trusted_plan_registry_digest;
    NEW.plan_profile_digest := trusted_plan_profile_digest;
    NEW.plan_tasks_hash := trusted_plan_tasks_hash;
    NEW.read_runtime_schema_version := trusted_runtime_schema_version;
    NEW.connector_digest := trusted_connector_digest;
    NEW.target_digest := trusted_target_digest;
    NEW.executor_digest := trusted_executor_digest;
    NEW.runtime_digest := trusted_runtime_digest;
    NEW.runtime_bound_at := trusted_runtime_bound_at;
    NEW.request_hash_version := trusted_request_hash_version;
    NEW.receipt_hash_version := trusted_receipt_hash_version;
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
      AND receipt.schema_version = 'runner-evidence.v3'
      AND receipt.lease_epoch = NEW.lease_epoch
      AND receipt.request_hash = NEW.request_hash
      AND receipt.request_hash_version = NEW.request_hash_version
      AND receipt.receipt_hash = NEW.receipt_hash
      AND receipt.receipt_hash_version = NEW.receipt_hash_version
      AND receipt.plan_schema_version = NEW.plan_schema_version
      AND receipt.plan_manifest_digest = NEW.plan_manifest_digest
      AND receipt.plan_registry_digest = NEW.plan_registry_digest
      AND receipt.plan_profile_digest = NEW.plan_profile_digest
      AND receipt.plan_tasks_hash = NEW.plan_tasks_hash
      AND receipt.read_runtime_schema_version = NEW.read_runtime_schema_version
      AND receipt.connector_digest = NEW.connector_digest
      AND receipt.target_digest = NEW.target_digest
      AND receipt.executor_digest = NEW.executor_digest
      AND receipt.runtime_digest = NEW.runtime_digest
      AND receipt.runtime_bound_at = NEW.runtime_bound_at
    FOR SHARE OF receipt;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'completed investigation task attempt requires its immutable v3 runtime receipt',
            CONSTRAINT = 'investigation_task_attempts_completion_projection_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

COMMIT;
