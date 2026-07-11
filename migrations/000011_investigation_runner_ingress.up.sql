BEGIN;

SET LOCAL lock_timeout = '5s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

LOCK TABLE runner_scope_bindings, runner_registrations, runner_certificates,
    tool_invocations, investigations, evidence, runner_evidence_receipts,
    investigation_idempotency_records, environments, workspaces IN ACCESS EXCLUSIVE MODE;

CREATE TABLE investigation_task_attempts (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    investigation_id uuid NOT NULL,
    task_id uuid NOT NULL,
    lease_epoch bigint NOT NULL,
    lease_token_sha256 text NOT NULL,
    runner_id text NOT NULL,
    scope_revision bigint NOT NULL,
    certificate_sha256 text NOT NULL,
    certificate_not_after timestamptz NOT NULL,
    heartbeat_seq bigint NOT NULL DEFAULT 0,
    lease_acquired_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    started_at timestamptz,
    terminal_at timestamptz,
    status text NOT NULL,
    request_hash text,
    receipt_hash text,
    updated_at timestamptz NOT NULL,

    PRIMARY KEY (tenant_id, workspace_id, investigation_id, task_id, lease_epoch),
    CONSTRAINT investigation_task_attempts_task_fk
        FOREIGN KEY (tenant_id, workspace_id, investigation_id, task_id)
        REFERENCES tool_invocations (tenant_id, workspace_id, investigation_id, id) ON DELETE RESTRICT,
    CONSTRAINT investigation_task_attempts_investigation_environment_fk
        FOREIGN KEY (tenant_id, workspace_id, investigation_id, environment_id)
        REFERENCES investigations (tenant_id, workspace_id, id, environment_id_snapshot) ON DELETE RESTRICT,
    CONSTRAINT investigation_task_attempts_registration_fk
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT,
    CONSTRAINT investigation_task_attempts_certificate_fk
        FOREIGN KEY (runner_id, certificate_sha256)
        REFERENCES runner_certificates (runner_id, certificate_sha256) ON DELETE RESTRICT,
    CONSTRAINT investigation_task_attempts_receipt_fence_uk UNIQUE (
        tenant_id, workspace_id, investigation_id, task_id, lease_epoch,
        runner_id, scope_revision, certificate_sha256, request_hash, receipt_hash
    ),
    CONSTRAINT investigation_task_attempts_identity_ck CHECK (
        lease_epoch > 0 AND scope_revision > 0 AND heartbeat_seq >= 0 AND
        octet_length(lease_token_sha256) = 64 AND
        lease_token_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(runner_id) BETWEEN 1 AND 256 AND
        left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        octet_length(certificate_sha256) = 64 AND
        certificate_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        (request_hash IS NULL OR (
            octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]'
        )) AND
        (receipt_hash IS NULL OR (
            octet_length(receipt_hash) = 64 AND receipt_hash COLLATE "C" !~ '[^a-f0-9]'
        ))
    ),
    CONSTRAINT investigation_task_attempts_time_ck CHECK (
        lease_acquired_at > '-infinity'::timestamptz AND lease_acquired_at < 'infinity'::timestamptz AND
        last_heartbeat_at > '-infinity'::timestamptz AND last_heartbeat_at < 'infinity'::timestamptz AND
        lease_expires_at > '-infinity'::timestamptz AND lease_expires_at < 'infinity'::timestamptz AND
        certificate_not_after > '-infinity'::timestamptz AND certificate_not_after < 'infinity'::timestamptz AND
        updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
        last_heartbeat_at >= lease_acquired_at AND lease_expires_at > last_heartbeat_at AND
        lease_expires_at <= certificate_not_after AND
        updated_at >= lease_acquired_at AND
        (started_at IS NULL OR (
            started_at >= lease_acquired_at AND started_at <= updated_at AND
            started_at > '-infinity'::timestamptz AND started_at < 'infinity'::timestamptz
        )) AND
        (terminal_at IS NULL OR (
            terminal_at >= lease_acquired_at AND terminal_at <= updated_at AND
            terminal_at > '-infinity'::timestamptz AND terminal_at < 'infinity'::timestamptz
        )) AND
        (started_at IS NULL OR terminal_at IS NULL OR terminal_at >= started_at)
    ),
    CONSTRAINT investigation_task_attempts_lifecycle_ck CHECK (
        status IN ('LEASED', 'RUNNING', 'COMPLETED', 'RELEASED', 'EXPIRED', 'CANCELLED') AND
        (
            (status = 'LEASED' AND started_at IS NULL AND terminal_at IS NULL) OR
            (status = 'RUNNING' AND started_at IS NOT NULL AND terminal_at IS NULL) OR
            (status = 'COMPLETED' AND started_at IS NOT NULL AND terminal_at IS NOT NULL) OR
            (status = 'RELEASED' AND started_at IS NULL AND terminal_at IS NOT NULL) OR
            (status IN ('EXPIRED', 'CANCELLED') AND terminal_at IS NOT NULL)
        ) AND
        (
            (status = 'COMPLETED' AND request_hash IS NOT NULL AND receipt_hash IS NOT NULL) OR
            (status <> 'COMPLETED' AND request_hash IS NULL AND receipt_hash IS NULL)
        )
    )
);

CREATE UNIQUE INDEX investigation_task_attempts_active_task_uk
    ON investigation_task_attempts (tenant_id, workspace_id, investigation_id, task_id)
    WHERE status IN ('LEASED', 'RUNNING');

CREATE UNIQUE INDEX investigation_task_attempts_token_hash_uk
    ON investigation_task_attempts (lease_token_sha256);

CREATE INDEX investigation_task_attempts_runner_active_idx
    ON investigation_task_attempts (tenant_id, runner_id, lease_acquired_at, task_id)
    WHERE status IN ('LEASED', 'RUNNING');

CREATE INDEX investigation_task_attempts_expiry_idx
    ON investigation_task_attempts (lease_expires_at, task_id, lease_epoch)
    WHERE status IN ('LEASED', 'RUNNING');

CREATE OR REPLACE FUNCTION validate_investigation_task_attempt_insert() RETURNS trigger AS $$
DECLARE
    transition_at timestamptz;
    task_status text;
    parent_status text;
    authenticated_certificate_status text;
    authenticated_certificate_not_before timestamptz;
    authenticated_certificate_not_after timestamptz;
BEGIN
    IF NEW.status <> 'LEASED' OR NEW.started_at IS NOT NULL OR NEW.terminal_at IS NOT NULL OR
       NEW.request_hash IS NOT NULL OR NEW.receipt_hash IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation task attempts must enter in LEASED state',
            CONSTRAINT = 'investigation_task_attempts_insert_guard';
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
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt requires its current exact scope binding',
            CONSTRAINT = 'investigation_task_attempts_scope_guard';
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
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt requires an enabled current READ registration',
            CONSTRAINT = 'investigation_task_attempts_registration_guard';
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
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt requires its registered certificate',
            CONSTRAINT = 'investigation_task_attempts_certificate_guard';
    END IF;

    SELECT task.status
    INTO task_status
    FROM tool_invocations AS task
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.runtime_schema_version = 'investigation-runtime.v1'
      AND task.status IN ('QUEUED', 'RUNNING')
    FOR SHARE OF task;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt requires an active runtime read task',
            CONSTRAINT = 'investigation_task_attempts_task_guard';
    END IF;

    PERFORM 1
    FROM investigation_task_attempts AS existing
    WHERE existing.tenant_id = NEW.tenant_id
      AND existing.workspace_id = NEW.workspace_id
      AND existing.investigation_id = NEW.investigation_id
      AND existing.task_id = NEW.task_id
      AND existing.lease_epoch >= NEW.lease_epoch
    FOR SHARE OF existing;
    IF FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt epoch must increase monotonically',
            CONSTRAINT = 'investigation_task_attempts_epoch_guard';
    END IF;

    SELECT parent.status
    INTO parent_status
    FROM investigations AS parent
    WHERE parent.tenant_id = NEW.tenant_id
      AND parent.workspace_id = NEW.workspace_id
      AND parent.id = NEW.investigation_id
      AND parent.environment_id_snapshot = NEW.environment_id
      AND parent.runtime_schema_version = 'investigation-runtime.v1'
      AND parent.status IN ('QUEUED', 'RUNNING')
    FOR SHARE OF parent;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt requires an active exact-environment investigation',
            CONSTRAINT = 'investigation_task_attempts_parent_guard';
    END IF;

    -- Take the security timestamp only after every identity, task, parent and
    -- prior-attempt lock above has been acquired. A lock wait must never make a
    -- stale certificate or lease appear current.
    transition_at := clock_timestamp();
    IF authenticated_certificate_status <> 'ACTIVE' OR
       authenticated_certificate_not_before > transition_at OR
       authenticated_certificate_not_after <= transition_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt requires its current ACTIVE certificate',
            CONSTRAINT = 'investigation_task_attempts_certificate_guard';
    END IF;
    NEW.certificate_not_after := authenticated_certificate_not_after;
    IF NEW.lease_expires_at <= transition_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation task attempt lease must be current',
            CONSTRAINT = 'investigation_task_attempts_lease_current_guard';
    END IF;
    IF NEW.lease_expires_at > authenticated_certificate_not_after THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'investigation task attempt lease cannot outlive its authenticated certificate',
            CONSTRAINT = 'investigation_task_attempts_certificate_guard';
    END IF;
    NEW.heartbeat_seq := 0;
    NEW.lease_acquired_at := transition_at;
    NEW.last_heartbeat_at := transition_at;
    NEW.updated_at := transition_at;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_task_attempts_insert_guard
    BEFORE INSERT ON investigation_task_attempts
    FOR EACH ROW EXECUTE FUNCTION validate_investigation_task_attempt_insert();

CREATE OR REPLACE FUNCTION enforce_investigation_task_attempt_lifecycle() RETURNS trigger AS $$
DECLARE
    transition_at timestamptz;
    heartbeat_changed boolean;
    authenticated_certificate_status text;
    authenticated_certificate_not_before timestamptz;
    authenticated_certificate_not_after timestamptz;
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.environment_id IS DISTINCT FROM NEW.environment_id OR
       OLD.investigation_id IS DISTINCT FROM NEW.investigation_id OR
       OLD.task_id IS DISTINCT FROM NEW.task_id OR
       OLD.lease_epoch IS DISTINCT FROM NEW.lease_epoch OR
       OLD.lease_token_sha256 IS DISTINCT FROM NEW.lease_token_sha256 OR
       OLD.runner_id IS DISTINCT FROM NEW.runner_id OR
       OLD.scope_revision IS DISTINCT FROM NEW.scope_revision OR
       OLD.certificate_sha256 IS DISTINCT FROM NEW.certificate_sha256 OR
       OLD.certificate_not_after IS DISTINCT FROM NEW.certificate_not_after OR
       OLD.lease_acquired_at IS DISTINCT FROM NEW.lease_acquired_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation task attempt identity and fence are immutable',
            CONSTRAINT = 'investigation_task_attempts_identity_guard';
    END IF;

    IF OLD.started_at IS DISTINCT FROM NEW.started_at OR
       OLD.terminal_at IS DISTINCT FROM NEW.terminal_at OR
       OLD.updated_at IS DISTINCT FROM NEW.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation task attempt audit timestamps are server-owned',
            CONSTRAINT = 'investigation_task_attempts_timestamp_guard';
    END IF;

    IF OLD.status IN ('COMPLETED', 'RELEASED', 'EXPIRED', 'CANCELLED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'terminal investigation task attempts are immutable',
            CONSTRAINT = 'investigation_task_attempts_terminal_guard';
    END IF;
    IF OLD IS NOT DISTINCT FROM NEW THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation task attempt no-op updates are forbidden',
            CONSTRAINT = 'investigation_task_attempts_state_guard';
    END IF;

    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'LEASED' AND NEW.status IN ('RUNNING', 'RELEASED', 'EXPIRED', 'CANCELLED')) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('COMPLETED', 'EXPIRED', 'CANCELLED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'invalid investigation task attempt transition',
            CONSTRAINT = 'investigation_task_attempts_state_guard';
    END IF;

    -- Recheck the same current, exact identity used by the Gateway whenever
    -- an update advances or extends trusted work. Fail-safe cancellation and
    -- expiry remain possible after scope or certificate revocation.
    IF NEW.status IN ('RUNNING', 'COMPLETED', 'RELEASED') THEN
        PERFORM 1
        FROM runner_scope_bindings AS binding
        WHERE binding.tenant_id = NEW.tenant_id
          AND binding.runner_id = NEW.runner_id
          AND binding.workspace_id = NEW.workspace_id
          AND binding.environment_id = NEW.environment_id
        FOR SHARE OF binding;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'active investigation task attempt update requires its current exact scope binding',
                CONSTRAINT = 'investigation_task_attempts_update_scope_guard';
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
                ERRCODE = '23514',
                MESSAGE = 'active investigation task attempt update requires an enabled current READ registration',
                CONSTRAINT = 'investigation_task_attempts_update_registration_guard';
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
                ERRCODE = '23514',
                MESSAGE = 'active investigation task attempt update requires its registered certificate',
                CONSTRAINT = 'investigation_task_attempts_update_certificate_guard';
        END IF;
        transition_at := clock_timestamp();
        IF authenticated_certificate_status <> 'ACTIVE' OR
           authenticated_certificate_not_before > transition_at OR
           authenticated_certificate_not_after <= transition_at OR
           authenticated_certificate_not_after <> NEW.certificate_not_after THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'active investigation task attempt update requires its current ACTIVE certificate',
                CONSTRAINT = 'investigation_task_attempts_update_certificate_guard';
        END IF;
    ELSE
        transition_at := clock_timestamp();
    END IF;

    heartbeat_changed := OLD.heartbeat_seq IS DISTINCT FROM NEW.heartbeat_seq OR
        OLD.last_heartbeat_at IS DISTINCT FROM NEW.last_heartbeat_at OR
        OLD.lease_expires_at IS DISTINCT FROM NEW.lease_expires_at;
    IF heartbeat_changed AND OLD.lease_expires_at <= transition_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'expired investigation task attempt cannot heartbeat',
            CONSTRAINT = 'investigation_task_attempts_lease_current_guard';
    END IF;
    IF heartbeat_changed AND NOT (
        OLD.status = 'RUNNING' AND NEW.status IN ('RUNNING', 'CANCELLED') AND
        NEW.heartbeat_seq = OLD.heartbeat_seq + 1 AND
        NEW.last_heartbeat_at > OLD.last_heartbeat_at AND
        NEW.lease_expires_at > NEW.last_heartbeat_at AND
        ((NEW.status = 'RUNNING' AND NEW.lease_expires_at >= OLD.lease_expires_at) OR
         (NEW.status = 'CANCELLED' AND NEW.lease_expires_at = OLD.lease_expires_at))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation task attempt heartbeat must be current and strictly sequenced',
            CONSTRAINT = 'investigation_task_attempts_heartbeat_guard';
    END IF;

    IF NEW.status = 'RUNNING' AND OLD.status = 'LEASED' THEN
        IF OLD.lease_expires_at <= transition_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'expired investigation task attempt cannot start',
                CONSTRAINT = 'investigation_task_attempts_lease_current_guard';
        END IF;
        NEW.started_at := transition_at;
    ELSIF NEW.status IN ('COMPLETED', 'RELEASED', 'EXPIRED', 'CANCELLED') AND
          NEW.status IS DISTINCT FROM OLD.status THEN
        IF NEW.status = 'COMPLETED' AND OLD.lease_expires_at <= transition_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'expired investigation task attempt cannot complete',
                CONSTRAINT = 'investigation_task_attempts_lease_current_guard';
        END IF;
        IF NEW.status = 'RELEASED' AND OLD.lease_expires_at <= transition_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'expired investigation task attempt cannot be released',
                CONSTRAINT = 'investigation_task_attempts_lease_current_guard';
        END IF;
        IF NEW.status = 'EXPIRED' AND OLD.lease_expires_at > transition_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'current investigation task attempt cannot be expired',
                CONSTRAINT = 'investigation_task_attempts_state_guard';
        END IF;
        NEW.terminal_at := transition_at;
    END IF;
    NEW.updated_at := transition_at;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_task_attempts_lifecycle_guard
    BEFORE UPDATE ON investigation_task_attempts
    FOR EACH ROW EXECUTE FUNCTION enforce_investigation_task_attempt_lifecycle();

CREATE OR REPLACE FUNCTION reject_investigation_task_attempt_removal() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'investigation task attempt history is append-only',
        CONSTRAINT = 'investigation_task_attempts_history_guard';
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_task_attempts_no_delete
    BEFORE DELETE ON investigation_task_attempts
    FOR EACH ROW EXECUTE FUNCTION reject_investigation_task_attempt_removal();

CREATE TRIGGER investigation_task_attempts_no_truncate
    BEFORE TRUNCATE ON investigation_task_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION reject_investigation_task_attempt_removal();

ALTER TABLE runner_evidence_receipts
    ADD COLUMN lease_epoch bigint,
    DROP CONSTRAINT runner_evidence_receipts_identity_ck,
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
    ),
    ADD CONSTRAINT runner_evidence_receipts_attempt_fence_fk
        FOREIGN KEY (
            tenant_id, workspace_id, investigation_id, task_id, lease_epoch,
            runner_id, scope_revision, certificate_sha256, request_hash, receipt_hash
        )
        REFERENCES investigation_task_attempts (
            tenant_id, workspace_id, investigation_id, task_id, lease_epoch,
            runner_id, scope_revision, certificate_sha256, request_hash, receipt_hash
        ) ON DELETE RESTRICT;

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

    -- Bind the receipt timestamp only after identity, task, attempt and parent locks.
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

CREATE CONSTRAINT TRIGGER investigation_task_attempts_completion_projection_guard
    AFTER INSERT OR UPDATE OF status, request_hash, receipt_hash ON investigation_task_attempts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_investigation_task_attempt_completion();

COMMIT;
