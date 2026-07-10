BEGIN;

-- Freeze every table inspected by the downgrade guard before checking state.
-- This closes the check/contract race with concurrent Claim, Submit, registry
-- mutation, certificate rotation, receipt insertion, and domain transitions.
LOCK TABLE action_queue, execution_leases, executions, runner_result_receipts,
    runner_certificates, runner_scope_bindings, runner_registrations
    IN ACCESS EXCLUSIVE MODE;

-- SHA-256 completion fences and result receipts cannot be reconstructed as
-- legacy bearer tokens. Refuse a downgrade instead of silently weakening the
-- fence or releasing an unresolved target lock.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM action_queue
        WHERE status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    ) OR EXISTS (
        SELECT 1 FROM execution_leases
        WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN')
    ) OR EXISTS (
        SELECT 1 FROM executions
        WHERE status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe runner hardening rollback: active, finalizing, or uncertain execution exists';
    END IF;
    IF EXISTS (
        SELECT 1 FROM action_queue
        WHERE status = 'QUEUED'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe runner hardening rollback: queued actions would lose exact-scope authorization';
    END IF;
    IF EXISTS (SELECT 1 FROM runner_result_receipts) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe runner hardening rollback: durable result receipts exist';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execution_leases
        WHERE lease_token_sha256 IS NOT NULL OR completed_lease_token_sha256 IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe runner hardening rollback: irreversible lease token hashes exist';
    END IF;
    IF EXISTS (SELECT 1 FROM runner_certificates) OR
       EXISTS (SELECT 1 FROM runner_scope_bindings) OR
       EXISTS (SELECT 1 FROM runner_registrations) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe runner hardening rollback: trusted runner registry state exists';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS runner_result_receipts_no_truncate ON runner_result_receipts;
DROP TRIGGER IF EXISTS runner_result_receipts_immutable ON runner_result_receipts;
DROP FUNCTION reject_runner_result_receipt_mutation();
DROP TABLE runner_result_receipts;
DROP TABLE runner_certificates;
DROP TRIGGER IF EXISTS runner_scope_bindings_revision ON runner_scope_bindings;
DROP TRIGGER IF EXISTS runner_scope_bindings_no_truncate ON runner_scope_bindings;
DROP TRIGGER IF EXISTS runner_scope_bindings_immutable ON runner_scope_bindings;
DROP TABLE runner_scope_bindings;
DROP FUNCTION bump_runner_scope_revision();
DROP FUNCTION reject_runner_scope_binding_update();
DROP TABLE runner_registrations;

ALTER TABLE executions DROP CONSTRAINT executions_status_check;
ALTER TABLE executions ADD CONSTRAINT executions_status_check CHECK (
    status IN (
        'QUEUED', 'LEASED', 'RUNNING', 'WAITING_EXTERNAL_APPROVAL', 'WAITING_SYNC',
        'VERIFYING', 'SUCCEEDED', 'FAILED', 'ROLLED_BACK', 'CANCELLED'
    )
);

ALTER TABLE action_queue
    DROP CONSTRAINT action_queue_receipt_fence_uk;

DROP INDEX action_queue_workspace_idempotency_uk;
DROP INDEX action_queue_active_target_uk;
DROP INDEX action_queue_single_production_write_uk;

ALTER TABLE action_queue
    DROP CONSTRAINT action_queue_status_ck,
    DROP CONSTRAINT action_queue_idempotency_key_ck,
    DROP CONSTRAINT action_queue_request_hash_ck,
    DROP CONSTRAINT action_queue_authorization_expiry_ck,
    DROP CONSTRAINT action_queue_scope_revision_ck,
    DROP CONSTRAINT action_queue_heartbeat_seq_ck,
    DROP CONSTRAINT action_queue_cancel_intent_ck,
    DROP CONSTRAINT action_queue_completion_status_ck,
    DROP CONSTRAINT action_queue_active_lease_shape_ck,
    DROP CONSTRAINT action_queue_terminal_shape_ck,
    DROP CONSTRAINT action_queue_result_shape_ck,
    DROP CONSTRAINT action_queue_completed_fence_ck,
    DROP CONSTRAINT action_queue_terminal_proof_ck;

ALTER TABLE action_queue
    ADD CONSTRAINT action_queue_status_ck CHECK (
        status IN ('QUEUED', 'LEASED', 'RUNNING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED')
    ),
    ADD CONSTRAINT action_queue_active_lease_shape_ck CHECK (
        (
            status IN ('LEASED', 'RUNNING') AND lease_epoch > 0 AND runner_id IS NOT NULL AND lease_token_sha256 IS NOT NULL AND
            lease_acquired_at IS NOT NULL AND lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL AND
            completed_at IS NULL AND result_hash IS NULL
        ) OR (
            status NOT IN ('LEASED', 'RUNNING') AND lease_token_sha256 IS NULL AND lease_expires_at IS NULL
        )
    ),
    ADD CONSTRAINT action_queue_terminal_shape_ck CHECK (
        (status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED') AND completed_at IS NOT NULL) OR
        (status IN ('QUEUED', 'LEASED', 'RUNNING') AND completed_at IS NULL)
    ),
    ADD CONSTRAINT action_queue_result_shape_ck CHECK (
        (status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED') AND result_hash IS NOT NULL) OR
        (status IN ('QUEUED', 'LEASED', 'RUNNING', 'CANCELLED') AND result_hash IS NULL)
    ),
    ADD CONSTRAINT action_queue_completed_fence_ck CHECK (
        (completed_lease_token_sha256 IS NULL AND completed_lease_epoch IS NULL) OR
        (
            runner_id IS NOT NULL AND completed_lease_token_sha256 IS NOT NULL AND completed_lease_epoch IS NOT NULL AND
            completed_lease_epoch > 0 AND completed_lease_epoch = lease_epoch AND
            status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED')
        )
    ),
    ADD CONSTRAINT action_queue_terminal_proof_ck CHECK (
        (
            status IN ('QUEUED', 'LEASED', 'RUNNING') AND completed_lease_token_sha256 IS NULL AND reconciliation_id IS NULL
        ) OR (
            status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED') AND completed_lease_token_sha256 IS NOT NULL
        ) OR (
            status = 'CANCELLED' AND runner_id IS NULL AND completed_lease_token_sha256 IS NULL AND reconciliation_id IS NULL
        )
    );

CREATE UNIQUE INDEX action_queue_active_target_uk
    ON action_queue (target_key)
    WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN');

CREATE UNIQUE INDEX action_queue_single_production_write_uk
    ON action_queue ((1))
    WHERE runner_pool = 'WRITE' AND production = true AND status IN ('LEASED', 'RUNNING', 'UNCERTAIN');

ALTER TABLE action_queue
    DROP COLUMN completion_status,
    DROP COLUMN cancel_reason_hash,
    DROP COLUMN cancel_requested_at,
    DROP COLUMN heartbeat_seq,
    DROP COLUMN scope_revision,
    DROP COLUMN request_hash_version,
    DROP COLUMN request_hash,
    DROP COLUMN authorization_expires_at,
    DROP COLUMN idempotency_key;

ALTER TABLE execution_leases
    DROP CONSTRAINT execution_leases_plaintext_token_empty_ck,
    DROP CONSTRAINT execution_leases_token_hashes_ck,
    DROP CONSTRAINT execution_leases_active_hash_shape_ck,
    DROP CONSTRAINT execution_leases_completion_hash_shape_ck;

ALTER TABLE execution_leases
    ADD CONSTRAINT execution_leases_active_shape_ck CHECK (
        (
            status IN ('LEASED', 'RUNNING') AND runner_id IS NOT NULL AND lease_token IS NOT NULL AND lease_epoch > 0 AND
            lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL AND lease_expires_at > last_heartbeat_at
        ) OR (
            status NOT IN ('LEASED', 'RUNNING') AND lease_token IS NULL AND lease_expires_at IS NULL
        )
    ),
    ADD CONSTRAINT execution_leases_completion_shape_ck CHECK (
        (
            completed_lease_token IS NULL AND completed_lease_epoch IS NULL AND result_hash IS NULL AND
            ((reconciliation_id IS NULL AND status NOT IN ('SUCCEEDED', 'FAILED')) OR
             (reconciliation_id IS NOT NULL AND status IN ('SUCCEEDED', 'FAILED')))
        ) OR (
            completed_lease_token IS NOT NULL AND completed_lease_epoch IS NOT NULL AND completed_lease_epoch > 0 AND
            completed_lease_epoch = lease_epoch AND runner_id IS NOT NULL AND result_hash IS NOT NULL AND
            octet_length(result_hash) = 64 AND result_hash COLLATE "C" !~ '[^a-f0-9]' AND
            status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')
        )
    );

ALTER TABLE execution_leases
    DROP COLUMN completed_lease_token_sha256,
    DROP COLUMN lease_token_sha256;

COMMIT;
