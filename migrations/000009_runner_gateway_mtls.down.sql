BEGIN;

-- Downgrading removes authenticated receipt and heartbeat evidence. Freeze
-- every inspected table and refuse the rollback unless no M3 protocol state
-- can be lost or reinterpreted by an older Runner implementation.
LOCK TABLE action_queue, execution_leases, runner_result_receipts, runner_certificates, runner_registrations, credential_revocations, credential_revocation_receipts, credential_revocation_system_receipts, audit_records, outbox_events IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM action_queue
        WHERE status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    ) OR EXISTS (
        SELECT 1 FROM runner_result_receipts
        WHERE schema_version = 'runner-result.v2'
    ) OR EXISTS (
        SELECT 1 FROM runner_certificates WHERE status = 'REVOKED'
    ) OR EXISTS (
        SELECT 1 FROM runner_registrations
        WHERE credential_revocation_capable = true
    ) OR EXISTS (
        SELECT 1 FROM credential_revocations
        WHERE status = 'REVOKING' OR heartbeat_seq <> 0
    ) OR EXISTS (
        SELECT 1 FROM credential_revocation_receipts
    ) OR EXISTS (
        SELECT 1 FROM credential_revocation_system_receipts
    ) OR EXISTS (
        SELECT 1 FROM audit_records
        WHERE action LIKE 'runner.gateway.%'
           OR action LIKE 'credential.revocation.runner.%'
    ) OR EXISTS (
        SELECT 1 FROM outbox_events
        WHERE event_type LIKE 'runner.gateway.%'
           OR event_type LIKE 'credential.revocation.runner.%'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe Runner Gateway rollback: active leases or M3 evidence remain';
    END IF;

    IF EXISTS (
        SELECT 1 FROM execution_leases
        WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe Runner Gateway rollback: legacy execution leases remain active',
            CONSTRAINT = 'execution_leases_m3_cutover_guard';
    END IF;
END;
$$;

DROP TRIGGER execution_leases_m3_cutover_guard ON execution_leases;
DROP FUNCTION reject_legacy_execution_lease_activation();

DROP TRIGGER credential_revocations_completion_receipt_guard ON credential_revocations;
DROP FUNCTION validate_credential_revocation_completion_receipt();
DROP TRIGGER credential_revocations_system_recovery_receipt ON credential_revocations;
DROP FUNCTION capture_credential_revocation_system_recovery();
DROP TRIGGER credential_revocation_system_receipts_no_truncate ON credential_revocation_system_receipts;
DROP TRIGGER credential_revocation_system_receipts_immutable ON credential_revocation_system_receipts;
DROP TRIGGER credential_revocation_system_receipts_insert_guard ON credential_revocation_system_receipts;
DROP TRIGGER credential_revocation_system_receipts_final_shape ON credential_revocation_system_receipts;
DROP TABLE credential_revocation_system_receipts;
DROP FUNCTION reject_credential_revocation_system_receipt_mutation();
DROP FUNCTION validate_credential_revocation_system_receipt_final_shape();
DROP FUNCTION guard_credential_revocation_system_receipt_insert();
DROP TRIGGER IF EXISTS credential_revocation_receipts_no_truncate ON credential_revocation_receipts;
DROP TRIGGER IF EXISTS credential_revocation_receipts_immutable ON credential_revocation_receipts;
DROP TRIGGER IF EXISTS credential_revocation_receipts_claim_guard ON credential_revocation_receipts;
DROP TRIGGER IF EXISTS credential_revocation_receipts_final_shape ON credential_revocation_receipts;
DROP TABLE credential_revocation_receipts;
DROP FUNCTION reject_credential_revocation_receipt_mutation();
DROP FUNCTION validate_credential_revocation_receipt_final_shape();
DROP FUNCTION validate_credential_revocation_receipt_claim();

DROP TRIGGER credential_revocations_heartbeat_sequence_guard ON credential_revocations;
DROP FUNCTION enforce_credential_revocation_heartbeat_sequence();
ALTER TABLE credential_revocations
    DROP CONSTRAINT credential_revocations_heartbeat_seq_ck,
    DROP COLUMN heartbeat_seq;

DROP TRIGGER runner_result_receipts_insert_guard ON runner_result_receipts;
DROP FUNCTION enforce_runner_result_receipt_insert();
ALTER TABLE runner_result_receipts
    DROP CONSTRAINT runner_result_receipts_schema_ck,
    ADD CONSTRAINT runner_result_receipts_schema_ck CHECK (schema_version = 'runner-result.v1');

-- Restore the exact M2 receipt semantics. Historical v1 rows remain usable,
-- while every M3-only v2 row was rejected by the rollback guard above.
CREATE OR REPLACE FUNCTION enforce_action_queue_credential_cleanup() RETURNS trigger AS $$
DECLARE
    cleanup_required boolean;
    fence_token_sha256 text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'QUEUED' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'actions must enter the queue in QUEUED state',
                CONSTRAINT = 'action_queue_state_transition_guard';
        END IF;
        IF NEW.credential_expected = true OR NEW.credential_lease_epoch IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'new actions cannot predeclare a credential anchor',
                CONSTRAINT = 'action_queue_credential_marker_guard';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status IS DISTINCT FROM NEW.status AND NOT (
        (OLD.status = 'QUEUED' AND NEW.status IN ('LEASED', 'CANCELLED')) OR
        (OLD.status = 'LEASED' AND NEW.status IN ('RUNNING', 'QUEUED', 'FAILED', 'CANCELLED')) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('FINALIZING', 'UNCERTAIN')) OR
        (OLD.status = 'FINALIZING' AND NEW.status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')) OR
        (OLD.status = 'UNCERTAIN' AND NEW.status IN ('SUCCEEDED', 'FAILED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'invalid action execution state transition',
            CONSTRAINT = 'action_queue_state_transition_guard';
    END IF;

    IF OLD.status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED')
       AND (
           OLD.result_hash IS DISTINCT FROM NEW.result_hash OR
           OLD.completion_status IS DISTINCT FROM NEW.completion_status
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'action result proof is immutable after execution completion begins',
            CONSTRAINT = 'action_queue_result_proof_guard';
    END IF;

    IF OLD.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED')
       AND NEW.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED')
       AND (
           OLD.runner_id IS DISTINCT FROM NEW.runner_id
           OR OLD.runner_tenant_id IS DISTINCT FROM NEW.runner_tenant_id
           OR OLD.runner_workspace_id IS DISTINCT FROM NEW.runner_workspace_id
           OR OLD.runner_environment_id IS DISTINCT FROM NEW.runner_environment_id
           OR OLD.scope_revision IS DISTINCT FROM NEW.scope_revision
           OR OLD.lease_epoch IS DISTINCT FROM NEW.lease_epoch
           OR CASE
               WHEN OLD.status IN ('LEASED', 'RUNNING') THEN OLD.lease_token_sha256
               ELSE OLD.completed_lease_token_sha256
           END IS DISTINCT FROM CASE
               WHEN NEW.status IN ('LEASED', 'RUNNING') THEN NEW.lease_token_sha256
               ELSE NEW.completed_lease_token_sha256
           END
           OR (
               OLD.status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED') AND
               OLD.completed_lease_epoch IS DISTINCT FROM NEW.completed_lease_epoch
           )
           OR (
               NEW.status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED') AND
               NEW.completed_lease_epoch IS DISTINCT FROM NEW.lease_epoch
           )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'action active runner fence is immutable',
            CONSTRAINT = 'action_queue_active_fence_guard';
    END IF;

    IF OLD.status = 'LEASED' AND NEW.status = 'FAILED'
       AND NEW.completion_status IS DISTINCT FROM 'FAILED' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'a rejected lease must retain a FAILED completion proof',
            CONSTRAINT = 'action_queue_rejection_proof_guard';
    END IF;

    IF OLD.status = 'FINALIZING' AND NEW.status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN') THEN
        IF NEW.status IS DISTINCT FROM OLD.completion_status OR NOT EXISTS (
            SELECT 1
            FROM runner_result_receipts AS receipt
            WHERE receipt.action_id = NEW.action_id
              AND receipt.tenant_id = NEW.runner_tenant_id
              AND receipt.workspace_id = NEW.runner_workspace_id
              AND receipt.environment_id = NEW.runner_environment_id
              AND receipt.runner_id = NEW.runner_id
              AND receipt.lease_epoch = NEW.lease_epoch
              AND receipt.scope_revision = NEW.scope_revision
              AND receipt.receipt_hash = NEW.result_hash
              AND receipt.completion_status = NEW.completion_status
              AND receipt.schema_version = 'runner-result.v1'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'final action state requires its exact immutable runner result receipt',
                CONSTRAINT = 'action_queue_result_receipt_guard';
        END IF;
    END IF;

    IF OLD.status = 'UNCERTAIN' AND NEW.status IN ('SUCCEEDED', 'FAILED')
       AND (
           NEW.reconciliation_id IS NULL OR
           NEW.reconciliation_actor IS NULL OR
           NEW.reconciliation_result_hash IS NULL OR
           NEW.reconciled_at IS NULL
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'uncertain action resolution requires a complete reconciliation proof',
            CONSTRAINT = 'action_queue_reconciliation_proof_guard';
    END IF;

    IF OLD.credential_expected = false AND NEW.credential_expected = true THEN
        IF (
            OLD.status = NEW.status AND OLD.status IN ('LEASED', 'RUNNING') AND
            OLD.runner_pool = 'WRITE' AND OLD.production = false AND
            NEW.lease_epoch = OLD.lease_epoch AND
            NEW.credential_lease_epoch = OLD.lease_epoch
        ) IS NOT TRUE OR NOT EXISTS (
            SELECT 1
            FROM credential_revocations AS revocation
            WHERE revocation.action_id = NEW.action_id
              AND revocation.tenant_id = NEW.runner_tenant_id
              AND revocation.workspace_id = NEW.runner_workspace_id
              AND revocation.environment_id = NEW.runner_environment_id
              AND revocation.target_key = NEW.target_key
              AND revocation.production = NEW.production
              AND revocation.runner_id = NEW.runner_id
              AND revocation.action_lease_epoch = NEW.lease_epoch
              AND revocation.action_lease_token_sha256 = NEW.lease_token_sha256
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'action credential marker requires an exact durable anchor',
                CONSTRAINT = 'action_queue_credential_marker_guard';
        END IF;
    END IF;

    IF OLD.credential_expected = true AND (
        NEW.credential_expected = false OR
        NEW.credential_lease_epoch IS DISTINCT FROM OLD.credential_lease_epoch
    ) AND NOT (
        OLD.status = 'LEASED' AND NEW.status = 'QUEUED'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'action credential marker is immutable while retained',
            CONSTRAINT = 'action_queue_credential_marker_guard';
    END IF;

    IF OLD.runner_pool = 'WRITE'
       AND OLD.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
       AND NEW.status NOT IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN') THEN
        fence_token_sha256 := CASE
            WHEN OLD.status IN ('LEASED', 'RUNNING') THEN OLD.lease_token_sha256
            ELSE OLD.completed_lease_token_sha256
        END;
        cleanup_required :=
            OLD.status IN ('RUNNING', 'FINALIZING', 'UNCERTAIN') OR
            OLD.credential_expected OR
            EXISTS (
                SELECT 1
                FROM credential_revocations AS candidate
                WHERE candidate.action_id = OLD.action_id
                  AND candidate.action_lease_epoch = OLD.lease_epoch
            );
        IF cleanup_required AND NOT EXISTS (
            SELECT 1
            FROM credential_revocations AS terminal
            WHERE terminal.action_id = OLD.action_id
              AND terminal.tenant_id = OLD.runner_tenant_id
              AND terminal.workspace_id = OLD.runner_workspace_id
              AND terminal.environment_id = OLD.runner_environment_id
              AND terminal.target_key = OLD.target_key
              AND terminal.production = OLD.production
              AND terminal.runner_id = OLD.runner_id
              AND terminal.action_lease_epoch = OLD.lease_epoch
              AND terminal.action_lease_token_sha256 = fence_token_sha256
              AND terminal.status IN ('REVOKED', 'NO_CREDENTIAL')
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'action target remains locked until credential cleanup is terminal',
                CONSTRAINT = 'action_queue_credential_cleanup_gate';
        END IF;
        IF OLD.status = 'LEASED' AND NEW.status = 'QUEUED' THEN
            NEW.credential_expected := false;
            NEW.credential_lease_epoch := NULL;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION validate_action_queue_finalizing_receipt() RETURNS trigger AS $$
BEGIN
    IF NEW.status = 'FINALIZING' AND NOT EXISTS (
        SELECT 1
        FROM runner_result_receipts AS receipt
        WHERE receipt.action_id = NEW.action_id
          AND receipt.tenant_id = NEW.runner_tenant_id
          AND receipt.workspace_id = NEW.runner_workspace_id
          AND receipt.environment_id = NEW.runner_environment_id
          AND receipt.runner_id = NEW.runner_id
          AND receipt.lease_epoch = NEW.lease_epoch
          AND receipt.scope_revision = NEW.scope_revision
          AND receipt.receipt_hash = NEW.result_hash
          AND receipt.completion_status = NEW.completion_status
          AND receipt.schema_version = 'runner-result.v1'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'FINALIZING action requires its exact immutable runner result receipt',
            CONSTRAINT = 'action_queue_finalizing_receipt_shape';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS runner_certificates_no_truncate ON runner_certificates;
DROP TRIGGER IF EXISTS runner_certificates_no_delete ON runner_certificates;
DROP TRIGGER runner_certificates_lifecycle_guard ON runner_certificates;
DROP FUNCTION reject_runner_certificate_removal();
DROP FUNCTION enforce_runner_certificate_lifecycle();
ALTER TABLE runner_certificates
    DROP CONSTRAINT runner_certificates_time_ck,
    DROP CONSTRAINT runner_certificates_metadata_ck;

ALTER TABLE runner_registrations
    DROP CONSTRAINT runner_registrations_revocation_capability_ck,
    DROP COLUMN credential_revocation_capable;

COMMIT;
