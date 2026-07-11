BEGIN;

-- Credential revocation data is a safety boundary.
-- Only REVOKED/NO_CREDENTIAL rows without evidence and with fully delivered outbox events are safe to discard.
-- The immutable action_type and signed credential_ttl_seconds bindings are removed only with the guarded table drop.
-- Lock every table participating in the guard so no writer can cross the check.
LOCK TABLE action_queue, execution_leases, credential_revocations, credential_revocation_confirmations, audit_records, outbox_events IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM action_queue
        WHERE runner_pool = 'WRITE' AND status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    ) OR EXISTS (
        SELECT 1
        FROM execution_leases
        WHERE runner_pool = 'WRITE' AND status IN ('LEASED', 'RUNNING', 'UNCERTAIN')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe credential revocation rollback: write executions must be drained';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM credential_revocations
        WHERE status NOT IN ('REVOKED', 'NO_CREDENTIAL')
           OR accessor_ciphertext IS NOT NULL
           OR encryption_key_id IS NOT NULL
           OR evidence_hash IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM credential_revocation_confirmations
    ) OR EXISTS (
        SELECT 1
        FROM outbox_events
        WHERE event_type LIKE 'credential.revocation.%' AND delivered_at IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe credential revocation rollback: active, evidenced, protected, or undispatched state remains';
    END IF;
END;
$$;

DROP TRIGGER action_queue_finalizing_receipt_shape ON action_queue;
DROP FUNCTION validate_action_queue_finalizing_receipt();
DROP TRIGGER action_queue_no_truncate ON action_queue;
DROP TRIGGER action_queue_no_delete ON action_queue;
DROP FUNCTION reject_action_queue_removal();
DROP TRIGGER action_queue_00_terminal_immutable_guard ON action_queue;
DROP FUNCTION reject_action_queue_terminal_mutation();
DROP TRIGGER action_queue_submission_identity_guard ON action_queue;
DROP FUNCTION reject_action_queue_submission_identity_mutation();
DROP TRIGGER action_queue_credential_cleanup_gate ON action_queue;
DROP FUNCTION enforce_action_queue_credential_cleanup();
DROP TRIGGER credential_revocations_action_marker_shape ON credential_revocations;
DROP FUNCTION validate_credential_revocation_action_marker();

DROP TABLE credential_revocation_confirmations;
DROP TABLE credential_revocations;
DROP TRIGGER audit_records_no_truncate ON audit_records;

DROP FUNCTION validate_credential_confirmation_parent_shape();
DROP FUNCTION validate_credential_confirmation_shape();
DROP FUNCTION validate_credential_revocation_confirmation();
DROP FUNCTION reject_credential_confirmation_mutation();
DROP FUNCTION enforce_credential_revocation_transition();
DROP FUNCTION reject_credential_revocation_removal();
DROP FUNCTION reject_credential_revocation_reparenting();

ALTER TABLE action_queue
    DROP CONSTRAINT action_queue_credential_marker_shape_ck,
    DROP CONSTRAINT action_queue_no_active_production_write_ck,
    DROP COLUMN credential_lease_epoch,
    DROP COLUMN credential_expected;

ALTER TABLE execution_leases
    DROP CONSTRAINT execution_leases_no_active_production_write_ck;

COMMIT;
