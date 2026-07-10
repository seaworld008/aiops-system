BEGIN;

-- Credential revocation data is a safety boundary.
-- Only REVOKED/NO_CREDENTIAL rows without evidence and with fully delivered outbox events are safe to discard.
-- Lock every table participating in the guard so no writer can cross the check.
LOCK TABLE action_queue, credential_revocations, credential_revocation_confirmations, audit_records, outbox_events IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM action_queue
        WHERE runner_pool = 'WRITE' AND status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe credential revocation rollback: write action queue must be drained';
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

COMMIT;
