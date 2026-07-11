BEGIN;

-- COORDINATED CUTOVER PREREQUISITE: the public control plane remains live,
-- but every old Runner and credential revoker must be drained before this
-- migration. M3 authenticates every lease mutation with a registered client
-- certificate and a sequenced heartbeat; mixed old/new Runner protocols are
-- intentionally unsupported.
LOCK TABLE action_queue, execution_leases, runner_result_receipts, runner_certificates,
    runner_registrations, credential_revocations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM action_queue
        WHERE status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    ) OR EXISTS (
        SELECT 1 FROM credential_revocations WHERE status = 'REVOKING'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe Runner Gateway upgrade: Runner and revocation leases must be drained';
    END IF;

    IF EXISTS (
        SELECT 1 FROM execution_leases
        WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe Runner Gateway upgrade: legacy execution leases must be drained',
            CONSTRAINT = 'execution_leases_m3_cutover_guard';
    END IF;
END;
$$;

-- execution_leases is the pre-ActionQueue claim surface. Keeping the table as
-- a compatibility shell is useful for rollback, but an old process must never
-- be able to create a second, unauthenticated lease after this cutover.
CREATE OR REPLACE FUNCTION reject_legacy_execution_lease_activation() RETURNS trigger AS $$
BEGIN
    IF NEW.status IN ('LEASED', 'RUNNING', 'UNCERTAIN') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy execution lease activation is disabled after Runner Gateway cutover',
            CONSTRAINT = 'execution_leases_m3_cutover_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER execution_leases_m3_cutover_guard
    BEFORE INSERT OR UPDATE ON execution_leases
    FOR EACH ROW EXECUTE FUNCTION reject_legacy_execution_lease_activation();

ALTER TABLE runner_registrations
    ADD COLUMN credential_revocation_capable boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT runner_registrations_revocation_capability_ck CHECK (
        NOT credential_revocation_capable OR runner_pool = 'WRITE'
    );

ALTER TABLE runner_certificates
    ADD CONSTRAINT runner_certificates_metadata_ck CHECK (
        octet_length(issuer_key_id) BETWEEN 1 AND 256 AND
        left(issuer_key_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        issuer_key_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        (revocation_reason IS NULL OR (
            octet_length(revocation_reason) BETWEEN 1 AND 512 AND
            revocation_reason = btrim(revocation_reason) AND
            revocation_reason !~ '[[:cntrl:]]'
        ))
    ),
    ADD CONSTRAINT runner_certificates_time_ck CHECK (
        not_before > '-infinity'::timestamptz AND not_before < 'infinity'::timestamptz AND
        not_after > '-infinity'::timestamptz AND not_after < 'infinity'::timestamptz AND
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
        not_before < not_after AND created_at < not_after AND
        (revoked_at IS NULL OR (
            revoked_at > '-infinity'::timestamptz AND revoked_at < 'infinity'::timestamptz AND
            revoked_at >= created_at
        ))
    );

CREATE OR REPLACE FUNCTION enforce_runner_certificate_lifecycle() RETURNS trigger AS $$
DECLARE
    transition_at timestamptz;
BEGIN
    transition_at := clock_timestamp();
    IF TG_OP = 'INSERT' THEN
        NEW.created_at := transition_at;
        IF NEW.status <> 'ACTIVE' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'Runner certificates must be registered ACTIVE',
                CONSTRAINT = 'runner_certificates_lifecycle_guard';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.certificate_sha256 IS DISTINCT FROM NEW.certificate_sha256
       OR OLD.runner_id IS DISTINCT FROM NEW.runner_id
       OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.issuer_key_id IS DISTINCT FROM NEW.issuer_key_id
       OR OLD.serial_hex IS DISTINCT FROM NEW.serial_hex
       OR OLD.spki_sha256 IS DISTINCT FROM NEW.spki_sha256
       OR OLD.not_before IS DISTINCT FROM NEW.not_before
       OR OLD.not_after IS DISTINCT FROM NEW.not_after
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Runner certificate identity metadata is immutable',
            CONSTRAINT = 'runner_certificates_lifecycle_guard';
    END IF;

    IF OLD.status = 'ACTIVE' AND NEW.status = 'REVOKED' THEN
        IF NEW.revocation_reason IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'Runner certificate revocation requires a reason',
                CONSTRAINT = 'runner_certificates_lifecycle_guard';
        END IF;
        NEW.revoked_at := transition_at;
        RETURN NEW;
    END IF;

    IF OLD IS DISTINCT FROM NEW THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Runner certificates only permit ACTIVE to REVOKED',
            CONSTRAINT = 'runner_certificates_lifecycle_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER runner_certificates_lifecycle_guard
    BEFORE INSERT OR UPDATE ON runner_certificates
    FOR EACH ROW EXECUTE FUNCTION enforce_runner_certificate_lifecycle();

CREATE OR REPLACE FUNCTION reject_runner_certificate_removal() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'Runner certificate history cannot be deleted or truncated',
        CONSTRAINT = 'runner_certificates_history_guard';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER runner_certificates_no_delete
    BEFORE DELETE ON runner_certificates
    FOR EACH ROW EXECUTE FUNCTION reject_runner_certificate_removal();

CREATE TRIGGER runner_certificates_no_truncate
    BEFORE TRUNCATE ON runner_certificates
    FOR EACH STATEMENT EXECUTE FUNCTION reject_runner_certificate_removal();

ALTER TABLE runner_result_receipts
    DROP CONSTRAINT runner_result_receipts_schema_ck,
    ADD CONSTRAINT runner_result_receipts_schema_ck CHECK (
        schema_version = 'runner-result.v1' OR
        (schema_version = 'runner-result.v2' AND certificate_sha256 IS NOT NULL)
    );

CREATE OR REPLACE FUNCTION enforce_runner_result_receipt_insert() RETURNS trigger AS $$
BEGIN
    NEW.received_at := clock_timestamp();
    IF NEW.schema_version <> 'runner-result.v2' OR NEW.certificate_sha256 IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new Runner result receipts require the authenticated v2 schema',
            CONSTRAINT = 'runner_result_receipts_insert_guard';
    END IF;

    PERFORM 1
    FROM runner_registrations AS registration
    WHERE registration.runner_id = NEW.runner_id
      AND registration.tenant_id = NEW.tenant_id
      AND registration.enabled = true
      AND registration.runner_pool = 'WRITE'
      AND registration.scope_revision = NEW.scope_revision
    FOR SHARE OF registration;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Runner result receipt does not match its current WRITE registration',
            CONSTRAINT = 'runner_result_receipts_insert_guard';
    END IF;

    PERFORM 1
    FROM runner_certificates AS certificate
    WHERE certificate.runner_id = NEW.runner_id
      AND certificate.tenant_id = NEW.tenant_id
      AND certificate.certificate_sha256 = NEW.certificate_sha256
      AND certificate.status = 'ACTIVE'
      AND certificate.not_before <= NEW.received_at
      AND certificate.not_after > NEW.received_at
    FOR SHARE OF certificate;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Runner result receipt does not match a current authenticated certificate',
            CONSTRAINT = 'runner_result_receipts_insert_guard';
    END IF;

    PERFORM 1
    FROM action_queue AS action
    WHERE action.action_id = NEW.action_id
      AND action.runner_id = NEW.runner_id
      AND action.runner_tenant_id = NEW.tenant_id
      AND action.runner_workspace_id = NEW.workspace_id
      AND action.runner_environment_id = NEW.environment_id
      AND action.runner_pool = 'WRITE'
      AND action.status = 'FINALIZING'
      AND action.lease_epoch = NEW.lease_epoch
      AND action.scope_revision = NEW.scope_revision
      AND action.result_hash = NEW.receipt_hash
      AND action.completion_status = NEW.completion_status
    FOR SHARE OF action;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Runner result receipt does not match its trusted WRITE action fence',
            CONSTRAINT = 'runner_result_receipts_insert_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER runner_result_receipts_insert_guard
    BEFORE INSERT ON runner_result_receipts
    FOR EACH ROW EXECUTE FUNCTION enforce_runner_result_receipt_insert();

-- Preserve every M2 state-machine invariant while allowing an authenticated
-- v2 receipt to satisfy the same finalization proof as a historical v1 row.
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
              AND receipt.schema_version IN ('runner-result.v1', 'runner-result.v2')
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
          AND receipt.schema_version IN ('runner-result.v1', 'runner-result.v2')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'FINALIZING action requires its exact immutable runner result receipt',
            CONSTRAINT = 'action_queue_finalizing_receipt_shape';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE credential_revocations
    ADD COLUMN heartbeat_seq bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT credential_revocations_heartbeat_seq_ck CHECK (heartbeat_seq >= 0);

CREATE OR REPLACE FUNCTION enforce_credential_revocation_heartbeat_sequence() RETURNS trigger AS $$
DECLARE
    transition_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.heartbeat_seq <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocation heartbeat sequence must begin at zero',
                CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.claim_epoch > OLD.claim_epoch THEN
        IF (
            to_jsonb(NEW) - ARRAY[
                'status', 'claim_epoch', 'claimed_by', 'claim_token_sha256', 'claimed_at',
                'claim_expires_at', 'last_heartbeat_at', 'attempt', 'heartbeat_seq', 'updated_at', 'version'
            ]
        ) IS DISTINCT FROM (
            to_jsonb(OLD) - ARRAY[
                'status', 'claim_epoch', 'claimed_by', 'claim_token_sha256', 'claimed_at',
                'claim_expires_at', 'last_heartbeat_at', 'attempt', 'heartbeat_seq', 'updated_at', 'version'
            ]
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocation claim cannot mutate non-claim state',
                CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
        END IF;
        PERFORM 1
        FROM runner_registrations AS registration
        WHERE registration.runner_id = NEW.claimed_by
          AND registration.tenant_id = NEW.tenant_id
          AND registration.enabled = true
          AND registration.runner_pool = 'WRITE'
          AND registration.credential_revocation_capable = true
        FOR SHARE OF registration;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'credential revocation claims require an enabled capability Runner',
                CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
        END IF;
        PERFORM 1
        FROM runner_scope_bindings AS binding
        WHERE binding.runner_id = NEW.claimed_by
          AND binding.tenant_id = NEW.tenant_id
          AND binding.workspace_id = NEW.workspace_id
          AND binding.environment_id = NEW.environment_id
        FOR SHARE OF binding;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'credential revocation claims require the exact registered scope pair',
                CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
        END IF;
        transition_at := clock_timestamp();
        NEW.heartbeat_seq := 0;
        NEW.claimed_at := transition_at;
        NEW.last_heartbeat_at := transition_at;
        NEW.claim_expires_at := transition_at + interval '30 seconds';
        RETURN NEW;
    END IF;

    IF OLD.status = 'REVOKING' AND NEW.status = 'REVOKING'
       AND NEW.claim_epoch = OLD.claim_epoch THEN
        IF NEW.claimed_by IS DISTINCT FROM OLD.claimed_by
           OR NEW.claim_token_sha256 IS DISTINCT FROM OLD.claim_token_sha256
           OR NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
           OR (
               to_jsonb(NEW) - ARRAY[
                   'heartbeat_seq', 'last_heartbeat_at', 'claim_expires_at', 'updated_at', 'version'
               ]
           ) IS DISTINCT FROM (
               to_jsonb(OLD) - ARRAY[
                   'heartbeat_seq', 'last_heartbeat_at', 'claim_expires_at', 'updated_at', 'version'
               ]
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocation active claim is immutable outside heartbeat evidence',
                CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
        END IF;
        IF NEW.heartbeat_seq = OLD.heartbeat_seq THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocation heartbeat replay cannot update state',
                CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
        END IF;
    END IF;

    IF NEW.heartbeat_seq < OLD.heartbeat_seq OR
       NEW.heartbeat_seq > OLD.heartbeat_seq + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential revocation heartbeat sequence must advance exactly once',
            CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
    END IF;

    IF NEW.heartbeat_seq = OLD.heartbeat_seq + 1 THEN
        transition_at := clock_timestamp();
        IF NOT (
            OLD.status = 'REVOKING' AND NEW.status = 'REVOKING' AND
            NEW.claim_epoch = OLD.claim_epoch AND
            NEW.claimed_by IS NOT DISTINCT FROM OLD.claimed_by AND
            NEW.claim_token_sha256 IS NOT DISTINCT FROM OLD.claim_token_sha256 AND
            OLD.claim_expires_at > transition_at AND
            transition_at > OLD.last_heartbeat_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocation heartbeat sequence is not bound to its current active claim',
                CONSTRAINT = 'credential_revocations_heartbeat_sequence_guard';
        END IF;
        NEW.last_heartbeat_at := transition_at;
        NEW.claim_expires_at := transition_at + interval '30 seconds';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocations_heartbeat_sequence_guard
    BEFORE INSERT OR UPDATE ON credential_revocations
    FOR EACH ROW EXECUTE FUNCTION enforce_credential_revocation_heartbeat_sequence();

CREATE TABLE credential_revocation_receipts (
    revocation_id uuid NOT NULL,
    claim_epoch bigint NOT NULL,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    runner_id text NOT NULL,
    scope_revision bigint NOT NULL,
    certificate_sha256 text NOT NULL,
    issuer text NOT NULL,
    issuer_revision text NOT NULL,
    claim_token_sha256 text NOT NULL,
    heartbeat_seq bigint NOT NULL,
    outcome text NOT NULL,
    failure_count integer,
    failure_code text,
    failure_detail_sha256 text,
    receipt_hash text NOT NULL,
    schema_version text NOT NULL DEFAULT 'credential-revocation-result.v1',
    received_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    PRIMARY KEY (revocation_id, claim_epoch),
    CONSTRAINT credential_revocation_receipts_revocation_fk
        FOREIGN KEY (revocation_id)
        REFERENCES credential_revocations (revocation_id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocation_receipts_registration_fk
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocation_receipts_environment_scope_fk
        FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocation_receipts_certificate_fk
        FOREIGN KEY (runner_id, certificate_sha256)
        REFERENCES runner_certificates (runner_id, certificate_sha256) ON DELETE RESTRICT,
    CONSTRAINT credential_revocation_receipts_epoch_ck CHECK (
        claim_epoch > 0 AND scope_revision > 0 AND heartbeat_seq >= 0
    ),
    CONSTRAINT credential_revocation_receipts_runner_ck CHECK (
        octet_length(runner_id) BETWEEN 1 AND 256 AND
        left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT credential_revocation_receipts_issuer_ck CHECK (
        octet_length(issuer) BETWEEN 1 AND 256 AND
        issuer = btrim(issuer) AND issuer !~ '[[:cntrl:]]' AND
        octet_length(issuer_revision) BETWEEN 1 AND 256 AND
        left(issuer_revision, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        issuer_revision COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT credential_revocation_receipts_hashes_ck CHECK (
        octet_length(certificate_sha256) = 64 AND certificate_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(claim_token_sha256) = 64 AND claim_token_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(receipt_hash) = 64 AND receipt_hash COLLATE "C" !~ '[^a-f0-9]' AND
        (failure_detail_sha256 IS NULL OR (
            octet_length(failure_detail_sha256) = 64 AND failure_detail_sha256 COLLATE "C" !~ '[^a-f0-9]'
        ))
    ),
    CONSTRAINT credential_revocation_receipts_outcome_ck CHECK (
        (
            outcome = 'REVOKED' AND failure_count IS NULL AND
            failure_code IS NULL AND failure_detail_sha256 IS NULL
        ) OR (
            outcome = 'FAILED' AND failure_count IS NOT NULL AND failure_count > 0 AND
            failure_code IS NOT NULL AND
            failure_code IN (
                'ISSUER_UNAVAILABLE', 'RATE_LIMITED', 'TIMEOUT', 'AUTHENTICATION_FAILED',
                'PERMISSION_DENIED', 'REFERENCE_NOT_FOUND', 'INVALID_REFERENCE', 'UNKNOWN'
            ) AND failure_detail_sha256 IS NOT NULL
        )
    ),
    CONSTRAINT credential_revocation_receipts_schema_ck CHECK (
        schema_version = 'credential-revocation-result.v1'
    ),
    CONSTRAINT credential_revocation_receipts_received_at_ck CHECK (
        received_at > '-infinity'::timestamptz AND received_at < 'infinity'::timestamptz
    )
);

CREATE OR REPLACE FUNCTION validate_credential_revocation_receipt_claim() RETURNS trigger AS $$
DECLARE
    parent_failure_count integer;
BEGIN
    NEW.received_at := clock_timestamp();
    PERFORM 1
    FROM runner_registrations AS registration
    WHERE registration.runner_id = NEW.runner_id
      AND registration.tenant_id = NEW.tenant_id
      AND registration.enabled = true
      AND registration.runner_pool = 'WRITE'
      AND registration.credential_revocation_capable = true
      AND registration.scope_revision = NEW.scope_revision
    FOR SHARE OF registration;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation receipt requires an enabled capability Runner',
            CONSTRAINT = 'credential_revocation_receipts_claim_guard';
    END IF;

    PERFORM 1
    FROM runner_certificates AS certificate
    WHERE certificate.runner_id = NEW.runner_id
      AND certificate.tenant_id = NEW.tenant_id
      AND certificate.certificate_sha256 = NEW.certificate_sha256
      AND certificate.status = 'ACTIVE'
      AND certificate.not_before <= NEW.received_at
      AND certificate.not_after > NEW.received_at
    FOR SHARE OF certificate;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation receipt requires a current authenticated certificate',
            CONSTRAINT = 'credential_revocation_receipts_claim_guard';
    END IF;

    PERFORM 1
    FROM runner_scope_bindings AS binding
    WHERE binding.runner_id = NEW.runner_id
      AND binding.tenant_id = NEW.tenant_id
      AND binding.workspace_id = NEW.workspace_id
      AND binding.environment_id = NEW.environment_id
    FOR SHARE OF binding;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation receipt requires its current exact Runner scope pair',
            CONSTRAINT = 'credential_revocation_receipts_claim_guard';
    END IF;

    SELECT revocation.failure_count
    INTO parent_failure_count
    FROM credential_revocations AS revocation
    JOIN runner_registrations AS registration
      ON registration.runner_id = NEW.runner_id
     AND registration.tenant_id = revocation.tenant_id
    WHERE revocation.revocation_id = NEW.revocation_id
      AND revocation.tenant_id = NEW.tenant_id
      AND revocation.workspace_id = NEW.workspace_id
      AND revocation.environment_id = NEW.environment_id
      AND revocation.status = 'REVOKING'
      AND revocation.claim_epoch = NEW.claim_epoch
      AND revocation.claimed_by = NEW.runner_id
      AND revocation.issuer = NEW.issuer
      AND revocation.issuer_revision = NEW.issuer_revision
      AND revocation.claim_token_sha256 = NEW.claim_token_sha256
      AND revocation.heartbeat_seq = NEW.heartbeat_seq
      AND revocation.claim_expires_at > NEW.received_at
    FOR SHARE OF revocation;

    IF NOT FOUND OR (NEW.outcome = 'FAILED' AND NEW.failure_count <> parent_failure_count + 1) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation receipt does not match an authenticated active claim',
            CONSTRAINT = 'credential_revocation_receipts_claim_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocation_receipts_claim_guard
    BEFORE INSERT ON credential_revocation_receipts
    FOR EACH ROW EXECUTE FUNCTION validate_credential_revocation_receipt_claim();

CREATE OR REPLACE FUNCTION validate_credential_revocation_receipt_final_shape() RETURNS trigger AS $$
DECLARE
    parent credential_revocations%ROWTYPE;
BEGIN
    SELECT * INTO parent
    FROM credential_revocations
    WHERE revocation_id = NEW.revocation_id;

    IF NOT FOUND OR parent.claim_epoch <> NEW.claim_epoch
       OR parent.heartbeat_seq <> NEW.heartbeat_seq
       OR parent.tenant_id <> NEW.tenant_id
       OR parent.workspace_id <> NEW.workspace_id
       OR parent.environment_id <> NEW.environment_id
       OR parent.issuer <> NEW.issuer
       OR parent.issuer_revision <> NEW.issuer_revision
       OR NOT EXISTS (
           SELECT 1
           FROM runner_registrations AS registration
           JOIN runner_scope_bindings AS binding
             ON binding.runner_id = registration.runner_id
            AND binding.tenant_id = registration.tenant_id
           WHERE registration.runner_id = NEW.runner_id
             AND registration.tenant_id = NEW.tenant_id
             AND registration.enabled = true
             AND registration.runner_pool = 'WRITE'
             AND registration.credential_revocation_capable = true
             AND registration.scope_revision = NEW.scope_revision
             AND binding.workspace_id = NEW.workspace_id
             AND binding.environment_id = NEW.environment_id
       )
       OR EXISTS (
           SELECT 1
           FROM credential_revocation_system_receipts AS sibling
           WHERE sibling.revocation_id = NEW.revocation_id
             AND sibling.claim_epoch = NEW.claim_epoch
       )
       OR (
           NEW.outcome = 'REVOKED' AND NOT (
               parent.status = 'REVOKED' AND
               parent.completed_claim_epoch = NEW.claim_epoch AND
               parent.completed_claimed_by = NEW.runner_id AND
               parent.completed_claim_token_sha256 = NEW.claim_token_sha256
           )
       ) OR (
           NEW.outcome = 'FAILED' AND NOT (
               parent.status IN ('REVOCATION_PENDING', 'MANUAL_REQUIRED') AND
               parent.failure_count = NEW.failure_count AND
               parent.failure_code = NEW.failure_code AND
               parent.failure_detail_sha256 = NEW.failure_detail_sha256
           )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation receipt does not match the committed completion state',
            CONSTRAINT = 'credential_revocation_receipts_final_shape';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER credential_revocation_receipts_final_shape
    AFTER INSERT ON credential_revocation_receipts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_credential_revocation_receipt_final_shape();

CREATE OR REPLACE FUNCTION reject_credential_revocation_receipt_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'credential revocation completion receipts are immutable',
        CONSTRAINT = 'credential_revocation_receipts_immutable_guard';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocation_receipts_immutable
    BEFORE UPDATE OR DELETE ON credential_revocation_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_credential_revocation_receipt_mutation();

CREATE TRIGGER credential_revocation_receipts_no_truncate
    BEFORE TRUNCATE ON credential_revocation_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION reject_credential_revocation_receipt_mutation();

-- A crashed revoker is a database-owned recovery path, not a Runner
-- completion. Preserve the exact pre-transition claim and retry evidence in a
-- separate immutable receipt. The only accepted recovery fact is derivable
-- from database-owned expiry, attempt, and retry-cycle timestamps; an
-- application-side protected-reference error can never mint this evidence.
CREATE TABLE credential_revocation_system_receipts (
    revocation_id uuid NOT NULL,
    claim_epoch bigint NOT NULL,
    recovery_kind text NOT NULL,
    claimed_by text NOT NULL,
    claim_token_sha256 text NOT NULL,
    heartbeat_seq bigint NOT NULL,
    attempt integer NOT NULL,
    retry_cycle_attempt_base integer NOT NULL,
    retry_cycle_started_at timestamptz NOT NULL,
    claimed_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz NOT NULL,
    claim_expires_at timestamptz NOT NULL,
    prior_failure_count integer NOT NULL,
    failure_count integer NOT NULL,
    failure_code text NOT NULL,
    failure_detail_sha256 text NOT NULL,
    parent_version bigint NOT NULL,
    manual_required_at timestamptz NOT NULL,
    schema_version text NOT NULL DEFAULT 'credential-revocation-system-recovery.v1',
    received_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    PRIMARY KEY (revocation_id, claim_epoch),
    CONSTRAINT credential_revocation_system_receipts_revocation_fk
        FOREIGN KEY (revocation_id)
        REFERENCES credential_revocations (revocation_id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocation_system_receipts_counter_ck CHECK (
        claim_epoch > 0 AND heartbeat_seq >= 0 AND attempt > 0 AND
        retry_cycle_attempt_base >= 0 AND retry_cycle_attempt_base <= attempt AND
        prior_failure_count >= 0 AND failure_count = prior_failure_count + 1 AND
        parent_version > 1
    ),
    CONSTRAINT credential_revocation_system_receipts_claim_ck CHECK (
        octet_length(claimed_by) BETWEEN 1 AND 256 AND
        left(claimed_by, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        claimed_by COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        octet_length(claim_token_sha256) = 64 AND
        claim_token_sha256 COLLATE "C" !~ '[^a-f0-9]'
    ),
    CONSTRAINT credential_revocation_system_receipts_shape_ck CHECK (
        recovery_kind = 'EXHAUSTED_WITHOUT_ACK' AND
        failure_code = 'UNKNOWN' AND
        failure_detail_sha256 = '5797f0f8a568d5f215e18706d1e9e08a55101b1ba68ced7926e77a6c253359fe' AND
        (
            attempt - retry_cycle_attempt_base >= 12 OR
            retry_cycle_started_at <= manual_required_at - interval '2 hours'
        ) AND
        claim_expires_at <= manual_required_at
    ),
    CONSTRAINT credential_revocation_system_receipts_schema_ck CHECK (
        schema_version = 'credential-revocation-system-recovery.v1'
    ),
    CONSTRAINT credential_revocation_system_receipts_time_ck CHECK (
        retry_cycle_started_at > '-infinity'::timestamptz AND retry_cycle_started_at < 'infinity'::timestamptz AND
        claimed_at > '-infinity'::timestamptz AND claimed_at < 'infinity'::timestamptz AND
        last_heartbeat_at > '-infinity'::timestamptz AND last_heartbeat_at < 'infinity'::timestamptz AND
        claim_expires_at > '-infinity'::timestamptz AND claim_expires_at < 'infinity'::timestamptz AND
        last_heartbeat_at >= claimed_at AND claim_expires_at > last_heartbeat_at AND
        manual_required_at > '-infinity'::timestamptz AND manual_required_at < 'infinity'::timestamptz AND
        received_at > '-infinity'::timestamptz AND received_at < 'infinity'::timestamptz AND
        manual_required_at <= received_at
    )
);

CREATE OR REPLACE FUNCTION guard_credential_revocation_system_receipt_insert() RETURNS trigger AS $$
BEGIN
    IF pg_trigger_depth() <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential revocation system recovery receipts are database generated',
            CONSTRAINT = 'credential_revocation_system_receipts_insert_guard';
    END IF;
    NEW.received_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocation_system_receipts_insert_guard
    BEFORE INSERT ON credential_revocation_system_receipts
    FOR EACH ROW EXECUTE FUNCTION guard_credential_revocation_system_receipt_insert();

CREATE OR REPLACE FUNCTION capture_credential_revocation_system_recovery() RETURNS trigger AS $$
BEGIN
    IF OLD.status <> 'REVOKING' OR NEW.status <> 'MANUAL_REQUIRED' THEN
        RETURN NEW;
    END IF;

    IF NOT (
        OLD.claim_expires_at <= NEW.manual_required_at AND
        (
            OLD.attempt - OLD.retry_cycle_attempt_base >= 12 OR
            OLD.retry_cycle_started_at <= NEW.manual_required_at - interval '2 hours'
        ) AND
        NEW.failure_count = OLD.failure_count + 1 AND
        NEW.failure_code = 'UNKNOWN' AND
        NEW.failure_detail_sha256 = '5797f0f8a568d5f215e18706d1e9e08a55101b1ba68ced7926e77a6c253359fe'
    ) THEN
        RETURN NEW;
    END IF;

    IF NEW.version <> OLD.version + 1 OR
       NEW.claim_epoch <> OLD.claim_epoch OR
       NEW.attempt <> OLD.attempt OR
       NEW.retry_cycle_attempt_base <> OLD.retry_cycle_attempt_base OR
       NEW.retry_cycle_started_at IS DISTINCT FROM OLD.retry_cycle_started_at OR
       NEW.claimed_by IS NOT NULL OR NEW.claim_token_sha256 IS NOT NULL OR
       NEW.claimed_at IS NOT NULL OR NEW.claim_expires_at IS NOT NULL OR
       NEW.last_heartbeat_at IS NOT NULL OR NEW.manual_required_at IS NULL OR
       (
           to_jsonb(NEW) - ARRAY[
               'status', 'claimed_by', 'claim_token_sha256', 'claimed_at', 'claim_expires_at',
               'last_heartbeat_at', 'failure_count', 'failure_code', 'failure_detail_sha256',
               'manual_required_at', 'updated_at', 'version'
           ]
       ) IS DISTINCT FROM (
           to_jsonb(OLD) - ARRAY[
               'status', 'claimed_by', 'claim_token_sha256', 'claimed_at', 'claim_expires_at',
               'last_heartbeat_at', 'failure_count', 'failure_code', 'failure_detail_sha256',
               'manual_required_at', 'updated_at', 'version'
           ]
       ) THEN
        RETURN NEW;
    END IF;

    INSERT INTO credential_revocation_system_receipts (
        revocation_id, claim_epoch, recovery_kind, claimed_by, claim_token_sha256,
        heartbeat_seq, attempt, retry_cycle_attempt_base, retry_cycle_started_at,
        claimed_at, last_heartbeat_at, claim_expires_at,
        prior_failure_count, failure_count, failure_code,
        failure_detail_sha256, parent_version, manual_required_at
    ) VALUES (
        OLD.revocation_id, OLD.claim_epoch, 'EXHAUSTED_WITHOUT_ACK', OLD.claimed_by, OLD.claim_token_sha256,
        OLD.heartbeat_seq, OLD.attempt, OLD.retry_cycle_attempt_base, OLD.retry_cycle_started_at,
        OLD.claimed_at, OLD.last_heartbeat_at, OLD.claim_expires_at,
        OLD.failure_count, NEW.failure_count, NEW.failure_code,
        NEW.failure_detail_sha256, NEW.version, NEW.manual_required_at
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocations_system_recovery_receipt
    AFTER UPDATE ON credential_revocations
    FOR EACH ROW
    WHEN (OLD.status = 'REVOKING' AND NEW.status = 'MANUAL_REQUIRED')
    EXECUTE FUNCTION capture_credential_revocation_system_recovery();

CREATE OR REPLACE FUNCTION validate_credential_revocation_system_receipt_final_shape() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM credential_revocations AS parent
        WHERE parent.revocation_id = NEW.revocation_id
          AND parent.status = 'MANUAL_REQUIRED'
          AND parent.claim_epoch = NEW.claim_epoch
          AND parent.heartbeat_seq = NEW.heartbeat_seq
          AND parent.attempt = NEW.attempt
          AND parent.retry_cycle_attempt_base = NEW.retry_cycle_attempt_base
          AND parent.retry_cycle_started_at = NEW.retry_cycle_started_at
          AND parent.failure_count = NEW.failure_count
          AND parent.failure_code = NEW.failure_code
          AND parent.failure_detail_sha256 = NEW.failure_detail_sha256
          AND parent.version = NEW.parent_version
          AND parent.manual_required_at = NEW.manual_required_at
          AND parent.claimed_by IS NULL
          AND parent.claim_token_sha256 IS NULL
          AND parent.claimed_at IS NULL
          AND parent.claim_expires_at IS NULL
          AND parent.last_heartbeat_at IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM credential_revocation_receipts AS sibling
        WHERE sibling.revocation_id = NEW.revocation_id
          AND sibling.claim_epoch = NEW.claim_epoch
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'system recovery receipt does not match the committed manual-required state',
            CONSTRAINT = 'credential_revocation_system_receipts_final_shape';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER credential_revocation_system_receipts_final_shape
    AFTER INSERT ON credential_revocation_system_receipts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_credential_revocation_system_receipt_final_shape();

CREATE OR REPLACE FUNCTION reject_credential_revocation_system_receipt_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'credential revocation system recovery receipts are immutable',
        CONSTRAINT = 'credential_revocation_system_receipts_immutable_guard';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocation_system_receipts_immutable
    BEFORE UPDATE OR DELETE ON credential_revocation_system_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_credential_revocation_system_receipt_mutation();

CREATE TRIGGER credential_revocation_system_receipts_no_truncate
    BEFORE TRUNCATE ON credential_revocation_system_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION reject_credential_revocation_system_receipt_mutation();

CREATE OR REPLACE FUNCTION validate_credential_revocation_completion_receipt() RETURNS trigger AS $$
DECLARE
    runner_proof_count integer;
    system_proof_count integer;
BEGIN
    SELECT count(*)
    INTO runner_proof_count
    FROM credential_revocation_receipts AS receipt
    JOIN runner_registrations AS registration
      ON registration.runner_id = receipt.runner_id
     AND registration.tenant_id = receipt.tenant_id
     AND registration.scope_revision = receipt.scope_revision
     AND registration.enabled = true
     AND registration.runner_pool = 'WRITE'
     AND registration.credential_revocation_capable = true
    JOIN runner_scope_bindings AS binding
      ON binding.runner_id = receipt.runner_id
     AND binding.tenant_id = receipt.tenant_id
     AND binding.workspace_id = receipt.workspace_id
     AND binding.environment_id = receipt.environment_id
    WHERE receipt.revocation_id = OLD.revocation_id
      AND receipt.claim_epoch = OLD.claim_epoch
      AND receipt.tenant_id = OLD.tenant_id
      AND receipt.workspace_id = OLD.workspace_id
      AND receipt.environment_id = OLD.environment_id
      AND receipt.runner_id = OLD.claimed_by
      AND receipt.issuer = OLD.issuer
      AND receipt.issuer_revision = OLD.issuer_revision
      AND receipt.claim_token_sha256 = OLD.claim_token_sha256
      AND receipt.heartbeat_seq = OLD.heartbeat_seq
      AND (
          (
              NEW.status = 'REVOKED' AND receipt.outcome = 'REVOKED'
          ) OR (
              NEW.status IN ('REVOCATION_PENDING', 'MANUAL_REQUIRED') AND
              receipt.outcome = 'FAILED' AND
              receipt.failure_count = NEW.failure_count AND
              receipt.failure_code = NEW.failure_code AND
              receipt.failure_detail_sha256 = NEW.failure_detail_sha256
          )
      );

    SELECT count(*)
    INTO system_proof_count
    FROM credential_revocation_system_receipts AS receipt
    WHERE receipt.revocation_id = OLD.revocation_id
      AND receipt.claim_epoch = OLD.claim_epoch
      AND receipt.claimed_by = OLD.claimed_by
      AND receipt.claim_token_sha256 = OLD.claim_token_sha256
      AND receipt.heartbeat_seq = OLD.heartbeat_seq
      AND receipt.attempt = OLD.attempt
      AND receipt.retry_cycle_attempt_base = OLD.retry_cycle_attempt_base
      AND receipt.retry_cycle_started_at = OLD.retry_cycle_started_at
      AND receipt.claimed_at = OLD.claimed_at
      AND receipt.last_heartbeat_at = OLD.last_heartbeat_at
      AND receipt.claim_expires_at = OLD.claim_expires_at
      AND receipt.prior_failure_count = OLD.failure_count
      AND receipt.failure_count = NEW.failure_count
      AND receipt.failure_code = NEW.failure_code
      AND receipt.failure_detail_sha256 = NEW.failure_detail_sha256
      AND receipt.parent_version = NEW.version
      AND receipt.manual_required_at = NEW.manual_required_at
      AND NEW.status = 'MANUAL_REQUIRED';

    IF runner_proof_count + system_proof_count <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'revocation completion requires exactly one Runner or system recovery proof',
            CONSTRAINT = 'credential_revocations_completion_receipt_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER credential_revocations_completion_receipt_guard
    AFTER UPDATE ON credential_revocations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (
        OLD.status = 'REVOKING' AND
        NEW.status IN ('REVOKED', 'REVOCATION_PENDING', 'MANUAL_REQUIRED')
    )
    EXECUTE FUNCTION validate_credential_revocation_completion_receipt();

COMMIT;
