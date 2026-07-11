BEGIN;

-- COORDINATED CUTOVER PREREQUISITE: stop and drain all old write runners
-- before applying this migration. Mixed old/new write runners are unsupported:
-- old binaries do not create the durable credential anchor required by M2.
-- This migration installs the durable credential safety boundary.
-- Do not enable the production write switch; it remains outside this stage's supported execution modes.
LOCK TABLE action_queue, execution_leases IN ACCESS EXCLUSIVE MODE;

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
            MESSAGE = 'unsafe credential revocation upgrade: active write executions must be drained';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM action_queue AS finalizing
        WHERE finalizing.status = 'FINALIZING'
          AND NOT EXISTS (
              SELECT 1
              FROM runner_result_receipts AS receipt
              WHERE receipt.action_id = finalizing.action_id
                AND receipt.tenant_id = finalizing.runner_tenant_id
                AND receipt.workspace_id = finalizing.runner_workspace_id
                AND receipt.environment_id = finalizing.runner_environment_id
                AND receipt.runner_id = finalizing.runner_id
                AND receipt.lease_epoch = finalizing.lease_epoch
                AND receipt.scope_revision = finalizing.scope_revision
                AND receipt.receipt_hash = finalizing.result_hash
                AND receipt.completion_status = finalizing.completion_status
                AND receipt.schema_version = 'runner-result.v1'
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe credential revocation upgrade: FINALIZING actions require exact runner result receipts',
            CONSTRAINT = 'action_queue_finalizing_receipt_shape';
    END IF;
END;
$$;

ALTER TABLE action_queue
    ADD COLUMN credential_expected boolean NOT NULL DEFAULT false,
    ADD COLUMN credential_lease_epoch bigint,
    ADD CONSTRAINT action_queue_credential_marker_shape_ck CHECK (
        (NOT credential_expected AND credential_lease_epoch IS NULL) OR
        (
            credential_expected AND runner_pool = 'WRITE' AND production = false AND
            credential_lease_epoch IS NOT NULL AND credential_lease_epoch > 0 AND
            credential_lease_epoch = lease_epoch AND
            status <> 'QUEUED'
        )
    ),
    ADD CONSTRAINT action_queue_no_active_production_write_ck CHECK (
        runner_pool <> 'WRITE' OR production = false OR
        status NOT IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    );

ALTER TABLE execution_leases
    ADD CONSTRAINT execution_leases_no_active_production_write_ck CHECK (
        runner_pool <> 'WRITE' OR production = false OR
        status NOT IN ('LEASED', 'RUNNING', 'UNCERTAIN')
    );

CREATE TRIGGER audit_records_no_truncate
    BEFORE TRUNCATE ON audit_records
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();

CREATE TABLE credential_revocations (
    revocation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    action_id text NOT NULL,
    target_key text NOT NULL,
    production boolean NOT NULL,
    runner_id text NOT NULL,
    action_lease_epoch bigint NOT NULL,
    action_lease_token_sha256 text NOT NULL,
    issuer text NOT NULL,
    issuer_revision text NOT NULL,
    action_type text NOT NULL,
    connector_id text NOT NULL,
    scope_permission text NOT NULL,
    scope_resource text NOT NULL,
    credential_ttl_seconds integer NOT NULL,
    credential_expires_at timestamptz NOT NULL,
    child_create_permit_sha256 text NOT NULL,
    child_create_authorized_at timestamptz,
    child_create_ttl_seconds integer,
    status text NOT NULL DEFAULT 'PREPARED',
    accessor_ciphertext bytea,
    accessor_hmac bytea,
    encryption_key_id text,
    claim_epoch bigint NOT NULL DEFAULT 0,
    claimed_by text,
    claim_token_sha256 text,
    claimed_at timestamptz,
    claim_expires_at timestamptz,
    last_heartbeat_at timestamptz,
    completed_claim_epoch bigint,
    completed_claim_token_sha256 text,
    completed_claimed_by text,
    attempt integer NOT NULL DEFAULT 0,
    retry_cycle_attempt_base integer NOT NULL DEFAULT 0,
    retry_cycle_started_at timestamptz,
    failure_count integer NOT NULL DEFAULT 0,
    failure_code text,
    failure_detail_sha256 text,
    available_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    evidence_hash text,
    anchored_at timestamptz,
    activated_at timestamptz,
    revocation_requested_at timestamptz,
    manual_required_at timestamptz,
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    CONSTRAINT credential_revocations_action_epoch_uk UNIQUE (action_id, action_lease_epoch),
    CONSTRAINT credential_revocations_action_fk
        FOREIGN KEY (action_id) REFERENCES action_queue (action_id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocations_workspace_scope_fk
        FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES workspaces (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocations_environment_scope_fk
        FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocations_runner_fk
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocations_status_ck CHECK (
        status IN ('PREPARED', 'ANCHORED', 'ACTIVE', 'REVOCATION_PENDING', 'REVOKING', 'REVOKED', 'MANUAL_REQUIRED', 'NO_CREDENTIAL')
    ),
    CONSTRAINT credential_revocations_non_production_ck CHECK (production = false),
    CONSTRAINT credential_revocations_epoch_counters_ck CHECK (
        action_lease_epoch > 0 AND claim_epoch >= 0 AND attempt >= 0 AND
        retry_cycle_attempt_base >= 0 AND retry_cycle_attempt_base <= attempt AND
        failure_count >= 0 AND version > 0
    ),
    CONSTRAINT credential_revocations_identifier_ck CHECK (
        octet_length(action_id) BETWEEN 1 AND 256 AND
        left(action_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        action_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        octet_length(target_key) BETWEEN 1 AND 512 AND
        left(target_key, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        target_key COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        octet_length(runner_id) BETWEEN 1 AND 256 AND
        left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT credential_revocations_metadata_ck CHECK (
        octet_length(issuer) BETWEEN 1 AND 256 AND
        octet_length(issuer_revision) BETWEEN 1 AND 256 AND
        left(issuer_revision, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        issuer_revision COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        octet_length(action_type) BETWEEN 1 AND 256 AND
        left(action_type, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        action_type COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        octet_length(connector_id) BETWEEN 1 AND 256 AND
        octet_length(scope_permission) BETWEEN 1 AND 256 AND
        octet_length(scope_resource) BETWEEN 1 AND 2048 AND
        issuer = btrim(issuer) AND action_type = btrim(action_type) AND connector_id = btrim(connector_id) AND
        scope_permission = btrim(scope_permission) AND scope_resource = btrim(scope_resource) AND
        issuer !~ '[[:cntrl:]]' AND action_type !~ '[[:cntrl:]]' AND connector_id !~ '[[:cntrl:]]' AND
        scope_permission !~ '[[:cntrl:]]' AND scope_resource !~ '[[:cntrl:]]'
    ),
    CONSTRAINT credential_revocations_time_ck CHECK (
        credential_ttl_seconds BETWEEN 1 AND 900 AND
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
        credential_expires_at > '-infinity'::timestamptz AND credential_expires_at < 'infinity'::timestamptz AND
        credential_expires_at > created_at AND
        credential_expires_at <= created_at + interval '15 minutes' AND
        credential_expires_at <= created_at + make_interval(secs => credential_ttl_seconds) AND
        available_at > '-infinity'::timestamptz AND available_at < 'infinity'::timestamptz AND
        (retry_cycle_started_at IS NULL OR (
            retry_cycle_started_at > '-infinity'::timestamptz AND retry_cycle_started_at < 'infinity'::timestamptz
        )) AND
        (manual_required_at IS NULL OR (
            manual_required_at > '-infinity'::timestamptz AND manual_required_at < 'infinity'::timestamptz AND
            manual_required_at >= created_at AND manual_required_at <= updated_at
        )) AND
        (revoked_at IS NULL OR (
            revoked_at > '-infinity'::timestamptz AND revoked_at < 'infinity'::timestamptz AND
            revoked_at >= created_at AND revoked_at <= updated_at
        )) AND
        (manual_required_at IS NULL OR revoked_at IS NULL OR revoked_at >= manual_required_at) AND
        updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
        updated_at >= created_at
    ),
    CONSTRAINT credential_revocations_hashes_ck CHECK (
        octet_length(action_lease_token_sha256) = 64 AND action_lease_token_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(child_create_permit_sha256) = 64 AND child_create_permit_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        (claim_token_sha256 IS NULL OR (
            octet_length(claim_token_sha256) = 64 AND claim_token_sha256 COLLATE "C" !~ '[^a-f0-9]'
        )) AND
        (completed_claim_token_sha256 IS NULL OR (
            octet_length(completed_claim_token_sha256) = 64 AND completed_claim_token_sha256 COLLATE "C" !~ '[^a-f0-9]'
        )) AND
        (failure_detail_sha256 IS NULL OR (
            octet_length(failure_detail_sha256) = 64 AND failure_detail_sha256 COLLATE "C" !~ '[^a-f0-9]'
        )) AND
        (evidence_hash IS NULL OR (
            octet_length(evidence_hash) = 64 AND evidence_hash COLLATE "C" !~ '[^a-f0-9]'
        ))
    ),
    CONSTRAINT credential_revocations_child_create_ck CHECK (
        (
            child_create_authorized_at IS NULL AND child_create_ttl_seconds IS NULL
        ) OR (
            child_create_authorized_at IS NOT NULL AND
            child_create_ttl_seconds BETWEEN 1 AND 900 AND
            child_create_authorized_at >= created_at AND
            child_create_authorized_at + child_create_ttl_seconds * interval '1 second' + interval '15 seconds'
                <= credential_expires_at
        )
    ),
    CONSTRAINT credential_revocations_protected_ref_ck CHECK (
        (status = 'PREPARED' AND accessor_ciphertext IS NULL AND accessor_hmac IS NULL AND encryption_key_id IS NULL) OR
        (status = 'NO_CREDENTIAL' AND accessor_ciphertext IS NULL AND accessor_hmac IS NULL AND encryption_key_id IS NULL) OR
        (
            status IN ('ANCHORED', 'ACTIVE', 'REVOCATION_PENDING', 'REVOKING', 'MANUAL_REQUIRED') AND
            accessor_ciphertext IS NOT NULL AND accessor_hmac IS NOT NULL AND encryption_key_id IS NOT NULL AND
            octet_length(accessor_ciphertext) BETWEEN 29 AND 4124 AND octet_length(accessor_hmac) = 32 AND
            octet_length(encryption_key_id) BETWEEN 1 AND 128 AND
            left(encryption_key_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
            encryption_key_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        ) OR
        (status = 'REVOKED' AND accessor_ciphertext IS NULL AND accessor_hmac IS NOT NULL AND encryption_key_id IS NULL)
    ),
    CONSTRAINT credential_revocations_claim_shape_ck CHECK (
        (
            status = 'REVOKING' AND claimed_by IS NOT NULL AND claim_token_sha256 IS NOT NULL AND
            claimed_at IS NOT NULL AND claim_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL AND
            claim_epoch > 0 AND attempt > 0 AND claim_expires_at > last_heartbeat_at AND
            last_heartbeat_at >= claimed_at AND octet_length(claimed_by) BETWEEN 1 AND 256
        ) OR
        (
            status <> 'REVOKING' AND claimed_by IS NULL AND claim_token_sha256 IS NULL AND
            claimed_at IS NULL AND claim_expires_at IS NULL AND last_heartbeat_at IS NULL
        )
    ),
    CONSTRAINT credential_revocations_completion_fence_ck CHECK (
        (
            completed_claim_epoch IS NULL AND completed_claim_token_sha256 IS NULL AND completed_claimed_by IS NULL
        ) OR
        (
            status = 'REVOKED' AND completed_claim_epoch IS NOT NULL AND completed_claim_epoch > 0 AND
            completed_claim_epoch <= claim_epoch AND completed_claim_token_sha256 IS NOT NULL AND
            completed_claimed_by IS NOT NULL AND octet_length(completed_claimed_by) BETWEEN 1 AND 256
        )
    ),
    CONSTRAINT credential_revocations_revoked_proof_ck CHECK (
        (
            status <> 'REVOKED' AND completed_claim_epoch IS NULL AND
            completed_claim_token_sha256 IS NULL AND completed_claimed_by IS NULL
        ) OR (
            status = 'REVOKED' AND (
                (
                    evidence_hash IS NULL AND completed_claim_epoch IS NOT NULL AND
                    completed_claim_token_sha256 IS NOT NULL AND completed_claimed_by IS NOT NULL
                ) OR (
                    evidence_hash IS NOT NULL AND completed_claim_epoch IS NULL AND
                    completed_claim_token_sha256 IS NULL AND completed_claimed_by IS NULL
                )
            )
        )
    ),
    CONSTRAINT credential_revocations_failure_ck CHECK (
        (
            failure_count = 0 AND failure_code IS NULL AND failure_detail_sha256 IS NULL
        ) OR
        (
            failure_count > 0 AND
            failure_code IN ('ISSUER_UNAVAILABLE', 'RATE_LIMITED', 'TIMEOUT', 'AUTHENTICATION_FAILED', 'PERMISSION_DENIED', 'REFERENCE_NOT_FOUND', 'INVALID_REFERENCE', 'UNKNOWN') AND
            failure_detail_sha256 IS NOT NULL
        )
    ),
    CONSTRAINT credential_revocations_status_time_ck CHECK (
        (
            status = 'PREPARED' AND anchored_at IS NULL AND activated_at IS NULL AND
            revocation_requested_at IS NULL AND retry_cycle_started_at IS NULL AND
            retry_cycle_attempt_base = 0 AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status = 'NO_CREDENTIAL' AND anchored_at IS NULL AND activated_at IS NULL AND
            revocation_requested_at IS NULL AND retry_cycle_started_at IS NULL AND
            retry_cycle_attempt_base = 0 AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status = 'ANCHORED' AND anchored_at IS NOT NULL AND activated_at IS NULL AND
            revocation_requested_at IS NULL AND retry_cycle_started_at IS NULL AND
            retry_cycle_attempt_base = 0 AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status = 'ACTIVE' AND anchored_at IS NOT NULL AND activated_at IS NOT NULL AND
            revocation_requested_at IS NULL AND retry_cycle_started_at IS NULL AND
            retry_cycle_attempt_base = 0 AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status IN ('REVOCATION_PENDING', 'REVOKING') AND anchored_at IS NOT NULL AND
            revocation_requested_at IS NOT NULL AND retry_cycle_started_at IS NOT NULL AND revoked_at IS NULL
        ) OR (
            status = 'MANUAL_REQUIRED' AND anchored_at IS NOT NULL AND revocation_requested_at IS NOT NULL AND
            retry_cycle_started_at IS NOT NULL AND manual_required_at IS NOT NULL AND failure_count > 0 AND revoked_at IS NULL
        ) OR (
            status = 'REVOKED' AND anchored_at IS NOT NULL AND revocation_requested_at IS NOT NULL AND
            retry_cycle_started_at IS NOT NULL AND revoked_at IS NOT NULL
        )
    ),
    CONSTRAINT credential_revocations_evidence_ck CHECK (
        evidence_hash IS NULL OR status IN ('MANUAL_REQUIRED', 'REVOKED')
    )
);

CREATE INDEX credential_revocations_claim_idx
    ON credential_revocations (available_at, created_at, revocation_id)
    WHERE status = 'REVOCATION_PENDING';

CREATE INDEX credential_revocations_expired_claim_idx
    ON credential_revocations (claim_expires_at, revocation_id)
    WHERE status = 'REVOKING';

CREATE INDEX credential_revocations_prepared_recovery_idx
    ON credential_revocations (credential_expires_at, revocation_id)
    WHERE status = 'PREPARED';

CREATE INDEX credential_revocations_managed_recovery_idx
    ON credential_revocations ((COALESCE(activated_at, anchored_at)), revocation_id)
    WHERE status IN ('ANCHORED', 'ACTIVE');

CREATE INDEX credential_revocations_exhausted_recovery_idx
    ON credential_revocations (retry_cycle_started_at, revocation_id)
    INCLUDE (attempt, retry_cycle_attempt_base, claim_expires_at)
    WHERE status IN ('REVOCATION_PENDING', 'REVOKING');

CREATE INDEX credential_revocations_management_idx
    ON credential_revocations (workspace_id, environment_id, status, created_at DESC, revocation_id DESC);

-- Signed submission columns are routed through an UPDATE OF trigger so routine
-- heartbeat updates never detoast and compare the bounded 256 KiB envelope.
CREATE OR REPLACE FUNCTION reject_action_queue_submission_identity_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.action_id IS DISTINCT FROM NEW.action_id
       OR OLD.envelope IS DISTINCT FROM NEW.envelope
       OR OLD.submission_hash IS DISTINCT FROM NEW.submission_hash
       OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR OLD.request_hash IS DISTINCT FROM NEW.request_hash
       OR OLD.request_hash_version IS DISTINCT FROM NEW.request_hash_version
       OR OLD.plan_hash IS DISTINCT FROM NEW.plan_hash
       OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR OLD.environment_id IS DISTINCT FROM NEW.environment_id
       OR OLD.target_key IS DISTINCT FROM NEW.target_key
       OR OLD.environment_revision IS DISTINCT FROM NEW.environment_revision
       OR OLD.authorization_expires_at IS DISTINCT FROM NEW.authorization_expires_at
       OR OLD.runner_pool IS DISTINCT FROM NEW.runner_pool
       OR OLD.production IS DISTINCT FROM NEW.production
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'action submission identity is immutable',
            CONSTRAINT = 'action_queue_submission_identity_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER action_queue_submission_identity_guard
    BEFORE UPDATE OF
        action_id, envelope, submission_hash, idempotency_key, request_hash,
        request_hash_version, plan_hash, workspace_id, environment_id, target_key,
        environment_revision, authorization_expires_at, runner_pool, production, created_at
    ON action_queue
    FOR EACH ROW EXECUTE FUNCTION reject_action_queue_submission_identity_mutation();

CREATE OR REPLACE FUNCTION reject_action_queue_terminal_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD IS DISTINCT FROM NEW THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'terminal action records are immutable',
            CONSTRAINT = 'action_queue_terminal_immutable_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- The WHEN clause keeps the 256 KiB envelope out of the heartbeat hot path:
-- the whole-row comparison is only evaluated after PostgreSQL has selected a
-- terminal OLD row for this dedicated trigger. PostgreSQL orders triggers of
-- the same kind by name; the 00 prefix also makes terminal immutability run
-- before the narrower cleanup and submission guards.
CREATE TRIGGER action_queue_00_terminal_immutable_guard
    BEFORE UPDATE ON action_queue
    FOR EACH ROW
    WHEN (OLD.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED'))
    EXECUTE FUNCTION reject_action_queue_terminal_mutation();

CREATE OR REPLACE FUNCTION reject_action_queue_removal() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'action queue history cannot be deleted or truncated',
        CONSTRAINT = 'action_queue_history_immutable_guard';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER action_queue_no_delete
    BEFORE DELETE ON action_queue
    FOR EACH ROW EXECUTE FUNCTION reject_action_queue_removal();

CREATE TRIGGER action_queue_no_truncate
    BEFORE TRUNCATE ON action_queue
    FOR EACH STATEMENT EXECUTE FUNCTION reject_action_queue_removal();

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

    -- Keep the receipt lookup structurally unreachable from heartbeat and
    -- other same-state hot paths; do not rely on SQL boolean short-circuiting.
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

CREATE TRIGGER action_queue_credential_cleanup_gate
    BEFORE INSERT OR UPDATE ON action_queue
    FOR EACH ROW EXECUTE FUNCTION enforce_action_queue_credential_cleanup();

-- Complete intentionally writes FINALIZING before inserting its immutable
-- receipt in the same transaction. The reverse proof must therefore run at
-- COMMIT, while terminal transitions can require the already-committed receipt.
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

CREATE CONSTRAINT TRIGGER action_queue_finalizing_receipt_shape
    AFTER INSERT OR UPDATE ON action_queue
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (NEW.status = 'FINALIZING')
    EXECUTE FUNCTION validate_action_queue_finalizing_receipt();

CREATE OR REPLACE FUNCTION validate_credential_revocation_action_marker() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM action_queue AS action
        WHERE action.action_id = NEW.action_id
          AND action.runner_tenant_id = NEW.tenant_id
          AND action.runner_workspace_id = NEW.workspace_id
          AND action.runner_environment_id = NEW.environment_id
          AND action.target_key = NEW.target_key
          AND action.production = NEW.production
          AND action.runner_id = NEW.runner_id
          AND action.lease_epoch = NEW.action_lease_epoch
          AND action.credential_expected = true
          AND action.credential_lease_epoch = NEW.action_lease_epoch
          AND action.envelope ->> 'action_type' = NEW.action_type
          AND action.envelope #>> '{credential_scope,connector_id}' = NEW.connector_id
          AND action.envelope #>> '{credential_scope,permission}' = NEW.scope_permission
          AND action.envelope #>> '{credential_scope,resource}' = NEW.scope_resource
          AND action.envelope #>> '{credential_scope,ttl_seconds}' = NEW.credential_ttl_seconds::text
          AND NEW.credential_expires_at <= action.authorization_expires_at
          AND action.status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED')
          AND CASE
              WHEN action.status IN ('LEASED', 'RUNNING') THEN action.lease_token_sha256
              ELSE action.completed_lease_token_sha256
          END = NEW.action_lease_token_sha256
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation requires an exact action marker',
            CONSTRAINT = 'credential_revocations_action_marker_shape';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER credential_revocations_action_marker_shape
    AFTER INSERT ON credential_revocations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_credential_revocation_action_marker();

CREATE OR REPLACE FUNCTION enforce_credential_revocation_transition() RETURNS trigger AS $$
DECLARE
    transition_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.created_at > clock_timestamp() THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocation creation time cannot be in the future',
                CONSTRAINT = 'credential_revocations_created_at_guard';
        END IF;
        IF NEW.status <> 'PREPARED' OR NEW.version <> 1
           OR NEW.child_create_authorized_at IS NOT NULL
           OR NEW.child_create_ttl_seconds IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocations must begin in PREPARED at version 1';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status IN ('REVOKED', 'NO_CREDENTIAL') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'terminal credential revocations are immutable';
    END IF;

    IF NEW.version <> OLD.version + 1
       OR NEW.updated_at < OLD.updated_at
       OR NEW.claim_epoch < OLD.claim_epoch
       OR NEW.attempt < OLD.attempt
       OR NEW.retry_cycle_attempt_base < OLD.retry_cycle_attempt_base
       OR NEW.failure_count < OLD.failure_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential revocation counters and time must advance monotonically';
    END IF;

    transition_at := clock_timestamp();
    NEW.updated_at := GREATEST(NEW.updated_at, transition_at);

    IF (
        OLD.retry_cycle_attempt_base IS DISTINCT FROM NEW.retry_cycle_attempt_base OR
        OLD.retry_cycle_started_at IS DISTINCT FROM NEW.retry_cycle_started_at
    ) AND NOT (
        OLD.status IN ('ANCHORED', 'ACTIVE', 'MANUAL_REQUIRED') AND
        NEW.status = 'REVOCATION_PENDING' AND
        NEW.retry_cycle_attempt_base = OLD.attempt AND
        NEW.retry_cycle_started_at IS NOT NULL AND
        NEW.retry_cycle_started_at >= OLD.updated_at AND
        NEW.retry_cycle_started_at <= transition_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential revocation retry cycle may only reset after authorization loss or manual repair';
    END IF;

    IF OLD.child_create_authorized_at IS NOT NULL AND (
        OLD.child_create_authorized_at IS DISTINCT FROM NEW.child_create_authorized_at OR
        OLD.child_create_ttl_seconds IS DISTINCT FROM NEW.child_create_ttl_seconds
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential child creation authorization is immutable';
    END IF;

    IF OLD.child_create_authorized_at IS NULL AND NEW.child_create_authorized_at IS NOT NULL AND (
        OLD.status <> 'PREPARED' OR NEW.status <> 'PREPARED' OR
        NEW.child_create_ttl_seconds IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential child creation may only be authorized once from PREPARED';
    END IF;

    IF OLD.status = 'REVOKING' AND NEW.status = 'REVOCATION_PENDING' AND (
        OLD.attempt - OLD.retry_cycle_attempt_base >= 12 OR
        OLD.retry_cycle_started_at <= transition_at - interval '2 hours'
    ) THEN
        NEW.status := 'MANUAL_REQUIRED';
        NEW.available_at := OLD.available_at;
        NEW.manual_required_at := transition_at;
        NEW.updated_at := GREATEST(NEW.updated_at, transition_at);
    END IF;

    IF OLD.status IN ('REVOCATION_PENDING', 'REVOKING') AND NEW.status = 'MANUAL_REQUIRED' THEN
        NEW.manual_required_at := transition_at;
    ELSIF OLD.manual_required_at IS DISTINCT FROM NEW.manual_required_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential manual-required lifecycle evidence is database-controlled';
    END IF;

    IF OLD.status IN ('REVOKING', 'MANUAL_REQUIRED') AND NEW.status = 'REVOKED' THEN
        NEW.revoked_at := transition_at;
    ELSIF OLD.revoked_at IS DISTINCT FROM NEW.revoked_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential revoked lifecycle evidence is database-controlled';
    END IF;

    IF OLD.status = NEW.status THEN
        IF (
            NEW.claim_epoch IS DISTINCT FROM OLD.claim_epoch OR
            NEW.attempt IS DISTINCT FROM OLD.attempt
        ) AND NOT (
            OLD.status = 'REVOKING' AND
            OLD.claim_expires_at <= transition_at AND
            OLD.attempt - OLD.retry_cycle_attempt_base < 12 AND
            OLD.retry_cycle_started_at > transition_at - interval '2 hours' AND
            NEW.claim_epoch = OLD.claim_epoch + 1 AND
            NEW.attempt = OLD.attempt + 1
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'credential revocation may only reclaim an expired non-exhausted claim';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.status = 'PREPARED' AND NEW.status = 'ANCHORED' AND OLD.child_create_authorized_at IS NOT NULL) OR
        (OLD.status = 'PREPARED' AND NEW.status = 'NO_CREDENTIAL' AND (
            OLD.child_create_authorized_at IS NULL OR
            OLD.credential_expires_at <= transition_at - interval '1 minute'
        )) OR
        (OLD.status = 'ANCHORED' AND NEW.status IN ('ACTIVE', 'REVOCATION_PENDING')) OR
        (OLD.status = 'ACTIVE' AND NEW.status = 'REVOCATION_PENDING') OR
        (OLD.status = 'REVOCATION_PENDING' AND NEW.status = 'REVOKING' AND
            OLD.attempt - OLD.retry_cycle_attempt_base < 12 AND
            OLD.retry_cycle_started_at > transition_at - interval '2 hours' AND
            NEW.claim_epoch = OLD.claim_epoch + 1 AND NEW.attempt = OLD.attempt + 1) OR
        (OLD.status = 'REVOCATION_PENDING' AND NEW.status = 'MANUAL_REQUIRED' AND (
            OLD.attempt - OLD.retry_cycle_attempt_base >= 12 OR
            OLD.retry_cycle_started_at <= transition_at - interval '2 hours'
        )) OR
        (OLD.status = 'REVOKING' AND NEW.status = 'REVOCATION_PENDING' AND
            OLD.attempt - OLD.retry_cycle_attempt_base < 12 AND
            OLD.retry_cycle_started_at > transition_at - interval '2 hours') OR
        (OLD.status = 'REVOKING' AND NEW.status IN ('MANUAL_REQUIRED', 'REVOKED')) OR
        (OLD.status = 'MANUAL_REQUIRED' AND NEW.status IN ('REVOCATION_PENDING', 'REVOKED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'invalid credential revocation lifecycle transition';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocations_state_machine
    BEFORE INSERT OR UPDATE ON credential_revocations
    FOR EACH ROW EXECUTE FUNCTION enforce_credential_revocation_transition();

CREATE OR REPLACE FUNCTION reject_credential_revocation_reparenting() RETURNS trigger AS $$
BEGIN
    IF OLD.revocation_id IS DISTINCT FROM NEW.revocation_id
       OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR OLD.environment_id IS DISTINCT FROM NEW.environment_id
       OR OLD.action_id IS DISTINCT FROM NEW.action_id
       OR OLD.target_key IS DISTINCT FROM NEW.target_key
       OR OLD.production IS DISTINCT FROM NEW.production
       OR OLD.runner_id IS DISTINCT FROM NEW.runner_id
       OR OLD.action_lease_epoch IS DISTINCT FROM NEW.action_lease_epoch
       OR OLD.action_lease_token_sha256 IS DISTINCT FROM NEW.action_lease_token_sha256
       OR OLD.child_create_permit_sha256 IS DISTINCT FROM NEW.child_create_permit_sha256
       OR OLD.issuer IS DISTINCT FROM NEW.issuer
       OR OLD.issuer_revision IS DISTINCT FROM NEW.issuer_revision
       OR OLD.action_type IS DISTINCT FROM NEW.action_type
       OR OLD.connector_id IS DISTINCT FROM NEW.connector_id
       OR OLD.scope_permission IS DISTINCT FROM NEW.scope_permission
       OR OLD.scope_resource IS DISTINCT FROM NEW.scope_resource
       OR OLD.credential_ttl_seconds IS DISTINCT FROM NEW.credential_ttl_seconds
       OR OLD.credential_expires_at IS DISTINCT FROM NEW.credential_expires_at
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential revocation ownership and action fence are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocations_no_reparenting
    BEFORE UPDATE ON credential_revocations
    FOR EACH ROW EXECUTE FUNCTION reject_credential_revocation_reparenting();

CREATE OR REPLACE FUNCTION reject_credential_revocation_removal() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'credential revocations are durable lifecycle records';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocations_no_delete
    BEFORE DELETE ON credential_revocations
    FOR EACH ROW EXECUTE FUNCTION reject_credential_revocation_removal();

CREATE TRIGGER credential_revocations_no_truncate
    BEFORE TRUNCATE ON credential_revocations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_credential_revocation_removal();

CREATE TABLE credential_revocation_confirmations (
    revocation_id uuid NOT NULL,
    subject text NOT NULL,
    evidence_hash text NOT NULL,
    platform_admin boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    PRIMARY KEY (revocation_id, subject),
    CONSTRAINT credential_revocation_confirmations_revocation_fk
        FOREIGN KEY (revocation_id) REFERENCES credential_revocations (revocation_id) ON DELETE RESTRICT,
    CONSTRAINT credential_revocation_confirmations_subject_ck CHECK (
        octet_length(subject) BETWEEN 6 AND 512 AND subject LIKE 'oidc:%' AND
        subject = btrim(subject) AND subject !~ '[[:cntrl:]]'
    ),
    CONSTRAINT credential_revocation_confirmations_evidence_ck CHECK (
        octet_length(evidence_hash) = 64 AND evidence_hash COLLATE "C" !~ '[^a-f0-9]'
    )
);

CREATE OR REPLACE FUNCTION validate_credential_revocation_confirmation() RETURNS trigger AS $$
DECLARE
    parent_status text;
    parent_evidence text;
    existing_count integer;
    existing_admin boolean;
BEGIN
    SELECT status, evidence_hash
    INTO parent_status, parent_evidence
    FROM credential_revocations
    WHERE revocation_id = NEW.revocation_id
    FOR UPDATE;

    IF parent_status IS DISTINCT FROM 'MANUAL_REQUIRED'
       OR parent_evidence IS DISTINCT FROM NEW.evidence_hash THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation confirmation must match locked manual evidence';
    END IF;

    SELECT count(*), COALESCE(bool_or(platform_admin), false)
    INTO existing_count, existing_admin
    FROM credential_revocation_confirmations
    WHERE revocation_id = NEW.revocation_id;

    IF existing_count >= 2 OR (existing_count = 1 AND NOT (existing_admin OR NEW.platform_admin)) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation requires two confirmations with a platform administrator';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocation_confirmations_validate
    BEFORE INSERT ON credential_revocation_confirmations
    FOR EACH ROW EXECUTE FUNCTION validate_credential_revocation_confirmation();

CREATE OR REPLACE FUNCTION reject_credential_confirmation_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'credential revocation confirmations are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_revocation_confirmations_no_mutation
    BEFORE UPDATE OR DELETE ON credential_revocation_confirmations
    FOR EACH ROW EXECUTE FUNCTION reject_credential_confirmation_mutation();

CREATE TRIGGER credential_revocation_confirmations_no_truncate
    BEFORE TRUNCATE ON credential_revocation_confirmations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_credential_confirmation_mutation();

CREATE OR REPLACE FUNCTION validate_credential_confirmation_shape() RETURNS trigger AS $$
DECLARE
    confirmation_count integer;
    has_platform_admin boolean;
    evidence_matches boolean;
BEGIN
    SELECT count(*), COALESCE(bool_or(platform_admin), false),
           COALESCE(bool_and(evidence_hash = NEW.evidence_hash), true)
    INTO confirmation_count, has_platform_admin, evidence_matches
    FROM credential_revocation_confirmations
    WHERE revocation_id = NEW.revocation_id;

    IF NEW.evidence_hash IS NULL THEN
        IF confirmation_count <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'credential revocation confirmations require evidence';
        END IF;
    ELSIF NEW.status = 'MANUAL_REQUIRED' THEN
        IF confirmation_count <> 1 OR NOT evidence_matches THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'manual credential revocation evidence requires exactly one matching confirmation';
        END IF;
    ELSIF NEW.status = 'REVOKED' THEN
        IF confirmation_count <> 2 OR NOT has_platform_admin OR NOT evidence_matches THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'externally confirmed revocation requires two matching confirmations including a platform administrator';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation evidence is invalid for the lifecycle state';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER credential_revocations_confirmation_shape
    AFTER INSERT OR UPDATE OF status, evidence_hash ON credential_revocations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_credential_confirmation_shape();

CREATE OR REPLACE FUNCTION validate_credential_confirmation_parent_shape() RETURNS trigger AS $$
DECLARE
    parent_status text;
    parent_evidence text;
    confirmation_count integer;
    has_platform_admin boolean;
    evidence_matches boolean;
BEGIN
    SELECT status, evidence_hash
    INTO parent_status, parent_evidence
    FROM credential_revocations
    WHERE revocation_id = NEW.revocation_id;

    SELECT count(*), COALESCE(bool_or(platform_admin), false),
           COALESCE(bool_and(evidence_hash = parent_evidence), true)
    INTO confirmation_count, has_platform_admin, evidence_matches
    FROM credential_revocation_confirmations
    WHERE revocation_id = NEW.revocation_id;

    IF confirmation_count = 1 THEN
        IF parent_status IS DISTINCT FROM 'MANUAL_REQUIRED'
           OR parent_evidence IS DISTINCT FROM NEW.evidence_hash
           OR NOT evidence_matches THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'first credential revocation confirmation must retain matching manual state';
        END IF;
    ELSIF confirmation_count = 2 THEN
        IF parent_status IS DISTINCT FROM 'REVOKED'
           OR parent_evidence IS DISTINCT FROM NEW.evidence_hash
           OR NOT has_platform_admin OR NOT evidence_matches THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'second credential revocation confirmation must atomically complete matching revoked state';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'credential revocation confirmation count is invalid';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER credential_revocation_confirmations_parent_shape
    AFTER INSERT ON credential_revocation_confirmations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_credential_confirmation_parent_shape();

COMMIT;
