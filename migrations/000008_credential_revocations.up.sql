BEGIN;

-- COORDINATED CUTOVER PREREQUISITE: stop and drain all old write runners
-- before applying this migration. Mixed old/new write runners are unsupported:
-- old binaries do not create the durable credential anchor required by M2.
-- This migration only installs persistence. Do not enable the production write switch
-- until the Broker/Service/Revoker integration and drills are complete.
LOCK TABLE action_queue IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM action_queue
        WHERE runner_pool = 'WRITE' AND status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe credential revocation upgrade: write action queue must be drained';
    END IF;
END;
$$;

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
    connector_id text NOT NULL,
    scope_permission text NOT NULL,
    scope_resource text NOT NULL,
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
    CONSTRAINT credential_revocations_epoch_counters_ck CHECK (
        action_lease_epoch > 0 AND claim_epoch >= 0 AND attempt >= 0 AND failure_count >= 0 AND version > 0
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
        octet_length(connector_id) BETWEEN 1 AND 256 AND
        octet_length(scope_permission) BETWEEN 1 AND 256 AND
        octet_length(scope_resource) BETWEEN 1 AND 2048 AND
        issuer = btrim(issuer) AND connector_id = btrim(connector_id) AND
        scope_permission = btrim(scope_permission) AND scope_resource = btrim(scope_resource) AND
        issuer !~ '[[:cntrl:]]' AND connector_id !~ '[[:cntrl:]]' AND
        scope_permission !~ '[[:cntrl:]]' AND scope_resource !~ '[[:cntrl:]]'
    ),
    CONSTRAINT credential_revocations_time_ck CHECK (
        credential_expires_at > '-infinity'::timestamptz AND credential_expires_at < 'infinity'::timestamptz AND
        credential_expires_at > created_at AND
        credential_expires_at <= created_at + interval '15 minutes' AND
        available_at > '-infinity'::timestamptz AND available_at < 'infinity'::timestamptz AND
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
            revocation_requested_at IS NULL AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status = 'NO_CREDENTIAL' AND anchored_at IS NULL AND activated_at IS NULL AND
            revocation_requested_at IS NULL AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status = 'ANCHORED' AND anchored_at IS NOT NULL AND activated_at IS NULL AND
            revocation_requested_at IS NULL AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status = 'ACTIVE' AND anchored_at IS NOT NULL AND activated_at IS NOT NULL AND
            revocation_requested_at IS NULL AND manual_required_at IS NULL AND revoked_at IS NULL
        ) OR (
            status IN ('REVOCATION_PENDING', 'REVOKING') AND anchored_at IS NOT NULL AND
            revocation_requested_at IS NOT NULL AND revoked_at IS NULL
        ) OR (
            status = 'MANUAL_REQUIRED' AND anchored_at IS NOT NULL AND revocation_requested_at IS NOT NULL AND
            manual_required_at IS NOT NULL AND revoked_at IS NULL
        ) OR (
            status = 'REVOKED' AND anchored_at IS NOT NULL AND revocation_requested_at IS NOT NULL AND revoked_at IS NOT NULL
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

CREATE OR REPLACE FUNCTION enforce_credential_revocation_transition() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
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
       OR NEW.failure_count < OLD.failure_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'credential revocation counters and time must advance monotonically';
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

    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.status = 'PREPARED' AND NEW.status = 'ANCHORED' AND OLD.child_create_authorized_at IS NOT NULL) OR
        (OLD.status = 'PREPARED' AND NEW.status = 'NO_CREDENTIAL' AND (
            OLD.child_create_authorized_at IS NULL OR
            OLD.credential_expires_at <= clock_timestamp() - interval '1 minute'
        )) OR
        (OLD.status = 'ANCHORED' AND NEW.status IN ('ACTIVE', 'REVOCATION_PENDING')) OR
        (OLD.status = 'ACTIVE' AND NEW.status = 'REVOCATION_PENDING') OR
        (OLD.status = 'REVOCATION_PENDING' AND NEW.status = 'REVOKING') OR
        (OLD.status = 'REVOKING' AND NEW.status IN ('REVOCATION_PENDING', 'MANUAL_REQUIRED', 'REVOKED')) OR
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
       OR OLD.connector_id IS DISTINCT FROM NEW.connector_id
       OR OLD.scope_permission IS DISTINCT FROM NEW.scope_permission
       OR OLD.scope_resource IS DISTINCT FROM NEW.scope_resource
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
