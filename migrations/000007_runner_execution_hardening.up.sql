BEGIN;

-- COORDINATED CUTOVER PREREQUISITE: stop all old Runner binaries and drain the
-- action queue before applying this migration. Mixed old/new Runner versions
-- are intentionally unsupported because removing reusable bearer-token
-- material is a security boundary, not a rolling-compatible schema change.
-- The old token columns remain as an empty compatibility shell; they are not
-- dropped in this migration.
LOCK TABLE action_queue IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM action_queue WHERE status IN ('LEASED', 'RUNNING')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe runner hardening upgrade: active action queue must be drained';
    END IF;
END;
$$;

-- Expand the legacy lease table with irreversible token digests before the Go
-- repository switches reads and writes.
ALTER TABLE execution_leases
    ADD COLUMN lease_token_sha256 text,
    ADD COLUMN completed_lease_token_sha256 text;

UPDATE execution_leases
SET lease_token_sha256 = CASE
        WHEN lease_token IS NULL THEN NULL
        ELSE encode(sha256(convert_to(lease_token, 'UTF8')), 'hex')
    END,
    completed_lease_token_sha256 = CASE
        WHEN completed_lease_token IS NULL THEN NULL
        ELSE encode(sha256(convert_to(completed_lease_token, 'UTF8')), 'hex')
    END;

ALTER TABLE execution_leases
    DROP CONSTRAINT execution_leases_active_shape_ck,
    DROP CONSTRAINT execution_leases_completion_shape_ck;

UPDATE execution_leases
SET lease_token = NULL, completed_lease_token = NULL;

ALTER TABLE execution_leases
    ADD CONSTRAINT execution_leases_plaintext_token_empty_ck
        CHECK (lease_token IS NULL AND completed_lease_token IS NULL),
    ADD CONSTRAINT execution_leases_token_hashes_ck CHECK (
        (lease_token_sha256 IS NULL OR (
            octet_length(lease_token_sha256) = 64 AND
            lease_token_sha256 COLLATE "C" !~ '[^a-f0-9]'
        )) AND
        (completed_lease_token_sha256 IS NULL OR (
            octet_length(completed_lease_token_sha256) = 64 AND
            completed_lease_token_sha256 COLLATE "C" !~ '[^a-f0-9]'
        ))
    ),
    ADD CONSTRAINT execution_leases_active_hash_shape_ck CHECK (
        (
            status IN ('LEASED', 'RUNNING') AND runner_id IS NOT NULL AND
            lease_token_sha256 IS NOT NULL AND lease_epoch > 0 AND
            lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL AND
            lease_expires_at > last_heartbeat_at
        ) OR (
            status NOT IN ('LEASED', 'RUNNING') AND
            lease_token_sha256 IS NULL AND lease_expires_at IS NULL
        )
    ),
    ADD CONSTRAINT execution_leases_completion_hash_shape_ck CHECK (
        (
            completed_lease_token_sha256 IS NULL AND completed_lease_epoch IS NULL AND
            result_hash IS NULL AND (
                (reconciliation_id IS NULL AND status NOT IN ('SUCCEEDED', 'FAILED')) OR
                (reconciliation_id IS NOT NULL AND status IN ('SUCCEEDED', 'FAILED'))
            )
        ) OR (
            completed_lease_token_sha256 IS NOT NULL AND completed_lease_epoch IS NOT NULL AND
            completed_lease_epoch > 0 AND completed_lease_epoch = lease_epoch AND
            runner_id IS NOT NULL AND result_hash IS NOT NULL AND
            octet_length(result_hash) = 64 AND result_hash COLLATE "C" !~ '[^a-f0-9]' AND
            status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')
        )
    );

-- Persist request idempotency, exact runner scope revision, sequenced
-- heartbeats, cancellation intent, and durable two-phase completion state.
ALTER TABLE action_queue
    ADD COLUMN idempotency_key text,
    ADD COLUMN request_hash text,
    ADD COLUMN request_hash_version text,
    ADD COLUMN authorization_expires_at timestamptz,
    ADD COLUMN runner_tenant_id uuid,
    ADD COLUMN runner_workspace_id uuid,
    ADD COLUMN runner_environment_id uuid,
    ADD COLUMN scope_revision bigint,
    ADD COLUMN heartbeat_seq bigint NOT NULL DEFAULT 0,
    ADD COLUMN cancel_requested_at timestamptz,
    ADD COLUMN cancel_reason_hash text,
    ADD COLUMN completion_status text;

UPDATE action_queue
SET idempotency_key = envelope ->> 'idempotency_key',
    request_hash = submission_hash,
    request_hash_version = 'legacy-submission.v1',
    authorization_expires_at = CASE
        WHEN pg_input_is_valid(envelope ->> 'expires_at', 'timestamp with time zone')
        THEN (envelope ->> 'expires_at')::timestamptz
        ELSE NULL
    END,
    completion_status = CASE
        WHEN status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN') THEN status
        ELSE NULL
    END;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM action_queue
        WHERE idempotency_key IS NULL OR idempotency_key = '' OR request_hash IS NULL OR authorization_expires_at IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'action queue contains rows without recoverable idempotency metadata';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM action_queue
        GROUP BY workspace_id, idempotency_key
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'action queue contains duplicate workspace idempotency keys';
    END IF;
END;
$$;

ALTER TABLE action_queue
    ALTER COLUMN idempotency_key SET NOT NULL,
    ALTER COLUMN request_hash SET NOT NULL,
    ALTER COLUMN request_hash_version SET NOT NULL,
    ALTER COLUMN authorization_expires_at SET NOT NULL,
    DROP CONSTRAINT action_queue_status_ck,
    DROP CONSTRAINT action_queue_active_lease_shape_ck,
    DROP CONSTRAINT action_queue_terminal_shape_ck,
    DROP CONSTRAINT action_queue_result_shape_ck,
    DROP CONSTRAINT action_queue_completed_fence_ck,
    DROP CONSTRAINT action_queue_terminal_proof_ck;

ALTER TABLE action_queue
    ADD CONSTRAINT action_queue_status_ck CHECK (
        status IN ('QUEUED', 'LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED')
    ),
    ADD CONSTRAINT action_queue_idempotency_key_ck CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 256 AND
        left(idempotency_key, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        idempotency_key COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    ADD CONSTRAINT action_queue_request_hash_ck CHECK (
        octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
        request_hash_version IN ('legacy-submission.v1', 'action-request.v1')
    ),
    ADD CONSTRAINT action_queue_authorization_expiry_ck CHECK (
        authorization_expires_at > '-infinity'::timestamptz AND
        authorization_expires_at < 'infinity'::timestamptz
    ),
    ADD CONSTRAINT action_queue_runner_scope_identity_ck CHECK (
        (
            status IN ('QUEUED', 'CANCELLED') AND
            runner_tenant_id IS NULL AND runner_workspace_id IS NULL AND runner_environment_id IS NULL
        ) OR (
            status IN ('LEASED', 'RUNNING') AND
            runner_tenant_id IS NOT NULL AND runner_workspace_id IS NOT NULL AND runner_environment_id IS NOT NULL AND
            runner_workspace_id::text = workspace_id AND runner_environment_id::text = environment_id
        ) OR (
            status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED') AND (
                (
                    runner_tenant_id IS NULL AND runner_workspace_id IS NULL AND runner_environment_id IS NULL
                ) OR (
                    runner_tenant_id IS NOT NULL AND runner_workspace_id IS NOT NULL AND runner_environment_id IS NOT NULL AND
                    runner_workspace_id::text = workspace_id AND runner_environment_id::text = environment_id
                )
            )
        )
    ),
    ADD CONSTRAINT action_queue_scope_revision_ck CHECK (
        scope_revision IS NULL OR scope_revision > 0
    ),
    ADD CONSTRAINT action_queue_heartbeat_seq_ck CHECK (heartbeat_seq >= 0),
    ADD CONSTRAINT action_queue_cancel_intent_ck CHECK (
        (cancel_requested_at IS NULL AND cancel_reason_hash IS NULL) OR
        (
            cancel_requested_at IS NOT NULL AND cancel_reason_hash IS NOT NULL AND
            octet_length(cancel_reason_hash) = 64 AND cancel_reason_hash COLLATE "C" !~ '[^a-f0-9]' AND
            status IN ('RUNNING', 'FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED')
        )
    ),
    ADD CONSTRAINT action_queue_completion_status_ck CHECK (
        completion_status IS NULL OR completion_status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')
    ),
    ADD CONSTRAINT action_queue_active_lease_shape_ck CHECK (
        (
            status IN ('LEASED', 'RUNNING') AND lease_epoch > 0 AND runner_id IS NOT NULL AND
            runner_tenant_id IS NOT NULL AND runner_workspace_id IS NOT NULL AND runner_environment_id IS NOT NULL AND
            scope_revision IS NOT NULL AND lease_token_sha256 IS NOT NULL AND
            lease_acquired_at IS NOT NULL AND lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL AND
            lease_expires_at > last_heartbeat_at AND
            completed_at IS NULL AND result_hash IS NULL AND completion_status IS NULL
        ) OR (
            status NOT IN ('LEASED', 'RUNNING') AND lease_token_sha256 IS NULL AND lease_expires_at IS NULL
        )
    ),
    ADD CONSTRAINT action_queue_terminal_shape_ck CHECK (
        (status = 'FINALIZING' AND completed_at IS NULL) OR
        (status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED') AND completed_at IS NOT NULL) OR
        (status IN ('QUEUED', 'LEASED', 'RUNNING') AND completed_at IS NULL)
    ),
    ADD CONSTRAINT action_queue_result_shape_ck CHECK (
        (
            status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED') AND
            result_hash IS NOT NULL AND completion_status IS NOT NULL
        ) OR (
            status IN ('QUEUED', 'LEASED', 'RUNNING', 'CANCELLED') AND
            result_hash IS NULL AND completion_status IS NULL
        )
    ),
    ADD CONSTRAINT action_queue_completed_fence_ck CHECK (
        (completed_lease_token_sha256 IS NULL AND completed_lease_epoch IS NULL) OR
        (
            runner_id IS NOT NULL AND completed_lease_token_sha256 IS NOT NULL AND completed_lease_epoch IS NOT NULL AND
            completed_lease_epoch > 0 AND completed_lease_epoch = lease_epoch AND
            status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED')
        )
    ),
    ADD CONSTRAINT action_queue_terminal_proof_ck CHECK (
        (
            status IN ('QUEUED', 'LEASED', 'RUNNING') AND completed_lease_token_sha256 IS NULL AND
            reconciliation_id IS NULL
        ) OR (
            status IN ('FINALIZING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED') AND
            completed_lease_token_sha256 IS NOT NULL
        ) OR (
            status = 'CANCELLED' AND runner_id IS NULL AND completed_lease_token_sha256 IS NULL AND
            reconciliation_id IS NULL
        )
    );

DROP INDEX action_queue_active_target_uk;
DROP INDEX action_queue_single_production_write_uk;

CREATE UNIQUE INDEX action_queue_active_target_uk
    ON action_queue (target_key)
    WHERE status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN');

CREATE UNIQUE INDEX action_queue_single_production_write_uk
    ON action_queue ((1))
    WHERE runner_pool = 'WRITE' AND production = true AND status IN ('LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN');

CREATE UNIQUE INDEX action_queue_workspace_idempotency_uk
    ON action_queue (workspace_id, idempotency_key);

ALTER TABLE action_queue
    ADD CONSTRAINT action_queue_receipt_fence_uk UNIQUE (
        runner_tenant_id, runner_workspace_id, runner_environment_id,
        action_id, runner_id, lease_epoch, scope_revision, result_hash, completion_status
    );

-- Align the durable domain projection with the runner queue state machine.
ALTER TABLE executions DROP CONSTRAINT executions_status_check;
ALTER TABLE executions ADD CONSTRAINT executions_status_check CHECK (
    status IN (
        'QUEUED', 'LEASED', 'RUNNING', 'FINALIZING', 'UNCERTAIN',
        'WAITING_EXTERNAL_APPROVAL', 'WAITING_SYNC', 'VERIFYING',
        'SUCCEEDED', 'FAILED', 'ROLLED_BACK', 'CANCELLED'
    )
) NOT VALID;
ALTER TABLE executions VALIDATE CONSTRAINT executions_status_check;

-- M3 will bind the certificate identity to these records. M1 establishes the
-- trusted, revisioned registry and exact workspace/environment pairs.
CREATE TABLE runner_registrations (
    runner_id text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    spiffe_uri text NOT NULL UNIQUE,
    runner_pool text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    scope_revision bigint NOT NULL DEFAULT 1,
    max_concurrency integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    CONSTRAINT runner_registrations_tenant_runner_uk UNIQUE (tenant_id, runner_id),
    CONSTRAINT runner_registrations_pool_ck CHECK (runner_pool IN ('READ', 'WRITE')),
    CONSTRAINT runner_registrations_scope_revision_ck CHECK (scope_revision > 0),
    CONSTRAINT runner_registrations_max_concurrency_ck CHECK (max_concurrency BETWEEN 1 AND 1024),
    CONSTRAINT runner_registrations_runner_id_ck CHECK (
        octet_length(runner_id) BETWEEN 1 AND 256 AND
        left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT runner_registrations_spiffe_uri_ck CHECK (
        octet_length(spiffe_uri) BETWEEN 10 AND 2048 AND spiffe_uri LIKE 'spiffe://%'
    ),
    CONSTRAINT runner_registrations_updated_ck CHECK (updated_at >= created_at)
);

ALTER TABLE action_queue
    ADD CONSTRAINT action_queue_runner_registration_fk
        FOREIGN KEY (runner_tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT;

CREATE TABLE runner_scope_bindings (
    runner_id text NOT NULL,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    PRIMARY KEY (runner_id, tenant_id, workspace_id, environment_id),
    CONSTRAINT runner_scope_bindings_registration_fk
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT,
    CONSTRAINT runner_scope_bindings_environment_scope_fk
        FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT
);

-- Scope bindings are revisioned registry state. Mutating a pair in place is
-- forbidden, and every insert/delete bumps the parent revision in the same
-- transaction. The resolver's FOR SHARE lock therefore observes either the
-- complete old scope or the complete new scope, never mixed bindings under an
-- unchanged revision.
CREATE OR REPLACE FUNCTION reject_runner_scope_binding_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'runner scope bindings are immutable; delete and insert to change a pair';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER runner_scope_bindings_immutable
    BEFORE UPDATE ON runner_scope_bindings
    FOR EACH ROW EXECUTE FUNCTION reject_runner_scope_binding_update();

CREATE TRIGGER runner_scope_bindings_no_truncate
    BEFORE TRUNCATE ON runner_scope_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION reject_runner_scope_binding_update();

CREATE OR REPLACE FUNCTION bump_runner_scope_revision() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE runner_registrations
        SET scope_revision = scope_revision + 1,
            updated_at = statement_timestamp()
        WHERE tenant_id = NEW.tenant_id AND runner_id = NEW.runner_id;
        RETURN NEW;
    END IF;

    UPDATE runner_registrations
    SET scope_revision = scope_revision + 1,
        updated_at = statement_timestamp()
    WHERE tenant_id = OLD.tenant_id AND runner_id = OLD.runner_id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER runner_scope_bindings_revision
    AFTER INSERT OR DELETE ON runner_scope_bindings
    FOR EACH ROW EXECUTE FUNCTION bump_runner_scope_revision();

CREATE TABLE runner_certificates (
    certificate_sha256 text PRIMARY KEY,
    runner_id text NOT NULL,
    tenant_id uuid NOT NULL,
    issuer_key_id text NOT NULL,
    serial_hex text NOT NULL,
    spki_sha256 text NOT NULL,
    status text NOT NULL DEFAULT 'ACTIVE',
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    CONSTRAINT runner_certificates_registration_fk
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT,
    CONSTRAINT runner_certificates_runner_hash_uk UNIQUE (runner_id, certificate_sha256),
    CONSTRAINT runner_certificates_issuer_serial_uk UNIQUE (issuer_key_id, serial_hex),
    CONSTRAINT runner_certificates_status_ck CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT runner_certificates_hashes_ck CHECK (
        octet_length(certificate_sha256) = 64 AND certificate_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(spki_sha256) = 64 AND spki_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(serial_hex) BETWEEN 2 AND 256 AND serial_hex COLLATE "C" !~ '[^a-f0-9]'
    ),
    CONSTRAINT runner_certificates_window_ck CHECK (not_before < not_after),
    CONSTRAINT runner_certificates_revocation_shape_ck CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason IS NULL) OR
        (status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE TABLE runner_result_receipts (
    action_id text NOT NULL,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    runner_id text NOT NULL,
    lease_epoch bigint NOT NULL,
    scope_revision bigint NOT NULL,
    certificate_sha256 text,
    receipt_hash text NOT NULL,
    completion_status text NOT NULL,
    schema_version text NOT NULL,
    summary jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    PRIMARY KEY (action_id, lease_epoch),
    CONSTRAINT runner_result_receipts_registration_fk
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT,
    CONSTRAINT runner_result_receipts_environment_scope_fk
        FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT runner_result_receipts_action_fence_fk
        FOREIGN KEY (
            tenant_id, workspace_id, environment_id,
            action_id, runner_id, lease_epoch, scope_revision, receipt_hash, completion_status
        )
        REFERENCES action_queue (
            runner_tenant_id, runner_workspace_id, runner_environment_id,
            action_id, runner_id, lease_epoch, scope_revision, result_hash, completion_status
        )
        ON DELETE RESTRICT,
    CONSTRAINT runner_result_receipts_certificate_fk
        FOREIGN KEY (runner_id, certificate_sha256)
        REFERENCES runner_certificates (runner_id, certificate_sha256) ON DELETE RESTRICT,
    CONSTRAINT runner_result_receipts_status_ck
        CHECK (completion_status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')),
    CONSTRAINT runner_result_receipts_scope_revision_ck CHECK (scope_revision > 0),
    CONSTRAINT runner_result_receipts_hash_ck CHECK (
        octet_length(receipt_hash) = 64 AND receipt_hash COLLATE "C" !~ '[^a-f0-9]'
    ),
    CONSTRAINT runner_result_receipts_schema_ck CHECK (schema_version = 'runner-result.v1'),
    CONSTRAINT runner_result_receipts_summary_ck CHECK (
        jsonb_typeof(summary) = 'object' AND pg_column_size(summary) BETWEEN 2 AND 16384
    )
);

CREATE OR REPLACE FUNCTION reject_runner_result_receipt_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runner result receipts are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER runner_result_receipts_immutable
    BEFORE UPDATE OR DELETE ON runner_result_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_runner_result_receipt_mutation();

CREATE TRIGGER runner_result_receipts_no_truncate
    BEFORE TRUNCATE ON runner_result_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION reject_runner_result_receipt_mutation();

COMMIT;
