BEGIN;

CREATE TABLE action_queue (
    action_id text PRIMARY KEY,
    envelope jsonb NOT NULL,
    submission_hash text NOT NULL,
    plan_hash text NOT NULL,
    workspace_id text NOT NULL,
    environment_id text NOT NULL,
    target_key text NOT NULL,
    environment_revision text NOT NULL,
    runner_pool text NOT NULL,
    production boolean NOT NULL,
    status text NOT NULL DEFAULT 'QUEUED',
    not_before timestamptz NOT NULL DEFAULT statement_timestamp(),
    last_nack_hash text,
    runner_id text,
    lease_token_sha256 text,
    lease_epoch bigint NOT NULL DEFAULT 0,
    lease_acquired_at timestamptz,
    lease_expires_at timestamptz,
    last_heartbeat_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    completed_lease_token_sha256 text,
    completed_lease_epoch bigint,
    result_hash text,
    reconciliation_id text,
    reconciliation_actor text,
    reconciliation_result_hash text,
    reconciled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    CONSTRAINT action_queue_pool_ck CHECK (runner_pool IN ('READ', 'WRITE')),
    CONSTRAINT action_queue_status_ck CHECK (status IN ('QUEUED', 'LEASED', 'RUNNING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    CONSTRAINT action_queue_epoch_ck CHECK (lease_epoch >= 0),
    CONSTRAINT action_queue_envelope_size_ck CHECK (pg_column_size(envelope) BETWEEN 2 AND 262144),
    CONSTRAINT action_queue_action_id_ck CHECK (
        octet_length(action_id) BETWEEN 1 AND 256 AND
        left(action_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        action_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT action_queue_workspace_id_ck CHECK (
        octet_length(workspace_id) BETWEEN 1 AND 256 AND
        left(workspace_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        workspace_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT action_queue_environment_id_ck CHECK (
        octet_length(environment_id) BETWEEN 1 AND 256 AND
        left(environment_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        environment_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT action_queue_target_key_ck CHECK (
        octet_length(target_key) BETWEEN 1 AND 512 AND
        left(target_key, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        target_key COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT action_queue_environment_revision_ck CHECK (
        octet_length(environment_revision) BETWEEN 1 AND 256 AND
        left(environment_revision, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        environment_revision COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
    ),
    CONSTRAINT action_queue_runner_id_ck CHECK (
        runner_id IS NULL OR (
            octet_length(runner_id) BETWEEN 1 AND 256 AND
            left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
            runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        )
    ),
    CONSTRAINT action_queue_reconciliation_identity_ck CHECK (
        (reconciliation_id IS NULL AND reconciliation_actor IS NULL AND reconciliation_result_hash IS NULL AND reconciled_at IS NULL) OR
        (
            reconciliation_id IS NOT NULL AND reconciliation_actor IS NOT NULL AND
            reconciliation_result_hash IS NOT NULL AND reconciled_at IS NOT NULL AND
            octet_length(reconciliation_id) BETWEEN 1 AND 256 AND
            left(reconciliation_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
            reconciliation_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
            octet_length(reconciliation_actor) BETWEEN 1 AND 256 AND
            left(reconciliation_actor, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
            reconciliation_actor COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
            status IN ('SUCCEEDED', 'FAILED')
        )
    ),
    CONSTRAINT action_queue_hashes_ck CHECK (
        octet_length(submission_hash) = 64 AND submission_hash COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(plan_hash) = 64 AND plan_hash COLLATE "C" !~ '[^a-f0-9]' AND
        (last_nack_hash IS NULL OR (octet_length(last_nack_hash) = 64 AND last_nack_hash COLLATE "C" !~ '[^a-f0-9]')) AND
        (lease_token_sha256 IS NULL OR (octet_length(lease_token_sha256) = 64 AND lease_token_sha256 COLLATE "C" !~ '[^a-f0-9]')) AND
        (completed_lease_token_sha256 IS NULL OR (octet_length(completed_lease_token_sha256) = 64 AND completed_lease_token_sha256 COLLATE "C" !~ '[^a-f0-9]')) AND
        (result_hash IS NULL OR (octet_length(result_hash) = 64 AND result_hash COLLATE "C" !~ '[^a-f0-9]')) AND
        (reconciliation_result_hash IS NULL OR (octet_length(reconciliation_result_hash) = 64 AND reconciliation_result_hash COLLATE "C" !~ '[^a-f0-9]'))
    ),
    CONSTRAINT action_queue_active_lease_shape_ck CHECK (
        (
            status IN ('LEASED', 'RUNNING') AND lease_epoch > 0 AND runner_id IS NOT NULL AND lease_token_sha256 IS NOT NULL AND
            lease_acquired_at IS NOT NULL AND lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL AND
            completed_at IS NULL AND result_hash IS NULL
        ) OR (
            status NOT IN ('LEASED', 'RUNNING') AND lease_token_sha256 IS NULL AND lease_expires_at IS NULL
        )
    ),
    CONSTRAINT action_queue_terminal_shape_ck CHECK (
        (status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED') AND completed_at IS NOT NULL) OR
        (status IN ('QUEUED', 'LEASED', 'RUNNING') AND completed_at IS NULL)
    ),
    CONSTRAINT action_queue_result_shape_ck CHECK (
        (status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED') AND result_hash IS NOT NULL) OR
        (status IN ('QUEUED', 'LEASED', 'RUNNING', 'CANCELLED') AND result_hash IS NULL)
    ),
    CONSTRAINT action_queue_completed_fence_ck CHECK (
        (completed_lease_token_sha256 IS NULL AND completed_lease_epoch IS NULL) OR
        (
            runner_id IS NOT NULL AND completed_lease_token_sha256 IS NOT NULL AND completed_lease_epoch IS NOT NULL AND
            completed_lease_epoch > 0 AND completed_lease_epoch = lease_epoch AND
            status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED')
        )
    ),
    CONSTRAINT action_queue_terminal_proof_ck CHECK (
        (
            status IN ('QUEUED', 'LEASED', 'RUNNING') AND completed_lease_token_sha256 IS NULL AND
            reconciliation_id IS NULL
        ) OR (
            status IN ('UNCERTAIN', 'SUCCEEDED', 'FAILED') AND completed_lease_token_sha256 IS NOT NULL
        ) OR (
            status = 'CANCELLED' AND runner_id IS NULL AND completed_lease_token_sha256 IS NULL AND
            reconciliation_id IS NULL
        )
    )
);

CREATE UNIQUE INDEX action_queue_active_target_uk
    ON action_queue (target_key)
    WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN');

CREATE UNIQUE INDEX action_queue_single_production_write_uk
    ON action_queue ((1))
    WHERE runner_pool = 'WRITE' AND production = true AND status IN ('LEASED', 'RUNNING', 'UNCERTAIN');

CREATE UNIQUE INDEX action_queue_reconciliation_id_uk
    ON action_queue (reconciliation_id)
    WHERE reconciliation_id IS NOT NULL;

CREATE INDEX action_queue_claim_idx
    ON action_queue (runner_pool, workspace_id, environment_id, not_before, created_at, action_id)
    WHERE status = 'QUEUED';

CREATE INDEX action_queue_active_expiry_idx
    ON action_queue (lease_expires_at, action_id)
    WHERE status IN ('LEASED', 'RUNNING');

COMMIT;
