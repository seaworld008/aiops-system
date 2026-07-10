BEGIN;

-- Runner leases deliberately live beside, rather than inside, the workflow
-- executions table. The lease protocol uses stable opaque execution IDs and
-- can therefore fence read-side work as well as write-side action executions.
CREATE TABLE execution_leases (
    execution_id text PRIMARY KEY,
    target_key text NOT NULL,
    runner_pool text NOT NULL,
    production boolean NOT NULL,
    status text NOT NULL DEFAULT 'QUEUED',
    runner_id text,
    lease_token text,
    lease_epoch bigint NOT NULL DEFAULT 0,
    lease_acquired_at timestamptz,
    lease_expires_at timestamptz,
    last_heartbeat_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    result_hash text,
    completed_lease_token text,
    completed_lease_epoch bigint,
    reconciliation_id text,
    reconciliation_actor text,
    reconciliation_result_hash text,
    reconciled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),

    CONSTRAINT execution_leases_execution_id_ck
        CHECK (
            octet_length(execution_id) BETWEEN 1 AND 256
            AND left(execution_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
            AND execution_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        ),
    CONSTRAINT execution_leases_target_key_ck
        CHECK (
            octet_length(target_key) BETWEEN 1 AND 512
            AND left(target_key, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
            AND target_key COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        ),
    CONSTRAINT execution_leases_runner_id_ck CHECK (
        runner_id IS NULL
        OR (
            octet_length(runner_id) BETWEEN 1 AND 256
            AND left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
            AND runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        )
    ),
    CONSTRAINT execution_leases_lease_token_ck CHECK (
        lease_token IS NULL
        OR (
            octet_length(lease_token) BETWEEN 1 AND 256
            AND left(lease_token, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
            AND lease_token COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        )
    ),
    CONSTRAINT execution_leases_completed_lease_token_ck CHECK (
        completed_lease_token IS NULL
        OR (
            octet_length(completed_lease_token) BETWEEN 1 AND 256
            AND left(completed_lease_token, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
            AND completed_lease_token COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        )
    ),
    CONSTRAINT execution_leases_reconciliation_id_ck CHECK (
        reconciliation_id IS NULL
        OR (
            octet_length(reconciliation_id) BETWEEN 1 AND 256
            AND left(reconciliation_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
            AND reconciliation_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        )
    ),
    CONSTRAINT execution_leases_reconciliation_actor_ck CHECK (
        reconciliation_actor IS NULL
        OR (
            octet_length(reconciliation_actor) BETWEEN 1 AND 256
            AND left(reconciliation_actor, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
            AND reconciliation_actor COLLATE "C" !~ '[^A-Za-z0-9._:/@-]'
        )
    ),
    CONSTRAINT execution_leases_runner_pool_ck
        CHECK (runner_pool IN ('READ', 'WRITE')),
    CONSTRAINT execution_leases_status_ck
        CHECK (status IN ('QUEUED', 'LEASED', 'RUNNING', 'UNCERTAIN', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    CONSTRAINT execution_leases_epoch_ck
        CHECK (lease_epoch >= 0),
    CONSTRAINT execution_leases_active_shape_ck CHECK (
        (
            status IN ('LEASED', 'RUNNING')
            AND runner_id IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_epoch > 0
            AND lease_expires_at IS NOT NULL
            AND last_heartbeat_at IS NOT NULL
            AND lease_expires_at > last_heartbeat_at
        )
        OR
        (
            status NOT IN ('LEASED', 'RUNNING')
            AND lease_token IS NULL
            AND lease_expires_at IS NULL
        )
    ),
    CONSTRAINT execution_leases_completion_shape_ck CHECK (
        (
            completed_lease_token IS NULL
            AND completed_lease_epoch IS NULL
            AND result_hash IS NULL
            AND (
                (
                    reconciliation_id IS NULL
                    AND status NOT IN ('SUCCEEDED', 'FAILED')
                )
                OR
                (
                    reconciliation_id IS NOT NULL
                    AND status IN ('SUCCEEDED', 'FAILED')
                )
            )
        )
        OR
        (
            completed_lease_token IS NOT NULL
            AND completed_lease_epoch IS NOT NULL
            AND completed_lease_epoch > 0
            AND completed_lease_epoch = lease_epoch
            AND runner_id IS NOT NULL
            AND result_hash IS NOT NULL
            AND octet_length(result_hash) = 64
            AND result_hash COLLATE "C" !~ '[^a-f0-9]'
            AND status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN')
        )
    ),
    CONSTRAINT execution_leases_reconciliation_shape_ck CHECK (
        (
            reconciliation_id IS NULL
            AND reconciliation_actor IS NULL
            AND reconciliation_result_hash IS NULL
            AND reconciled_at IS NULL
        )
        OR
        (
            reconciliation_id IS NOT NULL
            AND reconciliation_actor IS NOT NULL
            AND reconciliation_result_hash IS NOT NULL
            AND octet_length(reconciliation_result_hash) = 64
            AND reconciliation_result_hash COLLATE "C" !~ '[^a-f0-9]'
            AND reconciled_at IS NOT NULL
            AND status IN ('SUCCEEDED', 'FAILED')
        )
    ),
    CONSTRAINT execution_leases_status_timestamp_shape_ck CHECK (
        (
            status = 'QUEUED'
            AND started_at IS NULL
            AND completed_at IS NULL
        )
        OR
        (
            status = 'LEASED'
            AND lease_acquired_at IS NOT NULL
            AND started_at IS NULL
            AND completed_at IS NULL
        )
        OR
        (
            status = 'RUNNING'
            AND lease_acquired_at IS NOT NULL
            AND started_at IS NOT NULL
            AND completed_at IS NULL
        )
        OR
        (
            status IN ('SUCCEEDED', 'FAILED', 'UNCERTAIN', 'CANCELLED')
            AND completed_at IS NOT NULL
        )
    ),
    CONSTRAINT execution_leases_updated_after_created_ck
        CHECK (updated_at >= created_at)
);

-- An UNCERTAIN execution may still be changing its target. Reserving both its
-- target and (for production writes) the global write slot prevents a blind
-- retry until explicit reconciliation resolves the uncertainty.
CREATE UNIQUE INDEX execution_leases_active_target_uk
    ON execution_leases (target_key)
    WHERE status IN ('LEASED', 'RUNNING', 'UNCERTAIN');

CREATE UNIQUE INDEX execution_leases_single_production_write_uk
    ON execution_leases ((runner_pool))
    WHERE runner_pool = 'WRITE' AND production = true AND status IN ('LEASED', 'RUNNING', 'UNCERTAIN');

CREATE UNIQUE INDEX execution_leases_reconciliation_id_uk
    ON execution_leases (reconciliation_id)
    WHERE reconciliation_id IS NOT NULL;

CREATE INDEX execution_leases_claim_queue_idx
    ON execution_leases (runner_pool, created_at, execution_id)
    WHERE status = 'QUEUED';

CREATE INDEX execution_leases_expired_idx
    ON execution_leases (lease_expires_at, execution_id)
    WHERE status IN ('LEASED', 'RUNNING');

COMMIT;
