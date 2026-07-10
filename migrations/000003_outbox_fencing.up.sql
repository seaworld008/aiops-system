BEGIN;

ALTER TABLE outbox_events
	ADD COLUMN aggregate_version bigint NOT NULL DEFAULT 1,
	ADD COLUMN claimed_by text,
	ADD COLUMN claim_token uuid,
	ADD COLUMN claim_expires_at timestamptz,
	ADD COLUMN last_error_code varchar(128),
	ADD CONSTRAINT outbox_claim_lease_shape_ck CHECK (
		(claimed_at IS NULL AND claimed_by IS NULL AND claim_token IS NULL AND claim_expires_at IS NULL)
		OR
		(claimed_at IS NOT NULL AND claimed_by IS NOT NULL AND claim_token IS NOT NULL AND claim_expires_at > claimed_at)
	),
	ADD CONSTRAINT outbox_attempts_nonnegative_ck CHECK (attempts >= 0),
	ADD CONSTRAINT outbox_aggregate_version_positive_ck CHECK (aggregate_version > 0),
	ADD CONSTRAINT outbox_aggregate_event_uk UNIQUE (
		tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version, event_type
	);

DROP INDEX outbox_pending_idx;
CREATE INDEX outbox_dispatch_idx
	ON outbox_events (available_at, created_at, id)
	WHERE delivered_at IS NULL;
CREATE INDEX outbox_expired_claim_idx
	ON outbox_events (claim_expires_at, id)
	WHERE delivered_at IS NULL AND claim_token IS NOT NULL;

COMMIT;
