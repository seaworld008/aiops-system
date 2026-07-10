BEGIN;

DROP INDEX IF EXISTS outbox_expired_claim_idx;
DROP INDEX IF EXISTS outbox_dispatch_idx;
ALTER TABLE outbox_events
	DROP CONSTRAINT IF EXISTS outbox_aggregate_event_uk,
	DROP CONSTRAINT IF EXISTS outbox_aggregate_version_positive_ck,
	DROP CONSTRAINT IF EXISTS outbox_attempts_nonnegative_ck,
	DROP CONSTRAINT IF EXISTS outbox_claim_lease_shape_ck,
	DROP COLUMN IF EXISTS last_error_code,
	DROP COLUMN IF EXISTS claim_expires_at,
	DROP COLUMN IF EXISTS claim_token,
	DROP COLUMN IF EXISTS claimed_by,
	DROP COLUMN IF EXISTS aggregate_version;

CREATE INDEX outbox_pending_idx ON outbox_events (available_at, created_at)
	WHERE delivered_at IS NULL;

COMMIT;
