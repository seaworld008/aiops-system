BEGIN;

DROP INDEX IF EXISTS action_queue_active_expiry_idx;
DROP INDEX IF EXISTS action_queue_claim_idx;
DROP INDEX IF EXISTS action_queue_reconciliation_id_uk;
DROP INDEX IF EXISTS action_queue_single_production_write_uk;
DROP INDEX IF EXISTS action_queue_active_target_uk;
DROP TABLE IF EXISTS action_queue;

COMMIT;
