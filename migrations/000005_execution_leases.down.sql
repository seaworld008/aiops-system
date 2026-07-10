BEGIN;

DROP INDEX IF EXISTS execution_leases_expired_idx;
DROP INDEX IF EXISTS execution_leases_claim_queue_idx;
DROP INDEX IF EXISTS execution_leases_reconciliation_id_uk;
DROP INDEX IF EXISTS execution_leases_single_production_write_uk;
DROP INDEX IF EXISTS execution_leases_active_target_uk;
DROP TABLE IF EXISTS execution_leases;

COMMIT;
