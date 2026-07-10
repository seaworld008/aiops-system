BEGIN;

ALTER TABLE audit_records
    DROP CONSTRAINT IF EXISTS audit_records_details_object_ck,
    DROP COLUMN IF EXISTS details;

COMMIT;
