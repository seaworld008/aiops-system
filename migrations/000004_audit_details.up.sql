BEGIN;

ALTER TABLE audit_records
    ADD COLUMN details jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT audit_records_details_object_ck
        CHECK (jsonb_typeof(details) = 'object');

COMMIT;
