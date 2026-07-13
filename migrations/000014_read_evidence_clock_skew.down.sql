BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

LOCK TABLE investigation_task_attempts, evidence, runner_evidence_receipts
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM evidence
        WHERE runtime_schema_version = 'investigation-runtime.v1'
          AND collected_at > created_at
    ) OR EXISTS (
        SELECT 1
        FROM evidence AS admitted
        JOIN runner_evidence_receipts AS receipt
          ON receipt.tenant_id = admitted.tenant_id
         AND receipt.workspace_id = admitted.workspace_id
         AND receipt.investigation_id = admitted.investigation_id
         AND receipt.task_id = admitted.task_id
         AND receipt.evidence_id = admitted.id
         AND receipt.schema_version = 'runner-evidence.v3'
        JOIN investigation_task_attempts AS attempt
          ON attempt.tenant_id = receipt.tenant_id
         AND attempt.workspace_id = receipt.workspace_id
         AND attempt.investigation_id = receipt.investigation_id
         AND attempt.task_id = receipt.task_id
         AND attempt.lease_epoch = receipt.lease_epoch
        WHERE admitted.runtime_schema_version = 'investigation-runtime.v1'
          AND (
              admitted.collected_at < attempt.started_at OR
              admitted.collected_at > receipt.received_at
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe read evidence clock-skew rollback: source timestamps outside legacy exact bounds remain';
    END IF;
END;
$$;

ALTER TABLE evidence
    DROP CONSTRAINT evidence_runtime_shape_ck,
    ADD CONSTRAINT evidence_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND incident_id IS NULL AND task_id IS NULL AND
            payload_document IS NULL AND attributes IS NULL
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            incident_id IS NOT NULL AND task_id IS NOT NULL AND
            payload_document IS NOT NULL AND attributes IS NOT NULL AND
            octet_length(connector) BETWEEN 1 AND 128 AND
            left(connector, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            connector COLLATE "C" !~ '[^a-z0-9_.-]' AND
            investigation_json_object_document_valid(payload_document, 65536) AND
            octet_length(content_hash) = 64 AND content_hash COLLATE "C" !~ '[^a-f0-9]' AND
            encode(sha256(payload_document), 'hex') = content_hash AND
            jsonb_typeof(attributes) = 'object' AND pg_column_size(attributes) BETWEEN 2 AND 16384 AND
            jsonb_typeof(query_summary) = 'object' AND pg_column_size(query_summary) BETWEEN 2 AND 65536 AND
            jsonb_typeof(redacted_summary) = 'object' AND pg_column_size(redacted_summary) BETWEEN 2 AND 65536 AND
            resource_ref IS NULL AND raw_ref IS NULL AND truncated = false AND
            trust_level = 'AUTHENTICATED_READ_RUNNER' AND
            collected_at > '-infinity'::timestamptz AND collected_at < 'infinity'::timestamptz AND
            created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
            collected_at <= created_at
        )
    );

CREATE OR REPLACE FUNCTION validate_runtime_evidence_insert() RETURNS trigger AS $$
DECLARE
    task_status text;
    parent_status text;
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NEW;
    END IF;
    SELECT task.status
    INTO task_status
    FROM tool_invocations AS task
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.tool_name = NEW.connector
      AND task.runtime_schema_version = 'investigation-runtime.v1'
    FOR SHARE OF task;
    IF NOT FOUND OR task_status NOT IN ('QUEUED', 'RUNNING') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime evidence can only be admitted while its parent and read task are active',
            CONSTRAINT = 'evidence_runtime_insert_guard';
    END IF;

    SELECT parent.status
    INTO parent_status
    FROM investigations AS parent
    WHERE parent.tenant_id = NEW.tenant_id
      AND parent.workspace_id = NEW.workspace_id
      AND parent.id = NEW.investigation_id
      AND parent.runtime_schema_version = 'investigation-runtime.v1'
    FOR NO KEY UPDATE OF parent;
    IF NOT FOUND OR parent_status NOT IN ('QUEUED', 'RUNNING') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime evidence can only be admitted while its parent and read task are active',
            CONSTRAINT = 'evidence_runtime_insert_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

COMMIT;
