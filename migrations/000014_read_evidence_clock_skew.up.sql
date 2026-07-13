BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

-- collected_at is a source/Runner timestamp. created_at and receipt
-- received_at remain server-owned. Allow only the same fixed two-second skew
-- enforced by readtask.MaxEvidenceClockSkew; larger drift fails closed.
CREATE OR REPLACE FUNCTION validate_runtime_evidence_insert() RETURNS trigger AS $$
DECLARE
    task_status text;
    task_clock_floor timestamptz;
    attempt_clock_floor timestamptz;
    parent_status text;
    receipt_at timestamptz;
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NEW;
    END IF;
    SELECT task.status, COALESCE(task.started_at, task.created_at)
    INTO task_status, task_clock_floor
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

    SELECT attempt.started_at
    INTO attempt_clock_floor
    FROM investigation_task_attempts AS attempt
    WHERE attempt.tenant_id = NEW.tenant_id
      AND attempt.workspace_id = NEW.workspace_id
      AND attempt.investigation_id = NEW.investigation_id
      AND attempt.task_id = NEW.task_id
      AND attempt.status = 'RUNNING'
    ORDER BY attempt.lease_epoch DESC
    LIMIT 1
    FOR SHARE OF attempt;
    task_clock_floor := COALESCE(attempt_clock_floor, task_clock_floor);

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

    receipt_at := clock_timestamp();
    IF NEW.collected_at < task_clock_floor - interval '2 seconds' OR
       NEW.collected_at > receipt_at + interval '2 seconds' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime evidence source timestamp exceeds the bounded Runner clock skew',
            CONSTRAINT = 'evidence_runtime_clock_skew_guard';
    END IF;
    NEW.created_at := receipt_at;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

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
            collected_at <= created_at + interval '2 seconds'
        )
    );

COMMENT ON CONSTRAINT evidence_runtime_shape_ck ON evidence IS
    'Runtime evidence source time may differ from server-owned created_at by at most two seconds';

COMMIT;
