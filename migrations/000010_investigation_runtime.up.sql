BEGIN;

SET LOCAL lock_timeout = '5s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

LOCK TABLE incidents, incident_signals, investigations, tool_invocations,
    evidence, hypotheses, hypothesis_evidence, feedback, runner_scope_bindings,
    runner_registrations, runner_certificates, environments, services, signals,
    workspaces IN ACCESS EXCLUSIVE MODE;

ALTER TABLE incidents
    ADD COLUMN correlation_key text,
    ADD COLUMN mapping_status text,
    ADD COLUMN last_signal_at timestamptz,
    ADD COLUMN signal_count integer,
    ADD COLUMN runtime_schema_version text,
    ADD CONSTRAINT incidents_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND correlation_key IS NULL AND
            mapping_status IS NULL AND last_signal_at IS NULL AND signal_count IS NULL
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            correlation_key IS NOT NULL AND mapping_status IS NOT NULL AND
            last_signal_at IS NOT NULL AND signal_count IS NOT NULL AND
            octet_length(correlation_key) BETWEEN 1 AND 512 AND
            left(correlation_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            correlation_key COLLATE "C" !~ '[^a-z0-9._:/@-]' AND
            mapping_status IN ('EXACT', 'AMBIGUOUS', 'UNRESOLVED') AND
            signal_count > 0 AND
            last_signal_at >= opened_at AND last_signal_at <= updated_at AND
            opened_at > '-infinity'::timestamptz AND opened_at < 'infinity'::timestamptz AND
            last_signal_at > '-infinity'::timestamptz AND last_signal_at < 'infinity'::timestamptz AND
            updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
            (
                (mapping_status = 'EXACT' AND service_id IS NOT NULL AND environment_id IS NOT NULL) OR
                mapping_status IN ('AMBIGUOUS', 'UNRESOLVED')
            )
        )
    );

CREATE UNIQUE INDEX incidents_active_correlation_uk
    ON incidents (tenant_id, workspace_id, correlation_key)
    WHERE runtime_schema_version = 'investigation-runtime.v1'
      AND status IN ('OPEN', 'INVESTIGATING', 'MITIGATING');

CREATE INDEX incidents_runtime_list_idx
    ON incidents (workspace_id, opened_at, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE INDEX incidents_runtime_status_list_idx
    ON incidents (workspace_id, status, opened_at, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE OR REPLACE FUNCTION enforce_incident_runtime_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.runtime_schema_version = 'investigation-runtime.v1' AND NOT (
            NEW.status = 'OPEN' AND NEW.version = 1 AND NEW.confirmed_hypothesis_id IS NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'runtime incident must start OPEN at version one without a confirmed root cause',
                CONSTRAINT = 'incidents_runtime_initial_state_guard';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        IF NEW.runtime_schema_version = 'investigation-runtime.v1' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'legacy rows cannot be promoted to investigation runtime by UPDATE',
                CONSTRAINT = 'incidents_runtime_marker_guard';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.runtime_schema_version IS DISTINCT FROM NEW.runtime_schema_version OR
       OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.correlation_key IS DISTINCT FROM NEW.correlation_key OR
       OLD.mapping_status IS DISTINCT FROM NEW.mapping_status OR
       OLD.service_id IS DISTINCT FROM NEW.service_id OR
       OLD.environment_id IS DISTINCT FROM NEW.environment_id OR
       OLD.severity IS DISTINCT FROM NEW.severity OR
       OLD.title IS DISTINCT FROM NEW.title OR
       (OLD.confirmed_hypothesis_id IS NOT NULL AND
        OLD.confirmed_hypothesis_id IS DISTINCT FROM NEW.confirmed_hypothesis_id) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime incident correlation and scope identity are immutable',
            CONSTRAINT = 'incidents_runtime_identity_guard';
    END IF;
    IF OLD IS DISTINCT FROM NEW AND NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime incident version must advance exactly once for every mutation',
            CONSTRAINT = 'incidents_runtime_version_guard';
    END IF;
    IF NEW.signal_count < OLD.signal_count OR NEW.signal_count > OLD.signal_count + 1 OR
       NEW.last_signal_at < OLD.last_signal_at OR NEW.opened_at > OLD.opened_at OR
       NEW.updated_at < OLD.updated_at OR NEW.version < OLD.version THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime incident signal facts cannot move backward or skip a count',
            CONSTRAINT = 'incidents_runtime_signal_guard';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'OPEN' AND NEW.status = 'INVESTIGATING') OR
        (OLD.status = 'INVESTIGATING' AND NEW.status = 'MITIGATING') OR
        (OLD.status = 'MITIGATING' AND NEW.status = 'RESOLVED') OR
        (OLD.status = 'RESOLVED' AND NEW.status = 'CLOSED')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'invalid runtime incident state transition',
            CONSTRAINT = 'incidents_runtime_state_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER incidents_runtime_mutation_guard
    BEFORE INSERT OR UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION enforce_incident_runtime_mutation();

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM incident_signals
        GROUP BY tenant_id, workspace_id, signal_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe investigation runtime upgrade: one signal is associated with multiple incidents';
    END IF;
END;
$$;

CREATE UNIQUE INDEX incident_signals_single_incident_per_signal_uk
    ON incident_signals (tenant_id, workspace_id, signal_id);

ALTER TABLE incident_signals
    ADD CONSTRAINT incident_signals_runtime_exact_association_uk
        UNIQUE (tenant_id, workspace_id, incident_id, signal_id);

CREATE TABLE investigation_signal_correlations (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    signal_id uuid NOT NULL,
    incident_id uuid,
    correlation_key text NOT NULL,
    mapping_status text NOT NULL,
    service_id uuid,
    environment_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    PRIMARY KEY (tenant_id, workspace_id, signal_id),
    CONSTRAINT investigation_signal_correlations_workspace_fk
        FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES workspaces (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT investigation_signal_correlations_signal_fk
        FOREIGN KEY (tenant_id, workspace_id, signal_id)
        REFERENCES signals (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT investigation_signal_correlations_incident_fk
        FOREIGN KEY (tenant_id, workspace_id, incident_id)
        REFERENCES incidents (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT investigation_signal_correlations_association_fk
        FOREIGN KEY (tenant_id, workspace_id, incident_id, signal_id)
        REFERENCES incident_signals (tenant_id, workspace_id, incident_id, signal_id) ON DELETE RESTRICT,
    CONSTRAINT investigation_signal_correlations_service_fk
        FOREIGN KEY (tenant_id, workspace_id, service_id)
        REFERENCES services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT investigation_signal_correlations_environment_fk
        FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT investigation_signal_correlations_key_ck CHECK (
        octet_length(correlation_key) BETWEEN 1 AND 512 AND
        left(correlation_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
        correlation_key COLLATE "C" !~ '[^a-z0-9._:/@-]'
    ),
    CONSTRAINT investigation_signal_correlations_mapping_ck CHECK (
        (mapping_status = 'EXACT' AND service_id IS NOT NULL AND environment_id IS NOT NULL) OR
        (mapping_status IN ('AMBIGUOUS', 'UNRESOLVED'))
    ),
    CONSTRAINT investigation_signal_correlations_time_ck CHECK (
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz
    )
);

CREATE INDEX investigation_signal_correlations_incident_idx
    ON investigation_signal_correlations (tenant_id, workspace_id, incident_id, signal_id)
    WHERE incident_id IS NOT NULL;

CREATE OR REPLACE FUNCTION validate_investigation_signal_correlation_insert() RETURNS trigger AS $$
DECLARE
    signal_status text;
BEGIN
    NEW.created_at := clock_timestamp();
    SELECT status INTO signal_status
    FROM signals
    WHERE tenant_id = NEW.tenant_id
      AND workspace_id = NEW.workspace_id
      AND id = NEW.signal_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'investigation signal correlation requires its exact signal scope',
            CONSTRAINT = 'investigation_signal_correlations_signal_fk';
    END IF;

    IF NEW.incident_id IS NULL THEN
        IF signal_status <> 'resolved' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'resolved signal without an active incident requires a durable no-op tombstone',
                CONSTRAINT = 'investigation_signal_correlations_noop_guard';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM incidents AS incident
    JOIN incident_signals AS association
      ON association.tenant_id = incident.tenant_id
     AND association.workspace_id = incident.workspace_id
     AND association.incident_id = incident.id
     AND association.signal_id = NEW.signal_id
    WHERE incident.tenant_id = NEW.tenant_id
      AND incident.workspace_id = NEW.workspace_id
      AND incident.id = NEW.incident_id
      AND incident.runtime_schema_version = 'investigation-runtime.v1'
      AND incident.status IN ('OPEN', 'INVESTIGATING', 'MITIGATING')
      AND incident.correlation_key = NEW.correlation_key
      AND incident.mapping_status = NEW.mapping_status
      AND incident.service_id IS NOT DISTINCT FROM NEW.service_id
      AND incident.environment_id IS NOT DISTINCT FROM NEW.environment_id
    FOR NO KEY UPDATE OF incident;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'signal correlation does not match its exact runtime incident association',
            CONSTRAINT = 'investigation_signal_correlations_incident_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_signal_correlations_insert_guard
    BEFORE INSERT ON investigation_signal_correlations
    FOR EACH ROW EXECUTE FUNCTION validate_investigation_signal_correlation_insert();

CREATE OR REPLACE FUNCTION reject_investigation_signal_correlation_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'investigation signal correlations are immutable',
        CONSTRAINT = 'investigation_signal_correlations_immutable_guard';
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_signal_correlations_immutable
    BEFORE UPDATE OR DELETE ON investigation_signal_correlations
    FOR EACH ROW EXECUTE FUNCTION reject_investigation_signal_correlation_mutation();

CREATE TRIGGER investigation_signal_correlations_no_truncate
    BEFORE TRUNCATE ON investigation_signal_correlations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_investigation_signal_correlation_mutation();

CREATE OR REPLACE FUNCTION reject_correlated_signal_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        IF EXISTS (SELECT 1 FROM investigation_signal_correlations) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'signals referenced by investigation correlations are immutable',
                CONSTRAINT = 'signals_investigation_correlation_guard';
        END IF;
        RETURN NULL;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM investigation_signal_correlations AS correlation
        WHERE correlation.tenant_id = OLD.tenant_id
          AND correlation.workspace_id = OLD.workspace_id
          AND correlation.signal_id = OLD.id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'signals referenced by investigation correlations are immutable',
            CONSTRAINT = 'signals_investigation_correlation_guard';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER signals_investigation_correlation_guard
    BEFORE UPDATE OR DELETE ON signals
    FOR EACH ROW EXECUTE FUNCTION reject_correlated_signal_mutation();

CREATE TRIGGER signals_investigation_correlation_no_truncate
    BEFORE TRUNCATE ON signals
    FOR EACH STATEMENT EXECUTE FUNCTION reject_correlated_signal_mutation();

CREATE OR REPLACE FUNCTION investigation_runtime_incident_signal_set_valid(
    expected_tenant_id uuid,
    expected_workspace_id uuid,
    expected_incident_id uuid
) RETURNS boolean AS $$
DECLARE
    parent_runtime_schema_version text;
    parent_signal_count integer;
    parent_opened_at timestamptz;
    parent_last_signal_at timestamptz;
    correlation_count bigint;
    association_count bigint;
    first_signal_at timestamptz;
    last_signal_at timestamptz;
BEGIN
    SELECT
        incident.runtime_schema_version,
        incident.signal_count,
        incident.opened_at,
        incident.last_signal_at
    INTO
        parent_runtime_schema_version,
        parent_signal_count,
        parent_opened_at,
        parent_last_signal_at
    FROM incidents AS incident
    WHERE incident.tenant_id = expected_tenant_id
      AND incident.workspace_id = expected_workspace_id
      AND incident.id = expected_incident_id
    FOR SHARE OF incident;
    IF NOT FOUND OR parent_runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN true;
    END IF;

    SELECT count(*), min(signal.observed_at), max(signal.observed_at)
    INTO correlation_count, first_signal_at, last_signal_at
    FROM investigation_signal_correlations AS correlation
    JOIN signals AS signal
      ON signal.tenant_id = correlation.tenant_id
     AND signal.workspace_id = correlation.workspace_id
     AND signal.id = correlation.signal_id
    WHERE correlation.tenant_id = expected_tenant_id
      AND correlation.workspace_id = expected_workspace_id
      AND correlation.incident_id = expected_incident_id;

    SELECT count(*) INTO association_count
    FROM incident_signals AS association
    WHERE association.tenant_id = expected_tenant_id
      AND association.workspace_id = expected_workspace_id
      AND association.incident_id = expected_incident_id;

    RETURN correlation_count = parent_signal_count
       AND association_count = parent_signal_count
       AND first_signal_at IS NOT DISTINCT FROM parent_opened_at
       AND last_signal_at IS NOT DISTINCT FROM parent_last_signal_at;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE FUNCTION validate_runtime_incident_signal_projection() RETURNS trigger AS $$
DECLARE
    valid_set boolean;
BEGIN
    IF TG_TABLE_NAME = 'incidents' THEN
        valid_set := investigation_runtime_incident_signal_set_valid(NEW.tenant_id, NEW.workspace_id, NEW.id);
    ELSIF TG_TABLE_NAME = 'incident_signals' THEN
        IF TG_OP IN ('UPDATE', 'DELETE') THEN
            valid_set := investigation_runtime_incident_signal_set_valid(
                OLD.tenant_id, OLD.workspace_id, OLD.incident_id
            );
            IF NOT valid_set THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'runtime incident signal aggregate does not match its durable correlation set',
                    CONSTRAINT = 'incidents_runtime_signal_set_guard';
            END IF;
        END IF;
        IF TG_OP IN ('INSERT', 'UPDATE') THEN
            valid_set := investigation_runtime_incident_signal_set_valid(
                NEW.tenant_id, NEW.workspace_id, NEW.incident_id
            );
        ELSE
            RETURN NULL;
        END IF;
    ELSE
        IF NEW.incident_id IS NULL THEN
            RETURN NULL;
        END IF;
        valid_set := investigation_runtime_incident_signal_set_valid(
            NEW.tenant_id, NEW.workspace_id, NEW.incident_id
        );
    END IF;
    IF NOT valid_set THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime incident signal aggregate does not match its durable correlation set',
            CONSTRAINT = 'incidents_runtime_signal_set_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER incidents_runtime_signal_projection_guard
    AFTER INSERT OR UPDATE ON incidents
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_incident_signal_projection();

CREATE CONSTRAINT TRIGGER incident_signals_runtime_projection_guard
    AFTER INSERT OR UPDATE OR DELETE ON incident_signals
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_incident_signal_projection();

CREATE CONSTRAINT TRIGGER investigation_signal_correlations_runtime_projection_guard
    AFTER INSERT ON investigation_signal_correlations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_incident_signal_projection();

ALTER TABLE investigations
    ADD COLUMN model_status text,
    ADD COLUMN idempotency_key text,
    ADD COLUMN request_hash text,
    ADD COLUMN request_hash_version text,
    ADD COLUMN failure_code text,
    ADD COLUMN model_failure_code text,
    ADD COLUMN started_at timestamptz,
    ADD COLUMN updated_at timestamptz,
    ADD COLUMN service_id_snapshot uuid,
    ADD COLUMN environment_id_snapshot uuid,
    ADD COLUMN mapping_status_snapshot text,
    ADD COLUMN runtime_schema_version text,
    ADD CONSTRAINT investigations_service_snapshot_fk
        FOREIGN KEY (tenant_id, workspace_id, service_id_snapshot)
        REFERENCES services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT investigations_environment_snapshot_fk
        FOREIGN KEY (tenant_id, workspace_id, environment_id_snapshot)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT investigations_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND model_status IS NULL AND idempotency_key IS NULL AND
            request_hash IS NULL AND request_hash_version IS NULL AND failure_code IS NULL AND
            model_failure_code IS NULL AND started_at IS NULL AND updated_at IS NULL AND
            service_id_snapshot IS NULL AND environment_id_snapshot IS NULL AND mapping_status_snapshot IS NULL
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            model_status IS NOT NULL AND idempotency_key IS NOT NULL AND
            request_hash IS NOT NULL AND request_hash_version IS NOT NULL AND
            updated_at IS NOT NULL AND mapping_status_snapshot IS NOT NULL AND
            model_status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED') AND
            octet_length(idempotency_key) BETWEEN 1 AND 128 AND
            left(idempotency_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            idempotency_key COLLATE "C" !~ '[^a-z0-9._:/-]' AND
            octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
            request_hash_version = 'investigation.create.v1' AND
            mapping_status_snapshot IN ('EXACT', 'AMBIGUOUS', 'UNRESOLVED') AND
            (
                (mapping_status_snapshot = 'EXACT' AND service_id_snapshot IS NOT NULL AND environment_id_snapshot IS NOT NULL) OR
                mapping_status_snapshot IN ('AMBIGUOUS', 'UNRESOLVED')
            ) AND
            window_start > '-infinity'::timestamptz AND window_start < 'infinity'::timestamptz AND
            window_end > '-infinity'::timestamptz AND window_end < 'infinity'::timestamptz AND
            window_start <= window_end AND
            created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
            updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
            updated_at >= created_at AND
            (started_at IS NULL OR (started_at >= created_at AND started_at <= updated_at)) AND
            (completed_at IS NULL OR (completed_at >= created_at AND completed_at <= updated_at)) AND
            (completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at) AND
            (
                (status NOT IN ('FAILED', 'CANCELLED') AND failure_code IS NULL) OR
                (
                    status IN ('FAILED', 'CANCELLED') AND failure_code IS NOT NULL AND
                    octet_length(failure_code) BETWEEN 1 AND 128 AND
                    left(failure_code, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
                    failure_code COLLATE "C" !~ '[^a-z0-9_.-]'
                )
            ) AND
            (
                (model_status <> 'FAILED' AND model_failure_code IS NULL) OR
                (
                    model_status = 'FAILED' AND model_failure_code IS NOT NULL AND
                    octet_length(model_failure_code) BETWEEN 1 AND 128 AND
                    left(model_failure_code, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
                    model_failure_code COLLATE "C" !~ '[^a-z0-9_.-]'
                )
            )
        )
    ),
    ADD CONSTRAINT investigations_runtime_lifecycle_ck CHECK (
        runtime_schema_version IS NULL OR
        (
            status = 'QUEUED' AND model_status = 'PENDING' AND
            started_at IS NULL AND completed_at IS NULL
        ) OR (
            status = 'RUNNING' AND model_status IN ('PENDING', 'RUNNING') AND
            started_at IS NOT NULL AND completed_at IS NULL
        ) OR (
            status IN ('PARTIAL', 'COMPLETED') AND model_status IN ('COMPLETED', 'FAILED', 'SKIPPED') AND
            started_at IS NOT NULL AND completed_at IS NOT NULL
        ) OR (
            status IN ('FAILED', 'CANCELLED') AND model_status = 'CANCELLED' AND
            completed_at IS NOT NULL
        )
    );

CREATE UNIQUE INDEX investigations_single_active_incident_uk
    ON investigations (tenant_id, workspace_id, incident_id)
    WHERE runtime_schema_version = 'investigation-runtime.v1'
      AND status IN ('QUEUED', 'RUNNING');

CREATE INDEX investigations_runtime_list_idx
    ON investigations (workspace_id, created_at, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE INDEX investigations_runtime_incident_list_idx
    ON investigations (workspace_id, incident_id, created_at, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE INDEX investigations_runtime_status_list_idx
    ON investigations (workspace_id, status, created_at, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE OR REPLACE FUNCTION reject_investigation_runtime_identity_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.runtime_schema_version = 'investigation-runtime.v1' AND (
        OLD.runtime_schema_version IS DISTINCT FROM NEW.runtime_schema_version OR
        OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
        OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
        OLD.incident_id IS DISTINCT FROM NEW.incident_id OR
        OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key OR
        OLD.request_hash IS DISTINCT FROM NEW.request_hash OR
        OLD.request_hash_version IS DISTINCT FROM NEW.request_hash_version OR
        OLD.service_id_snapshot IS DISTINCT FROM NEW.service_id_snapshot OR
        OLD.environment_id_snapshot IS DISTINCT FROM NEW.environment_id_snapshot OR
        OLD.mapping_status_snapshot IS DISTINCT FROM NEW.mapping_status_snapshot OR
        OLD.window_start IS DISTINCT FROM NEW.window_start OR
        OLD.window_end IS DISTINCT FROM NEW.window_end OR
        OLD.tool_schema_version IS DISTINCT FROM NEW.tool_schema_version OR
        OLD.created_at IS DISTINCT FROM NEW.created_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation runtime identity and admission snapshot are immutable',
            CONSTRAINT = 'investigations_runtime_identity_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigations_runtime_identity_guard
    BEFORE UPDATE ON investigations
    FOR EACH ROW EXECUTE FUNCTION reject_investigation_runtime_identity_mutation();

CREATE OR REPLACE FUNCTION enforce_investigation_runtime_transition() RETURNS trigger AS $$
DECLARE
    incident incidents%ROWTYPE;
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy rows cannot be promoted to investigation runtime by UPDATE',
            CONSTRAINT = 'investigations_runtime_marker_guard';
    END IF;
    -- Runtime Incident correlation/scope and the Investigation admission
    -- snapshot are independently immutable after creation. Re-locking the
    -- Incident for every lifecycle UPDATE would invert the repository's
    -- global Task -> Investigation order against Incident -> Investigation
    -- creation/feedback transactions and can deadlock. Validate the exact
    -- snapshot only at its admission boundary.
    IF TG_OP = 'INSERT' THEN
        SELECT parent.* INTO incident
        FROM incidents AS parent
        WHERE parent.tenant_id = NEW.tenant_id
          AND parent.workspace_id = NEW.workspace_id
          AND parent.id = NEW.incident_id
          AND parent.runtime_schema_version = 'investigation-runtime.v1'
        FOR SHARE OF parent;
        IF NOT FOUND OR
           incident.service_id IS DISTINCT FROM NEW.service_id_snapshot OR
           incident.environment_id IS DISTINCT FROM NEW.environment_id_snapshot OR
           incident.mapping_status IS DISTINCT FROM NEW.mapping_status_snapshot THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'investigation admission snapshot does not match its runtime incident',
                CONSTRAINT = 'investigations_runtime_incident_snapshot_guard';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status IN ('PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED') AND OLD IS DISTINCT FROM NEW THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'terminal investigation state is immutable',
            CONSTRAINT = 'investigations_runtime_terminal_guard';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'QUEUED' AND NEW.status IN ('RUNNING', 'FAILED', 'CANCELLED')) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'invalid investigation runtime state transition',
            CONSTRAINT = 'investigations_runtime_state_guard';
    END IF;
    IF NEW.status = OLD.status AND NEW.model_status IS DISTINCT FROM OLD.model_status AND NOT (
        OLD.status = 'RUNNING' AND OLD.model_status = 'PENDING' AND NEW.model_status = 'RUNNING'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'invalid investigation runtime model transition',
            CONSTRAINT = 'investigations_runtime_model_state_guard';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'QUEUED' AND NEW.status = 'RUNNING' AND NEW.model_status = 'PENDING') OR
        (OLD.status = 'QUEUED' AND NEW.status IN ('FAILED', 'CANCELLED') AND NEW.model_status = 'CANCELLED') OR
        (
            OLD.status = 'RUNNING' AND NEW.status IN ('PARTIAL', 'COMPLETED') AND
            (
                (OLD.model_status = 'PENDING' AND NEW.model_status = 'SKIPPED') OR
                (OLD.model_status = 'RUNNING' AND NEW.model_status IN ('COMPLETED', 'FAILED'))
            )
        ) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('FAILED', 'CANCELLED') AND NEW.model_status = 'CANCELLED')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation terminal model state does not follow its persisted model lifecycle',
            CONSTRAINT = 'investigations_runtime_model_state_guard';
    END IF;
    IF OLD.status = 'RUNNING' AND OLD.model_status = 'PENDING' AND
       NEW.status = 'RUNNING' AND NEW.model_status = 'RUNNING' AND EXISTS (
            SELECT 1
            FROM tool_invocations AS task
            WHERE task.tenant_id = NEW.tenant_id
              AND task.workspace_id = NEW.workspace_id
              AND task.investigation_id = NEW.id
              AND task.runtime_schema_version = 'investigation-runtime.v1'
              AND task.status IN ('QUEUED', 'RUNNING')
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'model cannot start before every runtime read task is terminal',
            CONSTRAINT = 'investigations_runtime_model_evidence_guard';
    END IF;
    IF NEW.updated_at < OLD.updated_at OR
       (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at) OR
       (OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'investigation runtime lifecycle facts cannot move backward',
            CONSTRAINT = 'investigations_runtime_time_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigations_runtime_transition_guard
    BEFORE INSERT OR UPDATE ON investigations
    FOR EACH ROW EXECUTE FUNCTION enforce_investigation_runtime_transition();

CREATE OR REPLACE FUNCTION investigation_json_object_document_valid(document bytea, maximum_bytes integer)
RETURNS boolean AS $$
DECLARE
    parsed jsonb;
BEGIN
    IF document IS NULL OR maximum_bytes < 2 OR octet_length(document) NOT BETWEEN 2 AND maximum_bytes THEN
        RETURN false;
    END IF;
    parsed := convert_from(document, 'UTF8')::jsonb;
    RETURN jsonb_typeof(parsed) = 'object';
EXCEPTION
    WHEN OTHERS THEN
        RETURN false;
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path FROM CURRENT;

ALTER TABLE tool_invocations ALTER COLUMN started_at DROP NOT NULL;

ALTER TABLE tool_invocations
    ADD COLUMN incident_id uuid,
    ADD COLUMN task_key text,
    ADD COLUMN position smallint,
    ADD COLUMN input_document bytea,
    ADD COLUMN evidence_id uuid,
    ADD COLUMN failure_code text,
    ADD COLUMN created_at timestamptz,
    ADD COLUMN updated_at timestamptz,
    ADD COLUMN runtime_schema_version text,
    ADD CONSTRAINT tool_invocations_runtime_investigation_fk
        FOREIGN KEY (tenant_id, workspace_id, incident_id, investigation_id)
        REFERENCES investigations (tenant_id, workspace_id, incident_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT tool_invocations_runtime_scope_uk
        UNIQUE (tenant_id, workspace_id, investigation_id, id),
    ADD CONSTRAINT tool_invocations_runtime_connector_scope_uk
        UNIQUE (tenant_id, workspace_id, investigation_id, id, tool_name),
    ADD CONSTRAINT tool_invocations_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND incident_id IS NULL AND task_key IS NULL AND
            position IS NULL AND input_document IS NULL AND evidence_id IS NULL AND
            failure_code IS NULL AND created_at IS NULL AND updated_at IS NULL AND
            started_at IS NOT NULL
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            investigation_id IS NOT NULL AND incident_id IS NOT NULL AND execution_id IS NULL AND
            task_key IS NOT NULL AND position IS NOT NULL AND input_document IS NOT NULL AND
            created_at IS NOT NULL AND updated_at IS NOT NULL AND
            octet_length(task_key) BETWEEN 1 AND 64 AND
            left(task_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            task_key COLLATE "C" !~ '[^a-z0-9_.-]' AND
            position BETWEEN 1 AND 12 AND
            octet_length(tool_name) BETWEEN 1 AND 128 AND
            left(tool_name, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            tool_name COLLATE "C" !~ '[^a-z0-9_.-]' AND
            octet_length(tool_version) BETWEEN 1 AND 64 AND
            left(tool_version, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            tool_version COLLATE "C" !~ '[^a-z0-9_.-]' AND
            investigation_json_object_document_valid(input_document, 65536) AND
            octet_length(input_hash) = 64 AND input_hash COLLATE "C" !~ '[^a-f0-9]' AND
            encode(sha256(input_document), 'hex') = input_hash AND
            (output_hash IS NULL OR (
                octet_length(output_hash) = 64 AND output_hash COLLATE "C" !~ '[^a-f0-9]'
            )) AND
            created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
            updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
            updated_at >= created_at AND
            (started_at IS NULL OR (started_at >= created_at AND started_at <= updated_at)) AND
            (completed_at IS NULL OR (completed_at >= created_at AND completed_at <= updated_at)) AND
            (completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at)
        )
    ),
    ADD CONSTRAINT tool_invocations_runtime_lifecycle_ck CHECK (
        runtime_schema_version IS NULL OR
        (
            status = 'QUEUED' AND started_at IS NULL AND completed_at IS NULL AND
            evidence_id IS NULL AND output_hash IS NULL AND failure_code IS NULL
        ) OR (
            status = 'RUNNING' AND started_at IS NOT NULL AND completed_at IS NULL AND
            evidence_id IS NULL AND output_hash IS NULL AND failure_code IS NULL
        ) OR (
            status = 'EVIDENCE' AND started_at IS NOT NULL AND completed_at IS NOT NULL AND
            evidence_id IS NOT NULL AND output_hash IS NOT NULL AND failure_code IS NULL
        ) OR (
            status = 'FAILED' AND started_at IS NOT NULL AND completed_at IS NOT NULL AND
            evidence_id IS NULL AND output_hash IS NULL AND
            failure_code IS NOT NULL AND
            octet_length(failure_code) BETWEEN 1 AND 128 AND
            left(failure_code, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            failure_code COLLATE "C" !~ '[^a-z0-9_.-]'
        ) OR (
            status = 'CANCELLED' AND completed_at IS NOT NULL AND
            evidence_id IS NULL AND output_hash IS NULL AND
            failure_code IS NOT NULL AND
            octet_length(failure_code) BETWEEN 1 AND 128 AND
            left(failure_code, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            failure_code COLLATE "C" !~ '[^a-z0-9_.-]'
        )
    );

CREATE UNIQUE INDEX tool_invocations_runtime_task_key_uk
    ON tool_invocations (tenant_id, workspace_id, investigation_id, task_key)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE UNIQUE INDEX tool_invocations_runtime_position_uk
    ON tool_invocations (tenant_id, workspace_id, investigation_id, position)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE INDEX tool_invocations_runtime_list_idx
    ON tool_invocations (workspace_id, investigation_id, position, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE INDEX tool_invocations_runtime_status_list_idx
    ON tool_invocations (workspace_id, investigation_id, status, position, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE OR REPLACE FUNCTION enforce_tool_invocation_runtime_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        IF NEW.runtime_schema_version = 'investigation-runtime.v1' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'legacy rows cannot be promoted to investigation runtime by UPDATE',
                CONSTRAINT = 'tool_invocations_runtime_marker_guard';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.runtime_schema_version IS DISTINCT FROM NEW.runtime_schema_version OR
       OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.incident_id IS DISTINCT FROM NEW.incident_id OR
       OLD.investigation_id IS DISTINCT FROM NEW.investigation_id OR
       OLD.execution_id IS DISTINCT FROM NEW.execution_id OR
       OLD.task_key IS DISTINCT FROM NEW.task_key OR OLD.position IS DISTINCT FROM NEW.position OR
       OLD.tool_name IS DISTINCT FROM NEW.tool_name OR OLD.tool_version IS DISTINCT FROM NEW.tool_version OR
       OLD.input_document IS DISTINCT FROM NEW.input_document OR OLD.input_hash IS DISTINCT FROM NEW.input_hash OR
       OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime read task ownership and input are immutable',
            CONSTRAINT = 'tool_invocations_runtime_identity_guard';
    END IF;
    IF OLD.status IN ('EVIDENCE', 'FAILED', 'CANCELLED') AND OLD IS DISTINCT FROM NEW THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'terminal read task state is immutable',
            CONSTRAINT = 'tool_invocations_runtime_terminal_guard';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'QUEUED' AND NEW.status IN ('RUNNING', 'EVIDENCE', 'FAILED', 'CANCELLED')) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('EVIDENCE', 'FAILED', 'CANCELLED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'invalid runtime read task state transition',
            CONSTRAINT = 'tool_invocations_runtime_state_guard';
    END IF;
    IF NEW.updated_at < OLD.updated_at OR
       (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at) OR
       (OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime read task lifecycle facts cannot move backward',
            CONSTRAINT = 'tool_invocations_runtime_time_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER tool_invocations_runtime_mutation_guard
    BEFORE UPDATE ON tool_invocations
    FOR EACH ROW EXECUTE FUNCTION enforce_tool_invocation_runtime_mutation();

CREATE OR REPLACE FUNCTION validate_tool_invocation_runtime_parent_lifecycle() RETURNS trigger AS $$
DECLARE
    parent_status text;
    parent_runtime_schema_version text;
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NULL;
    END IF;
    SELECT parent.status, parent.runtime_schema_version
    INTO parent_status, parent_runtime_schema_version
    FROM investigations AS parent
    WHERE parent.tenant_id = NEW.tenant_id
      AND parent.workspace_id = NEW.workspace_id
      AND parent.id = NEW.investigation_id
    FOR SHARE OF parent;
    IF NOT FOUND OR parent_runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime read task state is incompatible with its parent investigation lifecycle',
            CONSTRAINT = 'tool_invocations_runtime_parent_guard';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT (NEW.status = 'QUEUED' AND parent_status = 'QUEUED') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'runtime read tasks can only be inserted QUEUED while the parent investigation is QUEUED',
                CONSTRAINT = 'tool_invocations_runtime_parent_guard';
        END IF;
        RETURN NULL;
    END IF;
    IF OLD.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' OR NOT (
            (NEW.status = 'QUEUED' AND parent_status IN ('QUEUED', 'RUNNING')) OR
            (NEW.status = 'RUNNING' AND parent_status = 'RUNNING') OR
            (
                NEW.status IN ('EVIDENCE', 'FAILED', 'CANCELLED') AND
                parent_status IN ('RUNNING', 'FAILED', 'CANCELLED')
            )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime read task state is incompatible with its parent investigation lifecycle',
            CONSTRAINT = 'tool_invocations_runtime_parent_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER tool_invocations_runtime_parent_guard
    AFTER INSERT OR UPDATE OF status, runtime_schema_version ON tool_invocations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_tool_invocation_runtime_parent_lifecycle();

CREATE OR REPLACE FUNCTION reject_tool_invocation_runtime_removal() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        IF EXISTS (
            SELECT 1 FROM tool_invocations
            WHERE runtime_schema_version = 'investigation-runtime.v1'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'runtime read tasks are durable and cannot be removed',
                CONSTRAINT = 'tool_invocations_runtime_removal_guard';
        END IF;
        RETURN NULL;
    END IF;
    IF OLD.runtime_schema_version = 'investigation-runtime.v1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime read tasks are durable and cannot be removed',
            CONSTRAINT = 'tool_invocations_runtime_removal_guard';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER tool_invocations_runtime_no_delete
    BEFORE DELETE ON tool_invocations
    FOR EACH ROW EXECUTE FUNCTION reject_tool_invocation_runtime_removal();

CREATE TRIGGER tool_invocations_runtime_no_truncate
    BEFORE TRUNCATE ON tool_invocations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_tool_invocation_runtime_removal();

CREATE OR REPLACE FUNCTION validate_investigation_runtime_terminal_tasks() RETURNS trigger AS $$
DECLARE
    total_tasks integer;
    open_tasks integer;
    non_evidence_tasks integer;
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NULL;
    END IF;
    SELECT
        count(*),
        count(*) FILTER (WHERE task.status IN ('QUEUED', 'RUNNING')),
        count(*) FILTER (WHERE task.status <> 'EVIDENCE')
    INTO total_tasks, open_tasks, non_evidence_tasks
    FROM tool_invocations AS task
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.id
      AND task.runtime_schema_version = 'investigation-runtime.v1';
    IF total_tasks NOT BETWEEN 1 AND 12 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime investigation must commit atomically with between one and twelve read tasks',
            CONSTRAINT = 'investigations_runtime_terminal_tasks_guard';
    END IF;
    IF NEW.status NOT IN ('PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED') THEN
        RETURN NULL;
    END IF;
    IF open_tasks <> 0 OR
       (NEW.status = 'COMPLETED' AND non_evidence_tasks <> 0) OR
       (NEW.status = 'PARTIAL' AND non_evidence_tasks = 0) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'terminal investigation status does not match its committed read task set',
            CONSTRAINT = 'investigations_runtime_terminal_tasks_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER investigations_runtime_terminal_tasks_guard
    AFTER INSERT OR UPDATE OF status ON investigations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_investigation_runtime_terminal_tasks();

ALTER TABLE evidence
    ADD COLUMN incident_id uuid,
    ADD COLUMN task_id uuid,
    ADD COLUMN payload_document bytea,
    ADD COLUMN attributes jsonb,
    ADD COLUMN runtime_schema_version text,
    ADD CONSTRAINT evidence_runtime_investigation_fk
        FOREIGN KEY (tenant_id, workspace_id, incident_id, investigation_id)
        REFERENCES investigations (tenant_id, workspace_id, incident_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_runtime_task_fk
        FOREIGN KEY (tenant_id, workspace_id, investigation_id, task_id, connector)
        REFERENCES tool_invocations (tenant_id, workspace_id, investigation_id, id, tool_name) ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_runtime_task_result_uk
        UNIQUE (tenant_id, workspace_id, investigation_id, task_id, id, content_hash),
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

CREATE UNIQUE INDEX evidence_runtime_task_uk
    ON evidence (tenant_id, workspace_id, task_id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE INDEX evidence_runtime_list_idx
    ON evidence (workspace_id, investigation_id, collected_at, created_at, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

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

CREATE TRIGGER evidence_runtime_insert_guard
    BEFORE INSERT ON evidence
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_evidence_insert();

CREATE OR REPLACE FUNCTION validate_runtime_evidence_task_projection() RETURNS trigger AS $$
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NULL;
    END IF;
    PERFORM 1
    FROM tool_invocations AS task
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.tool_name = NEW.connector
      AND task.runtime_schema_version = 'investigation-runtime.v1'
      AND task.status = 'EVIDENCE'
      AND task.evidence_id = NEW.id
      AND task.output_hash = NEW.content_hash
    FOR SHARE OF task;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime evidence must be exactly projected by its terminal read task',
            CONSTRAINT = 'evidence_runtime_task_projection_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER evidence_runtime_task_projection_guard
    AFTER INSERT ON evidence
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_evidence_task_projection();

CREATE OR REPLACE FUNCTION reject_evidence_runtime_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        IF EXISTS (
            SELECT 1 FROM evidence
            WHERE runtime_schema_version = 'investigation-runtime.v1'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'evidence containing runtime facts cannot be truncated',
                CONSTRAINT = 'evidence_runtime_immutable_guard';
        END IF;
        RETURN NULL;
    END IF;
    IF OLD.runtime_schema_version = 'investigation-runtime.v1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime evidence is immutable',
            CONSTRAINT = 'evidence_runtime_immutable_guard';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.runtime_schema_version = 'investigation-runtime.v1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime evidence is immutable',
            CONSTRAINT = 'evidence_runtime_immutable_guard';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER evidence_runtime_immutable
    BEFORE UPDATE OR DELETE ON evidence
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_runtime_mutation();

CREATE TRIGGER evidence_runtime_no_truncate
    BEFORE TRUNCATE ON evidence
    FOR EACH STATEMENT EXECUTE FUNCTION reject_evidence_runtime_mutation();

ALTER TABLE tool_invocations
    ADD CONSTRAINT tool_invocations_runtime_evidence_fk
        FOREIGN KEY (tenant_id, workspace_id, investigation_id, id, evidence_id, output_hash)
        REFERENCES evidence (tenant_id, workspace_id, investigation_id, task_id, id, content_hash)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION investigation_text_array_bounded(values_to_check text[], maximum_items integer, maximum_bytes integer)
RETURNS boolean AS $$
DECLARE
    item text;
BEGIN
    IF values_to_check IS NULL OR cardinality(values_to_check) > maximum_items THEN
        RETURN false;
    END IF;
    FOREACH item IN ARRAY values_to_check LOOP
        IF item IS NULL OR item = '' OR item <> btrim(item) OR octet_length(item) > maximum_bytes OR
           item ~ '[[:cntrl:]]' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path FROM CURRENT;

ALTER TABLE hypotheses
    ADD COLUMN confidence double precision,
    ADD COLUMN proposal_document bytea,
    ADD COLUMN proposal_hash text,
    ADD COLUMN unknowns text[],
    ADD COLUMN runtime_schema_version text,
    ADD CONSTRAINT hypotheses_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND confidence IS NULL AND proposal_document IS NULL AND
            proposal_hash IS NULL AND unknowns IS NULL
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            confidence IS NOT NULL AND proposal_document IS NOT NULL AND
            proposal_hash IS NOT NULL AND unknowns IS NOT NULL AND
            confidence BETWEEN 0.0 AND 1.0 AND
            rank BETWEEN 1 AND 100 AND
            (
                (confidence < 0.5 AND confidence_band = 'LOW') OR
                (confidence >= 0.5 AND confidence < 0.8 AND confidence_band = 'MEDIUM') OR
                (confidence >= 0.8 AND confidence_band = 'HIGH')
            ) AND
            octet_length(summary) BETWEEN 1 AND 4096 AND summary = btrim(summary) AND
            summary !~ '[[:cntrl:]]' AND
            investigation_json_object_document_valid(proposal_document, 65536) AND
            octet_length(proposal_hash) = 64 AND proposal_hash COLLATE "C" !~ '[^a-f0-9]' AND
            encode(sha256(proposal_document), 'hex') = proposal_hash AND
            investigation_text_array_bounded(unknowns, 32, 512) AND
            created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz
        )
    );

ALTER TABLE hypotheses
    ADD CONSTRAINT hypotheses_runtime_exact_scope_uk
        UNIQUE (tenant_id, workspace_id, incident_id, investigation_id, id),
    ADD CONSTRAINT hypotheses_runtime_marker_scope_uk
        UNIQUE (tenant_id, workspace_id, incident_id, investigation_id, id, runtime_schema_version),
    ADD CONSTRAINT hypotheses_runtime_confirmation_marker_uk
        UNIQUE (tenant_id, workspace_id, incident_id, status, id, runtime_schema_version);

ALTER TABLE incidents
    ADD CONSTRAINT incidents_runtime_confirmed_hypothesis_fk
        FOREIGN KEY (tenant_id, workspace_id, id, confirmed_hypothesis_status, confirmed_hypothesis_id, runtime_schema_version)
        REFERENCES hypotheses (
            tenant_id, workspace_id, incident_id, status, id, runtime_schema_version
        ) ON DELETE RESTRICT;

CREATE UNIQUE INDEX hypotheses_runtime_rank_uk
    ON hypotheses (tenant_id, workspace_id, investigation_id, rank)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE INDEX hypotheses_runtime_list_idx
    ON hypotheses (workspace_id, investigation_id, rank, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE UNIQUE INDEX hypotheses_runtime_confirmed_incident_uk
    ON hypotheses (tenant_id, workspace_id, incident_id)
    WHERE runtime_schema_version = 'investigation-runtime.v1' AND status = 'CONFIRMED';

CREATE OR REPLACE FUNCTION enforce_hypothesis_runtime_mutation() RETURNS trigger AS $$
DECLARE
    parent_status text;
    parent_model_status text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
            RETURN NEW;
        END IF;
        SELECT parent.status, parent.model_status INTO parent_status, parent_model_status
        FROM investigations AS parent
        WHERE parent.tenant_id = NEW.tenant_id
          AND parent.workspace_id = NEW.workspace_id
          AND parent.id = NEW.investigation_id
          AND parent.incident_id = NEW.incident_id
          AND parent.runtime_schema_version = 'investigation-runtime.v1'
        FOR UPDATE OF parent;
        IF NOT FOUND OR NEW.status <> 'PROPOSED' OR
           parent_status <> 'RUNNING' OR parent_model_status <> 'RUNNING' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'runtime hypothesis must be inserted as PROPOSED while its investigation is RUNNING',
                CONSTRAINT = 'hypotheses_runtime_initial_state_guard';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        IF NEW.runtime_schema_version = 'investigation-runtime.v1' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'legacy rows cannot be promoted to investigation runtime by UPDATE',
                CONSTRAINT = 'hypotheses_runtime_marker_guard';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status = 'PROPOSED' AND NEW.status IN ('CONFIRMED', 'REJECTED') AND
       OLD.id = NEW.id AND OLD.tenant_id = NEW.tenant_id AND OLD.workspace_id = NEW.workspace_id AND
       OLD.incident_id = NEW.incident_id AND OLD.investigation_id = NEW.investigation_id AND
       OLD.rank = NEW.rank AND OLD.confidence_band = NEW.confidence_band AND
       OLD.summary = NEW.summary AND OLD.created_at = NEW.created_at AND
       OLD.confidence = NEW.confidence AND OLD.proposal_document = NEW.proposal_document AND
       OLD.proposal_hash = NEW.proposal_hash AND OLD.unknowns = NEW.unknowns AND
       OLD.runtime_schema_version = NEW.runtime_schema_version THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'runtime hypothesis facts are immutable except human terminal verdict',
        CONSTRAINT = 'hypotheses_runtime_mutation_guard';
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER hypotheses_runtime_mutation_guard
    BEFORE INSERT OR UPDATE ON hypotheses
    FOR EACH ROW EXECUTE FUNCTION enforce_hypothesis_runtime_mutation();

ALTER TABLE hypothesis_evidence
    ADD COLUMN position smallint,
    ADD COLUMN runtime_schema_version text,
    ADD CONSTRAINT hypothesis_evidence_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND position IS NULL
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            position IS NOT NULL AND position BETWEEN 1 AND 64 AND relation = 'SUPPORTS'
        )
    );

CREATE UNIQUE INDEX hypothesis_evidence_runtime_position_uk
    ON hypothesis_evidence (tenant_id, workspace_id, investigation_id, hypothesis_id, position)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE OR REPLACE FUNCTION validate_runtime_hypothesis_evidence_insert() RETURNS trigger AS $$
DECLARE
    parent_status text;
    parent_model_status text;
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NEW;
    END IF;
    SELECT parent.status, parent.model_status INTO parent_status, parent_model_status
    FROM investigations AS parent
    WHERE parent.tenant_id = NEW.tenant_id
      AND parent.workspace_id = NEW.workspace_id
      AND parent.id = NEW.investigation_id
      AND parent.runtime_schema_version = 'investigation-runtime.v1'
    FOR UPDATE OF parent;
    IF NOT FOUND OR parent_status <> 'RUNNING' OR parent_model_status <> 'RUNNING' OR NOT EXISTS (
        SELECT 1
        FROM hypotheses AS hypothesis
        JOIN evidence AS evidence_fact
          ON evidence_fact.tenant_id = hypothesis.tenant_id
         AND evidence_fact.workspace_id = hypothesis.workspace_id
         AND evidence_fact.investigation_id = hypothesis.investigation_id
        WHERE hypothesis.tenant_id = NEW.tenant_id
          AND hypothesis.workspace_id = NEW.workspace_id
          AND hypothesis.investigation_id = NEW.investigation_id
          AND hypothesis.id = NEW.hypothesis_id
          AND hypothesis.runtime_schema_version = 'investigation-runtime.v1'
          AND evidence_fact.id = NEW.evidence_id
          AND evidence_fact.runtime_schema_version = 'investigation-runtime.v1'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime hypothesis evidence can only be added while its investigation is RUNNING',
            CONSTRAINT = 'hypothesis_evidence_runtime_insert_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER hypothesis_evidence_runtime_insert_guard
    BEFORE INSERT ON hypothesis_evidence
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_hypothesis_evidence_insert();

CREATE OR REPLACE FUNCTION validate_runtime_hypothesis_evidence() RETURNS trigger AS $$
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NULL;
    END IF;
    PERFORM 1
    FROM hypothesis_evidence AS link
    WHERE link.tenant_id = NEW.tenant_id
      AND link.workspace_id = NEW.workspace_id
      AND link.investigation_id = NEW.investigation_id
      AND link.hypothesis_id = NEW.id
      AND link.runtime_schema_version = 'investigation-runtime.v1';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime hypothesis requires at least one exact persisted evidence reference',
            CONSTRAINT = 'hypotheses_runtime_evidence_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER hypotheses_runtime_evidence_guard
    AFTER INSERT OR UPDATE OF status ON hypotheses
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_hypothesis_evidence();

CREATE OR REPLACE FUNCTION reject_hypothesis_evidence_runtime_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        IF EXISTS (
            SELECT 1 FROM hypothesis_evidence
            WHERE runtime_schema_version = 'investigation-runtime.v1'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'hypothesis evidence containing runtime facts cannot be truncated',
                CONSTRAINT = 'hypothesis_evidence_runtime_immutable_guard';
        END IF;
        RETURN NULL;
    END IF;
    IF OLD.runtime_schema_version = 'investigation-runtime.v1' OR
       (TG_OP = 'UPDATE' AND NEW.runtime_schema_version = 'investigation-runtime.v1') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime hypothesis evidence is immutable',
            CONSTRAINT = 'hypothesis_evidence_runtime_immutable_guard';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER hypothesis_evidence_runtime_immutable
    BEFORE UPDATE OR DELETE ON hypothesis_evidence
    FOR EACH ROW EXECUTE FUNCTION reject_hypothesis_evidence_runtime_mutation();

CREATE TRIGGER hypothesis_evidence_runtime_no_truncate
    BEFORE TRUNCATE ON hypothesis_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION reject_hypothesis_evidence_runtime_mutation();

CREATE OR REPLACE FUNCTION investigation_runtime_hypothesis_set_valid(
    expected_tenant_id uuid,
    expected_workspace_id uuid,
    expected_investigation_id uuid
) RETURNS boolean AS $$
DECLARE
    parent_status text;
    parent_model_status text;
    parent_runtime_schema_version text;
    hypothesis_count integer;
BEGIN
    SELECT status, model_status, runtime_schema_version
    INTO parent_status, parent_model_status, parent_runtime_schema_version
    FROM investigations
    WHERE tenant_id = expected_tenant_id
      AND workspace_id = expected_workspace_id
      AND id = expected_investigation_id;
    IF NOT FOUND OR parent_runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN false;
    END IF;

    SELECT count(*)
    INTO hypothesis_count
    FROM hypotheses
    WHERE tenant_id = expected_tenant_id
      AND workspace_id = expected_workspace_id
      AND investigation_id = expected_investigation_id
      AND runtime_schema_version = 'investigation-runtime.v1';

    IF parent_status IN ('PARTIAL', 'COMPLETED') AND parent_model_status = 'COMPLETED' THEN
        RETURN hypothesis_count BETWEEN 1 AND 20;
    END IF;
    RETURN hypothesis_count = 0;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE FUNCTION validate_investigation_runtime_hypothesis_set() RETURNS trigger AS $$
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NULL;
    END IF;
    IF NOT investigation_runtime_hypothesis_set_valid(NEW.tenant_id, NEW.workspace_id, NEW.id) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime investigation model outcome does not match its exact hypothesis set',
            CONSTRAINT = 'investigations_runtime_hypothesis_set_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER investigations_runtime_hypothesis_set_guard
    AFTER INSERT OR UPDATE OF status, model_status ON investigations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_investigation_runtime_hypothesis_set();

CREATE OR REPLACE FUNCTION validate_runtime_hypothesis_parent_set() RETURNS trigger AS $$
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' THEN
        RETURN NULL;
    END IF;
    IF NOT investigation_runtime_hypothesis_set_valid(
        NEW.tenant_id,
        NEW.workspace_id,
        NEW.investigation_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime hypotheses must commit atomically with a completed model outcome',
            CONSTRAINT = 'hypotheses_runtime_parent_set_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER hypotheses_runtime_parent_set_guard
    AFTER INSERT OR UPDATE OF status ON hypotheses
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_hypothesis_parent_set();

ALTER TABLE feedback DROP CONSTRAINT feedback_kind_check;
ALTER TABLE feedback DROP CONSTRAINT feedback_check;

ALTER TABLE feedback
    ADD COLUMN incident_id uuid,
    ADD COLUMN actor_type text,
    ADD COLUMN details_document bytea,
    ADD COLUMN details_hash text,
    ADD COLUMN runtime_schema_version text,
    ADD CONSTRAINT feedback_incident_scope_fk
        FOREIGN KEY (tenant_id, workspace_id, incident_id)
        REFERENCES incidents (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT feedback_kind_check CHECK (
        kind IN (
            'HELPFUL', 'NOT_HELPFUL', 'CONFIRM', 'REJECT', 'CORRECT',
            'CONFIRMED', 'REJECTED', 'INCONCLUSIVE'
        )
    ),
    ADD CONSTRAINT feedback_check CHECK (
        kind NOT IN ('CONFIRM', 'REJECT', 'CORRECT', 'CONFIRMED', 'REJECTED', 'INCONCLUSIVE') OR
        hypothesis_id IS NOT NULL
    ),
    ADD CONSTRAINT feedback_runtime_scope_uk
        UNIQUE (tenant_id, workspace_id, investigation_id, id),
    ADD CONSTRAINT feedback_runtime_shape_ck CHECK (
        (
            runtime_schema_version IS NULL AND incident_id IS NULL AND actor_type IS NULL AND
            details_document IS NULL AND details_hash IS NULL AND
            kind IN ('HELPFUL', 'NOT_HELPFUL', 'CONFIRM', 'REJECT', 'CORRECT')
        ) OR (
            runtime_schema_version = 'investigation-runtime.v1' AND
            incident_id IS NOT NULL AND hypothesis_id IS NOT NULL AND actor_type IS NOT NULL AND
            details_document IS NOT NULL AND details_hash IS NOT NULL AND actor_type = 'HUMAN' AND
            kind IN ('CONFIRMED', 'REJECTED', 'INCONCLUSIVE') AND comment IS NULL AND
            octet_length(actor_id) BETWEEN 1 AND 256 AND
            left(actor_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
            actor_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
            investigation_json_object_document_valid(details_document, 65536) AND
            octet_length(details_hash) = 64 AND details_hash COLLATE "C" !~ '[^a-f0-9]' AND
            encode(sha256(details_document), 'hex') = details_hash AND
            created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz
        )
    );

ALTER TABLE feedback
    ADD CONSTRAINT feedback_runtime_hypothesis_marker_fk
        FOREIGN KEY (tenant_id, workspace_id, incident_id, investigation_id, hypothesis_id, runtime_schema_version)
        REFERENCES hypotheses (
            tenant_id, workspace_id, incident_id, investigation_id,
            id, runtime_schema_version
        )
        ON DELETE RESTRICT;

CREATE INDEX feedback_runtime_investigation_idx
    ON feedback (workspace_id, investigation_id, created_at, id)
    WHERE runtime_schema_version = 'investigation-runtime.v1';

CREATE OR REPLACE FUNCTION reject_feedback_runtime_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        IF EXISTS (
            SELECT 1 FROM feedback
            WHERE runtime_schema_version = 'investigation-runtime.v1'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'feedback containing runtime evidence cannot be truncated',
                CONSTRAINT = 'feedback_runtime_immutable_guard';
        END IF;
        RETURN NULL;
    END IF;
    IF OLD.runtime_schema_version = 'investigation-runtime.v1' OR
       (TG_OP = 'UPDATE' AND NEW.runtime_schema_version = 'investigation-runtime.v1') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime feedback is immutable',
            CONSTRAINT = 'feedback_runtime_immutable_guard';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER feedback_runtime_immutable
    BEFORE UPDATE OR DELETE ON feedback
    FOR EACH ROW EXECUTE FUNCTION reject_feedback_runtime_mutation();

CREATE TRIGGER feedback_runtime_no_truncate
    BEFORE TRUNCATE ON feedback
    FOR EACH STATEMENT EXECUTE FUNCTION reject_feedback_runtime_mutation();

CREATE OR REPLACE FUNCTION validate_runtime_hypothesis_feedback() RETURNS trigger AS $$
DECLARE
    required_kind text;
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' OR
       NEW.status NOT IN ('CONFIRMED', 'REJECTED') THEN
        RETURN NULL;
    END IF;
    required_kind := CASE NEW.status WHEN 'CONFIRMED' THEN 'CONFIRMED' ELSE 'REJECTED' END;
    PERFORM 1
    FROM feedback AS human_feedback
    WHERE human_feedback.tenant_id = NEW.tenant_id
      AND human_feedback.workspace_id = NEW.workspace_id
      AND human_feedback.incident_id = NEW.incident_id
      AND human_feedback.investigation_id = NEW.investigation_id
      AND human_feedback.hypothesis_id = NEW.id
      AND human_feedback.runtime_schema_version = 'investigation-runtime.v1'
      AND human_feedback.actor_type = 'HUMAN'
      AND human_feedback.kind = required_kind;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime hypothesis terminal verdict requires exact HUMAN feedback',
            CONSTRAINT = 'hypotheses_runtime_feedback_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER hypotheses_runtime_feedback_guard
    AFTER INSERT OR UPDATE OF status ON hypotheses
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_hypothesis_feedback();

CREATE OR REPLACE FUNCTION validate_runtime_feedback_projection() RETURNS trigger AS $$
BEGIN
    IF NEW.runtime_schema_version IS DISTINCT FROM 'investigation-runtime.v1' OR NEW.kind = 'INCONCLUSIVE' THEN
        RETURN NULL;
    END IF;
    PERFORM 1
    FROM hypotheses AS hypothesis
    JOIN incidents AS incident
      ON incident.tenant_id = hypothesis.tenant_id
     AND incident.workspace_id = hypothesis.workspace_id
     AND incident.id = hypothesis.incident_id
    WHERE hypothesis.tenant_id = NEW.tenant_id
      AND hypothesis.workspace_id = NEW.workspace_id
      AND hypothesis.incident_id = NEW.incident_id
      AND hypothesis.investigation_id = NEW.investigation_id
      AND hypothesis.id = NEW.hypothesis_id
      AND hypothesis.runtime_schema_version = 'investigation-runtime.v1'
      AND (
        (NEW.kind = 'REJECTED' AND hypothesis.status = 'REJECTED') OR
        (
            NEW.kind = 'CONFIRMED' AND hypothesis.status = 'CONFIRMED' AND
            incident.confirmed_hypothesis_id = hypothesis.id
        )
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runtime HUMAN feedback does not match its committed hypothesis projection',
            CONSTRAINT = 'feedback_runtime_projection_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER feedback_runtime_projection_guard
    AFTER INSERT ON feedback
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_runtime_feedback_projection();

CREATE TABLE investigation_idempotency_records (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    operation text NOT NULL,
    request_hash text NOT NULL,
    request_hash_version text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid NOT NULL,
    result_snapshot bytea,
    result_snapshot_sha256 text,
    result_snapshot_version text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    PRIMARY KEY (workspace_id, idempotency_key),
    CONSTRAINT investigation_idempotency_records_tenant_scope_uk
        UNIQUE (tenant_id, workspace_id, idempotency_key),
    CONSTRAINT investigation_idempotency_records_workspace_fk
        FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES workspaces (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT investigation_idempotency_records_identity_ck CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        left(idempotency_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
        idempotency_key COLLATE "C" !~ '[^a-z0-9._:/-]' AND
        operation IN (
            'create_investigation', 'complete_task', 'start_model',
            'finalize_investigation', 'fail_investigation', 'record_feedback'
        ) AND
        octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
        (
            (operation = 'create_investigation' AND request_hash_version = 'investigation.create.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'complete_task' AND request_hash_version = 'investigation.complete-task.v1' AND resource_type = 'RUNNER_EVIDENCE_RECEIPT') OR
            (operation = 'start_model' AND request_hash_version = 'investigation.start-model.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'finalize_investigation' AND request_hash_version = 'investigation.finalize.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'fail_investigation' AND request_hash_version = 'investigation.fail.v1' AND resource_type = 'INVESTIGATION') OR
            (operation = 'record_feedback' AND request_hash_version = 'investigation.feedback.v1' AND resource_type = 'FEEDBACK')
        ) AND
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz
    ),
    CONSTRAINT investigation_idempotency_records_snapshot_ck CHECK (
        (
            result_snapshot IS NULL AND result_snapshot_sha256 IS NULL AND result_snapshot_version IS NULL AND
            operation NOT IN ('start_model', 'finalize_investigation')
        ) OR (
            result_snapshot IS NOT NULL AND result_snapshot_sha256 IS NOT NULL AND result_snapshot_version IS NOT NULL AND
            operation IN ('start_model', 'finalize_investigation') AND
            octet_length(result_snapshot) BETWEEN 2 AND 8388608 AND
            octet_length(result_snapshot_sha256) = 64 AND
            result_snapshot_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
            encode(sha256(result_snapshot), 'hex') = result_snapshot_sha256 AND
            (
                (operation = 'start_model' AND result_snapshot_version = 'investigation.start-model-result.v1') OR
                (operation = 'finalize_investigation' AND result_snapshot_version = 'investigation.finalize-result.v1')
            )
        )
    )
);

CREATE INDEX investigation_idempotency_records_resource_idx
    ON investigation_idempotency_records (tenant_id, workspace_id, resource_type, resource_id);

CREATE OR REPLACE FUNCTION reject_investigation_idempotency_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'investigation idempotency records are append-only',
        CONSTRAINT = 'investigation_idempotency_records_append_only_guard';
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER investigation_idempotency_records_append_only
    BEFORE UPDATE OR DELETE ON investigation_idempotency_records
    FOR EACH ROW EXECUTE FUNCTION reject_investigation_idempotency_mutation();

CREATE TRIGGER investigation_idempotency_records_no_truncate
    BEFORE TRUNCATE ON investigation_idempotency_records
    FOR EACH STATEMENT EXECUTE FUNCTION reject_investigation_idempotency_mutation();

ALTER TABLE investigations
    ADD CONSTRAINT investigations_runtime_environment_scope_uk
        UNIQUE (tenant_id, workspace_id, id, environment_id_snapshot);

CREATE TABLE runner_evidence_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    investigation_id uuid NOT NULL,
    task_id uuid NOT NULL,
    runner_id text NOT NULL,
    scope_revision bigint NOT NULL,
    certificate_sha256 text NOT NULL,
    connector_id text NOT NULL,
    evidence_id uuid,
    content_hash text,
    failure_code text,
    idempotency_key text NOT NULL,
    request_hash text NOT NULL,
    receipt_hash text NOT NULL,
    schema_version text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT runner_evidence_receipts_workspace_fk
        FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES workspaces (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT runner_evidence_receipts_environment_fk
        FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT runner_evidence_receipts_investigation_environment_fk
        FOREIGN KEY (tenant_id, workspace_id, investigation_id, environment_id)
        REFERENCES investigations (tenant_id, workspace_id, id, environment_id_snapshot) ON DELETE RESTRICT,
    CONSTRAINT runner_evidence_receipts_task_fk
        FOREIGN KEY (tenant_id, workspace_id, investigation_id, task_id, connector_id)
        REFERENCES tool_invocations (tenant_id, workspace_id, investigation_id, id, tool_name) ON DELETE RESTRICT,
    CONSTRAINT runner_evidence_receipts_evidence_fk
        FOREIGN KEY (tenant_id, workspace_id, investigation_id, task_id, evidence_id, content_hash)
        REFERENCES evidence (tenant_id, workspace_id, investigation_id, task_id, id, content_hash) ON DELETE RESTRICT,
    CONSTRAINT runner_evidence_receipts_registration_fk
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runner_registrations (tenant_id, runner_id) ON DELETE RESTRICT,
    CONSTRAINT runner_evidence_receipts_certificate_fk
        FOREIGN KEY (runner_id, certificate_sha256)
        REFERENCES runner_certificates (runner_id, certificate_sha256) ON DELETE RESTRICT,
    CONSTRAINT runner_evidence_receipts_identity_ck CHECK (
        octet_length(runner_id) BETWEEN 1 AND 256 AND
        left(runner_id, 1) COLLATE "C" ~ '^[A-Za-z0-9]$' AND
        runner_id COLLATE "C" !~ '[^A-Za-z0-9._:/@-]' AND
        scope_revision > 0 AND
        octet_length(certificate_sha256) = 64 AND certificate_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(connector_id) BETWEEN 1 AND 128 AND
        left(connector_id, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
        connector_id COLLATE "C" !~ '[^a-z0-9_.-]' AND
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        left(idempotency_key, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
        idempotency_key COLLATE "C" !~ '[^a-z0-9._:/-]' AND
        octet_length(request_hash) = 64 AND request_hash COLLATE "C" !~ '[^a-f0-9]' AND
        octet_length(receipt_hash) = 64 AND receipt_hash COLLATE "C" !~ '[^a-f0-9]' AND
        schema_version = 'runner-evidence.v1' AND
        received_at > '-infinity'::timestamptz AND received_at < 'infinity'::timestamptz
    ),
    CONSTRAINT runner_evidence_receipts_result_ck CHECK (
        (
            evidence_id IS NOT NULL AND content_hash IS NOT NULL AND failure_code IS NULL AND
            octet_length(content_hash) = 64 AND content_hash COLLATE "C" !~ '[^a-f0-9]'
        ) OR (
            evidence_id IS NULL AND content_hash IS NULL AND failure_code IS NOT NULL AND
            octet_length(failure_code) BETWEEN 1 AND 128 AND
            left(failure_code, 1) COLLATE "C" ~ '^[a-z0-9]$' AND
            failure_code COLLATE "C" !~ '[^a-z0-9_.-]'
        )
    )
);

CREATE UNIQUE INDEX runner_evidence_receipts_task_uk
    ON runner_evidence_receipts (tenant_id, workspace_id, investigation_id, task_id);

CREATE UNIQUE INDEX runner_evidence_receipts_idempotency_uk
    ON runner_evidence_receipts (workspace_id, idempotency_key);

CREATE OR REPLACE FUNCTION validate_runner_evidence_receipt_insert() RETURNS trigger AS $$
BEGIN
    NEW.received_at := clock_timestamp();

    PERFORM 1
    FROM runner_scope_bindings AS binding
    WHERE binding.tenant_id = NEW.tenant_id
      AND binding.runner_id = NEW.runner_id
      AND binding.workspace_id = NEW.workspace_id
      AND binding.environment_id = NEW.environment_id
    FOR SHARE OF binding;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runner evidence receipt requires its current exact scope binding',
            CONSTRAINT = 'runner_evidence_receipts_scope_guard';
    END IF;

    PERFORM 1
    FROM runner_registrations AS registration
    WHERE registration.tenant_id = NEW.tenant_id
      AND registration.runner_id = NEW.runner_id
      AND registration.enabled = true
      AND registration.runner_pool = 'READ'
      AND registration.scope_revision = NEW.scope_revision
    FOR SHARE OF registration;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runner evidence receipt requires an enabled current READ registration',
            CONSTRAINT = 'runner_evidence_receipts_registration_guard';
    END IF;

    PERFORM 1
    FROM runner_certificates AS certificate
    WHERE certificate.tenant_id = NEW.tenant_id
      AND certificate.runner_id = NEW.runner_id
      AND certificate.certificate_sha256 = NEW.certificate_sha256
      AND certificate.status = 'ACTIVE'
      AND certificate.not_before <= NEW.received_at
      AND certificate.not_after > NEW.received_at
    FOR SHARE OF certificate;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runner evidence receipt requires its current ACTIVE certificate',
            CONSTRAINT = 'runner_evidence_receipts_certificate_guard';
    END IF;

    PERFORM 1
    FROM tool_invocations AS task
    JOIN investigations AS investigation
      ON investigation.tenant_id = task.tenant_id
     AND investigation.workspace_id = task.workspace_id
     AND investigation.id = task.investigation_id
    WHERE task.tenant_id = NEW.tenant_id
      AND task.workspace_id = NEW.workspace_id
      AND task.investigation_id = NEW.investigation_id
      AND task.id = NEW.task_id
      AND task.tool_name = NEW.connector_id
      AND task.runtime_schema_version = 'investigation-runtime.v1'
      AND task.completed_at IS NOT NULL
      AND investigation.runtime_schema_version = 'investigation-runtime.v1'
      AND investigation.status IN ('RUNNING', 'PARTIAL', 'COMPLETED')
      AND (
        (
            NEW.evidence_id IS NOT NULL AND NEW.content_hash IS NOT NULL AND NEW.failure_code IS NULL AND
            task.status = 'EVIDENCE' AND task.evidence_id = NEW.evidence_id AND
            task.output_hash = NEW.content_hash AND task.failure_code IS NULL
        ) OR (
            NEW.evidence_id IS NULL AND NEW.content_hash IS NULL AND NEW.failure_code IS NOT NULL AND
            task.status IN ('FAILED', 'CANCELLED') AND task.evidence_id IS NULL AND
            task.output_hash IS NULL AND task.failure_code = NEW.failure_code
        )
      )
    FOR SHARE OF task;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'runner evidence receipt does not match the committed terminal task result',
            CONSTRAINT = 'runner_evidence_receipts_task_result_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER runner_evidence_receipts_insert_guard
    BEFORE INSERT ON runner_evidence_receipts
    FOR EACH ROW EXECUTE FUNCTION validate_runner_evidence_receipt_insert();

CREATE OR REPLACE FUNCTION reject_runner_evidence_receipt_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'runner evidence receipts are immutable',
        CONSTRAINT = 'runner_evidence_receipts_immutable_guard';
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER runner_evidence_receipts_immutable
    BEFORE UPDATE OR DELETE ON runner_evidence_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_runner_evidence_receipt_mutation();

CREATE TRIGGER runner_evidence_receipts_no_truncate
    BEFORE TRUNCATE ON runner_evidence_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION reject_runner_evidence_receipt_mutation();

COMMIT;
