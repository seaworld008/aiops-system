BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

SET LOCAL search_path = pg_catalog, public, pg_temp;

SET LOCAL ROLE aiops_schema_owner;

LOCK TABLE public.tenants, public.workspaces, public.environments, public.integrations,
    public.services, public.service_bindings, public.audit_records, public.outbox_events
    IN ACCESS EXCLUSIVE MODE NOWAIT;

DO $$
DECLARE
    missing_role text;
BEGIN
    SELECT required.role_name
    INTO missing_role
    FROM unnest(ARRAY[
        'aiops_migrator',
        'aiops_schema_owner',
        'aiops_control_plane_runtime',
        'aiops_control_plane_workload'
    ]::text[]) AS required(role_name)
    LEFT JOIN pg_catalog.pg_roles AS role
      ON role.rolname = required.role_name
    WHERE role.oid IS NULL
    ORDER BY required.role_name COLLATE "C"
    LIMIT 1;
    IF missing_role IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42704',
            MESSAGE = 'required database role is missing: ' || missing_role;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.asset_catalog_text_valid(candidate text, maximum_bytes integer)
RETURNS boolean AS $$
BEGIN
    RETURN candidate IS NOT NULL
       AND octet_length(candidate) BETWEEN 1 AND maximum_bytes
       AND candidate = btrim(candidate)
       AND candidate COLLATE "C" !~ '[[:cntrl:]]';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_code_valid(candidate text, maximum_bytes integer)
RETURNS boolean AS $$
BEGIN
    RETURN asset_catalog_text_valid(candidate, maximum_bytes)
       AND left(candidate, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
       AND candidate COLLATE "C" !~ '[^A-Za-z0-9_.:/@+-]';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_sha256_valid(candidate text)
RETURNS boolean AS $$
BEGIN
    RETURN candidate IS NOT NULL
       AND octet_length(candidate) = 64
       AND candidate COLLATE "C" !~ '[^a-f0-9]';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_provider_kind_valid(candidate text)
RETURNS boolean AS $$
BEGIN
    RETURN candidate IS NOT NULL
       AND octet_length(candidate) BETWEEN 1 AND 64
       AND candidate COLLATE "C" ~ '^[A-Z][A-Z0-9_]{0,63}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_idempotency_key_valid(candidate text)
RETURNS boolean AS $$
BEGIN
    RETURN candidate IS NOT NULL
       AND octet_length(candidate) BETWEEN 1 AND 128
       AND candidate COLLATE "C" ~ '^[a-z0-9][a-z0-9._:/-]{0,127}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_opaque_reference_valid(candidate text)
RETURNS boolean AS $$
BEGIN
    RETURN candidate IS NOT NULL
       AND candidate COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_json_object_valid(
    document bytea,
    minimum_bytes integer,
    maximum_bytes integer
) RETURNS boolean AS $$
DECLARE
    raw_document text;
BEGIN
    IF document IS NULL OR octet_length(document) NOT BETWEEN minimum_bytes AND maximum_bytes THEN
        RETURN false;
    END IF;
    raw_document := convert_from(document, 'UTF8');
    RETURN raw_document IS JSON OBJECT WITH UNIQUE KEYS;
EXCEPTION
    WHEN OTHERS THEN
        RETURN false;
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_labels_valid(document jsonb)
RETURNS boolean AS $$
BEGIN
    RETURN document IS NOT NULL
       AND jsonb_typeof(document) = 'object'
       AND (SELECT count(*) FROM jsonb_object_keys(document)) <= 64
       AND octet_length(convert_to(document::text, 'UTF8')) <= 16384;
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_checkpoint_envelope_valid(envelope bytea)
RETURNS boolean AS $$
BEGIN
    RETURN envelope IS NOT NULL
       AND octet_length(envelope) BETWEEN 29 AND 65536
       AND get_byte(envelope, 0) = 1
       AND substring(envelope FROM 2 FOR 12) <> decode(repeat('00', 12), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_field_provenance_valid(document bytea)
RETURNS boolean AS $$
DECLARE
    parsed jsonb;
    field_entry record;
    attribute text;
BEGIN
    IF NOT asset_catalog_json_object_valid(document, 2, 32768) THEN
        RETURN false;
    END IF;
    parsed := convert_from(document, 'UTF8')::jsonb;
    FOR field_entry IN SELECT key, value FROM jsonb_each(parsed)
    LOOP
        IF field_entry.key NOT IN (
            'provider_kind', 'external_id', 'kind', 'display_name', 'owner_group',
            'criticality', 'data_classification', 'labels', 'environment_id',
            'lifecycle', 'mapping_status', 'type_details'
        ) OR jsonb_typeof(field_entry.value) <> 'object' THEN
            RETURN false;
        END IF;
        FOR attribute IN SELECT jsonb_object_keys(field_entry.value)
        LOOP
            IF attribute NOT IN (
                'source_id', 'provider_kind', 'source_revision', 'observed_at',
                'provider_path_code', 'confidence', 'ownership'
            ) THEN
                RETURN false;
            END IF;
        END LOOP;
        IF NOT (
            field_entry.value ?& ARRAY[
                'source_id', 'provider_kind', 'source_revision', 'observed_at',
                'provider_path_code', 'confidence', 'ownership'
            ]
        ) OR field_entry.value->>'ownership' IS NULL
           OR field_entry.value->>'ownership' NOT IN ('SOURCE', 'GOVERNANCE', 'MERGE_DECISION')
           OR NOT asset_catalog_provider_kind_valid(field_entry.value->>'provider_kind')
           OR (field_entry.value->>'source_revision') COLLATE "C" !~ '^[1-9][0-9]*$'
           OR NOT asset_catalog_code_valid(field_entry.value->>'provider_path_code', 128)
           OR jsonb_typeof(field_entry.value->'confidence') <> 'number'
           OR (field_entry.value->'confidence')::text COLLATE "C" !~ '^(0|[1-9][0-9]?|100)$'
           OR (field_entry.value->>'observed_at') COLLATE "C" !~
                '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$' THEN
            RETURN false;
        END IF;
        PERFORM (field_entry.value->>'source_id')::uuid;
        IF NOT isfinite((field_entry.value->>'observed_at')::timestamptz) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
EXCEPTION
    WHEN OTHERS THEN
        RETURN false;
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public, pg_temp;

CREATE TABLE public.asset_sources (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN (
        'MANUAL', 'CSV_IMPORT', 'CONTROL_PLANE_API', 'EXTERNAL_CMDB', 'VSPHERE',
        'PROXMOX', 'OPENSTACK', 'CLOUD_PROVIDER', 'KUBERNETES_OPERATOR', 'AWX_INVENTORY'
    )),
    provider_kind text NOT NULL CHECK (asset_catalog_provider_kind_valid(provider_kind)),
    name text NOT NULL CHECK (asset_catalog_text_valid(name, 256)),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'DEGRADED', 'DISABLED')),
    published_revision bigint,
    published_revision_digest text,
    gate_status text NOT NULL DEFAULT 'UNAVAILABLE' CHECK (gate_status IN (
        'UNAVAILABLE', 'VALIDATING', 'AVAILABLE', 'DEGRADED', 'SUSPENDED'
    )),
    gate_reason_code text CHECK (gate_reason_code IS NULL OR asset_catalog_code_valid(gate_reason_code, 128)),
    gate_revision bigint NOT NULL DEFAULT 0 CHECK (gate_revision >= 0),
    validated_run_id uuid,
    validation_digest text,
    validated_binding_digest text,
    checkpoint_ciphertext bytea,
    checkpoint_key_id text,
    checkpoint_sha256 text,
    checkpoint_version bigint NOT NULL DEFAULT 0 CHECK (checkpoint_version >= 0),
    checkpoint_revision bigint NOT NULL DEFAULT 0 CHECK (checkpoint_revision >= 0),
    next_allowed_at timestamptz,
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    create_idempotency_key text NOT NULL CHECK (asset_catalog_idempotency_key_valid(create_idempotency_key)),
    create_request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(create_request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    last_success_run_id uuid,
    last_success_at timestamptz,
    last_complete_snapshot_run_id uuid,
    last_complete_snapshot_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, id),
    UNIQUE (tenant_id, workspace_id, id, provider_kind),
    UNIQUE (workspace_id, create_idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES public.workspaces (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_sources_published_pointer_ck CHECK ((
        (published_revision IS NULL AND published_revision_digest IS NULL) OR
        (published_revision > 0 AND asset_catalog_sha256_valid(published_revision_digest))
    ) IS TRUE),
    CONSTRAINT asset_sources_validation_ck CHECK (
        (validation_digest IS NULL OR asset_catalog_sha256_valid(validation_digest)) AND
        (validated_binding_digest IS NULL OR asset_catalog_sha256_valid(validated_binding_digest)) AND
        (gate_status <> 'AVAILABLE' OR (
            validated_run_id IS NOT NULL AND validation_digest IS NOT NULL AND
            validated_binding_digest IS NOT NULL AND published_revision IS NOT NULL
        ))
    ),
    CONSTRAINT asset_sources_checkpoint_ck CHECK (
        (
            checkpoint_ciphertext IS NULL AND checkpoint_key_id IS NULL AND
            checkpoint_sha256 IS NULL
        ) OR (
            asset_catalog_checkpoint_envelope_valid(checkpoint_ciphertext) AND
            asset_catalog_code_valid(checkpoint_key_id, 256) AND
            asset_catalog_sha256_valid(checkpoint_sha256) AND
            pg_catalog.encode(pg_catalog.sha256(checkpoint_ciphertext), 'hex') = checkpoint_sha256 AND
            checkpoint_revision > 0 AND checkpoint_version > 0
        )
    ),
    CONSTRAINT asset_sources_last_success_ck CHECK (
        (last_success_run_id IS NULL AND last_success_at IS NULL) OR
        (last_success_run_id IS NOT NULL AND last_success_at IS NOT NULL)
    ),
    CONSTRAINT asset_sources_last_complete_snapshot_ck CHECK (
        (last_complete_snapshot_run_id IS NULL AND last_complete_snapshot_at IS NULL) OR
        (last_complete_snapshot_run_id IS NOT NULL AND last_complete_snapshot_at IS NOT NULL)
    ),
    CONSTRAINT asset_sources_time_ck CHECK (
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
        updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
        (next_allowed_at IS NULL OR (next_allowed_at > '-infinity'::timestamptz AND next_allowed_at < 'infinity'::timestamptz)) AND
        (last_success_at IS NULL OR isfinite(last_success_at)) AND
        (last_complete_snapshot_at IS NULL OR isfinite(last_complete_snapshot_at))
    )
);

COMMENT ON COLUMN public.asset_sources.checkpoint_ciphertext IS
    'AES-256-GCM ciphertext only; exact AAD is asset-source-checkpoint.v1 over tenant, workspace, source, provider, checkpoint revision, canonical revision digest, source definition digest, checkpoint key id, and checkpoint version';
COMMENT ON COLUMN public.asset_sources.checkpoint_key_id IS 'Opaque encryption key identifier; never a key, secret, endpoint, or Vault path';

CREATE OR REPLACE FUNCTION public.asset_catalog_future_source_gate_admitted(candidate public.asset_sources)
RETURNS boolean AS $$
BEGIN
    RETURN false;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp;

CREATE TABLE public.asset_source_revisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL DEFAULT 'DRAFT' CHECK (state IN (
        'DRAFT', 'VALIDATING', 'VALIDATED', 'REJECTED', 'PUBLISHED', 'SUPERSEDED'
    )),
    canonical_profile_manifest bytea NOT NULL,
    profile_manifest_sha256 text NOT NULL,
    canonical_provider_schema bytea NOT NULL,
    canonical_provider_schema_sha256 text NOT NULL,
    integration_id uuid,
    sync_mode text NOT NULL CHECK (sync_mode IN ('MANUAL', 'ON_DEMAND', 'SCHEDULED')),
    authority_scope_digest text NOT NULL CHECK (asset_catalog_sha256_valid(authority_scope_digest)),
    source_definition_digest text NOT NULL CHECK (asset_catalog_sha256_valid(source_definition_digest)),
    canonical_revision_digest text NOT NULL CHECK (asset_catalog_sha256_valid(canonical_revision_digest)),
    credential_reference_id text,
    trust_reference_id text,
    network_policy_reference_id text,
    rate_limit_requests integer NOT NULL CHECK (rate_limit_requests BETWEEN 1 AND 1000000),
    rate_limit_window_seconds integer NOT NULL CHECK (rate_limit_window_seconds BETWEEN 1 AND 86400),
    backpressure_base_seconds integer NOT NULL CHECK (backpressure_base_seconds BETWEEN 1 AND 86400),
    backpressure_max_seconds integer NOT NULL CHECK (
        backpressure_max_seconds >= 1 AND
        backpressure_max_seconds <= 604800 AND
        backpressure_max_seconds >= backpressure_base_seconds
    ),
    profile_code text NOT NULL CHECK (asset_catalog_code_valid(profile_code, 128)),
    schedule_expression text,
    typed_extension_code text,
    prepared_extension_digest text,
    validation_run_id uuid,
    validation_digest text,
    created_by text NOT NULL CHECK (asset_catalog_text_valid(created_by, 256)),
    change_reason_code text NOT NULL CHECK (asset_catalog_code_valid(change_reason_code, 128)),
    expected_source_version bigint NOT NULL CHECK (expected_source_version > 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, id),
    UNIQUE (tenant_id, workspace_id, source_id, revision),
    UNIQUE (tenant_id, workspace_id, source_id, revision, canonical_revision_digest),
    FOREIGN KEY (tenant_id, workspace_id, source_id)
        REFERENCES public.asset_sources (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, integration_id)
        REFERENCES public.integrations (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_source_revisions_schema_ck CHECK (
        asset_catalog_json_object_valid(canonical_profile_manifest, 2, 16384) AND
        public.asset_catalog_sha256_valid(profile_manifest_sha256) AND
        pg_catalog.encode(pg_catalog.sha256(canonical_profile_manifest), 'hex') = profile_manifest_sha256 AND
        asset_catalog_json_object_valid(canonical_provider_schema, 2, 65536) AND
        public.asset_catalog_sha256_valid(canonical_provider_schema_sha256) AND
        pg_catalog.encode(pg_catalog.sha256(canonical_provider_schema), 'hex') = canonical_provider_schema_sha256
    ),
    CONSTRAINT asset_source_revisions_reference_ck CHECK (
        (credential_reference_id IS NULL OR public.asset_catalog_opaque_reference_valid(credential_reference_id)) AND
        (trust_reference_id IS NULL OR public.asset_catalog_opaque_reference_valid(trust_reference_id)) AND
        (network_policy_reference_id IS NULL OR public.asset_catalog_opaque_reference_valid(network_policy_reference_id)) AND
        (schedule_expression IS NULL OR asset_catalog_text_valid(schedule_expression, 256))
    ),
    CONSTRAINT asset_source_revisions_typed_extension_ck CHECK (
        (typed_extension_code IS NULL) = (prepared_extension_digest IS NULL) AND
        (typed_extension_code IS NULL OR (
            asset_catalog_code_valid(typed_extension_code, 128) AND
            public.asset_catalog_sha256_valid(prepared_extension_digest)
        ))
    ),
    CONSTRAINT asset_source_revisions_validation_ck CHECK (
        (state = 'DRAFT' AND validation_run_id IS NULL AND validation_digest IS NULL) OR
        (state = 'VALIDATING' AND validation_run_id IS NOT NULL AND validation_digest IS NULL) OR
        (state IN ('VALIDATED', 'REJECTED', 'PUBLISHED', 'SUPERSEDED') AND
            validation_run_id IS NOT NULL AND asset_catalog_sha256_valid(validation_digest))
    )
);

CREATE UNIQUE INDEX asset_source_revisions_published_uk
    ON public.asset_source_revisions (tenant_id, workspace_id, source_id)
    WHERE state = 'PUBLISHED';

CREATE TABLE public.asset_source_revision_authorities (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    environment_id uuid NOT NULL,
    canonical_ordinal integer NOT NULL CHECK (canonical_ordinal BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (tenant_id, workspace_id, source_id, source_revision, environment_id),
    UNIQUE (tenant_id, workspace_id, source_id, source_revision, canonical_ordinal),
    FOREIGN KEY (tenant_id, workspace_id, source_id, source_revision)
        REFERENCES public.asset_source_revisions (
            tenant_id, workspace_id, source_id, revision
        ) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES public.environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_source_revision_authorities_created_at_ck CHECK (isfinite(created_at))
);

CREATE TABLE public.asset_source_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    source_revision_digest text NOT NULL CHECK (asset_catalog_sha256_valid(source_revision_digest)),
    run_kind text NOT NULL CHECK (run_kind IN (
        'VALIDATION', 'DISCOVERY', 'CSV_IMPORT', 'API_INGESTION', 'MANUAL_MUTATION'
    )),
    status text NOT NULL DEFAULT 'QUEUED' CHECK (status IN (
        'QUEUED', 'DELAYED', 'RUNNING', 'FINALIZING',
        'SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED'
    )),
    stage_code text NOT NULL DEFAULT 'WAITING' CHECK (stage_code IN (
        'WAITING', 'DELAYED', 'VALIDATING', 'READING', 'NORMALIZING',
        'APPLYING', 'CLEANING_UP', 'COMPLETED'
    )),
    stage_changed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    trigger_type text NOT NULL CHECK (trigger_type IN ('HUMAN', 'API', 'SCHEDULED')),
    gate_revision bigint NOT NULL CHECK (gate_revision >= 0),
    idempotency_key text NOT NULL CHECK (asset_catalog_idempotency_key_valid(idempotency_key)),
    request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(request_hash)),
    cursor_before_sha256 text,
    cursor_after_sha256 text,
    page_sequence bigint NOT NULL DEFAULT 0 CHECK (page_sequence >= 0),
    page_digest text,
    relation_page_sequence bigint NOT NULL DEFAULT 0 CHECK (relation_page_sequence >= 0),
    relation_page_digest text,
    final_page boolean NOT NULL DEFAULT false,
    complete_snapshot boolean NOT NULL DEFAULT false,
    effective_complete_snapshot boolean NOT NULL DEFAULT false,
    checkpoint_version bigint NOT NULL DEFAULT 0 CHECK (checkpoint_version >= 0),
    lease_owner text,
    lease_expires_at timestamptz,
    fence_epoch bigint NOT NULL DEFAULT 0 CHECK (fence_epoch >= 0),
    fence_token_hash text,
    heartbeat_sequence bigint NOT NULL DEFAULT 0 CHECK (heartbeat_sequence >= 0),
    not_before timestamptz NOT NULL DEFAULT statement_timestamp(),
    pending_transition text,
    pending_transition_reason text,
    pending_transition_not_before timestamptz,
    pending_transition_digest text,
    observed_count bigint NOT NULL DEFAULT 0 CHECK (observed_count >= 0),
    created_count bigint NOT NULL DEFAULT 0 CHECK (created_count >= 0),
    changed_count bigint NOT NULL DEFAULT 0 CHECK (changed_count >= 0),
    unchanged_count bigint NOT NULL DEFAULT 0 CHECK (unchanged_count >= 0),
    conflict_count bigint NOT NULL DEFAULT 0 CHECK (conflict_count >= 0),
    missing_count bigint NOT NULL DEFAULT 0 CHECK (missing_count >= 0),
    stale_count bigint NOT NULL DEFAULT 0 CHECK (stale_count >= 0),
    restored_count bigint NOT NULL DEFAULT 0 CHECK (restored_count >= 0),
    tombstoned_count bigint NOT NULL DEFAULT 0 CHECK (tombstoned_count >= 0),
    rejected_count bigint NOT NULL DEFAULT 0 CHECK (rejected_count >= 0),
    work_result_kind text CHECK (work_result_kind IS NULL OR work_result_kind IN (
        'DATA_PROJECTION', 'VALIDATION_PROOF', 'FAILURE_INTENT'
    )),
    work_result_status text CHECK (work_result_status IS NULL OR work_result_status IN (
        'SUCCEEDED', 'PARTIAL', 'FAILED'
    )),
    work_result_digest text,
    work_result_recorded_at timestamptz,
    validation_outcome text CHECK (validation_outcome IS NULL OR validation_outcome IN ('SUCCEEDED', 'FAILED')),
    validation_digest text,
    validation_proof_digest text,
    lineage_rollover_reason text,
    lineage_rollover_evidence_digest text,
    cleanup_attempt_id uuid,
    cleanup_attempt_epoch bigint NOT NULL DEFAULT 0 CHECK (cleanup_attempt_epoch >= 0),
    cleanup_status text NOT NULL DEFAULT 'NOT_OPENED' CHECK (cleanup_status IN (
        'NOT_OPENED', 'PENDING', 'REVOKED', 'NO_CREDENTIAL', 'UNCERTAIN'
    )),
    cleanup_digest text,
    terminal_failure_override text CHECK (
        terminal_failure_override IS NULL OR terminal_failure_override = 'CLEANUP_UNCERTAIN'
    ),
    terminal_failure_override_digest text,
    terminal_command_sha256 text,
    failure_code text,
    trace_id text,
    started_at timestamptz,
    heartbeat_at timestamptz,
    completed_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, id),
    UNIQUE (tenant_id, workspace_id, source_id, id),
    UNIQUE (tenant_id, workspace_id, source_id, id, source_revision),
    UNIQUE (tenant_id, workspace_id, source_id, id, source_revision, source_revision_digest),
    UNIQUE (workspace_id, idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, source_id, source_revision, source_revision_digest)
        REFERENCES public.asset_source_revisions (tenant_id, workspace_id, source_id, revision, canonical_revision_digest) ON DELETE RESTRICT,
    CONSTRAINT asset_source_runs_hash_ck CHECK (
        (cursor_before_sha256 IS NULL OR asset_catalog_sha256_valid(cursor_before_sha256)) AND
        (cursor_after_sha256 IS NULL OR asset_catalog_sha256_valid(cursor_after_sha256)) AND
        (page_digest IS NULL OR asset_catalog_sha256_valid(page_digest)) AND
        (relation_page_digest IS NULL OR asset_catalog_sha256_valid(relation_page_digest)) AND
        (validation_digest IS NULL OR asset_catalog_sha256_valid(validation_digest)) AND
        (validation_proof_digest IS NULL OR asset_catalog_sha256_valid(validation_proof_digest)) AND
        (work_result_digest IS NULL OR asset_catalog_sha256_valid(work_result_digest)) AND
        (lineage_rollover_evidence_digest IS NULL OR asset_catalog_sha256_valid(lineage_rollover_evidence_digest)) AND
        (pending_transition_digest IS NULL OR asset_catalog_sha256_valid(pending_transition_digest)) AND
        (cleanup_digest IS NULL OR asset_catalog_sha256_valid(cleanup_digest)) AND
        (terminal_failure_override_digest IS NULL OR asset_catalog_sha256_valid(terminal_failure_override_digest)) AND
        (terminal_command_sha256 IS NULL OR asset_catalog_sha256_valid(terminal_command_sha256)) AND
        (fence_token_hash IS NULL OR asset_catalog_sha256_valid(fence_token_hash))
    ),
    CONSTRAINT asset_source_runs_lease_ck CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL AND fence_token_hash IS NULL) OR
        (asset_catalog_code_valid(lease_owner, 256) AND lease_expires_at IS NOT NULL AND fence_token_hash IS NOT NULL AND fence_epoch > 0)
    ),
    CONSTRAINT asset_source_runs_snapshot_ck CHECK (
        (NOT complete_snapshot OR final_page) AND
        (NOT effective_complete_snapshot OR complete_snapshot) AND
        (NOT effective_complete_snapshot OR rejected_count = 0)
    ),
    CONSTRAINT asset_source_runs_pending_transition_ck CHECK ((
        (pending_transition IS NULL AND pending_transition_reason IS NULL AND
            pending_transition_not_before IS NULL AND pending_transition_digest IS NULL) OR
        (pending_transition = 'DELAY' AND
            pending_transition_reason IN ('PROVIDER_RETRY_AFTER', 'TRANSPORT_BACKOFF') AND
            pending_transition_not_before IS NOT NULL AND isfinite(pending_transition_not_before) AND
            asset_catalog_sha256_valid(pending_transition_digest))
    ) IS TRUE),
    CONSTRAINT asset_source_runs_cleanup_ck CHECK (
        (cleanup_status = 'NOT_OPENED' AND cleanup_attempt_id IS NULL AND cleanup_attempt_epoch = 0 AND cleanup_digest IS NULL) OR
        (cleanup_status = 'PENDING' AND cleanup_attempt_id IS NOT NULL AND cleanup_attempt_epoch > 0 AND cleanup_digest IS NULL) OR
        (cleanup_status = 'REVOKED' AND cleanup_attempt_id IS NOT NULL AND cleanup_attempt_epoch > 0 AND asset_catalog_sha256_valid(cleanup_digest)) OR
        (cleanup_status = 'NO_CREDENTIAL' AND cleanup_attempt_id IS NULL AND cleanup_attempt_epoch = 0 AND asset_catalog_sha256_valid(cleanup_digest)) OR
        (cleanup_status = 'UNCERTAIN' AND cleanup_attempt_id IS NOT NULL AND cleanup_attempt_epoch > 0 AND asset_catalog_sha256_valid(cleanup_digest))
    ),
    CONSTRAINT asset_source_runs_work_result_ck CHECK ((
        (work_result_kind IS NULL AND work_result_status IS NULL AND work_result_digest IS NULL AND
            work_result_recorded_at IS NULL AND validation_outcome IS NULL AND
            validation_digest IS NULL AND validation_proof_digest IS NULL) OR
        (work_result_kind = 'DATA_PROJECTION' AND run_kind <> 'VALIDATION' AND
            work_result_status IN ('SUCCEEDED', 'PARTIAL') AND asset_catalog_sha256_valid(work_result_digest) AND
            work_result_recorded_at IS NOT NULL AND isfinite(work_result_recorded_at) AND
            validation_outcome IS NULL AND validation_digest IS NULL AND validation_proof_digest IS NULL) OR
        (work_result_kind = 'VALIDATION_PROOF' AND run_kind = 'VALIDATION' AND
            work_result_status IN ('SUCCEEDED', 'FAILED') AND validation_outcome = work_result_status AND
            asset_catalog_sha256_valid(work_result_digest) AND asset_catalog_sha256_valid(validation_digest) AND
            asset_catalog_sha256_valid(validation_proof_digest) AND work_result_recorded_at IS NOT NULL AND
            isfinite(work_result_recorded_at)) OR
        (work_result_kind = 'FAILURE_INTENT' AND work_result_status = 'FAILED' AND
            asset_catalog_sha256_valid(work_result_digest) AND work_result_recorded_at IS NOT NULL AND
            isfinite(work_result_recorded_at) AND validation_outcome IS NULL AND
            validation_digest IS NULL AND validation_proof_digest IS NULL)
    ) IS TRUE),
    CONSTRAINT asset_source_runs_lineage_rollover_ck CHECK (
        (lineage_rollover_reason IS NULL AND lineage_rollover_evidence_digest IS NULL) OR
        (asset_catalog_code_valid(lineage_rollover_reason, 128) AND
            asset_catalog_sha256_valid(lineage_rollover_evidence_digest) AND run_kind <> 'VALIDATION')
    ),
    CONSTRAINT asset_source_runs_terminal_override_ck CHECK ((
        (terminal_failure_override IS NULL AND terminal_failure_override_digest IS NULL) OR
        (terminal_failure_override = 'CLEANUP_UNCERTAIN' AND
            asset_catalog_sha256_valid(terminal_failure_override_digest) AND cleanup_status = 'UNCERTAIN')
    ) IS TRUE),
    CONSTRAINT asset_source_runs_state_ck CHECK (
        (status = 'QUEUED' AND stage_code = 'WAITING' AND started_at IS NULL AND heartbeat_at IS NULL AND
            completed_at IS NULL AND lease_owner IS NULL AND work_result_kind IS NULL AND cleanup_status = 'NOT_OPENED') OR
        (status = 'DELAYED' AND stage_code = 'DELAYED' AND started_at IS NOT NULL AND completed_at IS NULL AND
            lease_owner IS NULL AND lease_expires_at IS NULL AND fence_token_hash IS NULL AND work_result_kind IS NULL) OR
        (status = 'RUNNING' AND stage_code IN ('VALIDATING', 'READING', 'NORMALIZING', 'APPLYING', 'CLEANING_UP') AND
            started_at IS NOT NULL AND heartbeat_at IS NOT NULL AND completed_at IS NULL AND
            lease_owner IS NOT NULL AND heartbeat_sequence > 0 AND work_result_kind IS NULL) OR
        (status = 'FINALIZING' AND stage_code = 'CLEANING_UP' AND started_at IS NOT NULL AND
            heartbeat_at IS NOT NULL AND completed_at IS NULL AND lease_owner IS NOT NULL AND
            heartbeat_sequence > 0 AND work_result_kind IS NOT NULL) OR
        (status IN ('SUCCEEDED', 'PARTIAL', 'FAILED') AND stage_code = 'COMPLETED' AND
            completed_at IS NOT NULL AND asset_catalog_sha256_valid(terminal_command_sha256)) OR
        (status = 'CANCELLED' AND stage_code = 'COMPLETED' AND completed_at IS NOT NULL AND
            terminal_command_sha256 IS NULL)
    ),
    CONSTRAINT asset_source_runs_failure_ck CHECK (
        (failure_code IS NULL OR asset_catalog_code_valid(failure_code, 128)) AND
        (trace_id IS NULL OR asset_catalog_text_valid(trace_id, 128))
    ),
    CONSTRAINT asset_source_runs_time_ck CHECK (
        isfinite(not_before) AND isfinite(stage_changed_at) AND isfinite(created_at) AND
        (lease_expires_at IS NULL OR isfinite(lease_expires_at)) AND
        (started_at IS NULL OR isfinite(started_at)) AND
        (heartbeat_at IS NULL OR (heartbeat_at >= started_at AND isfinite(heartbeat_at))) AND
        (completed_at IS NULL OR (completed_at >= COALESCE(started_at, created_at) AND isfinite(completed_at)))
    )
);

COMMENT ON COLUMN public.asset_source_runs.fence_token_hash IS 'Lowercase SHA-256 hash only; raw lease or fence tokens are forbidden';
COMMENT ON COLUMN public.asset_source_runs.terminal_command_sha256 IS 'Exact FramedTupleV1 digest bound to the immutable TERMINAL_COMMITTED audit receipt';

CREATE OR REPLACE FUNCTION public.asset_catalog_framed_value_v1(candidate bytea)
RETURNS bytea AS $$
BEGIN
    IF candidate IS NULL THEN
        RETURN decode('00', 'hex');
    END IF;
    RETURN decode('01', 'hex') OPERATOR(pg_catalog.||)
        pg_catalog.int4send(pg_catalog.octet_length(candidate)) OPERATOR(pg_catalog.||)
        candidate;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_source_revision_binding_digest(
    candidate public.asset_source_revisions
) RETURNS text AS $$
DECLARE
    framed bytea;
BEGIN
    IF candidate.tenant_id IS NULL OR candidate.workspace_id IS NULL OR
       candidate.source_id IS NULL OR candidate.revision IS NULL OR candidate.revision < 1 OR
       candidate.source_definition_digest IS NULL OR
       pg_catalog.octet_length(candidate.source_definition_digest) <> 64 OR
       candidate.source_definition_digest COLLATE "C" ~ '[^a-f0-9]' OR
       candidate.sync_mode IS NULL OR candidate.sync_mode NOT IN ('MANUAL', 'ON_DEMAND', 'SCHEDULED') OR
       candidate.authority_scope_digest IS NULL OR
       pg_catalog.octet_length(candidate.authority_scope_digest) <> 64 OR
       candidate.authority_scope_digest COLLATE "C" ~ '[^a-f0-9]' OR
       candidate.rate_limit_requests IS NULL OR candidate.rate_limit_window_seconds IS NULL OR
       candidate.backpressure_base_seconds IS NULL OR candidate.backpressure_max_seconds IS NULL OR
       candidate.rate_limit_requests NOT BETWEEN 1 AND 1000000 OR
       candidate.rate_limit_window_seconds NOT BETWEEN 1 AND 86400 OR
       candidate.backpressure_base_seconds NOT BETWEEN 1 AND 86400 OR
       candidate.backpressure_max_seconds NOT BETWEEN candidate.backpressure_base_seconds AND 604800 OR
       candidate.profile_code IS NULL OR
       pg_catalog.octet_length(candidate.profile_code) NOT BETWEEN 1 AND 128 OR
       candidate.profile_code <> pg_catalog.btrim(candidate.profile_code) OR
       candidate.profile_code COLLATE "C" ~ '[[:cntrl:]]' OR
       pg_catalog.left(candidate.profile_code, 1) COLLATE "C" !~ '^[A-Za-z0-9]$' OR
       candidate.profile_code COLLATE "C" ~ '[^A-Za-z0-9_.:/@+-]' OR
       (candidate.credential_reference_id IS NOT NULL AND
            candidate.credential_reference_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') OR
       (candidate.trust_reference_id IS NOT NULL AND
            candidate.trust_reference_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') OR
       (candidate.network_policy_reference_id IS NOT NULL AND
            candidate.network_policy_reference_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') OR
       (candidate.schedule_expression IS NOT NULL AND
            (pg_catalog.octet_length(candidate.schedule_expression) NOT BETWEEN 1 AND 256 OR
             candidate.schedule_expression <> pg_catalog.btrim(candidate.schedule_expression) OR
             candidate.schedule_expression COLLATE "C" ~ '[[:cntrl:]]')) OR
       (candidate.typed_extension_code IS NULL) <> (candidate.prepared_extension_digest IS NULL) OR
       (candidate.typed_extension_code IS NOT NULL AND
            (pg_catalog.octet_length(candidate.typed_extension_code) NOT BETWEEN 1 AND 128 OR
             candidate.typed_extension_code <> pg_catalog.btrim(candidate.typed_extension_code) OR
             candidate.typed_extension_code COLLATE "C" ~ '[[:cntrl:]]' OR
             pg_catalog.left(candidate.typed_extension_code, 1) COLLATE "C" !~ '^[A-Za-z0-9]$' OR
             candidate.typed_extension_code COLLATE "C" ~ '[^A-Za-z0-9_.:/@+-]')) OR
       (candidate.prepared_extension_digest IS NOT NULL AND
            (pg_catalog.octet_length(candidate.prepared_extension_digest) <> 64 OR
             candidate.prepared_extension_digest COLLATE "C" ~ '[^a-f0-9]')) THEN
        RETURN NULL;
    END IF;

    framed :=
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to('asset-source-revision-binding.v1', 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.tenant_id::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.workspace_id::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.source_id::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.revision::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.decode(candidate.source_definition_digest, 'hex')
        ) ||
        public.asset_catalog_framed_value_v1(
            CASE WHEN candidate.integration_id IS NULL THEN NULL
                 ELSE pg_catalog.convert_to(candidate.integration_id::text, 'UTF8') END
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.sync_mode, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            CASE WHEN candidate.credential_reference_id IS NULL THEN NULL
                 ELSE pg_catalog.convert_to(candidate.credential_reference_id, 'UTF8') END
        ) ||
        public.asset_catalog_framed_value_v1(
            CASE WHEN candidate.trust_reference_id IS NULL THEN NULL
                 ELSE pg_catalog.convert_to(candidate.trust_reference_id, 'UTF8') END
        ) ||
        public.asset_catalog_framed_value_v1(
            CASE WHEN candidate.network_policy_reference_id IS NULL THEN NULL
                 ELSE pg_catalog.convert_to(candidate.network_policy_reference_id, 'UTF8') END
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.decode(candidate.authority_scope_digest, 'hex')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.rate_limit_requests::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.rate_limit_window_seconds::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.backpressure_base_seconds::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.backpressure_max_seconds::text, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(candidate.profile_code, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            CASE WHEN candidate.schedule_expression IS NULL THEN NULL
                 ELSE pg_catalog.convert_to(candidate.schedule_expression, 'UTF8') END
        ) ||
        public.asset_catalog_framed_value_v1(
            CASE WHEN candidate.typed_extension_code IS NULL THEN NULL
                 ELSE pg_catalog.convert_to(candidate.typed_extension_code, 'UTF8') END
        ) ||
        public.asset_catalog_framed_value_v1(
            CASE WHEN candidate.prepared_extension_digest IS NULL THEN NULL
                 ELSE pg_catalog.decode(candidate.prepared_extension_digest, 'hex') END
        );

    RETURN pg_catalog.encode(pg_catalog.sha256(framed), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_source_run_no_credential_digest(candidate public.asset_source_runs)
RETURNS text AS $$
DECLARE
    framed bytea;
BEGIN
    IF candidate.id IS NULL OR candidate.source_revision < 1 OR
       NOT asset_catalog_sha256_valid(candidate.source_revision_digest) OR candidate.fence_epoch < 1 THEN
        RETURN NULL;
    END IF;
    framed :=
        asset_catalog_framed_value_v1(convert_to('asset-run-no-credential.v1', 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.id::text, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.source_revision::text, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(decode(candidate.source_revision_digest, 'hex')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.fence_epoch::text, 'UTF8'));
    RETURN pg_catalog.encode(pg_catalog.sha256(framed), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_source_run_delay_intent_digest(
    candidate public.asset_source_runs,
    desired_reason text,
    desired_not_before timestamptz
) RETURNS text AS $$
DECLARE
    framed bytea;
BEGIN
    IF candidate.id IS NULL OR candidate.cleanup_attempt_epoch < 0 OR
       desired_reason IS NULL OR desired_not_before IS NULL OR NOT isfinite(desired_not_before) THEN
        RETURN NULL;
    END IF;
    framed :=
        asset_catalog_framed_value_v1(convert_to('asset-run-delay-intent.v1', 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.id::text, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(CASE WHEN candidate.cleanup_attempt_id IS NULL THEN NULL ELSE convert_to(candidate.cleanup_attempt_id::text, 'UTF8') END) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.cleanup_attempt_epoch::text, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(desired_reason, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(
            to_char(desired_not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'UTF8'
        ));
    RETURN pg_catalog.encode(pg_catalog.sha256(framed), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_source_run_failure_override_digest(
    candidate public.asset_source_runs,
    desired_failure_code text
) RETURNS text AS $$
DECLARE
    framed bytea;
BEGIN
    IF candidate.id IS NULL OR candidate.cleanup_status <> 'UNCERTAIN' OR
       NOT asset_catalog_sha256_valid(candidate.cleanup_digest) OR desired_failure_code IS NULL OR
       (candidate.work_result_kind IS NOT NULL AND candidate.work_result_digest IS NULL) OR
       (candidate.work_result_digest IS NOT NULL AND NOT asset_catalog_sha256_valid(candidate.work_result_digest)) THEN
        RETURN NULL;
    END IF;
    framed :=
        asset_catalog_framed_value_v1(convert_to('asset-run-terminal-failure-override.v1', 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.id::text, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(CASE WHEN candidate.work_result_kind IS NULL THEN NULL ELSE convert_to(candidate.work_result_kind, 'UTF8') END) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(CASE WHEN candidate.work_result_digest IS NULL THEN NULL ELSE decode(candidate.work_result_digest, 'hex') END) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.cleanup_status, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(decode(candidate.cleanup_digest, 'hex')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(desired_failure_code, 'UTF8'));
    RETURN pg_catalog.encode(pg_catalog.sha256(framed), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.asset_catalog_source_run_terminal_digest(
    candidate public.asset_source_runs,
    desired_status text,
    desired_failure_code text
) RETURNS text AS $$
DECLARE
    framed bytea;
BEGIN
    IF candidate.id IS NULL OR desired_status NOT IN ('SUCCEEDED', 'PARTIAL', 'FAILED') OR
       candidate.work_result_kind IS NULL OR NOT asset_catalog_sha256_valid(candidate.work_result_digest) OR
       NOT (
            (candidate.cleanup_status IN ('REVOKED', 'NO_CREDENTIAL', 'UNCERTAIN') AND
                asset_catalog_sha256_valid(candidate.cleanup_digest)) OR
            (candidate.cleanup_status = 'NOT_OPENED' AND candidate.cleanup_attempt_id IS NULL AND
                candidate.cleanup_attempt_epoch = 0 AND candidate.cleanup_digest IS NULL AND
                desired_status = 'FAILED' AND candidate.work_result_kind = 'FAILURE_INTENT' AND
                candidate.work_result_status = 'FAILED' AND desired_failure_code IS NOT NULL AND
                candidate.failure_code IS NOT DISTINCT FROM desired_failure_code AND
                candidate.terminal_failure_override IS NULL AND
                candidate.terminal_failure_override_digest IS NULL AND
                candidate.pending_transition IS NULL AND candidate.pending_transition_reason IS NULL AND
                candidate.pending_transition_not_before IS NULL AND candidate.pending_transition_digest IS NULL AND
                candidate.page_sequence = 0 AND candidate.page_digest IS NULL AND
                candidate.relation_page_sequence = 0 AND candidate.relation_page_digest IS NULL AND
                candidate.cursor_after_sha256 IS NULL AND NOT candidate.final_page AND
                NOT candidate.complete_snapshot AND NOT candidate.effective_complete_snapshot AND
                candidate.observed_count = 0 AND candidate.created_count = 0 AND
                candidate.changed_count = 0 AND candidate.unchanged_count = 0 AND
                candidate.conflict_count = 0 AND candidate.missing_count = 0 AND
                candidate.stale_count = 0 AND candidate.restored_count = 0 AND
                candidate.tombstoned_count = 0 AND candidate.rejected_count = 0 AND
                candidate.lineage_rollover_reason IS NULL AND
                candidate.lineage_rollover_evidence_digest IS NULL)
       ) OR
       (candidate.terminal_failure_override_digest IS NOT NULL AND
           NOT asset_catalog_sha256_valid(candidate.terminal_failure_override_digest)) THEN
        RETURN NULL;
    END IF;
    framed :=
        asset_catalog_framed_value_v1(convert_to('asset-run-terminal.v1', 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.id::text, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(desired_status, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.work_result_kind, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(decode(candidate.work_result_digest, 'hex')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(convert_to(candidate.cleanup_status, 'UTF8')) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(CASE WHEN candidate.cleanup_digest IS NULL THEN NULL ELSE decode(candidate.cleanup_digest, 'hex') END) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(CASE WHEN candidate.terminal_failure_override IS NULL THEN NULL ELSE convert_to(candidate.terminal_failure_override, 'UTF8') END) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(CASE WHEN candidate.terminal_failure_override_digest IS NULL THEN NULL ELSE decode(candidate.terminal_failure_override_digest, 'hex') END) OPERATOR(pg_catalog.||)
        asset_catalog_framed_value_v1(CASE WHEN desired_failure_code IS NULL THEN NULL ELSE convert_to(desired_failure_code, 'UTF8') END);
    RETURN pg_catalog.encode(pg_catalog.sha256(framed), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public, pg_temp;

CREATE INDEX asset_source_runs_history_idx
    ON public.asset_source_runs (tenant_id, workspace_id, source_id, created_at DESC, id DESC);
CREATE INDEX asset_source_runs_queued_claim_idx
    ON public.asset_source_runs (not_before, created_at, id) WHERE status IN ('QUEUED', 'DELAYED');
CREATE INDEX asset_source_runs_expired_lease_idx
    ON public.asset_source_runs (lease_expires_at, id) WHERE status = 'RUNNING';
CREATE INDEX asset_source_runs_cleanup_reclaim_idx
    ON public.asset_source_runs (lease_expires_at, id) WHERE status = 'FINALIZING';
CREATE UNIQUE INDEX asset_source_runs_nonterminal_uk
    ON public.asset_source_runs (tenant_id, workspace_id, source_id)
    WHERE status IN ('QUEUED', 'DELAYED', 'RUNNING', 'FINALIZING');

ALTER TABLE public.asset_source_revisions
    ADD CONSTRAINT asset_source_revisions_validation_run_fk
        FOREIGN KEY (tenant_id, workspace_id, source_id, validation_run_id)
        REFERENCES public.asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT;

ALTER TABLE public.asset_sources
    ADD CONSTRAINT asset_sources_published_revision_fk
        FOREIGN KEY (tenant_id, workspace_id, id, published_revision, published_revision_digest)
        REFERENCES public.asset_source_revisions (tenant_id, workspace_id, source_id, revision, canonical_revision_digest) ON DELETE RESTRICT,
    ADD CONSTRAINT asset_sources_validated_run_fk
        FOREIGN KEY (tenant_id, workspace_id, id, validated_run_id)
        REFERENCES public.asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT asset_sources_last_success_run_fk
        FOREIGN KEY (tenant_id, workspace_id, id, last_success_run_id)
        REFERENCES public.asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT asset_sources_last_complete_snapshot_run_fk
        FOREIGN KEY (tenant_id, workspace_id, id, last_complete_snapshot_run_id)
        REFERENCES public.asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT;

CREATE TABLE public.asset_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    source_id uuid NOT NULL,
    run_id uuid NOT NULL,
    provider_kind text NOT NULL CHECK (asset_catalog_provider_kind_valid(provider_kind)),
    external_id text NOT NULL CHECK (asset_catalog_text_valid(external_id, 512)),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    canonical_revision_digest text NOT NULL CHECK (asset_catalog_sha256_valid(canonical_revision_digest)),
    source_definition_digest text NOT NULL CHECK (asset_catalog_sha256_valid(source_definition_digest)),
    observed_at timestamptz NOT NULL,
    freshness_kind text NOT NULL CHECK (freshness_kind IN (
        'CATALOG_SEQUENCE', 'OBJECT_SEQUENCE', 'OBJECT_TIME_SEQUENCE', 'CHECKPOINT_SEQUENCE'
    )),
    freshness_order_time timestamptz,
    freshness_order_sequence bigint NOT NULL CHECK (freshness_order_sequence > 0),
    provider_version_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(provider_version_sha256)),
    provider_fact_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(provider_fact_sha256)),
    fingerprint_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(fingerprint_sha256)),
    provider_provenance_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(provider_provenance_sha256)),
    previous_observation_id uuid,
    previous_chain_sha256 text,
    observation_chain_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(observation_chain_sha256)),
    accepted_checkpoint_version bigint NOT NULL CHECK (accepted_checkpoint_version > 0),
    run_fence_epoch bigint NOT NULL CHECK (run_fence_epoch > 0),
    run_page_sequence bigint NOT NULL CHECK (run_page_sequence > 0),
    schema_version text NOT NULL CHECK (asset_catalog_code_valid(schema_version, 128)),
    normalized_document bytea,
    document_sha256 text,
    field_provenance bytea NOT NULL,
    field_provenance_sha256 text NOT NULL,
    tombstone boolean NOT NULL DEFAULT false,
    tombstone_reason_code text,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, source_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, source_id, id),
    CONSTRAINT asset_observations_same_run_object_uk UNIQUE (tenant_id, workspace_id, source_id, run_id, provider_kind, external_id),
    UNIQUE (tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id, id, observation_chain_sha256),
    UNIQUE (
        tenant_id, workspace_id, environment_id, source_id, provider_kind,
        external_id, source_revision, observed_at, observation_chain_sha256, id
    ),
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES public.environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_observations_source_provider_fk FOREIGN KEY (
        tenant_id, workspace_id, source_id, provider_kind
    ) REFERENCES public.asset_sources (
        tenant_id, workspace_id, id, provider_kind
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_observations_source_revision_fk FOREIGN KEY (
        tenant_id, workspace_id, source_id, source_revision, canonical_revision_digest
    ) REFERENCES public.asset_source_revisions (
        tenant_id, workspace_id, source_id, revision, canonical_revision_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_observations_run_revision_fk FOREIGN KEY (
        tenant_id, workspace_id, source_id, run_id, source_revision, canonical_revision_digest
    ) REFERENCES public.asset_source_runs (
        tenant_id, workspace_id, source_id, id, source_revision, source_revision_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_observations_previous_exact_fk FOREIGN KEY (
        tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id,
        previous_observation_id, previous_chain_sha256
    ) REFERENCES public.asset_observations (
        tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id,
        id, observation_chain_sha256
    ) MATCH SIMPLE ON DELETE RESTRICT,
    CONSTRAINT asset_observations_document_ck CHECK (
        (NOT tombstone AND normalized_document IS NOT NULL AND
            asset_catalog_json_object_valid(normalized_document, 2, 65536) AND
            asset_catalog_sha256_valid(document_sha256) AND
            pg_catalog.encode(pg_catalog.sha256(normalized_document), 'hex') = document_sha256 AND tombstone_reason_code IS NULL) OR
        (tombstone AND normalized_document IS NULL AND document_sha256 IS NULL AND
            asset_catalog_code_valid(tombstone_reason_code, 128))
    ),
    CONSTRAINT asset_observations_provenance_ck CHECK (
        asset_catalog_field_provenance_valid(field_provenance) AND
        asset_catalog_sha256_valid(field_provenance_sha256) AND
        pg_catalog.encode(pg_catalog.sha256(field_provenance), 'hex') = field_provenance_sha256
    ),
    CONSTRAINT asset_observations_previous_pair_ck CHECK (
        (previous_observation_id IS NULL AND previous_chain_sha256 IS NULL) OR
        (previous_observation_id IS NOT NULL AND asset_catalog_sha256_valid(previous_chain_sha256))
    ),
    CONSTRAINT asset_observations_freshness_ck CHECK (
        (freshness_kind IN ('CATALOG_SEQUENCE', 'OBJECT_SEQUENCE', 'CHECKPOINT_SEQUENCE') AND
            freshness_order_time IS NULL) OR
        (freshness_kind = 'OBJECT_TIME_SEQUENCE' AND freshness_order_time IS NOT NULL AND
            isfinite(freshness_order_time))
    ),
    CONSTRAINT asset_observations_checkpoint_freshness_ck CHECK (
        freshness_kind <> 'CHECKPOINT_SEQUENCE' OR freshness_order_sequence = accepted_checkpoint_version
    ),
    CONSTRAINT asset_observations_time_ck CHECK (
        isfinite(observed_at) AND isfinite(created_at)
    )
);

CREATE TABLE public.assets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    source_id uuid NOT NULL,
    provider_kind text NOT NULL CHECK (asset_catalog_provider_kind_valid(provider_kind)),
    external_id text NOT NULL CHECK (asset_catalog_text_valid(external_id, 512)),
    kind text NOT NULL,
    display_name text NOT NULL CHECK (asset_catalog_text_valid(display_name, 256)),
    owner_group text CHECK (owner_group IS NULL OR asset_catalog_text_valid(owner_group, 256)),
    criticality text NOT NULL DEFAULT 'LOW' CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    data_classification text NOT NULL DEFAULT 'INTERNAL' CHECK (data_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    lifecycle text NOT NULL DEFAULT 'DISCOVERED' CHECK (lifecycle IN ('DISCOVERED', 'ACTIVE', 'STALE', 'QUARANTINED', 'RETIRED')),
    mapping_status text NOT NULL DEFAULT 'UNRESOLVED' CHECK (mapping_status IN ('EXACT', 'AMBIGUOUS', 'UNRESOLVED')),
    last_observation_id uuid NOT NULL,
    last_observation_chain_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(last_observation_chain_sha256)),
    last_observed_at timestamptz NOT NULL,
    last_source_revision bigint NOT NULL CHECK (last_source_revision > 0),
    create_idempotency_key text NOT NULL CHECK (asset_catalog_idempotency_key_valid(create_idempotency_key)),
    create_request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(create_request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, source_id, provider_kind, external_id),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, source_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, source_id, external_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id, id),
    UNIQUE (workspace_id, create_idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES public.environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT assets_source_provider_fk FOREIGN KEY (
        tenant_id, workspace_id, source_id, provider_kind
    ) REFERENCES public.asset_sources (
        tenant_id, workspace_id, id, provider_kind
    ) ON DELETE RESTRICT,
    CONSTRAINT assets_last_observation_exact_fk FOREIGN KEY (
        tenant_id, workspace_id, environment_id, source_id, provider_kind,
        external_id, last_source_revision, last_observed_at,
        last_observation_chain_sha256, last_observation_id
    ) REFERENCES public.asset_observations (
        tenant_id, workspace_id, environment_id, source_id, provider_kind,
        external_id, source_revision, observed_at, observation_chain_sha256, id
    ) ON DELETE RESTRICT,
    CONSTRAINT assets_last_source_revision_fk FOREIGN KEY (
        tenant_id, workspace_id, source_id, last_source_revision
    ) REFERENCES public.asset_source_revisions (
        tenant_id, workspace_id, source_id, revision
    ) ON DELETE RESTRICT,
    CONSTRAINT assets_kind_check CHECK (kind IN (
        'SERVICE', 'LINUX_VM', 'WINDOWS_VM', 'BARE_METAL_HOST',
        'KUBERNETES_CLUSTER', 'KUBERNETES_NAMESPACE', 'KUBERNETES_WORKLOAD',
        'DATABASE_INSTANCE', 'DATABASE', 'METRICS_SOURCE', 'LOG_SOURCE',
        'TRACE_SOURCE', 'AWX_INVENTORY', 'ARGO_APPLICATION', 'CI_PIPELINE',
        'GIT_REPOSITORY', 'CLOUD_RESOURCE'
    )),
    CONSTRAINT assets_labels_ck CHECK (
        asset_catalog_labels_valid(labels)
    ),
    CONSTRAINT assets_time_ck CHECK (
        isfinite(last_observed_at) AND isfinite(created_at) AND isfinite(updated_at)
    )
);

CREATE INDEX assets_catalog_idx
    ON public.assets (tenant_id, workspace_id, environment_id, lower(display_name), id)
    WHERE lifecycle <> 'RETIRED';
CREATE INDEX assets_filter_idx
    ON public.assets (tenant_id, workspace_id, environment_id, kind, lifecycle, mapping_status, id);

CREATE TABLE public.asset_type_details (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    source_id uuid NOT NULL,
    provider_kind text NOT NULL CHECK (asset_catalog_provider_kind_valid(provider_kind)),
    external_id text NOT NULL CHECK (asset_catalog_text_valid(external_id, 512)),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    source_observed_at timestamptz NOT NULL,
    source_observation_chain_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(source_observation_chain_sha256)),
    revision bigint NOT NULL CHECK (revision > 0),
    schema_version text NOT NULL CHECK (asset_catalog_code_valid(schema_version, 128)),
    source_observation_id uuid NOT NULL,
    details_document bytea NOT NULL,
    details_sha256 text NOT NULL,
    actor_id text NOT NULL CHECK (asset_catalog_text_valid(actor_id, 256)),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, asset_id, revision),
    CONSTRAINT asset_type_details_asset_identity_fk FOREIGN KEY (
        tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id, asset_id
    ) REFERENCES public.assets (
        tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_type_details_observation_fact_fk FOREIGN KEY (
        tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id,
        source_revision, source_observed_at, source_observation_chain_sha256, source_observation_id
    ) REFERENCES public.asset_observations (
        tenant_id, workspace_id, environment_id, source_id, provider_kind, external_id,
        source_revision, observed_at, observation_chain_sha256, id
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_type_details_document_ck CHECK (
        asset_catalog_json_object_valid(details_document, 2, 65536) AND
        asset_catalog_sha256_valid(details_sha256) AND
        pg_catalog.encode(pg_catalog.sha256(details_document), 'hex') = details_sha256
    ),
    CONSTRAINT asset_type_details_time_ck CHECK (
        isfinite(source_observed_at) AND isfinite(created_at)
    )
);

CREATE TABLE public.asset_conflicts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    candidate_asset_id uuid,
    candidate_service_id uuid,
    source_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    conflict_type text NOT NULL CHECK (asset_catalog_code_valid(conflict_type, 128)),
    field_name text CHECK (field_name IS NULL OR asset_catalog_code_valid(field_name, 128)),
    existing_value_sha256 text,
    candidate_value_sha256 text,
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'RESOLVED', 'REJECTED')),
    resolution text CHECK (resolution IS NULL OR resolution IN (
        'CONFIRM_EXACT', 'REJECT_CANDIDATE', 'KEEP_UNRESOLVED', 'QUARANTINE_ASSET'
    )),
    resolution_reason_code text,
    resolved_by text,
    resolved_at timestamptz,
    resolution_idempotency_key text,
    resolution_request_hash text,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (workspace_id, resolution_idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
        REFERENCES public.assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, candidate_asset_id)
        REFERENCES public.assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, candidate_service_id)
        REFERENCES public.services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_conflicts_source_observation_fk FOREIGN KEY (
        tenant_id, workspace_id, environment_id, source_id, observation_id
    ) REFERENCES public.asset_observations (
        tenant_id, workspace_id, environment_id, source_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_conflicts_candidate_ck CHECK (
        candidate_asset_id IS NOT NULL OR candidate_service_id IS NOT NULL OR
        (field_name IS NOT NULL AND candidate_value_sha256 IS NOT NULL)
    ),
    CONSTRAINT asset_conflicts_hash_ck CHECK (
        (existing_value_sha256 IS NULL OR asset_catalog_sha256_valid(existing_value_sha256)) AND
        (candidate_value_sha256 IS NULL OR asset_catalog_sha256_valid(candidate_value_sha256))
    ),
    CONSTRAINT asset_conflicts_resolution_ck CHECK (
        (status = 'OPEN' AND resolution IS NULL AND resolution_reason_code IS NULL AND
            resolved_by IS NULL AND resolved_at IS NULL AND resolution_idempotency_key IS NULL AND resolution_request_hash IS NULL) OR
        (status IN ('RESOLVED', 'REJECTED') AND resolution IS NOT NULL AND
            asset_catalog_code_valid(resolution_reason_code, 128) AND
            asset_catalog_text_valid(resolved_by, 256) AND resolved_at IS NOT NULL AND
            asset_catalog_idempotency_key_valid(resolution_idempotency_key) AND
            asset_catalog_sha256_valid(resolution_request_hash))
    )
);

CREATE UNIQUE INDEX asset_conflicts_open_queue_uk
    ON public.asset_conflicts (
        tenant_id, workspace_id, source_id, observation_id, conflict_type,
        field_name, candidate_asset_id, candidate_service_id
    ) NULLS NOT DISTINCT WHERE status = 'OPEN';
CREATE INDEX asset_conflicts_open_idx
    ON public.asset_conflicts (tenant_id, workspace_id, environment_id, created_at, id)
    WHERE status = 'OPEN';

CREATE TABLE public.asset_relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    canonical_revision_digest text NOT NULL CHECK (asset_catalog_sha256_valid(canonical_revision_digest)),
    last_run_id uuid NOT NULL,
    last_page_sequence bigint NOT NULL CHECK (last_page_sequence > 0),
    accepted_checkpoint_version bigint NOT NULL CHECK (accepted_checkpoint_version > 0),
    run_fence_epoch bigint NOT NULL CHECK (run_fence_epoch > 0),
    relation_page_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(relation_page_sha256)),
    source_environment_id uuid NOT NULL,
    target_environment_id uuid NOT NULL,
    source_asset_id uuid NOT NULL,
    target_asset_id uuid NOT NULL,
    from_external_id text NOT NULL CHECK (asset_catalog_text_valid(from_external_id, 512)),
    to_external_id text NOT NULL CHECK (asset_catalog_text_valid(to_external_id, 512)),
    relationship_type text NOT NULL,
    provider_path_code text NOT NULL CHECK (asset_catalog_code_valid(provider_path_code, 128)),
    confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    freshness_kind text NOT NULL CHECK (freshness_kind IN (
        'CATALOG_SEQUENCE', 'OBJECT_SEQUENCE', 'OBJECT_TIME_SEQUENCE', 'CHECKPOINT_SEQUENCE'
    )),
    freshness_order_time timestamptz,
    freshness_order_sequence bigint NOT NULL CHECK (freshness_order_sequence > 0),
    provider_version_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(provider_version_sha256)),
    relation_fact_sha256 text NOT NULL CHECK (asset_catalog_sha256_valid(relation_fact_sha256)),
    provenance text NOT NULL CHECK (provenance IN ('MANUAL', 'DISCOVERED', 'MERGE_DECISION')),
    provenance_source_id uuid,
    cross_environment_policy_reference_id text,
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
    idempotency_key text NOT NULL CHECK (asset_catalog_idempotency_key_valid(idempotency_key)),
    request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, id),
    UNIQUE (workspace_id, idempotency_key),
    CONSTRAINT asset_relationships_type_check CHECK (relationship_type IN (
        'RUNS_ON', 'CONTAINS', 'DEPENDS_ON', 'MONITORED_BY', 'LOGS_TO', 'TRACES_TO',
        'DELIVERED_BY', 'MANAGED_BY', 'PRIMARY_RUNTIME_FOR'
    )),
    CONSTRAINT asset_relationships_source_revision_fk FOREIGN KEY (
        tenant_id, workspace_id, source_id, source_revision, canonical_revision_digest
    ) REFERENCES public.asset_source_revisions (
        tenant_id, workspace_id, source_id, revision, canonical_revision_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_relationships_last_run_fk FOREIGN KEY (
        tenant_id, workspace_id, source_id, last_run_id, source_revision, canonical_revision_digest
    ) REFERENCES public.asset_source_runs (
        tenant_id, workspace_id, source_id, id, source_revision, source_revision_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_relationships_source_asset_fk FOREIGN KEY (
        tenant_id, workspace_id, source_environment_id, source_id, from_external_id, source_asset_id
    ) REFERENCES public.assets (
        tenant_id, workspace_id, environment_id, source_id, external_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT asset_relationships_target_asset_fk FOREIGN KEY (
        tenant_id, workspace_id, target_environment_id, source_id, to_external_id, target_asset_id
    ) REFERENCES public.assets (
        tenant_id, workspace_id, environment_id, source_id, external_id, id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, provenance_source_id)
        REFERENCES public.asset_sources (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_relationships_distinct_ck CHECK (source_asset_id <> target_asset_id),
    CONSTRAINT asset_relationships_cross_environment_ck CHECK (
        (source_environment_id = target_environment_id AND cross_environment_policy_reference_id IS NULL) OR
        (source_environment_id <> target_environment_id AND
            public.asset_catalog_opaque_reference_valid(cross_environment_policy_reference_id))
    ),
    CONSTRAINT asset_relationships_freshness_ck CHECK (
        (freshness_kind IN ('CATALOG_SEQUENCE', 'OBJECT_SEQUENCE', 'CHECKPOINT_SEQUENCE') AND
            freshness_order_time IS NULL) OR
        (freshness_kind = 'OBJECT_TIME_SEQUENCE' AND freshness_order_time IS NOT NULL AND
            isfinite(freshness_order_time))
    ),
    CONSTRAINT asset_relationships_provenance_ck CHECK ((
        (provenance = 'DISCOVERED' AND provenance_source_id = source_id) OR
        (provenance IN ('MANUAL', 'MERGE_DECISION') AND provenance_source_id IS NULL)
    ) IS TRUE),
    CONSTRAINT asset_relationships_time_ck CHECK (
        isfinite(created_at) AND isfinite(updated_at)
    )
);

CREATE UNIQUE INDEX asset_relationships_active_edge_uk ON public.asset_relationships (tenant_id, workspace_id, source_asset_id, target_asset_id, relationship_type) WHERE status = 'ACTIVE';

CREATE TABLE public.service_asset_bindings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    service_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    binding_role text NOT NULL CHECK (binding_role IN (
        'PRIMARY_RUNTIME', 'DEPENDENCY', 'OBSERVABILITY_SOURCE', 'DELIVERY_TARGET', 'MANAGED_TARGET'
    )),
    mapping_status text NOT NULL CHECK (mapping_status IN ('EXACT', 'AMBIGUOUS', 'UNRESOLVED')),
    provenance text NOT NULL CHECK (provenance IN ('MANUAL', 'DISCOVERED', 'MERGE_DECISION')),
    provenance_source_id uuid,
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
    idempotency_key text NOT NULL CHECK (asset_catalog_idempotency_key_valid(idempotency_key)),
    request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (workspace_id, idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, service_id)
        REFERENCES public.services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT service_asset_bindings_service_environment_fk
        FOREIGN KEY (service_id, environment_id)
        REFERENCES public.service_bindings (service_id, environment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
        REFERENCES public.assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    CONSTRAINT service_asset_bindings_provenance_asset_fk FOREIGN KEY (
        tenant_id, workspace_id, environment_id, provenance_source_id, asset_id
    ) REFERENCES public.assets (
        tenant_id, workspace_id, environment_id, source_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT service_asset_bindings_provenance_ck CHECK (
        (provenance = 'DISCOVERED' AND provenance_source_id IS NOT NULL) OR
        (provenance IN ('MANUAL', 'MERGE_DECISION') AND provenance_source_id IS NULL)
    )
);

CREATE UNIQUE INDEX service_asset_bindings_active_uk ON public.service_asset_bindings (tenant_id, workspace_id, environment_id, service_id, asset_id, binding_role) WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX asset_management_idempotency_audit_uk ON public.audit_records (workspace_id, request_id) WHERE resource_type IN ('ASSET', 'ASSET_SOURCE', 'ASSET_SOURCE_RUN', 'ASSET_CONFLICT', 'SERVICE_ASSET_BINDING');

CREATE OR REPLACE FUNCTION public.validate_asset_management_audit_insert() RETURNS trigger AS $$
BEGIN
    IF NEW.resource_type IN ('ASSET', 'ASSET_SOURCE', 'ASSET_SOURCE_RUN', 'ASSET_CONFLICT', 'SERVICE_ASSET_BINDING')
       AND (NOT asset_catalog_idempotency_key_valid(NEW.request_id) OR NOT asset_catalog_sha256_valid(NEW.payload_hash)) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'asset-management audit requires a bounded idempotency key and canonical SHA-256 payload hash',
            CONSTRAINT = 'asset_management_audit_shape_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_management_audit_insert_guard
    BEFORE INSERT ON public.audit_records
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_management_audit_insert();

CREATE OR REPLACE FUNCTION public.reject_asset_catalog_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = TG_TABLE_NAME || ' is append-only',
        CONSTRAINT = TG_TABLE_NAME || '_immutable';
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_observations_immutable
    BEFORE UPDATE ON public.asset_observations
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_immutable();

CREATE TRIGGER asset_type_details_immutable
    BEFORE UPDATE ON public.asset_type_details
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_immutable();

CREATE TRIGGER asset_source_revision_authorities_immutable
    BEFORE UPDATE ON public.asset_source_revision_authorities
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_immutable();

CREATE OR REPLACE FUNCTION public.reject_asset_catalog_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = TG_TABLE_NAME || ' physical delete is forbidden',
        CONSTRAINT = TG_TABLE_NAME || '_delete_guard';
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.reject_asset_catalog_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = TG_TABLE_NAME || ' physical truncate is forbidden',
        CONSTRAINT = TG_TABLE_NAME || '_truncate_guard';
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_sources_delete_guard
    BEFORE DELETE ON public.asset_sources
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER asset_source_revisions_delete_guard
    BEFORE DELETE ON public.asset_source_revisions
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER asset_source_revision_authorities_delete_guard
    BEFORE DELETE ON public.asset_source_revision_authorities
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER asset_source_runs_delete_guard
    BEFORE DELETE ON public.asset_source_runs
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER asset_observations_delete_guard
    BEFORE DELETE ON public.asset_observations
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER assets_delete_guard
    BEFORE DELETE ON public.assets
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER asset_type_details_delete_guard
    BEFORE DELETE ON public.asset_type_details
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER asset_conflicts_delete_guard
    BEFORE DELETE ON public.asset_conflicts
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER asset_relationships_delete_guard
    BEFORE DELETE ON public.asset_relationships
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();
CREATE TRIGGER service_asset_bindings_delete_guard
    BEFORE DELETE ON public.service_asset_bindings
    FOR EACH ROW EXECUTE FUNCTION public.reject_asset_catalog_delete();

CREATE TRIGGER asset_sources_truncate_guard
    BEFORE TRUNCATE ON public.asset_sources
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER asset_source_revisions_truncate_guard
    BEFORE TRUNCATE ON public.asset_source_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER asset_source_revision_authorities_truncate_guard
    BEFORE TRUNCATE ON public.asset_source_revision_authorities
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER asset_source_runs_truncate_guard
    BEFORE TRUNCATE ON public.asset_source_runs
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER asset_observations_truncate_guard
    BEFORE TRUNCATE ON public.asset_observations
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER assets_truncate_guard
    BEFORE TRUNCATE ON public.assets
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER asset_type_details_truncate_guard
    BEFORE TRUNCATE ON public.asset_type_details
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER asset_conflicts_truncate_guard
    BEFORE TRUNCATE ON public.asset_conflicts
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER asset_relationships_truncate_guard
    BEFORE TRUNCATE ON public.asset_relationships
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();
CREATE TRIGGER service_asset_bindings_truncate_guard
    BEFORE TRUNCATE ON public.service_asset_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_asset_catalog_truncate();

CREATE OR REPLACE FUNCTION public.enforce_assets_transition() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.lifecycle <> 'DISCOVERED' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset must start DISCOVERED at version one',
                CONSTRAINT = 'assets_initial_state_guard';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;

    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.environment_id IS DISTINCT FROM NEW.environment_id OR
       OLD.source_id IS DISTINCT FROM NEW.source_id OR
       OLD.provider_kind IS DISTINCT FROM NEW.provider_kind OR
       OLD.external_id IS DISTINCT FROM NEW.external_id OR
       OLD.kind IS DISTINCT FROM NEW.kind THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset scope and source identity are immutable',
            CONSTRAINT = 'assets_identity_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset version must advance exactly once',
            CONSTRAINT = 'assets_version_guard';
    END IF;
    IF OLD.lifecycle = 'RETIRED' AND NEW.lifecycle <> 'RETIRED' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'retired asset is terminal',
            CONSTRAINT = 'assets_retired_terminal_guard';
    END IF;
    IF OLD.lifecycle IS DISTINCT FROM NEW.lifecycle AND NOT (
        (OLD.lifecycle = 'DISCOVERED' AND NEW.lifecycle IN ('ACTIVE', 'QUARANTINED', 'RETIRED')) OR
        (OLD.lifecycle = 'ACTIVE' AND NEW.lifecycle IN ('STALE', 'QUARANTINED', 'RETIRED')) OR
        (OLD.lifecycle = 'STALE' AND NEW.lifecycle IN ('ACTIVE', 'QUARANTINED', 'RETIRED')) OR
        (OLD.lifecycle = 'QUARANTINED' AND NEW.lifecycle IN ('ACTIVE', 'RETIRED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'invalid asset lifecycle transition',
            CONSTRAINT = 'assets_lifecycle_guard';
    END IF;
    IF (
        OLD.last_observation_id IS DISTINCT FROM NEW.last_observation_id OR
        OLD.last_observation_chain_sha256 IS DISTINCT FROM NEW.last_observation_chain_sha256 OR
        OLD.last_observed_at IS DISTINCT FROM NEW.last_observed_at OR
        OLD.last_source_revision IS DISTINCT FROM NEW.last_source_revision
    ) AND (
        OLD.owner_group IS DISTINCT FROM NEW.owner_group OR
        OLD.criticality IS DISTINCT FROM NEW.criticality OR
        OLD.data_classification IS DISTINCT FROM NEW.data_classification OR
        OLD.labels IS DISTINCT FROM NEW.labels
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'discovery cannot overwrite asset governance fields',
            CONSTRAINT = 'assets_governance_guard';
    END IF;
    IF NEW.last_observed_at < OLD.last_observed_at OR NEW.last_source_revision < OLD.last_source_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset observation projection cannot move backward',
            CONSTRAINT = 'assets_observation_projection_guard';
    END IF;
    IF (OLD.last_observation_id IS DISTINCT FROM NEW.last_observation_id) IS DISTINCT FROM
       (OLD.last_observation_chain_sha256 IS DISTINCT FROM NEW.last_observation_chain_sha256) OR
       (OLD.last_observation_id IS DISTINCT FROM NEW.last_observation_id AND
            NEW.last_observed_at <= OLD.last_observed_at) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset projection must advance observation id, chain, and catalog time together',
            CONSTRAINT = 'assets_observation_projection_guard';
    END IF;
    NEW.created_at := OLD.created_at;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER assets_transition_guard
    BEFORE INSERT OR UPDATE ON public.assets
    FOR EACH ROW EXECUTE FUNCTION public.enforce_assets_transition();

CREATE OR REPLACE FUNCTION public.enforce_asset_conflict_transition() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'OPEN' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset conflict must start OPEN at version one',
                CONSTRAINT = 'asset_conflicts_initial_state_guard';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF OLD.status IN ('RESOLVED', 'REJECTED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'resolved asset conflict is terminal',
            CONSTRAINT = 'asset_conflicts_terminal_guard';
    END IF;
    IF (to_jsonb(OLD) - ARRAY[
            'status', 'resolution', 'resolution_reason_code', 'resolved_by', 'resolved_at',
            'resolution_idempotency_key', 'resolution_request_hash', 'version', 'updated_at'
        ]) IS DISTINCT FROM
       (to_jsonb(NEW) - ARRAY[
            'status', 'resolution', 'resolution_reason_code', 'resolved_by', 'resolved_at',
            'resolution_idempotency_key', 'resolution_request_hash', 'version', 'updated_at'
        ]) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset conflict scope, candidates, and evidence are immutable',
            CONSTRAINT = 'asset_conflicts_identity_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset conflict version must advance exactly once',
            CONSTRAINT = 'asset_conflicts_version_guard';
    END IF;
    IF NEW.status NOT IN ('RESOLVED', 'REJECTED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'open asset conflict can only reach a terminal decision',
            CONSTRAINT = 'asset_conflicts_state_guard';
    END IF;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_conflicts_transition_guard
    BEFORE INSERT OR UPDATE ON public.asset_conflicts
    FOR EACH ROW EXECUTE FUNCTION public.enforce_asset_conflict_transition();

CREATE OR REPLACE FUNCTION public.enforce_asset_catalog_edge_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = TG_TABLE_NAME || ' must start at version one',
                CONSTRAINT = TG_TABLE_NAME || '_initial_version_guard';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF (to_jsonb(OLD) - ARRAY['status', 'version', 'updated_at']) IS DISTINCT FROM
       (to_jsonb(NEW) - ARRAY['status', 'version', 'updated_at']) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = TG_TABLE_NAME || ' identity, provenance, and request are immutable',
            CONSTRAINT = TG_TABLE_NAME || '_identity_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = TG_TABLE_NAME || ' version must advance exactly once',
            CONSTRAINT = TG_TABLE_NAME || '_version_guard';
    END IF;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION public.enforce_asset_relationship_mutation() RETURNS trigger AS $$
DECLARE
    bound_run asset_source_runs%ROWTYPE;
    bound_source asset_sources%ROWTYPE;
    admitted_at timestamptz := clock_timestamp();
BEGIN
    SELECT run.* INTO bound_run
    FROM asset_source_runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.workspace_id = NEW.workspace_id
      AND run.source_id = NEW.source_id
      AND run.id = NEW.last_run_id
      AND run.source_revision = NEW.source_revision
      AND run.source_revision_digest = NEW.canonical_revision_digest
    FOR SHARE OF run;
    IF NOT FOUND OR bound_run.run_kind = 'VALIDATION' OR bound_run.status <> 'RUNNING' OR
       bound_run.stage_code NOT IN ('NORMALIZING', 'APPLYING') OR
       bound_run.lease_owner IS NULL OR bound_run.lease_expires_at IS NULL OR
       bound_run.lease_expires_at <= admitted_at OR bound_run.fence_epoch <= 0 OR
       NEW.run_fence_epoch IS DISTINCT FROM bound_run.fence_epoch OR
       NEW.last_page_sequence IS DISTINCT FROM bound_run.page_sequence + 1 OR
       NEW.last_page_sequence IS DISTINCT FROM bound_run.relation_page_sequence + 1 OR
       NEW.accepted_checkpoint_version IS DISTINCT FROM bound_run.checkpoint_version + 1 OR
       (NEW.freshness_kind IN ('CATALOG_SEQUENCE', 'CHECKPOINT_SEQUENCE') AND
           NEW.freshness_order_sequence IS DISTINCT FROM NEW.accepted_checkpoint_version) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'relationship projection requires the next exact page and checkpoint of a live fenced data run',
            CONSTRAINT = 'asset_relationships_run_admission_guard';
    END IF;

    SELECT source.* INTO bound_source
    FROM asset_sources AS source
    WHERE source.tenant_id = NEW.tenant_id
      AND source.workspace_id = NEW.workspace_id
      AND source.id = NEW.source_id
    FOR SHARE OF source;
    IF NOT FOUND OR bound_source.status <> 'ACTIVE' OR
       bound_source.published_revision IS DISTINCT FROM NEW.source_revision OR
       bound_source.published_revision_digest IS DISTINCT FROM NEW.canonical_revision_digest OR
       bound_source.checkpoint_version IS DISTINCT FROM bound_run.checkpoint_version OR
       bound_source.checkpoint_sha256 IS DISTINCT FROM
           COALESCE(bound_run.cursor_after_sha256, bound_run.cursor_before_sha256) OR
       NOT COALESCE(
           (bound_source.gate_status = 'AVAILABLE' AND
               bound_source.gate_revision = bound_run.gate_revision) OR
           (bound_source.gate_status = 'DEGRADED' AND
               bound_source.gate_reason_code = 'CHECKPOINT_LINEAGE_ROLLOVER' AND
               bound_source.gate_revision = bound_run.gate_revision + 1 AND
               bound_run.lineage_rollover_reason IS NOT NULL AND
               bound_run.lineage_rollover_evidence_digest IS NOT NULL),
           false
       ) OR
       (NEW.freshness_kind = 'CATALOG_SEQUENCE') IS DISTINCT FROM
           (bound_run.run_kind = 'MANUAL_MUTATION' AND bound_source.source_kind = 'MANUAL') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'relationship source gate, revision, or checkpoint drifted from its live run',
            CONSTRAINT = 'asset_relationships_run_admission_guard';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'relationship must start at version one',
                CONSTRAINT = 'asset_relationships_initial_state_guard';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.id IS DISTINCT FROM NEW.id OR OLD.source_id IS DISTINCT FROM NEW.source_id OR
       OLD.source_environment_id IS DISTINCT FROM NEW.source_environment_id OR
       OLD.target_environment_id IS DISTINCT FROM NEW.target_environment_id OR
       OLD.source_asset_id IS DISTINCT FROM NEW.source_asset_id OR
       OLD.target_asset_id IS DISTINCT FROM NEW.target_asset_id OR
       OLD.from_external_id IS DISTINCT FROM NEW.from_external_id OR
       OLD.to_external_id IS DISTINCT FROM NEW.to_external_id OR
       OLD.relationship_type IS DISTINCT FROM NEW.relationship_type OR
       OLD.provider_path_code IS DISTINCT FROM NEW.provider_path_code OR
       OLD.provenance IS DISTINCT FROM NEW.provenance OR
       OLD.provenance_source_id IS DISTINCT FROM NEW.provenance_source_id OR
       OLD.cross_environment_policy_reference_id IS DISTINCT FROM NEW.cross_environment_policy_reference_id OR
       OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key OR
       OLD.request_hash IS DISTINCT FROM NEW.request_hash OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'relationship identity, provenance, and creation request are immutable',
            CONSTRAINT = 'asset_relationships_identity_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'relationship version must advance exactly once',
            CONSTRAINT = 'asset_relationships_version_guard';
    END IF;
    IF NEW.last_run_id IS NOT DISTINCT FROM OLD.last_run_id OR
       NEW.source_revision < OLD.source_revision OR
       (NEW.source_revision = OLD.source_revision AND (
            NEW.freshness_kind IS DISTINCT FROM OLD.freshness_kind OR
            (NEW.freshness_kind = 'OBJECT_TIME_SEQUENCE' AND (
                (NEW.freshness_order_time, NEW.freshness_order_sequence) <
                    (OLD.freshness_order_time, OLD.freshness_order_sequence) OR
                ((NEW.freshness_order_time, NEW.freshness_order_sequence) =
                    (OLD.freshness_order_time, OLD.freshness_order_sequence) AND (
                        NEW.provider_version_sha256 IS DISTINCT FROM OLD.provider_version_sha256 OR
                        NEW.relation_fact_sha256 IS DISTINCT FROM OLD.relation_fact_sha256
                ))
            )) OR
            (NEW.freshness_kind <> 'OBJECT_TIME_SEQUENCE' AND (
                NEW.freshness_order_sequence < OLD.freshness_order_sequence OR
                (NEW.freshness_order_sequence = OLD.freshness_order_sequence AND (
                    NEW.provider_version_sha256 IS DISTINCT FROM OLD.provider_version_sha256 OR
                    NEW.relation_fact_sha256 IS DISTINCT FROM OLD.relation_fact_sha256
                ))
            ))
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'relationship freshness must satisfy the closed revision and order comparison',
            CONSTRAINT = 'asset_relationships_freshness_monotonic_guard';
    END IF;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_relationships_mutation_guard
    BEFORE INSERT OR UPDATE ON public.asset_relationships
    FOR EACH ROW EXECUTE FUNCTION public.enforce_asset_relationship_mutation();

CREATE OR REPLACE FUNCTION public.validate_asset_relationship_page_closure() RETURNS trigger AS $$
DECLARE
    committed_run asset_source_runs%ROWTYPE;
    committed_source asset_sources%ROWTYPE;
BEGIN
    SELECT run.* INTO committed_run
    FROM asset_source_runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.workspace_id = NEW.workspace_id
      AND run.source_id = NEW.source_id
      AND run.id = NEW.last_run_id
      AND run.source_revision = NEW.source_revision
      AND run.source_revision_digest = NEW.canonical_revision_digest
    FOR SHARE OF run;
    IF NOT FOUND OR committed_run.fence_epoch IS DISTINCT FROM NEW.run_fence_epoch OR
       committed_run.page_sequence IS DISTINCT FROM NEW.last_page_sequence OR
       committed_run.relation_page_sequence IS DISTINCT FROM NEW.last_page_sequence OR
       committed_run.relation_page_digest IS DISTINCT FROM NEW.relation_page_sha256 OR
       committed_run.checkpoint_version IS DISTINCT FROM NEW.accepted_checkpoint_version OR
       committed_run.page_digest IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'relationship page did not close with its exact run coordinates',
            CONSTRAINT = 'asset_relationships_page_closure_guard';
    END IF;

    SELECT source.* INTO committed_source
    FROM asset_sources AS source
    WHERE source.tenant_id = NEW.tenant_id
      AND source.workspace_id = NEW.workspace_id
      AND source.id = NEW.source_id
    FOR SHARE OF source;
    IF NOT FOUND OR committed_source.status <> 'ACTIVE' OR
       committed_source.published_revision IS DISTINCT FROM NEW.source_revision OR
       committed_source.published_revision_digest IS DISTINCT FROM NEW.canonical_revision_digest OR
       committed_source.checkpoint_version IS DISTINCT FROM NEW.accepted_checkpoint_version OR
       committed_source.checkpoint_sha256 IS DISTINCT FROM
           COALESCE(committed_run.cursor_after_sha256, committed_run.cursor_before_sha256) OR
       NOT COALESCE(
           (committed_run.lineage_rollover_reason IS NULL AND
                committed_source.gate_status = 'AVAILABLE' AND
                committed_source.gate_revision = committed_run.gate_revision) OR
           (committed_run.lineage_rollover_reason IS NOT NULL AND
                committed_source.gate_status = 'DEGRADED' AND
                committed_source.gate_reason_code = 'CHECKPOINT_LINEAGE_ROLLOVER' AND
                committed_source.gate_revision = committed_run.gate_revision + 1),
           false
       ) OR
       NOT EXISTS (
           SELECT 1
           FROM audit_records AS audit
           WHERE audit.tenant_id = NEW.tenant_id
             AND audit.workspace_id = NEW.workspace_id
             AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
             AND audit.actor_type = 'SYSTEM'
             AND audit.actor_id = committed_run.lease_owner
             AND audit.action = 'RELATION_PAGE_COMMITTED'
             AND audit.resource_type = 'ASSET_SOURCE_RUN'
             AND audit.resource_id = NEW.last_run_id::text
             AND audit.request_id = 'source-relation-page:' || NEW.last_run_id::text || ':' || NEW.last_page_sequence::text
             AND audit.payload_hash = NEW.relation_page_sha256
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'relationship page lacks its exact source checkpoint or immutable receipt',
            CONSTRAINT = 'asset_relationships_page_closure_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE CONSTRAINT TRIGGER asset_relationships_page_closure_guard
    AFTER INSERT OR UPDATE ON public.asset_relationships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_relationship_page_closure();

CREATE TRIGGER service_asset_bindings_mutation_guard
    BEFORE INSERT OR UPDATE ON public.service_asset_bindings
    FOR EACH ROW EXECUTE FUNCTION public.enforce_asset_catalog_edge_mutation();

CREATE OR REPLACE FUNCTION public.enforce_asset_sources_mutation() RETURNS trigger AS $$
DECLARE
    gate_is_valid boolean;
    validation_gate_is_valid boolean;
    rollover_gate_is_valid boolean := false;
    validated_publication_continues boolean := false;
    checkpoint_changed boolean;
    publication_changed boolean;
    gate_status_changed boolean;
    gate_reason_changed boolean;
    gate_revision_changed boolean;
    validation_binding_changed boolean;
    last_success_is_valid boolean;
    last_complete_is_valid boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (NEW.source_kind = 'MANUAL') IS DISTINCT FROM (NEW.provider_kind = 'MANUAL_V1') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'MANUAL source and MANUAL_V1 provider must be bound exactly together',
                CONSTRAINT = 'asset_sources_manual_provider_guard';
        END IF;
        IF NEW.version <> 1 OR NEW.status <> 'ACTIVE' OR
           NEW.gate_status <> 'UNAVAILABLE' OR NEW.gate_revision <> 0 OR
           NEW.published_revision IS NOT NULL OR NEW.published_revision_digest IS NOT NULL OR
           NEW.validated_run_id IS NOT NULL OR NEW.validation_digest IS NOT NULL OR
           NEW.validated_binding_digest IS NOT NULL OR
           NEW.checkpoint_ciphertext IS NOT NULL OR NEW.checkpoint_key_id IS NOT NULL OR
           NEW.checkpoint_sha256 IS NOT NULL OR NEW.checkpoint_revision <> 0 OR
           NEW.checkpoint_version <> 0 OR NEW.next_allowed_at IS NOT NULL OR
           NEW.consecutive_failures <> 0 OR NEW.last_success_run_id IS NOT NULL OR
           NEW.last_success_at IS NOT NULL OR NEW.last_complete_snapshot_run_id IS NOT NULL OR
           NEW.last_complete_snapshot_at IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source must start active at version one with a closed empty gate, checkpoint, and success state',
                CONSTRAINT = 'asset_sources_initial_state_guard';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;

    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.id IS DISTINCT FROM NEW.id OR
       OLD.source_kind IS DISTINCT FROM NEW.source_kind OR
       OLD.provider_kind IS DISTINCT FROM NEW.provider_kind OR
       OLD.create_idempotency_key IS DISTINCT FROM NEW.create_idempotency_key OR
       OLD.create_request_hash IS DISTINCT FROM NEW.create_request_hash OR
       OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source scope, provider, and creation identity are immutable',
            CONSTRAINT = 'asset_sources_identity_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source version must advance exactly once',
            CONSTRAINT = 'asset_sources_version_guard';
    END IF;
    publication_changed :=
        OLD.published_revision IS DISTINCT FROM NEW.published_revision OR
        OLD.published_revision_digest IS DISTINCT FROM NEW.published_revision_digest;
    IF NOT publication_changed AND
       (NEW.checkpoint_version < OLD.checkpoint_version OR NEW.checkpoint_version > OLD.checkpoint_version + 1) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source checkpoint version cannot regress or skip',
            CONSTRAINT = 'asset_sources_checkpoint_version_guard';
    END IF;
    checkpoint_changed :=
        OLD.checkpoint_ciphertext IS DISTINCT FROM NEW.checkpoint_ciphertext OR
        OLD.checkpoint_key_id IS DISTINCT FROM NEW.checkpoint_key_id OR
        OLD.checkpoint_sha256 IS DISTINCT FROM NEW.checkpoint_sha256 OR
        OLD.checkpoint_revision IS DISTINCT FROM NEW.checkpoint_revision;
    IF publication_changed THEN
        IF NEW.published_revision IS NULL OR NEW.checkpoint_revision <> NEW.published_revision OR
           NEW.checkpoint_version <> 0 OR NEW.checkpoint_ciphertext IS NOT NULL OR
           NEW.checkpoint_key_id IS NOT NULL OR NEW.checkpoint_sha256 IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'source publication must reset the checkpoint lineage to the new revision',
                CONSTRAINT = 'asset_sources_checkpoint_publication_guard';
        END IF;
    ELSIF checkpoint_changed AND NEW.checkpoint_version <> OLD.checkpoint_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source checkpoint mutation must advance its version exactly once',
            CONSTRAINT = 'asset_sources_checkpoint_version_guard';
    END IF;
    IF NOT publication_changed AND NOT checkpoint_changed AND
       NEW.checkpoint_version IS DISTINCT FROM OLD.checkpoint_version AND
       NEW.source_kind <> 'MANUAL' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source checkpoint version requires an encrypted checkpoint mutation',
            CONSTRAINT = 'asset_sources_checkpoint_version_guard';
    END IF;

    IF publication_changed THEN
        IF OLD.gate_status = 'VALIDATING' AND
           OLD.gate_reason_code = 'VALIDATION_IN_PROGRESS' AND
           OLD.validated_run_id IS NOT NULL AND OLD.validation_digest IS NULL AND
           OLD.validated_binding_digest IS NULL THEN
            SELECT EXISTS (
                SELECT 1
                FROM asset_source_revisions AS revision
                JOIN asset_source_runs AS validation_run
                  ON validation_run.tenant_id = revision.tenant_id
                 AND validation_run.workspace_id = revision.workspace_id
                 AND validation_run.source_id = revision.source_id
                 AND validation_run.id = revision.validation_run_id
                WHERE revision.tenant_id = NEW.tenant_id
                  AND revision.workspace_id = NEW.workspace_id
                  AND revision.source_id = NEW.id
                  AND revision.revision = NEW.published_revision
                  AND revision.canonical_revision_digest = NEW.published_revision_digest
                  AND revision.state = 'VALIDATED'
                  AND revision.validation_run_id = OLD.validated_run_id
                  AND validation_run.source_revision = revision.revision
                  AND validation_run.source_revision_digest = revision.canonical_revision_digest
                  AND validation_run.run_kind = 'VALIDATION'
                  AND validation_run.status = 'SUCCEEDED'
                  AND validation_run.stage_code = 'COMPLETED'
                  AND validation_run.gate_revision + 1 = OLD.gate_revision
                  AND validation_run.completed_at IS NOT NULL
            ) INTO validated_publication_continues;
        END IF;
        NEW.gate_status := 'UNAVAILABLE';
        NEW.gate_reason_code := CASE
            WHEN validated_publication_continues THEN 'PUBLISHED_VALIDATION_REFERENCE_DRIFT'
            ELSE 'PUBLISHED_REFERENCE_DRIFT'
        END;
        NEW.gate_revision := OLD.gate_revision + 1;
        NEW.validated_run_id := NULL;
        NEW.validation_digest := NULL;
        NEW.validated_binding_digest := NULL;
    END IF;
    IF NOT publication_changed AND OLD.gate_status = 'AVAILABLE' AND (
        OLD.validated_run_id IS DISTINCT FROM NEW.validated_run_id OR
        OLD.validation_digest IS DISTINCT FROM NEW.validation_digest OR
        OLD.validated_binding_digest IS DISTINCT FROM NEW.validated_binding_digest
    ) THEN
        NEW.gate_status := 'UNAVAILABLE';
        NEW.gate_reason_code := 'BOUND_REFERENCE_DRIFT';
        NEW.gate_revision := OLD.gate_revision + 1;
        NEW.validated_run_id := NULL;
        NEW.validation_digest := NULL;
        NEW.validated_binding_digest := NULL;
    END IF;
    IF OLD.gate_status = 'DEGRADED' AND
       (NEW.status <> 'ACTIVE' OR NEW.gate_status = 'UNAVAILABLE') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'live checkpoint-lineage rollover must reach an exact terminal gate before source deactivation',
            CONSTRAINT = 'asset_sources_rollover_gate_guard';
    END IF;
    IF NEW.status <> 'ACTIVE' AND NOT (
        NEW.gate_status = 'SUSPENDED' AND NEW.gate_reason_code = 'CLEANUP_UNCERTAIN' AND
        NEW.validated_run_id IS NULL AND NEW.validation_digest IS NULL AND
        NEW.validated_binding_digest IS NULL
    ) AND (
        OLD.status = 'ACTIVE' OR OLD.gate_status <> 'UNAVAILABLE' OR NEW.gate_status <> 'UNAVAILABLE' OR
        NEW.validated_run_id IS NOT NULL OR NEW.validation_digest IS NOT NULL OR
        NEW.validated_binding_digest IS NOT NULL
    ) THEN
        NEW.gate_status := 'UNAVAILABLE';
        NEW.gate_reason_code := 'SOURCE_NOT_ACTIVE';
        NEW.gate_revision := OLD.gate_revision + 1;
        NEW.validated_run_id := NULL;
        NEW.validation_digest := NULL;
        NEW.validated_binding_digest := NULL;
    END IF;
    IF OLD.gate_status = 'AVAILABLE' AND NEW.gate_status = 'UNAVAILABLE' AND
       NOT publication_changed AND NEW.status = 'ACTIVE' THEN
        NEW.gate_reason_code := COALESCE(NEW.gate_reason_code, 'GATE_CLOSED');
        NEW.validated_run_id := NULL;
        NEW.validation_digest := NULL;
        NEW.validated_binding_digest := NULL;
    END IF;
    IF NEW.gate_status = 'SUSPENDED' AND OLD.gate_status <> 'SUSPENDED' THEN
        NEW.validated_run_id := NULL;
        NEW.validation_digest := NULL;
        NEW.validated_binding_digest := NULL;
    END IF;
    IF OLD.gate_status = 'UNAVAILABLE' AND NEW.gate_status = 'VALIDATING' THEN
        NEW.gate_reason_code := 'VALIDATION_IN_PROGRESS';
        SELECT EXISTS (
            SELECT 1
            FROM asset_source_revisions AS revision
            JOIN asset_source_runs AS validation_run
              ON validation_run.tenant_id = revision.tenant_id
             AND validation_run.workspace_id = revision.workspace_id
             AND validation_run.source_id = revision.source_id
             AND validation_run.id = revision.validation_run_id
            WHERE revision.tenant_id = NEW.tenant_id
              AND revision.workspace_id = NEW.workspace_id
              AND revision.source_id = NEW.id
              AND revision.state = 'VALIDATING'
              AND revision.validation_run_id = NEW.validated_run_id
              AND validation_run.source_revision = revision.revision
              AND validation_run.source_revision_digest = revision.canonical_revision_digest
              AND validation_run.run_kind = 'VALIDATION'
              AND validation_run.status = 'QUEUED'
              AND validation_run.stage_code = 'WAITING'
              AND validation_run.gate_revision = OLD.gate_revision
              AND validation_run.checkpoint_version = 0
              AND validation_run.cursor_before_sha256 IS NULL
              AND validation_run.cursor_after_sha256 IS NULL
        ) INTO validation_gate_is_valid;
        IF NEW.status <> 'ACTIVE' OR NEW.validation_digest IS NOT NULL OR
           NEW.validated_binding_digest IS NOT NULL OR NOT validation_gate_is_valid THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'VALIDATING gate requires its exact newly bound queued validation run and epoch',
                CONSTRAINT = 'asset_sources_validating_gate_guard';
        END IF;
    END IF;

    gate_status_changed := OLD.gate_status IS DISTINCT FROM NEW.gate_status;
    gate_reason_changed := OLD.gate_reason_code IS DISTINCT FROM NEW.gate_reason_code;
    gate_revision_changed := OLD.gate_revision IS DISTINCT FROM NEW.gate_revision;
    validation_binding_changed :=
        OLD.validated_run_id IS DISTINCT FROM NEW.validated_run_id OR
        OLD.validation_digest IS DISTINCT FROM NEW.validation_digest OR
        OLD.validated_binding_digest IS DISTINCT FROM NEW.validated_binding_digest;

    IF OLD.gate_status = 'SUSPENDED' AND NEW.gate_status = 'SUSPENDED' AND
       (gate_reason_changed OR gate_revision_changed OR validation_binding_changed) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'suspended source gate facts are immutable until an authorized fail-close transition',
            CONSTRAINT = 'asset_sources_suspended_reopen_guard';
    END IF;
    IF OLD.gate_status = 'VALIDATING' AND NEW.gate_status = 'VALIDATING' AND
       (gate_reason_changed OR gate_revision_changed OR validation_binding_changed) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'VALIDATING source gate facts are immutable until publication or terminal fail-close',
            CONSTRAINT = 'asset_sources_validating_gate_guard';
    END IF;
    IF OLD.gate_status = 'UNAVAILABLE' AND NEW.gate_status = 'UNAVAILABLE' AND
       (gate_reason_changed OR gate_revision_changed OR validation_binding_changed) AND
       NOT publication_changed AND NOT (
            OLD.status = 'ACTIVE' AND NEW.status <> 'ACTIVE' AND
            NEW.gate_reason_code = 'SOURCE_NOT_ACTIVE' AND
            NEW.gate_revision = OLD.gate_revision + 1 AND
            NEW.validated_run_id IS NULL AND NEW.validation_digest IS NULL AND
            NEW.validated_binding_digest IS NULL
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'UNAVAILABLE source gate facts cannot be washed without publication or non-active fail-close',
            CONSTRAINT = 'asset_sources_gate_transition_guard';
    END IF;

    IF NEW.gate_revision < OLD.gate_revision OR NEW.gate_revision > OLD.gate_revision + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source gate revision cannot regress or skip',
            CONSTRAINT = 'asset_sources_gate_revision_guard';
    END IF;
    IF (gate_status_changed OR gate_reason_changed OR validation_binding_changed) AND
       NEW.gate_revision <> OLD.gate_revision + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source gate facts must advance their revision exactly once',
            CONSTRAINT = 'asset_sources_gate_transition_guard';
    END IF;
    IF gate_revision_changed AND NOT (
       gate_status_changed OR gate_reason_changed OR validation_binding_changed OR
       publication_changed) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source gate revision requires an exact gate-changing fact',
            CONSTRAINT = 'asset_sources_gate_transition_guard';
    END IF;
    IF OLD.gate_status = 'SUSPENDED' AND NEW.gate_status <> 'SUSPENDED' AND NOT (
       publication_changed AND NEW.gate_status = 'UNAVAILABLE' AND
           NEW.validated_run_id IS NULL AND NEW.validation_digest IS NULL AND
           NEW.validated_binding_digest IS NULL OR
       NEW.status <> 'ACTIVE' AND NEW.gate_status = 'UNAVAILABLE' AND
           NEW.validated_run_id IS NULL AND NEW.validation_digest IS NULL AND
           NEW.validated_binding_digest IS NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'suspended source can leave only through publication or non-active fail-close',
            CONSTRAINT = 'asset_sources_suspended_reopen_guard';
    END IF;
    IF gate_status_changed AND NOT (
       (publication_changed AND NEW.gate_status = 'UNAVAILABLE') OR
       (NEW.status <> 'ACTIVE' AND NEW.gate_status = 'UNAVAILABLE') OR
       (OLD.gate_status = 'UNAVAILABLE' AND NEW.gate_status = 'AVAILABLE') OR
       (OLD.gate_status = 'UNAVAILABLE' AND NEW.gate_status = 'VALIDATING') OR
       (OLD.gate_status = 'UNAVAILABLE' AND NEW.gate_status = 'SUSPENDED') OR
       (OLD.gate_status = 'VALIDATING' AND NEW.gate_status IN ('UNAVAILABLE', 'SUSPENDED')) OR
       (OLD.gate_status = 'AVAILABLE' AND NEW.gate_status IN ('UNAVAILABLE', 'DEGRADED', 'SUSPENDED')) OR
       (OLD.gate_status = 'DEGRADED' AND NEW.gate_status IN ('AVAILABLE', 'SUSPENDED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source gate transition is outside the closed state graph',
            CONSTRAINT = 'asset_sources_gate_transition_guard';
    END IF;
    IF NEW.gate_status = 'AVAILABLE' THEN
        SELECT EXISTS (
            SELECT 1
            FROM asset_source_revisions AS revision
            JOIN asset_source_runs AS validation_run
              ON validation_run.tenant_id = revision.tenant_id
             AND validation_run.workspace_id = revision.workspace_id
             AND validation_run.source_id = revision.source_id
             AND validation_run.id = NEW.validated_run_id
            WHERE revision.tenant_id = NEW.tenant_id
              AND revision.workspace_id = NEW.workspace_id
              AND revision.source_id = NEW.id
              AND revision.revision = NEW.published_revision
              AND revision.canonical_revision_digest = NEW.published_revision_digest
              AND revision.state = 'PUBLISHED'
              AND revision.validation_run_id = NEW.validated_run_id
              AND revision.validation_digest = NEW.validation_digest
              AND revision.canonical_revision_digest = NEW.validated_binding_digest
              AND NEW.validated_binding_digest = NEW.published_revision_digest
              AND validation_run.source_revision = revision.revision
              AND validation_run.source_revision_digest = revision.canonical_revision_digest
              AND validation_run.run_kind = 'VALIDATION'
              AND validation_run.status = 'SUCCEEDED'
              AND validation_run.stage_code = 'COMPLETED'
              AND validation_run.work_result_kind = 'VALIDATION_PROOF'
              AND validation_run.work_result_status = 'SUCCEEDED'
              AND validation_run.validation_outcome = 'SUCCEEDED'
              AND validation_run.validation_digest = NEW.validation_digest
              AND validation_run.validation_proof_digest = NEW.validation_digest
              AND validation_run.completed_at IS NOT NULL
        ) INTO gate_is_valid;
        IF OLD.gate_status = 'UNAVAILABLE' THEN
            gate_is_valid := gate_is_valid AND COALESCE(
                (OLD.gate_reason_code = 'PUBLISHED_REFERENCE_DRIFT' AND EXISTS (
                    SELECT 1
                    FROM asset_source_runs AS validation_run
                    WHERE validation_run.tenant_id = NEW.tenant_id
                      AND validation_run.workspace_id = NEW.workspace_id
                      AND validation_run.source_id = NEW.id
                      AND validation_run.id = NEW.validated_run_id
                      AND validation_run.gate_revision + 1 = OLD.gate_revision
                )) OR
                (OLD.gate_reason_code = 'PUBLISHED_VALIDATION_REFERENCE_DRIFT' AND EXISTS (
                    SELECT 1
                    FROM asset_source_runs AS validation_run
                    WHERE validation_run.tenant_id = NEW.tenant_id
                      AND validation_run.workspace_id = NEW.workspace_id
                      AND validation_run.source_id = NEW.id
                      AND validation_run.id = NEW.validated_run_id
                      AND validation_run.gate_revision + 2 = OLD.gate_revision
                )),
                false
            );
        ELSIF OLD.gate_status = 'AVAILABLE' THEN
            gate_is_valid := gate_is_valid AND NOT publication_changed AND
                OLD.gate_reason_code IS NOT DISTINCT FROM NEW.gate_reason_code AND
                OLD.gate_revision IS NOT DISTINCT FROM NEW.gate_revision AND
                OLD.validated_run_id IS NOT DISTINCT FROM NEW.validated_run_id AND
                OLD.validation_digest IS NOT DISTINCT FROM NEW.validation_digest AND
                OLD.validated_binding_digest IS NOT DISTINCT FROM NEW.validated_binding_digest;
        ELSIF OLD.gate_status = 'DEGRADED' THEN
            SELECT EXISTS (
                SELECT 1
                FROM asset_source_runs AS rollover_run
                WHERE rollover_run.tenant_id = NEW.tenant_id
                  AND rollover_run.workspace_id = NEW.workspace_id
                  AND rollover_run.source_id = NEW.id
                  AND rollover_run.run_kind <> 'VALIDATION'
                  AND rollover_run.source_revision = NEW.published_revision
                  AND rollover_run.source_revision_digest = NEW.published_revision_digest
                  AND rollover_run.lineage_rollover_reason IS NOT NULL
                  AND rollover_run.lineage_rollover_evidence_digest IS NOT NULL
                  AND rollover_run.status = 'SUCCEEDED'
                  AND rollover_run.stage_code = 'COMPLETED'
                  AND rollover_run.effective_complete_snapshot
                  AND rollover_run.completed_at IS NOT NULL
                  AND rollover_run.gate_revision + 1 = OLD.gate_revision
                  AND rollover_run.gate_revision + 2 = NEW.gate_revision
                  AND rollover_run.xmin = pg_catalog.pg_current_xact_id()::xid
            ) INTO rollover_gate_is_valid;
            gate_is_valid := gate_is_valid AND rollover_gate_is_valid AND
                OLD.gate_reason_code IS NOT DISTINCT FROM 'CHECKPOINT_LINEAGE_ROLLOVER' AND
                OLD.validated_run_id IS NOT DISTINCT FROM NEW.validated_run_id AND
                OLD.validation_digest IS NOT DISTINCT FROM NEW.validation_digest AND
                OLD.validated_binding_digest IS NOT DISTINCT FROM NEW.validated_binding_digest;
        ELSE
            gate_is_valid := false;
        END IF;
        IF NEW.status <> 'ACTIVE' OR NEW.gate_reason_code IS NOT NULL OR gate_is_valid IS NOT TRUE THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source gate requires its exact published successful validation and binding digest',
                CONSTRAINT = 'asset_sources_available_gate_guard';
        END IF;
    END IF;
    IF NEW.published_revision IS NOT NULL AND NEW.checkpoint_revision IS DISTINCT FROM NEW.published_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'asset source checkpoint must bind to the exact published revision',
            CONSTRAINT = 'asset_sources_checkpoint_revision_guard';
    END IF;
    IF NEW.source_kind = 'MANUAL' AND (
        NEW.checkpoint_ciphertext IS NOT NULL OR NEW.checkpoint_key_id IS NOT NULL OR NEW.checkpoint_sha256 IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'manual source checkpoint is a logical catalog sequence and never ciphertext',
            CONSTRAINT = 'asset_sources_manual_checkpoint_guard';
    END IF;
    IF OLD.last_success_run_id IS DISTINCT FROM NEW.last_success_run_id OR
       OLD.last_success_at IS DISTINCT FROM NEW.last_success_at THEN
        IF OLD.last_success_run_id IS NOT NULL AND NEW.last_success_run_id IS NULL AND
           NOT publication_changed THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'asset source last success pointer may be cleared only by publication',
                CONSTRAINT = 'asset_sources_last_success_guard';
        END IF;
        IF NEW.last_success_run_id IS NULL OR NEW.last_success_at IS NULL THEN
            IF NEW.last_success_run_id IS NOT NULL OR NEW.last_success_at IS NOT NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514', MESSAGE = 'asset source last success run and time must change together',
                    CONSTRAINT = 'asset_sources_last_success_ck';
            END IF;
        ELSE
            SELECT EXISTS (
                SELECT 1
                FROM asset_source_runs AS run
                WHERE run.tenant_id = NEW.tenant_id
                  AND run.workspace_id = NEW.workspace_id
                  AND run.source_id = NEW.id
                  AND run.id = NEW.last_success_run_id
                  AND run.run_kind <> 'VALIDATION'
                  AND run.status = 'SUCCEEDED'
                  AND run.source_revision = NEW.published_revision
                  AND run.source_revision_digest = NEW.published_revision_digest
                  AND run.completed_at IS NOT NULL
                  AND NEW.last_success_at = run.completed_at
            ) INTO last_success_is_valid;
            IF NOT last_success_is_valid OR
               (OLD.last_success_at IS NOT NULL AND NEW.last_success_at < OLD.last_success_at) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514', MESSAGE = 'asset source last success must reference its exact completed projection run',
                    CONSTRAINT = 'asset_sources_last_success_guard';
            END IF;
        END IF;
    END IF;
    IF OLD.last_complete_snapshot_run_id IS DISTINCT FROM NEW.last_complete_snapshot_run_id OR
       OLD.last_complete_snapshot_at IS DISTINCT FROM NEW.last_complete_snapshot_at THEN
        IF OLD.last_complete_snapshot_run_id IS NOT NULL AND
           NEW.last_complete_snapshot_run_id IS NULL AND NOT publication_changed THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'asset source complete snapshot pointer may be cleared only by publication',
                CONSTRAINT = 'asset_sources_last_complete_snapshot_guard';
        END IF;
        IF NEW.last_complete_snapshot_run_id IS NULL OR NEW.last_complete_snapshot_at IS NULL THEN
            IF NEW.last_complete_snapshot_run_id IS NOT NULL OR NEW.last_complete_snapshot_at IS NOT NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514', MESSAGE = 'asset source complete snapshot run and time must change together',
                    CONSTRAINT = 'asset_sources_last_complete_snapshot_ck';
            END IF;
        ELSE
            SELECT EXISTS (
                SELECT 1 FROM asset_source_runs AS run
                WHERE run.tenant_id = NEW.tenant_id
                  AND run.workspace_id = NEW.workspace_id
                  AND run.source_id = NEW.id
                  AND run.id = NEW.last_complete_snapshot_run_id
                  AND run.run_kind <> 'VALIDATION'
                  AND run.status = 'SUCCEEDED'
                  AND run.effective_complete_snapshot
                  AND run.source_revision = NEW.published_revision
                  AND run.source_revision_digest = NEW.published_revision_digest
                  AND run.completed_at = NEW.last_complete_snapshot_at
            ) INTO last_complete_is_valid;
            IF NOT last_complete_is_valid OR
               (OLD.last_complete_snapshot_at IS NOT NULL AND NEW.last_complete_snapshot_at < OLD.last_complete_snapshot_at) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514', MESSAGE = 'asset source complete snapshot pointer must equal its exact successful complete run',
                    CONSTRAINT = 'asset_sources_last_complete_snapshot_guard';
            END IF;
        END IF;
    END IF;
    NEW.updated_at := statement_timestamp();
    IF NEW.source_kind IN ('KUBERNETES_OPERATOR', 'AWX_INVENTORY') AND
       NEW.gate_status IN ('VALIDATING', 'AVAILABLE', 'DEGRADED') AND (
            current_setting('transaction_isolation') IS DISTINCT FROM 'serializable' OR
            public.asset_catalog_future_source_gate_admitted(NEW) IS NOT TRUE
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'future-phase source live gate is not admitted by its accepted successor hook',
            CONSTRAINT = 'asset_sources_future_phase_gate_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_sources_mutation_guard
    BEFORE INSERT OR UPDATE ON public.asset_sources
    FOR EACH ROW EXECUTE FUNCTION public.enforce_asset_sources_mutation();

CREATE OR REPLACE FUNCTION public.validate_asset_source_deferred_state() RETURNS trigger AS $$
DECLARE
    current_source public.asset_sources%ROWTYPE;
BEGIN
    SELECT * INTO current_source
    FROM public.asset_sources
    WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id AND id = NEW.id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF current_setting('transaction_isolation') IS DISTINCT FROM 'serializable' OR
           current_source.version <> 2 OR
           current_source.gate_status <> 'UNAVAILABLE' OR
           current_source.gate_revision <> 0 OR
           current_source.checkpoint_revision <> 0 OR
           current_source.checkpoint_version <> 0 OR
           current_source.published_revision IS NOT NULL OR
           current_source.validated_run_id IS NOT NULL OR
           current_source.checkpoint_ciphertext IS NOT NULL OR
           NOT EXISTS (
                SELECT 1
                FROM public.asset_source_revisions AS revision
                WHERE revision.tenant_id = current_source.tenant_id
                  AND revision.workspace_id = current_source.workspace_id
                  AND revision.source_id = current_source.id
                  AND revision.revision = 1
                  AND revision.state = 'DRAFT'
                  AND revision.expected_source_version = 1
                  AND revision.xmin = pg_catalog.pg_current_xact_id()::xid
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'asset source insert requires its exact same-transaction initial DRAFT revision',
                CONSTRAINT = 'asset_sources_initial_revision_closure_guard';
        END IF;
        IF current_source.source_kind IN ('KUBERNETES_OPERATOR', 'AWX_INVENTORY') AND
           public.asset_catalog_future_source_gate_admitted(current_source) IS NOT TRUE THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'future-phase source insert is not admitted by its accepted successor hook',
                CONSTRAINT = 'asset_sources_future_phase_gate_guard';
        END IF;
        RETURN NULL;
    END IF;
    IF current_source.published_revision IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM asset_source_revisions AS revision
        WHERE revision.tenant_id = current_source.tenant_id
          AND revision.workspace_id = current_source.workspace_id
          AND revision.source_id = current_source.id
          AND revision.revision = current_source.published_revision
          AND revision.canonical_revision_digest = current_source.published_revision_digest
          AND revision.state = 'PUBLISHED'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'asset source published pointer must resolve to the exact PUBLISHED revision',
            CONSTRAINT = 'asset_sources_published_state_guard';
    END IF;
    IF current_source.checkpoint_version > 0
       AND OLD.checkpoint_version IS DISTINCT FROM current_source.checkpoint_version
       AND OLD.published_revision IS NOT DISTINCT FROM current_source.published_revision
       AND NOT EXISTS (
            SELECT 1
            FROM asset_source_runs AS run
            WHERE run.tenant_id = current_source.tenant_id
              AND run.workspace_id = current_source.workspace_id
              AND run.source_id = current_source.id
              AND run.checkpoint_version = current_source.checkpoint_version
              AND run.source_revision = current_source.checkpoint_revision
              AND run.cursor_after_sha256 IS NOT DISTINCT FROM current_source.checkpoint_sha256
              AND run.page_sequence > 0
              AND run.run_kind <> 'VALIDATION'
              AND run.status IN ('RUNNING', 'FINALIZING', 'SUCCEEDED', 'PARTIAL', 'FAILED')
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'checkpoint advance requires the matching successful source page sequence',
            CONSTRAINT = 'asset_sources_checkpoint_page_guard';
    END IF;
    IF current_source.gate_status = 'DEGRADED' AND (
       current_source.gate_reason_code IS DISTINCT FROM 'CHECKPOINT_LINEAGE_ROLLOVER' OR NOT EXISTS (
            SELECT 1
            FROM asset_source_runs AS run
            WHERE run.tenant_id = current_source.tenant_id
              AND run.workspace_id = current_source.workspace_id
              AND run.source_id = current_source.id
              AND run.status IN ('RUNNING', 'FINALIZING', 'DELAYED')
              AND run.run_kind <> 'VALIDATION'
              AND run.source_revision = current_source.published_revision
              AND run.source_revision_digest = current_source.published_revision_digest
              AND run.gate_revision + 1 = current_source.gate_revision
              AND run.lineage_rollover_reason IS NOT NULL
              AND run.lineage_rollover_evidence_digest IS NOT NULL
              AND run.xmin = pg_catalog.pg_current_xact_id()::xid
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'degraded source gate requires its exact live checkpoint-lineage rollover run',
            CONSTRAINT = 'asset_sources_rollover_gate_guard';
    END IF;
    IF OLD.gate_status = 'DEGRADED' AND current_source.gate_status IN ('AVAILABLE', 'SUSPENDED') AND NOT EXISTS (
        SELECT 1
        FROM asset_source_runs AS run
        WHERE run.tenant_id = current_source.tenant_id
          AND run.workspace_id = current_source.workspace_id
          AND run.source_id = current_source.id
          AND run.run_kind <> 'VALIDATION'
          AND run.gate_revision + 2 = current_source.gate_revision
          AND run.lineage_rollover_reason IS NOT NULL
          AND run.lineage_rollover_evidence_digest IS NOT NULL
          AND run.xmin = pg_catalog.pg_current_xact_id()::xid
          AND run.status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED')
          AND ((current_source.gate_status = 'AVAILABLE' AND run.status = 'SUCCEEDED' AND
                current_source.gate_reason_code IS NULL AND run.effective_complete_snapshot) OR
               (current_source.gate_status = 'SUSPENDED' AND
                current_source.gate_reason_code IS NOT NULL AND run.status <> 'SUCCEEDED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'rollover gate may close only with its exact terminal successor run',
            CONSTRAINT = 'asset_sources_rollover_terminal_guard';
    END IF;
    IF OLD.gate_status IN ('UNAVAILABLE', 'VALIDATING', 'AVAILABLE') AND
       current_source.gate_status = 'SUSPENDED' AND NOT EXISTS (
        SELECT 1
        FROM asset_source_runs AS run
        WHERE run.tenant_id = current_source.tenant_id
          AND run.workspace_id = current_source.workspace_id
          AND run.source_id = current_source.id
          AND run.lineage_rollover_reason IS NULL
          AND run.status = 'FAILED'
          AND run.cleanup_status = 'UNCERTAIN'
          AND run.terminal_failure_override = 'CLEANUP_UNCERTAIN'
          AND run.completed_at IS NOT NULL
          AND run.xmin = pg_catalog.pg_current_xact_id()::xid
          AND current_source.gate_reason_code = 'CLEANUP_UNCERTAIN'
          AND current_source.gate_revision = OLD.gate_revision + 1
          AND current_source.gate_revision > run.gate_revision
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'source suspension requires its same-transaction failed cleanup-uncertain run',
            CONSTRAINT = 'asset_sources_cleanup_uncertain_terminal_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE CONSTRAINT TRIGGER asset_sources_deferred_state_guard
    AFTER INSERT OR UPDATE ON public.asset_sources
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state();

CREATE OR REPLACE FUNCTION public.enforce_asset_source_revision_transition() RETURNS trigger AS $$
DECLARE
    validation_is_valid boolean;
    current_source_version bigint;
    current_source_kind text;
    current_provider_kind text;
    expected_revision bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'DRAFT' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source revision must start DRAFT at version one',
                CONSTRAINT = 'asset_source_revisions_initial_state_guard';
        END IF;
        SELECT source.version, source.source_kind, source.provider_kind
        INTO current_source_version, current_source_kind, current_provider_kind
        FROM asset_sources AS source
        WHERE source.tenant_id = NEW.tenant_id
          AND source.workspace_id = NEW.workspace_id
          AND source.id = NEW.source_id
        FOR UPDATE OF source;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23503', MESSAGE = 'asset source revision requires its scoped stable source',
                CONSTRAINT = 'asset_source_revisions_source_fk';
        END IF;
        IF NEW.expected_source_version <> current_source_version THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'stale asset source version',
                CONSTRAINT = 'asset_source_revisions_source_version_guard';
        END IF;
        IF (current_source_kind = 'MANUAL' AND (
                current_provider_kind <> 'MANUAL_V1' OR NEW.profile_code <> 'MANUAL_V1' OR
                NEW.sync_mode <> 'MANUAL' OR NEW.credential_reference_id IS NOT NULL OR
                NEW.trust_reference_id IS NOT NULL OR NEW.network_policy_reference_id IS NOT NULL OR
                NEW.schedule_expression IS NOT NULL OR NEW.typed_extension_code IS NOT NULL OR
                NEW.prepared_extension_digest IS NOT NULL
            )) OR
           (current_source_kind <> 'MANUAL' AND (
                current_provider_kind = 'MANUAL_V1' OR NEW.profile_code = 'MANUAL_V1'
            )) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'source revision profile and opaque references must match the MANUAL/MANUAL_V1 boundary',
                CONSTRAINT = 'asset_source_revisions_manual_profile_guard';
        END IF;
        SELECT COALESCE(max(revision.revision), 0) + 1
        INTO expected_revision
        FROM asset_source_revisions AS revision
        WHERE revision.tenant_id = NEW.tenant_id
          AND revision.workspace_id = NEW.workspace_id
          AND revision.source_id = NEW.source_id;
        IF NEW.revision <> expected_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'asset source revision must be max plus one',
                CONSTRAINT = 'asset_source_revisions_sequence_guard';
        END IF;
        UPDATE asset_sources
        SET version = version + 1
        WHERE tenant_id = NEW.tenant_id
          AND workspace_id = NEW.workspace_id
          AND id = NEW.source_id
          AND version = current_source_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'stale asset source version',
                CONSTRAINT = 'asset_source_revisions_source_version_guard';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.id IS DISTINCT FROM NEW.id OR OLD.source_id IS DISTINCT FROM NEW.source_id OR
       OLD.revision IS DISTINCT FROM NEW.revision OR
       OLD.canonical_profile_manifest IS DISTINCT FROM NEW.canonical_profile_manifest OR
       OLD.profile_manifest_sha256 IS DISTINCT FROM NEW.profile_manifest_sha256 OR
       OLD.canonical_provider_schema IS DISTINCT FROM NEW.canonical_provider_schema OR
       OLD.canonical_provider_schema_sha256 IS DISTINCT FROM NEW.canonical_provider_schema_sha256 OR
       OLD.integration_id IS DISTINCT FROM NEW.integration_id OR OLD.sync_mode IS DISTINCT FROM NEW.sync_mode OR
       OLD.authority_scope_digest IS DISTINCT FROM NEW.authority_scope_digest OR
       OLD.source_definition_digest IS DISTINCT FROM NEW.source_definition_digest OR
       OLD.canonical_revision_digest IS DISTINCT FROM NEW.canonical_revision_digest OR
       OLD.credential_reference_id IS DISTINCT FROM NEW.credential_reference_id OR
       OLD.trust_reference_id IS DISTINCT FROM NEW.trust_reference_id OR
       OLD.network_policy_reference_id IS DISTINCT FROM NEW.network_policy_reference_id OR
       OLD.rate_limit_requests IS DISTINCT FROM NEW.rate_limit_requests OR
       OLD.rate_limit_window_seconds IS DISTINCT FROM NEW.rate_limit_window_seconds OR
       OLD.backpressure_base_seconds IS DISTINCT FROM NEW.backpressure_base_seconds OR
       OLD.backpressure_max_seconds IS DISTINCT FROM NEW.backpressure_max_seconds OR
       OLD.profile_code IS DISTINCT FROM NEW.profile_code OR
       OLD.schedule_expression IS DISTINCT FROM NEW.schedule_expression OR
       OLD.typed_extension_code IS DISTINCT FROM NEW.typed_extension_code OR
       OLD.prepared_extension_digest IS DISTINCT FROM NEW.prepared_extension_digest OR
       OLD.created_by IS DISTINCT FROM NEW.created_by OR
       OLD.change_reason_code IS DISTINCT FROM NEW.change_reason_code OR
       OLD.expected_source_version IS DISTINCT FROM NEW.expected_source_version OR
       OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source revision canonical content is immutable',
            CONSTRAINT = 'asset_source_revisions_canonical_immutable_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source revision version must advance exactly once',
            CONSTRAINT = 'asset_source_revisions_version_guard';
    END IF;
    IF (
        OLD.validation_run_id IS DISTINCT FROM NEW.validation_run_id OR
        OLD.validation_digest IS DISTINCT FROM NEW.validation_digest
    ) AND NOT (
        (OLD.state IN ('DRAFT', 'REJECTED') AND NEW.state = 'VALIDATING') OR
        (OLD.state = 'VALIDATING' AND NEW.state IN ('VALIDATED', 'REJECTED') AND
            NEW.validation_run_id IS NOT DISTINCT FROM OLD.validation_run_id)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'source revision validation evidence changes only across its exact bound validation transitions',
            CONSTRAINT = 'asset_source_revisions_validation_immutable_guard';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state IN ('DRAFT', 'REJECTED') AND NEW.state = 'VALIDATING') OR
        (OLD.state = 'VALIDATING' AND NEW.state IN ('VALIDATED', 'REJECTED')) OR
        (OLD.state = 'VALIDATED' AND NEW.state = 'PUBLISHED') OR
        (OLD.state = 'PUBLISHED' AND NEW.state = 'SUPERSEDED')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'invalid asset source revision state transition',
            CONSTRAINT = 'asset_source_revisions_state_guard';
    END IF;
    IF NEW.state = 'VALIDATING' AND OLD.state IN ('DRAFT', 'REJECTED') AND (
       NEW.validation_run_id IS NULL OR NEW.validation_run_id IS NOT DISTINCT FROM OLD.validation_run_id OR
       NEW.validation_digest IS NOT NULL OR NOT EXISTS (
        SELECT 1
        FROM asset_source_runs AS run
        WHERE run.tenant_id = NEW.tenant_id
          AND run.workspace_id = NEW.workspace_id
          AND run.source_id = NEW.source_id
          AND run.id = NEW.validation_run_id
          AND run.source_revision = NEW.revision
          AND run.source_revision_digest = NEW.canonical_revision_digest
          AND run.run_kind = 'VALIDATION'
          AND run.status = 'QUEUED'
          AND run.stage_code = 'WAITING'
          AND run.checkpoint_version = 0
          AND run.cursor_before_sha256 IS NULL
    )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'validation transition requires a newly appended exact validation run',
            CONSTRAINT = 'asset_source_revisions_new_validation_run_guard';
    END IF;
    IF NEW.state IN ('VALIDATED', 'PUBLISHED') THEN
        SELECT EXISTS (
            SELECT 1 FROM asset_source_runs AS run
            WHERE run.tenant_id = NEW.tenant_id
              AND run.workspace_id = NEW.workspace_id
              AND run.source_id = NEW.source_id
              AND run.id = NEW.validation_run_id
              AND run.source_revision = NEW.revision
              AND run.source_revision_digest = NEW.canonical_revision_digest
              AND run.run_kind = 'VALIDATION'
              AND run.status = 'SUCCEEDED'
              AND run.stage_code = 'COMPLETED'
              AND run.work_result_kind = 'VALIDATION_PROOF'
              AND run.work_result_status = 'SUCCEEDED'
              AND run.validation_outcome = 'SUCCEEDED'
              AND run.validation_digest = NEW.validation_digest
              AND run.validation_proof_digest = NEW.validation_digest
              AND run.completed_at IS NOT NULL
        ) INTO validation_is_valid;
        IF NOT validation_is_valid THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'validated source revision requires its exact successful validation run',
                CONSTRAINT = 'asset_source_revisions_validation_guard';
        END IF;
    END IF;
    IF NEW.state = 'REJECTED' AND OLD.state = 'VALIDATING' AND NOT EXISTS (
        SELECT 1 FROM asset_source_runs AS run
        WHERE run.tenant_id = NEW.tenant_id
          AND run.workspace_id = NEW.workspace_id
          AND run.source_id = NEW.source_id
          AND run.id = NEW.validation_run_id
          AND run.source_revision = NEW.revision
          AND run.source_revision_digest = NEW.canonical_revision_digest
          AND run.run_kind = 'VALIDATION'
          AND run.status IN ('FAILED', 'CANCELLED')
          AND run.stage_code = 'COMPLETED'
          AND run.completed_at IS NOT NULL
          AND NEW.validation_digest = COALESCE(
              run.terminal_failure_override_digest,
              run.validation_proof_digest,
              run.work_result_digest,
              run.request_hash
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'rejected source revision requires its exact terminal validation failure proof',
            CONSTRAINT = 'asset_source_revisions_rejection_guard';
    END IF;
    IF NEW.state = 'PUBLISHED' AND OLD.state <> 'PUBLISHED' THEN
        UPDATE asset_source_revisions
        SET state = 'SUPERSEDED', version = version + 1, updated_at = statement_timestamp()
        WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id
          AND source_id = NEW.source_id AND id <> NEW.id AND state = 'PUBLISHED';
        UPDATE asset_sources
        SET published_revision = NEW.revision,
            published_revision_digest = NEW.canonical_revision_digest,
            gate_status = 'UNAVAILABLE',
            gate_reason_code = 'PUBLICATION_CHANGED',
            gate_revision = gate_revision + 1,
            validated_run_id = NULL,
            validation_digest = NULL,
            validated_binding_digest = NULL,
            checkpoint_ciphertext = NULL,
            checkpoint_key_id = NULL,
            checkpoint_sha256 = NULL,
            checkpoint_revision = NEW.revision,
            checkpoint_version = 0,
            last_success_run_id = NULL,
            last_success_at = NULL,
            last_complete_snapshot_run_id = NULL,
            last_complete_snapshot_at = NULL,
            version = version + 1
        WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id AND id = NEW.source_id;
    END IF;
    NEW.created_at := OLD.created_at;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_source_revisions_transition_guard
    BEFORE INSERT OR UPDATE ON public.asset_source_revisions
    FOR EACH ROW EXECUTE FUNCTION public.enforce_asset_source_revision_transition();

CREATE OR REPLACE FUNCTION public.validate_asset_source_revision_deferred_state() RETURNS trigger AS $$
DECLARE
    current_revision public.asset_source_revisions%ROWTYPE;
    current_source public.asset_sources%ROWTYPE;
    profile_document json;
    profile_row_count bigint;
    profile_distinct_count bigint;
    reconstructed_profile text;
    trusted_path_values text;
    relationship_values text;
    authority_count bigint;
    authority_digest text;
    definition_digest text;
    binding_digest text;
BEGIN
    IF TG_TABLE_NAME = 'asset_source_revision_authorities' THEN
        SELECT revision.* INTO current_revision
        FROM public.asset_source_revisions AS revision
        WHERE revision.tenant_id = NEW.tenant_id
          AND revision.workspace_id = NEW.workspace_id
          AND revision.source_id = NEW.source_id
          AND revision.revision = NEW.source_revision
          AND revision.state = 'DRAFT'
          AND revision.version = 1
          AND revision.xmin = pg_catalog.pg_current_xact_id()::xid;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'authority membership may be appended only with its same-transaction parent revision',
                CONSTRAINT = 'asset_source_revision_authorities_parent_guard';
        END IF;
    ELSE
        SELECT revision.* INTO current_revision
        FROM public.asset_source_revisions AS revision
        WHERE revision.tenant_id = NEW.tenant_id
          AND revision.workspace_id = NEW.workspace_id
          AND revision.id = NEW.id;
    END IF;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT source.* INTO current_source
    FROM public.asset_sources AS source
    WHERE source.tenant_id = current_revision.tenant_id
      AND source.workspace_id = current_revision.workspace_id
      AND source.id = current_revision.source_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503', MESSAGE = 'source revision closure requires its exact scoped source',
            CONSTRAINT = 'asset_source_revisions_source_fk';
    END IF;

    profile_document := pg_catalog.convert_from(current_revision.canonical_profile_manifest, 'UTF8')::json;
    SELECT count(*), count(DISTINCT profile_entry.key)
    INTO profile_row_count, profile_distinct_count
    FROM pg_catalog.json_each(profile_document) AS profile_entry(key, value);
    IF profile_row_count <> 26 OR profile_distinct_count <> 26 OR EXISTS (
        SELECT 1
        FROM pg_catalog.json_each(profile_document) AS profile_entry(key, value)
        WHERE profile_entry.key NOT IN (
            'version', 'source_kind', 'provider_kind', 'profile_code', 'sync_mode',
            'freshness_kind', 'environment_mapping_mode', 'integration_mode',
            'credential_purpose', 'trust_mode', 'network_mode', 'rate_limit_requests',
            'rate_limit_window_seconds', 'backpressure_base_seconds', 'backpressure_max_seconds',
            'schedule_mode', 'max_page_items', 'max_page_relations', 'max_page_bytes',
            'max_document_bytes', 'parser_code', 'compatibility_class', 'dlp_policy_code',
            'trusted_path_codes', 'relationship_types', 'typed_extension_code'
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'source Profile manifest must contain the exact closed 26-key set',
            CONSTRAINT = 'asset_source_revisions_profile_manifest_guard';
    END IF;

    IF pg_catalog.json_typeof(profile_document->'version') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'source_kind') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'provider_kind') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'profile_code') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'sync_mode') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'freshness_kind') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'environment_mapping_mode') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'integration_mode') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'credential_purpose') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'trust_mode') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'network_mode') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'schedule_mode') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'parser_code') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'compatibility_class') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'dlp_policy_code') <> 'string' OR
       pg_catalog.json_typeof(profile_document->'rate_limit_requests') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'rate_limit_window_seconds') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'backpressure_base_seconds') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'backpressure_max_seconds') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'max_page_items') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'max_page_relations') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'max_page_bytes') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'max_document_bytes') <> 'number' OR
       pg_catalog.json_typeof(profile_document->'trusted_path_codes') <> 'array' OR
       pg_catalog.json_typeof(profile_document->'relationship_types') <> 'array' OR
       pg_catalog.json_typeof(profile_document->'typed_extension_code') NOT IN ('string', 'null') OR
       profile_document->>'source_kind' NOT IN (
            'MANUAL', 'CSV_IMPORT', 'CONTROL_PLANE_API', 'EXTERNAL_CMDB', 'VSPHERE',
            'PROXMOX', 'OPENSTACK', 'CLOUD_PROVIDER', 'KUBERNETES_OPERATOR', 'AWX_INVENTORY'
       ) OR
       profile_document->>'sync_mode' NOT IN ('MANUAL', 'ON_DEMAND', 'SCHEDULED') OR
       profile_document->>'freshness_kind' NOT IN (
            'CATALOG_SEQUENCE', 'OBJECT_SEQUENCE', 'OBJECT_TIME_SEQUENCE', 'CHECKPOINT_SEQUENCE'
       ) OR
       profile_document->>'environment_mapping_mode' NOT IN ('SINGLE_ENVIRONMENT', 'EXPLICIT_ITEM_ENVIRONMENT') OR
       profile_document->>'integration_mode' NOT IN ('NONE', 'REQUIRED') OR
       profile_document->>'trust_mode' NOT IN ('NONE', 'REQUIRED') OR
       profile_document->>'network_mode' NOT IN ('NONE', 'REQUIRED') OR
       profile_document->>'schedule_mode' NOT IN ('NONE', 'REQUIRED') OR
       (profile_document->>'provider_kind') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,63}$' OR
       (profile_document->>'profile_code') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$' OR
       (profile_document->>'credential_purpose') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$' OR
       (profile_document->>'parser_code') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$' OR
       (profile_document->>'compatibility_class') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$' OR
       (profile_document->>'dlp_policy_code') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$' OR
       (pg_catalog.json_typeof(profile_document->'typed_extension_code') = 'string' AND
            (profile_document->>'typed_extension_code') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$') OR
       (profile_document->>'rate_limit_requests') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       (profile_document->>'rate_limit_window_seconds') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       (profile_document->>'backpressure_base_seconds') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       (profile_document->>'backpressure_max_seconds') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       (profile_document->>'max_page_items') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       (profile_document->>'max_page_relations') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       (profile_document->>'max_page_bytes') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       (profile_document->>'max_document_bytes') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' OR
       pg_catalog.octet_length(profile_document->>'rate_limit_requests') > 18 OR
       pg_catalog.octet_length(profile_document->>'rate_limit_window_seconds') > 18 OR
       pg_catalog.octet_length(profile_document->>'backpressure_base_seconds') > 18 OR
       pg_catalog.octet_length(profile_document->>'backpressure_max_seconds') > 18 OR
       pg_catalog.octet_length(profile_document->>'max_page_items') > 18 OR
       pg_catalog.octet_length(profile_document->>'max_page_relations') > 18 OR
       pg_catalog.octet_length(profile_document->>'max_page_bytes') > 18 OR
       pg_catalog.octet_length(profile_document->>'max_document_bytes') > 18 OR
       (profile_document->>'max_page_items')::bigint < 1 OR
       (profile_document->>'max_page_relations')::bigint < 0 OR
       (profile_document->>'max_page_bytes')::bigint < 1 OR
       (profile_document->>'max_document_bytes')::bigint < 1 OR
       (profile_document->>'max_document_bytes')::bigint > (profile_document->>'max_page_bytes')::bigint THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'source Profile manifest has an invalid closed-key type or non-minimal integer',
            CONSTRAINT = 'asset_source_revisions_profile_manifest_guard';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.json_array_elements(profile_document->'trusted_path_codes') AS item(value)
        WHERE pg_catalog.json_typeof(item.value) <> 'string'
           OR (item.value #>> '{}') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.json_array_elements(profile_document->'relationship_types') AS item(value)
        WHERE pg_catalog.json_typeof(item.value) <> 'string'
           OR (item.value #>> '{}') COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,127}$'
    ) OR (
        SELECT count(*) FROM pg_catalog.json_array_elements(profile_document->'trusted_path_codes') AS item(value)
    ) NOT BETWEEN 1 AND 128 OR (
        SELECT count(*) FROM pg_catalog.json_array_elements(profile_document->'relationship_types') AS item(value)
    ) > 128 OR (
        SELECT count(*) FROM pg_catalog.json_array_elements(profile_document->'trusted_path_codes') AS item(value)
    ) <> (
        SELECT count(DISTINCT item.value #>> '{}')
        FROM pg_catalog.json_array_elements(profile_document->'trusted_path_codes') AS item(value)
    ) OR (
        SELECT count(*) FROM pg_catalog.json_array_elements(profile_document->'relationship_types') AS item(value)
    ) <> (
        SELECT count(DISTINCT item.value #>> '{}')
        FROM pg_catalog.json_array_elements(profile_document->'relationship_types') AS item(value)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'source Profile arrays must contain unique canonical string codes',
            CONSTRAINT = 'asset_source_revisions_profile_manifest_guard';
    END IF;

    SELECT COALESCE(
        pg_catalog.string_agg(pg_catalog.to_json(item.value #>> '{}')::text, ','
            ORDER BY (item.value #>> '{}') COLLATE "C"),
        ''
    ) INTO trusted_path_values
    FROM pg_catalog.json_array_elements(profile_document->'trusted_path_codes') AS item(value);
    SELECT COALESCE(
        pg_catalog.string_agg(pg_catalog.to_json(item.value #>> '{}')::text, ','
            ORDER BY (item.value #>> '{}') COLLATE "C"),
        ''
    ) INTO relationship_values
    FROM pg_catalog.json_array_elements(profile_document->'relationship_types') AS item(value);

    reconstructed_profile :=
        '{"backpressure_base_seconds":' || (profile_document->>'backpressure_base_seconds')::bigint::text ||
        ',"backpressure_max_seconds":' || (profile_document->>'backpressure_max_seconds')::bigint::text ||
        ',"compatibility_class":' || pg_catalog.to_json(profile_document->>'compatibility_class')::text ||
        ',"credential_purpose":' || pg_catalog.to_json(profile_document->>'credential_purpose')::text ||
        ',"dlp_policy_code":' || pg_catalog.to_json(profile_document->>'dlp_policy_code')::text ||
        ',"environment_mapping_mode":' || pg_catalog.to_json(profile_document->>'environment_mapping_mode')::text ||
        ',"freshness_kind":' || pg_catalog.to_json(profile_document->>'freshness_kind')::text ||
        ',"integration_mode":' || pg_catalog.to_json(profile_document->>'integration_mode')::text ||
        ',"max_document_bytes":' || (profile_document->>'max_document_bytes')::bigint::text ||
        ',"max_page_bytes":' || (profile_document->>'max_page_bytes')::bigint::text ||
        ',"max_page_items":' || (profile_document->>'max_page_items')::bigint::text ||
        ',"max_page_relations":' || (profile_document->>'max_page_relations')::bigint::text ||
        ',"network_mode":' || pg_catalog.to_json(profile_document->>'network_mode')::text ||
        ',"parser_code":' || pg_catalog.to_json(profile_document->>'parser_code')::text ||
        ',"profile_code":' || pg_catalog.to_json(profile_document->>'profile_code')::text ||
        ',"provider_kind":' || pg_catalog.to_json(profile_document->>'provider_kind')::text ||
        ',"rate_limit_requests":' || (profile_document->>'rate_limit_requests')::bigint::text ||
        ',"rate_limit_window_seconds":' || (profile_document->>'rate_limit_window_seconds')::bigint::text ||
        ',"relationship_types":[' || relationship_values || ']' ||
        ',"schedule_mode":' || pg_catalog.to_json(profile_document->>'schedule_mode')::text ||
        ',"source_kind":' || pg_catalog.to_json(profile_document->>'source_kind')::text ||
        ',"sync_mode":' || pg_catalog.to_json(profile_document->>'sync_mode')::text ||
        ',"trust_mode":' || pg_catalog.to_json(profile_document->>'trust_mode')::text ||
        ',"trusted_path_codes":[' || trusted_path_values || ']' ||
        ',"typed_extension_code":' || CASE
            WHEN pg_catalog.json_typeof(profile_document->'typed_extension_code') = 'null' THEN 'null'
            ELSE pg_catalog.to_json(profile_document->>'typed_extension_code')::text
        END ||
        ',"version":' || pg_catalog.to_json(profile_document->>'version')::text || '}';

    IF pg_catalog.convert_to(reconstructed_profile, 'UTF8') IS DISTINCT FROM current_revision.canonical_profile_manifest OR
       pg_catalog.encode(pg_catalog.sha256(current_revision.canonical_profile_manifest), 'hex')
            IS DISTINCT FROM current_revision.profile_manifest_sha256 OR
       pg_catalog.encode(pg_catalog.sha256(current_revision.canonical_provider_schema), 'hex')
            IS DISTINCT FROM current_revision.canonical_provider_schema_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'source Profile or Provider schema bytes are not exact canonical content',
            CONSTRAINT = 'asset_source_revisions_canonical_content_guard';
    END IF;

    SELECT count(*) INTO authority_count
    FROM public.asset_source_revision_authorities AS authority
    WHERE authority.tenant_id = current_revision.tenant_id
      AND authority.workspace_id = current_revision.workspace_id
      AND authority.source_id = current_revision.source_id
      AND authority.source_revision = current_revision.revision;
    IF authority_count NOT BETWEEN 1 AND 100 OR EXISTS (
        SELECT 1
        FROM (
            SELECT authority.canonical_ordinal,
                   pg_catalog.row_number() OVER (
                       ORDER BY authority.environment_id::text COLLATE "C"
                   ) AS expected_ordinal
            FROM public.asset_source_revision_authorities AS authority
            WHERE authority.tenant_id = current_revision.tenant_id
              AND authority.workspace_id = current_revision.workspace_id
              AND authority.source_id = current_revision.source_id
              AND authority.source_revision = current_revision.revision
        ) AS ordered_authority
        WHERE ordered_authority.canonical_ordinal <> ordered_authority.expected_ordinal
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'source revision authorities must be contiguous in canonical Environment UUID order',
            CONSTRAINT = 'asset_source_revision_authorities_order_guard';
    END IF;

    authority_digest := pg_catalog.encode(pg_catalog.sha256(
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to('asset-source-authority-scope.v1', 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(authority_count::text, 'UTF8')
        ) ||
        (
            SELECT pg_catalog.string_agg(
                public.asset_catalog_framed_value_v1(
                    pg_catalog.convert_to(authority.environment_id::text, 'UTF8')
                ),
                ''::bytea ORDER BY authority.environment_id::text COLLATE "C"
            )
            FROM public.asset_source_revision_authorities AS authority
            WHERE authority.tenant_id = current_revision.tenant_id
              AND authority.workspace_id = current_revision.workspace_id
              AND authority.source_id = current_revision.source_id
              AND authority.source_revision = current_revision.revision
        )
    ), 'hex');

    definition_digest := pg_catalog.encode(pg_catalog.sha256(
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to('asset-source-definition.v2', 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(current_source.source_kind, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(current_source.provider_kind, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.convert_to(current_revision.profile_code, 'UTF8')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.decode(current_revision.profile_manifest_sha256, 'hex')
        ) ||
        public.asset_catalog_framed_value_v1(
            pg_catalog.decode(current_revision.canonical_provider_schema_sha256, 'hex')
        )
    ), 'hex');

    binding_digest := public.asset_catalog_source_revision_binding_digest(current_revision);
    IF authority_digest IS DISTINCT FROM current_revision.authority_scope_digest OR
       definition_digest IS DISTINCT FROM current_revision.source_definition_digest OR
       binding_digest IS DISTINCT FROM current_revision.canonical_revision_digest THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'source revision authority, definition, or binding digest drifted from canonical facts',
            CONSTRAINT = 'asset_source_revisions_digest_closure_guard';
    END IF;

    IF profile_document->>'version' <> 'asset-source-profile-manifest.v1' OR
       profile_document->>'source_kind' IS DISTINCT FROM current_source.source_kind OR
       profile_document->>'provider_kind' IS DISTINCT FROM current_source.provider_kind OR
       profile_document->>'profile_code' IS DISTINCT FROM current_revision.profile_code OR
       profile_document->>'sync_mode' IS DISTINCT FROM current_revision.sync_mode OR
       (profile_document->>'rate_limit_requests')::bigint <> current_revision.rate_limit_requests::bigint OR
       (profile_document->>'rate_limit_window_seconds')::bigint <> current_revision.rate_limit_window_seconds::bigint OR
       (profile_document->>'backpressure_base_seconds')::bigint <> current_revision.backpressure_base_seconds::bigint OR
       (profile_document->>'backpressure_max_seconds')::bigint <> current_revision.backpressure_max_seconds::bigint OR
       ((profile_document->>'integration_mode') = 'NONE') IS DISTINCT FROM (current_revision.integration_id IS NULL) OR
       ((profile_document->>'credential_purpose') = 'NONE') IS DISTINCT FROM (current_revision.credential_reference_id IS NULL) OR
       ((profile_document->>'trust_mode') = 'NONE') IS DISTINCT FROM (current_revision.trust_reference_id IS NULL) OR
       ((profile_document->>'network_mode') = 'NONE') IS DISTINCT FROM (current_revision.network_policy_reference_id IS NULL) OR
       ((profile_document->>'schedule_mode') = 'NONE') IS DISTINCT FROM (current_revision.schedule_expression IS NULL) OR
       (profile_document->>'environment_mapping_mode' = 'SINGLE_ENVIRONMENT' AND authority_count <> 1) OR
       (profile_document->>'typed_extension_code') IS DISTINCT FROM current_revision.typed_extension_code THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'source Profile semantics drift from their persisted revision binding',
            CONSTRAINT = 'asset_source_revisions_profile_parity_guard';
    END IF;

    IF current_source.source_kind = 'KUBERNETES_OPERATOR' AND (
        current_revision.typed_extension_code IS NULL OR
        current_revision.prepared_extension_digest IS NULL OR
        current_revision.typed_extension_code IS DISTINCT FROM current_revision.profile_code
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'KUBERNETES_OPERATOR requires its exact prepared typed-extension pair',
            CONSTRAINT = 'asset_source_revisions_typed_extension_guard';
    ELSIF current_source.source_kind <> 'KUBERNETES_OPERATOR' AND (
        current_revision.typed_extension_code IS NOT NULL OR
        current_revision.prepared_extension_digest IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'non-KUBERNETES_OPERATOR sources cannot bind a typed extension',
            CONSTRAINT = 'asset_source_revisions_typed_extension_guard';
    END IF;

    IF current_source.source_kind = 'MANUAL' AND (
       current_source.provider_kind <> 'MANUAL_V1' OR
       current_revision.profile_code <> 'MANUAL_V1' OR
       current_revision.sync_mode <> 'MANUAL' OR
       current_revision.rate_limit_requests <> 1 OR
       current_revision.rate_limit_window_seconds <> 1 OR
       current_revision.backpressure_base_seconds <> 1 OR
       current_revision.backpressure_max_seconds <> 1 OR
       current_revision.integration_id IS NOT NULL OR
       current_revision.credential_reference_id IS NOT NULL OR
       current_revision.trust_reference_id IS NOT NULL OR
       current_revision.network_policy_reference_id IS NOT NULL OR
       current_revision.schedule_expression IS NOT NULL OR
       current_revision.typed_extension_code IS NOT NULL OR
       current_revision.prepared_extension_digest IS NOT NULL OR
       authority_count <> 1 OR
       pg_catalog.octet_length(current_revision.canonical_profile_manifest) <> 794 OR
       current_revision.canonical_profile_manifest IS DISTINCT FROM pg_catalog.convert_to('{"backpressure_base_seconds":1,"backpressure_max_seconds":1,"compatibility_class":"MANUAL_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CATALOG_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":65536,"max_page_items":1,"max_page_relations":0,"network_mode":"NONE","parser_code":"MANUAL_ASSET_V1","profile_code":"MANUAL_V1","provider_kind":"MANUAL_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":[],"schedule_mode":"NONE","source_kind":"MANUAL","sync_mode":"MANUAL","trust_mode":"NONE","trusted_path_codes":["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}', 'UTF8') OR
       current_revision.profile_manifest_sha256 <> '57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96' OR
       pg_catalog.octet_length(current_revision.canonical_provider_schema) <> 62 OR
       current_revision.canonical_provider_schema IS DISTINCT FROM pg_catalog.convert_to('{"additionalProperties":false,"properties":{},"type":"object"}', 'UTF8') OR
       current_revision.canonical_provider_schema_sha256 <> '99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa' OR
       current_revision.source_definition_digest <> '7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'MANUAL revision must equal the exact built-in asset-source-definition.v2 Profile contract',
            CONSTRAINT = 'asset_source_revisions_manual_profile_guard';
    END IF;

    IF current_revision.state = 'PUBLISHED' AND (
       current_source.published_revision IS DISTINCT FROM current_revision.revision OR
       current_source.published_revision_digest IS DISTINCT FROM current_revision.canonical_revision_digest) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'published revision and source pointer must close in the same transaction',
            CONSTRAINT = 'asset_source_revisions_publication_closure_guard';
    END IF;
    IF current_revision.state = 'SUPERSEDED' AND (
       current_source.published_revision IS NOT DISTINCT FROM current_revision.revision OR
       NOT EXISTS (
            SELECT 1 FROM public.asset_source_revisions AS successor
            WHERE successor.tenant_id = current_revision.tenant_id
              AND successor.workspace_id = current_revision.workspace_id
              AND successor.source_id = current_revision.source_id
              AND successor.state = 'PUBLISHED'
              AND successor.revision > current_revision.revision
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'superseded revision requires its exact later published successor',
            CONSTRAINT = 'asset_source_revisions_supersede_closure_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE CONSTRAINT TRIGGER asset_source_revisions_deferred_state_guard
    AFTER INSERT OR UPDATE ON public.asset_source_revisions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_revision_deferred_state();

CREATE CONSTRAINT TRIGGER asset_source_revision_authorities_deferred_state_guard
    AFTER INSERT ON public.asset_source_revision_authorities
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_revision_deferred_state();

CREATE OR REPLACE FUNCTION public.enforce_asset_source_run_mutation() RETURNS trigger AS $$
DECLARE
    current_source asset_sources%ROWTYPE;
    current_revision asset_source_revisions%ROWTYPE;
    now_at timestamptz := clock_timestamp();
    progress_changed boolean;
    snapshot_changed boolean;
    work_changed boolean;
    cleanup_changed boolean;
    pending_changed boolean;
    terminal_facts_changed boolean;
    lease_identity_changed boolean;
    rollover_changed boolean;
    source_admitted boolean := false;
    cleanup_receipt_exists boolean;
    sealed_cleanup_receipt_exists boolean := false;
    sealed_cleanup_reclaim boolean := false;
    page_receipt_exists boolean;
    relation_receipt_exists boolean;
    rollover_receipt_exists boolean;
    terminal_receipt_exists boolean;
    direct_failure_without_cleanup boolean := false;
    expected_cleanup_digest text;
    expected_terminal_digest text;
    expected_override_digest text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'QUEUED' OR NEW.stage_code <> 'WAITING' OR NEW.version <> 1 OR
           NEW.page_sequence <> 0 OR NEW.relation_page_sequence <> 0 OR NEW.checkpoint_version < 0 OR
           NEW.final_page OR NEW.complete_snapshot OR NEW.effective_complete_snapshot OR
           NEW.fence_epoch <> 0 OR NEW.heartbeat_sequence <> 0 OR
           NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR NEW.fence_token_hash IS NOT NULL OR
           NEW.started_at IS NOT NULL OR NEW.heartbeat_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR
           NEW.cursor_after_sha256 IS NOT NULL OR NEW.page_digest IS NOT NULL OR NEW.relation_page_digest IS NOT NULL OR
           NEW.pending_transition IS NOT NULL OR NEW.work_result_kind IS NOT NULL OR
           NEW.cleanup_status <> 'NOT_OPENED' OR NEW.cleanup_attempt_id IS NOT NULL OR
           NEW.cleanup_attempt_epoch <> 0 OR NEW.cleanup_digest IS NOT NULL OR
           NEW.terminal_failure_override IS NOT NULL OR NEW.terminal_failure_override_digest IS NOT NULL OR
           NEW.terminal_command_sha256 IS NOT NULL OR NEW.failure_code IS NOT NULL OR
           NEW.lineage_rollover_reason IS NOT NULL OR NEW.lineage_rollover_evidence_digest IS NOT NULL OR
           NEW.observed_count <> 0 OR NEW.created_count <> 0 OR NEW.changed_count <> 0 OR
           NEW.unchanged_count <> 0 OR NEW.conflict_count <> 0 OR NEW.missing_count <> 0 OR
           NEW.stale_count <> 0 OR NEW.restored_count <> 0 OR NEW.tombstoned_count <> 0 OR
           NEW.rejected_count <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source run must start QUEUED/WAITING with no lease, progress, result, cleanup, or completion evidence',
                CONSTRAINT = 'asset_source_runs_initial_state_guard';
        END IF;
        SELECT source.* INTO current_source
        FROM asset_sources AS source
        WHERE source.tenant_id = NEW.tenant_id
          AND source.workspace_id = NEW.workspace_id
          AND source.id = NEW.source_id
        FOR SHARE OF source;
        IF NOT FOUND OR current_source.status <> 'ACTIVE' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'source run requires the current active source',
                CONSTRAINT = 'asset_source_runs_admission_guard';
        END IF;
        IF (current_source.source_kind = 'MANUAL' AND
                NEW.run_kind NOT IN ('VALIDATION', 'MANUAL_MUTATION')) OR
           (current_source.source_kind <> 'MANUAL' AND NEW.run_kind = 'MANUAL_MUTATION') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'source run kind must match the closed MANUAL/MANUAL_V1 execution profile',
                CONSTRAINT = 'asset_source_runs_manual_profile_guard';
        END IF;
        IF current_source.gate_revision IS DISTINCT FROM NEW.gate_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'source run requires the current source gate revision',
                CONSTRAINT = 'asset_source_runs_admission_guard';
        END IF;
        SELECT revision.* INTO current_revision
        FROM asset_source_revisions AS revision
        WHERE revision.tenant_id = NEW.tenant_id
          AND revision.workspace_id = NEW.workspace_id
          AND revision.source_id = NEW.source_id
          AND revision.revision = NEW.source_revision
          AND revision.canonical_revision_digest = NEW.source_revision_digest
        FOR SHARE OF revision;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'source run requires its exact immutable source revision',
                CONSTRAINT = 'asset_source_runs_admission_guard';
        END IF;
        IF NEW.run_kind = 'VALIDATION' THEN
            IF current_source.gate_status <> 'UNAVAILABLE' OR
               current_revision.state NOT IN ('DRAFT', 'REJECTED') OR
               NEW.checkpoint_version <> 0 OR NEW.cursor_before_sha256 IS NOT NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514', MESSAGE = 'validation run requires an unavailable source gate and an empty checkpoint',
                    CONSTRAINT = 'asset_source_runs_admission_guard';
            END IF;
        ELSE
            IF current_revision.state <> 'PUBLISHED' OR current_source.gate_status <> 'AVAILABLE' OR
               current_source.published_revision IS DISTINCT FROM NEW.source_revision OR
               current_source.published_revision_digest IS DISTINCT FROM NEW.source_revision_digest OR
               current_source.checkpoint_version IS DISTINCT FROM NEW.checkpoint_version OR
               current_source.checkpoint_sha256 IS DISTINCT FROM NEW.cursor_before_sha256 OR
               (NEW.run_kind = 'MANUAL_MUTATION' AND current_source.source_kind <> 'MANUAL') THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514', MESSAGE = 'data run must bind the exact available published revision and checkpoint',
                    CONSTRAINT = 'asset_source_runs_admission_guard';
            END IF;
        END IF;
        NEW.created_at := now_at;
        NEW.stage_changed_at := now_at;
        RETURN NEW;
    END IF;

    IF OLD.status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'terminal asset source run and lease are immutable',
            CONSTRAINT = 'asset_source_runs_terminal_guard';
    END IF;
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.id IS DISTINCT FROM NEW.id OR OLD.source_id IS DISTINCT FROM NEW.source_id OR
       OLD.source_revision IS DISTINCT FROM NEW.source_revision OR
       OLD.source_revision_digest IS DISTINCT FROM NEW.source_revision_digest OR
       OLD.run_kind IS DISTINCT FROM NEW.run_kind OR OLD.trigger_type IS DISTINCT FROM NEW.trigger_type OR
       OLD.gate_revision IS DISTINCT FROM NEW.gate_revision OR
       OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key OR
       OLD.request_hash IS DISTINCT FROM NEW.request_hash OR
       OLD.cursor_before_sha256 IS DISTINCT FROM NEW.cursor_before_sha256 OR
       OLD.trace_id IS DISTINCT FROM NEW.trace_id OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source run identity and admission facts are immutable',
            CONSTRAINT = 'asset_source_runs_identity_guard';
    END IF;
    IF OLD.terminal_command_sha256 IS NOT NULL OR
       (NEW.status NOT IN ('SUCCEEDED', 'PARTIAL', 'FAILED') AND NEW.terminal_command_sha256 IS NOT NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'terminal command digest is write-once at terminal commit',
            CONSTRAINT = 'asset_source_runs_terminal_receipt_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source run version must advance exactly once',
            CONSTRAINT = 'asset_source_runs_version_guard';
    END IF;
    IF NEW.page_sequence < OLD.page_sequence OR NEW.page_sequence > OLD.page_sequence + 1 OR
       NEW.relation_page_sequence < OLD.relation_page_sequence OR
       NEW.relation_page_sequence > OLD.relation_page_sequence + 1 OR
       NEW.checkpoint_version < OLD.checkpoint_version OR NEW.checkpoint_version > OLD.checkpoint_version + 1 OR
       NEW.observed_count < OLD.observed_count OR NEW.created_count < OLD.created_count OR
       NEW.changed_count < OLD.changed_count OR NEW.unchanged_count < OLD.unchanged_count OR
       NEW.conflict_count < OLD.conflict_count OR NEW.missing_count < OLD.missing_count OR
       NEW.stale_count < OLD.stale_count OR NEW.restored_count < OLD.restored_count OR
       NEW.tombstoned_count < OLD.tombstoned_count OR NEW.rejected_count < OLD.rejected_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source run progress cannot regress or skip',
            CONSTRAINT = 'asset_source_runs_progress_guard';
    END IF;
    IF (OLD.final_page AND NOT NEW.final_page) OR
       (OLD.complete_snapshot AND NOT NEW.complete_snapshot) OR
       (OLD.effective_complete_snapshot AND NOT NEW.effective_complete_snapshot) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'accepted snapshot flags are monotonic and immutable',
            CONSTRAINT = 'asset_source_runs_snapshot_transition_guard';
    END IF;
    IF NEW.stage_code IS DISTINCT FROM OLD.stage_code THEN
        NEW.stage_changed_at := now_at;
    ELSIF NEW.stage_changed_at IS DISTINCT FROM OLD.stage_changed_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'run stage time is server owned',
            CONSTRAINT = 'asset_source_runs_stage_time_guard';
    END IF;
    IF OLD.status = 'FINALIZING' AND NEW.status = 'DELAYED' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'persisted finalizing work cannot return to delayed provider work',
            CONSTRAINT = 'asset_source_runs_pending_transition_guard';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status IN ('QUEUED', 'DELAYED') AND NEW.status IN ('RUNNING', 'CANCELLED')) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('RUNNING', 'DELAYED', 'FINALIZING')) OR
        (OLD.status = 'FINALIZING' AND NEW.status IN ('FINALIZING', 'SUCCEEDED', 'PARTIAL', 'FAILED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'invalid asset source run state transition',
            CONSTRAINT = 'asset_source_runs_state_guard';
    END IF;

    progress_changed :=
        OLD.page_sequence IS DISTINCT FROM NEW.page_sequence OR
        OLD.page_digest IS DISTINCT FROM NEW.page_digest OR
        OLD.relation_page_sequence IS DISTINCT FROM NEW.relation_page_sequence OR
        OLD.relation_page_digest IS DISTINCT FROM NEW.relation_page_digest OR
        OLD.checkpoint_version IS DISTINCT FROM NEW.checkpoint_version OR
        OLD.cursor_after_sha256 IS DISTINCT FROM NEW.cursor_after_sha256 OR
        OLD.observed_count IS DISTINCT FROM NEW.observed_count OR
        OLD.created_count IS DISTINCT FROM NEW.created_count OR
        OLD.changed_count IS DISTINCT FROM NEW.changed_count OR
        OLD.unchanged_count IS DISTINCT FROM NEW.unchanged_count OR
        OLD.conflict_count IS DISTINCT FROM NEW.conflict_count OR
        OLD.missing_count IS DISTINCT FROM NEW.missing_count OR
        OLD.stale_count IS DISTINCT FROM NEW.stale_count OR
        OLD.restored_count IS DISTINCT FROM NEW.restored_count OR
        OLD.tombstoned_count IS DISTINCT FROM NEW.tombstoned_count OR
        OLD.rejected_count IS DISTINCT FROM NEW.rejected_count OR
        OLD.final_page IS DISTINCT FROM NEW.final_page OR
        OLD.complete_snapshot IS DISTINCT FROM NEW.complete_snapshot OR
        OLD.effective_complete_snapshot IS DISTINCT FROM NEW.effective_complete_snapshot;
    snapshot_changed :=
        OLD.final_page IS DISTINCT FROM NEW.final_page OR
        OLD.complete_snapshot IS DISTINCT FROM NEW.complete_snapshot OR
        OLD.effective_complete_snapshot IS DISTINCT FROM NEW.effective_complete_snapshot;
    work_changed :=
        OLD.work_result_kind IS DISTINCT FROM NEW.work_result_kind OR
        OLD.work_result_status IS DISTINCT FROM NEW.work_result_status OR
        OLD.work_result_digest IS DISTINCT FROM NEW.work_result_digest OR
        OLD.work_result_recorded_at IS DISTINCT FROM NEW.work_result_recorded_at OR
        OLD.validation_outcome IS DISTINCT FROM NEW.validation_outcome OR
        OLD.validation_digest IS DISTINCT FROM NEW.validation_digest OR
        OLD.validation_proof_digest IS DISTINCT FROM NEW.validation_proof_digest;
    cleanup_changed :=
        OLD.cleanup_attempt_id IS DISTINCT FROM NEW.cleanup_attempt_id OR
        OLD.cleanup_attempt_epoch IS DISTINCT FROM NEW.cleanup_attempt_epoch OR
        OLD.cleanup_status IS DISTINCT FROM NEW.cleanup_status OR
        OLD.cleanup_digest IS DISTINCT FROM NEW.cleanup_digest;
    pending_changed :=
        OLD.pending_transition IS DISTINCT FROM NEW.pending_transition OR
        OLD.pending_transition_reason IS DISTINCT FROM NEW.pending_transition_reason OR
        OLD.pending_transition_not_before IS DISTINCT FROM NEW.pending_transition_not_before OR
        OLD.pending_transition_digest IS DISTINCT FROM NEW.pending_transition_digest;
    terminal_facts_changed :=
        OLD.terminal_failure_override IS DISTINCT FROM NEW.terminal_failure_override OR
        OLD.terminal_failure_override_digest IS DISTINCT FROM NEW.terminal_failure_override_digest OR
        OLD.failure_code IS DISTINCT FROM NEW.failure_code OR
        OLD.terminal_command_sha256 IS DISTINCT FROM NEW.terminal_command_sha256;
    lease_identity_changed :=
        OLD.lease_owner IS DISTINCT FROM NEW.lease_owner OR
        OLD.fence_token_hash IS DISTINCT FROM NEW.fence_token_hash;
    rollover_changed :=
        OLD.lineage_rollover_reason IS DISTINCT FROM NEW.lineage_rollover_reason OR
        OLD.lineage_rollover_evidence_digest IS DISTINCT FROM NEW.lineage_rollover_evidence_digest;

    SELECT source.* INTO current_source
    FROM asset_sources AS source
    WHERE source.tenant_id = NEW.tenant_id
      AND source.workspace_id = NEW.workspace_id
      AND source.id = NEW.source_id
    FOR SHARE OF source;
    SELECT revision.* INTO current_revision
    FROM asset_source_revisions AS revision
    WHERE revision.tenant_id = NEW.tenant_id
      AND revision.workspace_id = NEW.workspace_id
      AND revision.source_id = NEW.source_id
      AND revision.revision = NEW.source_revision
      AND revision.canonical_revision_digest = NEW.source_revision_digest
    FOR SHARE OF revision;

    IF FOUND AND current_source.id IS NOT NULL AND current_source.status = 'ACTIVE' THEN
        IF NEW.run_kind = 'VALIDATION' THEN
            source_admitted := COALESCE((
                current_revision.id IS NOT NULL AND
                current_revision.state = 'VALIDATING' AND
                current_revision.validation_run_id IS NOT DISTINCT FROM NEW.id AND
                ((current_source.gate_status = 'UNAVAILABLE' AND
                    current_source.gate_revision = NEW.gate_revision) OR
                 (current_source.gate_status = 'VALIDATING' AND
                    current_source.validated_run_id IS NOT DISTINCT FROM NEW.id AND
                    current_source.validation_digest IS NULL AND
                    current_source.validated_binding_digest IS NULL AND
                    current_source.gate_revision = NEW.gate_revision + 1)) AND
                NEW.checkpoint_version = 0 AND NEW.cursor_before_sha256 IS NULL AND
                NEW.cursor_after_sha256 IS NULL
            ), false);
        ELSE
            source_admitted := COALESCE((
                current_revision.id IS NOT NULL AND current_revision.state = 'PUBLISHED' AND
                current_source.published_revision = NEW.source_revision AND
                current_source.published_revision_digest = NEW.source_revision_digest AND
                current_source.checkpoint_revision = NEW.source_revision AND
                current_source.checkpoint_version = NEW.checkpoint_version AND
                ((current_source.source_kind = 'MANUAL' AND current_source.checkpoint_sha256 IS NULL AND
                    NEW.cursor_after_sha256 IS NULL) OR
                 (current_source.source_kind <> 'MANUAL' AND
                    current_source.checkpoint_sha256 IS NOT DISTINCT FROM
                        COALESCE(NEW.cursor_after_sha256, NEW.cursor_before_sha256))) AND
                ((NEW.lineage_rollover_reason IS NULL AND
                    current_source.gate_status = 'AVAILABLE' AND
                    current_source.gate_revision = NEW.gate_revision) OR
                 (NEW.lineage_rollover_reason IS NOT NULL AND
                    current_source.gate_status = 'DEGRADED' AND
                    current_source.gate_reason_code = 'CHECKPOINT_LINEAGE_ROLLOVER' AND
                    current_source.gate_revision = NEW.gate_revision + 1))
            ), false);
        END IF;
    END IF;

    IF rollover_changed THEN
        IF current_source.source_kind = 'MANUAL' OR current_source.provider_kind = 'MANUAL_V1' THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'MANUAL_V1 logical checkpoint lineage cannot be rolled over',
                CONSTRAINT = 'asset_source_runs_manual_rollover_guard';
        END IF;
        SELECT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = NEW.tenant_id AND audit.workspace_id = NEW.workspace_id
              AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
              AND audit.actor_type = 'SYSTEM' AND audit.actor_id = NEW.lease_owner
              AND audit.action = 'CHECKPOINT_LINEAGE_ROLLOVER_BOUND'
              AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = NEW.id::text
              AND audit.request_id = 'source-rollover:' || NEW.id::text
              AND audit.payload_hash = NEW.lineage_rollover_evidence_digest
        ) INTO rollover_receipt_exists;
        IF OLD.lineage_rollover_reason IS NOT NULL OR
           NEW.lineage_rollover_reason IS NULL OR NEW.lineage_rollover_evidence_digest IS NULL OR
           NEW.run_kind = 'VALIDATION' OR OLD.status <> 'RUNNING' OR
           OLD.lease_expires_at <= now_at OR lease_identity_changed OR progress_changed OR work_changed OR
           cleanup_changed OR NEW.heartbeat_sequence <> OLD.heartbeat_sequence OR source_admitted IS NOT TRUE OR
           NOT rollover_receipt_exists THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'checkpoint lineage rollover requires one live fenced binding and exact immutable receipt',
                CONSTRAINT = 'asset_source_runs_rollover_receipt_guard';
        END IF;
    END IF;

    IF current_source.source_kind = 'MANUAL' THEN
        IF current_source.provider_kind <> 'MANUAL_V1' OR current_revision.profile_code <> 'MANUAL_V1' OR
           current_revision.credential_reference_id IS NOT NULL OR
           current_revision.trust_reference_id IS NOT NULL OR
           current_revision.network_policy_reference_id IS NOT NULL OR
           NEW.cleanup_status NOT IN ('NOT_OPENED', 'NO_CREDENTIAL') OR
           (cleanup_changed AND NOT (
                OLD.cleanup_status = 'NOT_OPENED' AND NEW.cleanup_status = 'NO_CREDENTIAL'
           )) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'MANUAL_V1 cleanup permits only the exact no-credential closure',
                CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
        END IF;
    ELSIF NEW.cleanup_status = 'NO_CREDENTIAL' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'credential-bearing source cleanup cannot claim a no-credential closure',
            CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
    END IF;

    IF cleanup_changed THEN
        IF OLD.cleanup_status = 'NOT_OPENED' AND NEW.cleanup_status = 'PENDING' THEN
            IF OLD.status <> 'RUNNING' OR NEW.cleanup_attempt_id IS NULL OR
               NEW.cleanup_attempt_epoch <> NEW.fence_epoch OR NEW.cleanup_digest IS NOT NULL OR
               OLD.lease_expires_at <= now_at OR lease_identity_changed THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'cleanup attempt reservation requires the current live fence',
                    CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
            END IF;
        ELSIF OLD.cleanup_status = 'NOT_OPENED' AND NEW.cleanup_status = 'NO_CREDENTIAL' THEN
            expected_cleanup_digest := asset_catalog_source_run_no_credential_digest(NEW);
            SELECT EXISTS (
                SELECT 1 FROM audit_records AS audit
                WHERE audit.tenant_id = NEW.tenant_id AND audit.workspace_id = NEW.workspace_id
                  AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
                  AND audit.actor_type = 'SYSTEM' AND audit.actor_id = NEW.lease_owner
                  AND audit.action = 'ATTEMPT_CLEANED'
                  AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = NEW.id::text
                  AND audit.request_id = 'source-attempt:' || NEW.id::text || ':0'
                  AND audit.payload_hash = expected_cleanup_digest
            ) INTO cleanup_receipt_exists;
            IF current_source.source_kind <> 'MANUAL' OR current_source.provider_kind <> 'MANUAL_V1' OR
               current_revision.profile_code <> 'MANUAL_V1' OR
               current_revision.credential_reference_id IS NOT NULL OR
               current_revision.trust_reference_id IS NOT NULL OR
               current_revision.network_policy_reference_id IS NOT NULL OR
               NEW.cleanup_attempt_id IS NOT NULL OR NEW.cleanup_attempt_epoch <> 0 OR
               NEW.cleanup_digest IS DISTINCT FROM expected_cleanup_digest OR NOT cleanup_receipt_exists OR
               OLD.status NOT IN ('RUNNING', 'FINALIZING') OR OLD.lease_expires_at <= now_at OR
               lease_identity_changed OR NEW.stage_code <> 'CLEANING_UP' OR NOT (
                    (NEW.pending_transition IS NOT DISTINCT FROM 'DELAY' AND NEW.work_result_kind IS NULL) OR
                    (NEW.pending_transition IS NULL AND NEW.work_result_kind IS NOT NULL)
               ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'no-credential cleanup requires the exact MANUAL_V1 proof and receipt',
                    CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
            END IF;
        ELSIF OLD.cleanup_status = 'PENDING' AND NEW.cleanup_status IN ('REVOKED', 'UNCERTAIN') THEN
            SELECT EXISTS (
                SELECT 1 FROM audit_records AS audit
                WHERE audit.tenant_id = NEW.tenant_id AND audit.workspace_id = NEW.workspace_id
                  AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
                  AND audit.actor_type = 'SYSTEM' AND audit.actor_id = NEW.lease_owner
                  AND audit.action = 'ATTEMPT_CLEANED'
                  AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = NEW.id::text
                  AND audit.request_id = 'source-attempt:' || NEW.id::text || ':' || NEW.cleanup_attempt_epoch::text
                  AND audit.payload_hash = NEW.cleanup_digest
            ) INTO cleanup_receipt_exists;
            IF NEW.cleanup_attempt_id IS DISTINCT FROM OLD.cleanup_attempt_id OR
               NEW.cleanup_attempt_epoch IS DISTINCT FROM OLD.cleanup_attempt_epoch OR
               NOT asset_catalog_sha256_valid(NEW.cleanup_digest) OR NOT cleanup_receipt_exists OR
               OLD.lease_expires_at <= now_at OR lease_identity_changed OR
               NEW.stage_code <> 'CLEANING_UP' OR NOT (
                    (NEW.pending_transition IS NOT DISTINCT FROM 'DELAY' AND NEW.work_result_kind IS NULL) OR
                    (NEW.pending_transition IS NULL AND NEW.work_result_kind IS NOT NULL)
               ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'cleanup completion requires the exact reserved attempt proof and receipt',
                    CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
            END IF;
        ELSIF OLD.cleanup_status IN ('REVOKED', 'NO_CREDENTIAL') AND NEW.cleanup_status = 'NOT_OPENED' THEN
            SELECT EXISTS (
                SELECT 1 FROM audit_records AS audit
                WHERE audit.tenant_id = NEW.tenant_id AND audit.workspace_id = NEW.workspace_id
                  AND audit.action = 'ATTEMPT_CLEANED'
                  AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = NEW.id::text
                  AND audit.request_id = 'source-attempt:' || NEW.id::text || ':' || OLD.cleanup_attempt_epoch::text
                  AND audit.payload_hash = OLD.cleanup_digest
            ) INTO cleanup_receipt_exists;
            IF OLD.status <> 'DELAYED' OR NEW.status <> 'RUNNING' OR
               NEW.cleanup_attempt_id IS NOT NULL OR NEW.cleanup_attempt_epoch <> 0 OR
               NEW.cleanup_digest IS NOT NULL OR NOT cleanup_receipt_exists THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'fresh claim may clear only a receipted consumed cleanup summary',
                    CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
            END IF;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'invalid or unreceipted cleanup state transition',
                CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
        END IF;
    END IF;

    IF current_source.source_kind = 'MANUAL' AND (
       NEW.pending_transition IS NOT NULL OR NEW.status = 'DELAYED' OR NEW.stage_code = 'DELAYED'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'synchronous MANUAL_V1 runs cannot enter provider backoff or delayed work',
            CONSTRAINT = 'asset_source_runs_pending_transition_guard';
    END IF;

    IF OLD.status = 'RUNNING' AND NEW.status = 'DELAYED' THEN
        SELECT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = OLD.tenant_id AND audit.workspace_id = OLD.workspace_id
              AND audit.actor_type = 'SYSTEM'
              AND audit.action = 'ATTEMPT_CLEANED'
              AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = OLD.id::text
              AND audit.request_id = 'source-attempt:' || OLD.id::text || ':' || OLD.cleanup_attempt_epoch::text
              AND audit.payload_hash = OLD.cleanup_digest
        ) INTO cleanup_receipt_exists;
        IF OLD.stage_code <> 'CLEANING_UP' OR OLD.pending_transition <> 'DELAY' OR
           OLD.pending_transition_digest IS DISTINCT FROM asset_catalog_source_run_delay_intent_digest(
               OLD, OLD.pending_transition_reason, OLD.pending_transition_not_before
           ) OR OLD.cleanup_status NOT IN ('REVOKED', 'NO_CREDENTIAL') OR
           NOT asset_catalog_sha256_valid(OLD.cleanup_digest) OR NOT cleanup_receipt_exists OR
           NEW.stage_code <> 'DELAYED' OR NEW.pending_transition IS NOT NULL OR
           NEW.pending_transition_reason IS NOT NULL OR NEW.pending_transition_not_before IS NOT NULL OR
           NEW.pending_transition_digest IS NOT NULL OR NEW.lease_owner IS NOT NULL OR
           NEW.lease_expires_at IS NOT NULL OR NEW.fence_token_hash IS NOT NULL OR
           NEW.fence_epoch IS DISTINCT FROM OLD.fence_epoch OR
           NEW.heartbeat_sequence IS DISTINCT FROM OLD.heartbeat_sequence OR
           NEW.heartbeat_at IS DISTINCT FROM OLD.heartbeat_at OR
           NEW.started_at IS DISTINCT FROM OLD.started_at OR NEW.completed_at IS NOT NULL OR
           NEW.cleanup_status IS DISTINCT FROM OLD.cleanup_status OR
           NEW.cleanup_attempt_id IS DISTINCT FROM OLD.cleanup_attempt_id OR
           NEW.cleanup_attempt_epoch IS DISTINCT FROM OLD.cleanup_attempt_epoch OR
           NEW.cleanup_digest IS DISTINCT FROM OLD.cleanup_digest OR
           progress_changed OR work_changed OR rollover_changed OR terminal_facts_changed THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'delay consumes an exact receipted cleanup transition and releases only the lease',
                CONSTRAINT = 'asset_source_runs_delay_guard';
        END IF;
        NEW.not_before := OLD.pending_transition_not_before;
        RETURN NEW;
    END IF;

    IF OLD.cleanup_status IN ('REVOKED', 'UNCERTAIN') AND
       NEW.cleanup_status = OLD.cleanup_status THEN
        SELECT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = OLD.tenant_id AND audit.workspace_id = OLD.workspace_id
              AND audit.actor_type = 'SYSTEM'
              AND audit.action = 'ATTEMPT_CLEANED'
              AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = OLD.id::text
              AND audit.request_id = 'source-attempt:' || OLD.id::text || ':' ||
                    OLD.cleanup_attempt_epoch::text
              AND audit.payload_hash = OLD.cleanup_digest
        ) INTO sealed_cleanup_receipt_exists;
        sealed_cleanup_reclaim := COALESCE((
            current_source.source_kind <> 'MANUAL' AND
            OLD.status IN ('RUNNING', 'FINALIZING') AND NEW.status = OLD.status AND
            OLD.stage_code = 'CLEANING_UP' AND NEW.stage_code = 'CLEANING_UP' AND
            OLD.lease_expires_at <= now_at AND lease_identity_changed AND
            asset_catalog_sha256_valid(OLD.cleanup_digest) AND sealed_cleanup_receipt_exists
        ), false);
    END IF;

    IF OLD.cleanup_status IN ('REVOKED', 'NO_CREDENTIAL', 'UNCERTAIN') AND
       NEW.cleanup_status = OLD.cleanup_status AND (
            progress_changed OR rollover_changed OR
            NEW.stage_code IN ('VALIDATING', 'READING', 'NORMALIZING', 'APPLYING') OR
            ((NEW.heartbeat_sequence <> OLD.heartbeat_sequence OR
                NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at) AND
                sealed_cleanup_reclaim IS NOT TRUE)
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'cleaned or uncertain attempt cannot resume provider progress',
            CONSTRAINT = 'asset_source_runs_cleanup_transition_guard';
    END IF;

    IF pending_changed AND NOT (
       (OLD.pending_transition IS NULL AND NEW.pending_transition = 'DELAY' AND
        OLD.status = 'RUNNING' AND NEW.status = 'RUNNING' AND NEW.stage_code = 'CLEANING_UP') OR
       (OLD.pending_transition = 'DELAY' AND NEW.pending_transition IS NULL AND
        OLD.status = 'RUNNING' AND OLD.stage_code = 'CLEANING_UP' AND
        NEW.status = 'DELAYED' AND NEW.stage_code = 'DELAYED') OR
       (OLD.pending_transition = 'DELAY' AND NEW.pending_transition IS NULL AND
        OLD.status = 'RUNNING' AND NEW.status = 'FINALIZING' AND
        OLD.stage_code = 'CLEANING_UP' AND NEW.stage_code = 'CLEANING_UP' AND
        OLD.cleanup_status = 'PENDING' AND NEW.cleanup_status = 'UNCERTAIN' AND
        NEW.work_result_kind = 'FAILURE_INTENT' AND NEW.work_result_status = 'FAILED' AND
        asset_catalog_sha256_valid(NEW.work_result_digest))) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'delay intent is write-once and consumed only by the cleanup-to-delay transition',
            CONSTRAINT = 'asset_source_runs_pending_transition_guard';
    END IF;
    IF NEW.pending_transition = 'DELAY' AND
       NEW.pending_transition_digest IS DISTINCT FROM asset_catalog_source_run_delay_intent_digest(
           NEW, NEW.pending_transition_reason, NEW.pending_transition_not_before
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'delay intent must remain bound to the exact cleanup attempt facts',
            CONSTRAINT = 'asset_source_runs_pending_transition_guard';
    END IF;
    IF OLD.pending_transition IS NULL AND NEW.pending_transition = 'DELAY' AND (
       NEW.pending_transition_not_before <= now_at OR
       NEW.pending_transition_not_before > now_at + make_interval(secs => current_revision.backpressure_max_seconds) OR
       (current_source.source_kind = 'MANUAL' AND (
            OLD.cleanup_status <> 'NOT_OPENED' OR NEW.cleanup_attempt_id IS NOT NULL OR
            NEW.cleanup_attempt_epoch <> 0
       )) OR
       (current_source.source_kind <> 'MANUAL' AND (
            OLD.cleanup_status <> 'PENDING' OR NEW.cleanup_status <> 'PENDING' OR
            NEW.cleanup_attempt_id IS NULL OR NEW.cleanup_attempt_epoch <= 0 OR
            NEW.cleanup_attempt_id IS DISTINCT FROM OLD.cleanup_attempt_id OR
            NEW.cleanup_attempt_epoch IS DISTINCT FROM OLD.cleanup_attempt_epoch
       ))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'delay intent must be created once for the exact open attempt inside the revision backpressure window',
            CONSTRAINT = 'asset_source_runs_pending_transition_guard';
    END IF;

    IF OLD.status IN ('QUEUED', 'DELAYED') THEN
        IF NEW.status = 'CANCELLED' THEN
            IF source_admitted IS TRUE OR (OLD.status = 'DELAYED' AND (
                OLD.cleanup_status NOT IN ('REVOKED', 'NO_CREDENTIAL') OR OLD.work_result_kind IS NOT NULL
            )) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'only ineligible released no-result work can be cancelled',
                    CONSTRAINT = 'asset_source_runs_cancel_guard';
            END IF;
            IF NEW.stage_code <> 'COMPLETED' OR NEW.work_result_kind IS NOT NULL OR progress_changed OR
               NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR NEW.fence_token_hash IS NOT NULL OR
               NEW.terminal_command_sha256 IS NOT NULL OR NEW.pending_transition IS NOT NULL OR
               NEW.started_at IS DISTINCT FROM OLD.started_at OR
               NEW.heartbeat_at IS DISTINCT FROM OLD.heartbeat_at OR
               NEW.fence_epoch IS DISTINCT FROM OLD.fence_epoch OR
               NEW.heartbeat_sequence IS DISTINCT FROM OLD.heartbeat_sequence OR
               terminal_facts_changed THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'ineligible cancellation cannot fabricate progress, lease, or work result',
                    CONSTRAINT = 'asset_source_runs_cancel_guard';
            END IF;
            IF (NEW.run_kind = 'VALIDATION' OR current_source.source_kind = 'MANUAL') AND
               current_setting('transaction_isolation') <> 'serializable' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'validation and synchronous MANUAL_V1 cancellation closure requires a serializable transaction',
                    CONSTRAINT = 'asset_source_runs_terminal_isolation_guard';
            END IF;
            NEW.completed_at := now_at;
            RETURN NEW;
        END IF;
        IF source_admitted IS NOT TRUE OR
           (current_source.next_allowed_at IS NOT NULL AND current_source.next_allowed_at > now_at) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'claim requires the current source gate, revision, checkpoint, and backpressure window',
                CONSTRAINT = 'asset_source_runs_claim_admission_guard';
        END IF;
        IF now_at < OLD.not_before OR NEW.status <> 'RUNNING' OR
           NEW.stage_code <> (CASE WHEN NEW.run_kind = 'VALIDATION' THEN 'VALIDATING' ELSE 'READING' END) OR
           NEW.lease_owner IS NULL OR NEW.fence_token_hash IS NULL OR NEW.lease_expires_at <= now_at OR
           NEW.fence_epoch <> OLD.fence_epoch + 1 OR NEW.heartbeat_sequence <> OLD.heartbeat_sequence + 1 OR
           progress_changed OR work_changed OR NEW.completed_at IS NOT NULL OR rollover_changed OR
           (cleanup_changed AND NEW.cleanup_status <> 'NOT_OPENED') OR
           NEW.pending_transition IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'claim must establish exactly one new live fence and heartbeat',
                CONSTRAINT = 'asset_source_runs_claim_guard';
        END IF;
        IF OLD.status = 'QUEUED' THEN
            NEW.started_at := now_at;
        ELSIF NEW.started_at IS DISTINCT FROM OLD.started_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'delayed run keeps its original start time',
                CONSTRAINT = 'asset_source_runs_started_at_guard';
        END IF;
        NEW.heartbeat_at := now_at;
        RETURN NEW;
    END IF;

    IF NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'claimed run start time is immutable',
            CONSTRAINT = 'asset_source_runs_started_at_guard';
    END IF;
    IF NEW.stage_code IS DISTINCT FROM OLD.stage_code AND NOT (
       (lease_identity_changed AND NEW.stage_code = 'CLEANING_UP') OR
       (OLD.status = 'RUNNING' AND NEW.status = 'RUNNING' AND (
            (OLD.stage_code = 'READING' AND NEW.stage_code IN ('NORMALIZING', 'CLEANING_UP')) OR
            (OLD.stage_code = 'NORMALIZING' AND NEW.stage_code IN ('APPLYING', 'CLEANING_UP')) OR
            (OLD.stage_code = 'APPLYING' AND NEW.stage_code IN ('READING', 'CLEANING_UP')) OR
            (OLD.stage_code = 'VALIDATING' AND NEW.stage_code = 'CLEANING_UP')
	       )) OR
	       (OLD.status = 'RUNNING' AND NEW.status = 'FINALIZING' AND NEW.stage_code = 'CLEANING_UP') OR
	       (OLD.status = 'FINALIZING' AND NEW.status IN ('SUCCEEDED', 'PARTIAL', 'FAILED') AND
            OLD.stage_code = 'CLEANING_UP' AND NEW.stage_code = 'COMPLETED')) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'run stage must follow the closed validation, page, cleanup, and terminal graph',
            CONSTRAINT = 'asset_source_runs_stage_transition_guard';
    END IF;
    IF lease_identity_changed THEN
        IF OLD.lease_expires_at > now_at OR NEW.lease_owner IS NULL OR NEW.fence_token_hash IS NULL OR
           NEW.lease_expires_at <= now_at OR NEW.fence_epoch <> OLD.fence_epoch + 1 OR
           NEW.heartbeat_sequence <> OLD.heartbeat_sequence + 1 OR progress_changed OR work_changed OR
           rollover_changed OR cleanup_changed OR
           (OLD.cleanup_status = 'PENDING' AND NEW.stage_code <> 'CLEANING_UP') OR
           (OLD.cleanup_status IN ('REVOKED', 'NO_CREDENTIAL', 'UNCERTAIN') AND
                NEW.stage_code <> 'CLEANING_UP') OR
           (source_admitted IS NOT TRUE AND NEW.stage_code <> 'CLEANING_UP') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'reclaim requires expiry, the next fence, and cleanup-only handling of an open attempt',
                CONSTRAINT = 'asset_source_runs_reclaim_guard';
        END IF;
        NEW.heartbeat_at := now_at;
    ELSIF NEW.fence_epoch IS DISTINCT FROM OLD.fence_epoch THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'current holder cannot change its fence epoch',
            CONSTRAINT = 'asset_source_runs_fence_guard';
    ELSIF NEW.heartbeat_sequence = OLD.heartbeat_sequence + 1 THEN
        IF OLD.lease_expires_at <= now_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'expired lease holder cannot heartbeat, extend, or advance work',
                CONSTRAINT = 'asset_source_runs_lease_expired_guard';
        END IF;
        IF source_admitted IS NOT TRUE THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'source drift forbids heartbeat, checkpoint, and provider progress',
                CONSTRAINT = 'asset_source_runs_source_admission_guard';
        END IF;
        IF NEW.lease_expires_at <= now_at OR NEW.lease_expires_at < OLD.lease_expires_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'heartbeat must retain a live non-regressing lease expiry',
                CONSTRAINT = 'asset_source_runs_heartbeat_guard';
        END IF;
        NEW.heartbeat_at := now_at;
    ELSIF NEW.heartbeat_sequence = OLD.heartbeat_sequence THEN
        IF NEW.heartbeat_at IS DISTINCT FROM OLD.heartbeat_at OR
           NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'lease time cannot change without the next heartbeat sequence',
                CONSTRAINT = 'asset_source_runs_heartbeat_guard';
        END IF;
        IF OLD.lease_expires_at <= now_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'expired lease holder cannot mutate the run',
                CONSTRAINT = 'asset_source_runs_lease_expired_guard';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'heartbeat sequence must stay fixed or advance exactly once',
            CONSTRAINT = 'asset_source_runs_heartbeat_guard';
    END IF;

    IF source_admitted IS NOT TRUE AND NOT lease_identity_changed AND (
       progress_changed OR rollover_changed OR NEW.heartbeat_sequence <> OLD.heartbeat_sequence OR
       NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at OR
       NEW.stage_code NOT IN ('CLEANING_UP', 'COMPLETED') OR
       (work_changed AND NEW.work_result_kind <> 'FAILURE_INTENT')) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'source drift permits only non-extending cleanup and deterministic failure',
            CONSTRAINT = 'asset_source_runs_source_admission_guard';
    END IF;

    IF snapshot_changed AND (
       OLD.status <> 'RUNNING' OR NEW.status NOT IN ('RUNNING', 'FINALIZING') OR
       NEW.page_sequence <> OLD.page_sequence + 1 OR NOT NEW.final_page OR
       (NEW.complete_snapshot AND (
            NEW.relation_page_sequence <> OLD.relation_page_sequence + 1 OR
            NEW.relation_page_digest IS NULL OR
            (NEW.relation_page_digest IS NOT DISTINCT FROM OLD.relation_page_digest AND
             NEW.relation_page_digest IS DISTINCT FROM 'b89ad607e709ef2ea85f7fc6eb0f80e32ae3ecf234220907a0fe718825f7c151')
       )) OR
       (NEW.run_kind = 'MANUAL_MUTATION' AND (NEW.complete_snapshot OR NEW.effective_complete_snapshot)) OR
       (NEW.run_kind <> 'MANUAL_MUTATION' AND
           NEW.effective_complete_snapshot IS DISTINCT FROM (NEW.complete_snapshot AND NEW.rejected_count = 0))) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'snapshot flags change only with an accepted final page and exact closure eligibility',
            CONSTRAINT = 'asset_source_runs_snapshot_transition_guard';
    END IF;

    IF progress_changed THEN
        IF OLD.status <> 'RUNNING' OR NEW.status NOT IN ('RUNNING', 'FINALIZING') OR
           OLD.stage_code NOT IN ('NORMALIZING', 'APPLYING') OR
           NEW.page_sequence <> OLD.page_sequence + 1 OR
           NEW.checkpoint_version <> OLD.checkpoint_version + 1 OR
           NEW.page_digest IS NULL OR NEW.page_digest IS NOT DISTINCT FROM OLD.page_digest OR
           (NEW.run_kind <> 'MANUAL_MUTATION' AND NEW.cursor_after_sha256 IS NULL) OR
           NEW.heartbeat_sequence <> OLD.heartbeat_sequence + 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'accepted page must advance page, checkpoint, heartbeat, and counts exactly once',
                CONSTRAINT = 'asset_source_runs_checkpoint_page_guard';
        END IF;
        SELECT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = NEW.tenant_id AND audit.workspace_id = NEW.workspace_id
              AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
              AND audit.actor_type = 'SYSTEM' AND audit.actor_id = NEW.lease_owner
              AND audit.action = 'PAGE_APPLIED'
              AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = NEW.id::text
              AND audit.request_id = 'source-page:' || NEW.id::text || ':' || NEW.page_sequence::text
              AND audit.payload_hash = NEW.page_digest
        ) INTO page_receipt_exists;
        relation_receipt_exists := true;
        IF NEW.relation_page_sequence = OLD.relation_page_sequence + 1 THEN
            SELECT EXISTS (
                SELECT 1 FROM audit_records AS audit
                WHERE audit.tenant_id = NEW.tenant_id AND audit.workspace_id = NEW.workspace_id
                  AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
                  AND audit.actor_type = 'SYSTEM' AND audit.actor_id = NEW.lease_owner
                  AND audit.action = 'RELATION_PAGE_COMMITTED'
                  AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = NEW.id::text
                  AND audit.request_id = 'source-relation-page:' || NEW.id::text || ':' || NEW.relation_page_sequence::text
                  AND audit.payload_hash = NEW.relation_page_digest
            ) INTO relation_receipt_exists;
        END IF;
        IF source_admitted IS NOT TRUE OR NEW.page_digest IS NOT DISTINCT FROM OLD.page_digest OR
           (NEW.relation_page_sequence = OLD.relation_page_sequence AND
                NEW.relation_page_digest IS DISTINCT FROM OLD.relation_page_digest) OR
           (NEW.relation_page_sequence = OLD.relation_page_sequence + 1 AND
                (NEW.relation_page_digest IS NULL OR
                 (NEW.relation_page_digest IS NOT DISTINCT FROM OLD.relation_page_digest AND
                  NEW.relation_page_digest IS DISTINCT FROM 'b89ad607e709ef2ea85f7fc6eb0f80e32ae3ecf234220907a0fe718825f7c151'))) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'accepted page requires exact source CAS and item/relation coordinates',
                CONSTRAINT = 'asset_source_runs_checkpoint_page_guard';
        END IF;
        IF NOT page_receipt_exists OR NOT relation_receipt_exists THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'accepted page requires exact immutable item and relation receipts',
                CONSTRAINT = 'asset_source_runs_page_closure_guard';
        END IF;
        IF OLD.final_page THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'no page may follow an accepted final page',
                CONSTRAINT = 'asset_source_runs_snapshot_transition_guard';
        END IF;
    END IF;

    IF OLD.status = 'RUNNING' AND NEW.status = 'FINALIZING' THEN
        IF NEW.stage_code <> 'CLEANING_UP' OR NOT work_changed OR NEW.work_result_kind IS NULL OR
           NEW.terminal_command_sha256 IS NOT NULL OR NEW.pending_transition IS NOT NULL OR
           (NEW.work_result_kind = 'DATA_PROJECTION' AND NOT NEW.final_page) OR
           (NEW.work_result_kind = 'VALIDATION_PROOF' AND NEW.run_kind <> 'VALIDATION') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'finalization requires one immutable typed work result and cleanup-only stage',
                CONSTRAINT = 'asset_source_runs_finalization_guard';
        END IF;
        IF NEW.terminal_failure_override IS NOT NULL THEN
            expected_override_digest := asset_catalog_source_run_failure_override_digest(NEW, NEW.failure_code);
            IF NEW.failure_code IS NULL OR
               NEW.terminal_failure_override IS DISTINCT FROM 'CLEANUP_UNCERTAIN' OR
               NEW.terminal_failure_override_digest IS DISTINCT FROM expected_override_digest THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'pre-terminal cleanup override must bind the exact uncertain cleanup and failure',
                    CONSTRAINT = 'asset_source_runs_terminal_transition_guard';
            END IF;
        END IF;
        NEW.work_result_recorded_at := now_at;
        RETURN NEW;
    END IF;

    IF OLD.status = 'FINALIZING' AND OLD.terminal_failure_override IS NOT NULL AND (
       NEW.terminal_failure_override IS DISTINCT FROM OLD.terminal_failure_override OR
       NEW.terminal_failure_override_digest IS DISTINCT FROM OLD.terminal_failure_override_digest OR
       NEW.failure_code IS DISTINCT FROM OLD.failure_code
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'persisted cleanup-uncertain terminal override is write-once',
            CONSTRAINT = 'asset_source_runs_terminal_transition_guard';
    END IF;

    IF OLD.status = 'FINALIZING' THEN
        IF work_changed THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'persisted work result is immutable during cleanup',
                CONSTRAINT = 'asset_source_runs_work_result_immutable_guard';
        END IF;
        IF NEW.status IN ('SUCCEEDED', 'PARTIAL', 'FAILED') THEN
            direct_failure_without_cleanup := COALESCE((
                current_source.source_kind <> 'MANUAL' AND source_admitted IS NOT TRUE AND
                NEW.status = 'FAILED' AND NEW.work_result_kind = 'FAILURE_INTENT' AND
                NEW.work_result_status = 'FAILED' AND
                asset_catalog_sha256_valid(NEW.work_result_digest) AND NEW.failure_code IS NOT NULL AND
                NEW.cleanup_status = 'NOT_OPENED' AND NEW.cleanup_attempt_id IS NULL AND
                NEW.cleanup_attempt_epoch = 0 AND NEW.cleanup_digest IS NULL AND NOT cleanup_changed AND
                NEW.terminal_failure_override IS NULL AND
                NEW.terminal_failure_override_digest IS NULL AND
                NEW.pending_transition IS NULL AND NEW.pending_transition_reason IS NULL AND
                NEW.pending_transition_not_before IS NULL AND NEW.pending_transition_digest IS NULL AND
                NEW.page_sequence = 0 AND NEW.page_digest IS NULL AND
                NEW.relation_page_sequence = 0 AND NEW.relation_page_digest IS NULL AND
                NEW.cursor_after_sha256 IS NULL AND
                NEW.checkpoint_version IS NOT DISTINCT FROM OLD.checkpoint_version AND
                NOT NEW.final_page AND NOT NEW.complete_snapshot AND
                NOT NEW.effective_complete_snapshot AND NOT progress_changed AND
                NEW.observed_count = 0 AND NEW.created_count = 0 AND
                NEW.changed_count = 0 AND NEW.unchanged_count = 0 AND
                NEW.conflict_count = 0 AND NEW.missing_count = 0 AND
                NEW.stale_count = 0 AND NEW.restored_count = 0 AND
                NEW.tombstoned_count = 0 AND NEW.rejected_count = 0 AND
                NEW.lineage_rollover_reason IS NULL AND
                NEW.lineage_rollover_evidence_digest IS NULL AND NOT rollover_changed
            ), false);
            expected_terminal_digest := asset_catalog_source_run_terminal_digest(NEW, NEW.status, NEW.failure_code);
            SELECT EXISTS (
                SELECT 1 FROM audit_records AS audit
                WHERE audit.tenant_id = NEW.tenant_id AND audit.workspace_id = NEW.workspace_id
                  AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
                  AND audit.actor_type = 'SYSTEM' AND audit.actor_id = NEW.lease_owner
                  AND audit.action = 'TERMINAL_COMMITTED'
                  AND audit.resource_type = 'ASSET_SOURCE_RUN' AND audit.resource_id = NEW.id::text
                  AND audit.request_id = 'source-terminal:' || NEW.id::text
                  AND audit.payload_hash = expected_terminal_digest
            ) INTO terminal_receipt_exists;
            IF NOT terminal_receipt_exists OR NEW.stage_code <> 'COMPLETED' OR
               (NEW.cleanup_status NOT IN ('REVOKED', 'NO_CREDENTIAL', 'UNCERTAIN') AND
                    direct_failure_without_cleanup IS NOT TRUE) OR cleanup_changed OR
               NEW.terminal_command_sha256 IS DISTINCT FROM expected_terminal_digest OR
               NEW.pending_transition IS NOT NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'terminal run requires its immutable terminal receipt and cleanup proof',
                    CONSTRAINT = 'asset_source_runs_terminal_receipt_guard';
            END IF;
            IF current_setting('transaction_isolation') <> 'serializable' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'terminal source run closure requires a serializable transaction',
                    CONSTRAINT = 'asset_source_runs_terminal_isolation_guard';
            END IF;
            IF NEW.status IN ('SUCCEEDED', 'PARTIAL') AND (
                NEW.cleanup_status NOT IN ('REVOKED', 'NO_CREDENTIAL') OR
                NEW.terminal_failure_override IS NOT NULL OR NEW.work_result_status <> NEW.status OR
                NEW.failure_code IS NOT NULL OR (NEW.status = 'PARTIAL' AND NEW.run_kind = 'VALIDATION')
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'successful terminal status must match the persisted work result and certain cleanup',
                    CONSTRAINT = 'asset_source_runs_terminal_transition_guard';
            END IF;
            IF NEW.status = 'FAILED' AND (
                NEW.failure_code IS NULL OR
                (NEW.work_result_status <> 'FAILED' AND
                    NEW.terminal_failure_override IS DISTINCT FROM 'CLEANUP_UNCERTAIN') OR
                (NEW.cleanup_status = 'UNCERTAIN' AND
                    NEW.terminal_failure_override IS DISTINCT FROM 'CLEANUP_UNCERTAIN') OR
                (NEW.cleanup_status <> 'UNCERTAIN' AND NEW.terminal_failure_override IS NOT NULL)
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'failed terminal status requires failure intent or cleanup-uncertain override',
                    CONSTRAINT = 'asset_source_runs_terminal_transition_guard';
            END IF;
            IF NEW.terminal_failure_override = 'CLEANUP_UNCERTAIN' THEN
                expected_override_digest := asset_catalog_source_run_failure_override_digest(NEW, NEW.failure_code);
                IF NEW.terminal_failure_override_digest IS DISTINCT FROM expected_override_digest THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '55000', MESSAGE = 'cleanup-uncertain override must bind the exact persisted result and failure',
                        CONSTRAINT = 'asset_source_runs_terminal_transition_guard';
                END IF;
            END IF;
            NEW.completed_at := now_at;
            RETURN NEW;
        END IF;
        IF NEW.status = 'FINALIZING' THEN
            IF NEW.completed_at IS NOT NULL OR NEW.terminal_command_sha256 IS NOT NULL OR
               (terminal_facts_changed AND (
                    NEW.terminal_failure_override IS DISTINCT FROM 'CLEANUP_UNCERTAIN' OR
                    NEW.failure_code IS NULL OR
                    NEW.terminal_failure_override_digest IS DISTINCT FROM
                        asset_catalog_source_run_failure_override_digest(NEW, NEW.failure_code)
               )) OR
               (NOT cleanup_changed AND NOT pending_changed AND NOT lease_identity_changed AND
                NEW.heartbeat_sequence = OLD.heartbeat_sequence AND NOT terminal_facts_changed) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'finalizing mutation must be fenced cleanup, intent, heartbeat, or exact failure override',
                    CONSTRAINT = 'asset_source_runs_finalizing_mutation_guard';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'RUNNING' AND NEW.status = 'RUNNING' THEN
        IF work_changed OR terminal_facts_changed OR NEW.completed_at IS NOT NULL OR
           (NOT progress_changed AND NOT lease_identity_changed AND NOT cleanup_changed AND
            NOT pending_changed AND NOT rollover_changed AND
            NEW.heartbeat_sequence = OLD.heartbeat_sequence AND
            NEW.stage_code IS NOT DISTINCT FROM OLD.stage_code) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'running mutation must be a stage, heartbeat, cleanup, intent, or accepted page transition',
                CONSTRAINT = 'asset_source_runs_running_mutation_guard';
        END IF;
        RETURN NEW;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_source_runs_mutation_guard
    BEFORE INSERT OR UPDATE ON public.asset_source_runs
    FOR EACH ROW EXECUTE FUNCTION public.enforce_asset_source_run_mutation();

CREATE OR REPLACE FUNCTION public.validate_asset_source_run_page_closure() RETURNS trigger AS $$
DECLARE
    current_run asset_source_runs%ROWTYPE;
    current_source asset_sources%ROWTYPE;
    persisted_observation_count bigint;
BEGIN
    IF NEW.page_sequence IS NOT DISTINCT FROM OLD.page_sequence THEN
        RETURN NULL;
    END IF;
    SELECT * INTO current_run
    FROM asset_source_runs
    WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id AND id = NEW.id;
    SELECT * INTO current_source
    FROM asset_sources
    WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id AND id = NEW.source_id;
    SELECT count(*) INTO persisted_observation_count
    FROM asset_observations AS observation
    WHERE observation.tenant_id = NEW.tenant_id
      AND observation.workspace_id = NEW.workspace_id
      AND observation.source_id = NEW.source_id
      AND observation.run_id = NEW.id;

    IF current_run.page_sequence IS DISTINCT FROM NEW.page_sequence OR
       current_run.page_digest IS DISTINCT FROM NEW.page_digest OR
       current_run.relation_page_sequence IS DISTINCT FROM NEW.relation_page_sequence OR
       current_run.relation_page_digest IS DISTINCT FROM NEW.relation_page_digest OR
       current_run.checkpoint_version IS DISTINCT FROM NEW.checkpoint_version OR
       current_run.observed_count IS DISTINCT FROM NEW.observed_count OR
       persisted_observation_count IS DISTINCT FROM NEW.observed_count OR
       current_source.status <> 'ACTIVE' OR
       current_source.published_revision IS DISTINCT FROM NEW.source_revision OR
       current_source.published_revision_digest IS DISTINCT FROM NEW.source_revision_digest OR
       current_source.checkpoint_revision IS DISTINCT FROM NEW.source_revision OR
       current_source.checkpoint_version IS DISTINCT FROM NEW.checkpoint_version OR
       ((current_source.source_kind = 'MANUAL' AND current_source.checkpoint_sha256 IS NOT NULL) OR
       (current_source.source_kind <> 'MANUAL' AND
            current_source.checkpoint_sha256 IS DISTINCT FROM NEW.cursor_after_sha256)) OR
       NOT COALESCE(
           (NEW.lineage_rollover_reason IS NULL AND
                current_source.gate_status = 'AVAILABLE' AND
                current_source.gate_revision = NEW.gate_revision) OR
           (NEW.lineage_rollover_reason IS NOT NULL AND
                current_source.gate_status = 'DEGRADED' AND
                current_source.gate_reason_code = 'CHECKPOINT_LINEAGE_ROLLOVER' AND
                current_source.gate_revision = NEW.gate_revision + 1),
           false
       ) OR
       NOT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = NEW.tenant_id
              AND audit.workspace_id = NEW.workspace_id
              AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
              AND audit.actor_type = 'SYSTEM'
              AND audit.actor_id = NEW.lease_owner
              AND audit.action = 'PAGE_APPLIED'
              AND audit.resource_type = 'ASSET_SOURCE_RUN'
              AND audit.resource_id = NEW.id::text
              AND audit.request_id = 'source-page:' || NEW.id::text || ':' || NEW.page_sequence::text
              AND audit.payload_hash = NEW.page_digest
       ) OR (NEW.relation_page_sequence > OLD.relation_page_sequence AND NOT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = NEW.tenant_id
              AND audit.workspace_id = NEW.workspace_id
              AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
              AND audit.actor_type = 'SYSTEM'
              AND audit.actor_id = NEW.lease_owner
              AND audit.action = 'RELATION_PAGE_COMMITTED'
              AND audit.resource_type = 'ASSET_SOURCE_RUN'
              AND audit.resource_id = NEW.id::text
              AND audit.request_id = 'source-relation-page:' || NEW.id::text || ':' || NEW.relation_page_sequence::text
              AND audit.payload_hash = NEW.relation_page_digest
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'source page, observations, checkpoint, and receipts must close atomically',
            CONSTRAINT = 'asset_source_runs_page_closure_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE CONSTRAINT TRIGGER asset_source_runs_page_closure_guard
    AFTER UPDATE ON public.asset_source_runs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_run_page_closure();

CREATE OR REPLACE FUNCTION public.validate_asset_source_run_terminal_closure() RETURNS trigger AS $$
DECLARE
    current_run asset_source_runs%ROWTYPE;
    current_source asset_sources%ROWTYPE;
    current_revision asset_source_revisions%ROWTYPE;
    expected_terminal_digest text;
    expected_rejection_digest text;
BEGIN
    SELECT * INTO current_run
    FROM asset_source_runs
    WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id AND id = NEW.id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT * INTO current_source
    FROM asset_sources
    WHERE tenant_id = current_run.tenant_id
      AND workspace_id = current_run.workspace_id
      AND id = current_run.source_id;
    SELECT * INTO current_revision
    FROM asset_source_revisions
    WHERE tenant_id = current_run.tenant_id
      AND workspace_id = current_run.workspace_id
      AND source_id = current_run.source_id
      AND revision = current_run.source_revision
      AND canonical_revision_digest = current_run.source_revision_digest;

    IF current_source.source_kind = 'MANUAL' AND current_run.cleanup_status = 'NO_CREDENTIAL' AND (
       current_source.provider_kind <> 'MANUAL_V1' OR current_revision.profile_code <> 'MANUAL_V1' OR
       current_revision.credential_reference_id IS NOT NULL OR
       current_revision.trust_reference_id IS NOT NULL OR
       current_revision.network_policy_reference_id IS NOT NULL OR
       current_run.cleanup_attempt_id IS NOT NULL OR current_run.cleanup_attempt_epoch <> 0 OR
       current_run.cleanup_digest IS DISTINCT FROM asset_catalog_source_run_no_credential_digest(current_run) OR
       current_run.status NOT IN ('SUCCEEDED', 'PARTIAL', 'FAILED') OR NOT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = current_run.tenant_id
              AND audit.workspace_id = current_run.workspace_id
              AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
              AND audit.actor_type = 'SYSTEM'
              AND audit.actor_id = current_run.lease_owner
              AND audit.action = 'ATTEMPT_CLEANED'
              AND audit.resource_type = 'ASSET_SOURCE_RUN'
              AND audit.resource_id = current_run.id::text
              AND audit.request_id = 'source-attempt:' || current_run.id::text || ':0'
              AND audit.payload_hash = current_run.cleanup_digest
       )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'MANUAL_V1 no-credential proof and terminal closure must share one serializable transaction',
            CONSTRAINT = 'asset_source_runs_manual_cleanup_closure_guard';
    END IF;

    IF current_source.source_kind = 'MANUAL' AND
       current_run.status NOT IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'synchronous MANUAL_V1 run cannot outlive its creating transaction',
            CONSTRAINT = 'asset_source_runs_manual_atomic_guard';
    END IF;

    IF current_run.cleanup_status = 'UNCERTAIN' AND current_run.lineage_rollover_reason IS NULL AND (
       current_run.status <> 'FAILED' OR current_source.gate_status <> 'SUSPENDED' OR
       current_source.gate_reason_code IS DISTINCT FROM 'CLEANUP_UNCERTAIN' OR
       current_source.gate_revision <= current_run.gate_revision) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'uncertain cleanup must fail and suspend the source in the same transaction',
            CONSTRAINT = 'asset_source_runs_cleanup_uncertain_closure_guard';
    END IF;
    IF current_run.status NOT IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED') THEN
        RETURN NULL;
    END IF;

    IF current_run.status <> 'CANCELLED' THEN
        expected_terminal_digest := asset_catalog_source_run_terminal_digest(
            current_run, current_run.status, current_run.failure_code
        );
        IF current_run.terminal_command_sha256 IS DISTINCT FROM expected_terminal_digest OR NOT EXISTS (
            SELECT 1 FROM audit_records AS audit
            WHERE audit.tenant_id = current_run.tenant_id
              AND audit.workspace_id = current_run.workspace_id
              AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
              AND audit.actor_type = 'SYSTEM'
              AND audit.actor_id = current_run.lease_owner
              AND audit.action = 'TERMINAL_COMMITTED'
              AND audit.resource_type = 'ASSET_SOURCE_RUN'
              AND audit.resource_id = current_run.id::text
              AND audit.request_id = 'source-terminal:' || current_run.id::text
              AND audit.payload_hash = expected_terminal_digest
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'terminal run and exact terminal receipt must close in the same transaction',
                CONSTRAINT = 'asset_source_runs_terminal_closure_guard';
        END IF;
    END IF;

    IF current_run.cleanup_status = 'UNCERTAIN' AND current_run.lineage_rollover_reason IS NULL THEN
        IF current_source.gate_status <> 'SUSPENDED' OR
           current_source.gate_reason_code IS DISTINCT FROM 'CLEANUP_UNCERTAIN' OR
           current_source.gate_revision <= current_run.gate_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'cleanup uncertainty must suspend the source gate atomically',
                CONSTRAINT = 'asset_source_runs_cleanup_uncertain_closure_guard';
        END IF;
    END IF;

    IF current_run.run_kind = 'VALIDATION' THEN
        expected_rejection_digest := COALESCE(
            current_run.terminal_failure_override_digest,
            current_run.validation_proof_digest,
            current_run.work_result_digest,
            current_run.request_hash
        );
        IF current_run.status = 'SUCCEEDED' THEN
            IF current_revision.state <> 'VALIDATED' OR
               current_revision.validation_run_id IS DISTINCT FROM current_run.id OR
               current_revision.validation_digest IS DISTINCT FROM current_run.validation_digest THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'successful validation run requires exact VALIDATED revision closure',
                    CONSTRAINT = 'asset_source_runs_validation_closure_guard';
            END IF;
        ELSIF current_run.status IN ('FAILED', 'CANCELLED') THEN
            IF current_revision.state <> 'REJECTED' OR
               current_revision.validation_run_id IS DISTINCT FROM current_run.id OR
               current_revision.validation_digest IS DISTINCT FROM expected_rejection_digest THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'failed or cancelled validation run requires exact REJECTED revision closure',
                    CONSTRAINT = 'asset_source_runs_validation_closure_guard';
            END IF;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'validation run cannot close PARTIAL',
                CONSTRAINT = 'asset_source_runs_validation_closure_guard';
        END IF;
        RETURN NULL;
    END IF;

    IF current_run.status IN ('SUCCEEDED', 'PARTIAL') AND (
       current_source.published_revision IS DISTINCT FROM current_run.source_revision OR
       current_source.published_revision_digest IS DISTINCT FROM current_run.source_revision_digest OR
       (current_run.lineage_rollover_reason IS NULL AND (
            current_source.status <> 'ACTIVE' OR
            current_source.gate_status <> 'AVAILABLE' OR
            current_source.gate_revision <> current_run.gate_revision
       ))) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'terminal data run requires the same exact published source revision',
            CONSTRAINT = 'asset_source_runs_source_closure_guard';
    END IF;

    IF current_run.status = 'SUCCEEDED' THEN
        IF current_source.last_success_run_id IS DISTINCT FROM current_run.id OR
           current_source.last_success_at IS DISTINCT FROM current_run.completed_at OR
           (current_run.effective_complete_snapshot AND (
                current_source.last_complete_snapshot_run_id IS DISTINCT FROM current_run.id OR
                current_source.last_complete_snapshot_at IS DISTINCT FROM current_run.completed_at
           )) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'successful data run and exact source success pointers must close atomically',
                CONSTRAINT = 'asset_source_runs_success_pointer_closure_guard';
        END IF;
    ELSIF current_source.last_success_run_id IS NOT DISTINCT FROM current_run.id OR
          current_source.last_complete_snapshot_run_id IS NOT DISTINCT FROM current_run.id THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'non-successful run cannot own source success pointers',
            CONSTRAINT = 'asset_source_runs_success_pointer_closure_guard';
    END IF;

    IF current_run.lineage_rollover_reason IS NOT NULL THEN
        IF current_run.status = 'SUCCEEDED' THEN
            IF NOT current_run.effective_complete_snapshot OR
               current_source.gate_status <> 'AVAILABLE' OR
               current_source.gate_reason_code IS NOT NULL OR
               current_source.gate_revision <> current_run.gate_revision + 2 THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'rollover success requires effective full closure and AVAILABLE gate revision plus two',
                    CONSTRAINT = 'asset_source_runs_rollover_closure_guard';
            END IF;
        ELSIF current_source.gate_status <> 'SUSPENDED' OR
              current_source.gate_reason_code IS NULL OR
              current_source.gate_revision <> current_run.gate_revision + 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'rollover failure requires SUSPENDED gate revision plus two',
                CONSTRAINT = 'asset_source_runs_rollover_closure_guard';
        END IF;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE CONSTRAINT TRIGGER asset_source_runs_terminal_closure_guard
    AFTER INSERT OR UPDATE ON public.asset_source_runs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_run_terminal_closure();


CREATE OR REPLACE FUNCTION public.enforce_asset_observation_admission() RETURNS trigger AS $$
DECLARE
    current_run asset_source_runs%ROWTYPE;
    current_source asset_sources%ROWTYPE;
    current_revision asset_source_revisions%ROWTYPE;
    prior_observation asset_observations%ROWTYPE;
    current_asset assets%ROWTYPE;
    field_entry record;
    accepted_at timestamptz := transaction_timestamp();
    lease_checked_at timestamptz := clock_timestamp();
BEGIN
    IF NOT asset_catalog_field_provenance_valid(NEW.field_provenance) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'asset observation provenance must use the closed canonical shape',
            CONSTRAINT = 'asset_observations_provenance_admission_guard';
    END IF;
    IF NEW.observed_at IS DISTINCT FROM accepted_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'asset observation catalog acceptance time is server owned',
            CONSTRAINT = 'asset_observations_observed_at_guard';
    END IF;

    SELECT source.* INTO current_source
    FROM asset_sources AS source
    WHERE source.tenant_id = NEW.tenant_id
      AND source.workspace_id = NEW.workspace_id
      AND source.id = NEW.source_id
    FOR SHARE OF source;
    IF NOT FOUND OR current_source.provider_kind IS DISTINCT FROM NEW.provider_kind THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503', MESSAGE = 'asset observation requires the exact scoped source provider',
            CONSTRAINT = 'asset_observations_source_provider_fk';
    END IF;

    SELECT run.* INTO current_run
    FROM asset_source_runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.workspace_id = NEW.workspace_id
      AND run.source_id = NEW.source_id
      AND run.id = NEW.run_id
    FOR SHARE OF run;
    IF NOT FOUND OR current_run.source_revision IS DISTINCT FROM NEW.source_revision OR
       current_run.source_revision_digest IS DISTINCT FROM NEW.canonical_revision_digest THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503', MESSAGE = 'asset observation requires the exact scoped run revision',
            CONSTRAINT = 'asset_observations_run_revision_fk';
    END IF;
    IF current_run.run_kind = 'VALIDATION' OR current_run.status <> 'RUNNING' OR
       current_run.stage_code NOT IN ('NORMALIZING', 'APPLYING') OR
       current_run.lease_owner IS NULL OR current_run.lease_expires_at IS NULL OR
       current_run.lease_expires_at <= lease_checked_at OR current_run.fence_epoch <= 0 OR
       NEW.run_fence_epoch IS DISTINCT FROM current_run.fence_epoch OR
       NEW.run_page_sequence IS DISTINCT FROM current_run.page_sequence + 1 OR
       NEW.accepted_checkpoint_version IS DISTINCT FROM current_run.checkpoint_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset observation requires the next exact page under a live fenced data run',
            CONSTRAINT = 'asset_observations_live_run_guard';
    END IF;

    IF current_source.status <> 'ACTIVE' OR
       current_source.published_revision IS DISTINCT FROM NEW.source_revision OR
       current_source.published_revision_digest IS DISTINCT FROM NEW.canonical_revision_digest OR
       current_source.checkpoint_version IS DISTINCT FROM current_run.checkpoint_version OR
       current_source.checkpoint_sha256 IS DISTINCT FROM
           COALESCE(current_run.cursor_after_sha256, current_run.cursor_before_sha256) OR
       NOT COALESCE(
           (current_source.gate_status = 'AVAILABLE' AND
               current_source.gate_revision = current_run.gate_revision) OR
           (current_source.gate_status = 'DEGRADED' AND
               current_source.gate_reason_code = 'CHECKPOINT_LINEAGE_ROLLOVER' AND
               current_source.gate_revision = current_run.gate_revision + 1 AND
               current_run.lineage_rollover_reason IS NOT NULL AND
               current_run.lineage_rollover_evidence_digest IS NOT NULL),
           false
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset observation source gate, revision, or checkpoint drifted from its live run',
            CONSTRAINT = 'asset_observations_source_admission_guard';
    END IF;
    SELECT revision.* INTO current_revision
    FROM asset_source_revisions AS revision
    WHERE revision.tenant_id = NEW.tenant_id
      AND revision.workspace_id = NEW.workspace_id
      AND revision.source_id = NEW.source_id
      AND revision.revision = NEW.source_revision
      AND revision.canonical_revision_digest = NEW.canonical_revision_digest;
    IF NOT FOUND OR current_revision.source_definition_digest IS DISTINCT FROM NEW.source_definition_digest THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503', MESSAGE = 'asset observation requires the exact immutable source definition',
            CONSTRAINT = 'asset_observations_source_revision_fk';
    END IF;
    IF (NEW.freshness_kind = 'CATALOG_SEQUENCE') IS DISTINCT FROM
       (current_run.run_kind = 'MANUAL_MUTATION' AND current_source.source_kind = 'MANUAL') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'catalog sequence freshness is reserved for governed manual mutation',
            CONSTRAINT = 'asset_observations_freshness_profile_guard';
    END IF;
    IF NEW.freshness_kind = 'CATALOG_SEQUENCE' AND
       (NEW.freshness_order_sequence <> NEW.accepted_checkpoint_version OR
        NEW.accepted_checkpoint_version <> current_source.checkpoint_version + 1) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'manual catalog sequence must equal the next logical source checkpoint',
            CONSTRAINT = 'asset_observations_catalog_sequence_guard';
    END IF;

    SELECT asset.* INTO current_asset
    FROM assets AS asset
    WHERE asset.tenant_id = NEW.tenant_id
      AND asset.workspace_id = NEW.workspace_id
      AND asset.environment_id = NEW.environment_id
      AND asset.source_id = NEW.source_id
      AND asset.provider_kind = NEW.provider_kind
      AND asset.external_id = NEW.external_id
    FOR UPDATE OF asset;
    IF FOUND THEN
        IF NEW.previous_observation_id IS DISTINCT FROM current_asset.last_observation_id OR
           NEW.previous_chain_sha256 IS DISTINCT FROM current_asset.last_observation_chain_sha256 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'asset observation previous chain must equal the locked asset projection',
                CONSTRAINT = 'asset_observations_previous_projection_guard';
        END IF;
    ELSIF NEW.previous_observation_id IS NOT NULL OR NEW.previous_chain_sha256 IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'first asset observation cannot claim a previous chain',
            CONSTRAINT = 'asset_observations_previous_projection_guard';
    END IF;

    IF NEW.previous_observation_id IS NOT NULL THEN
        SELECT observation.* INTO prior_observation
        FROM asset_observations AS observation
        WHERE observation.tenant_id = NEW.tenant_id
          AND observation.workspace_id = NEW.workspace_id
          AND observation.environment_id = NEW.environment_id
          AND observation.source_id = NEW.source_id
          AND observation.provider_kind = NEW.provider_kind
          AND observation.external_id = NEW.external_id
          AND observation.id = NEW.previous_observation_id
          AND observation.observation_chain_sha256 = NEW.previous_chain_sha256
        FOR SHARE OF observation;
        IF NOT FOUND OR prior_observation.observed_at >= NEW.observed_at OR
           NEW.source_revision < prior_observation.source_revision OR
           (NEW.source_revision = prior_observation.source_revision AND (
                prior_observation.freshness_kind IS DISTINCT FROM NEW.freshness_kind OR
                (NEW.freshness_kind = 'OBJECT_TIME_SEQUENCE' AND (
                    (NEW.freshness_order_time, NEW.freshness_order_sequence) <
                        (prior_observation.freshness_order_time,
                            prior_observation.freshness_order_sequence) OR
                    ((NEW.freshness_order_time, NEW.freshness_order_sequence) =
                        (prior_observation.freshness_order_time,
                            prior_observation.freshness_order_sequence) AND (
                            NEW.run_id IS NOT DISTINCT FROM prior_observation.run_id OR
                            NEW.provider_version_sha256 IS DISTINCT FROM
                                prior_observation.provider_version_sha256 OR
                            NEW.provider_fact_sha256 IS DISTINCT FROM
                                prior_observation.provider_fact_sha256
                    ))
                )) OR
                (NEW.freshness_kind <> 'OBJECT_TIME_SEQUENCE' AND (
                    NEW.freshness_order_sequence < prior_observation.freshness_order_sequence OR
                    (NEW.freshness_order_sequence = prior_observation.freshness_order_sequence AND (
                        NEW.run_id IS NOT DISTINCT FROM prior_observation.run_id OR
                        NEW.provider_version_sha256 IS DISTINCT FROM
                            prior_observation.provider_version_sha256 OR
                        NEW.provider_fact_sha256 IS DISTINCT FROM
                            prior_observation.provider_fact_sha256
                    ))
                ))
           )) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'asset observation freshness must satisfy the closed revision and order comparison',
                CONSTRAINT = 'asset_observations_freshness_monotonic_guard';
        END IF;
    END IF;

    FOR field_entry IN
        SELECT value FROM jsonb_each(convert_from(NEW.field_provenance, 'UTF8')::jsonb)
    LOOP
        IF (field_entry.value->>'source_id')::uuid IS DISTINCT FROM NEW.source_id OR
           field_entry.value->>'provider_kind' IS DISTINCT FROM NEW.provider_kind OR
           (field_entry.value->>'source_revision')::bigint IS DISTINCT FROM NEW.source_revision OR
           (field_entry.value->>'observed_at')::timestamptz IS DISTINCT FROM NEW.observed_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset observation provenance facts must equal the accepted row',
                CONSTRAINT = 'asset_observations_provenance_fact_guard';
        END IF;
    END LOOP;
    NEW.created_at := accepted_at;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE TRIGGER asset_observations_admission_guard
    BEFORE INSERT ON public.asset_observations
    FOR EACH ROW EXECUTE FUNCTION public.enforce_asset_observation_admission();

CREATE OR REPLACE FUNCTION public.validate_asset_observation_page_closure() RETURNS trigger AS $$
DECLARE
    committed_run asset_source_runs%ROWTYPE;
    committed_source asset_sources%ROWTYPE;
BEGIN
    SELECT run.* INTO committed_run
    FROM asset_source_runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.workspace_id = NEW.workspace_id
      AND run.source_id = NEW.source_id
      AND run.id = NEW.run_id
      AND run.source_revision = NEW.source_revision
      AND run.source_revision_digest = NEW.canonical_revision_digest
    FOR SHARE OF run;
    IF NOT FOUND OR committed_run.fence_epoch IS DISTINCT FROM NEW.run_fence_epoch OR
       committed_run.page_sequence IS DISTINCT FROM NEW.run_page_sequence OR
       committed_run.checkpoint_version IS DISTINCT FROM NEW.accepted_checkpoint_version OR
       committed_run.page_digest IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset observation page did not close with its exact run coordinates',
            CONSTRAINT = 'asset_observations_page_closure_guard';
    END IF;

    SELECT source.* INTO committed_source
    FROM asset_sources AS source
    WHERE source.tenant_id = NEW.tenant_id
      AND source.workspace_id = NEW.workspace_id
      AND source.id = NEW.source_id
    FOR SHARE OF source;
    IF NOT FOUND OR committed_source.status <> 'ACTIVE' OR
       committed_source.published_revision IS DISTINCT FROM NEW.source_revision OR
       committed_source.published_revision_digest IS DISTINCT FROM NEW.canonical_revision_digest OR
       committed_source.checkpoint_version IS DISTINCT FROM NEW.accepted_checkpoint_version OR
       committed_source.checkpoint_sha256 IS DISTINCT FROM
           COALESCE(committed_run.cursor_after_sha256, committed_run.cursor_before_sha256) OR
       NOT COALESCE(
           (committed_run.lineage_rollover_reason IS NULL AND
                committed_source.gate_status = 'AVAILABLE' AND
                committed_source.gate_revision = committed_run.gate_revision) OR
           (committed_run.lineage_rollover_reason IS NOT NULL AND
                committed_source.gate_status = 'DEGRADED' AND
                committed_source.gate_reason_code = 'CHECKPOINT_LINEAGE_ROLLOVER' AND
                committed_source.gate_revision = committed_run.gate_revision + 1),
           false
       ) OR
       NOT EXISTS (
           SELECT 1
           FROM audit_records AS audit
           WHERE audit.tenant_id = NEW.tenant_id
             AND audit.workspace_id = NEW.workspace_id
             AND audit.xmin = pg_catalog.pg_current_xact_id()::xid
             AND audit.actor_type = 'SYSTEM'
             AND audit.actor_id = committed_run.lease_owner
             AND audit.action = 'PAGE_APPLIED'
             AND audit.resource_type = 'ASSET_SOURCE_RUN'
             AND audit.resource_id = NEW.run_id::text
             AND audit.request_id = 'source-page:' || NEW.run_id::text || ':' || NEW.run_page_sequence::text
             AND audit.payload_hash = committed_run.page_digest
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset observation page lacks its exact source checkpoint or immutable receipt',
            CONSTRAINT = 'asset_observations_page_closure_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp;

CREATE CONSTRAINT TRIGGER asset_observations_page_closure_guard
    AFTER INSERT ON public.asset_observations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.validate_asset_observation_page_closure();

REVOKE EXECUTE ON FUNCTION
    public.asset_catalog_text_valid(text, integer),
    public.asset_catalog_code_valid(text, integer),
    public.asset_catalog_sha256_valid(text),
    public.asset_catalog_provider_kind_valid(text),
    public.asset_catalog_idempotency_key_valid(text),
    public.asset_catalog_json_object_valid(bytea, integer, integer),
    public.asset_catalog_labels_valid(jsonb),
    public.asset_catalog_checkpoint_envelope_valid(bytea),
    public.asset_catalog_field_provenance_valid(bytea),
    public.asset_catalog_framed_value_v1(bytea),
    public.asset_catalog_source_run_no_credential_digest(public.asset_source_runs),
    public.asset_catalog_source_run_delay_intent_digest(public.asset_source_runs, text, timestamp with time zone),
    public.asset_catalog_source_run_failure_override_digest(public.asset_source_runs, text),
    public.asset_catalog_source_run_terminal_digest(public.asset_source_runs, text, text),
    public.asset_catalog_opaque_reference_valid(text),
    public.asset_catalog_future_source_gate_admitted(public.asset_sources),
    public.asset_catalog_source_revision_binding_digest(public.asset_source_revisions),
    public.validate_asset_management_audit_insert(),
    public.reject_asset_catalog_immutable(),
    public.reject_asset_catalog_delete(),
    public.reject_asset_catalog_truncate(),
    public.enforce_assets_transition(),
    public.enforce_asset_conflict_transition(),
    public.enforce_asset_catalog_edge_mutation(),
    public.enforce_asset_relationship_mutation(),
    public.validate_asset_relationship_page_closure(),
    public.enforce_asset_sources_mutation(),
    public.validate_asset_source_deferred_state(),
    public.enforce_asset_source_revision_transition(),
    public.validate_asset_source_revision_deferred_state(),
    public.enforce_asset_source_run_mutation(),
    public.validate_asset_source_run_page_closure(),
    public.validate_asset_source_run_terminal_closure(),
    public.enforce_asset_observation_admission(),
    public.validate_asset_observation_page_closure()
    FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
GRANT SELECT ON TABLE public.workspaces, public.environments, public.services,
    public.service_bindings TO aiops_control_plane_runtime;
GRANT SELECT, INSERT ON TABLE
    public.asset_sources,
    public.asset_source_revisions,
    public.asset_source_revision_authorities,
    public.asset_source_runs,
    public.asset_observations,
    public.assets,
    public.asset_type_details,
    public.asset_conflicts,
    public.asset_relationships,
    public.service_asset_bindings
    TO aiops_control_plane_runtime;
GRANT UPDATE ON TABLE
    public.asset_sources,
    public.asset_source_revisions,
    public.asset_source_runs,
    public.assets,
    public.asset_conflicts,
    public.asset_relationships,
    public.service_asset_bindings
    TO aiops_control_plane_runtime;
GRANT SELECT ON TABLE public.audit_records TO aiops_control_plane_runtime;
GRANT INSERT (id, tenant_id, workspace_id, actor_type, actor_id, action, resource_type,
    resource_id, request_id, trace_id, payload_hash, details, created_at)
    ON public.audit_records TO aiops_control_plane_runtime;
GRANT SELECT ON TABLE public.outbox_events TO aiops_control_plane_runtime;
GRANT INSERT (id, tenant_id, workspace_id, aggregate_type, aggregate_id,
    aggregate_version, event_type, payload, created_at, available_at)
    ON public.outbox_events TO aiops_control_plane_runtime;
GRANT UPDATE (available_at, claimed_at, claimed_by, claim_token, claim_expires_at,
    delivered_at, delivered_claim_token, attempts, last_error_code)
    ON public.outbox_events TO aiops_control_plane_runtime;

GRANT EXECUTE ON FUNCTION
    public.asset_catalog_text_valid(text, integer),
    public.asset_catalog_code_valid(text, integer),
    public.asset_catalog_sha256_valid(text),
    public.asset_catalog_provider_kind_valid(text),
    public.asset_catalog_idempotency_key_valid(text),
    public.asset_catalog_json_object_valid(bytea, integer, integer),
    public.asset_catalog_labels_valid(jsonb),
    public.asset_catalog_checkpoint_envelope_valid(bytea),
    public.asset_catalog_field_provenance_valid(bytea),
    public.asset_catalog_framed_value_v1(bytea),
    public.asset_catalog_source_run_no_credential_digest(public.asset_source_runs),
    public.asset_catalog_source_run_delay_intent_digest(public.asset_source_runs, text, timestamp with time zone),
    public.asset_catalog_source_run_failure_override_digest(public.asset_source_runs, text),
    public.asset_catalog_source_run_terminal_digest(public.asset_source_runs, text, text),
    public.asset_catalog_opaque_reference_valid(text),
    public.asset_catalog_future_source_gate_admitted(public.asset_sources),
    public.asset_catalog_source_revision_binding_digest(public.asset_source_revisions)
    TO aiops_control_plane_runtime;

RESET ROLE;

COMMIT;
