BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

LOCK TABLE tenants, workspaces, environments, integrations, services,
    audit_records, outbox_events IN ACCESS EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION asset_catalog_text_valid(candidate text, maximum_bytes integer)
RETURNS boolean AS $$
BEGIN
    RETURN candidate IS NOT NULL
       AND octet_length(candidate) BETWEEN 1 AND maximum_bytes
       AND candidate COLLATE "C" !~ '[[:cntrl:]]';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path FROM CURRENT;

CREATE OR REPLACE FUNCTION asset_catalog_code_valid(candidate text, maximum_bytes integer)
RETURNS boolean AS $$
BEGIN
    RETURN asset_catalog_text_valid(candidate, maximum_bytes)
       AND left(candidate, 1) COLLATE "C" ~ '^[A-Za-z0-9]$'
       AND candidate COLLATE "C" !~ '[^A-Za-z0-9_.:/@+-]';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path FROM CURRENT;

CREATE OR REPLACE FUNCTION asset_catalog_sha256_valid(candidate text)
RETURNS boolean AS $$
BEGIN
    RETURN candidate IS NOT NULL
       AND octet_length(candidate) = 64
       AND candidate COLLATE "C" !~ '[^a-f0-9]';
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path FROM CURRENT;

CREATE OR REPLACE FUNCTION asset_catalog_json_object_valid(
    document bytea,
    minimum_bytes integer,
    maximum_bytes integer
) RETURNS boolean AS $$
DECLARE
    parsed jsonb;
BEGIN
    IF document IS NULL OR octet_length(document) NOT BETWEEN minimum_bytes AND maximum_bytes THEN
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

CREATE OR REPLACE FUNCTION asset_catalog_field_provenance_valid(document bytea)
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
            'criticality', 'classification', 'labels', 'environment_id',
            'lifecycle', 'mapping_status', 'relationships', 'type_details'
        ) OR jsonb_typeof(field_entry.value) <> 'object' THEN
            RETURN false;
        END IF;
        FOR attribute IN SELECT jsonb_object_keys(field_entry.value)
        LOOP
            IF attribute NOT IN (
                'source_id', 'provider_kind', 'source_revision', 'observed_at',
                'confidence', 'ownership'
            ) THEN
                RETURN false;
            END IF;
        END LOOP;
        IF NOT (
            field_entry.value ?& ARRAY[
                'source_id', 'provider_kind', 'source_revision', 'observed_at',
                'confidence', 'ownership'
            ]
        ) OR field_entry.value->>'ownership' NOT IN ('SOURCE', 'GOVERNANCE', 'MERGE_DECISION')
           OR NOT asset_catalog_code_valid(field_entry.value->>'provider_kind', 64)
           OR (field_entry.value->>'source_revision') COLLATE "C" !~ '^[1-9][0-9]*$'
           OR NOT asset_catalog_text_valid(field_entry.value->>'observed_at', 64)
           OR NOT asset_catalog_text_valid(field_entry.value->>'confidence', 32) THEN
            RETURN false;
        END IF;
        PERFORM (field_entry.value->>'source_id')::uuid;
        PERFORM (field_entry.value->>'observed_at')::timestamptz;
    END LOOP;
    RETURN true;
EXCEPTION
    WHEN OTHERS THEN
        RETURN false;
END;
$$ LANGUAGE plpgsql IMMUTABLE
SET search_path FROM CURRENT;

CREATE TABLE asset_sources (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN (
        'MANUAL', 'CSV_IMPORT', 'CONTROL_PLANE_API', 'EXTERNAL_CMDB', 'VSPHERE',
        'PROXMOX', 'OPENSTACK', 'CLOUD_PROVIDER', 'KUBERNETES_OPERATOR', 'AWX_INVENTORY'
    )),
    provider_kind text NOT NULL CHECK (asset_catalog_code_valid(provider_kind, 64)),
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
    checkpoint_revision bigint,
    next_allowed_at timestamptz,
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    create_idempotency_key text NOT NULL CHECK (asset_catalog_text_valid(create_idempotency_key, 256)),
    create_request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(create_request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    last_successful_run_id uuid,
    last_success_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, id),
    UNIQUE (workspace_id, create_idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_sources_published_pointer_ck CHECK (
        (published_revision IS NULL AND published_revision_digest IS NULL) OR
        (published_revision > 0 AND asset_catalog_sha256_valid(published_revision_digest))
    ),
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
            checkpoint_sha256 IS NULL AND checkpoint_revision IS NULL
        ) OR (
            checkpoint_ciphertext IS NOT NULL AND octet_length(checkpoint_ciphertext) BETWEEN 28 AND 65536 AND
            asset_catalog_code_valid(checkpoint_key_id, 256) AND
            asset_catalog_sha256_valid(checkpoint_sha256) AND
            encode(sha256(checkpoint_ciphertext), 'hex') = checkpoint_sha256 AND
            checkpoint_revision IS NOT NULL AND checkpoint_revision > 0
        )
    ),
    CONSTRAINT asset_sources_time_ck CHECK (
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
        updated_at > '-infinity'::timestamptz AND updated_at < 'infinity'::timestamptz AND
        (next_allowed_at IS NULL OR (next_allowed_at > '-infinity'::timestamptz AND next_allowed_at < 'infinity'::timestamptz)) AND
        (last_success_at IS NULL OR (last_success_at > '-infinity'::timestamptz AND last_success_at < 'infinity'::timestamptz))
    )
);

COMMENT ON COLUMN asset_sources.checkpoint_ciphertext IS
    'AES-256-GCM ciphertext only; AAD is tenant_id, workspace_id, source_id, provider_kind, source_definition_digest, checkpoint_version';
COMMENT ON COLUMN asset_sources.checkpoint_key_id IS 'Opaque encryption key identifier; never a key, secret, endpoint, or Vault path';

CREATE TABLE asset_source_revisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL DEFAULT 'DRAFT' CHECK (state IN (
        'DRAFT', 'VALIDATING', 'VALIDATED', 'REJECTED', 'PUBLISHED', 'SUPERSEDED'
    )),
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
    backpressure_max_seconds integer NOT NULL CHECK (backpressure_max_seconds BETWEEN 1 AND 604800 AND backpressure_max_seconds >= backpressure_base_seconds),
    profile_code text NOT NULL CHECK (asset_catalog_code_valid(profile_code, 128)),
    schedule_expression text,
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
        REFERENCES asset_sources (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, integration_id)
        REFERENCES integrations (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_source_revisions_schema_ck CHECK (
        asset_catalog_json_object_valid(canonical_provider_schema, 2, 65536) AND
        asset_catalog_sha256_valid(canonical_provider_schema_sha256) AND
        encode(sha256(canonical_provider_schema), 'hex') = canonical_provider_schema_sha256
    ),
    CONSTRAINT asset_source_revisions_reference_ck CHECK (
        (credential_reference_id IS NULL OR asset_catalog_code_valid(credential_reference_id, 256)) AND
        (trust_reference_id IS NULL OR asset_catalog_code_valid(trust_reference_id, 256)) AND
        (network_policy_reference_id IS NULL OR asset_catalog_code_valid(network_policy_reference_id, 256)) AND
        (schedule_expression IS NULL OR asset_catalog_text_valid(schedule_expression, 256))
    ),
    CONSTRAINT asset_source_revisions_validation_ck CHECK (
        (validation_run_id IS NULL AND validation_digest IS NULL) OR
        (validation_run_id IS NOT NULL AND asset_catalog_sha256_valid(validation_digest))
    )
);

CREATE UNIQUE INDEX asset_source_revisions_published_uk
    ON asset_source_revisions (tenant_id, workspace_id, source_id)
    WHERE state = 'PUBLISHED';

CREATE TABLE asset_source_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    source_revision_digest text NOT NULL CHECK (asset_catalog_sha256_valid(source_revision_digest)),
    run_kind text NOT NULL CHECK (run_kind IN ('VALIDATION', 'DISCOVERY', 'CSV_IMPORT', 'API_INGESTION')),
    status text NOT NULL DEFAULT 'QUEUED' CHECK (status IN (
        'QUEUED', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED'
    )),
    trigger_type text NOT NULL CHECK (trigger_type IN ('HUMAN', 'API', 'SCHEDULED')),
    definition_revision bigint NOT NULL CHECK (definition_revision > 0),
    gate_revision bigint NOT NULL CHECK (gate_revision >= 0),
    idempotency_key text NOT NULL CHECK (asset_catalog_text_valid(idempotency_key, 256)),
    request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(request_hash)),
    cursor_before_sha256 text,
    cursor_after_sha256 text,
    page_sequence bigint NOT NULL DEFAULT 0 CHECK (page_sequence >= 0),
    page_digest text,
    checkpoint_version bigint NOT NULL DEFAULT 0 CHECK (checkpoint_version >= 0),
    lease_owner text,
    lease_expires_at timestamptz,
    fence_epoch bigint NOT NULL DEFAULT 0 CHECK (fence_epoch >= 0),
    fence_token_hash text,
    heartbeat_sequence bigint NOT NULL DEFAULT 0 CHECK (heartbeat_sequence >= 0),
    not_before timestamptz NOT NULL DEFAULT statement_timestamp(),
    observed_count bigint NOT NULL DEFAULT 0 CHECK (observed_count >= 0),
    created_count bigint NOT NULL DEFAULT 0 CHECK (created_count >= 0),
    changed_count bigint NOT NULL DEFAULT 0 CHECK (changed_count >= 0),
    unchanged_count bigint NOT NULL DEFAULT 0 CHECK (unchanged_count >= 0),
    conflict_count bigint NOT NULL DEFAULT 0 CHECK (conflict_count >= 0),
    missing_count bigint NOT NULL DEFAULT 0 CHECK (missing_count >= 0),
    rejected_count bigint NOT NULL DEFAULT 0 CHECK (rejected_count >= 0),
    validation_digest text,
    failure_code text,
    trace_id text,
    started_at timestamptz,
    heartbeat_at timestamptz,
    completed_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, id),
    UNIQUE (tenant_id, workspace_id, source_id, id),
    UNIQUE (workspace_id, idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, source_id, source_revision, source_revision_digest)
        REFERENCES asset_source_revisions (tenant_id, workspace_id, source_id, revision, canonical_revision_digest) ON DELETE RESTRICT,
    CONSTRAINT asset_source_runs_hash_ck CHECK (
        (cursor_before_sha256 IS NULL OR asset_catalog_sha256_valid(cursor_before_sha256)) AND
        (cursor_after_sha256 IS NULL OR asset_catalog_sha256_valid(cursor_after_sha256)) AND
        (page_digest IS NULL OR asset_catalog_sha256_valid(page_digest)) AND
        (validation_digest IS NULL OR asset_catalog_sha256_valid(validation_digest)) AND
        (fence_token_hash IS NULL OR asset_catalog_sha256_valid(fence_token_hash))
    ),
    CONSTRAINT asset_source_runs_lease_ck CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL AND fence_token_hash IS NULL) OR
        (asset_catalog_code_valid(lease_owner, 256) AND lease_expires_at IS NOT NULL AND fence_token_hash IS NOT NULL AND fence_epoch > 0)
    ),
    CONSTRAINT asset_source_runs_state_ck CHECK (
        (status = 'QUEUED' AND started_at IS NULL AND heartbeat_at IS NULL AND completed_at IS NULL AND lease_owner IS NULL) OR
        (status = 'RUNNING' AND started_at IS NOT NULL AND heartbeat_at IS NOT NULL AND completed_at IS NULL AND lease_owner IS NOT NULL AND heartbeat_sequence > 0) OR
        (status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED') AND completed_at IS NOT NULL)
    ),
    CONSTRAINT asset_source_runs_failure_ck CHECK (
        (failure_code IS NULL OR asset_catalog_code_valid(failure_code, 128)) AND
        (trace_id IS NULL OR asset_catalog_text_valid(trace_id, 128))
    ),
    CONSTRAINT asset_source_runs_time_ck CHECK (
        not_before > '-infinity'::timestamptz AND not_before < 'infinity'::timestamptz AND
        created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz AND
        (lease_expires_at IS NULL OR (lease_expires_at > '-infinity'::timestamptz AND lease_expires_at < 'infinity'::timestamptz)) AND
        (started_at IS NULL OR (started_at > '-infinity'::timestamptz AND started_at < 'infinity'::timestamptz)) AND
        (heartbeat_at IS NULL OR (heartbeat_at >= started_at AND heartbeat_at < 'infinity'::timestamptz)) AND
        (completed_at IS NULL OR (completed_at >= COALESCE(started_at, created_at) AND completed_at < 'infinity'::timestamptz))
    )
);

COMMENT ON COLUMN asset_source_runs.fence_token_hash IS 'Lowercase SHA-256 hash only; raw lease or fence tokens are forbidden';

CREATE INDEX asset_source_runs_history_idx
    ON asset_source_runs (tenant_id, workspace_id, source_id, created_at DESC, id DESC);
CREATE INDEX asset_source_runs_queued_claim_idx
    ON asset_source_runs (not_before, created_at, id) WHERE status = 'QUEUED';
CREATE INDEX asset_source_runs_expired_lease_idx
    ON asset_source_runs (lease_expires_at, id) WHERE status = 'RUNNING';
CREATE UNIQUE INDEX asset_source_runs_live_uk
    ON asset_source_runs (tenant_id, workspace_id, source_id) WHERE status IN ('QUEUED', 'RUNNING');

ALTER TABLE asset_source_revisions
    ADD CONSTRAINT asset_source_revisions_validation_run_fk
        FOREIGN KEY (tenant_id, workspace_id, source_id, validation_run_id)
        REFERENCES asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT;

ALTER TABLE asset_sources
    ADD CONSTRAINT asset_sources_published_revision_fk
        FOREIGN KEY (tenant_id, workspace_id, id, published_revision, published_revision_digest)
        REFERENCES asset_source_revisions (tenant_id, workspace_id, source_id, revision, canonical_revision_digest) ON DELETE RESTRICT,
    ADD CONSTRAINT asset_sources_validated_run_fk
        FOREIGN KEY (tenant_id, workspace_id, id, validated_run_id)
        REFERENCES asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT asset_sources_last_successful_run_fk
        FOREIGN KEY (tenant_id, workspace_id, id, last_successful_run_id)
        REFERENCES asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT;

CREATE TABLE asset_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    source_id uuid NOT NULL,
    run_id uuid NOT NULL,
    provider_kind text NOT NULL CHECK (asset_catalog_code_valid(provider_kind, 64)),
    external_id text NOT NULL CHECK (asset_catalog_text_valid(external_id, 512)),
    source_revision text NOT NULL CHECK (asset_catalog_code_valid(source_revision, 128)),
    observed_at timestamptz NOT NULL,
    schema_version text NOT NULL CHECK (asset_catalog_code_valid(schema_version, 128)),
    normalized_document bytea NOT NULL,
    document_sha256 text NOT NULL,
    field_provenance bytea NOT NULL,
    field_provenance_sha256 text NOT NULL,
    tombstone boolean NOT NULL DEFAULT false,
    tombstone_reason_code text,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, source_id, id),
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, source_id, run_id)
        REFERENCES asset_source_runs (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_observations_document_ck CHECK (
        asset_catalog_json_object_valid(normalized_document, 2, 65536) AND
        octet_length(document_sha256) = 64 AND document_sha256 COLLATE "C" !~ '[^a-f0-9]' AND
        encode(sha256(normalized_document), 'hex') = document_sha256
    ),
    CONSTRAINT asset_observations_provenance_ck CHECK (
        asset_catalog_field_provenance_valid(field_provenance) AND
        asset_catalog_sha256_valid(field_provenance_sha256) AND
        encode(sha256(field_provenance), 'hex') = field_provenance_sha256
    ),
    CONSTRAINT asset_observations_tombstone_ck CHECK (
        (tombstone AND asset_catalog_code_valid(tombstone_reason_code, 128)) OR
        (NOT tombstone AND tombstone_reason_code IS NULL)
    )
);

CREATE TABLE assets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    source_id uuid NOT NULL,
    provider_kind text NOT NULL CHECK (asset_catalog_code_valid(provider_kind, 64)),
    external_id text NOT NULL CHECK (asset_catalog_text_valid(external_id, 512)),
    kind text NOT NULL CHECK (asset_catalog_code_valid(kind, 128)),
    display_name text NOT NULL CHECK (asset_catalog_text_valid(display_name, 256)),
    owner_group text CHECK (owner_group IS NULL OR asset_catalog_text_valid(owner_group, 256)),
    criticality text NOT NULL DEFAULT 'LOW' CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    classification text NOT NULL DEFAULT 'INTERNAL' CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    lifecycle text NOT NULL DEFAULT 'DISCOVERED' CHECK (lifecycle IN ('DISCOVERED', 'ACTIVE', 'STALE', 'QUARANTINED', 'RETIRED')),
    mapping_status text NOT NULL DEFAULT 'UNRESOLVED' CHECK (mapping_status IN ('EXACT', 'AMBIGUOUS', 'UNRESOLVED')),
    last_observation_id uuid NOT NULL,
    last_observed_at timestamptz NOT NULL,
    last_source_revision bigint NOT NULL CHECK (last_source_revision > 0),
    create_idempotency_key text NOT NULL CHECK (asset_catalog_text_valid(create_idempotency_key, 256)),
    create_request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(create_request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, source_id, provider_kind, external_id),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (workspace_id, create_idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, source_id)
        REFERENCES asset_sources (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, source_id, last_observation_id)
        REFERENCES asset_observations (tenant_id, workspace_id, source_id, id) ON DELETE RESTRICT,
    CONSTRAINT assets_labels_ck CHECK (
        jsonb_typeof(labels) = 'object' AND pg_column_size(labels) BETWEEN 2 AND 16384
    )
);

CREATE INDEX assets_catalog_idx
    ON assets (tenant_id, workspace_id, environment_id, lower(display_name), id)
    WHERE lifecycle <> 'RETIRED';
CREATE INDEX assets_filter_idx
    ON assets (tenant_id, workspace_id, environment_id, kind, lifecycle, mapping_status, id);

CREATE TABLE asset_type_details (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    schema_version text NOT NULL CHECK (asset_catalog_code_valid(schema_version, 128)),
    source_observation_id uuid NOT NULL,
    details_document bytea NOT NULL,
    details_sha256 text NOT NULL,
    actor_id text NOT NULL CHECK (asset_catalog_text_valid(actor_id, 256)),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, asset_id, revision),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
        REFERENCES assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, source_observation_id)
        REFERENCES asset_observations (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_type_details_document_ck CHECK (
        asset_catalog_json_object_valid(details_document, 2, 65536) AND
        asset_catalog_sha256_valid(details_sha256) AND
        encode(sha256(details_document), 'hex') = details_sha256
    )
);

CREATE TABLE asset_conflicts (
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
        REFERENCES assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, candidate_asset_id)
        REFERENCES assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, candidate_service_id)
        REFERENCES services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, source_id)
        REFERENCES asset_sources (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, observation_id)
        REFERENCES asset_observations (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
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
            asset_catalog_text_valid(resolution_idempotency_key, 256) AND
            asset_catalog_sha256_valid(resolution_request_hash))
    )
);

CREATE UNIQUE INDEX asset_conflicts_open_queue_uk
    ON asset_conflicts (
        tenant_id, workspace_id, source_id, observation_id, conflict_type,
        field_name, candidate_asset_id, candidate_service_id
    ) NULLS NOT DISTINCT WHERE status = 'OPEN';
CREATE INDEX asset_conflicts_open_idx
    ON asset_conflicts (tenant_id, workspace_id, environment_id, created_at, id)
    WHERE status = 'OPEN';

CREATE TABLE asset_relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    source_environment_id uuid NOT NULL,
    target_environment_id uuid NOT NULL,
    source_asset_id uuid NOT NULL,
    target_asset_id uuid NOT NULL,
    relationship_type text NOT NULL CHECK (relationship_type IN (
        'RUNS_ON', 'CONTAINS', 'DEPENDS_ON', 'MONITORED_BY', 'LOGS_TO', 'TRACES_TO',
        'DELIVERED_BY', 'MANAGED_BY', 'PRIMARY_RUNTIME_FOR'
    )),
    provenance text NOT NULL CHECK (provenance IN ('MANUAL', 'DISCOVERED', 'MERGE_DECISION')),
    provenance_source_id uuid,
    cross_environment_policy_reference_id text,
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
    idempotency_key text NOT NULL CHECK (asset_catalog_text_valid(idempotency_key, 256)),
    request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, id),
    UNIQUE (workspace_id, idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, source_environment_id, source_asset_id)
        REFERENCES assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, target_environment_id, target_asset_id)
        REFERENCES assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, provenance_source_id)
        REFERENCES asset_sources (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT asset_relationships_distinct_ck CHECK (source_asset_id <> target_asset_id),
    CONSTRAINT asset_relationships_cross_environment_ck CHECK (
        (source_environment_id = target_environment_id AND cross_environment_policy_reference_id IS NULL) OR
        (source_environment_id <> target_environment_id AND asset_catalog_code_valid(cross_environment_policy_reference_id, 256))
    )
);

CREATE UNIQUE INDEX asset_relationships_active_edge_uk ON asset_relationships (tenant_id, workspace_id, source_asset_id, target_asset_id, relationship_type) WHERE status = 'ACTIVE';

CREATE TABLE service_asset_bindings (
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
    idempotency_key text NOT NULL CHECK (asset_catalog_text_valid(idempotency_key, 256)),
    request_hash text NOT NULL CHECK (asset_catalog_sha256_valid(request_hash)),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (tenant_id, workspace_id, environment_id, id),
    UNIQUE (workspace_id, idempotency_key),
    FOREIGN KEY (tenant_id, workspace_id, service_id)
        REFERENCES services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
        REFERENCES assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, provenance_source_id)
        REFERENCES asset_sources (tenant_id, workspace_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX service_asset_bindings_active_uk ON service_asset_bindings (tenant_id, workspace_id, environment_id, service_id, asset_id, binding_role) WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX asset_management_idempotency_audit_uk ON audit_records (workspace_id, request_id) WHERE resource_type IN ('ASSET', 'ASSET_SOURCE', 'ASSET_SOURCE_RUN', 'ASSET_CONFLICT', 'SERVICE_ASSET_BINDING');

CREATE OR REPLACE FUNCTION validate_asset_management_audit_insert() RETURNS trigger AS $$
BEGIN
    IF NEW.resource_type IN ('ASSET', 'ASSET_SOURCE', 'ASSET_SOURCE_RUN', 'ASSET_CONFLICT', 'SERVICE_ASSET_BINDING')
       AND (NOT asset_catalog_text_valid(NEW.request_id, 256) OR NOT asset_catalog_sha256_valid(NEW.payload_hash)) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'asset-management audit requires a bounded idempotency key and canonical SHA-256 payload hash',
            CONSTRAINT = 'asset_management_audit_shape_guard';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER asset_management_audit_insert_guard
    BEFORE INSERT ON audit_records
    FOR EACH ROW EXECUTE FUNCTION validate_asset_management_audit_insert();

CREATE OR REPLACE FUNCTION reject_asset_catalog_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = TG_TABLE_NAME || ' is append-only',
        CONSTRAINT = TG_TABLE_NAME || '_immutable';
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER asset_observations_immutable
    BEFORE UPDATE OR DELETE ON asset_observations
    FOR EACH ROW EXECUTE FUNCTION reject_asset_catalog_immutable();

CREATE TRIGGER asset_type_details_immutable
    BEFORE UPDATE OR DELETE ON asset_type_details
    FOR EACH ROW EXECUTE FUNCTION reject_asset_catalog_immutable();

CREATE OR REPLACE FUNCTION enforce_assets_transition() RETURNS trigger AS $$
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
        OLD.last_observed_at IS DISTINCT FROM NEW.last_observed_at OR
        OLD.last_source_revision IS DISTINCT FROM NEW.last_source_revision
    ) AND (
        OLD.owner_group IS DISTINCT FROM NEW.owner_group OR
        OLD.criticality IS DISTINCT FROM NEW.criticality OR
        OLD.classification IS DISTINCT FROM NEW.classification OR
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
    NEW.created_at := OLD.created_at;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER assets_transition_guard
    BEFORE INSERT OR UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION enforce_assets_transition();

CREATE OR REPLACE FUNCTION enforce_asset_conflict_transition() RETURNS trigger AS $$
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
SET search_path FROM CURRENT;

CREATE TRIGGER asset_conflicts_transition_guard
    BEFORE INSERT OR UPDATE ON asset_conflicts
    FOR EACH ROW EXECUTE FUNCTION enforce_asset_conflict_transition();

CREATE OR REPLACE FUNCTION enforce_asset_catalog_edge_mutation() RETURNS trigger AS $$
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
SET search_path FROM CURRENT;

CREATE TRIGGER asset_relationships_mutation_guard
    BEFORE INSERT OR UPDATE ON asset_relationships
    FOR EACH ROW EXECUTE FUNCTION enforce_asset_catalog_edge_mutation();

CREATE TRIGGER service_asset_bindings_mutation_guard
    BEFORE INSERT OR UPDATE ON service_asset_bindings
    FOR EACH ROW EXECUTE FUNCTION enforce_asset_catalog_edge_mutation();

CREATE OR REPLACE FUNCTION enforce_asset_sources_mutation() RETURNS trigger AS $$
DECLARE
    gate_is_valid boolean;
    checkpoint_changed boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.gate_revision <> 0 OR NEW.checkpoint_version <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source must start at version one with closed gate and checkpoint zero',
                CONSTRAINT = 'asset_sources_initial_state_guard';
        END IF;
        IF NEW.gate_status = 'AVAILABLE' OR NEW.source_kind = 'KUBERNETES_OPERATOR' AND NEW.gate_status <> 'UNAVAILABLE' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'new asset source gate must be unavailable',
                CONSTRAINT = 'asset_sources_initial_gate_guard';
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
    IF NEW.checkpoint_version < OLD.checkpoint_version OR NEW.checkpoint_version > OLD.checkpoint_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source checkpoint version cannot regress or skip',
            CONSTRAINT = 'asset_sources_checkpoint_version_guard';
    END IF;
    checkpoint_changed :=
        OLD.checkpoint_ciphertext IS DISTINCT FROM NEW.checkpoint_ciphertext OR
        OLD.checkpoint_key_id IS DISTINCT FROM NEW.checkpoint_key_id OR
        OLD.checkpoint_sha256 IS DISTINCT FROM NEW.checkpoint_sha256 OR
        OLD.checkpoint_revision IS DISTINCT FROM NEW.checkpoint_revision;
    IF checkpoint_changed AND NEW.checkpoint_version <> OLD.checkpoint_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source checkpoint mutation must advance its version exactly once',
            CONSTRAINT = 'asset_sources_checkpoint_version_guard';
    END IF;
    IF NOT checkpoint_changed AND NEW.checkpoint_version IS DISTINCT FROM OLD.checkpoint_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source checkpoint version requires an encrypted checkpoint mutation',
            CONSTRAINT = 'asset_sources_checkpoint_version_guard';
    END IF;

    IF OLD.published_revision IS DISTINCT FROM NEW.published_revision OR
       OLD.published_revision_digest IS DISTINCT FROM NEW.published_revision_digest THEN
        NEW.gate_status := 'UNAVAILABLE';
        NEW.gate_reason_code := 'PUBLISHED_REFERENCE_DRIFT';
        NEW.gate_revision := OLD.gate_revision + 1;
        NEW.validated_run_id := NULL;
        NEW.validation_digest := NULL;
        NEW.validated_binding_digest := NULL;
    END IF;
    IF OLD.gate_status = 'AVAILABLE' AND (
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
    IF NEW.status <> 'ACTIVE' AND (
        OLD.gate_status <> 'UNAVAILABLE' OR NEW.gate_status <> 'UNAVAILABLE' OR
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
    IF NEW.gate_revision < OLD.gate_revision OR NEW.gate_revision > OLD.gate_revision + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source gate revision cannot regress or skip',
            CONSTRAINT = 'asset_sources_gate_revision_guard';
    END IF;
    IF NEW.gate_status IS DISTINCT FROM OLD.gate_status AND NEW.gate_revision <> OLD.gate_revision + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source gate transition must advance its revision exactly once',
            CONSTRAINT = 'asset_sources_gate_revision_guard';
    END IF;
    IF NEW.source_kind = 'KUBERNETES_OPERATOR' AND NEW.gate_status <> 'UNAVAILABLE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'KUBERNETES_OPERATOR source remains unavailable until its production adapter is accepted',
            CONSTRAINT = 'asset_sources_kubernetes_operator_gate_guard';
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
              AND revision.source_definition_digest = NEW.validated_binding_digest
              AND validation_run.source_revision = revision.revision
              AND validation_run.source_revision_digest = revision.canonical_revision_digest
              AND validation_run.run_kind = 'VALIDATION'
              AND validation_run.status = 'SUCCEEDED'
              AND validation_run.validation_digest = NEW.validation_digest
              AND validation_run.completed_at IS NOT NULL
        ) INTO gate_is_valid;
        IF NEW.status <> 'ACTIVE' OR NOT gate_is_valid THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source gate requires its exact published successful validation and binding digest',
                CONSTRAINT = 'asset_sources_available_gate_guard';
        END IF;
    END IF;
    IF NEW.checkpoint_ciphertext IS NOT NULL AND NEW.checkpoint_revision IS DISTINCT FROM NEW.published_revision THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'asset source checkpoint must bind to the exact published revision',
            CONSTRAINT = 'asset_sources_checkpoint_revision_guard';
    END IF;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER asset_sources_mutation_guard
    BEFORE INSERT OR UPDATE ON asset_sources
    FOR EACH ROW EXECUTE FUNCTION enforce_asset_sources_mutation();

CREATE OR REPLACE FUNCTION validate_asset_source_deferred_state() RETURNS trigger AS $$
DECLARE
    current_source asset_sources%ROWTYPE;
BEGIN
    SELECT * INTO current_source
    FROM asset_sources
    WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id AND id = NEW.id;
    IF NOT FOUND THEN
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
       AND current_source.checkpoint_ciphertext IS NOT NULL
       AND OLD.checkpoint_version IS DISTINCT FROM current_source.checkpoint_version
       AND OLD.published_revision IS NOT DISTINCT FROM current_source.published_revision
       AND NOT EXISTS (
            SELECT 1
            FROM asset_source_runs AS run
            WHERE run.tenant_id = current_source.tenant_id
              AND run.workspace_id = current_source.workspace_id
              AND run.source_id = current_source.id
              AND run.checkpoint_version = current_source.checkpoint_version
              AND run.page_sequence > 0
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'checkpoint advance requires the matching successful source page sequence',
            CONSTRAINT = 'asset_sources_checkpoint_page_guard';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE CONSTRAINT TRIGGER asset_sources_deferred_state_guard
    AFTER INSERT OR UPDATE ON asset_sources
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_asset_source_deferred_state();

CREATE OR REPLACE FUNCTION enforce_asset_source_revision_transition() RETURNS trigger AS $$
DECLARE
    validation_is_valid boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'DRAFT' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source revision must start DRAFT at version one',
                CONSTRAINT = 'asset_source_revisions_initial_state_guard';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
       OLD.id IS DISTINCT FROM NEW.id OR OLD.source_id IS DISTINCT FROM NEW.source_id OR
       OLD.revision IS DISTINCT FROM NEW.revision OR
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
    IF OLD.state IN ('VALIDATED', 'PUBLISHED', 'SUPERSEDED') AND (
        OLD.validation_run_id IS DISTINCT FROM NEW.validation_run_id OR
        OLD.validation_digest IS DISTINCT FROM NEW.validation_digest
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'validated source revision evidence is immutable',
            CONSTRAINT = 'asset_source_revisions_validation_immutable_guard';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state = 'DRAFT' AND NEW.state = 'VALIDATING') OR
        (OLD.state = 'VALIDATING' AND NEW.state IN ('VALIDATED', 'REJECTED')) OR
        (OLD.state = 'VALIDATED' AND NEW.state = 'PUBLISHED') OR
        (OLD.state = 'PUBLISHED' AND NEW.state = 'SUPERSEDED')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'invalid asset source revision state transition',
            CONSTRAINT = 'asset_source_revisions_state_guard';
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
              AND run.validation_digest = NEW.validation_digest
              AND run.completed_at IS NOT NULL
        ) INTO validation_is_valid;
        IF NOT validation_is_valid THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'validated source revision requires its exact successful validation run',
                CONSTRAINT = 'asset_source_revisions_validation_guard';
        END IF;
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
            checkpoint_revision = NULL,
            checkpoint_version = checkpoint_version + CASE WHEN checkpoint_ciphertext IS NULL THEN 0 ELSE 1 END,
            version = version + 1
        WHERE tenant_id = NEW.tenant_id AND workspace_id = NEW.workspace_id AND id = NEW.source_id;
    END IF;
    NEW.created_at := OLD.created_at;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER asset_source_revisions_transition_guard
    BEFORE INSERT OR UPDATE ON asset_source_revisions
    FOR EACH ROW EXECUTE FUNCTION enforce_asset_source_revision_transition();

CREATE OR REPLACE FUNCTION enforce_asset_source_run_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.page_sequence <> 0 OR NEW.checkpoint_version <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514', MESSAGE = 'asset source run must start at version one before any page',
                CONSTRAINT = 'asset_source_runs_initial_state_guard';
        END IF;
        NEW.created_at := statement_timestamp();
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
       OLD.definition_revision IS DISTINCT FROM NEW.definition_revision OR
       OLD.gate_revision IS DISTINCT FROM NEW.gate_revision OR
       OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key OR
       OLD.request_hash IS DISTINCT FROM NEW.request_hash OR OLD.not_before IS DISTINCT FROM NEW.not_before OR
       OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source run identity and exact revision are immutable',
            CONSTRAINT = 'asset_source_runs_identity_guard';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source run version must advance exactly once',
            CONSTRAINT = 'asset_source_runs_version_guard';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'QUEUED' AND NEW.status IN ('RUNNING', 'CANCELLED')) OR
        (OLD.status = 'RUNNING' AND NEW.status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514', MESSAGE = 'invalid asset source run state transition',
            CONSTRAINT = 'asset_source_runs_state_guard';
    END IF;
    IF NEW.fence_epoch < OLD.fence_epoch OR NEW.fence_epoch > OLD.fence_epoch + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'stale or skipped asset source run fence epoch',
            CONSTRAINT = 'asset_source_runs_fence_guard';
    END IF;
    IF NEW.fence_token_hash IS DISTINCT FROM OLD.fence_token_hash AND NEW.fence_epoch <> OLD.fence_epoch + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source run fence token hash requires the next fence epoch',
            CONSTRAINT = 'asset_source_runs_fence_guard';
    END IF;
    IF NEW.heartbeat_sequence < OLD.heartbeat_sequence OR NEW.heartbeat_sequence > OLD.heartbeat_sequence + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'asset source run heartbeat sequence cannot regress or skip',
            CONSTRAINT = 'asset_source_runs_heartbeat_guard';
    END IF;
    IF NEW.page_sequence IS DISTINCT FROM OLD.page_sequence OR NEW.checkpoint_version IS DISTINCT FROM OLD.checkpoint_version THEN
        IF NEW.page_sequence <> OLD.page_sequence + 1 OR
           NEW.checkpoint_version <> OLD.checkpoint_version + 1 OR
           NEW.page_digest IS NULL OR NEW.cursor_after_sha256 IS NULL OR NOT EXISTS (
                SELECT 1 FROM asset_sources AS source
                WHERE source.tenant_id = NEW.tenant_id
                  AND source.workspace_id = NEW.workspace_id
                  AND source.id = NEW.source_id
                  AND source.checkpoint_version = NEW.checkpoint_version
                  AND source.checkpoint_revision = NEW.source_revision
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'successful source page and encrypted checkpoint must advance exactly once together',
                CONSTRAINT = 'asset_source_runs_checkpoint_page_guard';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER asset_source_runs_mutation_guard
    BEFORE INSERT OR UPDATE ON asset_source_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_asset_source_run_mutation();

COMMIT;
