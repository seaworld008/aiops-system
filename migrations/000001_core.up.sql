BEGIN;

CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspaces (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE environments (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('DEV', 'STAGING', 'PROD')),
    change_enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE services (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    name text NOT NULL,
    owner_group text NOT NULL,
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE service_bindings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    service_id uuid NOT NULL REFERENCES services(id),
    environment_id uuid NOT NULL REFERENCES environments(id),
    mapping_status text NOT NULL CHECK (mapping_status IN ('EXACT', 'AMBIGUOUS', 'UNRESOLVED')),
    kubernetes jsonb NOT NULL DEFAULT '{}'::jsonb,
    prometheus jsonb NOT NULL DEFAULT '{}'::jsonb,
    logs jsonb NOT NULL DEFAULT '{}'::jsonb,
    awx jsonb NOT NULL DEFAULT '{}'::jsonb,
    delivery jsonb NOT NULL DEFAULT '{}'::jsonb,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (service_id, environment_id)
);

CREATE TABLE signals (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    integration_id uuid NOT NULL,
    provider text NOT NULL,
    provider_event_id text NOT NULL,
    payload_hash text NOT NULL,
    fingerprint text NOT NULL,
    observed_at timestamptz NOT NULL,
    payload_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, integration_id, provider_event_id)
);

CREATE INDEX signals_fingerprint_idx ON signals (workspace_id, fingerprint, observed_at DESC);

CREATE TABLE incidents (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    service_id uuid REFERENCES services(id),
    environment_id uuid REFERENCES environments(id),
    status text NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'MITIGATING', 'RESOLVED', 'CLOSED')),
    severity text NOT NULL,
    title text NOT NULL,
    confirmed_hypothesis_id uuid,
    opened_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 1
);

CREATE TABLE incident_signals (
    incident_id uuid NOT NULL REFERENCES incidents(id),
    signal_id uuid NOT NULL REFERENCES signals(id),
    PRIMARY KEY (incident_id, signal_id)
);

CREATE TABLE investigations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    incident_id uuid NOT NULL REFERENCES incidents(id),
    status text NOT NULL CHECK (status IN ('QUEUED', 'RUNNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    model_version text,
    prompt_version text,
    tool_schema_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    connector text NOT NULL,
    resource_ref text,
    query_summary jsonb NOT NULL,
    collected_at timestamptz NOT NULL,
    redacted_summary jsonb NOT NULL,
    raw_ref text,
    content_hash text NOT NULL,
    trust_level text NOT NULL,
    truncated boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hypotheses (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    status text NOT NULL CHECK (status IN ('PROPOSED', 'CONFIRMED', 'REJECTED')),
    rank integer NOT NULL,
    confidence_band text NOT NULL,
    summary text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE incidents
    ADD CONSTRAINT incidents_confirmed_hypothesis_fk
    FOREIGN KEY (confirmed_hypothesis_id) REFERENCES hypotheses(id);

CREATE TABLE hypothesis_evidence (
    hypothesis_id uuid NOT NULL REFERENCES hypotheses(id),
    evidence_id uuid NOT NULL REFERENCES evidence(id),
    relation text NOT NULL CHECK (relation IN ('SUPPORTS', 'CONTRADICTS')),
    PRIMARY KEY (hypothesis_id, evidence_id)
);

CREATE TABLE feedback (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    hypothesis_id uuid REFERENCES hypotheses(id),
    actor_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('HELPFUL', 'NOT_HELPFUL', 'CONFIRM', 'REJECT', 'CORRECT')),
    comment text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE action_plans (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    incident_id uuid NOT NULL REFERENCES incidents(id),
    version integer NOT NULL,
    action_type text NOT NULL,
    envelope jsonb NOT NULL,
    plan_hash text NOT NULL,
    policy_version text NOT NULL,
    risk_level text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, plan_hash)
);

CREATE TABLE policy_decisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    action_plan_id uuid NOT NULL REFERENCES action_plans(id),
    phase text NOT NULL,
    input_hash text NOT NULL,
    policy_version text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')),
    reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE approvals (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    action_plan_id uuid NOT NULL REFERENCES action_plans(id),
    plan_hash text NOT NULL,
    status text NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'REVOKED')),
    required_approvals integer NOT NULL CHECK (required_approvals IN (1, 2)),
    decisions jsonb NOT NULL DEFAULT '[]'::jsonb,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE executions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    action_plan_id uuid NOT NULL REFERENCES action_plans(id),
    status text NOT NULL CHECK (status IN ('QUEUED', 'LEASED', 'RUNNING', 'WAITING_EXTERNAL_APPROVAL', 'WAITING_SYNC', 'VERIFYING', 'SUCCEEDED', 'FAILED', 'ROLLED_BACK', 'CANCELLED')),
    runner_id text,
    lease_epoch bigint NOT NULL DEFAULT 0,
    result_hash text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tool_invocations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    investigation_id uuid REFERENCES investigations(id),
    execution_id uuid REFERENCES executions(id),
    tool_name text NOT NULL,
    tool_version text NOT NULL,
    input_hash text NOT NULL,
    output_hash text,
    status text NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz
);

CREATE TABLE model_calls (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    provider text NOT NULL,
    model text NOT NULL,
    prompt_version text NOT NULL,
    input_tokens bigint NOT NULL DEFAULT 0,
    output_tokens bigint NOT NULL DEFAULT 0,
    duration_ms bigint NOT NULL,
    result_hash text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_records (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    request_id text NOT NULL,
    trace_id text,
    payload_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_records are append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_records_no_update
    BEFORE UPDATE OR DELETE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

CREATE TABLE outbox_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    available_at timestamptz NOT NULL DEFAULT now(),
    claimed_at timestamptz,
    delivered_at timestamptz,
    attempts integer NOT NULL DEFAULT 0
);

CREATE INDEX outbox_pending_idx ON outbox_events (available_at, created_at)
    WHERE delivered_at IS NULL;

COMMIT;

