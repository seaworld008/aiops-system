BEGIN;

-- Composite candidate keys make tenant/workspace scope part of every domain
-- reference instead of trusting globally unique UUIDs alone.
ALTER TABLE workspaces ADD CONSTRAINT workspaces_tenant_scope_uk UNIQUE (tenant_id, id);
ALTER TABLE environments ADD CONSTRAINT environments_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE services ADD CONSTRAINT services_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE signals ADD CONSTRAINT signals_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE incidents ADD CONSTRAINT incidents_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE investigations ADD CONSTRAINT investigations_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE evidence ADD CONSTRAINT evidence_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE hypotheses ADD CONSTRAINT hypotheses_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE action_plans ADD CONSTRAINT action_plans_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE executions ADD CONSTRAINT executions_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);

ALTER TABLE environments ADD CONSTRAINT environments_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE services ADD CONSTRAINT services_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE service_bindings ADD CONSTRAINT service_bindings_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE signals ADD CONSTRAINT signals_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE incidents ADD CONSTRAINT incidents_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE investigations ADD CONSTRAINT investigations_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE evidence ADD CONSTRAINT evidence_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE hypotheses ADD CONSTRAINT hypotheses_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE feedback ADD CONSTRAINT feedback_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE action_plans ADD CONSTRAINT action_plans_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE policy_decisions ADD CONSTRAINT policy_decisions_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE approvals ADD CONSTRAINT approvals_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE executions ADD CONSTRAINT executions_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE tool_invocations ADD CONSTRAINT tool_invocations_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE model_calls ADD CONSTRAINT model_calls_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE audit_records ADD CONSTRAINT audit_records_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);
ALTER TABLE outbox_events ADD CONSTRAINT outbox_events_workspace_scope_fk
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id);

ALTER TABLE service_bindings ADD CONSTRAINT service_bindings_service_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, service_id)
    REFERENCES services (tenant_id, workspace_id, id);
ALTER TABLE service_bindings ADD CONSTRAINT service_bindings_environment_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
    REFERENCES environments (tenant_id, workspace_id, id);
ALTER TABLE incidents ADD CONSTRAINT incidents_service_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, service_id)
    REFERENCES services (tenant_id, workspace_id, id);
ALTER TABLE incidents ADD CONSTRAINT incidents_environment_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
    REFERENCES environments (tenant_id, workspace_id, id);
ALTER TABLE investigations ADD CONSTRAINT investigations_incident_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, incident_id)
    REFERENCES incidents (tenant_id, workspace_id, id);
ALTER TABLE evidence ADD CONSTRAINT evidence_investigation_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id)
    REFERENCES investigations (tenant_id, workspace_id, id);
ALTER TABLE hypotheses ADD CONSTRAINT hypotheses_investigation_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id)
    REFERENCES investigations (tenant_id, workspace_id, id);
ALTER TABLE feedback ADD CONSTRAINT feedback_investigation_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id)
    REFERENCES investigations (tenant_id, workspace_id, id);
ALTER TABLE feedback ADD CONSTRAINT feedback_hypothesis_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, hypothesis_id)
    REFERENCES hypotheses (tenant_id, workspace_id, id);
ALTER TABLE action_plans ADD CONSTRAINT action_plans_incident_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, incident_id)
    REFERENCES incidents (tenant_id, workspace_id, id);
ALTER TABLE policy_decisions ADD CONSTRAINT policy_decisions_action_plan_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, action_plan_id)
    REFERENCES action_plans (tenant_id, workspace_id, id);
ALTER TABLE approvals ADD CONSTRAINT approvals_action_plan_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, action_plan_id)
    REFERENCES action_plans (tenant_id, workspace_id, id);
ALTER TABLE executions ADD CONSTRAINT executions_action_plan_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, action_plan_id)
    REFERENCES action_plans (tenant_id, workspace_id, id);
ALTER TABLE tool_invocations ADD CONSTRAINT tool_invocations_investigation_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id)
    REFERENCES investigations (tenant_id, workspace_id, id);
ALTER TABLE tool_invocations ADD CONSTRAINT tool_invocations_execution_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, execution_id)
    REFERENCES executions (tenant_id, workspace_id, id);
ALTER TABLE model_calls ADD CONSTRAINT model_calls_investigation_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id)
    REFERENCES investigations (tenant_id, workspace_id, id);
ALTER TABLE incidents ADD CONSTRAINT incidents_confirmed_hypothesis_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, confirmed_hypothesis_id)
    REFERENCES hypotheses (tenant_id, workspace_id, id);

CREATE OR REPLACE FUNCTION enforce_incident_signal_scope() RETURNS trigger AS $$
DECLARE
    incident_tenant uuid;
    incident_workspace uuid;
    signal_tenant uuid;
    signal_workspace uuid;
BEGIN
    SELECT tenant_id, workspace_id INTO incident_tenant, incident_workspace
      FROM incidents WHERE id = NEW.incident_id;
    SELECT tenant_id, workspace_id INTO signal_tenant, signal_workspace
      FROM signals WHERE id = NEW.signal_id;
    IF incident_tenant IS DISTINCT FROM signal_tenant
       OR incident_workspace IS DISTINCT FROM signal_workspace THEN
        RAISE EXCEPTION 'incident and signal must belong to the same tenant/workspace';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER incident_signals_scope_guard
    BEFORE INSERT OR UPDATE ON incident_signals
    FOR EACH ROW EXECUTE FUNCTION enforce_incident_signal_scope();

CREATE OR REPLACE FUNCTION enforce_hypothesis_evidence_scope() RETURNS trigger AS $$
DECLARE
    hypothesis_tenant uuid;
    hypothesis_workspace uuid;
    evidence_tenant uuid;
    evidence_workspace uuid;
BEGIN
    SELECT tenant_id, workspace_id INTO hypothesis_tenant, hypothesis_workspace
      FROM hypotheses WHERE id = NEW.hypothesis_id;
    SELECT tenant_id, workspace_id INTO evidence_tenant, evidence_workspace
      FROM evidence WHERE id = NEW.evidence_id;
    IF hypothesis_tenant IS DISTINCT FROM evidence_tenant
       OR hypothesis_workspace IS DISTINCT FROM evidence_workspace THEN
        RAISE EXCEPTION 'hypothesis and evidence must belong to the same tenant/workspace';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER hypothesis_evidence_scope_guard
    BEFORE INSERT OR UPDATE ON hypothesis_evidence
    FOR EACH ROW EXECUTE FUNCTION enforce_hypothesis_evidence_scope();

CREATE OR REPLACE FUNCTION enforce_confirmed_hypothesis() RETURNS trigger AS $$
BEGIN
    IF NEW.confirmed_hypothesis_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM hypotheses h
          JOIN investigations inv
            ON inv.id = h.investigation_id
           AND inv.tenant_id = h.tenant_id
           AND inv.workspace_id = h.workspace_id
         WHERE h.id = NEW.confirmed_hypothesis_id
           AND h.tenant_id = NEW.tenant_id
           AND h.workspace_id = NEW.workspace_id
           AND h.status = 'CONFIRMED'
           AND inv.incident_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'confirmed hypothesis must be CONFIRMED and belong to this incident';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER incidents_confirmed_hypothesis_guard
    BEFORE INSERT OR UPDATE OF confirmed_hypothesis_id, tenant_id, workspace_id ON incidents
    FOR EACH ROW EXECUTE FUNCTION enforce_confirmed_hypothesis();

CREATE OR REPLACE FUNCTION protect_confirmed_hypothesis() RETURNS trigger AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM incidents i
         WHERE i.confirmed_hypothesis_id = OLD.id
           AND (
               NEW.status <> 'CONFIRMED'
               OR NOT EXISTS (
                   SELECT 1
                     FROM investigations inv
                    WHERE inv.id = NEW.investigation_id
                      AND inv.tenant_id = NEW.tenant_id
                      AND inv.workspace_id = NEW.workspace_id
                      AND inv.incident_id = i.id
               )
           )
    ) THEN
        RAISE EXCEPTION 'a confirmed root-cause hypothesis cannot be demoted or reparented';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER hypotheses_confirmed_root_cause_guard
    BEFORE UPDATE OF status, investigation_id, tenant_id, workspace_id ON hypotheses
    FOR EACH ROW EXECUTE FUNCTION protect_confirmed_hypothesis();

CREATE OR REPLACE FUNCTION reject_investigation_reparenting() RETURNS trigger AS $$
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR OLD.incident_id IS DISTINCT FROM NEW.incident_id THEN
        RAISE EXCEPTION 'investigation ownership is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER investigations_no_reparenting
    BEFORE UPDATE OF tenant_id, workspace_id, incident_id ON investigations
    FOR EACH ROW EXECUTE FUNCTION reject_investigation_reparenting();

COMMIT;
