BEGIN;

-- Composite candidate keys make tenant/workspace scope part of every domain
-- reference instead of trusting globally unique UUIDs alone.
ALTER TABLE workspaces ADD CONSTRAINT workspaces_tenant_scope_uk UNIQUE (tenant_id, id);
ALTER TABLE environments ADD CONSTRAINT environments_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE services ADD CONSTRAINT services_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE signals ADD CONSTRAINT signals_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE incidents ADD CONSTRAINT incidents_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE investigations ADD CONSTRAINT investigations_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE investigations ADD CONSTRAINT investigations_incident_scope_uk UNIQUE (tenant_id, workspace_id, incident_id, id);
ALTER TABLE evidence ADD CONSTRAINT evidence_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE evidence ADD CONSTRAINT evidence_investigation_scope_uk UNIQUE (tenant_id, workspace_id, investigation_id, id);
ALTER TABLE hypotheses ADD CONSTRAINT hypotheses_workspace_scope_uk UNIQUE (tenant_id, workspace_id, id);
ALTER TABLE hypotheses ADD CONSTRAINT hypotheses_investigation_scope_uk UNIQUE (tenant_id, workspace_id, investigation_id, id);
ALTER TABLE hypotheses ADD CONSTRAINT hypotheses_confirmation_scope_uk UNIQUE (tenant_id, workspace_id, incident_id, status, id);
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
    FOREIGN KEY (tenant_id, workspace_id, incident_id, investigation_id)
    REFERENCES investigations (tenant_id, workspace_id, incident_id, id);
ALTER TABLE feedback ADD CONSTRAINT feedback_investigation_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id)
    REFERENCES investigations (tenant_id, workspace_id, id);
ALTER TABLE feedback ADD CONSTRAINT feedback_hypothesis_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id, hypothesis_id)
    REFERENCES hypotheses (tenant_id, workspace_id, investigation_id, id);
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
    FOREIGN KEY (tenant_id, workspace_id, id, confirmed_hypothesis_status, confirmed_hypothesis_id)
    REFERENCES hypotheses (tenant_id, workspace_id, incident_id, status, id);

ALTER TABLE incident_signals ADD CONSTRAINT incident_signals_incident_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, incident_id)
    REFERENCES incidents (tenant_id, workspace_id, id);
ALTER TABLE incident_signals ADD CONSTRAINT incident_signals_signal_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, signal_id)
    REFERENCES signals (tenant_id, workspace_id, id);
ALTER TABLE hypothesis_evidence ADD CONSTRAINT hypothesis_evidence_hypothesis_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id, hypothesis_id)
    REFERENCES hypotheses (tenant_id, workspace_id, investigation_id, id);
ALTER TABLE hypothesis_evidence ADD CONSTRAINT hypothesis_evidence_evidence_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, investigation_id, evidence_id)
    REFERENCES evidence (tenant_id, workspace_id, investigation_id, id);

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
