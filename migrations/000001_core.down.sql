BEGIN;

DROP TABLE IF EXISTS outbox_events;
DROP TRIGGER IF EXISTS audit_records_no_update ON audit_records;
DROP FUNCTION IF EXISTS reject_audit_mutation();
DROP TABLE IF EXISTS audit_records;
DROP TABLE IF EXISTS model_calls;
DROP TABLE IF EXISTS tool_invocations;
DROP TABLE IF EXISTS executions;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS policy_decisions;
DROP TABLE IF EXISTS action_plans;
DROP TABLE IF EXISTS feedback;
DROP TABLE IF EXISTS hypothesis_evidence;
ALTER TABLE IF EXISTS incidents DROP CONSTRAINT IF EXISTS incidents_confirmed_hypothesis_fk;
DROP TABLE IF EXISTS hypotheses;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS investigations;
DROP TABLE IF EXISTS incident_signals;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS signals;
DROP TABLE IF EXISTS service_bindings;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS integrations;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS workspaces;
DROP TABLE IF EXISTS tenants;

COMMIT;
