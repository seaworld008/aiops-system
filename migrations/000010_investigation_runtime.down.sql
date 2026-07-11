BEGIN;

SET LOCAL lock_timeout = '5s';

SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

LOCK TABLE incidents, incident_signals, investigations, tool_invocations,
    evidence, hypotheses, hypothesis_evidence, feedback,
    investigation_signal_correlations, investigation_idempotency_records,
    runner_evidence_receipts, runner_scope_bindings, runner_registrations,
    runner_certificates, environments, services, signals, workspaces
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM runner_evidence_receipts)
       OR EXISTS (SELECT 1 FROM investigation_idempotency_records)
       OR EXISTS (SELECT 1 FROM investigation_signal_correlations)
       OR EXISTS (SELECT 1 FROM incidents WHERE runtime_schema_version = 'investigation-runtime.v1')
       OR EXISTS (SELECT 1 FROM investigations WHERE runtime_schema_version = 'investigation-runtime.v1')
       OR EXISTS (SELECT 1 FROM tool_invocations WHERE runtime_schema_version = 'investigation-runtime.v1')
       OR EXISTS (SELECT 1 FROM evidence WHERE runtime_schema_version = 'investigation-runtime.v1')
       OR EXISTS (SELECT 1 FROM hypotheses WHERE runtime_schema_version = 'investigation-runtime.v1')
       OR EXISTS (SELECT 1 FROM hypothesis_evidence WHERE runtime_schema_version = 'investigation-runtime.v1')
       OR EXISTS (SELECT 1 FROM feedback WHERE runtime_schema_version = 'investigation-runtime.v1')
       OR EXISTS (SELECT 1 FROM tool_invocations WHERE started_at IS NULL)
       OR EXISTS (
            SELECT 1 FROM feedback
            WHERE kind NOT IN ('HELPFUL', 'NOT_HELPFUL', 'CONFIRM', 'REJECT', 'CORRECT')
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe investigation runtime rollback: M5 runtime state remains';
    END IF;
END;
$$;

DROP TRIGGER runner_evidence_receipts_no_truncate ON runner_evidence_receipts;
DROP TRIGGER runner_evidence_receipts_immutable ON runner_evidence_receipts;
DROP TRIGGER runner_evidence_receipts_insert_guard ON runner_evidence_receipts;
DROP FUNCTION reject_runner_evidence_receipt_mutation();
DROP FUNCTION validate_runner_evidence_receipt_insert();
DROP TABLE runner_evidence_receipts;

DROP TRIGGER investigation_idempotency_records_no_truncate ON investigation_idempotency_records;
DROP TRIGGER investigation_idempotency_records_append_only ON investigation_idempotency_records;
DROP FUNCTION reject_investigation_idempotency_mutation();
DROP TABLE investigation_idempotency_records;

DROP TRIGGER feedback_runtime_no_truncate ON feedback;
DROP TRIGGER feedback_runtime_immutable ON feedback;
DROP TRIGGER feedback_runtime_projection_guard ON feedback;
DROP TRIGGER hypotheses_runtime_feedback_guard ON hypotheses;
DROP FUNCTION validate_runtime_feedback_projection();
DROP FUNCTION validate_runtime_hypothesis_feedback();
DROP FUNCTION reject_feedback_runtime_mutation();
DROP INDEX feedback_runtime_investigation_idx;
ALTER TABLE feedback
    DROP CONSTRAINT feedback_runtime_shape_ck,
    DROP CONSTRAINT feedback_runtime_scope_uk,
    DROP CONSTRAINT feedback_runtime_hypothesis_marker_fk,
    DROP CONSTRAINT feedback_incident_scope_fk,
    DROP CONSTRAINT feedback_kind_check,
    DROP CONSTRAINT feedback_check,
    DROP COLUMN runtime_schema_version,
    DROP COLUMN details_hash,
    DROP COLUMN details_document,
    DROP COLUMN actor_type,
    DROP COLUMN incident_id,
    ADD CONSTRAINT feedback_kind_check CHECK (kind IN ('HELPFUL', 'NOT_HELPFUL', 'CONFIRM', 'REJECT', 'CORRECT')),
    ADD CONSTRAINT feedback_check CHECK (kind NOT IN ('CONFIRM', 'REJECT', 'CORRECT') OR hypothesis_id IS NOT NULL);

DROP INDEX hypothesis_evidence_runtime_position_uk;
DROP TRIGGER hypotheses_runtime_parent_set_guard ON hypotheses;
DROP TRIGGER investigations_runtime_hypothesis_set_guard ON investigations;
DROP FUNCTION validate_runtime_hypothesis_parent_set();
DROP FUNCTION validate_investigation_runtime_hypothesis_set();
DROP FUNCTION investigation_runtime_hypothesis_set_valid(uuid, uuid, uuid);
DROP TRIGGER hypotheses_runtime_evidence_guard ON hypotheses;
DROP TRIGGER hypothesis_evidence_runtime_insert_guard ON hypothesis_evidence;
DROP TRIGGER hypothesis_evidence_runtime_no_truncate ON hypothesis_evidence;
DROP TRIGGER hypothesis_evidence_runtime_immutable ON hypothesis_evidence;
DROP FUNCTION validate_runtime_hypothesis_evidence();
DROP FUNCTION validate_runtime_hypothesis_evidence_insert();
DROP FUNCTION reject_hypothesis_evidence_runtime_mutation();
ALTER TABLE hypothesis_evidence
    DROP CONSTRAINT hypothesis_evidence_runtime_shape_ck,
    DROP COLUMN runtime_schema_version,
    DROP COLUMN position;

DROP TRIGGER hypotheses_runtime_mutation_guard ON hypotheses;
DROP FUNCTION enforce_hypothesis_runtime_mutation();
ALTER TABLE incidents DROP CONSTRAINT incidents_runtime_confirmed_hypothesis_fk;
DROP INDEX hypotheses_runtime_confirmed_incident_uk;
DROP INDEX hypotheses_runtime_list_idx;
DROP INDEX hypotheses_runtime_rank_uk;
ALTER TABLE hypotheses
    DROP CONSTRAINT hypotheses_runtime_shape_ck,
    DROP CONSTRAINT hypotheses_runtime_exact_scope_uk,
    DROP CONSTRAINT hypotheses_runtime_marker_scope_uk,
    DROP CONSTRAINT hypotheses_runtime_confirmation_marker_uk,
    DROP COLUMN runtime_schema_version,
    DROP COLUMN unknowns,
    DROP COLUMN proposal_hash,
    DROP COLUMN proposal_document,
    DROP COLUMN confidence;

ALTER TABLE tool_invocations DROP CONSTRAINT tool_invocations_runtime_evidence_fk;

DROP TRIGGER evidence_runtime_no_truncate ON evidence;
DROP TRIGGER evidence_runtime_immutable ON evidence;
DROP TRIGGER evidence_runtime_task_projection_guard ON evidence;
DROP TRIGGER evidence_runtime_insert_guard ON evidence;
DROP FUNCTION reject_evidence_runtime_mutation();
DROP FUNCTION validate_runtime_evidence_task_projection();
DROP FUNCTION validate_runtime_evidence_insert();
DROP INDEX evidence_runtime_list_idx;
DROP INDEX evidence_runtime_task_uk;
ALTER TABLE evidence
    DROP CONSTRAINT evidence_runtime_shape_ck,
    DROP CONSTRAINT evidence_runtime_task_result_uk,
    DROP CONSTRAINT evidence_runtime_task_fk,
    DROP CONSTRAINT evidence_runtime_investigation_fk,
    DROP COLUMN runtime_schema_version,
    DROP COLUMN attributes,
    DROP COLUMN payload_document,
    DROP COLUMN task_id,
    DROP COLUMN incident_id;

DROP INDEX tool_invocations_runtime_status_list_idx;
DROP INDEX tool_invocations_runtime_list_idx;
DROP INDEX tool_invocations_runtime_position_uk;
DROP INDEX tool_invocations_runtime_task_key_uk;
DROP TRIGGER investigations_runtime_terminal_tasks_guard ON investigations;
DROP FUNCTION validate_investigation_runtime_terminal_tasks();
DROP TRIGGER tool_invocations_runtime_parent_guard ON tool_invocations;
DROP FUNCTION validate_tool_invocation_runtime_parent_lifecycle();
DROP TRIGGER tool_invocations_runtime_no_truncate ON tool_invocations;
DROP TRIGGER tool_invocations_runtime_no_delete ON tool_invocations;
DROP FUNCTION reject_tool_invocation_runtime_removal();
DROP TRIGGER investigations_runtime_transition_guard ON investigations;
DROP FUNCTION enforce_investigation_runtime_transition();
DROP TRIGGER tool_invocations_runtime_mutation_guard ON tool_invocations;
DROP FUNCTION enforce_tool_invocation_runtime_mutation();
ALTER TABLE tool_invocations
    DROP CONSTRAINT tool_invocations_runtime_lifecycle_ck,
    DROP CONSTRAINT tool_invocations_runtime_shape_ck,
    DROP CONSTRAINT tool_invocations_runtime_connector_scope_uk,
    DROP CONSTRAINT tool_invocations_runtime_scope_uk,
    DROP CONSTRAINT tool_invocations_runtime_investigation_fk,
    DROP COLUMN runtime_schema_version,
    DROP COLUMN updated_at,
    DROP COLUMN created_at,
    DROP COLUMN failure_code,
    DROP COLUMN evidence_id,
    DROP COLUMN input_document,
    DROP COLUMN position,
    DROP COLUMN task_key,
    DROP COLUMN incident_id;
ALTER TABLE tool_invocations ALTER COLUMN started_at SET NOT NULL;

DROP FUNCTION investigation_text_array_bounded(text[], integer, integer);
DROP FUNCTION investigation_json_object_document_valid(bytea, integer);

DROP TRIGGER investigations_runtime_identity_guard ON investigations;
DROP FUNCTION reject_investigation_runtime_identity_mutation();
DROP INDEX investigations_runtime_status_list_idx;
DROP INDEX investigations_runtime_incident_list_idx;
DROP INDEX investigations_runtime_list_idx;
DROP INDEX investigations_single_active_incident_uk;
ALTER TABLE investigations
    DROP CONSTRAINT investigations_runtime_environment_scope_uk,
    DROP CONSTRAINT investigations_runtime_lifecycle_ck,
    DROP CONSTRAINT investigations_runtime_shape_ck,
    DROP CONSTRAINT investigations_environment_snapshot_fk,
    DROP CONSTRAINT investigations_service_snapshot_fk,
    DROP COLUMN runtime_schema_version,
    DROP COLUMN mapping_status_snapshot,
    DROP COLUMN environment_id_snapshot,
    DROP COLUMN service_id_snapshot,
    DROP COLUMN updated_at,
    DROP COLUMN started_at,
    DROP COLUMN model_failure_code,
    DROP COLUMN failure_code,
    DROP COLUMN request_hash_version,
    DROP COLUMN request_hash,
    DROP COLUMN idempotency_key,
    DROP COLUMN model_status;

DROP TRIGGER investigation_signal_correlations_no_truncate ON investigation_signal_correlations;
DROP TRIGGER investigation_signal_correlations_immutable ON investigation_signal_correlations;
DROP TRIGGER investigation_signal_correlations_insert_guard ON investigation_signal_correlations;
DROP TRIGGER signals_investigation_correlation_no_truncate ON signals;
DROP TRIGGER signals_investigation_correlation_guard ON signals;
DROP FUNCTION reject_correlated_signal_mutation();
DROP TRIGGER investigation_signal_correlations_runtime_projection_guard ON investigation_signal_correlations;
DROP TRIGGER incident_signals_runtime_projection_guard ON incident_signals;
DROP TRIGGER incidents_runtime_signal_projection_guard ON incidents;
DROP FUNCTION validate_runtime_incident_signal_projection();
DROP FUNCTION investigation_runtime_incident_signal_set_valid(uuid, uuid, uuid);
DROP FUNCTION reject_investigation_signal_correlation_mutation();
DROP FUNCTION validate_investigation_signal_correlation_insert();
DROP INDEX investigation_signal_correlations_incident_idx;
DROP TABLE investigation_signal_correlations;

ALTER TABLE incident_signals DROP CONSTRAINT incident_signals_runtime_exact_association_uk;
DROP INDEX incident_signals_single_incident_per_signal_uk;
DROP INDEX incidents_runtime_status_list_idx;
DROP INDEX incidents_runtime_list_idx;
DROP INDEX incidents_active_correlation_uk;
DROP TRIGGER incidents_runtime_mutation_guard ON incidents;
DROP FUNCTION enforce_incident_runtime_mutation();
ALTER TABLE incidents
    DROP CONSTRAINT incidents_runtime_shape_ck,
    DROP COLUMN runtime_schema_version,
    DROP COLUMN signal_count,
    DROP COLUMN last_signal_at,
    DROP COLUMN mapping_status,
    DROP COLUMN correlation_key;

COMMIT;
