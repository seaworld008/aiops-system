BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

SET LOCAL search_path = public, pg_catalog, pg_temp;

LOCK TABLE service_asset_bindings, asset_relationships, asset_conflicts,
    asset_type_details, assets, asset_observations, asset_source_runs,
    asset_source_revisions, asset_sources IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM service_asset_bindings)
       OR EXISTS (SELECT 1 FROM asset_relationships)
       OR EXISTS (SELECT 1 FROM asset_conflicts)
       OR EXISTS (SELECT 1 FROM asset_type_details)
       OR EXISTS (SELECT 1 FROM assets)
       OR EXISTS (SELECT 1 FROM asset_observations)
       OR EXISTS (SELECT 1 FROM asset_source_runs)
       OR EXISTS (SELECT 1 FROM asset_source_revisions)
       OR EXISTS (SELECT 1 FROM asset_sources) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe asset catalog rollback: catalog state remains';
    END IF;
END;
$$;

DROP TRIGGER asset_management_audit_insert_guard ON audit_records;
DROP INDEX asset_management_idempotency_audit_uk;

DROP TRIGGER asset_type_details_immutable ON asset_type_details;
DROP TRIGGER asset_observations_immutable ON asset_observations;
DROP TRIGGER asset_observations_page_closure_guard ON asset_observations;
DROP TRIGGER assets_transition_guard ON assets;
DROP TRIGGER asset_source_runs_terminal_closure_guard ON asset_source_runs;
DROP TRIGGER asset_source_runs_page_closure_guard ON asset_source_runs;
DROP TRIGGER asset_source_runs_mutation_guard ON asset_source_runs;
DROP TRIGGER asset_source_revisions_deferred_state_guard ON asset_source_revisions;
DROP TRIGGER asset_source_revisions_transition_guard ON asset_source_revisions;
DROP TRIGGER asset_sources_deferred_state_guard ON asset_sources;
DROP TRIGGER asset_sources_mutation_guard ON asset_sources;
DROP TRIGGER asset_conflicts_transition_guard ON asset_conflicts;
DROP TRIGGER asset_relationships_mutation_guard ON asset_relationships;
DROP TRIGGER asset_relationships_page_closure_guard ON asset_relationships;
DROP TRIGGER service_asset_bindings_mutation_guard ON service_asset_bindings;

DROP FUNCTION validate_asset_relationship_page_closure();
DROP FUNCTION validate_asset_observation_page_closure();
DROP FUNCTION validate_asset_source_run_terminal_closure();
DROP FUNCTION validate_asset_source_run_page_closure();
DROP FUNCTION validate_asset_source_revision_deferred_state();
DROP FUNCTION asset_catalog_source_run_terminal_digest(asset_source_runs, text, text);
DROP FUNCTION asset_catalog_source_run_failure_override_digest(asset_source_runs, text);
DROP FUNCTION asset_catalog_source_run_delay_intent_digest(asset_source_runs, text, timestamptz);
DROP FUNCTION asset_catalog_source_run_no_credential_digest(asset_source_runs);

ALTER TABLE asset_sources
    DROP CONSTRAINT asset_sources_published_revision_fk,
    DROP CONSTRAINT asset_sources_validated_run_fk,
    DROP CONSTRAINT asset_sources_last_success_run_fk,
    DROP CONSTRAINT asset_sources_last_complete_snapshot_run_fk;
ALTER TABLE asset_source_revisions
    DROP CONSTRAINT asset_source_revisions_validation_run_fk;

DROP TABLE service_asset_bindings;
DROP TABLE asset_relationships;
DROP TABLE asset_conflicts;
DROP TABLE asset_type_details;
DROP TABLE assets;
DROP TABLE asset_observations;
DROP TABLE asset_source_runs;
DROP TABLE asset_source_revisions;
DROP TABLE asset_sources;

DROP FUNCTION enforce_assets_transition();
DROP FUNCTION enforce_asset_conflict_transition();
DROP FUNCTION enforce_asset_catalog_edge_mutation();
DROP FUNCTION enforce_asset_relationship_mutation();
DROP FUNCTION validate_asset_management_audit_insert();
DROP FUNCTION enforce_asset_observation_admission();
DROP FUNCTION enforce_asset_source_run_mutation();
DROP FUNCTION enforce_asset_source_revision_transition();
DROP FUNCTION validate_asset_source_deferred_state();
DROP FUNCTION enforce_asset_sources_mutation();
DROP FUNCTION reject_asset_catalog_truncate();
DROP FUNCTION reject_asset_catalog_delete();
DROP FUNCTION reject_asset_catalog_immutable();
DROP FUNCTION asset_catalog_framed_value_v1(bytea);
DROP FUNCTION asset_catalog_checkpoint_envelope_valid(bytea);
DROP FUNCTION asset_catalog_labels_valid(jsonb);
DROP FUNCTION asset_catalog_field_provenance_valid(bytea);
DROP FUNCTION asset_catalog_json_object_valid(bytea, integer, integer);
DROP FUNCTION asset_catalog_idempotency_key_valid(text);
DROP FUNCTION asset_catalog_provider_kind_valid(text);
DROP FUNCTION asset_catalog_sha256_valid(text);
DROP FUNCTION asset_catalog_code_valid(text, integer);
DROP FUNCTION asset_catalog_text_valid(text, integer);

COMMIT;
