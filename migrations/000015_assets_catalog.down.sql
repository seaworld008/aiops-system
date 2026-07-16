BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL search_path = pg_catalog, public, pg_temp;

SET LOCAL ROLE aiops_schema_owner;

LOCK TABLE public.tenants, public.workspaces, public.environments, public.integrations,
    public.services, public.service_bindings, public.audit_records, public.outbox_events,
    public.asset_sources, public.asset_source_revisions,
    public.asset_source_revision_authorities, public.asset_source_runs,
    public.asset_source_limit_buckets, public.asset_source_limit_permits,
    public.asset_observations, public.assets, public.asset_type_details,
    public.asset_conflicts, public.asset_relationships, public.service_asset_bindings
    IN ACCESS EXCLUSIVE MODE NOWAIT;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.service_asset_bindings)
       OR EXISTS (SELECT 1 FROM public.asset_relationships)
       OR EXISTS (SELECT 1 FROM public.asset_conflicts)
       OR EXISTS (SELECT 1 FROM public.asset_type_details)
       OR EXISTS (SELECT 1 FROM public.assets)
       OR EXISTS (SELECT 1 FROM public.asset_observations)
       OR EXISTS (SELECT 1 FROM public.asset_source_limit_permits)
       OR EXISTS (SELECT 1 FROM public.asset_source_limit_buckets)
       OR EXISTS (SELECT 1 FROM public.asset_source_runs)
       OR EXISTS (SELECT 1 FROM public.asset_source_revision_authorities)
       OR EXISTS (SELECT 1 FROM public.asset_source_revisions)
       OR EXISTS (SELECT 1 FROM public.asset_sources) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe asset catalog rollback: catalog state remains';
    END IF;
END;
$$;

REVOKE SELECT ON TABLE public.workspaces, public.environments, public.services,
    public.service_bindings FROM aiops_control_plane_runtime;
REVOKE SELECT ON TABLE public.audit_records FROM aiops_control_plane_runtime;
REVOKE INSERT (id, tenant_id, workspace_id, actor_type, actor_id, action, resource_type,
    resource_id, request_id, trace_id, payload_hash, details, created_at)
    ON public.audit_records FROM aiops_control_plane_runtime;
REVOKE SELECT ON TABLE public.outbox_events FROM aiops_control_plane_runtime;
REVOKE INSERT (id, tenant_id, workspace_id, aggregate_type, aggregate_id,
    aggregate_version, event_type, payload, created_at, available_at)
    ON public.outbox_events FROM aiops_control_plane_runtime;
REVOKE UPDATE (available_at, claimed_at, claimed_by, claim_token, claim_expires_at,
    delivered_at, delivered_claim_token, attempts, last_error_code)
    ON public.outbox_events FROM aiops_control_plane_runtime;

DROP TRIGGER asset_management_audit_insert_guard ON public.audit_records;

DROP TRIGGER asset_observations_immutable ON public.asset_observations;
DROP TRIGGER asset_type_details_immutable ON public.asset_type_details;
DROP TRIGGER asset_source_revision_authorities_immutable ON public.asset_source_revision_authorities;
DROP TRIGGER asset_source_limit_permits_immutable ON public.asset_source_limit_permits;

DROP TRIGGER asset_sources_delete_guard ON public.asset_sources;
DROP TRIGGER asset_source_revisions_delete_guard ON public.asset_source_revisions;
DROP TRIGGER asset_source_revision_authorities_delete_guard ON public.asset_source_revision_authorities;
DROP TRIGGER asset_source_runs_delete_guard ON public.asset_source_runs;
DROP TRIGGER asset_source_limit_buckets_delete_guard ON public.asset_source_limit_buckets;
DROP TRIGGER asset_source_limit_permits_delete_guard ON public.asset_source_limit_permits;
DROP TRIGGER asset_observations_delete_guard ON public.asset_observations;
DROP TRIGGER assets_delete_guard ON public.assets;
DROP TRIGGER asset_type_details_delete_guard ON public.asset_type_details;
DROP TRIGGER asset_conflicts_delete_guard ON public.asset_conflicts;
DROP TRIGGER asset_relationships_delete_guard ON public.asset_relationships;
DROP TRIGGER service_asset_bindings_delete_guard ON public.service_asset_bindings;

DROP TRIGGER asset_sources_truncate_guard ON public.asset_sources;
DROP TRIGGER asset_source_revisions_truncate_guard ON public.asset_source_revisions;
DROP TRIGGER asset_source_revision_authorities_truncate_guard ON public.asset_source_revision_authorities;
DROP TRIGGER asset_source_runs_truncate_guard ON public.asset_source_runs;
DROP TRIGGER asset_source_limit_buckets_truncate_guard ON public.asset_source_limit_buckets;
DROP TRIGGER asset_source_limit_permits_truncate_guard ON public.asset_source_limit_permits;
DROP TRIGGER asset_observations_truncate_guard ON public.asset_observations;
DROP TRIGGER assets_truncate_guard ON public.assets;
DROP TRIGGER asset_type_details_truncate_guard ON public.asset_type_details;
DROP TRIGGER asset_conflicts_truncate_guard ON public.asset_conflicts;
DROP TRIGGER asset_relationships_truncate_guard ON public.asset_relationships;
DROP TRIGGER service_asset_bindings_truncate_guard ON public.service_asset_bindings;

DROP TRIGGER assets_transition_guard ON public.assets;
DROP TRIGGER asset_conflicts_transition_guard ON public.asset_conflicts;
DROP TRIGGER asset_relationships_mutation_guard ON public.asset_relationships;
DROP TRIGGER asset_relationships_page_closure_guard ON public.asset_relationships;
DROP TRIGGER service_asset_bindings_mutation_guard ON public.service_asset_bindings;
DROP TRIGGER asset_source_limit_buckets_mutation_guard ON public.asset_source_limit_buckets;
DROP TRIGGER asset_sources_mutation_guard ON public.asset_sources;
DROP TRIGGER asset_sources_deferred_state_guard ON public.asset_sources;
DROP TRIGGER asset_source_revisions_transition_guard ON public.asset_source_revisions;
DROP TRIGGER asset_source_revisions_deferred_state_guard ON public.asset_source_revisions;
DROP TRIGGER asset_source_revision_authorities_deferred_state_guard ON public.asset_source_revision_authorities;
DROP TRIGGER asset_source_runs_mutation_guard ON public.asset_source_runs;
DROP TRIGGER asset_source_runs_page_closure_guard ON public.asset_source_runs;
DROP TRIGGER asset_source_runs_terminal_closure_guard ON public.asset_source_runs;
DROP TRIGGER asset_observations_admission_guard ON public.asset_observations;
DROP TRIGGER asset_observations_page_closure_guard ON public.asset_observations;

DROP INDEX public.asset_management_idempotency_audit_uk;

DROP FUNCTION public.validate_asset_management_audit_insert();
DROP FUNCTION public.reject_asset_catalog_immutable();
DROP FUNCTION public.reject_asset_catalog_delete();
DROP FUNCTION public.reject_asset_catalog_truncate();
DROP FUNCTION public.enforce_assets_transition();
DROP FUNCTION public.enforce_asset_conflict_transition();
DROP FUNCTION public.enforce_asset_catalog_edge_mutation();
DROP FUNCTION public.enforce_asset_relationship_mutation();
DROP FUNCTION public.validate_asset_relationship_page_closure();
DROP FUNCTION public.enforce_asset_sources_mutation();
DROP FUNCTION public.validate_asset_source_deferred_state();
DROP FUNCTION public.enforce_asset_source_revision_transition();
DROP FUNCTION public.validate_asset_source_revision_deferred_state();
DROP FUNCTION public.enforce_asset_source_run_mutation();
DROP FUNCTION public.validate_asset_source_run_page_closure();
DROP FUNCTION public.validate_asset_source_run_terminal_closure();
DROP FUNCTION public.enforce_asset_observation_admission();
DROP FUNCTION public.validate_asset_observation_page_closure();
DROP FUNCTION public.asset_catalog_lock_exact_service_binding(uuid, uuid, uuid, uuid);

ALTER TABLE public.asset_source_limit_buckets
    DROP CONSTRAINT asset_source_limit_buckets_last_receipt_fk;
ALTER TABLE public.asset_sources
    DROP CONSTRAINT asset_sources_published_revision_fk;
ALTER TABLE public.asset_sources
    DROP CONSTRAINT asset_sources_validated_run_fk;
ALTER TABLE public.asset_sources
    DROP CONSTRAINT asset_sources_last_success_run_fk;
ALTER TABLE public.asset_sources
    DROP CONSTRAINT asset_sources_last_complete_snapshot_run_fk;
ALTER TABLE public.asset_source_revisions
    DROP CONSTRAINT asset_source_revisions_validation_run_fk;

DROP FUNCTION public.asset_catalog_source_run_terminal_digest(public.asset_source_runs, text, text);
DROP FUNCTION public.asset_catalog_source_run_failure_override_digest(public.asset_source_runs, text);
DROP FUNCTION public.asset_catalog_source_run_delay_intent_digest(public.asset_source_runs, text, timestamp with time zone);
DROP FUNCTION public.asset_catalog_source_run_no_credential_digest(public.asset_source_runs);
DROP FUNCTION public.asset_catalog_source_revision_binding_digest(public.asset_source_revisions);
DROP FUNCTION public.asset_catalog_future_source_gate_admitted(public.asset_sources);

DROP TABLE public.service_asset_bindings;
DROP TABLE public.asset_relationships;
DROP TABLE public.asset_conflicts;
DROP TABLE public.asset_type_details;
DROP TABLE public.assets;
DROP TABLE public.asset_observations;
DROP TABLE public.asset_source_limit_permits;
DROP TABLE public.asset_source_limit_buckets;
DROP TABLE public.asset_source_runs;
DROP TABLE public.asset_source_revision_authorities;
DROP TABLE public.asset_source_revisions;
DROP TABLE public.asset_sources;

DROP FUNCTION public.asset_catalog_opaque_reference_valid(text);
DROP FUNCTION public.asset_catalog_framed_value_v1(bytea);
DROP FUNCTION public.asset_catalog_checkpoint_envelope_valid(bytea);
DROP FUNCTION public.asset_catalog_labels_valid(jsonb);
DROP FUNCTION public.asset_catalog_field_provenance_valid(bytea);
DROP FUNCTION public.asset_catalog_json_object_valid(bytea, integer, integer);
DROP FUNCTION public.asset_catalog_idempotency_key_valid(text);
DROP FUNCTION public.asset_catalog_provider_kind_valid(text);
DROP FUNCTION public.asset_catalog_sha256_valid(text);
DROP FUNCTION public.asset_catalog_code_valid(text, integer);
DROP FUNCTION public.asset_catalog_text_valid(text, integer);

RESET ROLE;

COMMIT;
