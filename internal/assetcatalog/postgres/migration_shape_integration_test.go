package postgres_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestAssetCatalogMigrationFinalColumnShape(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	want := map[string][]string{
		"asset_sources": {
			"last_success_run_id", "last_success_at",
			"last_complete_snapshot_run_id", "last_complete_snapshot_at",
		},
		"asset_source_runs": {
			"stage_code", "stage_changed_at", "final_page", "complete_snapshot",
			"effective_complete_snapshot", "relation_page_sequence", "relation_page_digest",
			"pending_transition", "pending_transition_reason", "pending_transition_not_before",
			"pending_transition_digest", "stale_count", "restored_count", "tombstoned_count",
			"work_result_kind", "work_result_status", "work_result_digest", "work_result_recorded_at",
			"validation_outcome", "validation_proof_digest", "lineage_rollover_reason",
			"lineage_rollover_evidence_digest", "cleanup_attempt_id", "cleanup_attempt_epoch",
			"cleanup_status", "cleanup_digest", "terminal_failure_override",
			"terminal_failure_override_digest", "terminal_command_sha256",
		},
		"asset_source_limit_buckets": {
			"bucket_kind", "bucket_key", "source_id", "provider_kind", "next_token_at",
			"last_receipt_id", "version", "created_at", "updated_at",
		},
		"asset_source_limit_permits": {
			"permit_id", "record_kind", "source_id", "run_id", "provider_kind",
			"source_bucket_id", "source_bucket_kind", "source_bucket_key",
			"workspace_bucket_id", "workspace_bucket_kind", "workspace_bucket_key",
			"provider_bucket_id", "provider_bucket_kind", "provider_bucket_key",
			"request_id", "command_sha256", "receipt_sha256", "acquired_at", "expires_at",
			"not_before", "terminal_reason_code", "created_at",
		},
		"asset_observations": {
			"canonical_revision_digest", "source_definition_digest", "freshness_kind",
			"freshness_order_time", "freshness_order_sequence", "provider_version_sha256",
			"provider_fact_sha256", "fingerprint_sha256", "provider_provenance_sha256",
			"previous_observation_id", "previous_chain_sha256", "observation_chain_sha256",
			"accepted_checkpoint_version", "run_fence_epoch", "run_page_sequence",
		},
		"assets": {"last_observation_chain_sha256"},
		"asset_type_details": {
			"source_id", "provider_kind", "external_id", "source_revision",
			"source_observed_at", "source_observation_chain_sha256",
		},
		"asset_relationships": {
			"source_id", "source_revision", "canonical_revision_digest", "last_run_id",
			"last_page_sequence", "relation_page_sha256", "from_external_id", "to_external_id",
			"accepted_checkpoint_version", "run_fence_epoch",
			"provider_path_code", "confidence", "freshness_kind", "freshness_order_time",
			"freshness_order_sequence", "provider_version_sha256", "relation_fact_sha256",
		},
	}

	for table, columns := range want {
		rows, err := harness.db.Query(context.Background(), `
			SELECT column_name
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1
		`, table)
		if err != nil {
			t.Fatalf("read %s columns: %v", table, err)
		}
		actual := make(map[string]struct{})
		for rows.Next() {
			var column string
			if err := rows.Scan(&column); err != nil {
				rows.Close()
				t.Fatalf("scan %s column: %v", table, err)
			}
			actual[column] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("iterate %s columns: %v", table, err)
		}
		rows.Close()
		var missing []string
		for _, column := range columns {
			if _, ok := actual[column]; !ok {
				missing = append(missing, column)
			}
		}
		if len(missing) != 0 {
			sort.Strings(missing)
			t.Errorf("%s missing final columns: %s", table, strings.Join(missing, ", "))
		}
	}

	for _, obsolete := range []struct{ table, column string }{
		{"asset_source_runs", "definition_revision"},
		{"asset_sources", "last_successful_run_id"},
	} {
		var present bool
		if err := harness.db.QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2
			)
		`, obsolete.table, obsolete.column).Scan(&present); err != nil {
			t.Fatalf("inspect obsolete column %s.%s: %v", obsolete.table, obsolete.column, err)
		}
		if present {
			t.Errorf("obsolete column remains: %s.%s", obsolete.table, obsolete.column)
		}
	}
}

func TestAssetCatalogMigrationFinalNamedConstraintsAndIndexes(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	for _, name := range []string{
		"asset_relationships_type_check",
		"asset_observations_same_run_object_uk",
		"asset_observations_previous_pair_ck",
		"asset_source_runs_state_ck",
		"asset_sources_last_success_run_fk",
		"asset_sources_last_complete_snapshot_run_fk",
		"asset_source_runs_nonterminal_uk",
		"asset_source_runs_cleanup_reclaim_idx",
		"asset_source_limit_buckets_scope_key_uk",
		"asset_source_limit_buckets_last_receipt_fk",
		"asset_source_limit_permits_workspace_request_uk",
		"asset_source_limit_permits_one_terminal_uk",
		"asset_source_limit_permits_active_lookup_idx",
	} {
		var present bool
		if err := harness.db.QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM pg_constraint c
				JOIN pg_namespace n ON n.oid=c.connamespace
				WHERE n.nspname=current_schema() AND c.conname=$1
				UNION ALL
				SELECT 1 FROM pg_class i
				JOIN pg_namespace n ON n.oid=i.relnamespace
				WHERE n.nspname=current_schema() AND i.relkind='i' AND i.relname=$1
			)
		`, name).Scan(&present); err != nil {
			t.Fatalf("inspect catalog object %s: %v", name, err)
		}
		if !present {
			t.Errorf("required catalog object is missing: %s", name)
		}
	}

	var definition string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT pg_get_constraintdef(c.oid, true)
		FROM pg_constraint c
		JOIN pg_namespace n ON n.oid=c.connamespace
		WHERE n.nspname=current_schema() AND c.conname='asset_relationships_type_check'
	`).Scan(&definition); err != nil {
		t.Fatalf("read relationship type constraint: %v", err)
	}
	for _, value := range []string{
		"RUNS_ON", "CONTAINS", "DEPENDS_ON", "MONITORED_BY", "LOGS_TO", "TRACES_TO",
		"DELIVERED_BY", "MANAGED_BY", "PRIMARY_RUNTIME_FOR",
	} {
		if !strings.Contains(definition, fmt.Sprintf("'%s'", value)) {
			t.Errorf("relationship type constraint omits %s: %s", value, definition)
		}
	}
	for _, future := range []string{"CONFIGURES", "SELECTS", "OWNED_BY"} {
		if strings.Contains(definition, fmt.Sprintf("'%s'", future)) {
			t.Errorf("Phase 1 relationship constraint contains future value %s", future)
		}
	}
}
