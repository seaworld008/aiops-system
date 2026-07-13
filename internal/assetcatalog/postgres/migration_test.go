package postgres_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAssetCatalogMigrationOwnsExactTablesAndGuardsData(t *testing.T) {
	up := strings.ToLower(readMigration(t, "000015_assets_catalog.up.sql"))
	down := strings.ToLower(readMigration(t, "000015_assets_catalog.down.sql"))
	owned := []string{
		"asset_sources",
		"asset_source_revisions",
		"asset_source_runs",
		"asset_observations",
		"assets",
		"asset_type_details",
		"asset_conflicts",
		"asset_relationships",
		"service_asset_bindings",
	}
	for _, table := range owned {
		if !strings.Contains(up, "create table "+table) {
			t.Errorf("up does not create %s", table)
		}
		if !strings.Contains(down, "drop table "+table) {
			t.Errorf("down does not drop %s", table)
		}
	}
	for _, forbidden := range []string{
		"connection_profiles",
		"published_targets",
		"asset_snapshots",
		"investigation_grants",
		"runner_realms",
		"credential_references",
	} {
		if strings.Contains(up, "create table "+forbidden) {
			t.Errorf("000015 illegally owns %s", forbidden)
		}
	}
	for _, required := range []string{
		"unique (tenant_id, workspace_id, source_id, provider_kind, external_id)",
		"unique (tenant_id, workspace_id, environment_id, id)",
		"before update on asset_observations",
		"before update on asset_type_details",
		"before delete on asset_sources",
		"before truncate on asset_sources",
		"constraint assets_kind_check",
		"retired asset is terminal",
		"unsafe asset catalog rollback: catalog state remains",
	} {
		if !strings.Contains(up+"\n"+down, required) {
			t.Errorf("missing invariant %q", required)
		}
	}
}

func TestAssetCatalogMigrationContainsFinalGovernedRunAndFreshnessContract(t *testing.T) {
	up := strings.ToLower(readMigration(t, "000015_assets_catalog.up.sql"))

	for _, forbidden := range []string{
		"definition_revision",
		"last_successful_run_id",
		"'classification'",
	} {
		if strings.Contains(up, forbidden) {
			t.Errorf("obsolete schema token remains: %q", forbidden)
		}
	}

	for _, required := range []string{
		"'manual_mutation'",
		"'delayed'",
		"'finalizing'",
		"stage_code",
		"stage_changed_at",
		"pending_transition",
		"pending_transition_digest",
		"work_result_kind",
		"work_result_digest",
		"cleanup_attempt_id",
		"cleanup_attempt_epoch",
		"cleanup_status",
		"cleanup_digest",
		"terminal_failure_override",
		"terminal_failure_override_digest",
		"terminal_command_sha256",
		"checkpoint_lineage_rollover_bound",
		"relation_page_committed",
		"asset_source_runs_page_closure_guard",
		"asset_source_runs_terminal_closure_guard",
		"last_success_run_id",
		"last_complete_snapshot_run_id",
		"freshness_kind",
		"freshness_order_time",
		"freshness_order_sequence",
		"provider_version_sha256",
		"provider_fact_sha256",
		"fingerprint_sha256",
		"provider_provenance_sha256",
		"previous_observation_id",
		"previous_chain_sha256",
		"observation_chain_sha256",
		"accepted_checkpoint_version",
		"run_fence_epoch",
		"run_page_sequence",
		"unique (tenant_id, workspace_id, source_id, run_id, provider_kind, external_id)",
		"constraint asset_relationships_type_check",
		"relation_fact_sha256",
		"relation_page_sha256",
		"last_run_id",
		"last_page_sequence",
		"provider_path_code",
		"confidence",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("final governed schema token is missing: %q", required)
		}
	}
}

func TestAssetCatalogMigrationPinsTrustedPublicSearchPathBeforeObjectResolution(t *testing.T) {
	for _, name := range []string{
		"000015_assets_catalog.up.sql",
		"000015_assets_catalog.down.sql",
	} {
		t.Run(name, func(t *testing.T) {
			migration := strings.ToLower(readMigration(t, name))
			searchPath := strings.Index(migration,
				"set local search_path = public, pg_catalog, pg_temp;")
			firstObjectResolution := strings.Index(migration, "lock table")
			if searchPath < 0 || firstObjectResolution < 0 || searchPath > firstObjectResolution {
				t.Fatal("migration must pin the trusted public search_path before resolving catalog objects")
			}
			for _, forbidden := range []string{"set_config(", "current_schema()"} {
				if strings.Contains(migration[:firstObjectResolution], forbidden) {
					t.Fatalf("migration bootstrap resolves untrusted schema through %q", forbidden)
				}
			}
		})
	}
}

func TestAssetCatalogMigrationUsesWrapSafeSameTransactionXIDComparison(t *testing.T) {
	up := strings.ToLower(readMigration(t, "000015_assets_catalog.up.sql"))
	if strings.Contains(up, ".xmin::text::xid8") {
		t.Fatal("same-transaction closure must not reinterpret wrapped 32-bit xmin as epoch-zero xid8")
	}
	const wrapSafeComparison = ".xmin = pg_catalog.pg_current_xact_id()::xid"
	if count := strings.Count(up, wrapSafeComparison); count != 16 {
		t.Fatalf("wrap-safe same-transaction comparisons = %d, want 16", count)
	}
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve asset catalog migration test path")
	}
	contents, err := os.ReadFile(filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations", name)))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(contents)
}
