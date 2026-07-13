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
		"before update or delete on asset_observations",
		"before update or delete on asset_type_details",
		"retired asset is terminal",
		"unsafe asset catalog rollback: catalog state remains",
	} {
		if !strings.Contains(up+"\n"+down, required) {
			t.Errorf("missing invariant %q", required)
		}
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
