package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
)

func TestAssetCatalogSchemaAdmissionRejectsCatalogDrift(t *testing.T) {
	tests := []struct {
		name     string
		mutation string
	}{
		{
			name: "guard function body",
			mutation: `
				CREATE OR REPLACE FUNCTION reject_asset_catalog_immutable() RETURNS trigger AS $$
				BEGIN RETURN NEW; END;
				$$ LANGUAGE plpgsql SET search_path TO public, pg_catalog, pg_temp
			`,
		},
		{
			name: "weakened check",
			mutation: `
				ALTER TABLE assets DROP CONSTRAINT assets_kind_check;
				ALTER TABLE assets ADD CONSTRAINT assets_kind_check CHECK (kind <> '');
			`,
		},
		{name: "missing index", mutation: `DROP INDEX assets_filter_idx`},
		{
			name:     "renamed index",
			mutation: `ALTER INDEX assets_filter_idx RENAME TO assets_filter_idx_drifted`,
		},
		{
			name:     "disabled trigger",
			mutation: `ALTER TABLE asset_observations DISABLE TRIGGER asset_observations_immutable`,
		},
		{
			name:     "replica-only trigger",
			mutation: `ALTER TABLE asset_observations ENABLE REPLICA TRIGGER asset_observations_immutable`,
		},
		{
			name:     "column default",
			mutation: `ALTER TABLE asset_sources ALTER COLUMN gate_status SET DEFAULT 'AVAILABLE'`,
		},
		{
			name:     "column type",
			mutation: `ALTER TABLE asset_sources ALTER COLUMN name TYPE varchar(256) USING name::varchar(256)`,
		},
		{
			name:     "checkpoint comment",
			mutation: `COMMENT ON COLUMN asset_sources.checkpoint_ciphertext IS 'weakened comment'`,
		},
		{
			name:     "foreign key",
			mutation: `ALTER TABLE asset_observations DROP CONSTRAINT asset_observations_run_revision_fk`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			admission := assetpostgres.NewSchemaAdmission(harness.db, "public")
			if err := admission.Check(context.Background()); err != nil {
				t.Fatalf("pristine schema admission: %v", err)
			}
			execAssetSQL(t, harness.db, test.mutation)
			if err := admission.Check(context.Background()); !errors.Is(err, assetpostgres.ErrAssetCatalogUnavailable) {
				t.Fatalf("drifted schema admission error=%v, want %v", err, assetpostgres.ErrAssetCatalogUnavailable)
			}
		})
	}
}

func TestAssetCatalogSchemaAdmissionIgnoresSearchPathShadow(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	config := harness.db.Config()
	config.MinConns = 0
	config.MaxConns = 1
	attackPool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("create single-connection shadow pool: %v", err)
	}
	t.Cleanup(attackPool.Close)
	if err := attackPool.Ping(context.Background()); err != nil {
		t.Fatalf("ping single-connection shadow pool: %v", err)
	}

	execAssetSQL(t, attackPool, `
			CREATE SCHEMA shadow;
			CREATE TABLE shadow.asset_sources (id text);
			CREATE FUNCTION shadow.reject_asset_catalog_immutable() RETURNS trigger AS $$
			BEGIN RETURN NEW; END;
			$$ LANGUAGE plpgsql;
			CREATE FUNCTION shadow.always_false_oid_equal(oid, oid) RETURNS boolean AS $$
			BEGIN RETURN false; END;
			$$ LANGUAGE plpgsql IMMUTABLE;
			CREATE OPERATOR shadow.= (
				LEFTARG = oid,
				RIGHTARG = oid,
				FUNCTION = shadow.always_false_oid_equal
			);
			SET search_path TO shadow, public, pg_catalog;
		`)
	if err := assetpostgres.NewSchemaAdmission(attackPool, "public").Check(context.Background()); err != nil {
		t.Fatalf("explicit public admission was influenced by search_path shadow: %v", err)
	}
}
