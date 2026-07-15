package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
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
		{
			name:     "relation owner",
			mutation: `ALTER TABLE assets OWNER TO aiops_migrator`,
		},
		{
			name:     "relation acl",
			mutation: `GRANT DELETE ON TABLE assets TO aiops_control_plane_runtime`,
		},
		{
			name:     "column acl",
			mutation: `GRANT UPDATE (details) ON TABLE audit_records TO aiops_control_plane_runtime`,
		},
		{
			name:     "function acl",
			mutation: `GRANT EXECUTE ON FUNCTION reject_asset_catalog_immutable() TO PUBLIC`,
		},
		{
			name:     "schema acl",
			mutation: `GRANT USAGE ON SCHEMA public TO PUBLIC`,
		},
		{
			name: "database acl",
			mutation: `
				DO $$ BEGIN
					EXECUTE format(
						'GRANT TEMPORARY ON DATABASE %I TO aiops_control_plane_workload',
						current_database()
					);
				END $$
			`,
		},
		{
			name: "unexpected overload",
			mutation: `
				CREATE FUNCTION enforce_assets_transition(integer) RETURNS boolean AS $$
					SELECT true
				$$ LANGUAGE sql IMMUTABLE
			`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			admission := assetpostgres.NewSchemaAdmission(harness.application, "public")
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
	fixture := seedDraftAssetCatalog(t, harness.db)
	wantBinding, wantGate := readTrustedAssetCatalogDigestAndGate(t, harness.db, fixture)
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
	gotBinding, gotGate := readTrustedAssetCatalogDigestAndGate(t, attackPool, fixture)
	if gotBinding != wantBinding || gotGate != wantGate {
		t.Fatalf("ordinary search_path shadow changed trusted digest/gate: binding=%q gate=%t, want %q/%t",
			gotBinding, gotGate, wantBinding, wantGate)
	}
}

func TestAssetCatalogTrustedFunctionsIgnoreDedicatedHostileTemporaryShadow(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)

	var workloadHasTemporary bool
	if err := harness.application.QueryRow(context.Background(), `
		SELECT pg_catalog.has_database_privilege(current_user, current_database(), 'TEMPORARY')
	`).Scan(&workloadHasTemporary); err != nil {
		t.Fatalf("read workload TEMPORARY privilege: %v", err)
	}
	if workloadHasTemporary {
		t.Fatal("production workload unexpectedly has TEMPORARY privilege")
	}
	expectAssetSQLState(t, harness.application, "42501", `CREATE TEMP TABLE workload_shadow_probe(id integer)`)

	hostileRole := "aiops_hostile_test_" + randomAssetHex(t, 8)
	hostileIdentifier := pgx.Identifier{hostileRole}.Sanitize()
	databaseIdentifier := pgx.Identifier{harness.name}.Sanitize()
	hostilePassword := randomAssetHex(t, 32)
	if _, err := harness.admin.Exec(context.Background(), `CREATE ROLE `+hostileIdentifier+`
		LOGIN PASSWORD '`+hostilePassword+`'
		NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
		GRANT CONNECT, TEMPORARY ON DATABASE `+databaseIdentifier+` TO `+hostileIdentifier+`;`); err != nil {
		t.Fatal("create isolated hostile LOGIN fixture: unavailable")
	}
	t.Cleanup(func() {
		if _, err := harness.db.Exec(context.Background(), `DROP OWNED BY `+hostileIdentifier+`;`); err != nil {
			t.Errorf("drop hostile fixture privileges: %v", err)
		}
		if _, err := harness.admin.Exec(context.Background(), `DROP ROLE `+hostileIdentifier+`;`); err != nil {
			t.Errorf("drop hostile fixture LOGIN: %v", err)
		}
	})

	if _, err := harness.db.Exec(context.Background(), `SET ROLE aiops_schema_owner;
		GRANT USAGE ON SCHEMA public TO `+hostileIdentifier+`;
		GRANT SELECT ON TABLE public.asset_sources, public.asset_source_revisions TO `+hostileIdentifier+`;
		GRANT EXECUTE ON FUNCTION
			public.asset_catalog_framed_value_v1(bytea),
			public.asset_catalog_future_source_gate_admitted(public.asset_sources),
			public.asset_catalog_source_revision_binding_digest(public.asset_source_revisions)
			TO `+hostileIdentifier+`;
		RESET ROLE;`); err != nil {
		t.Fatalf("grant minimum hostile test-call privileges: %v", err)
	}

	config := harness.db.Config().ConnConfig.Copy()
	hostileConnection, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		t.Fatal("open dedicated hostile fixture connection: unavailable")
	}
	t.Cleanup(func() {
		if err := hostileConnection.Close(context.Background()); err != nil {
			t.Errorf("close hostile fixture connection: %v", err)
		}
	})
	if _, err := hostileConnection.Exec(context.Background(), `SET SESSION AUTHORIZATION `+hostileIdentifier); err != nil {
		t.Fatalf("enter dedicated hostile LOGIN identity: %v", err)
	}
	var sessionUser, currentUser string
	if err := hostileConnection.QueryRow(context.Background(), `SELECT session_user, current_user`).Scan(&sessionUser, &currentUser); err != nil {
		t.Fatalf("read hostile fixture identity: %v", err)
	}
	if sessionUser != hostileRole || currentUser != hostileRole {
		t.Fatalf("hostile fixture identity=session:%q current:%q, want %q", sessionUser, currentUser, hostileRole)
	}

	wantBinding, wantGate := readTrustedAssetCatalogDigestAndGate(t, hostileConnection, fixture)
	if wantBinding != fixture.revisionDigest || wantGate {
		t.Fatalf("trusted baseline binding/gate=%q/%t, want %q/false", wantBinding, wantGate, fixture.revisionDigest)
	}
	if _, err := hostileConnection.Exec(context.Background(), `
		CREATE TEMP TABLE asset_sources(id text);
		CREATE TEMP TABLE asset_source_revisions(id text);
		CREATE FUNCTION pg_temp.asset_catalog_future_source_gate_admitted(pg_temp.asset_sources)
		RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT true';
		CREATE FUNCTION pg_temp.asset_catalog_source_revision_binding_digest(pg_temp.asset_source_revisions)
		RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT repeat(''0'',64)';
		CREATE FUNCTION pg_temp.always_false_text_equal(text, text)
		RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT false';
		CREATE OPERATOR pg_temp.= (
			LEFTARG = text,
			RIGHTARG = text,
			FUNCTION = pg_temp.always_false_text_equal
		);
		SET search_path TO pg_temp, public, pg_catalog;
	`); err != nil {
		t.Fatalf("create hostile temporary relation/type/function/operator shadows: %v", err)
	}
	gotBinding, gotGate := readTrustedAssetCatalogDigestAndGate(t, hostileConnection, fixture)
	if gotBinding != wantBinding || gotGate != wantGate {
		t.Fatalf("temporary search_path shadow changed trusted digest/gate: binding=%q gate=%t, want %q/%t",
			gotBinding, gotGate, wantBinding, wantGate)
	}
}

func readTrustedAssetCatalogDigestAndGate(
	t *testing.T,
	database assetSQLQuerier,
	fixture assetCatalogFixture,
) (string, bool) {
	t.Helper()
	var binding string
	var gate bool
	if err := database.QueryRow(context.Background(), `
		SELECT public.asset_catalog_source_revision_binding_digest(revision_record),
			public.asset_catalog_future_source_gate_admitted(source_record)
		FROM public.asset_sources AS source_record
		JOIN public.asset_source_revisions AS revision_record
		  ON revision_record.tenant_id=source_record.tenant_id
		 AND revision_record.workspace_id=source_record.workspace_id
		 AND revision_record.source_id=source_record.id
		WHERE source_record.id=$1 AND revision_record.id=$2
	`, fixture.sourceID, fixture.revisionID).Scan(&binding, &gate); err != nil {
		t.Fatalf("read trusted asset catalog digest/gate: %v", err)
	}
	return binding, gate
}
