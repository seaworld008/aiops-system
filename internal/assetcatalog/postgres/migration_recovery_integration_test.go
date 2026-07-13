package postgres_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type recoveredTableProof struct {
	count    int64
	checksum string
}

func TestAssetCatalogRecovery(t *testing.T) {
	dsn := os.Getenv("AIOPS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; real PostgreSQL 18.4 logical recovery was not run")
	}
	assertContainerPostgreSQLTools(t)
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse recovery PostgreSQL DSN: %v", err)
	}
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect recovery PostgreSQL admin database: %v", err)
	}
	t.Cleanup(admin.Close)
	assertRecoveryServerVersion(t, admin)

	suffix := randomAssetHex(t, 6)
	sourceName := "aiops_assets_source_" + suffix
	targetName := "aiops_assets_target_" + suffix
	var source, target *pgxpool.Pool
	t.Cleanup(func() {
		if source != nil {
			source.Close()
		}
		if target != nil {
			target.Close()
		}
		dropRecoveryDatabase(t, admin, sourceName)
		dropRecoveryDatabase(t, admin, targetName)
	})
	createRecoveryDatabase(t, admin, sourceName)
	createRecoveryDatabase(t, admin, targetName)

	source = connectRecoveryDatabase(t, dsn, sourceName)
	(&assetCatalogHarness{db: source}).applyThroughAssetCatalog(t)
	fixture := seedRepresentativeAssetCatalog(t, source)
	seedRecoveryProjection(t, source, fixture)
	sourceProof := collectAssetCatalogProof(t, source)
	verifyAssetCatalogClosure(t, source, fixture)

	backup := logicalDumpDatabase(t, sourceName)
	if len(backup) < 1024 {
		t.Fatalf("logical backup is unexpectedly small: %d bytes", len(backup))
	}
	restoreLogicalDump(t, targetName, backup)
	target = connectRecoveryDatabase(t, dsn, targetName)
	assertRecoveryServerVersion(t, target)
	targetProof := collectAssetCatalogProof(t, target)
	if len(sourceProof) != len(targetProof) {
		t.Fatalf("restored proof table count=%d, want %d", len(targetProof), len(sourceProof))
	}
	for table, want := range sourceProof {
		got, ok := targetProof[table]
		if !ok || got != want {
			t.Errorf("restored %s proof=%+v present=%v, want %+v", table, got, ok, want)
		}
	}
	verifyAssetCatalogClosure(t, target, fixture)
	expectAssetSQLState(t, target, "55000", `UPDATE asset_observations SET source_revision='restored-tamper'`)
	expectAssetSQLState(t, target, "55000", `DELETE FROM asset_type_details WHERE id=$1`, fixture.typeDetailID)
}

func assertContainerPostgreSQLTools(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker CLI is required for PostgreSQL 18 logical recovery proof: %v", err)
	}
	for _, tool := range []string{"pg_dump", "pg_restore"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		command := exec.CommandContext(ctx, "docker", "--context", "colima-aiops", "exec", "aiops-postgres18", tool, "--version")
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("run container %s --version: %v: %s", tool, err, sanitizeToolOutput(output))
		}
		if !strings.Contains(string(output), "PostgreSQL) 18.4") {
			t.Fatalf("container %s version=%q, want PostgreSQL 18.4", tool, strings.TrimSpace(string(output)))
		}
	}
}

func createRecoveryDatabase(t *testing.T, admin *pgxpool.Pool, name string) {
	t.Helper()
	identifier := pgx.Identifier{name}.Sanitize()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" TEMPLATE template0"); err != nil {
		t.Fatalf("create clean recovery database %s: %v", name, err)
	}
}

func dropRecoveryDatabase(t *testing.T, admin *pgxpool.Pool, name string) {
	t.Helper()
	identifier := pgx.Identifier{name}.Sanitize()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)"); err != nil {
		t.Errorf("drop recovery database %s: %v", name, err)
	}
}

func connectRecoveryDatabase(t *testing.T, dsn, name string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated recovery database config: %v", err)
	}
	config.ConnConfig.Database = name
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "public"
	database, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("connect isolated recovery database %s: %v", name, err)
	}
	if err := database.Ping(context.Background()); err != nil {
		database.Close()
		t.Fatalf("ping isolated recovery database %s: %v", name, err)
	}
	return database
}

func assertRecoveryServerVersion(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	var serverVersion int
	if err := database.QueryRow(context.Background(), `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
		t.Fatalf("read recovery PostgreSQL server version: %v", err)
	}
	if serverVersion < 180004 || serverVersion >= 190000 {
		t.Fatalf("recovery proof requires PostgreSQL 18.4 or newer 18.x, got server_version_num=%d", serverVersion)
	}
}

func seedRecoveryProjection(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	validationRunID := "62000000-0000-4000-8000-000000000209"
	validationDigest := strings.Repeat("9", 64)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,status,trigger_type,definition_revision,gate_revision,idempotency_key,
			request_hash,validation_digest,completed_at
		) VALUES ($1,$2,$3,$4,1,$5,'VALIDATION','SUCCEEDED','HUMAN',1,0,
			'recovery-validation',repeat('8',64),$6,statement_timestamp())
	`, validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest, validationDigest)
	execAssetSQL(t, database, `UPDATE asset_source_revisions SET state='VALIDATING',version=version+1 WHERE id=$1`, fixture.revisionID)
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions
		SET state='VALIDATED',validation_run_id=$1,validation_digest=$2,version=version+1
		WHERE id=$3
	`, validationRunID, validationDigest, fixture.revisionID)
	execAssetSQL(t, database, `UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1`, fixture.revisionID)
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='AVAILABLE',gate_revision=gate_revision+1,validated_run_id=$1,
			validation_digest=$2,validated_binding_digest=repeat('c',64),version=version+1
		WHERE id=$3
	`, validationRunID, validationDigest, fixture.sourceID)
	execAssetSQL(t, database, `UPDATE assets SET lifecycle='ACTIVE',version=version+1 WHERE id=$1`, fixture.assetID)
}

func collectAssetCatalogProof(t *testing.T, database *pgxpool.Pool) map[string]recoveredTableProof {
	t.Helper()
	tables := []string{
		"asset_sources", "asset_source_revisions", "asset_source_runs", "asset_observations",
		"assets", "asset_type_details", "asset_conflicts", "asset_relationships", "service_asset_bindings",
	}
	proof := make(map[string]recoveredTableProof, len(tables))
	for _, table := range tables {
		query := fmt.Sprintf(`
			SELECT count(*), encode(sha256(convert_to(COALESCE(
				string_agg(to_jsonb(row_value)::text, E'\n' ORDER BY row_value.id), ''
			), 'UTF8')), 'hex')
			FROM %s AS row_value
		`, pgx.Identifier{table}.Sanitize())
		var tableProof recoveredTableProof
		if err := database.QueryRow(context.Background(), query).Scan(&tableProof.count, &tableProof.checksum); err != nil {
			t.Fatalf("collect recovery proof for %s: %v", table, err)
		}
		if tableProof.count == 0 || len(tableProof.checksum) != 64 {
			t.Fatalf("invalid source recovery proof for %s: %+v", table, tableProof)
		}
		proof[table] = tableProof
	}
	return proof
}

func verifyAssetCatalogClosure(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	var brokenReferences int64
	if err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM asset_sources s LEFT JOIN workspaces w
			 ON w.tenant_id=s.tenant_id AND w.id=s.workspace_id WHERE w.id IS NULL) +
			(SELECT count(*) FROM asset_source_revisions r LEFT JOIN asset_sources s
			 ON s.tenant_id=r.tenant_id AND s.workspace_id=r.workspace_id AND s.id=r.source_id WHERE s.id IS NULL) +
			(SELECT count(*) FROM asset_source_runs r LEFT JOIN asset_source_revisions v
			 ON v.tenant_id=r.tenant_id AND v.workspace_id=r.workspace_id AND v.source_id=r.source_id
			 AND v.revision=r.source_revision AND v.canonical_revision_digest=r.source_revision_digest WHERE v.id IS NULL) +
			(SELECT count(*) FROM asset_observations o LEFT JOIN asset_source_runs r
			 ON r.tenant_id=o.tenant_id AND r.workspace_id=o.workspace_id AND r.source_id=o.source_id AND r.id=o.run_id WHERE r.id IS NULL) +
			(SELECT count(*) FROM assets a LEFT JOIN asset_observations o
			 ON o.tenant_id=a.tenant_id AND o.workspace_id=a.workspace_id AND o.source_id=a.source_id AND o.id=a.last_observation_id WHERE o.id IS NULL) +
			(SELECT count(*) FROM asset_type_details d LEFT JOIN assets a
			 ON a.tenant_id=d.tenant_id AND a.workspace_id=d.workspace_id AND a.environment_id=d.environment_id AND a.id=d.asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM asset_conflicts c LEFT JOIN assets a
			 ON a.tenant_id=c.tenant_id AND a.workspace_id=c.workspace_id AND a.environment_id=c.environment_id AND a.id=c.asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM asset_relationships r LEFT JOIN assets a
			 ON a.tenant_id=r.tenant_id AND a.workspace_id=r.workspace_id AND a.environment_id=r.source_environment_id AND a.id=r.source_asset_id WHERE a.id IS NULL) +
			(SELECT count(*) FROM service_asset_bindings b LEFT JOIN services s
			 ON s.tenant_id=b.tenant_id AND s.workspace_id=b.workspace_id AND s.id=b.service_id WHERE s.id IS NULL)
	`).Scan(&brokenReferences); err != nil {
		t.Fatalf("verify restored foreign-key closure: %v", err)
	}
	if brokenReferences != 0 {
		t.Fatalf("restored asset catalog has %d broken parent references", brokenReferences)
	}

	var badHashes int64
	if err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM asset_source_revisions WHERE encode(sha256(canonical_provider_schema),'hex')<>canonical_provider_schema_sha256) +
			(SELECT count(*) FROM asset_observations WHERE encode(sha256(normalized_document),'hex')<>document_sha256
			 OR encode(sha256(field_provenance),'hex')<>field_provenance_sha256) +
			(SELECT count(*) FROM asset_type_details WHERE encode(sha256(details_document),'hex')<>details_sha256) +
			(SELECT count(*) FROM asset_sources WHERE checkpoint_ciphertext IS NOT NULL
			 AND encode(sha256(checkpoint_ciphertext),'hex')<>checkpoint_sha256)
	`).Scan(&badHashes); err != nil {
		t.Fatalf("verify restored SHA-256 equality: %v", err)
	}
	if badHashes != 0 {
		t.Fatalf("restored asset catalog has %d invalid content hashes", badHashes)
	}

	var revision int64
	var revisionDigest, revisionState, gateStatus, lifecycle string
	var assetVersion int64
	if err := database.QueryRow(context.Background(), `
		SELECT s.published_revision,s.published_revision_digest,r.state,s.gate_status,
			a.lifecycle,a.version
		FROM asset_sources s
		JOIN asset_source_revisions r ON r.tenant_id=s.tenant_id AND r.workspace_id=s.workspace_id
		 AND r.source_id=s.id AND r.revision=s.published_revision
		JOIN assets a ON a.id=$2
		WHERE s.id=$1
	`, fixture.sourceID, fixture.assetID).Scan(
		&revision, &revisionDigest, &revisionState, &gateStatus, &lifecycle, &assetVersion,
	); err != nil {
		t.Fatalf("verify restored source pointer and asset lifecycle: %v", err)
	}
	if revision != 1 || revisionDigest != fixture.revisionDigest || revisionState != "PUBLISHED" ||
		gateStatus != "AVAILABLE" || lifecycle != "ACTIVE" || assetVersion != 2 {
		t.Fatalf("restored pointer/lifecycle=(%d,%s,%s,%s,%s,%d)",
			revision, revisionDigest, revisionState, gateStatus, lifecycle, assetVersion)
	}
}

func logicalDumpDatabase(t *testing.T, databaseName string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx,
		"docker", "--context", "colima-aiops", "exec", "aiops-postgres18",
		"pg_dump", "--format=custom", "--no-owner", "--no-acl", "-U", "aiops", "-d", databaseName,
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	backup, err := command.Output()
	if err != nil {
		t.Fatalf("pg_dump sanitized recovery database: %v: %s", err, sanitizeToolOutput(stderr.Bytes()))
	}
	return backup
}

func restoreLogicalDump(t *testing.T, databaseName string, backup []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx,
		"docker", "--context", "colima-aiops", "exec", "-i", "aiops-postgres18",
		"pg_restore", "--exit-on-error", "--no-owner", "--no-acl", "-U", "aiops", "-d", databaseName,
	)
	command.Stdin = bytes.NewReader(backup)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("pg_restore sanitized recovery database: %v: %s", err, sanitizeToolOutput(stderr.Bytes()))
	}
}

func sanitizeToolOutput(output []byte) string {
	value := strings.TrimSpace(string(output))
	if len(value) > 1024 {
		return value[:1024] + "..."
	}
	return value
}
