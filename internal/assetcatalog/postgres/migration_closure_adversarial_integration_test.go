package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestQualificationFixtureExactPersistentABI(t *testing.T) {
	wantSourceColumns := []string{
		"gate_evidence_run_id",
		"gate_evidence_digest",
		"gate_evidence_expires_at",
	}
	wantRunColumns := []string{
		"qualification_evidence_kind",
		"qualification_scope_digest",
		"qualification_binding_digest",
		"qualification_profile_descriptor_digest",
		"qualification_runtime_manifest_digest",
		"qualification_lab_binding_digest",
		"qualification_prior_receipts_digest",
		"qualification_result_digest",
		"qualification_receipt_issued_at",
		"qualification_receipt_expires_at",
		"qualification_signing_key_id",
		"qualification_signature",
		"qualification_receipt_digest",
		"ha_owner_worker_identity_digest",
		"ha_takeover_worker_identity_digest",
		"ha_owner_process_instance_digest",
		"ha_takeover_process_instance_digest",
		"ha_takeover_receipt_digest",
		"ha_restart_receipt_digest",
		"ha_session_recovery_receipt_digest",
		"ha_cleanup_receipt_digest",
		"ha_response_loss_receipt_digest",
		"ha_fact_chain_digest",
	}
	if got, want := strings.Join(qualificationFixtureSourceColumns, "\n"),
		strings.Join(wantSourceColumns, "\n"); got != want {
		t.Fatalf("qualification Source columns:\n%s\nwant exact:\n%s", got, want)
	}
	if got, want := strings.Join(qualificationFixtureRunColumns, "\n"),
		strings.Join(wantRunColumns, "\n"); got != want {
		t.Fatalf("qualification Run columns:\n%s\nwant exact:\n%s", got, want)
	}
	wantSourceTypes := []string{"uuid", "text", "timestamp with time zone"}
	if got, want := strings.Join(qualificationFixtureSourceColumnTypes, "\n"),
		strings.Join(wantSourceTypes, "\n"); got != want {
		t.Fatalf("qualification Source column types:\n%s\nwant exact:\n%s", got, want)
	}
	wantRunTypes := make([]string, len(wantRunColumns))
	for index := range wantRunTypes {
		wantRunTypes[index] = "text"
	}
	wantRunTypes[8] = "timestamp with time zone"
	wantRunTypes[9] = "timestamp with time zone"
	if got, want := strings.Join(qualificationFixtureRunColumnTypes, "\n"),
		strings.Join(wantRunTypes, "\n"); got != want {
		t.Fatalf("qualification Run column types:\n%s\nwant exact:\n%s", got, want)
	}
}

func TestAssetCatalogQualificationFixtureSchemaContract(t *testing.T) {
	t.Run("old schema no-op or full exact fixture", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		state, err := qualificationFixtureSchemaStateFor(context.Background(), harness.db)
		if err != nil {
			t.Fatalf("inspect qualification fixture schema: %v", err)
		}
		fixture := seedDraftAssetCatalog(t, harness.db)
		fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
		finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))

		if state == qualificationFixtureSchemaOld {
			var total int
			if err := harness.db.QueryRow(context.Background(), `
				SELECT count(*) FROM asset_source_runs
				WHERE source_id=$1 AND run_kind='QUALIFICATION'
			`, fixture.sourceID).Scan(&total); err != nil {
				t.Fatalf("count old-schema qualification runs: %v", err)
			}
			if total != 0 {
				t.Fatalf("old schema qualification fixture wrote %d runs, want exact no-op", total)
			}
			return
		}

		var total, ha, canary int
		if err := harness.db.QueryRow(context.Background(), `
			SELECT count(*),
				count(*) FILTER (WHERE qualification_evidence_kind='TWO_WORKER_HA'),
				count(*) FILTER (WHERE qualification_evidence_kind='PROVIDER_CANARY')
			FROM asset_source_runs
			WHERE source_id=$1 AND run_kind='QUALIFICATION' AND
				status='SUCCEEDED' AND stage_code='COMPLETED'
		`, fixture.sourceID).Scan(&total, &ha, &canary); err != nil {
			t.Fatalf("count full-schema qualification fixture runs: %v", err)
		}
		if total != 2 || ha != 1 || canary != 1 {
			t.Fatalf(
				"full schema qualification fixtures=(total:%d HA:%d canary:%d), want (2,1,1)",
				total,
				ha,
				canary,
			)
		}
	})

	t.Run("partial schema fails closed", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		state, err := qualificationFixtureSchemaStateFor(context.Background(), harness.db)
		if err != nil {
			t.Fatalf("read qualification schema before partial mutation: %v", err)
		}
		if state == qualificationFixtureSchemaOld {
			execAssetSQL(t, harness.db, `
				ALTER TABLE asset_sources ADD COLUMN gate_evidence_run_id uuid
			`)
		} else {
			execAssetSQL(t, harness.db, `
				ALTER TABLE asset_sources DROP COLUMN gate_evidence_run_id CASCADE
			`)
		}

		if _, err = qualificationFixtureSchemaStateFor(
			context.Background(), harness.db,
		); err == nil || !strings.Contains(err.Error(), "partial qualification fixture schema") {
			t.Fatalf("partial qualification fixture schema error=%v, want fail-closed classification", err)
		}
	})

	for _, shape := range []struct {
		name       string
		definition string
	}{
		{name: "wrong marker type", definition: "text"},
		{name: "wrong marker nullability", definition: "uuid NOT NULL"},
	} {
		t.Run(shape.name+" fails closed", func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			state, err := qualificationFixtureSchemaStateFor(context.Background(), harness.db)
			if err != nil {
				t.Fatalf("read qualification schema before marker-shape mutation: %v", err)
			}
			if state == qualificationFixtureSchemaFull {
				return
			}
			execAssetSQL(t, harness.db, fmt.Sprintf(`
				ALTER TABLE asset_sources
					ADD COLUMN gate_evidence_run_id %s
			`, shape.definition))
			if _, err := qualificationFixtureSchemaStateFor(
				context.Background(), harness.db,
			); err == nil || !strings.Contains(err.Error(), "partial qualification fixture schema") {
				t.Fatalf("%s error=%v, want fail-closed classification", shape.name, err)
			}
		})
	}

	t.Run("unknown marker fails closed", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		execAssetSQL(t, harness.db, `
			ALTER TABLE asset_source_runs ADD COLUMN qualification_unknown_digest text
		`)

		if _, err := qualificationFixtureSchemaStateFor(
			context.Background(), harness.db,
		); err == nil || !strings.Contains(err.Error(), "partial qualification fixture schema") {
			t.Fatalf("unknown qualification fixture marker error=%v, want fail-closed classification", err)
		}
	})

	vocabularyReplacements := []struct {
		name    string
		oldSQL  string
		fullSQL string
	}{
		{
			name: "run kind",
			oldSQL: `
				ALTER TABLE asset_source_runs
					DROP CONSTRAINT asset_source_runs_run_kind_check;
				ALTER TABLE asset_source_runs
					ADD CONSTRAINT asset_source_runs_run_kind_check CHECK (run_kind IN (
						'VALIDATION','DISCOVERY','CSV_IMPORT','API_INGESTION','UNKNOWN_DATA'
					));
			`,
			fullSQL: `
				ALTER TABLE asset_source_runs
					DROP CONSTRAINT asset_source_runs_run_kind_check;
				ALTER TABLE asset_source_runs
					ADD CONSTRAINT asset_source_runs_run_kind_check CHECK (run_kind IN (
						'VALIDATION','DISCOVERY','CSV_IMPORT','API_INGESTION',
						'QUALIFICATION','UNKNOWN_DATA'
					));
			`,
		},
		{
			name: "work result kind",
			oldSQL: `
				ALTER TABLE asset_source_runs
					DROP CONSTRAINT asset_source_runs_work_result_kind_check;
				ALTER TABLE asset_source_runs
					ADD CONSTRAINT asset_source_runs_work_result_kind_check CHECK (
						work_result_kind IS NULL OR work_result_kind IN (
							'DATA_PROJECTION','VALIDATION_PROOF','UNKNOWN_PROOF'
						)
					);
			`,
			fullSQL: `
				ALTER TABLE asset_source_runs
					DROP CONSTRAINT asset_source_runs_work_result_kind_check;
				ALTER TABLE asset_source_runs
					ADD CONSTRAINT asset_source_runs_work_result_kind_check CHECK (
						work_result_kind IS NULL OR work_result_kind IN (
							'DATA_PROJECTION','VALIDATION_PROOF',
							'QUALIFICATION_PROOF','UNKNOWN_PROOF'
						)
					);
			`,
		},
	}
	for _, replacement := range vocabularyReplacements {
		t.Run("same-count "+replacement.name+" replacement fails closed", func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			state, err := qualificationFixtureSchemaStateFor(context.Background(), harness.db)
			if err != nil {
				t.Fatalf("read qualification schema before vocabulary replacement: %v", err)
			}
			statement := replacement.oldSQL
			if state == qualificationFixtureSchemaFull {
				statement = replacement.fullSQL
			}
			execAssetSQL(t, harness.db, statement)

			if _, err = qualificationFixtureSchemaStateFor(
				context.Background(), harness.db,
			); err == nil || !strings.Contains(err.Error(), "partial qualification fixture schema") {
				t.Fatalf(
					"same-count %s replacement error=%v, want fail-closed classification",
					replacement.name,
					err,
				)
			}
		})
	}

	t.Run("not-valid closure fails closed", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		execAssetSQL(t, harness.db, `
			ALTER TABLE asset_source_runs
				ADD CONSTRAINT qualification_fixture_not_valid_ck CHECK (true) NOT VALID
		`)

		if _, err := qualificationFixtureSchemaStateFor(
			context.Background(), harness.db,
		); err == nil || !strings.Contains(err.Error(), "partial qualification fixture schema") {
			t.Fatalf("not-valid qualification fixture closure error=%v, want fail-closed classification", err)
		}
	})
}

func TestAssetCatalogFutureSourceHookPersistentContractMatrix(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	base := seedDraftAssetCatalog(t, harness.db)
	defaultDefinitionDigest := futureHookDefinitionDigest(t, harness.migration)
	t.Cleanup(func() {
		futureHookReplace(t, harness.migration, futureHookModeDefaultFalse)
		if restored := futureHookDefinitionDigest(t, harness.migration); restored != defaultDefinitionDigest {
			t.Errorf("future Source hook definition digest after cleanup=%s, want default %s",
				restored, defaultDefinitionDigest)
		}
	})

	if !t.Run("default false rejects serializable initial closures without residue", func(t *testing.T) {
		for _, definition := range futureHookNewDefinitionPair(t, harness.db, base, "default-false") {
			expectClosureCommitError(t, harness.application, pgx.Serializable, "23514",
				"asset_sources_future_phase_gate_guard", func(tx pgx.Tx) error {
					return futureHookInsertInitial(tx, definition)
				})
			futureHookAssertNoResidue(t, harness.application, definition.fixture.sourceID)
		}
	}) {
		t.FailNow()
	}

	if !t.Run("NULL hook rejects serializable initial closures without residue", func(t *testing.T) {
		futureHookReplace(t, harness.migration, futureHookModeNull)
		for _, definition := range futureHookNewDefinitionPair(t, harness.db, base, "null-initial") {
			expectClosureCommitError(t, harness.application, pgx.Serializable, "23514",
				"asset_sources_future_phase_gate_guard", func(tx pgx.Tx) error {
					return futureHookInsertInitial(tx, definition)
				})
			futureHookAssertNoResidue(t, harness.application, definition.fixture.sourceID)
		}
	}) {
		t.FailNow()
	}

	if !t.Run("initial-only successor admits exact version two DRAFT closure", func(t *testing.T) {
		futureHookReplace(t, harness.migration, futureHookModeInitialOnly)
		for _, definition := range futureHookNewDefinitionPair(t, harness.db, base, "initial-only") {
			futureHookCreateInitial(t, harness.application, definition)
			futureHookAssertInitial(t, harness.application, definition)
		}
	}) {
		t.FailNow()
	}

	if !t.Run("read committed initial closure is rejected for both future kinds", func(t *testing.T) {
		for _, definition := range futureHookNewDefinitionPair(t, harness.db, base, "read-committed") {
			expectClosureCommitError(t, harness.application, pgx.ReadCommitted, "55000",
				"asset_sources_initial_revision_closure_guard", func(tx pgx.Tx) error {
					return futureHookInsertInitial(tx, definition)
				})
			futureHookAssertNoResidue(t, harness.application, definition.fixture.sourceID)
		}
	}) {
		t.FailNow()
	}

	if !t.Run("same transaction creation and legal validation binding rolls back", func(t *testing.T) {
		futureHookReplace(t, harness.migration, futureHookModeTrue)
		for _, definition := range futureHookNewDefinitionPair(t, harness.db, base, "same-tx-live") {
			expectClosureCommitError(t, harness.application, pgx.Serializable, "55000",
				"asset_sources_initial_revision_closure_guard", func(tx pgx.Tx) error {
					if err := futureHookInsertInitial(tx, definition); err != nil {
						return err
					}
					return futureHookBindValidation(tx, definition)
				})
			futureHookAssertNoResidue(t, harness.application, definition.fixture.sourceID)
		}
		futureHookReplace(t, harness.migration, futureHookModeInitialOnly)
	}) {
		t.FailNow()
	}

	var liveTrue, liveFalse, liveNull []futureHookDefinition
	var cleanupBomb, cleanupFalse, cleanupNull []futureHookDefinition
	if !t.Run("prepare independent persisted initial closures for later transactions", func(t *testing.T) {
		liveTrue = futureHookNewDefinitionPair(t, harness.db, base, "live-true")
		liveFalse = futureHookNewDefinitionPair(t, harness.db, base, "live-false")
		liveNull = futureHookNewDefinitionPair(t, harness.db, base, "live-null")
		cleanupBomb = futureHookNewDefinitionPair(t, harness.db, base, "cleanup-bomb")
		cleanupFalse = futureHookNewDefinitionPair(t, harness.db, base, "cleanup-false")
		cleanupNull = futureHookNewDefinitionPair(t, harness.db, base, "cleanup-null")
		for _, definitions := range [][]futureHookDefinition{
			liveTrue, liveFalse, liveNull, cleanupBomb, cleanupFalse, cleanupNull,
		} {
			for _, definition := range definitions {
				futureHookCreateInitial(t, harness.application, definition)
				futureHookAssertInitial(t, harness.application, definition)
			}
		}
	}) {
		t.FailNow()
	}

	if !t.Run("new serializable transaction reaches VALIDATING only under true hook", func(t *testing.T) {
		futureHookReplace(t, harness.migration, futureHookModeTrue)
		for _, definition := range liveTrue {
			futureHookStartValidation(t, harness.application, definition)
			futureHookAssertValidating(t, harness.application, definition)
		}
		for _, definitions := range [][]futureHookDefinition{cleanupBomb, cleanupFalse, cleanupNull} {
			for _, definition := range definitions {
				futureHookStartValidation(t, harness.application, definition)
				futureHookOpenAvailable(t, harness.application, definition)
			}
		}
	}) {
		t.FailNow()
	}

	if !t.Run("false hook rejects later VALIDATING and permits read committed fail-close", func(t *testing.T) {
		futureHookReplace(t, harness.migration, futureHookModeDefaultFalse)
		for _, definition := range liveFalse {
			expectClosureCommitError(t, harness.application, pgx.Serializable, "23514",
				"asset_sources_future_phase_gate_guard", func(tx pgx.Tx) error {
					return futureHookBindValidation(tx, definition)
				})
			futureHookAssertInitial(t, harness.application, definition)
		}
		for _, definition := range cleanupFalse {
			futureHookPauseAvailableReadCommitted(t, harness.application, definition)
		}
	}) {
		t.FailNow()
	}

	if !t.Run("NULL hook rejects later VALIDATING and permits read committed fail-close", func(t *testing.T) {
		futureHookReplace(t, harness.migration, futureHookModeNull)
		for _, definition := range liveNull {
			expectClosureCommitError(t, harness.application, pgx.Serializable, "23514",
				"asset_sources_future_phase_gate_guard", func(tx pgx.Tx) error {
					return futureHookBindValidation(tx, definition)
				})
			futureHookAssertInitial(t, harness.application, definition)
		}
		for _, definition := range cleanupNull {
			futureHookPauseAvailableReadCommitted(t, harness.application, definition)
		}
	}) {
		t.FailNow()
	}

	if !t.Run("bomb hook is not called by cleanup-uncertain suspension or read committed fail-close", func(t *testing.T) {
		for _, definition := range cleanupBomb {
			futureHookStartDiscoveryFailure(t, harness.application, definition)
		}
		futureHookReplace(t, harness.migration, futureHookModeBomb)
		for _, definition := range cleanupBomb {
			futureHookSuspendCleanupUncertain(t, harness.application, definition)
			futureHookCloseSuspendedReadCommitted(t, harness.application, definition)
		}
	}) {
		t.FailNow()
	}

	futureHookReplace(t, harness.migration, futureHookModeDefaultFalse)
	if restored := futureHookDefinitionDigest(t, harness.migration); restored != defaultDefinitionDigest {
		t.Fatalf("restored future Source hook definition digest=%s, want default %s",
			restored, defaultDefinitionDigest)
	}
}

func TestAssetCatalogValidationCleanupUncertainRequiresSourceSuspension(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	prepareCleanupUncertainValidationRun(t, harness.db, fixture)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_uncertain_closure_guard", func(tx pgx.Tx) error {
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, fixture.validationRunID, 1, cleanupDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, cleanupDigest); err != nil {
				return err
			}
			var overrideDigest string
			if err := tx.QueryRow(context.Background(), `
				SELECT asset_catalog_source_run_failure_override_digest(run,'CLEANUP_UNCERTAIN')
				FROM asset_source_runs AS run WHERE id=$1
			`, fixture.validationRunID).Scan(&overrideDigest); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET failure_code='CLEANUP_UNCERTAIN',
					terminal_failure_override='CLEANUP_UNCERTAIN',
					terminal_failure_override_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, overrideDigest); err != nil {
				return err
			}
			terminalDigest := sourceRunTerminalDigest(
				t, tx, fixture.validationRunID, "FAILED", "CLEANUP_UNCERTAIN",
			)
			insertTerminalAudit(t, tx, fixture, fixture.validationRunID, terminalDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
					version=version+1
				WHERE id=$1
			`, fixture.validationRunID, terminalDigest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_revisions
				SET state='REJECTED',validation_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.revisionID, overrideDigest)
			return err
		})
}

func TestAssetCatalogTerminalDataRunRejectsSourceGateDrift(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	finalizeClosureEmptyManualPage(t, harness.db, fixture, run)
	execAssetSQL(t, harness.db, `
		UPDATE asset_sources
		SET gate_status='UNAVAILABLE',gate_reason_code='CLOSURE_DRIFT',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_source_closure_guard", func(tx pgx.Tx) error {
			return closeClosureManualRun(t, tx, fixture, run.id)
		})
}

func TestAssetCatalogRunPageRejectsSourceAdmissionLostBeforeCommit(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_page_closure_guard", func(tx pgx.Tx) error {
			pageDigest := strings.Repeat("c", 64)
			if err := insertClosurePageReceipt(tx, fixture, run.id, 1, pageDigest); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				WITH envelope AS (
					SELECT decode('01'||repeat('09',12)||repeat('0a',16),'hex') AS ciphertext
				)
				UPDATE asset_sources AS source
				SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-page-key',
					checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
					checkpoint_version=source.checkpoint_version+1,version=source.version+1
				FROM envelope WHERE source.id=$1
			`, fixture.sourceID); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET stage_code='APPLYING',page_sequence=page_sequence+1,page_digest=$2,
					checkpoint_version=checkpoint_version+1,
					cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
					heartbeat_sequence=heartbeat_sequence+1,
					heartbeat_at=statement_timestamp(),
					lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
				WHERE id=$1
			`, run.id, pageDigest, fixture.sourceID); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
			`, fixture.sourceID)
			return err
		})
}

func TestAssetCatalogOwnedFunctionsUseCatalogFirstSearchPath(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	var total int
	var unsafeFunctions string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*)::integer,
			COALESCE(string_agg(p.oid::regprocedure::text, ',' ORDER BY p.oid::regprocedure::text)
				FILTER (WHERE p.proconfig IS DISTINCT FROM
					ARRAY['search_path=pg_catalog, public, pg_temp']::text[]), '')
		FROM pg_catalog.pg_proc AS p
		JOIN pg_catalog.pg_namespace AS n ON n.oid=p.pronamespace
		WHERE n.nspname='public' AND (
			p.proname LIKE 'asset_catalog_%' OR
			p.proname LIKE 'enforce_asset_%' OR
			p.proname LIKE 'validate_asset_%' OR
			p.proname LIKE 'reject_asset_catalog_%'
		)
	`).Scan(&total, &unsafeFunctions); err != nil {
		t.Fatalf("read 000015 function search paths: %v", err)
	}
	if total != 36 {
		t.Fatalf("000015 owned function count=%d, want 36", total)
	}
	if unsafeFunctions != "" {
		t.Fatalf("000015 functions without fixed catalog-first search_path: %s", unsafeFunctions)
	}
}

func TestAssetCatalogClockShadowCannotExpireLiveRun(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)

	connection, err := pgx.ConnectConfig(context.Background(), harness.db.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatalf("connect fresh hostile-search-path session: %v", err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	if _, err := connection.Exec(context.Background(), `
		CREATE FUNCTION public.clock_timestamp() RETURNS timestamptz
		LANGUAGE sql VOLATILE
		AS $$ SELECT pg_catalog.clock_timestamp()+interval '100 years' $$
	`); err != nil {
		t.Fatalf("create hostile public.clock_timestamp(): %v", err)
	}
	if _, err := connection.Exec(context.Background(), `
		UPDATE asset_source_runs SET stage_code='APPLYING',version=version+1 WHERE id=$1
	`, run.id); err != nil {
		t.Fatalf("catalog-first trigger rejected a live legal stage mutation: %v", err)
	}
}

func TestAssetCatalogRunningCleanupUncertainCannotCommitWithoutClosure(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	reserveClosureCleanupAttempt(t, harness.db, run.id)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_uncertain_closure_guard", func(tx pgx.Tx) error {
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
					work_result_status='FAILED',work_result_digest=repeat('b',64),
					work_result_recorded_at=statement_timestamp(),
					cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, run.id, cleanupDigest)
			return err
		})
}

func TestAssetCatalogCleanupProofRequiresCleanupStageAndSealedNextPath(t *testing.T) {
	t.Run("proof outside cleanup stage", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		execAssetSQL(t, harness.db, `
			UPDATE asset_source_runs
			SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
				cleanup_attempt_epoch=fence_epoch,version=version+1 WHERE id=$1
		`, run.id)

		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
				cleanupDigest := strings.Repeat("a", 64)
				insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
					WHERE id=$1
				`, run.id, cleanupDigest)
				return err
			})
	})

	t.Run("proof without sealed next path", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		reserveClosureCleanupAttempt(t, harness.db, run.id)

		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
				cleanupDigest := strings.Repeat("a", 64)
				insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
					WHERE id=$1
				`, run.id, cleanupDigest)
				return err
			})
	})
}

func TestAssetCatalogConsumedCleanupCannotHeartbeat(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	reserveClosureCleanupAttempt(t, harness.db, run.id)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), closureExactDelayIntentSQL,
				run.id, "30 seconds"); err != nil {
				return err
			}
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, run.id, cleanupDigest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET heartbeat_sequence=heartbeat_sequence+1,
					heartbeat_at=statement_timestamp(),
					lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogDelayIntentAndCleanupCoordinatesAreAtomic(t *testing.T) {
	t.Run("intent sealed before attempt cannot survive reserve", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationRun(t, harness.db)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_pending_transition_guard", closureExactDelayIntentSQL,
			runID, "30 seconds")
	})

	t.Run("cleanup proof cannot precede delay intent", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		reserveClosureCleanupAttempt(t, harness.db, run.id)
		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
				cleanupDigest := strings.Repeat("a", 64)
				insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
				if _, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs SET cleanup_status='REVOKED',cleanup_digest=$2,
						version=version+1 WHERE id=$1
				`, run.id, cleanupDigest); err != nil {
					return err
				}
				_, err := tx.Exec(context.Background(), closureExactDelayIntentSQL,
					run.id, "30 seconds")
				return err
			})
	})

	t.Run("pending delay excludes failure finalization", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		reserveClosureCleanupAttempt(t, harness.db, run.id)
		execAssetSQL(t, harness.db, closureExactDelayIntentSQL, run.id, "30 seconds")
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_finalization_guard", `
			UPDATE asset_source_runs
			SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
				work_result_status='FAILED',work_result_digest=repeat('f',64),
				work_result_recorded_at=statement_timestamp(),version=version+1
			WHERE id=$1
		`, run.id)
	})
}

func TestAssetCatalogExternalValidationCanAtomicallyAbandonDelayForCleanupUncertain(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	runID := seedClosureExternalValidationRun(t, harness.db)
	fixture := newAssetCatalogFixture()
	fixture.sourceID = closureExternalSourceID
	fixture.revisionID = closureExternalRevisionID
	fixture.validationRunID = runID
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id='8d000000-0000-4000-8000-000000000004',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, runID)
	execAssetSQL(t, harness.db, closureExactDelayIntentSQL, runID, "30 seconds")

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin cleanup-uncertain delay abandonment: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	cleanupDigest := strings.Repeat("a", 64)
	insertCleanupAudit(t, tx, fixture, runID, 1, cleanupDigest)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='FINALIZING',pending_transition=NULL,pending_transition_reason=NULL,
			pending_transition_not_before=NULL,pending_transition_digest=NULL,
			work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=repeat('b',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
		WHERE id=$1
	`, runID, cleanupDigest); err != nil {
		t.Fatalf("atomically abandon delay into uncertain failure intent: %v", err)
	}
	var overrideDigest string
	if err := tx.QueryRow(context.Background(), `
		SELECT asset_catalog_source_run_failure_override_digest(run,'CLEANUP_UNCERTAIN')
		FROM asset_source_runs AS run WHERE id=$1
	`, runID).Scan(&overrideDigest); err != nil {
		t.Fatalf("derive cleanup-uncertain override: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET failure_code='CLEANUP_UNCERTAIN',terminal_failure_override='CLEANUP_UNCERTAIN',
			terminal_failure_override_digest=$2,version=version+1 WHERE id=$1
	`, runID, overrideDigest); err != nil {
		t.Fatalf("seal cleanup-uncertain override: %v", err)
	}
	terminalDigest := sourceRunTerminalDigest(t, tx, runID, "FAILED", "CLEANUP_UNCERTAIN")
	insertTerminalAudit(t, tx, fixture, runID, terminalDigest)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, runID, terminalDigest); err != nil {
		t.Fatalf("fail cleanup-uncertain validation: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET gate_status='SUSPENDED',gate_reason_code='CLEANUP_UNCERTAIN',
			gate_revision=gate_revision+1,version=version+1 WHERE id=$1
	`, fixture.sourceID); err != nil {
		t.Fatalf("suspend cleanup-uncertain source: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_revisions
		SET state='REJECTED',validation_digest=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, overrideDigest); err != nil {
		t.Fatalf("reject cleanup-uncertain revision: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit cleanup-uncertain delay abandonment: %v", err)
	}
}

func TestAssetCatalogManualProfileIsClosed(t *testing.T) {
	t.Run("manual source requires MANUAL_V1 provider", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		expectClosureStatementError(t, harness.db, "23514", "asset_sources_manual_provider_guard", `
			INSERT INTO asset_sources (
				id,tenant_id,workspace_id,source_kind,provider_kind,name,
				create_idempotency_key,create_request_hash
			) VALUES (
				'8e000000-0000-4000-8000-000000000001',$1,$2,'MANUAL','EXTERNAL_V1',
				'invalid manual source','invalid-manual-source',repeat('1',64)
			)
		`, fixture.tenantID, fixture.workspaceID)
	})

	t.Run("non-manual source rejects MANUAL_V1 provider", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		expectClosureStatementError(t, harness.db, "23514", "asset_sources_manual_provider_guard", `
			INSERT INTO asset_sources (
				id,tenant_id,workspace_id,source_kind,provider_kind,name,
				create_idempotency_key,create_request_hash
			) VALUES (
				'8e000000-0000-4000-8000-000000000002',$1,$2,'EXTERNAL_CMDB','MANUAL_V1',
				'invalid external source','invalid-external-source',repeat('2',64)
			)
		`, fixture.tenantID, fixture.workspaceID)
	})

	for _, reference := range []string{
		"credential_reference_id", "trust_reference_id", "network_policy_reference_id",
	} {
		t.Run("manual revision rejects "+reference, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedDraftAssetCatalog(t, harness.db)
			insertClosureManualRevisionExpectingError(t, harness.db, fixture,
				"MANUAL_V1", reference, "asset_source_revisions_manual_profile_guard")
		})
	}

	t.Run("manual revision requires MANUAL_V1 profile", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		insertClosureManualRevisionExpectingError(t, harness.db, fixture,
			"EXTERNAL_V1", "", "asset_source_revisions_manual_profile_guard")
	})
}

func TestAssetCatalogManualValidationRejectsCredentialCleanupAttempt(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			startClosureManualValidationRunInTx(t, tx, fixture)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET stage_code='CLEANING_UP',cleanup_status='PENDING',
					cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
					version=version+1
				WHERE id=$1
			`, fixture.validationRunID)
			return err
		})
}

func TestAssetCatalogManualQueuedRunCannotCommit(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_manual_atomic_guard", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `
				INSERT INTO asset_source_runs (
					id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
					run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
				) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
					'manual-queued-atomic-red',repeat('1',64),0
				FROM asset_sources WHERE id=$4
			`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID,
				fixture.sourceID, fixture.revisionDigest)
			return err
		})
}

func TestAssetCatalogManualMutationRejectsCredentialCleanupAttempt(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET stage_code='CLEANING_UP',cleanup_status='PENDING',
					cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
					version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogManualRevokedCleanupCannotBeTerminallySealed(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	run := seedForgedLegacyManualFinalizingRun(t, harness.db, fixture)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_mutation_guard`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(context.Background(),
			`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	})
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',
			cleanup_attempt_id='8f700000-0000-4000-8000-000000000001',
			cleanup_attempt_epoch=fence_epoch,cleanup_digest=repeat('e',64)
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			return closeClosureManualRun(t, tx, fixture, run.id)
		})
}

func TestAssetCatalogManualRunRejectsLineageRollover(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_manual_rollover_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			if _, err := tx.Exec(context.Background(), `
				INSERT INTO audit_records (
					id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
					resource_id,request_id,trace_id,payload_hash
				) VALUES (
					gen_random_uuid(),$1,$2,'SYSTEM','runtime-manual-executor',
					'CHECKPOINT_LINEAGE_ROLLOVER_BOUND','ASSET_SOURCE_RUN',$3,
					'source-rollover:'||$3,'manual-rollover-trace',repeat('b',64)
				)
			`, fixture.tenantID, fixture.workspaceID, run.id); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_sources
				SET gate_status='DEGRADED',gate_reason_code='CHECKPOINT_LINEAGE_ROLLOVER',
					gate_revision=gate_revision+1,version=version+1
				WHERE id=$1
			`, fixture.sourceID); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET lineage_rollover_reason='PROVIDER_CURSOR_EXPIRED',
					lineage_rollover_evidence_digest=repeat('b',64),version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogFailedRolloverRejectsNullSuspensionReason(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startClosureExternalDiscoveryRun(t, harness.db, fixture)
	bindClosureExternalRollover(t, harness.db, fixture, run)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
			version=version+1
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
			work_result_status='FAILED',work_result_digest=repeat('c',64),
			version=version+1
		WHERE id=$1
	`, run.id)
	revokeClosureAttempt(t, harness.db, fixture, run.id, strings.Repeat("d", 64))

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_rollover_closure_guard", func(tx pgx.Tx) error {
			terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "FAILED", "ROLLOVER_FAILED")
			insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',failure_code='ROLLOVER_FAILED',
					terminal_command_sha256=$2,version=version+1
				WHERE id=$1
			`, run.id, terminalDigest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_sources
				SET gate_status='SUSPENDED',gate_reason_code=NULL,
					gate_revision=gate_revision+1,version=version+1
				WHERE id=$1
			`, fixture.sourceID)
			return err
		})
}

func TestAssetCatalogRunKindMatchesManualProfile(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	for _, runKind := range []string{"DISCOVERY", "CSV_IMPORT", "API_INGESTION"} {
		t.Run("manual rejects "+runKind, func(t *testing.T) {
			expectClosureStatementError(t, harness.db, "23514",
				"asset_source_runs_manual_profile_guard", `
				INSERT INTO asset_source_runs (
					id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
					run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
					checkpoint_version,cursor_before_sha256
				) SELECT '8f200000-0000-4000-8000-000000000001',$1,$2,$3,
					published_revision,published_revision_digest,$4,'HUMAN',gate_revision,
					'manual-forbidden-run',repeat('1',64),checkpoint_version,checkpoint_sha256
				FROM asset_sources WHERE id=$3
			`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, runKind)
		})
	}

	t.Run("non-manual rejects MANUAL_MUTATION", func(t *testing.T) {
		externalHarness := newAssetCatalogHarness(t)
		externalHarness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationRun(t, externalHarness.db)
		expectClosureStatementError(t, externalHarness.db, "23514",
			"asset_source_runs_manual_profile_guard", `
			INSERT INTO asset_source_runs (
				id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
				run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
			) SELECT '8f200000-0000-4000-8000-000000000002',tenant_id,workspace_id,
				source_id,source_revision,source_revision_digest,'MANUAL_MUTATION','HUMAN',
				gate_revision,'external-forbidden-manual-run',repeat('2',64),0
			FROM asset_source_runs WHERE id=$1
		`, runID)
	})
}

func TestAssetCatalogCleanupUncertainOverrideIsWriteOnce(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	prepareCleanupUncertainValidationRun(t, harness.db, fixture)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_terminal_transition_guard", func(tx pgx.Tx) error {
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, fixture.validationRunID, 1, cleanupDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, cleanupDigest); err != nil {
				return err
			}
			var digest string
			if err := tx.QueryRow(context.Background(), `
				SELECT asset_catalog_source_run_failure_override_digest(run,'CLEANUP_UNCERTAIN')
				FROM asset_source_runs AS run WHERE id=$1
			`, fixture.validationRunID).Scan(&digest); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET failure_code='CLEANUP_UNCERTAIN',
					terminal_failure_override='CLEANUP_UNCERTAIN',
					terminal_failure_override_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, digest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET failure_code='REWRITTEN_FAILURE',terminal_failure_override_digest=repeat('f',64),
					version=version+1 WHERE id=$1
			`, fixture.validationRunID)
			return err
		})
}

func TestAssetCatalogFailedTerminalCannotExploitNullOverride(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	finalizeClosureEmptyManualPage(t, harness.db, fixture, run)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_terminal_transition_guard", func(tx pgx.Tx) error {
			terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "FAILED", "FORGED_FAILED")
			insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',failure_code='FORGED_FAILED',
					terminal_command_sha256=$2,version=version+1
				WHERE id=$1
			`, run.id, terminalDigest)
			return err
		})
}

func TestAssetCatalogSuccessPointerCannotBeClearedOutsidePublication(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectClosureStatementError(t, harness.db, "55000", "asset_sources_last_success_guard", `
		UPDATE asset_sources
		SET last_success_run_id=NULL,last_success_at=NULL,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
}

func TestAssetCatalogCompleteSnapshotPointerCannotBeClearedOutsidePublication(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	expectClosureStatementError(t, harness.db, "55000",
		"asset_sources_last_complete_snapshot_guard", `
		UPDATE asset_sources
		SET last_complete_snapshot_run_id=NULL,last_complete_snapshot_at=NULL,
			version=version+1
		WHERE id=$1
	`, fixture.sourceID)
}

func TestAssetCatalogSupersededCompleteRunCannotBeReattachedAfterPublication(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	oldCompleteRunID := fixture.runID
	publishClosureExternalSuccessor(t, harness.db, fixture)
	expectClosureStatementError(t, harness.db, "23514",
		"asset_sources_last_complete_snapshot_guard", `
		UPDATE asset_sources
		SET last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, oldCompleteRunID)
}

func TestAssetCatalogAdmittedQueuedDataRunCannotCancelIneligible(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	const runID = "8f300000-0000-4000-8000-000000000001"
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cancel_guard", func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `
				INSERT INTO asset_source_runs (
					id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
					run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
					checkpoint_version,cursor_before_sha256
				) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
					'MANUAL_MUTATION','HUMAN',gate_revision,'admitted-cancel-ineligible',
					repeat('1',64),checkpoint_version,checkpoint_sha256
				FROM asset_sources WHERE id=$4
			`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',version=version+1 WHERE id=$1
			`, runID)
			return err
		})
}

func TestAssetCatalogNullableShapeChecksFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		mutation   string
	}{
		{
			name:       "data projection status cannot be null",
			constraint: "asset_source_runs_work_result_ck",
			mutation:   `UPDATE asset_source_runs SET work_result_status=NULL WHERE id=$1`,
		},
		{
			name:       "delay fields cannot exist without transition",
			constraint: "asset_source_runs_pending_transition_ck",
			mutation: `UPDATE asset_source_runs SET pending_transition=NULL,
				pending_transition_reason='TRANSPORT_BACKOFF',
				pending_transition_not_before=statement_timestamp()+interval '30 seconds',
				pending_transition_digest=repeat('a',64) WHERE id=$1`,
		},
		{
			name:       "override digest cannot exist without override",
			constraint: "asset_source_runs_terminal_override_ck",
			mutation: `UPDATE asset_source_runs SET terminal_failure_override=NULL,
				terminal_failure_override_digest=repeat('b',64) WHERE id=$1`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
			run := startRuntimeContractManualRun(t, harness.db, fixture)
			finalizeClosureEmptyManualPage(t, harness.db, fixture, run)
			execAssetSQL(t, harness.db,
				`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_mutation_guard`)
			t.Cleanup(func() {
				_, _ = harness.db.Exec(context.Background(),
					`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
			})
			expectClosureStatementError(t, harness.db, "23514", test.constraint,
				test.mutation, run.id)
		})
	}
}

func TestAssetCatalogNullableRelationshipAndPublishedPointerChecksFailClosed(t *testing.T) {
	t.Run("discovered relationship requires source provenance", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		execAssetSQL(t, harness.db,
			`ALTER TABLE asset_relationships DISABLE TRIGGER asset_relationships_mutation_guard`)
		t.Cleanup(func() {
			_, _ = harness.db.Exec(context.Background(),
				`ALTER TABLE asset_relationships ENABLE TRIGGER asset_relationships_mutation_guard`)
		})
		expectClosureStatementError(t, harness.db, "23514",
			"asset_relationships_provenance_ck", `
			UPDATE asset_relationships SET provenance_source_id=NULL WHERE id=$1
		`, fixture.relationshipID)
	})

	t.Run("published digest requires revision", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		execAssetSQL(t, harness.db,
			`ALTER TABLE asset_sources DISABLE TRIGGER asset_sources_mutation_guard`)
		t.Cleanup(func() {
			_, _ = harness.db.Exec(context.Background(),
				`ALTER TABLE asset_sources ENABLE TRIGGER asset_sources_mutation_guard`)
		})
		expectClosureStatementError(t, harness.db, "23514",
			"asset_sources_published_pointer_ck", `
			UPDATE asset_sources SET published_revision=NULL,
				published_revision_digest=repeat('f',64) WHERE id=$1
		`, fixture.sourceID)
	})
}

func TestAssetCatalogDelayIntentIsExactAndBounded(t *testing.T) {
	t.Run("arbitrary digest is rejected", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationCleanupAttempt(t, harness.db)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_pending_transition_guard", `
			WITH intent AS (SELECT statement_timestamp()+interval '30 seconds' AS not_before)
			UPDATE asset_source_runs AS run
			SET stage_code='CLEANING_UP',pending_transition='DELAY',
				pending_transition_reason='TRANSPORT_BACKOFF',
				pending_transition_not_before=intent.not_before,
				pending_transition_digest=repeat('a',64),version=run.version+1
			FROM intent WHERE run.id=$1
		`, runID)
	})

	t.Run("delay cannot exceed revision maximum", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationCleanupAttempt(t, harness.db)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_pending_transition_guard", closureExactDelayIntentSQL,
			runID, "61 seconds")
	})

	t.Run("exact digest inside revision window is accepted", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationCleanupAttempt(t, harness.db)
		if _, err := harness.db.Exec(context.Background(), closureExactDelayIntentSQL,
			runID, "30 seconds"); err != nil {
			t.Fatalf("persist exact bounded delay intent: %v", err)
		}
	})
}

func TestAssetCatalogManualRunRejectsDelayIntent(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_pending_transition_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			_, err := tx.Exec(context.Background(), closureExactDelayIntentSQL,
				run.id, "30 seconds")
			return err
		})
}

func TestAssetCatalogManualRunRejectsDelayedStates(t *testing.T) {
	t.Run("RUNNING cannot become DELAYED", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_pending_transition_guard", func(tx pgx.Tx) error {
				run := startClosureManualMutationRunInTx(t, tx, fixture)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET status='DELAYED',stage_code='DELAYED',lease_owner=NULL,
						lease_expires_at=NULL,fence_token_hash=NULL,version=version+1
					WHERE id=$1
				`, run.id)
				return err
			})
	})

	t.Run("FINALIZING cannot become DELAYED", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_pending_transition_guard", func(tx pgx.Tx) error {
				run := startClosureManualMutationRunInTx(t, tx, fixture)
				stageClosureManualEmptyPageInTx(t, tx, fixture, run)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET status='DELAYED',stage_code='DELAYED',lease_owner=NULL,
						lease_expires_at=NULL,fence_token_hash=NULL,version=version+1
					WHERE id=$1
				`, run.id)
				return err
			})
	})
}

func TestAssetCatalogManualNoCredentialCleanupCannotReset(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	run := seedForgedLegacyManualFinalizingRun(t, harness.db, fixture)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_mutation_guard`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(context.Background(),
			`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	})
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='DELAYED',stage_code='DELAYED',lease_owner=NULL,lease_expires_at=NULL,
			fence_token_hash=NULL,work_result_kind=NULL,work_result_status=NULL,
			work_result_digest=NULL,work_result_recorded_at=NULL,version=version+1
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='RUNNING',stage_code='READING',lease_owner='manual-reset-worker',
					lease_expires_at=statement_timestamp()+interval '5 minutes',
					fence_epoch=fence_epoch+1,fence_token_hash=repeat('f',64),
					heartbeat_sequence=heartbeat_sequence+1,cleanup_status='NOT_OPENED',
					cleanup_attempt_id=NULL,cleanup_attempt_epoch=0,cleanup_digest=NULL,
					version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogManualNoCredentialRequiresSameTransactionTerminalClosure(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_manual_cleanup_closure_guard", func(tx pgx.Tx) error {
			startClosureManualValidationRunInTx(t, tx, fixture)
			cleanupDigest := sourceRunNoCredentialDigest(t, tx, fixture.validationRunID)
			insertCleanupAudit(t, tx, fixture, fixture.validationRunID, 0, cleanupDigest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FINALIZING',stage_code='CLEANING_UP',
					work_result_kind='VALIDATION_PROOF',work_result_status='SUCCEEDED',
					work_result_digest=repeat('a',64),validation_outcome='SUCCEEDED',
					validation_digest=repeat('a',64),validation_proof_digest=repeat('a',64),
					cleanup_status='NO_CREDENTIAL',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, cleanupDigest)
			return err
		})
}

func TestAssetCatalogTerminalClosureRequiresSerializableIsolation(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	finalizeClosureEmptyManualPage(t, harness.db, fixture, run)

	expectClosureCommitError(t, harness.db, pgx.ReadCommitted, "55000",
		"asset_source_runs_terminal_isolation_guard", func(tx pgx.Tx) error {
			return closeClosureManualRun(t, tx, fixture, run.id)
		})
}

func TestAssetCatalogQueuedValidationCancellationRequiresSerializableIsolation(t *testing.T) {
	t.Run("read committed is rejected", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.ReadCommitted, "55000",
			"asset_source_runs_terminal_isolation_guard", func(tx pgx.Tx) error {
				return cancelQueuedClosureValidation(tx, fixture)
			})
	})

	t.Run("serializable closes the bound revision", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin serializable validation cancellation: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := cancelQueuedClosureValidation(tx, fixture); err != nil {
			t.Fatalf("close queued validation cancellation: %v", err)
		}
		if err := tx.Commit(context.Background()); err != nil {
			t.Fatalf("commit serializable validation cancellation: %v", err)
		}
	})
}

func TestAssetCatalogQueuedManualMutationCancellationRequiresSerializableIsolation(t *testing.T) {
	t.Run("read committed is rejected", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.ReadCommitted, "55000",
			"asset_source_runs_terminal_isolation_guard", func(tx pgx.Tx) error {
				return createAndCancelIneligibleManualMutation(tx, fixture,
					"8f310000-0000-4000-8000-000000000001", "manual-cancel-read-committed")
			})
	})

	t.Run("serializable closes synchronously", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin serializable manual mutation cancellation: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := createAndCancelIneligibleManualMutation(tx, fixture,
			"8f310000-0000-4000-8000-000000000002", "manual-cancel-serializable"); err != nil {
			t.Fatalf("close queued manual mutation cancellation: %v", err)
		}
		if err := tx.Commit(context.Background()); err != nil {
			t.Fatalf("commit serializable manual mutation cancellation: %v", err)
		}
	})
}

func TestAssetCatalogIneligibleQueuedCancellationCannotInjectExecutionFacts(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := prepareQueuedClosureValidation(t, harness.db)

	tests := []struct {
		name     string
		mutation string
	}{
		{
			name: "started_at",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',started_at=statement_timestamp(),
					version=version+1 WHERE id=$1`,
		},
		{
			name: "heartbeat_at",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',heartbeat_at=statement_timestamp(),
					version=version+1 WHERE id=$1`,
		},
		{
			name: "fence_epoch",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',fence_epoch=1,
					version=version+1 WHERE id=$1`,
		},
		{
			name: "failure_code",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',failure_code='FORGED_FAILURE',
					version=version+1 WHERE id=$1`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
				"asset_source_runs_cancel_guard", func(tx pgx.Tx) error {
					_, err := tx.Exec(context.Background(), test.mutation, fixture.validationRunID)
					return err
				})
		})
	}
}

func TestAssetCatalogValidationBindingIsImmutableWithinSameState(t *testing.T) {
	t.Run("VALIDATING cannot rebind", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		commitQueuedClosureCancellation(t, harness.db, fixture)
		execAssetSQL(t, harness.db, `
			UPDATE asset_sources SET status='ACTIVE',version=version+1 WHERE id=$1
		`, fixture.sourceID)
		const successorRunID = "8f400000-0000-4000-8000-000000000001"
		insertQueuedClosureValidationRun(t, harness.db, fixture, successorRunID,
			"closure-validation-successor")
		execAssetSQL(t, harness.db, `
			UPDATE asset_source_revisions
			SET state='VALIDATING',validation_run_id=$2,validation_digest=NULL,version=version+1
			WHERE id=$1
		`, fixture.revisionID, successorRunID)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_revisions_validation_immutable_guard", `
			UPDATE asset_source_revisions
			SET validation_run_id=$2,version=version+1 WHERE id=$1
		`, fixture.revisionID, fixture.validationRunID)
	})

	t.Run("REJECTED cannot rewrite failure evidence", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		commitQueuedClosureCancellation(t, harness.db, fixture)
		execAssetSQL(t, harness.db, `
			UPDATE asset_sources SET status='ACTIVE',version=version+1 WHERE id=$1
		`, fixture.sourceID)
		const successorRunID = "8f400000-0000-4000-8000-000000000002"
		insertQueuedClosureValidationRun(t, harness.db, fixture, successorRunID,
			"closure-validation-rejected-rewrite")
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_revisions_validation_immutable_guard", `
			UPDATE asset_source_revisions
			SET validation_run_id=$2,validation_digest=repeat('2',64),version=version+1
			WHERE id=$1
		`, fixture.revisionID, successorRunID)
	})
}

func TestAssetCatalogObservationUsesTransactionTimestampAndCallerCanonicalProvenance(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	t.Run("canonical caller material is accepted", func(t *testing.T) {
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin canonical observation transaction: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		run := startClosureManualMutationRunInTx(t, tx, fixture)
		acceptedAt := readClosureTransactionTimestamp(t, tx)
		if _, err := insertCanonicalClosureObservation(
			tx, fixture, run, "8f100000-0000-4000-8000-000000000001", acceptedAt,
		); err != nil {
			t.Fatalf("insert caller-canonical observation: %v", err)
		}
	})

	t.Run("non-transaction timestamp is rejected", func(t *testing.T) {
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin drifted observation transaction: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		run := startClosureManualMutationRunInTx(t, tx, fixture)
		acceptedAt := readClosureTransactionTimestamp(t, tx).Add(time.Microsecond)
		_, err = insertCanonicalClosureObservation(
			tx, fixture, run, "8f100000-0000-4000-8000-000000000002", acceptedAt,
		)
		assertClosurePostgresError(t, err, "23514", "asset_observations_observed_at_guard")
	})
}

func TestAssetCatalogObservationRejectsNullProvenanceOwnership(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	nullOwnershipSQL := strings.Replace(
		insertRuntimeObservationSQL, "'ownership','SOURCE'", "'ownership',NULL", 1,
	)
	if nullOwnershipSQL == insertRuntimeObservationSQL {
		t.Fatal("runtime observation SQL no longer exposes the canonical ownership material")
	}
	expectClosureCommitError(t, harness.db, pgx.Serializable, "23514",
		"asset_observations_provenance_admission_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			candidate := newRuntimeObservation(fixture, run,
				"8f100000-0000-4000-8000-000000000003", "null-provenance-ownership", "3")
			_, err := tx.Exec(context.Background(), nullOwnershipSQL,
				runtimeObservationArguments(candidate)...)
			return err
		})
}

const closureExactDelayIntentSQL = `
	WITH intent AS (
		SELECT statement_timestamp()+$2::interval AS not_before
	)
	UPDATE asset_source_runs AS run
	SET stage_code='CLEANING_UP',pending_transition='DELAY',
		pending_transition_reason='TRANSPORT_BACKOFF',
		pending_transition_not_before=intent.not_before,
		pending_transition_digest=asset_catalog_source_run_delay_intent_digest(
			run,'TRANSPORT_BACKOFF',intent.not_before
		),version=run.version+1
	FROM intent WHERE run.id=$1
`

const (
	closureExternalSourceID     = "8f000000-0000-4000-8000-000000000001"
	closureExternalRevisionID   = "8f000000-0000-4000-8000-000000000002"
	closureExternalValidationID = "8f000000-0000-4000-8000-000000000003"
)

type qualificationFixtureSchemaState string

const (
	qualificationFixtureSchemaOld  qualificationFixtureSchemaState = "OLD"
	qualificationFixtureSchemaFull qualificationFixtureSchemaState = "FULL"
)

var qualificationFixtureSourceColumns = []string{
	"gate_evidence_run_id",
	"gate_evidence_digest",
	"gate_evidence_expires_at",
}

var qualificationFixtureRunColumns = []string{
	"qualification_evidence_kind",
	"qualification_scope_digest",
	"qualification_binding_digest",
	"qualification_profile_descriptor_digest",
	"qualification_runtime_manifest_digest",
	"qualification_lab_binding_digest",
	"qualification_prior_receipts_digest",
	"qualification_result_digest",
	"qualification_receipt_issued_at",
	"qualification_receipt_expires_at",
	"qualification_signing_key_id",
	"qualification_signature",
	"qualification_receipt_digest",
	"ha_owner_worker_identity_digest",
	"ha_takeover_worker_identity_digest",
	"ha_owner_process_instance_digest",
	"ha_takeover_process_instance_digest",
	"ha_takeover_receipt_digest",
	"ha_restart_receipt_digest",
	"ha_session_recovery_receipt_digest",
	"ha_cleanup_receipt_digest",
	"ha_response_loss_receipt_digest",
	"ha_fact_chain_digest",
}

var qualificationFixtureSourceColumnTypes = []string{
	"uuid",
	"text",
	"timestamp with time zone",
}

var qualificationFixtureRunColumnTypes = []string{
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"timestamp with time zone",
	"timestamp with time zone",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
	"text",
}

var qualificationFixtureGateForeignKeyColumns = []string{
	"tenant_id",
	"workspace_id",
	"id",
	"gate_evidence_run_id",
}

var qualificationFixtureGateForeignKeyReferences = []string{
	"tenant_id",
	"workspace_id",
	"source_id",
	"id",
}

func qualificationFixtureSchemaStateFor(
	ctx context.Context,
	database *pgxpool.Pool,
) (qualificationFixtureSchemaState, error) {
	var (
		sourceExpectedColumns int
		sourceUnknownColumns  int
		runExpectedColumns    int
		runUnknownColumns     int
		exactSourceShapes     int
		exactRunShapes        int
		foreignKeyCount       int
		invalidClosureCount   int
		exactGateForeignKeys  int
		exactClosureTriggers  int
		oldVocabulary         bool
		fullVocabulary        bool
		fullConstraintClosure bool
	)
	if err := database.QueryRow(ctx, `
		WITH
		expected_source(column_name) AS (
			SELECT unnest($1::text[])
		),
		expected_run(column_name) AS (
			SELECT unnest($2::text[])
		),
		expected_source_shape(column_name, data_type) AS (
			SELECT * FROM unnest($1::text[], $6::text[])
		),
		expected_run_shape(column_name, data_type) AS (
			SELECT * FROM unnest($2::text[], $7::text[])
		),
		actual_source(column_name, data_type, is_nullable) AS (
			SELECT column_name,data_type,is_nullable
			FROM information_schema.columns
			WHERE table_schema='public' AND table_name='asset_sources'
			  AND column_name LIKE 'gate_evidence_%'
		),
		actual_run(column_name, data_type, is_nullable) AS (
			SELECT column_name,data_type,is_nullable
			FROM information_schema.columns
			WHERE table_schema='public' AND table_name='asset_source_runs'
			  AND (column_name LIKE 'qualification_%' OR column_name LIKE 'ha_%')
		),
		vocabulary AS (
			SELECT a.attname,
				COALESCE(string_agg(pg_get_constraintdef(c.oid, true), E'\n'), '') AS definition
			FROM pg_class r
			JOIN pg_namespace n ON n.oid=r.relnamespace
			JOIN pg_attribute a ON a.attrelid=r.oid AND NOT a.attisdropped
			LEFT JOIN pg_constraint c
			  ON c.conrelid=r.oid AND c.contype='c'
			 AND c.conkey=ARRAY[a.attnum]::smallint[]
			WHERE n.nspname='public' AND r.relname='asset_source_runs'
			  AND a.attname IN ('run_kind','work_result_kind','qualification_evidence_kind')
			GROUP BY a.attname
		),
		table_checks AS (
			SELECT r.relname,
				lower(COALESCE(string_agg(pg_get_constraintdef(c.oid, true), E'\n'), '')) AS definition
			FROM pg_class r
			JOIN pg_namespace n ON n.oid=r.relnamespace
			LEFT JOIN pg_constraint c ON c.conrelid=r.oid AND c.contype='c'
			WHERE n.nspname='public'
			  AND r.relname IN ('asset_sources','asset_source_runs')
			GROUP BY r.relname
		),
		definitions AS (
			SELECT
				COALESCE((SELECT definition FROM vocabulary WHERE attname='run_kind'), '') AS run_kind,
				COALESCE((SELECT definition FROM vocabulary WHERE attname='work_result_kind'), '') AS work_result_kind,
				COALESCE((SELECT definition FROM vocabulary WHERE attname='qualification_evidence_kind'), '') AS evidence_kind,
				COALESCE((SELECT definition FROM table_checks WHERE relname='asset_sources'), '') AS source_checks,
				COALESCE((SELECT definition FROM table_checks WHERE relname='asset_source_runs'), '') AS run_checks
		)
		SELECT
			(SELECT count(*) FROM actual_source JOIN expected_source USING (column_name)),
			(SELECT count(*) FROM actual_source LEFT JOIN expected_source USING (column_name)
			 WHERE expected_source.column_name IS NULL),
			(SELECT count(*) FROM actual_run JOIN expected_run USING (column_name)),
			(SELECT count(*) FROM actual_run LEFT JOIN expected_run USING (column_name)
			 WHERE expected_run.column_name IS NULL),
			(SELECT count(*)
			 FROM actual_source
			 JOIN expected_source_shape USING (column_name,data_type)
			 WHERE actual_source.is_nullable='YES'),
			(SELECT count(*)
			 FROM actual_run
			 JOIN expected_run_shape USING (column_name,data_type)
			 WHERE actual_run.is_nullable='YES'),
			(SELECT count(*)
			 FROM pg_constraint c
			 JOIN pg_class r ON r.oid=c.conrelid
			 JOIN pg_namespace n ON n.oid=r.relnamespace
			 WHERE n.nspname='public' AND r.relname=ANY($3::text[]) AND c.contype='f'),
			(SELECT count(*)
			 FROM pg_constraint c
			 JOIN pg_class r ON r.oid=c.conrelid
			 JOIN pg_namespace n ON n.oid=r.relnamespace
			 WHERE n.nspname='public'
			   AND (
					(c.contype='f' AND r.relname=ANY($3::text[])) OR
					(c.contype='c' AND r.relname IN ('asset_sources','asset_source_runs'))
			   )
			   AND (NOT c.convalidated OR NOT c.conenforced)),
			(SELECT count(*)
			 FROM pg_constraint c
			 JOIN pg_class source_table ON source_table.oid=c.conrelid
			 JOIN pg_namespace source_namespace ON source_namespace.oid=source_table.relnamespace
			 JOIN pg_class target_table ON target_table.oid=c.confrelid
			 JOIN pg_namespace target_namespace ON target_namespace.oid=target_table.relnamespace
			 WHERE source_namespace.nspname='public'
			   AND target_namespace.nspname='public'
			   AND source_table.relname='asset_sources'
			   AND target_table.relname='asset_source_runs'
			   AND c.contype='f'
			   AND c.conname='asset_sources_gate_evidence_run_fk'
			   AND c.condeferrable AND c.condeferred
			   AND c.convalidated AND c.conenforced
			   AND ARRAY(
					SELECT attribute.attname::text
					FROM unnest(c.conkey) WITH ORDINALITY AS key(attnum, position)
					JOIN pg_attribute attribute
					  ON attribute.attrelid=c.conrelid AND attribute.attnum=key.attnum
					ORDER BY key.position
			   )=$4::text[]
			   AND ARRAY(
					SELECT attribute.attname::text
					FROM unnest(c.confkey) WITH ORDINALITY AS key(attnum, position)
					JOIN pg_attribute attribute
					  ON attribute.attrelid=c.confrelid AND attribute.attnum=key.attnum
					ORDER BY key.position
			   )=$5::text[]),
			(SELECT count(*)
			 FROM pg_trigger trigger_record
			 JOIN pg_class relation ON relation.oid=trigger_record.tgrelid
			 JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
			 JOIN pg_constraint constraint_record
			   ON constraint_record.oid=trigger_record.tgconstraint
			 WHERE namespace.nspname='public'
			   AND relation.relname='asset_sources'
			   AND trigger_record.tgname='asset_sources_gate_evidence_closure_guard'
			   AND trigger_record.tgconstraint<>0
			   AND trigger_record.tgdeferrable
			   AND trigger_record.tginitdeferred
			   AND trigger_record.tgenabled='O'
			   AND constraint_record.convalidated
			   AND constraint_record.conenforced),
			regexp_count(run_kind, '''[A-Z][A-Z0-9_]*''')=5 AND
				run_kind LIKE '%''VALIDATION''%' AND run_kind LIKE '%''DISCOVERY''%' AND
				run_kind LIKE '%''CSV_IMPORT''%' AND run_kind LIKE '%''API_INGESTION''%' AND
				run_kind LIKE '%''MANUAL_MUTATION''%' AND
				regexp_count(work_result_kind, '''[A-Z][A-Z0-9_]*''')=3 AND
				work_result_kind LIKE '%''DATA_PROJECTION''%' AND
				work_result_kind LIKE '%''VALIDATION_PROOF''%' AND
				work_result_kind LIKE '%''FAILURE_INTENT''%' AND evidence_kind='',
			regexp_count(run_kind, '''[A-Z][A-Z0-9_]*''')=6 AND
				run_kind LIKE '%''VALIDATION''%' AND run_kind LIKE '%''DISCOVERY''%' AND
				run_kind LIKE '%''CSV_IMPORT''%' AND run_kind LIKE '%''API_INGESTION''%' AND
				run_kind LIKE '%''MANUAL_MUTATION''%' AND
				run_kind LIKE '%''QUALIFICATION''%' AND
				regexp_count(work_result_kind, '''[A-Z][A-Z0-9_]*''')=4 AND
				work_result_kind LIKE '%''DATA_PROJECTION''%' AND
				work_result_kind LIKE '%''VALIDATION_PROOF''%' AND
				work_result_kind LIKE '%''FAILURE_INTENT''%' AND
				work_result_kind LIKE '%''QUALIFICATION_PROOF''%' AND
				regexp_count(evidence_kind, '''[A-Z][A-Z0-9_]*''')=2 AND
				evidence_kind LIKE '%''TWO_WORKER_HA''%' AND
				evidence_kind LIKE '%''PROVIDER_CANARY''%',
			(SELECT bool_and(position(column_name IN source_checks)>0) FROM expected_source) AND
				(SELECT bool_and(position(column_name IN run_checks)>0) FROM expected_run)
		FROM definitions
	`, qualificationFixtureSourceColumns, qualificationFixtureRunColumns, assetCatalogTableNames(),
		qualificationFixtureGateForeignKeyColumns,
		qualificationFixtureGateForeignKeyReferences,
		qualificationFixtureSourceColumnTypes,
		qualificationFixtureRunColumnTypes,
	).Scan(
		&sourceExpectedColumns,
		&sourceUnknownColumns,
		&runExpectedColumns,
		&runUnknownColumns,
		&exactSourceShapes,
		&exactRunShapes,
		&foreignKeyCount,
		&invalidClosureCount,
		&exactGateForeignKeys,
		&exactClosureTriggers,
		&oldVocabulary,
		&fullVocabulary,
		&fullConstraintClosure,
	); err != nil {
		return "", fmt.Errorf("inspect qualification fixture schema closure: %w", err)
	}

	if sourceExpectedColumns == 0 && sourceUnknownColumns == 0 &&
		runExpectedColumns == 0 && runUnknownColumns == 0 &&
		exactSourceShapes == 0 && exactRunShapes == 0 &&
		foreignKeyCount == 44 && invalidClosureCount == 0 &&
		exactGateForeignKeys == 0 && exactClosureTriggers == 0 &&
		oldVocabulary {
		return qualificationFixtureSchemaOld, nil
	}
	if sourceExpectedColumns == len(qualificationFixtureSourceColumns) &&
		sourceUnknownColumns == 0 &&
		exactSourceShapes == len(qualificationFixtureSourceColumns) &&
		runExpectedColumns == len(qualificationFixtureRunColumns) &&
		runUnknownColumns == 0 &&
		exactRunShapes == len(qualificationFixtureRunColumns) &&
		foreignKeyCount == 45 &&
		invalidClosureCount == 0 &&
		exactGateForeignKeys == 1 &&
		exactClosureTriggers == 1 &&
		fullVocabulary &&
		fullConstraintClosure {
		return qualificationFixtureSchemaFull, nil
	}
	return "", fmt.Errorf(
		"partial qualification fixture schema: source_columns=%d+%d/%d run_columns=%d+%d/%d "+
			"foreign_keys=%d invalid_closure=%d exact_gate_fk=%d exact_closure_trigger=%d "+
			"old_vocabulary=%t full_vocabulary=%t closure=%t",
		sourceExpectedColumns,
		sourceUnknownColumns,
		exactSourceShapes,
		runExpectedColumns,
		runUnknownColumns,
		exactRunShapes,
		foreignKeyCount,
		invalidClosureCount,
		exactGateForeignKeys,
		exactClosureTriggers,
		oldVocabulary,
		fullVocabulary,
		fullConstraintClosure,
	)
}

const closureExternalProfileManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":"EXTERNAL_V1","credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":65536,"max_page_bytes":1048576,"max_page_items":100,"max_page_relations":100,"network_mode":"NONE","parser_code":"EXTERNAL_V1","profile_code":"EXTERNAL_V1","provider_kind":"EXTERNAL_V1","rate_limit_requests":100,"rate_limit_window_seconds":60,"relationship_types":["DEPENDS_ON"],"schedule_mode":"NONE","source_kind":"EXTERNAL_CMDB","sync_mode":"ON_DEMAND","trust_mode":"NONE","trusted_path_codes":["DISPLAY_NAME","EXTERNAL_ID","KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`

func startClosureManualValidationRunInTx(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
) {
	t.Helper()
	execAssetSQL(t, tx, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
			'closure-manual-cleanup-validation',repeat('1',64),0
		FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, tx, `
		UPDATE asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, fixture.validationRunID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='VALIDATING',lease_owner='closure-manual-validation',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('2',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, fixture.validationRunID)
}

func startClosureManualMutationRunInTx(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
) runtimeContractRun {
	t.Helper()
	run := runtimeContractRun{id: "8f700000-0000-4000-8000-000000000002"}
	var gateRevision int64
	var checkpointSHA *string
	if err := tx.QueryRow(context.Background(), `
		SELECT source.published_revision,source.published_revision_digest,
			revision.source_definition_digest,source.gate_revision,
			source.checkpoint_version,source.checkpoint_sha256,source.provider_kind
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.source_id=source.id AND revision.revision=source.published_revision
		WHERE source.id=$1
	`, fixture.sourceID).Scan(&run.revision, &run.revisionDigest,
		&run.sourceDefinitionDigest, &gateRevision, &run.checkpointVersion,
		&checkpointSHA, &run.providerKind); err != nil {
		t.Fatalf("read manual mutation admission: %v", err)
	}
	execAssetSQL(t, tx, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) VALUES ($1,$2,$3,$4,$5,$6,'MANUAL_MUTATION','HUMAN',$7,
			'closure-manual-atomic-mutation',repeat('1',64),$8,$9)
	`, run.id, fixture.tenantID, fixture.workspaceID, fixture.sourceID, run.revision,
		run.revisionDigest, gateRevision, checkpointSHA, run.checkpointVersion)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='runtime-manual-executor',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('2',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, run.id)
	if err := tx.QueryRow(context.Background(), `
		SELECT checkpoint_version,fence_epoch,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&run.checkpointVersion, &run.fenceEpoch, &run.pageSequence); err != nil {
		t.Fatalf("read manual mutation coordinates: %v", err)
	}
	return run
}

func stageClosureManualEmptyPageInTx(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	pageDigest := strings.Repeat("c", 64)
	if err := insertClosurePageReceipt(tx, fixture, run.id, run.pageSequence+1, pageDigest); err != nil {
		t.Fatalf("insert manual closure page receipt: %v", err)
	}
	cleanupDigest := sourceRunNoCredentialDigest(t, tx, run.id)
	insertCleanupAudit(t, tx, fixture, run.id, 0, cleanupDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_sources SET checkpoint_version=checkpoint_version+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			checkpoint_version=checkpoint_version+1,final_page=true,
			complete_snapshot=false,effective_complete_snapshot=false,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('d',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='NO_CREDENTIAL',cleanup_digest=$3,version=version+1
		WHERE id=$1
	`, run.id, pageDigest, cleanupDigest)
}

func seedForgedLegacyManualFinalizingRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) runtimeContractRun {
	t.Helper()
	execAssetSQL(t, database,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	t.Cleanup(func() {
		_, _ = database.Exec(context.Background(),
			`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	})
	run := startRuntimeContractManualRun(t, database, fixture)
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin forged legacy manual finalization: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	stageClosureManualEmptyPageInTx(t, tx, fixture, run)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit forged legacy manual finalization: %v", err)
	}
	execAssetSQL(t, database,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	return run
}

func prepareQueuedClosureValidation(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	fixture = seedClosureExternalDraftDefinition(
		t,
		database,
		fixture,
		closureExternalSourceID,
		closureExternalRevisionID,
		"EXTERNAL_V1",
		"queued validation source",
		"queued-validation-source",
	)
	fixture.validationRunID = closureExternalValidationID
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
			'closure-cancel-validation',repeat('1',64),0
		FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest)
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
	`, fixture.sourceID)
	return fixture
}

func cancelQueuedClosureValidation(tx pgx.Tx, fixture assetCatalogFixture) error {
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='CANCELLED',stage_code='COMPLETED',version=version+1 WHERE id=$1
	`, fixture.validationRunID); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		UPDATE asset_source_revisions
		SET state='REJECTED',validation_digest=repeat('1',64),version=version+1
		WHERE id=$1
	`, fixture.revisionID)
	return err
}

func createAndCancelIneligibleManualMutation(
	tx pgx.Tx,
	fixture assetCatalogFixture,
	runID string,
	idempotencyKey string,
) error {
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			checkpoint_version,cursor_before_sha256
		) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
			'MANUAL_MUTATION','HUMAN',gate_revision,$5,repeat('1',64),
			checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$4
	`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, idempotencyKey); err != nil {
		return err
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
	`, fixture.sourceID); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='CANCELLED',stage_code='COMPLETED',version=version+1 WHERE id=$1
	`, runID)
	return err
}

func commitQueuedClosureCancellation(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin queued validation cancellation: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := cancelQueuedClosureValidation(tx, fixture); err != nil {
		t.Fatalf("cancel queued validation: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit queued validation cancellation: %v", err)
	}
}

func insertQueuedClosureValidationRun(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	runID string,
	idempotencyKey string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,$6,repeat('3',64),0
		FROM asset_sources WHERE id=$4
	`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest, idempotencyKey)
}

func readClosureTransactionTimestamp(t *testing.T, tx pgx.Tx) time.Time {
	t.Helper()
	var acceptedAt time.Time
	if err := tx.QueryRow(context.Background(), `SELECT transaction_timestamp()`).Scan(&acceptedAt); err != nil {
		t.Fatalf("read transaction timestamp: %v", err)
	}
	return acceptedAt
}

func insertCanonicalClosureObservation(
	tx pgx.Tx,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	observationID string,
	acceptedAt time.Time,
) (pgconn.CommandTag, error) {
	provenance, err := json.Marshal(map[string]any{
		"display_name": map[string]any{
			"source_id":          fixture.sourceID,
			"provider_kind":      run.providerKind,
			"source_revision":    run.revision,
			"observed_at":        acceptedAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
			"provider_path_code": "DISPLAY_NAME",
			"confidence":         100,
			"ownership":          "SOURCE",
		},
	})
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	document := []byte(`{"display_name":"closure-observation"}`)
	documentDigest := sha256.Sum256(document)
	provenanceDigest := sha256.Sum256(provenance)
	return tx.Exec(context.Background(), `
		INSERT INTO asset_observations (
			id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
			source_revision,canonical_revision_digest,source_definition_digest,observed_at,
			freshness_kind,freshness_order_sequence,provider_version_sha256,provider_fact_sha256,
			fingerprint_sha256,provider_provenance_sha256,observation_chain_sha256,
			accepted_checkpoint_version,run_fence_epoch,run_page_sequence,schema_version,
			normalized_document,document_sha256,field_provenance,field_provenance_sha256
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,'closure-canonical-observation',$8,$9,$10,$11,
			'CATALOG_SEQUENCE',$12,repeat('1',64),repeat('2',64),repeat('3',64),
			repeat('4',64),repeat('5',64),$12,$13,$14,'asset.v1',$15,$16,$17,$18
		)
	`, observationID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.sourceID, run.id, run.providerKind, run.revision, run.revisionDigest,
		run.sourceDefinitionDigest, acceptedAt, run.checkpointVersion+1, run.fenceEpoch,
		run.pageSequence+1, document, hex.EncodeToString(documentDigest[:]), provenance,
		hex.EncodeToString(provenanceDigest[:]))
}

func seedClosureExternalValidationRun(t *testing.T, database *pgxpool.Pool) string {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	fixture = seedClosureExternalValidationOnFixture(t, database, fixture)
	return fixture.validationRunID
}

func seedClosureExternalValidationCleanupAttempt(
	t *testing.T,
	database *pgxpool.Pool,
) string {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	fixture = seedClosureExternalValidationOnFixture(t, database, fixture)
	reserveClosureCleanupAttempt(t, database, fixture.validationRunID)
	return fixture.validationRunID
}

func seedClosureExternalValidationOnFixture(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) assetCatalogFixture {
	t.Helper()
	fixture = seedClosureExternalDraftDefinition(
		t,
		database,
		fixture,
		closureExternalSourceID,
		closureExternalRevisionID,
		"EXTERNAL_V1",
		"closure external source",
		"closure-external-source",
	)
	fixture.validationRunID = closureExternalValidationID
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
			'closure-external-validation',repeat('5',64),0
		FROM asset_sources WHERE id=$4
	`, closureExternalValidationID, fixture.tenantID, fixture.workspaceID, closureExternalSourceID,
		fixture.revisionDigest)
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, closureExternalRevisionID, closureExternalValidationID)
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
			version=version+1
		WHERE id=$1
	`, closureExternalSourceID, closureExternalValidationID)
	var validationVisible bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.gate_status='VALIDATING' AND
			source.gate_reason_code='VALIDATION_IN_PROGRESS' AND
			source.gate_revision=run.gate_revision+1 AND
			source.validated_run_id=run.id AND source.validation_digest IS NULL AND
			source.validated_binding_digest IS NULL AND revision.state='VALIDATING' AND
			revision.validation_run_id=run.id AND run.status='QUEUED' AND
			run.stage_code='WAITING'
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision ON revision.source_id=source.id
		JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
		WHERE source.id=$1 AND revision.id=$2
	`, fixture.sourceID, fixture.revisionID).Scan(&validationVisible); err != nil {
		t.Fatalf("read visible external validation gate: %v", err)
	}
	if !validationVisible {
		t.Fatal("external validation did not expose the exact bound VALIDATING gate before claim")
	}
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='VALIDATING',lease_owner='closure-external-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('6',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, closureExternalValidationID)
	return fixture
}

func seedClosureExternalDraftDefinition(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	sourceID string,
	revisionID string,
	providerKind string,
	name string,
	idempotencyKey string,
) assetCatalogFixture {
	t.Helper()
	fixture.sourceID = sourceID
	fixture.revisionID = revisionID
	profile := []byte(strings.ReplaceAll(closureExternalProfileManifestV1, "EXTERNAL_V1", providerKind))
	providerSchema := []byte(`{"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"),
		[]byte("1"),
		[]byte(fixture.environmentID),
	)
	fixture.sourceDefinitionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"),
		[]byte("EXTERNAL_CMDB"),
		[]byte(providerKind),
		[]byte(providerKind),
		profileDigest[:],
		providerSchemaDigest[:],
	)
	fixture.revisionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"),
		[]byte(fixture.tenantID),
		[]byte(fixture.workspaceID),
		[]byte(fixture.sourceID),
		[]byte("1"),
		assetCatalogCorrectiveDecodeDigest(t, fixture.sourceDefinitionDigest),
		[]byte(fixture.integrationID),
		[]byte("ON_DEMAND"),
		[]byte("opaque-credential"),
		nil,
		nil,
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("100"),
		[]byte("60"),
		[]byte("1"),
		[]byte("60"),
		[]byte(providerKind),
		nil,
		nil,
		nil,
	)

	transaction, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external source definition closure: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	execAssetSQL(t, transaction, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,'EXTERNAL_CMDB',$4,$5,$6,repeat('1',64))
	`, sourceID, fixture.tenantID, fixture.workspaceID, providerKind, name, idempotencyKey)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_profile_manifest,profile_manifest_sha256,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,rate_limit_requests,rate_limit_window_seconds,
			backpressure_base_seconds,backpressure_max_seconds,profile_code,
			created_by,change_reason_code,expected_source_version
		) SELECT $1,$2,$3,$4,1,$5,$6,$7,$8,$9,'ON_DEMAND',
			$10,$11,$12,'opaque-credential',100,60,1,60,
			$13,'closure-test','INITIAL_CREATE',source.version
		FROM asset_sources AS source WHERE source.id=$4
	`, revisionID, fixture.tenantID, fixture.workspaceID,
		sourceID, profile, hex.EncodeToString(profileDigest[:]),
		providerSchema, hex.EncodeToString(providerSchemaDigest[:]), fixture.integrationID,
		authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest, providerKind)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revision_authorities (
			tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES ($1,$2,$3,1,$4,1)
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit external source definition closure: %v", err)
	}
	return fixture
}

func seedClosureExternalSuccessorDefinition(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	revisionID string,
	revision int64,
	providerKind string,
	providerSchema []byte,
	changeReason string,
) assetCatalogFixture {
	t.Helper()
	fixture.revisionID = revisionID
	profile := []byte(strings.ReplaceAll(closureExternalProfileManifestV1, "EXTERNAL_V1", providerKind))
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"),
		[]byte("1"),
		[]byte(fixture.environmentID),
	)
	fixture.sourceDefinitionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"),
		[]byte("EXTERNAL_CMDB"),
		[]byte(providerKind),
		[]byte(providerKind),
		profileDigest[:],
		providerSchemaDigest[:],
	)
	fixture.revisionDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"),
		[]byte(fixture.tenantID),
		[]byte(fixture.workspaceID),
		[]byte(fixture.sourceID),
		[]byte(strconv.FormatInt(revision, 10)),
		assetCatalogCorrectiveDecodeDigest(t, fixture.sourceDefinitionDigest),
		[]byte(fixture.integrationID),
		[]byte("ON_DEMAND"),
		[]byte("opaque-credential"),
		nil,
		nil,
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("100"),
		[]byte("60"),
		[]byte("1"),
		[]byte("60"),
		[]byte(providerKind),
		nil,
		nil,
		nil,
	)

	transaction, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external successor definition closure: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_profile_manifest,profile_manifest_sha256,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,rate_limit_requests,rate_limit_window_seconds,
			backpressure_base_seconds,backpressure_max_seconds,profile_code,
			created_by,change_reason_code,expected_source_version
		) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'ON_DEMAND',
			$11,$12,$13,'opaque-credential',100,60,1,60,$14,
			'closure-test',$15,source.version
		FROM asset_sources AS source WHERE source.id=$4
	`, revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, revision,
		profile, hex.EncodeToString(profileDigest[:]), providerSchema,
		hex.EncodeToString(providerSchemaDigest[:]), fixture.integrationID,
		authorityDigest, fixture.sourceDefinitionDigest, fixture.revisionDigest,
		providerKind, changeReason)
	execAssetSQL(t, transaction, `
		INSERT INTO asset_source_revision_authorities (
			tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES ($1,$2,$3,$4,$5,1)
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, revision, fixture.environmentID)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit external successor definition closure: %v", err)
	}
	return fixture
}

func seedClosureAuthoritativeCompleteCatalog(
	t *testing.T,
	database *pgxpool.Pool,
) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	return seedClosureAuthoritativeCompleteCatalogOnFixture(t, database, fixture)
}

func seedClosureAuthoritativeCompleteCatalogOnFixture(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) assetCatalogFixture {
	t.Helper()
	fixture = seedClosureExternalValidationOnFixture(t, database, fixture)
	finishClosureExternalValidation(t, database, fixture, 1, strings.Repeat("7", 64))
	fixture.runID = "8f500000-0000-4000-8000-000000000001"
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			checkpoint_version,cursor_before_sha256
		) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
			'DISCOVERY','SCHEDULED',gate_revision,'closure-authoritative-discovery',
			repeat('8',64),checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$4
	`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='closure-discovery-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('9',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, fixture.runID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, fixture.runID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='APPLYING',version=version+1 WHERE id=$1
	`, fixture.runID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1 WHERE id=$1
	`, fixture.runID)

	pageTx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin authoritative source page: %v", err)
	}
	defer func() { _ = pageTx.Rollback(context.Background()) }()
	pageDigest := strings.Repeat("a", 64)
	if err := insertClosurePageReceipt(pageTx, fixture, fixture.runID, 1, pageDigest); err != nil {
		t.Fatalf("insert authoritative page receipt: %v", err)
	}
	relationDigest := strings.Repeat("d", 64)
	if err := insertClosureRelationPageReceipt(
		pageTx, fixture, fixture.runID, 1, relationDigest,
	); err != nil {
		t.Fatalf("insert authoritative relation page receipt: %v", err)
	}
	insertClosureExternalObservation(t, pageTx, fixture, fixture.observationID, fixture.assetID,
		"external-host-a", "closure-host-a", strings.Repeat("7", 64))
	insertClosureExternalObservation(t, pageTx, fixture, fixture.secondObservationID, fixture.secondAssetID,
		"external-host-b", "closure-host-b", strings.Repeat("8", 64))
	seedClosureExternalProjectionEdges(t, pageTx, fixture)
	execAssetSQL(t, pageTx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('01',12)||repeat('02',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-key-1',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, pageTx, `
		UPDATE asset_source_runs AS run
		SET status='FINALIZING',stage_code='CLEANING_UP',page_sequence=1,
			page_digest=$2,relation_page_sequence=1,relation_page_digest=$4,
			checkpoint_version=1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
			observed_count=2,created_count=2,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('b',64),work_result_recorded_at=statement_timestamp(),
			version=run.version+1 WHERE run.id=$1
	`, fixture.runID, pageDigest, fixture.sourceID, relationDigest)
	if err := pageTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit authoritative source page: %v", err)
	}
	revokeClosureAttempt(t, database, fixture, fixture.runID, strings.Repeat("c", 64))
	terminalTx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin authoritative terminal closure: %v", err)
	}
	defer func() { _ = terminalTx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, terminalTx, fixture.runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, terminalTx, fixture, fixture.runID, terminalDigest)
	execAssetSQL(t, terminalTx, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, fixture.runID, terminalDigest)
	execAssetSQL(t, terminalTx, `
		UPDATE asset_sources
		SET last_success_run_id=$2,last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1 WHERE id=$1
	`, fixture.sourceID, fixture.runID)
	if err := terminalTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit authoritative terminal closure: %v", err)
	}
	return fixture
}

func insertClosureExternalObservation(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	observationID string,
	assetID string,
	externalID string,
	displayName string,
	chain string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		WITH accepted AS (SELECT transaction_timestamp() AS observed_at), payload AS (
			SELECT observed_at,
				convert_to(jsonb_build_object('display_name',$7,'kind','LINUX_VM')::text,'UTF8') AS document,
				convert_to(jsonb_build_object('display_name',jsonb_build_object(
					'source_id',$4::text,'provider_kind','EXTERNAL_V1','source_revision',1,
					'observed_at',to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
					'provider_path_code','external.display_name','confidence',100,'ownership','SOURCE'))::text,'UTF8') AS provenance
			FROM accepted
		), inserted AS (
			INSERT INTO asset_observations (
				id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
				source_revision,canonical_revision_digest,source_definition_digest,observed_at,freshness_kind,
				freshness_order_sequence,provider_version_sha256,provider_fact_sha256,fingerprint_sha256,
				provider_provenance_sha256,observation_chain_sha256,accepted_checkpoint_version,
				run_fence_epoch,run_page_sequence,schema_version,normalized_document,document_sha256,
				field_provenance,field_provenance_sha256
			) SELECT $1,$2,$3,$5,$4,$6,'EXTERNAL_V1',$8,1,$9,$12,observed_at,'OBJECT_SEQUENCE',1,
				repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),$10,1,1,1,'asset.v1',document,
				encode(sha256(document),'hex'),provenance,encode(sha256(provenance),'hex') FROM payload
			RETURNING observed_at
		)
		INSERT INTO assets (
			id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,kind,display_name,
			last_observation_id,last_observation_chain_sha256,last_observed_at,last_source_revision,
			create_idempotency_key,create_request_hash
		) SELECT $11,$2,$3,$5,$4,'EXTERNAL_V1',$8,'LINUX_VM',$7,$1,$10,observed_at,1,
			'create-'||$8,repeat('5',64) FROM inserted
	`, observationID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID,
		fixture.runID, displayName, externalID, fixture.revisionDigest, chain, assetID,
		fixture.sourceDefinitionDigest)
}

func seedClosureExternalProjectionEdges(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
) {
	t.Helper()
	details := []byte(`{"cpu_count":4}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_type_details (
			id,tenant_id,workspace_id,environment_id,asset_id,source_id,provider_kind,external_id,
			source_revision,source_observed_at,source_observation_chain_sha256,revision,schema_version,
			source_observation_id,details_document,details_sha256,actor_id
		) SELECT $1,$2,$3,$4,$5,$6,'EXTERNAL_V1','external-host-a',1,o.observed_at,o.observation_chain_sha256,
			1,'linux-vm.v1',o.id,$7,encode(sha256($7),'hex'),'closure-worker'
		FROM asset_observations o WHERE o.id=$8
	`, fixture.typeDetailID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.assetID, fixture.sourceID, details, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_conflicts (
			id,tenant_id,workspace_id,environment_id,asset_id,candidate_asset_id,source_id,observation_id,
			conflict_type,status
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'FINGERPRINT_COLLISION','OPEN')
	`, fixture.conflictID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.assetID, fixture.secondAssetID, fixture.sourceID, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_relationships (
			id,tenant_id,workspace_id,source_id,source_revision,canonical_revision_digest,last_run_id,
			last_page_sequence,relation_page_sha256,accepted_checkpoint_version,run_fence_epoch,
			source_environment_id,target_environment_id,source_asset_id,target_asset_id,
			from_external_id,to_external_id,relationship_type,provider_path_code,confidence,freshness_kind,
			freshness_order_sequence,provider_version_sha256,relation_fact_sha256,provenance,
			provenance_source_id,status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,1,$5,$6,1,repeat('d',64),1,1,$7,$7,$8,$9,
			'external-host-a','external-host-b','DEPENDS_ON','external.depends_on',100,'OBJECT_SEQUENCE',1,
			repeat('7',64),repeat('8',64),'DISCOVERED',$4,'ACTIVE',
			'relationship-create-'||$4::text,repeat('9',64))
	`, fixture.relationshipID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest, fixture.runID, fixture.environmentID, fixture.assetID, fixture.secondAssetID)
	execAssetSQL(t, database, `
		INSERT INTO service_asset_bindings (
			id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,mapping_status,
			provenance,provenance_source_id,status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,'PRIMARY_RUNTIME','EXACT','DISCOVERED',$7,'ACTIVE',
			'binding-create-'||$7::text,repeat('a',64))
	`, fixture.bindingID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.serviceID, fixture.assetID, fixture.sourceID)
}

func startClosureExternalDiscoveryRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) runtimeContractRun {
	t.Helper()
	run := runtimeContractRun{id: "8f600000-0000-4000-8000-000000000001"}
	var gateRevision int64
	var checkpointSHA *string
	if err := database.QueryRow(context.Background(), `
		SELECT source.published_revision,source.published_revision_digest,
			revision.source_definition_digest,source.gate_revision,
			source.checkpoint_version,source.checkpoint_sha256,source.provider_kind
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.source_id=source.id AND revision.revision=source.published_revision
		WHERE source.id=$1
	`, fixture.sourceID).Scan(&run.revision, &run.revisionDigest,
		&run.sourceDefinitionDigest, &gateRevision, &run.checkpointVersion,
		&checkpointSHA, &run.providerKind); err != nil {
		t.Fatalf("read external discovery admission: %v", err)
	}
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) VALUES ($1,$2,$3,$4,$5,$6,'DISCOVERY','SCHEDULED',$7,
			'closure-rollover-discovery',repeat('1',64),$8,$9)
	`, run.id, fixture.tenantID, fixture.workspaceID, fixture.sourceID, run.revision,
		run.revisionDigest, gateRevision, checkpointSHA, run.checkpointVersion)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='closure-rollover-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('2',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, run.id)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, run.id)
	if err := database.QueryRow(context.Background(), `
		SELECT checkpoint_version,fence_epoch,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&run.checkpointVersion, &run.fenceEpoch, &run.pageSequence); err != nil {
		t.Fatalf("read external discovery coordinates: %v", err)
	}
	return run
}

func bindClosureExternalRollover(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin rollover binding: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) VALUES (
			gen_random_uuid(),$1,$2,'SYSTEM','closure-rollover-worker',
			'CHECKPOINT_LINEAGE_ROLLOVER_BOUND','ASSET_SOURCE_RUN',$3,
			'source-rollover:'||$3,'rollover-binding-trace',repeat('b',64)
		)
	`, fixture.tenantID, fixture.workspaceID, run.id); err != nil {
		t.Fatalf("insert rollover binding receipt: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET gate_status='DEGRADED',gate_reason_code='CHECKPOINT_LINEAGE_ROLLOVER',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID); err != nil {
		t.Fatalf("degrade source for rollover: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET lineage_rollover_reason='PROVIDER_CURSOR_EXPIRED',
			lineage_rollover_evidence_digest=repeat('b',64),version=version+1
		WHERE id=$1
	`, run.id); err != nil {
		t.Fatalf("bind rollover evidence to immutable run admission: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit rollover binding: %v", err)
	}
}

func assertClosureExternalObservationAcceptedInRolloverPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	candidate := newRuntimeObservation(fixture, run,
		"8f600000-0000-4000-8000-000000000002", "rollover-external", "3")
	candidate.freshnessKind = "OBJECT_SEQUENCE"
	candidate.freshnessSequence = 1
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external rollover successor page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, run.id)
	if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
		runtimeObservationArguments(candidate)...); err != nil {
		t.Fatalf("insert external rollover observation: %v", err)
	}
	pageDigest := strings.Repeat("d", 64)
	if err := insertClosurePageReceipt(tx, fixture, run.id, run.pageSequence+1, pageDigest); err != nil {
		t.Fatalf("insert external rollover page receipt: %v", err)
	}
	relationDigest := strings.Repeat("e", 64)
	if err := insertClosureRelationPageReceipt(
		tx, fixture, run.id, 1, relationDigest,
	); err != nil {
		t.Fatalf("insert external rollover relation page receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('03',12)||repeat('04',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-key-2',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+1,relation_page_digest=$4,
			checkpoint_version=checkpoint_version+1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
			observed_count=observed_count+1,heartbeat_sequence=heartbeat_sequence+1,
			heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('f',64),version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID, relationDigest)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external rollover successor page: %v", err)
	}
}

func closeClosureExternalRolloverRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	revokeClosureAttempt(t, database, fixture, run.id, strings.Repeat("6", 64))
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external rollover terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, run.id, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_sources
		SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
			last_success_run_id=$2,
			last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, run.id)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external rollover terminal closure: %v", err)
	}

	var closed bool
	if err := database.QueryRow(context.Background(), `
		SELECT run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
			run.effective_complete_snapshot AND source.status='ACTIVE' AND
			source.gate_status='AVAILABLE' AND source.gate_reason_code IS NULL AND
			source.gate_revision=run.gate_revision+2 AND
			source.last_success_run_id=run.id AND source.last_success_at=run.completed_at AND
			source.last_complete_snapshot_run_id=run.id AND
			source.last_complete_snapshot_at=run.completed_at
		FROM asset_source_runs AS run
		JOIN asset_sources AS source ON source.id=run.source_id
		WHERE run.id=$1
	`, run.id).Scan(&closed); err != nil {
		t.Fatalf("read external rollover terminal closure: %v", err)
	}
	if !closed {
		t.Fatal("external rollover did not close with exact effective snapshot, pointers, and gate revision plus two")
	}
}

type qualificationFixtureSharedFacts struct {
	gateRevision            int64
	sourceCheckpointVersion int64
	sourceCheckpointSHA256  *string
	sourceLastSuccessRunID  *string
	sourceLastSuccessAt     *time.Time
	sourceLastCompleteRunID *string
	sourceLastCompleteAt    *time.Time
	providerKind            string
	sourceDefinitionDigest  string
	scopeDigest             string
	bindingDigest           string
	profileDescriptorDigest string
	runtimeManifestDigest   string
	labBindingDigest        string
	receiptExpiresAt        time.Time
}

type qualificationFixtureReceipt struct {
	runID         string
	receiptDigest string
}

type qualificationFixtureReceipts struct {
	facts  qualificationFixtureSharedFacts
	ha     qualificationFixtureReceipt
	canary qualificationFixtureReceipt
}

type qualificationFixtureSeal struct {
	evidenceKind            string
	scopeDigest             string
	bindingDigest           string
	profileDescriptorDigest string
	runtimeManifestDigest   string
	labBindingDigest        string
	priorReceiptsDigest     string
	resultDigest            string
	issuedAt                time.Time
	expiresAt               time.Time
	signingKeyID            string
	signature               string
	receiptDigest           string
	haOwnerWorker           *string
	haTakeoverWorker        *string
	haOwnerProcess          *string
	haTakeoverProcess       *string
	haTakeoverReceipt       *string
	haRestartReceipt        *string
	haSessionRecovery       *string
	haCleanupReceipt        *string
	haResponseLossReceipt   *string
	haFactChain             *string
}

func sealSyntheticQualificationFixtures(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	revision int64,
) qualificationFixtureReceipts {
	t.Helper()
	var facts qualificationFixtureSharedFacts
	if err := database.QueryRow(context.Background(), `
		SELECT source.gate_revision,source.checkpoint_version,source.checkpoint_sha256,
			source.last_success_run_id,source.last_success_at,
			source.last_complete_snapshot_run_id,source.last_complete_snapshot_at,
			source.provider_kind,revision.source_definition_digest,
			clock_timestamp()+interval '30 minutes'
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.tenant_id=source.tenant_id
		 AND revision.workspace_id=source.workspace_id
		 AND revision.source_id=source.id
		 AND revision.revision=source.published_revision
		 AND revision.canonical_revision_digest=source.published_revision_digest
		WHERE source.id=$1 AND revision.id=$2
	`, fixture.sourceID, fixture.revisionID).Scan(
		&facts.gateRevision,
		&facts.sourceCheckpointVersion,
		&facts.sourceCheckpointSHA256,
		&facts.sourceLastSuccessRunID,
		&facts.sourceLastSuccessAt,
		&facts.sourceLastCompleteRunID,
		&facts.sourceLastCompleteAt,
		&facts.providerKind,
		&facts.sourceDefinitionDigest,
		&facts.receiptExpiresAt,
	); err != nil {
		t.Fatalf("read synthetic-test-only qualification fixture facts: %v", err)
	}
	facts.bindingDigest = fixture.revisionDigest
	facts.scopeDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-qualification-scope.v1"),
		[]byte(fixture.tenantID),
		[]byte(fixture.workspaceID),
		[]byte(fixture.sourceID),
	)
	facts.profileDescriptorDigest = facts.sourceDefinitionDigest
	facts.runtimeManifestDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("synthetic-test-only-qualification-runtime-manifest.v1"),
		[]byte(facts.providerKind),
		assetCatalogCorrectiveDecodeDigest(t, facts.profileDescriptorDigest),
	)
	facts.labBindingDigest = assetCatalogCorrectiveFramedDigest(
		[]byte("synthetic-test-only-qualification-lab-binding.v1"),
		[]byte(fixture.sourceID),
		[]byte(strconv.FormatInt(revision, 10)),
	)

	haReceipt := sealSyntheticQualificationReceipt(
		t,
		database,
		fixture,
		revision,
		facts,
		"TWO_WORKER_HA",
		nil,
	)
	canaryReceipt := sealSyntheticQualificationReceipt(
		t,
		database,
		fixture,
		revision,
		facts,
		"PROVIDER_CANARY",
		[]string{haReceipt.receiptDigest},
	)
	qualificationFixtureRequireClosedTerminals(
		t, database, fixture, facts, haReceipt, canaryReceipt,
	)
	return qualificationFixtureReceipts{
		facts:  facts,
		ha:     haReceipt,
		canary: canaryReceipt,
	}
}

func beginSyntheticQualificationOwnerTx(
	t *testing.T,
	database *pgxpool.Pool,
	stage string,
) pgx.Tx {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin synthetic-test-only qualification %s: %v", stage, err)
	}
	if _, err := tx.Exec(context.Background(), `SET LOCAL ROLE aiops_schema_owner`); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatalf("assume migration owner for synthetic-test-only qualification %s: %v", stage, err)
	}
	return tx
}

func execSyntheticQualificationOwnerTransition(
	t *testing.T,
	database *pgxpool.Pool,
	stage string,
	statement string,
	arguments ...any,
) {
	t.Helper()
	tx := beginSyntheticQualificationOwnerTx(t, database, stage)
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, statement, arguments...)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit synthetic-test-only qualification %s: %v", stage, err)
	}
}

func sealSyntheticQualificationReceipt(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	revision int64,
	facts qualificationFixtureSharedFacts,
	evidenceKind string,
	priorReceiptDigests []string,
) qualificationFixtureReceipt {
	t.Helper()
	leaseOwner := "synthetic-test-only-qualification-owner"
	if evidenceKind == "PROVIDER_CANARY" {
		leaseOwner = "synthetic-test-only-qualification-canary"
	}
	idempotencyKey := fmt.Sprintf(
		"synthetic-test-only-%s-%s-%d",
		strings.ToLower(strings.ReplaceAll(evidenceKind, "_", "-")),
		fixture.sourceID,
		revision,
	)
	requestDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("synthetic-test-only-qualification-request.v1"),
		[]byte(fixture.sourceID),
		[]byte(strconv.FormatInt(revision, 10)),
		[]byte(evidenceKind),
	)
	priorDigest := qualificationFixturePriorReceiptsDigest(t, priorReceiptDigests)
	queueTx := beginSyntheticQualificationOwnerTx(t, database, "queue binding")
	defer func() { _ = queueTx.Rollback(context.Background()) }()
	var runID string
	if err := queueTx.QueryRow(context.Background(), `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version,
			qualification_evidence_kind,qualification_scope_digest,
			qualification_binding_digest,qualification_profile_descriptor_digest,
			qualification_runtime_manifest_digest,qualification_lab_binding_digest,
			qualification_prior_receipts_digest
		) VALUES (
			gen_random_uuid(),$1,$2,$3,$4,$5,'QUALIFICATION','API',$6,$7,$8,NULL,0,
			$9,$10,$11,$12,$13,$14,$15
		)
		RETURNING id
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, revision,
		fixture.revisionDigest, facts.gateRevision, idempotencyKey,
		requestDigest, evidenceKind, facts.scopeDigest, facts.bindingDigest,
		facts.profileDescriptorDigest, facts.runtimeManifestDigest,
		facts.labBindingDigest, priorDigest).Scan(&runID); err != nil {
		t.Fatalf("create synthetic-test-only qualification run: %v", err)
	}
	if err := queueTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit synthetic-test-only qualification queue binding: %v", err)
	}
	qualificationFixtureRequireQueuedBinding(t, database, runID, evidenceKind, priorDigest)

	execSyntheticQualificationOwnerTransition(t, database, "claim", `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner=$2,
			lease_expires_at=clock_timestamp()+interval '10 minutes',
			fence_epoch=1,fence_token_hash=$3,heartbeat_sequence=1,
			heartbeat_at=clock_timestamp(),version=version+1
		WHERE id=$1
	`, runID, leaseOwner, assetCatalogCorrectiveFramedDigest(
		[]byte("synthetic-test-only-qualification-fence.v1"),
		[]byte(runID),
		[]byte("1"),
	))

	execSyntheticQualificationOwnerTransition(t, database, "cleanup reservation", `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, runID)
	var cleanupAttemptEpoch int64
	if err := database.QueryRow(context.Background(), `
		SELECT cleanup_attempt_epoch
		FROM asset_source_runs
		WHERE id=$1 AND cleanup_status='PENDING'
	`, runID).Scan(&cleanupAttemptEpoch); err != nil {
		t.Fatalf("read synthetic-test-only cleanup attempt epoch: %v", err)
	}
	cleanupDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("synthetic-test-only-qualification-cleanup.v1"),
		[]byte(runID),
		[]byte(evidenceKind),
		[]byte(strconv.FormatInt(cleanupAttemptEpoch, 10)),
	)
	haFacts := qualificationFixtureHAFacts(
		t,
		fixture,
		revision,
		runID,
		evidenceKind,
		cleanupAttemptEpoch,
		cleanupDigest,
	)
	resultFields := [][]byte{
		[]byte("synthetic-test-only-qualification-result.v1"),
		[]byte(runID),
		[]byte(evidenceKind),
		[]byte(strconv.FormatInt(cleanupAttemptEpoch, 10)),
	}
	if haFacts.factChain != "" {
		resultFields = append(
			resultFields,
			assetCatalogCorrectiveDecodeDigest(t, haFacts.factChain),
		)
	}
	resultDigest := assetCatalogCorrectiveFramedDigest(resultFields...)
	execSyntheticQualificationOwnerTransition(t, database, "WorkResult", `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='QUALIFICATION_PROOF',
			work_result_status='SUCCEEDED',work_result_digest=$2,
			work_result_recorded_at=statement_timestamp(),
			qualification_result_digest=$2,version=version+1
		WHERE id=$1
	`, runID, resultDigest)
	qualificationFixtureRequireUnsealedFinalizing(t, database, runID, "PENDING")

	var (
		recordedAt   time.Time
		currentFence int64
	)
	if err := database.QueryRow(context.Background(), `
		SELECT work_result_recorded_at,fence_epoch
		FROM asset_source_runs
		WHERE id=$1 AND status='FINALIZING' AND cleanup_status='PENDING'
	`, runID).Scan(&recordedAt, &currentFence); err != nil {
		t.Fatalf("read synthetic-test-only qualification result time: %v", err)
	}
	seal := closeSyntheticQualificationReceipt(
		t,
		database,
		fixture,
		runID,
		revision,
		facts,
		evidenceKind,
		priorDigest,
		resultDigest,
		cleanupDigest,
		haFacts,
		recordedAt,
		currentFence,
		cleanupAttemptEpoch,
	)
	return qualificationFixtureReceipt{runID: runID, receiptDigest: seal.receiptDigest}
}

func closeSyntheticQualificationReceipt(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	runID string,
	revision int64,
	facts qualificationFixtureSharedFacts,
	evidenceKind string,
	priorDigest string,
	resultDigest string,
	cleanupDigest string,
	haFacts qualificationFixtureHASeal,
	recordedAt time.Time,
	currentFence int64,
	cleanupAttemptEpoch int64,
) qualificationFixtureSeal {
	t.Helper()
	tx := beginSyntheticQualificationOwnerTx(t, database, "final closure")
	defer func() { _ = tx.Rollback(context.Background()) }()

	insertCleanupAudit(t, tx, fixture, runID, cleanupAttemptEpoch, cleanupDigest)
	var revoked bool
	if err := tx.QueryRow(context.Background(), `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
		WHERE id=$1 AND status='FINALIZING' AND cleanup_status='PENDING'
		  AND fence_epoch=$3 AND cleanup_attempt_epoch=$4
		  AND qualification_result_digest=$5
		RETURNING true
	`, runID, cleanupDigest, currentFence, cleanupAttemptEpoch, resultDigest).Scan(&revoked); err != nil {
		t.Fatalf("record synthetic-test-only qualification cleanup proof: %v", err)
	}
	if !revoked {
		t.Fatal("synthetic-test-only qualification cleanup CAS returned false")
	}
	qualificationFixtureRequireUnsealedFinalizing(t, tx, runID, "REVOKED")

	var issuedAt time.Time
	if err := tx.QueryRow(context.Background(), `
		SELECT date_trunc(
			'microseconds',
			GREATEST(clock_timestamp(),$1::timestamptz+interval '1 microsecond')
		)
	`, recordedAt).Scan(&issuedAt); err != nil {
		t.Fatalf("derive independent synthetic-test-only receipt issued time: %v", err)
	}
	if !issuedAt.After(recordedAt) {
		t.Fatalf("qualification receipt issued_at=%s must be after WorkResult recorded_at=%s",
			issuedAt, recordedAt)
	}
	if !facts.receiptExpiresAt.After(issuedAt) {
		t.Fatalf("qualification receipt expiry=%s must be after issued_at=%s",
			facts.receiptExpiresAt, issuedAt)
	}

	signingKeyID := "synthetic-test-only-signing-key-v1"
	receiptDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-qualification-receipt.v1"),
		[]byte(fixture.tenantID),
		[]byte(fixture.workspaceID),
		[]byte(fixture.sourceID),
		[]byte(strconv.FormatInt(revision, 10)),
		assetCatalogCorrectiveDecodeDigest(t, facts.bindingDigest),
		assetCatalogCorrectiveDecodeDigest(t, facts.profileDescriptorDigest),
		assetCatalogCorrectiveDecodeDigest(t, facts.runtimeManifestDigest),
		assetCatalogCorrectiveDecodeDigest(t, facts.labBindingDigest),
		[]byte(evidenceKind),
		assetCatalogCorrectiveDecodeDigest(t, priorDigest),
		assetCatalogCorrectiveDecodeDigest(t, resultDigest),
		[]byte(qualificationFixtureTimestamp(issuedAt)),
		[]byte(qualificationFixtureTimestamp(facts.receiptExpiresAt)),
		[]byte(signingKeyID),
	)
	signatureMaterial := append(
		assetCatalogCorrectiveDecodeDigest(t, receiptDigest),
		assetCatalogCorrectiveDecodeDigest(t, receiptDigest)...,
	)
	seal := qualificationFixtureSeal{
		evidenceKind:            evidenceKind,
		scopeDigest:             facts.scopeDigest,
		bindingDigest:           facts.bindingDigest,
		profileDescriptorDigest: facts.profileDescriptorDigest,
		runtimeManifestDigest:   facts.runtimeManifestDigest,
		labBindingDigest:        facts.labBindingDigest,
		priorReceiptsDigest:     priorDigest,
		resultDigest:            resultDigest,
		issuedAt:                issuedAt,
		expiresAt:               facts.receiptExpiresAt,
		signingKeyID:            signingKeyID,
		signature:               base64.RawURLEncoding.EncodeToString(signatureMaterial),
		receiptDigest:           receiptDigest,
		haOwnerWorker:           qualificationFixtureOptionalDigest(haFacts.ownerWorker),
		haTakeoverWorker:        qualificationFixtureOptionalDigest(haFacts.takeoverWorker),
		haOwnerProcess:          qualificationFixtureOptionalDigest(haFacts.ownerProcess),
		haTakeoverProcess:       qualificationFixtureOptionalDigest(haFacts.takeoverProcess),
		haTakeoverReceipt:       qualificationFixtureOptionalDigest(haFacts.takeoverReceipt),
		haRestartReceipt:        qualificationFixtureOptionalDigest(haFacts.restartReceipt),
		haSessionRecovery:       qualificationFixtureOptionalDigest(haFacts.sessionRecovery),
		haCleanupReceipt:        qualificationFixtureOptionalDigest(haFacts.cleanupReceipt),
		haResponseLossReceipt:   qualificationFixtureOptionalDigest(haFacts.responseLossReceipt),
		haFactChain:             qualificationFixtureOptionalDigest(haFacts.factChain),
	}

	var sealed bool
	if err := tx.QueryRow(context.Background(), `
		UPDATE asset_source_runs
		SET qualification_receipt_issued_at=$2,qualification_receipt_expires_at=$3,
			qualification_signing_key_id=$4,qualification_signature=$5,
			qualification_receipt_digest=$6,
			ha_owner_worker_identity_digest=$7,ha_takeover_worker_identity_digest=$8,
			ha_owner_process_instance_digest=$9,ha_takeover_process_instance_digest=$10,
			ha_takeover_receipt_digest=$11,ha_restart_receipt_digest=$12,
			ha_session_recovery_receipt_digest=$13,ha_cleanup_receipt_digest=$14,
			ha_response_loss_receipt_digest=$15,ha_fact_chain_digest=$16,
			version=version+1
		WHERE id=$1 AND status='FINALIZING' AND cleanup_status='REVOKED'
		  AND fence_epoch=$17 AND cleanup_attempt_epoch=$18
		  AND qualification_evidence_kind=$19 AND qualification_scope_digest=$20
		  AND qualification_binding_digest=$21
		  AND qualification_profile_descriptor_digest=$22
		  AND qualification_runtime_manifest_digest=$23
		  AND qualification_lab_binding_digest=$24
		  AND qualification_prior_receipts_digest=$25
		  AND qualification_result_digest=$26
		  AND num_nonnulls(
			qualification_receipt_issued_at,qualification_receipt_expires_at,
			qualification_signing_key_id,
			qualification_signature,qualification_receipt_digest,
			ha_owner_worker_identity_digest,ha_takeover_worker_identity_digest,
			ha_owner_process_instance_digest,ha_takeover_process_instance_digest,
			ha_takeover_receipt_digest,ha_restart_receipt_digest,
			ha_session_recovery_receipt_digest,ha_cleanup_receipt_digest,
			ha_response_loss_receipt_digest,ha_fact_chain_digest
		  )=0
		RETURNING true
	`, runID, seal.issuedAt, seal.expiresAt, seal.signingKeyID, seal.signature,
		seal.receiptDigest,
		seal.haOwnerWorker, seal.haTakeoverWorker,
		seal.haOwnerProcess, seal.haTakeoverProcess, seal.haTakeoverReceipt,
		seal.haRestartReceipt, seal.haSessionRecovery, seal.haCleanupReceipt,
		seal.haResponseLossReceipt, seal.haFactChain, currentFence,
		cleanupAttemptEpoch, seal.evidenceKind, seal.scopeDigest, seal.bindingDigest,
		seal.profileDescriptorDigest, seal.runtimeManifestDigest, seal.labBindingDigest,
		seal.priorReceiptsDigest, seal.resultDigest).Scan(&sealed); err != nil {
		t.Fatalf("seal synthetic-test-only qualification receipt: %v", err)
	}
	if !sealed {
		t.Fatal("synthetic-test-only qualification receipt CAS returned false")
	}
	qualificationFixtureRequireSealedFinalizing(t, tx, runID, seal)

	terminalDigest := sourceRunTerminalDigest(t, tx, runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, runID, terminalDigest)
	var terminal bool
	if err := tx.QueryRow(context.Background(), `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',
			terminal_command_sha256=$2,version=version+1
		WHERE id=$1 AND status='FINALIZING'
		  AND qualification_receipt_digest=$3
		RETURNING true
	`, runID, terminalDigest, seal.receiptDigest).Scan(&terminal); err != nil {
		t.Fatalf("close synthetic-test-only qualification terminal: %v", err)
	}
	if !terminal {
		t.Fatal("synthetic-test-only qualification terminal CAS returned false")
	}

	var terminalClosed bool
	if err := tx.QueryRow(context.Background(), `
		SELECT run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
			run.cleanup_status='REVOKED' AND
			run.qualification_receipt_digest=$3 AND
			source.gate_status='UNAVAILABLE' AND
			num_nonnulls(
				source.gate_evidence_run_id,
				source.gate_evidence_digest,
				source.gate_evidence_expires_at
			)=0
		FROM asset_source_runs AS run
		JOIN asset_sources AS source
		  ON source.tenant_id=run.tenant_id
		 AND source.workspace_id=run.workspace_id
		 AND source.id=run.source_id
		WHERE run.id=$1 AND source.id=$2
	`, runID, fixture.sourceID, seal.receiptDigest).Scan(&terminalClosed); err != nil {
		t.Fatalf("verify qualification terminal kept Source gate closed: %v", err)
	}
	if !terminalClosed {
		t.Fatal("qualification terminal fixture wrote Source pointer or AVAILABLE")
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit synthetic-test-only qualification final closure: %v", err)
	}
	return seal
}

type qualificationFixtureHASeal struct {
	ownerWorker         string
	takeoverWorker      string
	ownerProcess        string
	takeoverProcess     string
	takeoverReceipt     string
	restartReceipt      string
	sessionRecovery     string
	cleanupReceipt      string
	responseLossReceipt string
	factChain           string
}

func qualificationFixtureHAFacts(
	t *testing.T,
	fixture assetCatalogFixture,
	revision int64,
	runID string,
	evidenceKind string,
	cleanupAttemptEpoch int64,
	cleanupDigest string,
) qualificationFixtureHASeal {
	t.Helper()
	if evidenceKind != "TWO_WORKER_HA" {
		return qualificationFixtureHASeal{}
	}
	factDigest := func(label string, eventFence int64) string {
		return assetCatalogCorrectiveFramedDigest(
			[]byte("synthetic-test-only-qualification-"+label+".v1"),
			[]byte(runID),
			[]byte(fixture.sourceID),
			[]byte(strconv.FormatInt(revision, 10)),
			[]byte(strconv.FormatInt(eventFence, 10)),
			[]byte(strconv.FormatInt(cleanupAttemptEpoch, 10)),
		)
	}
	facts := qualificationFixtureHASeal{
		ownerWorker:         factDigest("ha-owner-worker", 1),
		takeoverWorker:      factDigest("ha-takeover-worker", 2),
		ownerProcess:        factDigest("ha-owner-process", 1),
		takeoverProcess:     factDigest("ha-takeover-process", 2),
		takeoverReceipt:     factDigest("ha-takeover-receipt", 2),
		restartReceipt:      factDigest("ha-restart-receipt", 2),
		sessionRecovery:     factDigest("ha-session-recovery-receipt", 2),
		cleanupReceipt:      cleanupDigest,
		responseLossReceipt: factDigest("ha-response-loss-receipt", 2),
	}
	facts.factChain = assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-qualification-ha-fact-chain.v1"),
		[]byte(runID),
		[]byte(fixture.sourceID),
		[]byte(strconv.FormatInt(revision, 10)),
		[]byte(strconv.FormatInt(cleanupAttemptEpoch, 10)),
		assetCatalogCorrectiveDecodeDigest(t, facts.ownerWorker),
		assetCatalogCorrectiveDecodeDigest(t, facts.takeoverWorker),
		assetCatalogCorrectiveDecodeDigest(t, facts.ownerProcess),
		assetCatalogCorrectiveDecodeDigest(t, facts.takeoverProcess),
		assetCatalogCorrectiveDecodeDigest(t, facts.takeoverReceipt),
		assetCatalogCorrectiveDecodeDigest(t, facts.restartReceipt),
		assetCatalogCorrectiveDecodeDigest(t, facts.sessionRecovery),
		assetCatalogCorrectiveDecodeDigest(t, facts.cleanupReceipt),
		assetCatalogCorrectiveDecodeDigest(t, facts.responseLossReceipt),
	)
	return facts
}

func qualificationFixtureOptionalDigest(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func qualificationFixturePriorReceiptsDigest(t *testing.T, receipts []string) string {
	t.Helper()
	fields := [][]byte{
		[]byte("qualification-prior-receipts.v1"),
		[]byte(strconv.Itoa(len(receipts))),
	}
	for _, receipt := range receipts {
		fields = append(fields, assetCatalogCorrectiveDecodeDigest(t, receipt))
	}
	return assetCatalogCorrectiveFramedDigest(fields...)
}

func qualificationFixtureTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

func qualificationFixtureRequireQueuedBinding(
	t *testing.T,
	database assetSQLQuerier,
	runID string,
	evidenceKind string,
	priorReceiptsDigest string,
) {
	t.Helper()
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT run.status='QUEUED' AND run.stage_code='WAITING' AND
			run.cleanup_status='NOT_OPENED' AND run.run_kind='QUALIFICATION' AND
			run.qualification_evidence_kind=$2 AND
			run.qualification_prior_receipts_digest=$3 AND
			num_nonnulls(
				run.qualification_evidence_kind,run.qualification_scope_digest,
				run.qualification_binding_digest,run.qualification_profile_descriptor_digest,
				run.qualification_runtime_manifest_digest,run.qualification_lab_binding_digest,
				run.qualification_prior_receipts_digest
			)=7 AND
			num_nonnulls(
				run.qualification_result_digest,
				run.qualification_receipt_issued_at,run.qualification_receipt_expires_at,
				run.qualification_signing_key_id,run.qualification_signature,
				run.qualification_receipt_digest,
				run.ha_owner_worker_identity_digest,run.ha_takeover_worker_identity_digest,
				run.ha_owner_process_instance_digest,run.ha_takeover_process_instance_digest,
				run.ha_takeover_receipt_digest,run.ha_restart_receipt_digest,
				run.ha_session_recovery_receipt_digest,run.ha_cleanup_receipt_digest,
				run.ha_response_loss_receipt_digest,run.ha_fact_chain_digest
			)=0 AND
			run.work_result_kind IS NULL AND run.work_result_status IS NULL AND
			run.work_result_digest IS NULL AND run.work_result_recorded_at IS NULL AND
			run.cursor_before_sha256 IS NULL AND run.cursor_after_sha256 IS NULL AND
			run.checkpoint_version=0 AND run.page_sequence=0 AND
			run.relation_page_sequence=0
		FROM asset_source_runs AS run
		WHERE run.id=$1
	`, runID, evidenceKind, priorReceiptsDigest).Scan(&exact); err != nil {
		t.Fatalf("read immutable synthetic-test-only qualification queue binding: %v", err)
	}
	if !exact {
		t.Fatal("qualification queue fixture omitted or presealed immutable binding facts")
	}
}

func qualificationFixtureRequireUnsealedFinalizing(
	t *testing.T,
	database assetSQLQuerier,
	runID string,
	cleanupStatus string,
) {
	t.Helper()
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT run.status='FINALIZING' AND
			run.cleanup_status=$2 AND
			run.work_result_kind='QUALIFICATION_PROOF' AND
			run.work_result_status='SUCCEEDED' AND
			run.work_result_digest=run.qualification_result_digest AND
			run.work_result_recorded_at IS NOT NULL AND
			run.cursor_before_sha256 IS NULL AND run.cursor_after_sha256 IS NULL AND
			run.checkpoint_version=0 AND
			run.page_sequence=0 AND run.page_digest IS NULL AND
			run.relation_page_sequence=0 AND run.relation_page_digest IS NULL AND
			NOT run.final_page AND NOT run.complete_snapshot AND
			NOT run.effective_complete_snapshot AND
			run.observed_count=0 AND run.created_count=0 AND run.changed_count=0 AND
			run.unchanged_count=0 AND run.conflict_count=0 AND run.missing_count=0 AND
			run.stale_count=0 AND run.restored_count=0 AND
			run.tombstoned_count=0 AND run.rejected_count=0 AND
			num_nonnulls(
				run.qualification_evidence_kind,run.qualification_scope_digest,
				run.qualification_binding_digest,run.qualification_profile_descriptor_digest,
				run.qualification_runtime_manifest_digest,run.qualification_lab_binding_digest,
				run.qualification_prior_receipts_digest,run.qualification_result_digest
			)=8 AND
			num_nonnulls(
				run.qualification_receipt_issued_at,run.qualification_receipt_expires_at,
				run.qualification_signing_key_id,
				run.qualification_signature,run.qualification_receipt_digest,
				run.ha_owner_worker_identity_digest,run.ha_takeover_worker_identity_digest,
				run.ha_owner_process_instance_digest,run.ha_takeover_process_instance_digest,
				run.ha_takeover_receipt_digest,run.ha_restart_receipt_digest,
				run.ha_session_recovery_receipt_digest,run.ha_cleanup_receipt_digest,
				run.ha_response_loss_receipt_digest,run.ha_fact_chain_digest
			)=0
		FROM asset_source_runs AS run
		WHERE run.id=$1
	`, runID, cleanupStatus).Scan(&exact); err != nil {
		t.Fatalf("read unsealed synthetic-test-only qualification result: %v", err)
	}
	if !exact {
		t.Fatal("qualification WorkResult/cleanup fixture changed queue facts or presealed receipt/HA facts")
	}
}

func qualificationFixtureRequireSealedFinalizing(
	t *testing.T,
	database assetSQLQuerier,
	runID string,
	seal qualificationFixtureSeal,
) {
	t.Helper()
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT run.status='FINALIZING' AND run.stage_code='CLEANING_UP' AND
			run.terminal_command_sha256 IS NULL AND
			run.run_kind='QUALIFICATION' AND run.work_result_kind='QUALIFICATION_PROOF' AND
			run.work_result_status='SUCCEEDED' AND run.work_result_digest=$3 AND
			run.cleanup_status='REVOKED' AND run.qualification_evidence_kind=$2 AND
			run.qualification_result_digest=$3 AND run.qualification_receipt_digest=$4 AND
			run.qualification_receipt_issued_at>run.work_result_recorded_at AND
			run.qualification_receipt_expires_at>run.qualification_receipt_issued_at AND
			position('=' IN run.qualification_signature)=0 AND
			num_nonnulls(
				run.qualification_evidence_kind,run.qualification_scope_digest,
				run.qualification_binding_digest,run.qualification_profile_descriptor_digest,
				run.qualification_runtime_manifest_digest,run.qualification_lab_binding_digest,
				run.qualification_prior_receipts_digest,run.qualification_result_digest,
				run.qualification_receipt_issued_at,run.qualification_receipt_expires_at,
				run.qualification_signing_key_id,
				run.qualification_signature,run.qualification_receipt_digest
			)=13 AND
			run.page_sequence=0 AND run.page_digest IS NULL AND
			run.relation_page_sequence=0 AND run.relation_page_digest IS NULL AND
			NOT run.final_page AND NOT run.complete_snapshot AND
			NOT run.effective_complete_snapshot AND
			run.cursor_before_sha256 IS NULL AND run.cursor_after_sha256 IS NULL AND
			run.checkpoint_version=0 AND
			run.observed_count=0 AND run.created_count=0 AND run.changed_count=0 AND
			run.unchanged_count=0 AND run.conflict_count=0 AND run.missing_count=0 AND
			run.stale_count=0 AND run.restored_count=0 AND
			run.tombstoned_count=0 AND run.rejected_count=0 AND
			CASE WHEN $2='PROVIDER_CANARY' THEN
				num_nonnulls(
					run.ha_owner_worker_identity_digest,run.ha_takeover_worker_identity_digest,
					run.ha_owner_process_instance_digest,run.ha_takeover_process_instance_digest,
					run.ha_takeover_receipt_digest,run.ha_restart_receipt_digest,
					run.ha_session_recovery_receipt_digest,run.ha_cleanup_receipt_digest,
					run.ha_response_loss_receipt_digest,run.ha_fact_chain_digest
				)=0
			ELSE
				num_nonnulls(
					run.ha_owner_worker_identity_digest,run.ha_takeover_worker_identity_digest,
					run.ha_owner_process_instance_digest,run.ha_takeover_process_instance_digest,
					run.ha_takeover_receipt_digest,run.ha_restart_receipt_digest,
					run.ha_session_recovery_receipt_digest,run.ha_cleanup_receipt_digest,
					run.ha_response_loss_receipt_digest,run.ha_fact_chain_digest
				)=10 AND
				run.ha_owner_worker_identity_digest<>run.ha_takeover_worker_identity_digest AND
				run.ha_owner_process_instance_digest<>run.ha_takeover_process_instance_digest
			END
		FROM asset_source_runs AS run
		WHERE run.id=$1
	`, runID, seal.evidenceKind, seal.resultDigest, seal.receiptDigest).Scan(&exact); err != nil {
		t.Fatalf("read sealed synthetic-test-only qualification receipt: %v", err)
	}
	if !exact {
		t.Fatalf(
			"FINALIZING qualification %s receipt did not seal exact safe facts",
			seal.evidenceKind,
		)
	}
}

func qualificationFixtureRequireClosedTerminals(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	facts qualificationFixtureSharedFacts,
	ha qualificationFixtureReceipt,
	canary qualificationFixtureReceipt,
) {
	t.Helper()
	runIDs := []string{ha.runID, canary.runID}
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.status='ACTIVE' AND source.gate_status='UNAVAILABLE' AND
			source.gate_revision=$2 AND
			num_nonnulls(
				source.gate_evidence_run_id,
				source.gate_evidence_digest,
				source.gate_evidence_expires_at
			)=0 AND
			source.checkpoint_version=$3 AND
			source.checkpoint_sha256 IS NOT DISTINCT FROM $4 AND
			source.last_success_run_id IS NOT DISTINCT FROM $5 AND
			source.last_success_at IS NOT DISTINCT FROM $6 AND
			source.last_complete_snapshot_run_id IS NOT DISTINCT FROM $7 AND
			source.last_complete_snapshot_at IS NOT DISTINCT FROM $8 AND
			NOT COALESCE(source.last_success_run_id::text=ANY($9::text[]),false) AND
			NOT COALESCE(source.last_complete_snapshot_run_id::text=ANY($9::text[]),false) AND
			(SELECT count(*)
			 FROM asset_source_runs AS run
			 WHERE run.id::text=ANY($9::text[]) AND
				run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
				run.run_kind='QUALIFICATION' AND
				run.work_result_kind='QUALIFICATION_PROOF' AND
				run.work_result_status='SUCCEEDED' AND
				run.work_result_digest=run.qualification_result_digest AND
				run.cleanup_status='REVOKED' AND
				run.qualification_receipt_issued_at>run.work_result_recorded_at AND
				run.qualification_receipt_expires_at>run.qualification_receipt_issued_at AND
				run.terminal_command_sha256 IS NOT NULL)=2
		FROM asset_sources AS source
		WHERE source.id=$1
	`, fixture.sourceID, facts.gateRevision, facts.sourceCheckpointVersion,
		facts.sourceCheckpointSHA256, facts.sourceLastSuccessRunID,
		facts.sourceLastSuccessAt, facts.sourceLastCompleteRunID,
		facts.sourceLastCompleteAt, runIDs).Scan(&exact); err != nil {
		t.Fatalf("read synthetic-test-only closed qualification terminals: %v", err)
	}
	if !exact {
		t.Fatal("qualification terminal closure opened the Source gate or changed Catalog pointers")
	}
}

func qualificationFixtureRequireTerminalClosure(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	facts qualificationFixtureSharedFacts,
	ha qualificationFixtureReceipt,
	canary qualificationFixtureReceipt,
) {
	t.Helper()
	runIDs := []string{ha.runID, canary.runID}
	priorReceiptsDigest := qualificationFixturePriorReceiptsDigest(
		t, []string{ha.receiptDigest},
	)
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.status='ACTIVE' AND source.gate_status='AVAILABLE' AND
			source.gate_reason_code IS NULL AND source.gate_revision=$2+1 AND
			source.checkpoint_version=$3 AND
			source.checkpoint_sha256 IS NOT DISTINCT FROM $4 AND
			source.last_success_run_id IS NOT DISTINCT FROM $5 AND
			source.last_success_at IS NOT DISTINCT FROM $6 AND
			source.last_complete_snapshot_run_id IS NOT DISTINCT FROM $7 AND
			source.last_complete_snapshot_at IS NOT DISTINCT FROM $8 AND
			NOT COALESCE(source.last_success_run_id::text=ANY($9::text[]),false) AND
			NOT COALESCE(source.last_complete_snapshot_run_id::text=ANY($9::text[]),false) AND
			source.gate_evidence_run_id::text=$10 AND
			source.gate_evidence_digest=$11 AND
			source.gate_evidence_expires_at=$12 AND
			source.gate_evidence_expires_at>clock_timestamp() AND
			(SELECT count(*)
			 FROM asset_source_runs AS run
			 WHERE run.id::text=ANY($9::text[]) AND
				run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
				run.run_kind='QUALIFICATION' AND run.cleanup_status='REVOKED' AND
				run.cursor_before_sha256 IS NULL AND run.cursor_after_sha256 IS NULL AND
				run.checkpoint_version=0 AND
				run.page_sequence=0 AND run.page_digest IS NULL AND
				run.relation_page_sequence=0 AND run.relation_page_digest IS NULL AND
				NOT run.final_page AND NOT run.complete_snapshot AND
				NOT run.effective_complete_snapshot AND
				run.qualification_receipt_issued_at>run.work_result_recorded_at AND
				run.qualification_receipt_expires_at>run.qualification_receipt_issued_at AND
				run.observed_count=0 AND run.created_count=0 AND run.changed_count=0 AND
				run.unchanged_count=0 AND run.conflict_count=0 AND run.missing_count=0 AND
				run.stale_count=0 AND run.restored_count=0 AND
				run.tombstoned_count=0 AND run.rejected_count=0)=2 AND
			(SELECT qualification_prior_receipts_digest
			 FROM asset_source_runs WHERE id=$10)=$13 AND
			(SELECT count(*) FROM asset_observations
			 WHERE run_id::text=ANY($9::text[]))=0 AND
			(SELECT count(*) FROM asset_relationships
			 WHERE last_run_id::text=ANY($9::text[]))=0
		FROM asset_sources AS source
		WHERE source.id=$1
	`, fixture.sourceID, facts.gateRevision, facts.sourceCheckpointVersion,
		facts.sourceCheckpointSHA256, facts.sourceLastSuccessRunID,
		facts.sourceLastSuccessAt, facts.sourceLastCompleteRunID,
		facts.sourceLastCompleteAt, runIDs, canary.runID,
		canary.receiptDigest, facts.receiptExpiresAt,
		priorReceiptsDigest).Scan(&exact); err != nil {
		t.Fatalf("read synthetic-test-only qualification terminal closure: %v", err)
	}
	if !exact {
		t.Fatal("terminal qualification fixtures changed checkpoint, projection, or success pointers")
	}
}

func finishClosureExternalValidation(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	revision int64,
	proof string,
) {
	t.Helper()
	qualificationSchema, err := qualificationFixtureSchemaStateFor(
		context.Background(), database,
	)
	if err != nil {
		t.Fatalf("inspect qualification fixture schema before validation closure: %v", err)
	}
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1 WHERE id=$1
	`, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='VALIDATION_PROOF',
			work_result_status='SUCCEEDED',work_result_digest=$2,
			work_result_recorded_at=statement_timestamp(),validation_outcome='SUCCEEDED',
			validation_digest=$2,validation_proof_digest=$2,version=version+1 WHERE id=$1
	`, fixture.validationRunID, proof)
	revokeClosureAttempt(t, database, fixture, fixture.validationRunID, strings.Repeat("6", 64))
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external validation terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, fixture.validationRunID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_revisions
		SET state='VALIDATED',validation_digest=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, proof)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external validation terminal closure: %v", err)
	}
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1
	`, fixture.revisionID)
	var publicationClosed bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.published_revision=$3 AND
			source.published_revision_digest=revision.canonical_revision_digest AND
			revision.state='PUBLISHED' AND source.gate_status='UNAVAILABLE' AND
			source.gate_reason_code='PUBLISHED_VALIDATION_REFERENCE_DRIFT' AND
			source.gate_revision=run.gate_revision+2 AND
			source.validated_run_id IS NULL AND source.validation_digest IS NULL AND
			source.validated_binding_digest IS NULL
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision ON revision.id=$2
		JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
		WHERE source.id=$1
	`, fixture.sourceID, fixture.revisionID, revision).Scan(&publicationClosed); err != nil {
		t.Fatalf("read external publication fail-closed gate: %v", err)
	}
	if !publicationClosed {
		t.Fatal("external publication did not close the visible validation gate at its exact epoch")
	}
	var qualificationReceipts qualificationFixtureReceipts
	if qualificationSchema == qualificationFixtureSchemaFull {
		qualificationReceipts = sealSyntheticQualificationFixtures(
			t, database, fixture, revision,
		)
	}
	available, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external validation AVAILABLE gate: %v", err)
	}
	defer func() { _ = available.Rollback(context.Background()) }()
	if qualificationSchema == qualificationFixtureSchemaFull {
		// This disposable migration-owner fixture proves only structural closure/recovery.
		// It is never Task 19A2a/19A2b, G2/G4, or Provider availability evidence.
		execAssetSQL(t, available, `SET LOCAL ROLE aiops_schema_owner`)
		execAssetSQL(t, available, `
			UPDATE asset_sources
			SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
				validated_run_id=$2,validation_digest=$3,validated_binding_digest=$4,
				gate_evidence_run_id=$5,gate_evidence_digest=$6,
				gate_evidence_expires_at=$7,version=version+1
			WHERE id=$1 AND gate_status='UNAVAILABLE' AND
				gate_revision=$8 AND
				num_nonnulls(
					gate_evidence_run_id,
					gate_evidence_digest,
					gate_evidence_expires_at
				)=0
		`, fixture.sourceID, fixture.validationRunID, proof, fixture.revisionDigest,
			qualificationReceipts.canary.runID,
			qualificationReceipts.canary.receiptDigest,
			qualificationReceipts.facts.receiptExpiresAt,
			qualificationReceipts.facts.gateRevision)
	} else {
		execAssetSQL(t, available, `
			UPDATE asset_sources
			SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
				validated_run_id=$2,validation_digest=$3,validated_binding_digest=$4,
				version=version+1 WHERE id=$1
		`, fixture.sourceID, fixture.validationRunID, proof, fixture.revisionDigest)
	}
	if err := available.Commit(context.Background()); err != nil {
		t.Fatalf("commit external validation AVAILABLE gate: %v", err)
	}
	if qualificationSchema == qualificationFixtureSchemaFull {
		qualificationFixtureRequireTerminalClosure(
			t,
			database,
			fixture,
			qualificationReceipts.facts,
			qualificationReceipts.ha,
			qualificationReceipts.canary,
		)
	}
}

func revokeClosureAttempt(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	runID string,
	digest string,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external cleanup proof: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var epoch int64
	if err := tx.QueryRow(context.Background(), `
		SELECT cleanup_attempt_epoch FROM asset_source_runs WHERE id=$1
	`, runID).Scan(&epoch); err != nil {
		t.Fatalf("read external cleanup epoch: %v", err)
	}
	insertCleanupAudit(t, tx, fixture, runID, epoch, digest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1 WHERE id=$1
	`, runID, digest)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external cleanup proof: %v", err)
	}
}

func publishClosureExternalSuccessor(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	fixture = seedClosureExternalSuccessorDefinition(
		t,
		database,
		fixture,
		"8f500000-0000-4000-8000-000000000002",
		2,
		"EXTERNAL_V1",
		[]byte(`{"type":"object","version":2}`),
		"DEFINITION_CHANGE",
	)
	fixture.validationRunID = "8f500000-0000-4000-8000-000000000003"
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='UNAVAILABLE',gate_reason_code='VALIDATION_REQUESTED',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,2,$5,'VALIDATION','HUMAN',gate_revision,
			'closure-successor-validation',repeat('e',64),0 FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest)
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='VALIDATING',lease_owner='closure-successor-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('f',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, fixture.validationRunID)
	finishClosureExternalValidation(t, database, fixture, 2, strings.Repeat("c", 64))
}

func prepareCleanupUncertainValidationRun(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id='8d000000-0000-4000-8000-000000000001',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='VALIDATION_PROOF',
			work_result_status='FAILED',work_result_digest=repeat('f',64),
			work_result_recorded_at=statement_timestamp(),validation_outcome='FAILED',
			validation_digest=repeat('f',64),validation_proof_digest=repeat('f',64),
			version=version+1
		WHERE id=$1
	`, fixture.validationRunID)
}

func finalizeClosureEmptyManualPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin closure empty final page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	pageDigest := strings.Repeat("c", 64)
	if err := insertClosurePageReceipt(tx, fixture, run.id, run.pageSequence+1, pageDigest); err != nil {
		t.Fatalf("insert closure page receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('07',12)||repeat('08',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-closure-key',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			checkpoint_version=checkpoint_version+1,final_page=true,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			complete_snapshot=false,effective_complete_snapshot=false,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('d',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit closure empty final page: %v", err)
	}
	revokeClosureAttempt(t, database, fixture, run.id, strings.Repeat("e", 64))
}

func reserveClosureCleanupAttempt(t *testing.T, database assetSQLExecutor, runID string) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id='8d000000-0000-4000-8000-000000000002',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, runID)
}

func closeClosureManualRun(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
	runID string,
) error {
	t.Helper()
	terminalDigest := sourceRunTerminalDigest(t, tx, runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, runID, terminalDigest)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, runID, terminalDigest); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET last_success_run_id=$2,
			last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, runID)
	return err
}

func insertClosurePageReceipt(
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	runID string,
	pageSequence int64,
	pageDigest string,
) error {
	_, err := database.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) SELECT gen_random_uuid(),$1,$2,'SYSTEM',run.lease_owner,'PAGE_APPLIED',
			'ASSET_SOURCE_RUN',$3,'source-page:'||$3||':'||$4,
			'closure-page-trace',$5
		FROM asset_source_runs AS run WHERE run.id=$3
	`, fixture.tenantID, fixture.workspaceID, runID, pageSequence, pageDigest)
	return err
}

func insertClosureRelationPageReceipt(
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	runID string,
	pageSequence int64,
	pageDigest string,
) error {
	_, err := database.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) SELECT gen_random_uuid(),$1,$2,'SYSTEM',run.lease_owner,'RELATION_PAGE_COMMITTED',
			'ASSET_SOURCE_RUN',$3,'source-relation-page:'||$3||':'||$4,
			'closure-relation-page-trace',$5
		FROM asset_source_runs AS run WHERE run.id=$3
	`, fixture.tenantID, fixture.workspaceID, runID, pageSequence, pageDigest)
	return err
}

func insertClosureManualRevisionExpectingError(
	t *testing.T,
	database interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	fixture assetCatalogFixture,
	profile string,
	referenceColumn string,
	constraint string,
) {
	t.Helper()
	credentialReference := "NULL"
	trustReference := "NULL"
	networkReference := "NULL"
	switch referenceColumn {
	case "credential_reference_id":
		credentialReference = "'opaque-credential'"
	case "trust_reference_id":
		trustReference = "'opaque-trust'"
	case "network_policy_reference_id":
		networkReference = "'opaque-network'"
	}
	query := `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,trust_reference_id,network_policy_reference_id,
			rate_limit_requests,rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,
			expected_source_version
		) SELECT '8e000000-0000-4000-8000-000000000010',$1,$2,$3,2,
			convert_to('{"type":"object"}','UTF8'),
			encode(sha256(convert_to('{"type":"object"}','UTF8')),'hex'),$4,'MANUAL',
			repeat('3',64),repeat('4',64),repeat('5',64),` + credentialReference + `,` +
		trustReference + `,` + networkReference + `,100,60,1,60,$5,
			'closure-test','PROFILE_CHANGE',source.version
		FROM asset_sources AS source WHERE source.id=$3
	`
	expectClosureStatementError(t, database, "23514", constraint, query,
		fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.integrationID, profile)
}

type closureTxStarter interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func expectClosureCommitError(
	t *testing.T,
	database closureTxStarter,
	isolation pgx.TxIsoLevel,
	state string,
	constraint string,
	mutate func(pgx.Tx) error,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: isolation})
	if err != nil {
		t.Fatalf("begin closure adversarial transaction: %v", err)
	}
	mutationErr := mutate(tx)
	if mutationErr == nil {
		mutationErr = tx.Commit(context.Background())
	} else {
		_ = tx.Rollback(context.Background())
	}
	assertClosurePostgresError(t, mutationErr, state, constraint)
}

func expectClosureStatementError(
	t *testing.T,
	database interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	state string,
	constraint string,
	query string,
	arguments ...any,
) {
	t.Helper()
	_, err := database.Exec(context.Background(), query, arguments...)
	assertClosurePostgresError(t, err, state, constraint)
}

func assertClosurePostgresError(t *testing.T, err error, state string, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s constraint %s", state, constraint)
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		t.Fatalf("SQL error=%v, want PostgreSQL %s/%s", err, state, constraint)
	}
	if databaseError.Code != state || databaseError.ConstraintName != constraint {
		t.Fatalf("SQL error=%s/%s (%v), want %s/%s", databaseError.Code,
			databaseError.ConstraintName, err, state, constraint)
	}
}

type futureHookMode string

const (
	futureHookModeDefaultFalse futureHookMode = "default-false"
	futureHookModeNull         futureHookMode = "null"
	futureHookModeInitialOnly  futureHookMode = "initial-only"
	futureHookModeTrue         futureHookMode = "true"
	futureHookModeBomb         futureHookMode = "bomb"
)

type futureHookSourceSpec struct {
	sourceKind     string
	providerKind   string
	profileCode    string
	typedExtension bool
}

type futureHookDefinition struct {
	fixture                  assetCatalogFixture
	sourceKind               string
	providerKind             string
	profileCode              string
	canonicalProfile         []byte
	profileDigest            string
	canonicalProviderSchema  []byte
	providerSchemaDigest     string
	authorityDigest          string
	typedExtensionCode       string
	preparedExtensionDigest  string
	createIdempotencyKey     string
	validationIdempotencyKey string
	discoveryIdempotencyKey  string
	validationProof          string
	failureIntentDigest      string
	cleanupDigest            string
}

func futureHookNewDefinitionPair(
	t *testing.T,
	database *pgxpool.Pool,
	base assetCatalogFixture,
	label string,
) []futureHookDefinition {
	t.Helper()
	specifications := []futureHookSourceSpec{
		{
			sourceKind: "KUBERNETES_OPERATOR", providerKind: "FUTURE_K8S_V1",
			profileCode: "FUTURE_K8S_V1", typedExtension: true,
		},
		{
			sourceKind: "AWX_INVENTORY", providerKind: "FUTURE_AWX_V1",
			profileCode: "FUTURE_AWX_V1", typedExtension: false,
		},
	}
	definitions := make([]futureHookDefinition, 0, len(specifications))
	for _, specification := range specifications {
		definitions = append(definitions,
			futureHookNewDefinition(t, database, base, specification, label))
	}
	return definitions
}

func futureHookNewDefinition(
	t *testing.T,
	database *pgxpool.Pool,
	base assetCatalogFixture,
	specification futureHookSourceSpec,
	label string,
) futureHookDefinition {
	t.Helper()
	fixture := base
	if err := database.QueryRow(context.Background(), `
		SELECT gen_random_uuid()::text,gen_random_uuid()::text,
			gen_random_uuid()::text,gen_random_uuid()::text
	`).Scan(&fixture.sourceID, &fixture.revisionID, &fixture.validationRunID, &fixture.runID); err != nil {
		t.Fatalf("allocate unique future Source fixture UUIDs: %v", err)
	}
	canonicalProfile := futureHookCanonicalProfile(specification)
	canonicalProviderSchema := []byte(`{"additionalProperties":false,"type":"object"}`)
	profileDigestBytes := sha256.Sum256(canonicalProfile)
	providerSchemaDigestBytes := sha256.Sum256(canonicalProviderSchema)
	authorityDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-authority-scope.v1"),
		[]byte("1"),
		[]byte(fixture.environmentID),
	)
	sourceDefinitionDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-definition.v2"),
		[]byte(specification.sourceKind),
		[]byte(specification.providerKind),
		[]byte(specification.profileCode),
		profileDigestBytes[:],
		providerSchemaDigestBytes[:],
	)
	typedExtensionCode := ""
	preparedExtensionDigest := ""
	if specification.typedExtension {
		typedExtensionCode = specification.profileCode
		preparedExtensionDigest = assetCatalogCorrectiveFramedDigest(
			[]byte("future-hook-prepared-extension.v1"), []byte(fixture.sourceID),
		)
	}
	canonicalRevisionDigest := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-source-revision-binding.v1"),
		[]byte(fixture.tenantID),
		[]byte(fixture.workspaceID),
		[]byte(fixture.sourceID),
		[]byte("1"),
		assetCatalogCorrectiveDecodeDigest(t, sourceDefinitionDigest),
		nil,
		[]byte("ON_DEMAND"),
		[]byte("future-hook-credential"),
		nil,
		nil,
		assetCatalogCorrectiveDecodeDigest(t, authorityDigest),
		[]byte("10"),
		[]byte("60"),
		[]byte("1"),
		[]byte("60"),
		[]byte(specification.profileCode),
		nil,
		futureHookOptionalBytes(typedExtensionCode),
		futureHookOptionalDigest(t, preparedExtensionDigest),
	)
	fixture.sourceDefinitionDigest = sourceDefinitionDigest
	fixture.revisionDigest = canonicalRevisionDigest
	keySuffix := strings.ReplaceAll(fixture.sourceID, "-", "")[:12]
	return futureHookDefinition{
		fixture: fixture, sourceKind: specification.sourceKind,
		providerKind: specification.providerKind, profileCode: specification.profileCode,
		canonicalProfile:        canonicalProfile,
		profileDigest:           hex.EncodeToString(profileDigestBytes[:]),
		canonicalProviderSchema: canonicalProviderSchema,
		providerSchemaDigest:    hex.EncodeToString(providerSchemaDigestBytes[:]),
		authorityDigest:         authorityDigest, typedExtensionCode: typedExtensionCode,
		preparedExtensionDigest:  preparedExtensionDigest,
		createIdempotencyKey:     "future-hook-create-" + label + "-" + keySuffix,
		validationIdempotencyKey: "future-hook-validate-" + label + "-" + keySuffix,
		discoveryIdempotencyKey:  "future-hook-discover-" + label + "-" + keySuffix,
		validationProof: assetCatalogCorrectiveFramedDigest(
			[]byte("future-hook-validation-proof.v1"), []byte(fixture.sourceID),
		),
		failureIntentDigest: assetCatalogCorrectiveFramedDigest(
			[]byte("future-hook-failure-intent.v1"), []byte(fixture.runID),
		),
		cleanupDigest: assetCatalogCorrectiveFramedDigest(
			[]byte("future-hook-cleanup-proof.v1"), []byte(fixture.runID),
		),
	}
}

func futureHookCanonicalProfile(specification futureHookSourceSpec) []byte {
	typedExtension := "null"
	if specification.typedExtension {
		typedExtension = `"` + specification.profileCode + `"`
	}
	return []byte(`{"backpressure_base_seconds":1,"backpressure_max_seconds":60,` +
		`"compatibility_class":"` + specification.profileCode + `",` +
		`"credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1",` +
		`"environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_SEQUENCE",` +
		`"integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":1048576,` +
		`"max_page_items":100,"max_page_relations":0,"network_mode":"NONE",` +
		`"parser_code":"` + specification.profileCode + `","profile_code":"` +
		specification.profileCode + `","provider_kind":"` + specification.providerKind + `",` +
		`"rate_limit_requests":10,"rate_limit_window_seconds":60,"relationship_types":[],` +
		`"schedule_mode":"NONE","source_kind":"` + specification.sourceKind + `",` +
		`"sync_mode":"ON_DEMAND","trust_mode":"NONE",` +
		`"trusted_path_codes":["DISPLAY_NAME","EXTERNAL_ID"],` +
		`"typed_extension_code":` + typedExtension + `,` +
		`"version":"asset-source-profile-manifest.v1"}`)
}

func futureHookInsertInitial(tx pgx.Tx, definition futureHookDefinition) error {
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO public.asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,repeat('a',64))
	`, definition.fixture.sourceID, definition.fixture.tenantID, definition.fixture.workspaceID,
		definition.sourceKind, definition.providerKind,
		"future hook "+strings.ToLower(definition.providerKind),
		definition.createIdempotencyKey); err != nil {
		return err
	}
	var typedExtensionCode any
	var preparedExtensionDigest any
	if definition.typedExtensionCode != "" {
		typedExtensionCode = definition.typedExtensionCode
		preparedExtensionDigest = definition.preparedExtensionDigest
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO public.asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_profile_manifest,profile_manifest_sha256,
			canonical_provider_schema,canonical_provider_schema_sha256,
			sync_mode,authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,trust_reference_id,network_policy_reference_id,
			rate_limit_requests,rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,schedule_expression,
			typed_extension_code,prepared_extension_digest,
			created_by,change_reason_code,expected_source_version
		) VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,'ON_DEMAND',$9,$10,$11,
			'future-hook-credential',NULL,NULL,10,60,1,60,$12,NULL,$13,$14,
			'future-hook-test','INITIAL_CREATE',1)
	`, definition.fixture.revisionID, definition.fixture.tenantID,
		definition.fixture.workspaceID, definition.fixture.sourceID,
		definition.canonicalProfile, definition.profileDigest,
		definition.canonicalProviderSchema, definition.providerSchemaDigest,
		definition.authorityDigest, definition.fixture.sourceDefinitionDigest,
		definition.fixture.revisionDigest, definition.profileCode,
		typedExtensionCode, preparedExtensionDigest); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		INSERT INTO public.asset_source_revision_authorities (
			tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES ($1,$2,$3,1,$4,1)
	`, definition.fixture.tenantID, definition.fixture.workspaceID,
		definition.fixture.sourceID, definition.fixture.environmentID)
	return err
}

func futureHookBindValidation(tx pgx.Tx, definition futureHookDefinition) error {
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO public.asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',source.gate_revision,$6,
			repeat('b',64),0
		FROM public.asset_sources AS source WHERE source.id=$4
	`, definition.fixture.validationRunID, definition.fixture.tenantID,
		definition.fixture.workspaceID, definition.fixture.sourceID,
		definition.fixture.revisionDigest, definition.validationIdempotencyKey); err != nil {
		return err
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE public.asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1
		WHERE id=$1
	`, definition.fixture.revisionID, definition.fixture.validationRunID); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		UPDATE public.asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
			version=version+1
		WHERE id=$1
	`, definition.fixture.sourceID, definition.fixture.validationRunID)
	return err
}

func futureHookCreateInitial(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin serializable future Source initial closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	futureHookAssertIsolation(t, tx, "serializable")
	if err := futureHookInsertInitial(tx, definition); err != nil {
		t.Fatalf("insert %s initial future Source closure: %v", definition.sourceKind, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s initial future Source closure: %v", definition.sourceKind, err)
	}
}

func futureHookStartValidation(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin serializable future Source validation gate: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	futureHookAssertIsolation(t, tx, "serializable")
	if err := futureHookBindValidation(tx, definition); err != nil {
		t.Fatalf("bind %s future Source validation: %v", definition.sourceKind, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s future Source VALIDATING gate: %v", definition.sourceKind, err)
	}
}

func futureHookOpenAvailable(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE public.asset_source_runs
		SET status='RUNNING',stage_code='VALIDATING',lease_owner='future-hook-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('c',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, definition.fixture.validationRunID)
	finishClosureExternalValidation(
		t,
		database,
		definition.fixture,
		1,
		definition.validationProof,
	)
	futureHookAssertAvailable(t, database, definition)
}

func futureHookStartDiscoveryFailure(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	futureHookAssertAvailable(t, database, definition)
	execAssetSQL(t, database, `
		INSERT INTO public.asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) SELECT $1,$2,$3,$4,source.published_revision,source.published_revision_digest,
			'DISCOVERY','HUMAN',source.gate_revision,$5,repeat('d',64),
			source.checkpoint_sha256,source.checkpoint_version
		FROM public.asset_sources AS source WHERE source.id=$4
	`, definition.fixture.runID, definition.fixture.tenantID,
		definition.fixture.workspaceID, definition.fixture.sourceID,
		definition.discoveryIdempotencyKey)
	execAssetSQL(t, database, `
		UPDATE public.asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='future-hook-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('e',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, definition.fixture.runID)
	execAssetSQL(t, database, `
		UPDATE public.asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
			version=version+1
		WHERE id=$1
	`, definition.fixture.runID)
	execAssetSQL(t, database, `
		UPDATE public.asset_source_runs
		SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
			work_result_status='FAILED',work_result_digest=$2,
			work_result_recorded_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, definition.fixture.runID, definition.failureIntentDigest)

	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT run.status='FINALIZING' AND run.stage_code='CLEANING_UP' AND
			run.work_result_kind='FAILURE_INTENT' AND run.work_result_status='FAILED' AND
			run.work_result_digest=$2 AND run.cleanup_status='PENDING' AND
			run.cleanup_attempt_id IS NOT NULL AND run.cleanup_attempt_epoch=1 AND
			run.gate_revision=source.gate_revision AND source.gate_status='AVAILABLE' AND
			source.validated_run_id IS NOT NULL AND source.validation_digest IS NOT NULL AND
			source.validated_binding_digest IS NOT NULL
		FROM public.asset_source_runs AS run
		JOIN public.asset_sources AS source ON source.id=run.source_id
		WHERE run.id=$1
	`, definition.fixture.runID, definition.failureIntentDigest).Scan(&exact); err != nil {
		t.Fatalf("read future Source cleanup-uncertain preparation: %v", err)
	}
	if !exact {
		t.Fatalf("%s future Source did not reach exact cleanup-only failure intent",
			definition.sourceKind)
	}
}

func futureHookSuspendCleanupUncertain(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	gateRevision, sourceVersion := futureHookAssertAvailable(t, database, definition)
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin future Source cleanup-uncertain terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	futureHookAssertIsolation(t, tx, "serializable")
	var cleanupEpoch int64
	if err := tx.QueryRow(context.Background(), `
		SELECT cleanup_attempt_epoch FROM public.asset_source_runs WHERE id=$1
	`, definition.fixture.runID).Scan(&cleanupEpoch); err != nil {
		t.Fatalf("read future Source cleanup attempt epoch: %v", err)
	}
	insertCleanupAudit(t, tx, definition.fixture,
		definition.fixture.runID, cleanupEpoch, definition.cleanupDigest)
	execAssetSQL(t, tx, `
		UPDATE public.asset_source_runs
		SET cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
		WHERE id=$1
	`, definition.fixture.runID, definition.cleanupDigest)
	var overrideDigest string
	if err := tx.QueryRow(context.Background(), `
		SELECT public.asset_catalog_source_run_failure_override_digest(
			run,'CLEANUP_UNCERTAIN'
		) FROM public.asset_source_runs AS run WHERE run.id=$1
	`, definition.fixture.runID).Scan(&overrideDigest); err != nil {
		t.Fatalf("derive future Source cleanup-uncertain override: %v", err)
	}
	execAssetSQL(t, tx, `
		UPDATE public.asset_source_runs
		SET failure_code='CLEANUP_UNCERTAIN',terminal_failure_override='CLEANUP_UNCERTAIN',
			terminal_failure_override_digest=$2,version=version+1
		WHERE id=$1
	`, definition.fixture.runID, overrideDigest)
	terminalDigest := sourceRunTerminalDigest(
		t, tx, definition.fixture.runID, "FAILED", "CLEANUP_UNCERTAIN",
	)
	insertTerminalAudit(t, tx, definition.fixture, definition.fixture.runID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE public.asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, definition.fixture.runID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE public.asset_sources
		SET gate_status='SUSPENDED',gate_reason_code='CLEANUP_UNCERTAIN',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, definition.fixture.sourceID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s future Source cleanup-uncertain suspension: %v",
			definition.sourceKind, err)
	}

	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.status='ACTIVE' AND source.gate_status='SUSPENDED' AND
			source.gate_reason_code='CLEANUP_UNCERTAIN' AND
			source.gate_revision=$3 AND source.version=$4 AND
			source.validated_run_id IS NULL AND source.validation_digest IS NULL AND
			source.validated_binding_digest IS NULL AND run.status='FAILED' AND
			run.stage_code='COMPLETED' AND run.cleanup_status='UNCERTAIN' AND
			run.cleanup_digest=$5 AND run.terminal_failure_override='CLEANUP_UNCERTAIN'
		FROM public.asset_sources AS source
		JOIN public.asset_source_runs AS run ON run.source_id=source.id
		WHERE source.id=$1 AND run.id=$2
	`, definition.fixture.sourceID, definition.fixture.runID,
		gateRevision+1, sourceVersion+1, definition.cleanupDigest).Scan(&exact); err != nil {
		t.Fatalf("read future Source cleanup-uncertain suspension: %v", err)
	}
	if !exact {
		t.Fatalf("%s future Source cleanup-uncertain suspension lost exact gate closure",
			definition.sourceKind)
	}
}

func futureHookPauseAvailableReadCommitted(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	gateRevision, sourceVersion := futureHookAssertAvailable(t, database, definition)
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatalf("begin read-committed future Source fail-close: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	futureHookAssertIsolation(t, tx, "read committed")
	if _, err := tx.Exec(context.Background(), `
		UPDATE public.asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
	`, definition.fixture.sourceID); err != nil {
		t.Fatalf("read-committed %s future Source fail-close: %v", definition.sourceKind, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit read-committed %s future Source fail-close: %v",
			definition.sourceKind, err)
	}
	futureHookAssertPausedUnavailable(
		t, database, definition, gateRevision+1, sourceVersion+1,
	)
}

func futureHookCloseSuspendedReadCommitted(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	var gateRevision, sourceVersion int64
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT gate_revision,version,
			status='ACTIVE' AND gate_status='SUSPENDED' AND
			gate_reason_code='CLEANUP_UNCERTAIN' AND validated_run_id IS NULL AND
			validation_digest IS NULL AND validated_binding_digest IS NULL
		FROM public.asset_sources WHERE id=$1
	`, definition.fixture.sourceID).Scan(&gateRevision, &sourceVersion, &exact); err != nil {
		t.Fatalf("read suspended future Source before fail-close: %v", err)
	}
	if !exact {
		t.Fatalf("%s future Source is not exactly SUSPENDED before fail-close",
			definition.sourceKind)
	}
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatalf("begin suspended future Source read-committed fail-close: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	futureHookAssertIsolation(t, tx, "read committed")
	if _, err := tx.Exec(context.Background(), `
		UPDATE public.asset_sources
		SET status='PAUSED',gate_status='UNAVAILABLE',gate_reason_code='SOURCE_NOT_ACTIVE',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, definition.fixture.sourceID); err != nil {
		t.Fatalf("read-committed suspended %s future Source fail-close: %v",
			definition.sourceKind, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit suspended %s future Source fail-close: %v",
			definition.sourceKind, err)
	}
	futureHookAssertPausedUnavailable(
		t, database, definition, gateRevision+1, sourceVersion+1,
	)
}

func futureHookAssertNoResidue(t *testing.T, database *pgxpool.Pool, sourceID string) {
	t.Helper()
	var sources, revisions, authorities, runs int
	if err := database.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*)::integer FROM public.asset_sources WHERE id=$1),
			(SELECT count(*)::integer FROM public.asset_source_revisions WHERE source_id=$1),
			(SELECT count(*)::integer FROM public.asset_source_revision_authorities WHERE source_id=$1),
			(SELECT count(*)::integer FROM public.asset_source_runs WHERE source_id=$1)
	`, sourceID).Scan(&sources, &revisions, &authorities, &runs); err != nil {
		t.Fatalf("read rejected future Source transaction residue: %v", err)
	}
	if sources != 0 || revisions != 0 || authorities != 0 || runs != 0 {
		t.Fatalf("rejected future Source residue source=%d revision=%d authority=%d run=%d",
			sources, revisions, authorities, runs)
	}
}

func futureHookAssertInitial(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	var typedExtensionCode any
	var preparedExtensionDigest any
	if definition.typedExtensionCode != "" {
		typedExtensionCode = definition.typedExtensionCode
		preparedExtensionDigest = definition.preparedExtensionDigest
	}
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.status='ACTIVE' AND source.version=2 AND
			source.gate_status='UNAVAILABLE' AND source.gate_reason_code IS NULL AND
			source.gate_revision=0 AND source.published_revision IS NULL AND
			source.published_revision_digest IS NULL AND source.validated_run_id IS NULL AND
			source.validation_digest IS NULL AND source.validated_binding_digest IS NULL AND
			source.checkpoint_ciphertext IS NULL AND source.checkpoint_key_id IS NULL AND
			source.checkpoint_sha256 IS NULL AND source.checkpoint_revision=0 AND
			source.checkpoint_version=0 AND revision.state='DRAFT' AND revision.version=1 AND
			revision.validation_run_id IS NULL AND revision.validation_digest IS NULL AND
			revision.expected_source_version=1 AND
			revision.canonical_revision_digest=$3 AND
			revision.typed_extension_code IS NOT DISTINCT FROM $4::text AND
			revision.prepared_extension_digest IS NOT DISTINCT FROM $5::text AND
			(SELECT count(*)=1 FROM public.asset_source_revision_authorities AS authority
			 WHERE authority.source_id=source.id AND authority.source_revision=1 AND
			       authority.environment_id=$6 AND authority.canonical_ordinal=1) AND
			(SELECT count(*)=0 FROM public.asset_source_runs AS run WHERE run.source_id=source.id)
		FROM public.asset_sources AS source
		JOIN public.asset_source_revisions AS revision ON revision.source_id=source.id
		WHERE source.id=$1 AND revision.id=$2
	`, definition.fixture.sourceID, definition.fixture.revisionID,
		definition.fixture.revisionDigest, typedExtensionCode, preparedExtensionDigest,
		definition.fixture.environmentID).Scan(&exact); err != nil {
		t.Fatalf("read %s initial future Source closure: %v", definition.sourceKind, err)
	}
	if !exact {
		t.Fatalf("%s future Source did not persist exact version-2 UNAVAILABLE plus DRAFT closure",
			definition.sourceKind)
	}
}

func futureHookAssertValidating(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) {
	t.Helper()
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.status='ACTIVE' AND source.version=3 AND
			source.gate_status='VALIDATING' AND
			source.gate_reason_code='VALIDATION_IN_PROGRESS' AND
			source.gate_revision=1 AND source.validated_run_id=run.id AND
			source.validation_digest IS NULL AND source.validated_binding_digest IS NULL AND
			revision.state='VALIDATING' AND revision.version=2 AND
			revision.validation_run_id=run.id AND revision.validation_digest IS NULL AND
			run.run_kind='VALIDATION' AND run.status='QUEUED' AND run.stage_code='WAITING' AND
			run.gate_revision=0 AND run.checkpoint_version=0
		FROM public.asset_sources AS source
		JOIN public.asset_source_revisions AS revision ON revision.source_id=source.id
		JOIN public.asset_source_runs AS run ON run.id=revision.validation_run_id
		WHERE source.id=$1 AND revision.id=$2 AND run.id=$3
	`, definition.fixture.sourceID, definition.fixture.revisionID,
		definition.fixture.validationRunID).Scan(&exact); err != nil {
		t.Fatalf("read %s future Source VALIDATING closure: %v", definition.sourceKind, err)
	}
	if !exact {
		t.Fatalf("%s future Source did not reach exact later-transaction VALIDATING closure",
			definition.sourceKind)
	}
}

func futureHookAssertAvailable(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
) (int64, int64) {
	t.Helper()
	var gateRevision, sourceVersion int64
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.gate_revision,source.version,
			source.status='ACTIVE' AND source.gate_status='AVAILABLE' AND
			source.gate_reason_code IS NULL AND source.gate_revision=3 AND
			source.published_revision=1 AND
			source.published_revision_digest=revision.canonical_revision_digest AND
			source.checkpoint_revision=1 AND source.checkpoint_version=0 AND
			source.validated_run_id=run.id AND source.validation_digest=$4 AND
			source.validated_binding_digest=revision.canonical_revision_digest AND
			revision.state='PUBLISHED' AND revision.validation_digest=$4 AND
			run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
			run.work_result_kind='VALIDATION_PROOF' AND
			run.work_result_status='SUCCEEDED' AND run.validation_outcome='SUCCEEDED'
		FROM public.asset_sources AS source
		JOIN public.asset_source_revisions AS revision ON revision.source_id=source.id
		JOIN public.asset_source_runs AS run ON run.id=revision.validation_run_id
		WHERE source.id=$1 AND revision.id=$2 AND run.id=$3
	`, definition.fixture.sourceID, definition.fixture.revisionID,
		definition.fixture.validationRunID, definition.validationProof).Scan(
		&gateRevision,
		&sourceVersion,
		&exact,
	); err != nil {
		t.Fatalf("read %s future Source AVAILABLE closure: %v", definition.sourceKind, err)
	}
	if !exact {
		t.Fatalf("%s future Source did not reach exact published AVAILABLE closure",
			definition.sourceKind)
	}
	return gateRevision, sourceVersion
}

func futureHookAssertPausedUnavailable(
	t *testing.T,
	database *pgxpool.Pool,
	definition futureHookDefinition,
	wantGateRevision int64,
	wantSourceVersion int64,
) {
	t.Helper()
	var exact bool
	if err := database.QueryRow(context.Background(), `
		SELECT status='PAUSED' AND gate_status='UNAVAILABLE' AND
			gate_reason_code='SOURCE_NOT_ACTIVE' AND gate_revision=$2 AND version=$3 AND
			validated_run_id IS NULL AND validation_digest IS NULL AND
			validated_binding_digest IS NULL
		FROM public.asset_sources WHERE id=$1
	`, definition.fixture.sourceID, wantGateRevision, wantSourceVersion).Scan(&exact); err != nil {
		t.Fatalf("read %s future Source PAUSED/UNAVAILABLE fail-close: %v",
			definition.sourceKind, err)
	}
	if !exact {
		t.Fatalf("%s future Source fail-close did not clear all validation fields at gate +1",
			definition.sourceKind)
	}
}

func futureHookAssertIsolation(t *testing.T, tx pgx.Tx, want string) {
	t.Helper()
	var got string
	if err := tx.QueryRow(context.Background(), `
		SELECT current_setting('transaction_isolation')
	`).Scan(&got); err != nil {
		t.Fatalf("read future Source transaction isolation: %v", err)
	}
	if got != want {
		t.Fatalf("future Source transaction isolation=%q, want %q", got, want)
	}
}

func futureHookReplace(t *testing.T, migration *pgxpool.Pool, mode futureHookMode) {
	t.Helper()
	definition := futureHookReplacementSQL(t, mode)
	tx, err := migration.BeginTx(context.Background(), pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin future Source hook owner replacement: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var sessionUser, currentUser string
	if err := tx.QueryRow(context.Background(), `SELECT session_user,current_user`).Scan(
		&sessionUser, &currentUser,
	); err != nil {
		t.Fatalf("read future Source hook replacement identity: %v", err)
	}
	if sessionUser != "aiops_migrator" || currentUser != "aiops_migrator" {
		t.Fatalf("future Source hook replacement identity=%s/%s, want migrator/migrator",
			sessionUser, currentUser)
	}
	if _, err := tx.Exec(context.Background(), `SET LOCAL ROLE aiops_schema_owner`); err != nil {
		t.Fatalf("set future Source hook schema-owner role: %v", err)
	}
	if err := tx.QueryRow(context.Background(), `SELECT session_user,current_user`).Scan(
		&sessionUser, &currentUser,
	); err != nil {
		t.Fatalf("read future Source hook owner identity: %v", err)
	}
	if sessionUser != "aiops_migrator" || currentUser != "aiops_schema_owner" {
		t.Fatalf("future Source hook owner identity=%s/%s, want migrator/schema-owner",
			sessionUser, currentUser)
	}
	if _, err := tx.Exec(context.Background(), definition); err != nil {
		t.Fatalf("replace future Source hook in mode %s: %v", mode, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit future Source hook mode %s: %v", mode, err)
	}
	futureHookAssertReplacementContract(t, migration)
}

func futureHookReplacementSQL(t *testing.T, mode futureHookMode) string {
	t.Helper()
	body := ""
	switch mode {
	case futureHookModeDefaultFalse:
		body = `
BEGIN
    RETURN false;
END;
`
	case futureHookModeNull:
		body = `
BEGIN
    RETURN NULL;
END;
`
	case futureHookModeTrue:
		body = `
BEGIN
    RETURN true;
END;
`
	case futureHookModeBomb:
		body = `
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'future Source hook bomb was invoked',
        CONSTRAINT = 'future_hook_bomb_guard';
END;
`
	case futureHookModeInitialOnly:
		body = `
BEGIN
    RETURN candidate.source_kind IN ('KUBERNETES_OPERATOR', 'AWX_INVENTORY') AND
        candidate.status = 'ACTIVE' AND candidate.version = 2 AND
        candidate.gate_status = 'UNAVAILABLE' AND candidate.gate_reason_code IS NULL AND
        candidate.gate_revision = 0 AND candidate.published_revision IS NULL AND
        candidate.published_revision_digest IS NULL AND candidate.validated_run_id IS NULL AND
        candidate.validation_digest IS NULL AND candidate.validated_binding_digest IS NULL AND
        candidate.checkpoint_ciphertext IS NULL AND candidate.checkpoint_key_id IS NULL AND
        candidate.checkpoint_sha256 IS NULL AND candidate.checkpoint_revision = 0 AND
        candidate.checkpoint_version = 0 AND candidate.next_allowed_at IS NULL AND
        candidate.consecutive_failures = 0 AND candidate.last_success_run_id IS NULL AND
        candidate.last_success_at IS NULL AND candidate.last_complete_snapshot_run_id IS NULL AND
        candidate.last_complete_snapshot_at IS NULL AND
        (SELECT pg_catalog.count(*) = 1
         FROM public.asset_source_revisions AS revision
         WHERE revision.tenant_id = candidate.tenant_id
           AND revision.workspace_id = candidate.workspace_id
           AND revision.source_id = candidate.id AND revision.revision = 1
           AND revision.state = 'DRAFT' AND revision.version = 1
           AND revision.expected_source_version = 1
           AND ((candidate.source_kind = 'KUBERNETES_OPERATOR' AND
                 revision.typed_extension_code = revision.profile_code AND
                 revision.prepared_extension_digest IS NOT NULL) OR
                (candidate.source_kind = 'AWX_INVENTORY' AND
                 revision.typed_extension_code IS NULL AND
                 revision.prepared_extension_digest IS NULL))) AND
        (SELECT pg_catalog.count(*) = 1
         FROM public.asset_source_revision_authorities AS authority
         WHERE authority.tenant_id = candidate.tenant_id
           AND authority.workspace_id = candidate.workspace_id
           AND authority.source_id = candidate.id AND authority.source_revision = 1
           AND authority.canonical_ordinal = 1);
END;
`
	default:
		t.Fatalf("unknown future Source hook mode %q", mode)
	}
	return `CREATE OR REPLACE FUNCTION public.asset_catalog_future_source_gate_admitted(
    candidate public.asset_sources
) RETURNS boolean AS $$` + body + `$$ LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp;`
}

func futureHookAssertReplacementContract(t *testing.T, migration *pgxpool.Pool) {
	t.Helper()
	var count int
	var exact bool
	if err := migration.QueryRow(context.Background(), `
		SELECT count(*)::integer,COALESCE(bool_and(
			p.prokind='f' AND NOT p.proretset AND p.pronargs=1 AND
			argument_type.typname='asset_sources' AND
			argument_namespace.nspname='public' AND
			p.prorettype='pg_catalog.bool'::regtype::oid AND language.lanname='plpgsql' AND
			p.provolatile='s' AND NOT p.prosecdef AND
			p.proconfig IS NOT DISTINCT FROM
				ARRAY['search_path=pg_catalog, public, pg_temp']::text[] AND
			pg_catalog.pg_get_userbyid(p.proowner)='aiops_schema_owner' AND
			pg_catalog.has_function_privilege(
				'aiops_control_plane_runtime',p.oid,'EXECUTE'
			) AND NOT EXISTS (
				SELECT 1
				FROM pg_catalog.aclexplode(COALESCE(
					p.proacl,pg_catalog.acldefault('f',p.proowner)
				)) AS acl
				WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
			)
		),false)
		FROM pg_catalog.pg_proc AS p
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=p.pronamespace
		JOIN pg_catalog.pg_language AS language ON language.oid=p.prolang
		LEFT JOIN pg_catalog.pg_type AS argument_type ON argument_type.oid=p.proargtypes[0]
		LEFT JOIN pg_catalog.pg_namespace AS argument_namespace
			ON argument_namespace.oid=argument_type.typnamespace
		WHERE namespace.nspname='public' AND
			p.proname='asset_catalog_future_source_gate_admitted'
	`).Scan(&count, &exact); err != nil {
		t.Fatalf("inspect future Source hook replacement contract: %v", err)
	}
	if count != 1 || !exact {
		t.Fatalf("future Source hook replacement count=%d exact=%v, want one exact owner/signature/ACL contract",
			count, exact)
	}
}

func futureHookDefinitionDigest(t *testing.T, migration *pgxpool.Pool) string {
	t.Helper()
	tx, err := migration.BeginTx(context.Background(), pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin future Source hook definition fingerprint: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		SET LOCAL quote_all_identifiers=off;
		SET LOCAL search_path=pg_catalog,pg_temp
	`); err != nil {
		t.Fatalf("pin future Source hook definition fingerprint GUCs: %v", err)
	}
	var digest string
	if err := tx.QueryRow(context.Background(), `
		SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
			pg_catalog.pg_get_functiondef(p.oid),'UTF8'
		)),'hex')
		FROM pg_catalog.pg_proc AS p
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=p.pronamespace
		JOIN pg_catalog.pg_type AS argument_type ON argument_type.oid=p.proargtypes[0]
		JOIN pg_catalog.pg_namespace AS argument_namespace
			ON argument_namespace.oid=argument_type.typnamespace
		WHERE namespace.nspname='public' AND
			p.proname='asset_catalog_future_source_gate_admitted' AND
			p.pronargs=1 AND argument_type.typname='asset_sources' AND
			argument_namespace.nspname='public'
	`).Scan(&digest); err != nil {
		t.Fatalf("fingerprint future Source hook definition: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit future Source hook definition fingerprint: %v", err)
	}
	return digest
}

func futureHookOptionalBytes(value string) []byte {
	if value == "" {
		return nil
	}
	return []byte(value)
}

func futureHookOptionalDigest(t *testing.T, value string) []byte {
	t.Helper()
	if value == "" {
		return nil
	}
	return assetCatalogCorrectiveDecodeDigest(t, value)
}
