package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAssetCatalogObservationAdmissionRuntimeACLAllowsImmutablePriorChain(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	var externalID, priorChain string
	if err := harness.application.QueryRow(context.Background(), `
		SELECT external_id,observation_chain_sha256
		FROM asset_observations
		WHERE id=$1
	`, fixture.observationID).Scan(&externalID, &priorChain); err != nil {
		t.Fatalf("application runtime ordinary prior Observation SELECT: %v", err)
	}

	var runtimeCanUpdate, runtimeCanUpdateAnyColumn, runtimeCanDelete, runtimeCanTruncate bool
	var observationAdmissionSecurityDefiner bool
	if err := harness.application.QueryRow(context.Background(), `
		SELECT
			has_table_privilege(current_user,'public.asset_observations','UPDATE'),
			has_any_column_privilege(current_user,'public.asset_observations','UPDATE'),
			has_table_privilege(current_user,'public.asset_observations','DELETE'),
			has_table_privilege(current_user,'public.asset_observations','TRUNCATE'),
			(SELECT candidate.prosecdef
			 FROM pg_catalog.pg_proc AS candidate
			 WHERE candidate.oid=pg_catalog.to_regprocedure(
				'public.enforce_asset_observation_admission()'
			 ))
	`).Scan(&runtimeCanUpdate, &runtimeCanUpdateAnyColumn, &runtimeCanDelete,
		&runtimeCanTruncate, &observationAdmissionSecurityDefiner); err != nil {
		t.Fatalf("read application runtime Observation UPDATE privilege: %v", err)
	}
	if runtimeCanUpdate || runtimeCanUpdateAnyColumn || runtimeCanDelete || runtimeCanTruncate ||
		observationAdmissionSecurityDefiner {
		t.Fatalf("application runtime Observation mutation privileges update/table=%v/%v delete=%v truncate=%v security_definer=%v, want all false",
			runtimeCanUpdate, runtimeCanUpdateAnyColumn, runtimeCanDelete, runtimeCanTruncate,
			observationAdmissionSecurityDefiner)
	}
	assertObservationRuntimePermissionDenied(t, harness.application, `
		UPDATE asset_observations
		SET source_revision=source_revision
		WHERE id=$1
	`, fixture.observationID)
	assertObservationRuntimePermissionDenied(t, harness.application, `
		SELECT id
		FROM asset_observations
		WHERE id=$1
		FOR SHARE
	`, fixture.observationID)
	assertObservationRuntimePermissionDenied(t, harness.application, `
		DELETE FROM asset_observations WHERE id=$1
	`, fixture.observationID)
	assertObservationRuntimePermissionDenied(t, harness.application, `
		TRUNCATE TABLE asset_observations
	`)

	later := commitObservationACLPage(t, harness.application, fixture, observationACLPage{
		runID: "8fc10000-0000-4000-8000-000000000001", runKey: "observation-acl-later-run",
		runHashCharacter: "1", observationID: "8fc10000-0000-4000-8000-000000000002",
		externalID: externalID, observationChainCharacter: "2", previousID: fixture.observationID,
		previousChain: priorChain, freshnessSequence: 2, providerFactCharacter: "2",
		pageDigestCharacter: "3", relationDigestCharacter: "4", changedCount: 1,
	})
	tombstone := commitObservationACLPage(t, harness.application, fixture, observationACLPage{
		runID: "8fc10000-0000-4000-8000-000000000003", runKey: "observation-acl-tombstone-run",
		runHashCharacter: "3", observationID: "8fc10000-0000-4000-8000-000000000004",
		externalID: externalID, observationChainCharacter: "4", previousID: later.id,
		previousChain: later.observationChain, freshnessSequence: 3, providerFactCharacter: "4",
		pageDigestCharacter: "5", relationDigestCharacter: "6", document: nil,
		tombstone: true, reason: "PROVIDER_REMOVED", changedCount: 1, tombstonedCount: 1,
	})
	restore := commitObservationACLPage(t, harness.application, fixture, observationACLPage{
		runID: "8fc10000-0000-4000-8000-000000000005", runKey: "observation-acl-restore-run",
		runHashCharacter: "5", observationID: "8fc10000-0000-4000-8000-000000000006",
		externalID: externalID, observationChainCharacter: "6", previousID: tombstone.id,
		previousChain: tombstone.observationChain, freshnessSequence: 4,
		providerFactCharacter: "6", pageDigestCharacter: "7", relationDigestCharacter: "8",
		document: `{"display_name":"runtime-restored"}`, changedCount: 1, restoredCount: 1,
	})

	assertObservationACLChain(t, harness.application, fixture, later, tombstone, restore)
	assertObservationACLRejectionsAndAssetSerialization(
		t, harness.application, fixture, externalID, restore,
	)
}

type observationACLPage struct {
	runID, runKey, runHashCharacter                      string
	observationID, externalID, observationChainCharacter string
	previousID, previousChain                            string
	freshnessSequence                                    int64
	providerFactCharacter, pageDigestCharacter           string
	relationDigestCharacter                              string
	document                                             any
	tombstone                                            bool
	reason                                               any
	changedCount, restoredCount, tombstonedCount         int64
}

type committedObservationACLPage struct {
	id, observationChain string
	freshnessSequence    int64
	tombstone            bool
}

func commitObservationACLPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	page observationACLPage,
) committedObservationACLPage {
	t.Helper()
	run := startC1ExternalDiscoveryRun(
		t, database, fixture, page.runID, page.runKey, page.runHashCharacter,
	)
	candidate := newRuntimeObservation(
		fixture, run, page.observationID, page.externalID, page.observationChainCharacter,
	)
	candidate.freshnessKind = "OBJECT_SEQUENCE"
	candidate.freshnessSequence = page.freshnessSequence
	candidate.previousID = page.previousID
	candidate.previousChain = page.previousChain
	if page.document != nil || page.tombstone {
		candidate.document = page.document
	}
	candidate.tombstone = page.tombstone
	candidate.reason = page.reason

	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, run.id)
	transaction, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Observation ACL corrective page: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(context.Background(), insertRuntimeObservationSQL,
		c1ObservationArguments(candidate, strings.Repeat(page.providerFactCharacter, 64))...); err != nil {
		t.Fatalf("insert Observation ACL corrective fact: %v", err)
	}
	execAssetSQL(t, transaction, `
		UPDATE assets AS asset
		SET display_name=CASE WHEN observation.tombstone THEN asset.display_name ELSE 'runtime restored object' END,
			last_observation_id=observation.id,
			last_observation_chain_sha256=observation.observation_chain_sha256,
			last_observed_at=observation.observed_at,
			last_source_revision=observation.source_revision,
			version=asset.version+1
		FROM asset_observations AS observation
		WHERE asset.id=$1 AND observation.id=$2
	`, fixture.assetID, candidate.id)
	pageDigest := strings.Repeat(page.pageDigestCharacter, 64)
	relationDigest := strings.Repeat(page.relationDigestCharacter, 64)
	if err := insertClosurePageReceipt(transaction, fixture, run.id, 1, pageDigest); err != nil {
		t.Fatalf("insert Observation ACL corrective page receipt: %v", err)
	}
	if err := insertClosureRelationPageReceipt(transaction, fixture, run.id, 1, relationDigest); err != nil {
		t.Fatalf("insert Observation ACL corrective relation receipt: %v", err)
	}
	execAssetSQL(t, transaction, `
		WITH envelope AS (
			SELECT decode('01'||repeat(substr($2,1,2),12)||repeat(substr($2,3,2),16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,
			checkpoint_key_id='opaque-observation-acl-key-'||substr($2,1,1),
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID, pageDigest)
	execAssetSQL(t, transaction, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+1,relation_page_digest=$4,
			checkpoint_version=checkpoint_version+1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
			observed_count=observed_count+1,changed_count=changed_count+$5,
			restored_count=restored_count+$6,tombstoned_count=tombstoned_count+$7,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('e',64),version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID, relationDigest, page.changedCount,
		page.restoredCount, page.tombstonedCount)
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("commit Observation ACL corrective page: %v", err)
	}
	closeC1ExternalSuccess(t, database, fixture, run.id)

	var persisted committedObservationACLPage
	if err := database.QueryRow(context.Background(), `
		SELECT id::text,observation_chain_sha256,freshness_order_sequence,tombstone
		FROM asset_observations WHERE id=$1
	`, candidate.id).Scan(&persisted.id, &persisted.observationChain,
		&persisted.freshnessSequence, &persisted.tombstone); err != nil {
		t.Fatalf("read committed Observation ACL corrective fact: %v", err)
	}
	return persisted
}

func assertObservationACLChain(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	later, tombstone, restore committedObservationACLPage,
) {
	t.Helper()
	var laterPrior, tombstonePrior, restorePrior, projectedObservation string
	var tombstoneFlag, restoreFlag bool
	if err := database.QueryRow(context.Background(), `
		SELECT later.previous_observation_id::text,tombstone.previous_observation_id::text,
			restore.previous_observation_id::text,tombstone.tombstone,restore.tombstone,
			asset.last_observation_id::text
		FROM asset_observations AS later
		JOIN asset_observations AS tombstone ON tombstone.id=$2
		JOIN asset_observations AS restore ON restore.id=$3
		JOIN assets AS asset ON asset.id=$4
		WHERE later.id=$1
	`, later.id, tombstone.id, restore.id, fixture.assetID).Scan(
		&laterPrior, &tombstonePrior, &restorePrior, &tombstoneFlag, &restoreFlag,
		&projectedObservation,
	); err != nil {
		t.Fatalf("read later/tombstone/restore Observation chain: %v", err)
	}
	if laterPrior != fixture.observationID || tombstonePrior != later.id ||
		restorePrior != tombstone.id || !tombstoneFlag || restoreFlag ||
		projectedObservation != restore.id || later.freshnessSequence != 2 ||
		tombstone.freshnessSequence != 3 || restore.freshnessSequence != 4 {
		t.Fatalf("Observation chain prior=%s/%s/%s tombstone=%v/%v projected=%s freshness=%d/%d/%d",
			laterPrior, tombstonePrior, restorePrior, tombstoneFlag, restoreFlag,
			projectedObservation, later.freshnessSequence, tombstone.freshnessSequence,
			restore.freshnessSequence)
	}
}

func assertObservationACLRejectionsAndAssetSerialization(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	externalID string,
	restore committedObservationACLPage,
) {
	t.Helper()
	run := startC1ExternalDiscoveryRun(t, database, fixture,
		"8fc10000-0000-4000-8000-000000000007", "observation-acl-negative-run", "7")
	baseCandidate := func(id, external, chainCharacter string) runtimeObservation {
		candidate := newRuntimeObservation(fixture, run, id, external, chainCharacter)
		candidate.freshnessKind = "OBJECT_SEQUENCE"
		candidate.freshnessSequence = 5
		candidate.previousID = restore.id
		candidate.previousChain = restore.observationChain
		return candidate
	}

	var observationsBefore int64
	var projectionBefore string
	if err := database.QueryRow(context.Background(), `
		SELECT count(*),(SELECT last_observation_id::text FROM assets WHERE id=$2)
		FROM asset_observations WHERE source_id=$1
	`, fixture.sourceID, fixture.assetID).Scan(&observationsBefore, &projectionBefore); err != nil {
		t.Fatalf("read Observation state before fail-closed assertions: %v", err)
	}

	wrongChain := baseCandidate(
		"8fc10000-0000-4000-8000-000000000008", externalID, "8",
	)
	wrongChain.previousChain = strings.Repeat("f", 64)
	expectObservationCorrectiveError(t, database, "55000",
		"asset_observations_previous_projection_guard", wrongChain)

	fakePrior := baseCandidate(
		"8fc10000-0000-4000-8000-000000000009", "external-host-b", "9",
	)
	expectObservationCorrectiveError(t, database, "55000",
		"asset_observations_previous_projection_guard", fakePrior)

	regressed := baseCandidate(
		"8fc10000-0000-4000-8000-00000000000a", externalID, "a",
	)
	regressed.freshnessSequence = 3
	expectObservationCorrectiveError(t, database, "55000",
		"asset_observations_freshness_monotonic_guard", regressed)

	locking := baseCandidate(
		"8fc10000-0000-4000-8000-00000000000b", externalID, "b",
	)
	lockingTransaction, err := database.BeginTx(
		context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		t.Fatalf("begin current Asset serialization assertion: %v", err)
	}
	if _, err := lockingTransaction.Exec(context.Background(), insertRuntimeObservationSQL,
		c1ObservationArguments(locking, strings.Repeat("b", 64))...); err != nil {
		_ = lockingTransaction.Rollback(context.Background())
		t.Fatalf("insert uncommitted Observation for current Asset lock assertion: %v", err)
	}
	contender, err := database.Begin(context.Background())
	if err != nil {
		_ = lockingTransaction.Rollback(context.Background())
		t.Fatalf("begin current Asset lock contender: %v", err)
	}
	if _, err := contender.Exec(context.Background(), `SET LOCAL lock_timeout='100ms'`); err != nil {
		_ = contender.Rollback(context.Background())
		_ = lockingTransaction.Rollback(context.Background())
		t.Fatalf("set current Asset lock contender timeout: %v", err)
	}
	_, contenderErr := contender.Exec(context.Background(), `
		SELECT id FROM assets WHERE id=$1 FOR UPDATE
	`, fixture.assetID)
	_ = contender.Rollback(context.Background())
	assertObservationPostgresError(t, contenderErr, "55P03", "")
	if err := lockingTransaction.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback current Asset serialization assertion: %v", err)
	}

	drifted := baseCandidate(
		"8fc10000-0000-4000-8000-00000000000c", externalID, "c",
	)
	drifted.runFenceEpoch++
	expectObservationCorrectiveError(t, database, "55000",
		"asset_observations_live_run_guard", drifted)

	var observationsAfter int64
	var projectionAfter string
	if err := database.QueryRow(context.Background(), `
		SELECT count(*),(SELECT last_observation_id::text FROM assets WHERE id=$2)
		FROM asset_observations WHERE source_id=$1
	`, fixture.sourceID, fixture.assetID).Scan(&observationsAfter, &projectionAfter); err != nil {
		t.Fatalf("read Observation state after fail-closed assertions: %v", err)
	}
	if observationsAfter != observationsBefore || projectionAfter != projectionBefore {
		t.Fatalf("rejected Observation attempts changed count/projection %d/%s -> %d/%s",
			observationsBefore, projectionBefore, observationsAfter, projectionAfter)
	}
}

func expectObservationCorrectiveError(
	t *testing.T,
	database *pgxpool.Pool,
	state, constraint string,
	candidate runtimeObservation,
) {
	t.Helper()
	transaction, err := database.BeginTx(
		context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		t.Fatalf("begin Observation corrective rejection assertion: %v", err)
	}
	_, statementErr := transaction.Exec(context.Background(), insertRuntimeObservationSQL,
		c1ObservationArguments(candidate, strings.Repeat("d", 64))...)
	rollbackErr := transaction.Rollback(context.Background())
	if rollbackErr != nil {
		t.Fatalf("rollback Observation corrective rejection assertion: %v", rollbackErr)
	}
	assertObservationPostgresError(t, statementErr, state, constraint)
}

func assertObservationPostgresError(t *testing.T, err error, state, constraint string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != state ||
		(constraint != "" && postgresError.ConstraintName != constraint) {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE/constraint %s/%s", err, state, constraint)
	}
}

func assertObservationRuntimePermissionDenied(
	t *testing.T,
	database *pgxpool.Pool,
	query string,
	arguments ...any,
) {
	t.Helper()
	transaction, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin application runtime ACL assertion: %v", err)
	}
	_, statementErr := transaction.Exec(context.Background(), query, arguments...)
	rollbackErr := transaction.Rollback(context.Background())
	if rollbackErr != nil {
		t.Fatalf("rollback application runtime ACL assertion: %v", rollbackErr)
	}
	var postgresError *pgconn.PgError
	if !errors.As(statementErr, &postgresError) || postgresError.Code != "42501" {
		t.Fatalf("application runtime ACL error=%v, want PostgreSQL SQLSTATE 42501", statementErr)
	}
}
