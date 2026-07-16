package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestAssetCatalogLimiterPersistenceAndRuntimeParentLockContract(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	ctx := context.Background()

	expectRuntimeContractError(t, harness.application, "42501", "", `
		SELECT id FROM public.services
		WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3
		FOR KEY SHARE
	`, fixture.tenantID, fixture.workspaceID, fixture.serviceID)
	expectRuntimeContractError(t, harness.application, "42501", "", `
		SELECT service_id FROM public.service_bindings
		WHERE tenant_id=$1 AND workspace_id=$2 AND service_id=$3 AND environment_id=$4
		FOR SHARE
	`, fixture.tenantID, fixture.workspaceID, fixture.serviceID, fixture.environmentID)
	expectRuntimeContractError(t, harness.application, "42501", "", `
		UPDATE public.services SET version=version
		WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3
	`, fixture.tenantID, fixture.workspaceID, fixture.serviceID)
	expectRuntimeContractError(t, harness.application, "42501", "", `
		UPDATE public.service_bindings SET mapping_status=mapping_status
		WHERE tenant_id=$1 AND workspace_id=$2 AND service_id=$3 AND environment_id=$4
	`, fixture.tenantID, fixture.workspaceID, fixture.serviceID, fixture.environmentID)
	expectRuntimeContractError(t, harness.application, "55000",
		"asset_catalog_exact_service_binding_isolation_guard", `
			SELECT public.asset_catalog_lock_exact_service_binding($1,$2,$3,$4)
		`, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.serviceID)

	readOnly, err := harness.application.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatalf("begin read-only parent-lock assertion: %v", err)
	}
	_, readOnlyErr := readOnly.Exec(ctx,
		`SELECT public.asset_catalog_lock_exact_service_binding($1,$2,$3,$4)`,
		fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.serviceID)
	assertRuntimePostgresError(t, readOnlyErr, "55000",
		"asset_catalog_exact_service_binding_isolation_guard")
	if err := readOnly.Rollback(ctx); err != nil {
		t.Fatalf("rollback read-only parent-lock assertion: %v", err)
	}

	parentLock, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin runtime parent-lock transaction: %v", err)
	}
	var locked bool
	if err := parentLock.QueryRow(ctx,
		`SELECT public.asset_catalog_lock_exact_service_binding($1,$2,$3,$4)`,
		fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.serviceID,
	).Scan(&locked); err != nil || !locked {
		_ = parentLock.Rollback(ctx)
		t.Fatalf("runtime exact parent lock: locked=%v error=%v", locked, err)
	}
	parentContender, err := harness.db.Begin(ctx)
	if err != nil {
		_ = parentLock.Rollback(ctx)
		t.Fatalf("begin legacy-binding contender: %v", err)
	}
	execAssetSQL(t, parentContender, `SET LOCAL lock_timeout='250ms'`)
	_, contenderErr := parentContender.Exec(ctx, `
		UPDATE public.service_bindings
		SET mapping_status='AMBIGUOUS'
		WHERE tenant_id=$1 AND workspace_id=$2 AND service_id=$3 AND environment_id=$4
	`, fixture.tenantID, fixture.workspaceID, fixture.serviceID, fixture.environmentID)
	assertRuntimePostgresError(t, contenderErr, "55P03", "")
	if err := parentContender.Rollback(ctx); err != nil {
		_ = parentLock.Rollback(ctx)
		t.Fatalf("rollback legacy-binding contender: %v", err)
	}
	if err := parentLock.Commit(ctx); err != nil {
		t.Fatalf("commit runtime parent-lock transaction: %v", err)
	}

	execAssetSQL(t, harness.db, `
		UPDATE public.service_bindings SET mapping_status='AMBIGUOUS'
		WHERE tenant_id=$1 AND workspace_id=$2 AND service_id=$3 AND environment_id=$4
	`, fixture.tenantID, fixture.workspaceID, fixture.serviceID, fixture.environmentID)
	nonExact, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin non-EXACT parent-lock assertion: %v", err)
	}
	_, nonExactErr := nonExact.Exec(ctx,
		`SELECT public.asset_catalog_lock_exact_service_binding($1,$2,$3,$4)`,
		fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.serviceID)
	assertRuntimePostgresError(t, nonExactErr, "23514",
		"asset_catalog_exact_service_binding_mapping_guard")
	if err := nonExact.Rollback(ctx); err != nil {
		t.Fatalf("rollback non-EXACT parent-lock assertion: %v", err)
	}
	execAssetSQL(t, harness.db, `
		UPDATE public.service_bindings SET mapping_status='EXACT'
		WHERE tenant_id=$1 AND workspace_id=$2 AND service_id=$3 AND environment_id=$4
	`, fixture.tenantID, fixture.workspaceID, fixture.serviceID, fixture.environmentID)

	const (
		sourceBucketID    = "69000000-0000-4000-8000-000000000201"
		workspaceBucketID = "69000000-0000-4000-8000-000000000202"
		providerBucketID  = "69000000-0000-4000-8000-000000000203"
		acquireReceiptID  = "69100000-0000-4000-8000-000000000201"
		releaseReceiptID  = "69100000-0000-4000-8000-000000000202"
	)
	execAssetSQL(t, harness.application, `
		INSERT INTO public.asset_source_limit_buckets (
			id,tenant_id,workspace_id,bucket_kind,bucket_key,source_id,provider_kind,next_token_at
		) VALUES
			($1,$4,$5,'SOURCE',$6,$6,NULL,transaction_timestamp()),
			($2,$4,$5,'WORKSPACE',$5,NULL,NULL,transaction_timestamp()),
			($3,$4,$5,'PROVIDER','MANUAL_V1',NULL,'MANUAL_V1',transaction_timestamp())
	`, sourceBucketID, workspaceBucketID, providerBucketID,
		fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	expectRuntimeContractError(t, harness.application, "42501", "", `
		UPDATE public.asset_source_limit_buckets SET bucket_key=bucket_key WHERE id=$1
	`, sourceBucketID)

	serializingHolder, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Limiter serialization holder: %v", err)
	}
	lockLimiterBuckets(t, serializingHolder, sourceBucketID, workspaceBucketID, providerBucketID)
	serializingContender, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		_ = serializingHolder.Rollback(ctx)
		t.Fatalf("begin Limiter serialization contender: %v", err)
	}
	execAssetSQL(t, serializingContender, `SET LOCAL lock_timeout='250ms'`)
	_, limiterLockErr := serializingContender.Exec(ctx,
		`SELECT id FROM public.asset_source_limit_buckets WHERE id=$1 FOR UPDATE`,
		sourceBucketID)
	assertRuntimePostgresError(t, limiterLockErr, "55P03", "")
	if err := serializingContender.Rollback(ctx); err != nil {
		_ = serializingHolder.Rollback(ctx)
		t.Fatalf("rollback Limiter serialization contender: %v", err)
	}
	if err := serializingHolder.Rollback(ctx); err != nil {
		t.Fatalf("rollback Limiter serialization holder: %v", err)
	}

	acquiredAt := time.Now().UTC().Truncate(time.Microsecond)
	expiresAt := acquiredAt.Add(5 * time.Minute)
	acquireCommand := strings.Repeat("1", 64)
	acquireReceipt := strings.Repeat("2", 64)
	acquire, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Limiter acquire transaction: %v", err)
	}
	lockLimiterBuckets(t, acquire, sourceBucketID, workspaceBucketID, providerBucketID)
	execAssetSQL(t, acquire, `
		INSERT INTO public.asset_source_limit_permits (
			id,tenant_id,workspace_id,permit_id,record_kind,source_id,run_id,provider_kind,
			source_bucket_id,source_bucket_kind,source_bucket_key,
			workspace_bucket_id,workspace_bucket_kind,workspace_bucket_key,
			provider_bucket_id,provider_bucket_kind,provider_bucket_key,
			request_id,command_sha256,receipt_sha256,acquired_at,expires_at,created_at
		) VALUES (
			$1,$2,$3,$1,'ACQUIRE',$4,$5,'MANUAL_V1',
			$6,'SOURCE',$4,$7,'WORKSPACE',$3,$8,'PROVIDER','MANUAL_V1',
			'limiter-acquire-response-loss',$9,$10,$11,$12,$11
		)
	`, acquireReceiptID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.runID,
		sourceBucketID, workspaceBucketID, providerBucketID,
		acquireCommand, acquireReceipt, acquiredAt, expiresAt)
	updateLimiterBuckets(t, acquire, acquireReceiptID, true,
		sourceBucketID, workspaceBucketID, providerBucketID)
	if err := acquire.Commit(ctx); err != nil {
		t.Fatalf("commit Limiter acquire transaction: %v", err)
	}

	var replayCommand, replayReceipt string
	if err := harness.application.QueryRow(ctx, `
		SELECT command_sha256,receipt_sha256
		FROM public.asset_source_limit_permits
		WHERE workspace_id=$1 AND request_id='limiter-acquire-response-loss'
	`, fixture.workspaceID).Scan(&replayCommand, &replayReceipt); err != nil {
		t.Fatalf("lookup lost Acquire response: %v", err)
	}
	if replayCommand != acquireCommand || replayReceipt != acquireReceipt {
		t.Fatalf("lost Acquire replay=(%s,%s), want stored command/receipt", replayCommand, replayReceipt)
	}
	expectRuntimeContractError(t, harness.application, "42501", "", `
		UPDATE public.asset_source_limit_permits SET receipt_sha256=receipt_sha256 WHERE id=$1
	`, acquireReceiptID)
	expectRuntimeContractError(t, harness.application, "23505",
		"asset_source_limit_permits_workspace_request_uk", `
			INSERT INTO public.asset_source_limit_permits (
				id,tenant_id,workspace_id,permit_id,record_kind,source_id,run_id,provider_kind,
				source_bucket_id,source_bucket_kind,source_bucket_key,
				workspace_bucket_id,workspace_bucket_kind,workspace_bucket_key,
				provider_bucket_id,provider_bucket_kind,provider_bucket_key,
				request_id,command_sha256,receipt_sha256,acquired_at,expires_at,created_at
			) VALUES (
				'69100000-0000-4000-8000-000000000299',$1,$2,
				'69100000-0000-4000-8000-000000000299','ACQUIRE',$3,$4,'MANUAL_V1',
				$5,'SOURCE',$3,$6,'WORKSPACE',$2,$7,'PROVIDER','MANUAL_V1',
				'limiter-acquire-response-loss',$8,$9,$10,$11,$10
			)
		`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.runID,
		sourceBucketID, workspaceBucketID, providerBucketID,
		strings.Repeat("3", 64), strings.Repeat("4", 64), acquiredAt, expiresAt)

	assertActiveLimiterPermits(t, harness, fixture, 1)
	releaseCommand := strings.Repeat("5", 64)
	releaseReceipt := strings.Repeat("6", 64)
	release, err := harness.application.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Limiter release transaction: %v", err)
	}
	lockLimiterBuckets(t, release, sourceBucketID, workspaceBucketID, providerBucketID)
	execAssetSQL(t, release, `
		INSERT INTO public.asset_source_limit_permits (
			id,tenant_id,workspace_id,permit_id,record_kind,source_id,run_id,provider_kind,
			source_bucket_id,source_bucket_kind,source_bucket_key,
			workspace_bucket_id,workspace_bucket_kind,workspace_bucket_key,
			provider_bucket_id,provider_bucket_kind,provider_bucket_key,
			request_id,command_sha256,receipt_sha256,acquired_at,expires_at,terminal_reason_code
		) VALUES (
			$1,$2,$3,$4,'RELEASE',$5,$6,'MANUAL_V1',
			$7,'SOURCE',$5,$8,'WORKSPACE',$3,$9,'PROVIDER','MANUAL_V1',
			'limiter-release-response-loss',$10,$11,$12,$13,'COMPLETED'
		)
	`, releaseReceiptID, fixture.tenantID, fixture.workspaceID, acquireReceiptID,
		fixture.sourceID, fixture.runID, sourceBucketID, workspaceBucketID, providerBucketID,
		releaseCommand, releaseReceipt, acquiredAt, expiresAt)
	updateLimiterBuckets(t, release, releaseReceiptID, false,
		sourceBucketID, workspaceBucketID, providerBucketID)
	if err := release.Commit(ctx); err != nil {
		t.Fatalf("commit Limiter release transaction: %v", err)
	}
	assertActiveLimiterPermits(t, harness, fixture, 0)

	expectRuntimeContractError(t, harness.application, "23505",
		"asset_source_limit_permits_one_terminal_uk", `
			INSERT INTO public.asset_source_limit_permits (
				id,tenant_id,workspace_id,permit_id,record_kind,source_id,run_id,provider_kind,
				source_bucket_id,source_bucket_kind,source_bucket_key,
				workspace_bucket_id,workspace_bucket_kind,workspace_bucket_key,
				provider_bucket_id,provider_bucket_kind,provider_bucket_key,
				request_id,command_sha256,receipt_sha256,acquired_at,expires_at,terminal_reason_code
			) VALUES (
				'69100000-0000-4000-8000-000000000203',$1,$2,$3,'RELEASE',$4,$5,'MANUAL_V1',
				$6,'SOURCE',$4,$7,'WORKSPACE',$2,$8,'PROVIDER','MANUAL_V1',
				'limiter-second-terminal',repeat('7',64),repeat('8',64),$9,$10,'DUPLICATE_RELEASE'
			)
		`, fixture.tenantID, fixture.workspaceID, acquireReceiptID, fixture.sourceID, fixture.runID,
		sourceBucketID, workspaceBucketID, providerBucketID, acquiredAt, expiresAt)
	expectRuntimeContractError(t, harness.db, "55000", "asset_source_limit_permits_immutable", `
		UPDATE public.asset_source_limit_permits SET receipt_sha256=receipt_sha256 WHERE id=$1
	`, acquireReceiptID)
	expectRuntimeContractError(t, harness.db, "55000", "asset_source_limit_buckets_delete_guard", `
		DELETE FROM public.asset_source_limit_buckets WHERE id=$1
	`, sourceBucketID)
	expectRuntimeContractError(t, harness.db, "55000", "asset_source_limit_permits_truncate_guard",
		`TRUNCATE public.asset_source_limit_permits, public.asset_source_limit_buckets`)
}

func lockLimiterBuckets(t *testing.T, transaction pgx.Tx, bucketIDs ...string) {
	t.Helper()
	for _, bucketID := range bucketIDs {
		execAssetSQL(t, transaction,
			`SELECT id FROM public.asset_source_limit_buckets WHERE id=$1 FOR UPDATE`,
			bucketID)
	}
}

func updateLimiterBuckets(
	t *testing.T,
	transaction pgx.Tx,
	receiptID string,
	advanceToken bool,
	bucketIDs ...string,
) {
	t.Helper()
	for _, bucketID := range bucketIDs {
		if advanceToken {
			execAssetSQL(t, transaction, `
				UPDATE public.asset_source_limit_buckets
				SET next_token_at=next_token_at+interval '1 second',
					last_receipt_id=$1,version=version+1
				WHERE id=$2
			`, receiptID, bucketID)
			continue
		}
		execAssetSQL(t, transaction, `
			UPDATE public.asset_source_limit_buckets
			SET last_receipt_id=$1,version=version+1
			WHERE id=$2
		`, receiptID, bucketID)
	}
}

func assertActiveLimiterPermits(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	expected int,
) {
	t.Helper()
	var active int
	if err := harness.application.QueryRow(context.Background(), `
		SELECT count(*)
		FROM public.asset_source_limit_permits AS acquire
		WHERE acquire.tenant_id=$1
		  AND acquire.workspace_id=$2
		  AND acquire.source_id=$3
		  AND acquire.provider_kind='MANUAL_V1'
		  AND acquire.record_kind='ACQUIRE'
		  AND acquire.expires_at>clock_timestamp()
		  AND NOT EXISTS (
				SELECT 1
				FROM public.asset_source_limit_permits AS terminal
				WHERE terminal.tenant_id=acquire.tenant_id
				  AND terminal.workspace_id=acquire.workspace_id
				  AND terminal.permit_id=acquire.id
				  AND terminal.record_kind IN ('RELEASE','DELAY','EXPIRE')
		  )
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID).Scan(&active); err != nil {
		t.Fatalf("count active Limiter permits: %v", err)
	}
	if active != expected {
		t.Fatalf("active Limiter permits=%d, want %d", active, expected)
	}
}
