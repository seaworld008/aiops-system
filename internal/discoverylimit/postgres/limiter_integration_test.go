package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	queuepostgres "github.com/seaworld008/aiops-system/internal/discoveryqueue/postgres"
)

func TestIntegrationConcurrentAcquireUsesDurableCapacityAndExactReplay(t *testing.T) {
	harness := newLimiterHarness(t)
	harness.applyMigrations(t)
	fixture := seedLimiterRun(t, harness, "concurrent", "EXTERNAL_LIMIT_V1", 1, 1, 30*time.Second)

	first := newTestLimiter(t, harness)
	second := newTestLimiter(t, harness)
	commands := []discoverylimit.AcquireCommand{
		{
			Coordinates: fixture.coordinates(),
			RequestID:   "limiter-concurrent-a",
			TTL:         5 * time.Minute,
		},
		{
			Coordinates: fixture.coordinates(),
			RequestID:   "limiter-concurrent-b",
			TTL:         5 * time.Minute,
		},
	}
	type outcome struct {
		command discoverylimit.AcquireCommand
		permit  discoverylimit.Permit
		err     error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	var wait sync.WaitGroup
	for index, limiter := range []*Limiter{first, second} {
		wait.Add(1)
		go func(limiter *Limiter, command discoverylimit.AcquireCommand) {
			defer wait.Done()
			<-start
			permit, err := limiter.Acquire(context.Background(), command)
			outcomes <- outcome{command: command, permit: permit, err: err}
		}(limiter, commands[index])
	}
	close(start)
	wait.Wait()
	close(outcomes)

	var winner outcome
	winners, limited := 0, 0
	for result := range outcomes {
		switch {
		case result.err == nil:
			winners++
			winner = result
		case errors.Is(result.err, discoverylimit.ErrLimited):
			limited++
		default:
			t.Fatalf("concurrent Acquire() error = %v", result.err)
		}
	}
	if winners != 1 || limited != 1 {
		t.Fatalf("concurrent Acquire outcomes winners=%d limited=%d, want 1/1", winners, limited)
	}
	if !winner.permit.Valid() || winner.permit.Coordinates != fixture.coordinates() ||
		winner.permit.RequestID != winner.command.RequestID ||
		winner.permit.ExpiresAt.Sub(winner.permit.AcquiredAt) != winner.command.TTL {
		t.Fatalf("winning permit = %#v", winner.permit)
	}

	harness.profiles.remove(fixture.profile.ProfileCode)
	replay, err := newTestLimiter(t, harness).Acquire(
		context.Background(), winner.command,
	)
	if err != nil {
		t.Fatalf("Acquire(response-loss replay) error = %v", err)
	}
	if !reflect.DeepEqual(replay, winner.permit) {
		t.Fatalf("Acquire replay = %#v, want original %#v", replay, winner.permit)
	}
	changed := winner.command
	changed.TTL += time.Second
	if _, err := first.Acquire(context.Background(), changed); !errors.Is(err, discoverylimit.ErrIdempotency) {
		t.Fatalf("Acquire(changed replay) error = %v, want ErrIdempotency", err)
	}

	assertLimiterLedgerCounts(t, harness.application, fixture, 1, 0, 1)
	rows, err := harness.application.Query(context.Background(), `
		SELECT bucket_kind,version,last_receipt_id::text,next_token_at>$1
		FROM public.asset_source_limit_buckets
		WHERE tenant_id=$2 AND workspace_id=$3
		  AND (
		    (bucket_kind='SOURCE' AND bucket_key=$4) OR
		    (bucket_kind='WORKSPACE' AND bucket_key=$3) OR
		    (bucket_kind='PROVIDER' AND bucket_key=$5)
		  )
		ORDER BY CASE bucket_kind WHEN 'SOURCE' THEN 1 WHEN 'WORKSPACE' THEN 2 ELSE 3 END
	`, winner.permit.AcquiredAt, fixture.tenantID, fixture.workspaceID,
		fixture.sourceID, fixture.providerKind)
	if err != nil {
		t.Fatalf("read Limiter buckets: %v", err)
	}
	defer rows.Close()
	var kinds []string
	for rows.Next() {
		var kind, receiptID string
		var version int64
		var advanced bool
		if err := rows.Scan(&kind, &version, &receiptID, &advanced); err != nil {
			t.Fatalf("scan Limiter bucket: %v", err)
		}
		if version != 2 || receiptID != winner.permit.PermitID || !advanced {
			t.Fatalf("bucket %s = version:%d receipt:%s advanced:%t", kind, version, receiptID, advanced)
		}
		kinds = append(kinds, kind)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate Limiter buckets: %v", err)
	}
	if !reflect.DeepEqual(kinds, []string{"SOURCE", "WORKSPACE", "PROVIDER"}) {
		t.Fatalf("bucket lock identities = %v", kinds)
	}
}

func TestIntegrationTerminalReplayDelayAndCoordinateDriftFailClosed(t *testing.T) {
	harness := newLimiterHarness(t)
	harness.applyMigrations(t)
	repository := newTestLimiter(t, harness)
	fixture := seedLimiterRun(t, harness, "terminal", "EXTERNAL_TERMINAL_V1",
		1_000_000, 1, 30*time.Second)

	permit, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-terminal-acquire", TTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	driftCases := []struct {
		name        string
		coordinates discoverylimit.Coordinates
	}{
		{name: "scope", coordinates: discoverylimit.Coordinates{
			Scope: assetcatalog.SourceScope{
				TenantID: fixture.tenantID, WorkspaceID: uuid.NewString(),
			},
			SourceID: fixture.sourceID, RunID: fixture.runID, ProviderKind: fixture.providerKind,
		}},
		{name: "source", coordinates: discoverylimit.Coordinates{
			Scope: fixture.coordinates().Scope, SourceID: uuid.NewString(),
			RunID: fixture.runID, ProviderKind: fixture.providerKind,
		}},
		{name: "run", coordinates: discoverylimit.Coordinates{
			Scope: fixture.coordinates().Scope, SourceID: fixture.sourceID,
			RunID: uuid.NewString(), ProviderKind: fixture.providerKind,
		}},
		{name: "provider", coordinates: discoverylimit.Coordinates{
			Scope: fixture.coordinates().Scope, SourceID: fixture.sourceID,
			RunID: fixture.runID, ProviderKind: "OTHER_PROVIDER_V1",
		}},
	}
	for _, test := range driftCases {
		t.Run(test.name, func(t *testing.T) {
			_, err := repository.Release(context.Background(), discoverylimit.ReleaseCommand{
				Coordinates: test.coordinates, PermitID: permit.PermitID,
				RequestID: "limiter-drift-" + test.name, ReasonCode: "COMPLETED",
			})
			if !errors.Is(err, discoverylimit.ErrStalePermit) {
				t.Fatalf("Release(%s drift) error = %v, want ErrStalePermit", test.name, err)
			}
		})
	}

	releaseCommand := discoverylimit.ReleaseCommand{
		Coordinates: fixture.coordinates(), PermitID: permit.PermitID,
		RequestID: "limiter-release-response-loss", ReasonCode: "COMPLETED",
	}
	harness.profiles.remove(fixture.profile.ProfileCode)
	release, err := repository.Release(context.Background(), releaseCommand)
	if err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if !release.Valid() || release.Kind != discoverylimit.ReceiptRelease ||
		release.PermitID != permit.PermitID || release.NotBefore != nil {
		t.Fatalf("Release receipt = %#v", release)
	}
	releaseReplay, err := newTestLimiter(t, harness).Release(
		context.Background(), releaseCommand,
	)
	if err != nil {
		t.Fatalf("Release(response-loss replay) error = %v", err)
	}
	if !reflect.DeepEqual(releaseReplay, release) {
		t.Fatalf("Release replay = %#v, want %#v", releaseReplay, release)
	}
	changedRelease := releaseCommand
	changedRelease.ReasonCode = "OTHER_REASON"
	if _, err := repository.Release(context.Background(), changedRelease); !errors.Is(err, discoverylimit.ErrIdempotency) {
		t.Fatalf("Release(changed replay) error = %v, want ErrIdempotency", err)
	}
	if _, err := repository.Release(context.Background(), discoverylimit.ReleaseCommand{
		Coordinates: fixture.coordinates(), PermitID: permit.PermitID,
		RequestID: "limiter-second-terminal", ReasonCode: "DUPLICATE",
	}); !errors.Is(err, discoverylimit.ErrStateConflict) {
		t.Fatalf("Release(second terminal) error = %v, want ErrStateConflict", err)
	}

	delayedFixture := seedLimiterRun(t, harness, "delay", "EXTERNAL_DELAY_V1",
		1_000_000, 1, 30*time.Second)
	delayedPermit, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: delayedFixture.coordinates(), RequestID: "limiter-delay-acquire", TTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Acquire(delay fixture) error = %v", err)
	}
	notBefore := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	delayCommand := discoverylimit.DelayCommand{
		Coordinates: delayedFixture.coordinates(), PermitID: delayedPermit.PermitID,
		RequestID: "limiter-delay-response-loss", ReasonCode: "PROVIDER_RETRY_AFTER",
		NotBefore: notBefore,
	}
	delay, err := repository.Delay(context.Background(), delayCommand)
	if err != nil {
		t.Fatalf("Delay() error = %v", err)
	}
	if !delay.Valid() || delay.Kind != discoverylimit.ReceiptDelay ||
		delay.NotBefore == nil || !delay.NotBefore.Equal(notBefore) {
		t.Fatalf("Delay receipt = %#v", delay)
	}
	delayReplay, err := newTestLimiter(t, harness).Delay(
		context.Background(), delayCommand,
	)
	if err != nil {
		t.Fatalf("Delay(response-loss replay) error = %v", err)
	}
	if !reflect.DeepEqual(delayReplay, delay) {
		t.Fatalf("Delay replay = %#v, want %#v", delayReplay, delay)
	}
	if _, err := repository.Release(context.Background(), discoverylimit.ReleaseCommand{
		Coordinates: delayedFixture.coordinates(), PermitID: delayedPermit.PermitID,
		RequestID: "limiter-release-after-delay", ReasonCode: "COMPLETED",
	}); !errors.Is(err, discoverylimit.ErrStateConflict) {
		t.Fatalf("Release(after Delay terminal) error = %v, want ErrStateConflict", err)
	}

	assertLimiterLedgerCounts(t, harness.application, fixture, 1, 1, 0)
	assertLimiterLedgerCounts(t, harness.application, delayedFixture, 1, 1, 0)
}

func TestIntegrationExpiredPermitAppendsExpireAndRecoversCapacity(t *testing.T) {
	harness := newLimiterHarness(t)
	harness.applyMigrations(t)
	repository := newTestLimiter(t, harness)
	fixture := seedLimiterRun(t, harness, "expiry", "EXTERNAL_EXPIRY_V1", 1, 1, 30*time.Second)

	first, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-expiry-first", TTL: time.Microsecond,
	})
	if err != nil {
		t.Fatalf("Acquire(short permit) error = %v", err)
	}
	if _, err := repository.Release(context.Background(), discoverylimit.ReleaseCommand{
		Coordinates: fixture.coordinates(), PermitID: first.PermitID,
		RequestID: "limiter-expired-release", ReasonCode: "COMPLETED",
	}); !errors.Is(err, discoverylimit.ErrStalePermit) {
		t.Fatalf("Release(expired permit) error = %v, want ErrStalePermit", err)
	}
	var kind, reason, requestID string
	if err := harness.application.QueryRow(context.Background(), `
		SELECT record_kind,terminal_reason_code,request_id
		FROM public.asset_source_limit_permits
		WHERE tenant_id=$1 AND workspace_id=$2 AND permit_id=$3
		  AND record_kind IN ('RELEASE','DELAY','EXPIRE')
	`, fixture.tenantID, fixture.workspaceID, first.PermitID).Scan(&kind, &reason, &requestID); err != nil {
		t.Fatalf("read expiry receipt: %v", err)
	}
	if kind != "EXPIRE" || reason != "PERMIT_EXPIRED" ||
		requestID != "limiter-expire:"+first.PermitID {
		t.Fatalf("expiry receipt = kind:%s reason:%s request:%s", kind, reason, requestID)
	}
	assertLimiterLedgerCounts(t, harness.application, fixture, 1, 1, 0)

	tokenReadyAt := first.AcquiredAt.Add(time.Second)
	if delay := time.Until(tokenReadyAt.Add(50 * time.Millisecond)); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C
	}
	second, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-expiry-second", TTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Acquire(after expiry recovery) error = %v", err)
	}
	if second.PermitID == first.PermitID {
		t.Fatal("expiry recovery reused the expired permit identity")
	}
	assertLimiterLedgerCounts(t, harness.application, fixture, 2, 1, 1)
}

func TestIntegrationExpirySweepAppendsEveryTerminalWithContinuousBucketCAS(t *testing.T) {
	harness := newLimiterHarness(t)
	harness.applyMigrations(t)
	repository := newTestLimiter(t, harness)
	fixture := seedLimiterRun(t, harness, "expiry-sweep", "EXTERNAL_EXPIRY_SWEEP_V1",
		1_000_000, 1, 30*time.Second)

	var latest discoverylimit.Permit
	for index := 0; index < 3; index++ {
		permit, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
			Coordinates: fixture.coordinates(),
			RequestID:   fmt.Sprintf("limiter-expiry-sweep-%d", index),
			TTL:         500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("Acquire(expiry sweep %d) error = %v", index, err)
		}
		latest = permit
	}
	if delay := time.Until(latest.ExpiresAt.Add(20 * time.Millisecond)); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C
	}
	recovered, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-expiry-sweep-recovered",
		TTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Acquire(after multi-expiry sweep) error = %v", err)
	}
	assertLimiterLedgerCounts(t, harness.application, fixture, 4, 3, 1)

	var bucketCount int
	if err := harness.application.QueryRow(context.Background(), `
		SELECT count(*)
		FROM public.asset_source_limit_buckets
		WHERE tenant_id=$1 AND workspace_id=$2
		  AND version=8 AND last_receipt_id=$3
	`, fixture.tenantID, fixture.workspaceID, recovered.PermitID).Scan(&bucketCount); err != nil {
		t.Fatalf("read multi-expiry bucket CAS: %v", err)
	}
	if bucketCount != 3 {
		t.Fatalf("multi-expiry bucket CAS rows = %d, want 3", bucketCount)
	}
}

func TestIntegrationAcquireRejectsExpiredRunLease(t *testing.T) {
	harness := newLimiterHarness(t)
	harness.applyMigrations(t)
	fixture := seedLimiterRun(t, harness, "stale-run", "EXTERNAL_STALE_V1", 10, 1, 50*time.Millisecond)
	repository := newTestLimiter(t, harness)
	if _, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-expire:" + uuid.NewString(),
		TTL: time.Minute,
	}); !errors.Is(err, discoverylimit.ErrInvalidRequest) {
		t.Fatalf("Acquire(reserved expiry request) error = %v, want ErrInvalidRequest", err)
	}
	time.Sleep(100 * time.Millisecond)

	if _, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-stale-run", TTL: time.Minute,
	}); !errors.Is(err, discoverylimit.ErrIneligible) {
		t.Fatalf("Acquire(expired Run lease) error = %v, want ErrIneligible", err)
	}
	assertLimiterLedgerCounts(t, harness.application, fixture, 0, 0, 0)
}

func TestIntegrationAcquireRequiresExactInstalledProfile(t *testing.T) {
	harness := newLimiterHarness(t)
	harness.applyMigrations(t)
	fixture := seedLimiterRun(t, harness, "profile", "EXTERNAL_PROFILE_V1", 10, 1, 30*time.Second)
	repository := newTestLimiter(t, harness)

	harness.profiles.remove(fixture.profile.ProfileCode)
	if _, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-profile-missing", TTL: time.Minute,
	}); !errors.Is(err, discoverylimit.ErrIneligible) {
		t.Fatalf("Acquire(missing Profile) error = %v, want ErrIneligible", err)
	}
	harness.profiles.put(fixture.profile)
	if _, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-profile-exact", TTL: time.Minute,
	}); err != nil {
		t.Fatalf("Acquire(exact Profile) error = %v", err)
	}

	drifted := fixture.profile.Clone()
	drifted.CanonicalProfileManifest = []byte(strings.Replace(
		string(drifted.CanonicalProfileManifest),
		`"rate_limit_requests":10`, `"rate_limit_requests":11`, 1,
	))
	drifted.RateLimitRequests = 11
	digest := sha256.Sum256(drifted.CanonicalProfileManifest)
	drifted.ProfileManifestSHA256 = hex.EncodeToString(digest[:])
	harness.profiles.put(drifted)
	if _, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
		Coordinates: fixture.coordinates(), RequestID: "limiter-profile-drift", TTL: time.Minute,
	}); !errors.Is(err, discoverylimit.ErrIneligible) {
		t.Fatalf("Acquire(same-code Profile drift) error = %v, want ErrIneligible", err)
	}
	assertLimiterLedgerCounts(t, harness.application, fixture, 1, 0, 1)
}

func TestIntegrationAcquireRevalidatesEligibilityAfterBucketLockWait(t *testing.T) {
	harness := newLimiterHarness(t)
	harness.applyMigrations(t)

	drifted := seedLimiterRun(t, harness, "source-drift", "EXTERNAL_SOURCE_DRIFT_V1",
		10, 1, 30*time.Second)
	limiterExec(t, harness.db, `
		UPDATE public.asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
	`, drifted.sourceID)
	if _, err := newTestLimiter(t, harness).Acquire(
		context.Background(), discoverylimit.AcquireCommand{
			Coordinates: drifted.coordinates(), RequestID: "limiter-source-drift",
			TTL: time.Minute,
		},
	); !errors.Is(err, discoverylimit.ErrIneligible) {
		t.Fatalf("Acquire(source eligibility drift) error = %v, want ErrIneligible", err)
	}
	assertLimiterLedgerCounts(t, harness.application, drifted, 0, 0, 0)

	waiting := seedLimiterRun(t, harness, "lease-wait", "EXTERNAL_LEASE_WAIT_V1",
		10, 1, 500*time.Millisecond)
	bucketIDs := [3]string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	limiterExec(t, harness.application, `
		INSERT INTO public.asset_source_limit_buckets(
		  id,tenant_id,workspace_id,bucket_kind,bucket_key,source_id,provider_kind
		) VALUES
		  ($1,$4,$5,'SOURCE',$6,$6,NULL),
		  ($2,$4,$5,'WORKSPACE',$5,NULL,NULL),
		  ($3,$4,$5,'PROVIDER',$7,NULL,$7)
	`, bucketIDs[0], bucketIDs[1], bucketIDs[2],
		waiting.tenantID, waiting.workspaceID, waiting.sourceID, waiting.providerKind)
	holder, err := harness.application.BeginTx(
		context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable},
	)
	if err != nil {
		t.Fatalf("begin Limiter bucket holder: %v", err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	limiterExec(t, holder, `
		SELECT id FROM public.asset_source_limit_buckets WHERE id=$1 FOR UPDATE
	`, bucketIDs[0])

	repository := newTestLimiter(t, harness)
	result := make(chan error, 1)
	go func() {
		_, err := repository.Acquire(context.Background(), discoverylimit.AcquireCommand{
			Coordinates: waiting.coordinates(), RequestID: "limiter-lease-expired-while-waiting",
			TTL: time.Minute,
		})
		result <- err
	}()
	waitForLimiterRunLock(t, harness.application, waiting.runID)
	var leaseExpiresAt time.Time
	if err := harness.application.QueryRow(context.Background(), `
		SELECT lease_expires_at FROM public.asset_source_runs WHERE id=$1
	`, waiting.runID).Scan(&leaseExpiresAt); err != nil {
		t.Fatalf("read waiting Run lease: %v", err)
	}
	if delay := time.Until(leaseExpiresAt.Add(30 * time.Millisecond)); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C
	}
	if err := holder.Rollback(context.Background()); err != nil {
		t.Fatalf("release Limiter bucket holder: %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, discoverylimit.ErrIneligible) {
			t.Fatalf("Acquire(lease expired after bucket wait) error = %v, want ErrIneligible", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire remained blocked after bucket holder released")
	}
	assertLimiterLedgerCounts(t, harness.application, waiting, 0, 0, 0)
}

func waitForLimiterRunLock(t *testing.T, pool *pgxpool.Pool, runID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tx, err := pool.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin Limiter Run lock probe: %v", err)
		}
		_, lockErr := tx.Exec(context.Background(), `
			SELECT id FROM public.asset_source_runs WHERE id=$1 FOR UPDATE NOWAIT
		`, runID)
		_ = tx.Rollback(context.Background())
		var databaseError *pgconn.PgError
		if errors.As(lockErr, &databaseError) && databaseError.Code == "55P03" {
			return
		}
		if lockErr != nil {
			t.Fatalf("probe Limiter Run lock: %v", lockErr)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		<-timer.C
		timer.Stop()
	}
	t.Fatal("Acquire did not lock the Run before waiting for the SOURCE bucket")
}

func newTestLimiter(t *testing.T, harness *limiterHarness) *Limiter {
	t.Helper()
	limiter, err := New(harness.application, harness.profiles)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return limiter
}

func assertLimiterLedgerCounts(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture limiterFixture,
	acquires, terminals, active int,
) {
	t.Helper()
	var gotAcquires, gotTerminals, gotActive int
	if err := pool.QueryRow(context.Background(), `
		SELECT
		  count(*) FILTER (WHERE record_kind='ACQUIRE'),
		  count(*) FILTER (WHERE record_kind IN ('RELEASE','DELAY','EXPIRE')),
		  count(*) FILTER (
		    WHERE record_kind='ACQUIRE' AND expires_at>clock_timestamp()
		      AND NOT EXISTS (
		        SELECT 1 FROM public.asset_source_limit_permits AS terminal
		        WHERE terminal.tenant_id=asset_source_limit_permits.tenant_id
		          AND terminal.workspace_id=asset_source_limit_permits.workspace_id
		          AND terminal.permit_id=asset_source_limit_permits.id
		          AND terminal.record_kind IN ('RELEASE','DELAY','EXPIRE')
		      )
		  )
		FROM public.asset_source_limit_permits
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND run_id=$4 AND provider_kind=$5
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.runID, fixture.providerKind).Scan(&gotAcquires, &gotTerminals, &gotActive); err != nil {
		t.Fatalf("read Limiter ledger counts: %v", err)
	}
	if gotAcquires != acquires || gotTerminals != terminals || gotActive != active {
		t.Fatalf("Limiter ledger counts acquire=%d terminal=%d active=%d, want %d/%d/%d",
			gotAcquires, gotTerminals, gotActive, acquires, terminals, active)
	}
}

type limiterHarness struct {
	admin, db, migration, application *pgxpool.Pool
	name                              string
	profiles                          *limiterProfileResolver
}

var safeLimiterControlDatabase = regexp.MustCompile(`^aiops_test(_[a-z0-9]+)*$`)

type limiterProfileResolver struct {
	mu       sync.RWMutex
	profiles map[assetcatalog.ProfileCode]assetcatalog.BuiltinSourceProfile
}

func newLimiterProfileResolver() *limiterProfileResolver {
	return &limiterProfileResolver{
		profiles: make(map[assetcatalog.ProfileCode]assetcatalog.BuiltinSourceProfile),
	}
}

func (resolver *limiterProfileResolver) ResolveProfileAdmission(
	ctx context.Context,
	code assetcatalog.ProfileCode,
) (assetcatalog.BuiltinSourceProfile, error) {
	if err := ctx.Err(); err != nil {
		return assetcatalog.BuiltinSourceProfile{}, err
	}
	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	profile, ok := resolver.profiles[code]
	if !ok {
		return assetcatalog.BuiltinSourceProfile{}, assetcatalog.ErrNotFound
	}
	return profile.Clone(), nil
}

func (resolver *limiterProfileResolver) put(profile assetcatalog.BuiltinSourceProfile) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.profiles[profile.ProfileCode] = profile.Clone()
}

func (resolver *limiterProfileResolver) remove(code assetcatalog.ProfileCode) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	delete(resolver.profiles, code)
}

func newLimiterHarness(t *testing.T) *limiterHarness {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	if adminDSN == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; real PostgreSQL 18.4 TLS tests were not run")
	}
	migrationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_MIGRATION_DSN"))
	applicationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_APPLICATION_DSN"))
	if migrationDSN == "" || applicationDSN == "" {
		t.Fatal("migration and application PostgreSQL identities are required")
	}
	if adminDSN == migrationDSN || adminDSN == applicationDSN || migrationDSN == applicationDSN {
		t.Fatal("PostgreSQL test identities must be distinct")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !safeLimiterControlDatabase.MatchString(adminConfig.ConnConfig.Database) {
		t.Fatal("test-control PostgreSQL DSN is not a dedicated safe database")
	}
	controlName := adminConfig.ConnConfig.Database
	migrationConfig := limiterRoleConfig(t, migrationDSN, controlName, "aiops_migrator")
	applicationConfig := limiterRoleConfig(t, applicationDSN, controlName, "aiops_control_plane_workload")
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect PostgreSQL test-control database: unavailable")
	}
	var serverVersion int
	var sslEnabled bool
	if err := admin.QueryRow(ctx, `
		SELECT current_setting('server_version_num')::integer,current_setting('ssl')='on'
	`).Scan(&serverVersion, &sslEnabled); err != nil ||
		serverVersion < 180004 || serverVersion >= 190000 || !sslEnabled {
		admin.Close()
		t.Fatal("integration harness requires PostgreSQL 18.4+ 18.x with TLS")
	}

	databaseName := "aiops_limiter_test_" + randomLimiterHex(t, 16)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	harness := &limiterHarness{
		admin: admin, name: databaseName, profiles: newLimiterProfileResolver(),
	}
	created := false
	t.Cleanup(func() {
		if harness.application != nil {
			harness.application.Close()
		}
		if harness.migration != nil {
			harness.migration.Close()
		}
		if harness.db != nil {
			harness.db.Close()
		}
		if created {
			if _, err := admin.Exec(context.Background(),
				"DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)"); err != nil {
				t.Errorf("drop isolated Limiter database %s: %v", databaseName, err)
			}
		}
		admin.Close()
	})
	if _, err := admin.Exec(ctx,
		"CREATE DATABASE "+identifier+" WITH TEMPLATE template0 OWNER aiops_schema_owner"); err != nil {
		t.Fatalf("create isolated Limiter database; cleanup ownership unconfirmed: %v", err)
	}
	created = true
	if _, err := admin.Exec(ctx, `SET ROLE aiops_schema_owner;
REVOKE ALL ON DATABASE `+identifier+` FROM PUBLIC;
REVOKE ALL ON DATABASE `+identifier+` FROM aiops_control_plane_runtime;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_migrator;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_control_plane_workload;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision isolated Limiter database ACL: %v", err)
	}

	dbConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse isolated test-control config")
	}
	dbConfig.ConnConfig.Database = databaseName
	dbConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if dbConfig.ConnConfig.RuntimeParams == nil {
		dbConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	dbConfig.ConnConfig.RuntimeParams["search_path"] = "public"
	dbConfig.MaxConns = max(dbConfig.MaxConns, 12)
	harness.db, err = pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		t.Fatal("connect isolated Limiter test-control database")
	}
	if _, err := harness.db.Exec(ctx, `ALTER SCHEMA public OWNER TO aiops_schema_owner;
SET ROLE aiops_schema_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM aiops_migrator;
REVOKE ALL ON SCHEMA public FROM aiops_control_plane_workload;
GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner;
GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision Limiter schema ACL: %v", err)
	}
	migrationConfig.ConnConfig.Database = databaseName
	harness.migration, err = pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal("connect isolated Limiter migration identity")
	}
	applicationConfig.ConnConfig.Database = databaseName
	harness.application, err = pgxpool.NewWithConfig(ctx, applicationConfig)
	if err != nil {
		t.Fatal("connect isolated Limiter application identity")
	}
	assertLimiterIdentity(t, harness.migration, "aiops_migrator")
	assertLimiterIdentity(t, harness.application, "aiops_control_plane_workload")
	return harness
}

func limiterRoleConfig(t *testing.T, dsn, controlName, expectedUser string) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || config.ConnConfig.Database != controlName || config.ConnConfig.User != expectedUser {
		t.Fatalf("invalid %s PostgreSQL test identity", expectedUser)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	config.MaxConns = max(config.MaxConns, 12)
	return config
}

func assertLimiterIdentity(t *testing.T, pool *pgxpool.Pool, expected string) {
	t.Helper()
	var sessionUser, currentUser string
	if err := pool.QueryRow(context.Background(), `SELECT session_user,current_user`).Scan(
		&sessionUser, &currentUser,
	); err != nil || sessionUser != expected || currentUser != expected {
		t.Fatalf("PostgreSQL identity mismatch for %s", expected)
	}
}

func (harness *limiterHarness) applyMigrations(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(limiterMigrationDirectory(t))
	if err != nil {
		t.Fatalf("read migration directory: %v", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") &&
			entry.Name() <= "000015_assets_catalog.up.sql" {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) != 15 {
		t.Fatalf("migration set through 000015 has %d files, want 15", len(files))
	}
	for _, name := range files {
		harness.applyMigration(t, name)
	}
}

func (harness *limiterHarness) applyMigration(t *testing.T, name string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(limiterMigrationDirectory(t), name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	if name == "000012_outbox_event_routing.up.sql" {
		config := harness.migration.Config().ConnConfig.Copy()
		connection, err := pgx.ConnectConfig(context.Background(), config)
		if err != nil {
			t.Fatalf("connect nontransactional migration %s", name)
		}
		defer func() { _ = connection.Close(context.Background()) }()
		if _, err := connection.Exec(context.Background(),
			`SET search_path=pg_catalog,public,pg_temp; SET ROLE aiops_schema_owner`); err != nil {
			t.Fatalf("set nontransactional migration role: %v", err)
		}
		if _, err := connection.Exec(context.Background(), string(source)); err != nil {
			failLimiterMigration(t, name, err)
		}
		if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
			t.Fatalf("reset nontransactional migration role: %v", err)
		}
		return
	}
	text := string(source)
	if name != "000015_assets_catalog.up.sql" {
		index := strings.Index(text, "BEGIN;")
		if index < 0 {
			t.Fatalf("migration %s does not start a transaction", name)
		}
		index += len("BEGIN;")
		text = text[:index] +
			"\nSET LOCAL ROLE aiops_schema_owner;\nSET LOCAL search_path=public,pg_catalog,pg_temp;" +
			text[index:]
	}
	connection, err := harness.migration.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire migration connection for %s", name)
	}
	defer connection.Release()
	if _, err := connection.Exec(context.Background(), text); err != nil {
		failLimiterMigration(t, name, err)
	}
	if _, err := connection.Exec(context.Background(), `RESET ROLE`); err != nil {
		t.Fatalf("reset migration role after %s: %v", name, err)
	}
}

func failLimiterMigration(t *testing.T, name string, err error) {
	t.Helper()
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		t.Fatalf("apply migration %s: %s (SQLSTATE %s, constraint %s)",
			name, databaseError.Message, databaseError.Code, databaseError.ConstraintName)
	}
	t.Fatalf("apply migration %s: %v", name, err)
}

type limiterFixture struct {
	tenantID, workspaceID, environmentID, integrationID string
	sourceID, revisionID, runID, providerKind           string
	claim                                               discoveryqueue.ClaimResult
	profile                                             assetcatalog.BuiltinSourceProfile
}

func (fixture limiterFixture) coordinates() discoverylimit.Coordinates {
	return discoverylimit.Coordinates{
		Scope: assetcatalog.SourceScope{
			TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
		},
		SourceID: fixture.sourceID, RunID: fixture.runID, ProviderKind: fixture.providerKind,
	}
}

func seedLimiterRun(
	t *testing.T,
	harness *limiterHarness,
	suffix, providerKind string,
	rateRequests, rateWindowSeconds int64,
	leaseDuration time.Duration,
) limiterFixture {
	t.Helper()
	fixture := limiterFixture{
		tenantID: uuid.NewString(), workspaceID: uuid.NewString(),
		environmentID: uuid.NewString(), integrationID: uuid.NewString(),
		sourceID: uuid.NewString(), revisionID: uuid.NewString(), runID: uuid.NewString(),
		providerKind: providerKind,
	}
	limiterExec(t, harness.db, `INSERT INTO public.tenants(id,name) VALUES($1,$2)`,
		fixture.tenantID, "limiter-tenant-"+suffix)
	limiterExec(t, harness.db,
		`INSERT INTO public.workspaces(id,tenant_id,name) VALUES($1,$2,$3)`,
		fixture.workspaceID, fixture.tenantID, "limiter-workspace-"+suffix)
	limiterExec(t, harness.db, `
		INSERT INTO public.environments(id,tenant_id,workspace_id,name,kind)
		VALUES($1,$2,$3,$4,'PROD')
	`, fixture.environmentID, fixture.tenantID, fixture.workspaceID, "limiter-environment-"+suffix)
	limiterExec(t, harness.db, `
		INSERT INTO public.integrations(id,tenant_id,workspace_id,provider,name,secret_ref,config)
		VALUES($1,$2,$3,'external',$4,'opaque://limiter-test','{}')
	`, fixture.integrationID, fixture.tenantID, fixture.workspaceID, "limiter-integration-"+suffix)

	profile := []byte(fmt.Sprintf(
		`{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":%q,"credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":65536,"max_page_bytes":1048576,"max_page_items":100,"max_page_relations":100,"network_mode":"NONE","parser_code":%q,"profile_code":%q,"provider_kind":%q,"rate_limit_requests":%d,"rate_limit_window_seconds":%d,"relationship_types":[],"schedule_mode":"NONE","source_kind":"EXTERNAL_CMDB","sync_mode":"ON_DEMAND","trust_mode":"NONE","trusted_path_codes":["DISPLAY_NAME","EXTERNAL_ID","KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`,
		providerKind, providerKind, providerKind, providerKind, rateRequests, rateWindowSeconds,
	))
	providerSchema := []byte(`{"type":"object"}`)
	profileDigest := sha256.Sum256(profile)
	providerSchemaDigest := sha256.Sum256(providerSchema)
	fixture.profile = assetcatalog.BuiltinSourceProfile{
		SourceKind: assetcatalog.SourceKindExternalCMDB, ProviderKind: providerKind,
		ProfileCode: assetcatalog.ProfileCode(providerKind), SyncMode: assetcatalog.SyncModeOnDemand,
		CanonicalProfileManifest: profile, CanonicalProviderSchema: providerSchema,
		ProfileManifestSHA256:         hex.EncodeToString(profileDigest[:]),
		CanonicalProviderSchemaSHA256: hex.EncodeToString(providerSchemaDigest[:]),
		RateLimitRequests:             rateRequests, RateLimitWindowSeconds: rateWindowSeconds,
	}
	harness.profiles.put(fixture.profile)
	authorityDigest := limiterFramedDigest(
		[]byte("asset-source-authority-scope.v1"), []byte("1"), []byte(fixture.environmentID),
	)
	sourceDefinitionDigest := limiterFramedDigest(
		[]byte("asset-source-definition.v2"), []byte("EXTERNAL_CMDB"), []byte(providerKind),
		[]byte(providerKind), profileDigest[:], providerSchemaDigest[:],
	)
	revisionDigest := limiterFramedDigest(
		[]byte("asset-source-revision-binding.v1"), []byte(fixture.tenantID),
		[]byte(fixture.workspaceID), []byte(fixture.sourceID), []byte("1"),
		limiterDecodeDigest(t, sourceDefinitionDigest), []byte(fixture.integrationID),
		[]byte("ON_DEMAND"), []byte("opaque-credential"), nil, nil,
		limiterDecodeDigest(t, authorityDigest), []byte(fmt.Sprint(rateRequests)),
		[]byte(fmt.Sprint(rateWindowSeconds)), []byte("1"), []byte("60"),
		[]byte(providerKind), nil, nil, nil,
	)

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Limiter source definition: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	limiterExec(t, tx, `
		INSERT INTO public.asset_sources(
		  id,tenant_id,workspace_id,source_kind,provider_kind,name,
		  create_idempotency_key,create_request_hash
		) VALUES($1,$2,$3,'EXTERNAL_CMDB',$4,$5,$6,repeat('1',64))
	`, fixture.sourceID, fixture.tenantID, fixture.workspaceID, providerKind,
		"limiter-"+suffix, "limiter-source-"+suffix)
	limiterExec(t, tx, `
		INSERT INTO public.asset_source_revisions(
		  id,tenant_id,workspace_id,source_id,revision,canonical_profile_manifest,
		  profile_manifest_sha256,canonical_provider_schema,canonical_provider_schema_sha256,
		  integration_id,sync_mode,authority_scope_digest,source_definition_digest,
		  canonical_revision_digest,credential_reference_id,rate_limit_requests,
		  rate_limit_window_seconds,backpressure_base_seconds,backpressure_max_seconds,
		  profile_code,created_by,change_reason_code,expected_source_version
		)
		SELECT $1,$2,$3,$4,1,$5,$6,$7,$8,$9,'ON_DEMAND',$10,$11,$12,
		       'opaque-credential',$13,$14,1,60,$15,'limiter-test','INITIAL_CREATE',source.version
		FROM public.asset_sources AS source WHERE source.id=$4
	`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		profile, hex.EncodeToString(profileDigest[:]), providerSchema,
		hex.EncodeToString(providerSchemaDigest[:]), fixture.integrationID,
		authorityDigest, sourceDefinitionDigest, revisionDigest,
		rateRequests, rateWindowSeconds, providerKind)
	limiterExec(t, tx, `
		INSERT INTO public.asset_source_revision_authorities(
		  tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES($1,$2,$3,1,$4,1)
	`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit Limiter source definition: %v", err)
	}

	tx, err = harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Limiter validation admission: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	limiterExec(t, tx, `
		INSERT INTO public.asset_source_runs(
		  id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
		  run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		)
		SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,$6,repeat('2',64),0
		FROM public.asset_sources WHERE id=$4
	`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		revisionDigest, "limiter-run-"+suffix)
	limiterExec(t, tx, `
		UPDATE public.asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, fixture.runID)
	limiterExec(t, tx, `
		UPDATE public.asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,validated_run_id=$2,
		    validation_digest=NULL,validated_binding_digest=NULL,version=version+1
		WHERE id=$1
	`, fixture.sourceID, fixture.runID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit Limiter validation admission: %v", err)
	}

	queue, err := queuepostgres.New(
		harness.application, acceptingLimiterCleanupVerifier{}, acceptingLimiterRolloverVerifier{},
	)
	if err != nil {
		t.Fatalf("create Queue fixture repository: %v", err)
	}
	fixture.claim, err = queue.Claim(context.Background(), discoveryqueue.ClaimCommand{
		Owner: "limiter-worker-" + suffix, LeaseDuration: leaseDuration,
		ProviderKinds: []string{providerKind},
	})
	if err != nil {
		t.Fatalf("claim Limiter fixture Run: %v", err)
	}
	t.Cleanup(fixture.claim.Destroy)
	if fixture.claim.Run.ID != fixture.runID {
		t.Fatalf("claimed Run = %s, want %s", fixture.claim.Run.ID, fixture.runID)
	}
	return fixture
}

type acceptingLimiterCleanupVerifier struct{}

func (acceptingLimiterCleanupVerifier) VerifyCleanupProof(
	context.Context,
	discoveryqueue.CleanupProof,
) error {
	return nil
}

type acceptingLimiterRolloverVerifier struct{}

func (acceptingLimiterRolloverVerifier) VerifyCheckpointLineageRollover(
	context.Context,
	discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	return nil
}

type limiterSQLExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func limiterExec(t *testing.T, executor limiterSQLExecutor, statement string, arguments ...any) {
	t.Helper()
	if _, err := executor.Exec(context.Background(), statement, arguments...); err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) {
			t.Fatalf("Limiter fixture SQL failed: %s (SQLSTATE %s, constraint %s)",
				databaseError.Message, databaseError.Code, databaseError.ConstraintName)
		}
		t.Fatalf("Limiter fixture SQL failed: %v", err)
	}
}

func limiterMigrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve Limiter integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
}

func randomLimiterHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("read Limiter test randomness: %v", err)
	}
	return hex.EncodeToString(value)
}

func limiterFramedDigest(values ...[]byte) string {
	hasher := sha256.New()
	for _, value := range values {
		if value == nil {
			_, _ = hasher.Write([]byte{0})
			continue
		}
		_, _ = hasher.Write([]byte{1})
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write(value)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func limiterDecodeDigest(t *testing.T, digest string) []byte {
	t.Helper()
	value, err := hex.DecodeString(digest)
	if err != nil || len(value) != sha256.Size {
		t.Fatalf("invalid Limiter fixture digest %q", digest)
	}
	return value
}
