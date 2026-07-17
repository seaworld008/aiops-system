package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/authn"
)

func TestSourceRevisionIntegrationCreateSourceAtomicallyCreatesRevisionOneAndReplays(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	command := manualSourceCreateCommand(t, fixture, "create-source", "1")

	created, err := repository.CreateSource(context.Background(), command)
	if err != nil {
		t.Fatalf("CreateSource() error = %v", err)
	}
	if created.Source.ID == "" || created.Source.Version != 2 ||
		created.Source.Status != assetcatalog.SourceStatusActive ||
		created.Source.GateStatus != assetcatalog.SourceGateUnavailable ||
		created.Source.GateRevision != 0 || created.Source.PublishedRevision != 0 ||
		created.Source.CheckpointVersion != 0 ||
		created.Revision.SourceID != created.Source.ID ||
		created.Revision.Revision != 1 ||
		created.Revision.Status != assetcatalog.SourceRevisionDraft ||
		created.Revision.ExpectedSourceVersion != 1 ||
		created.Revision.ProfileCode != assetcatalog.ProfileCode("MANUAL_V1") ||
		created.Revision.CredentialReferenceID != "" ||
		created.Revision.TrustReferenceID != "" ||
		created.Revision.NetworkPolicyReferenceID != "" ||
		created.Revision.ScheduleExpression != "" ||
		created.Revision.CanonicalRevisionDigest != created.Revision.BindingDigest() ||
		created.Receipt.AuditID == "" || created.Receipt.IdempotentReplay {
		t.Fatalf("CreateSource() = %#v", created)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 1, 1, 1, 1, 1)
	assertSourceMutationSideEffectsDLP(t, harness.db, fixture.workspaceID, "manual-v1")

	replay, err := repository.CreateSource(context.Background(), command)
	if err != nil || !replay.Receipt.IdempotentReplay ||
		replay.Source.ID != created.Source.ID ||
		replay.Revision.ID != created.Revision.ID ||
		replay.Receipt.AuditID != created.Receipt.AuditID {
		t.Fatalf("CreateSource(replay) = (%#v, %v), first = %#v", replay, err, created)
	}
	changed := command
	changed.Name = "changed source"
	if _, err := repository.CreateSource(context.Background(), changed); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("CreateSource(hash drift) error = %v", err)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 1, 1, 1, 1, 1)
}

func TestSourceRevisionIntegrationCreateSourceReplayReturnsOriginalAfterLegalPublication(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	command := manualSourceCreateCommand(t, fixture, "create-source-replay-after-publish", "1")
	created, err := repository.CreateSource(context.Background(), command)
	if err != nil {
		t.Fatalf("CreateSource() error = %v", err)
	}
	scope := assetcatalog.SourceScope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
	}
	validated, err := repository.RequestValidation(
		context.Background(),
		assetcatalog.ValidateSourceRevisionCommand{
			Context:                 sourceRevisionMutationContext(t, scope, "validate-created-source", "2"),
			SourceID:                created.Source.ID,
			Revision:                created.Revision.Revision,
			ExpectedSourceVersion:   created.Source.Version,
			ExpectedRevisionVersion: created.Revision.Version,
			ExpectedRevisionDigest:  created.Revision.CanonicalRevisionDigest,
		},
	)
	if err != nil {
		t.Fatalf("RequestValidation() error = %v", err)
	}
	published, err := repository.Publish(
		context.Background(),
		assetcatalog.PublishSourceRevisionCommand{
			Context:                  sourceRevisionMutationContext(t, scope, "publish-created-source", "3"),
			SourceID:                 created.Source.ID,
			Revision:                 created.Revision.Revision,
			ReasonCode:               "VALIDATION_REVIEWED",
			ExpectedSourceVersion:    validated.Source.Version,
			ExpectedRevisionVersion:  validated.Revision.Version,
			ExpectedRevisionDigest:   validated.Revision.CanonicalRevisionDigest,
			ExpectedValidationRunID:  validated.Run.ID,
			ExpectedValidationDigest: validated.Run.ValidationProofDigest,
		},
	)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if published.Source.PublishedRevision != 1 ||
		published.Source.GateStatus != assetcatalog.SourceGateAvailable ||
		published.Revision.Status != assetcatalog.SourceRevisionPublished {
		t.Fatalf("Publish() = %#v", published)
	}

	replay, err := repository.CreateSource(context.Background(), command)
	if err != nil {
		t.Fatalf("CreateSource(replay after publish) error = %v", err)
	}
	want := created.Clone()
	want.Receipt.IdempotentReplay = true
	if !reflect.DeepEqual(replay, want) {
		t.Fatalf("CreateSource(replay after publish) = %#v, want original %#v", replay, want)
	}

	changed := command
	changed.Name = "changed after publication"
	if _, err := repository.CreateSource(context.Background(), changed); !errors.Is(
		err, assetcatalog.ErrIdempotency,
	) {
		t.Fatalf("CreateSource(hash drift after publish) error = %v", err)
	}
	crossScope := command
	crossScope.Context = sourceRevisionMutationContext(
		t,
		assetcatalog.SourceScope{
			TenantID: fixture.tenantID, WorkspaceID: fixture.otherWorkspaceID,
		},
		command.Context.IdempotencyKey(),
		"1",
	)
	if _, err := repository.CreateSource(context.Background(), crossScope); !errors.Is(
		err, assetcatalog.ErrScopeViolation,
	) {
		t.Fatalf("CreateSource(cross-scope replay) error = %v", err)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 1, 1, 1, 1, 1)
}

func TestSourceRevisionIntegrationCreateSourceReplayRejectsReceiptAuditAndOutboxDrift(t *testing.T) {
	testCases := []struct {
		name       string
		mutate     func(*testing.T, *pgxpool.Pool, assetcatalog.SourceRevisionMutation)
		wantAudits int
		wantOutbox int
	}{
		{
			name: "missing receipt",
			mutate: func(t *testing.T, database *pgxpool.Pool, created assetcatalog.SourceRevisionMutation) {
				t.Helper()
				execAssetSQL(t, database, `ALTER TABLE public.audit_records DISABLE TRIGGER audit_records_no_update`)
				execAssetSQL(t, database, `DELETE FROM audit_records WHERE id=$1::uuid`, created.Receipt.AuditID)
				execAssetSQL(t, database, `ALTER TABLE public.audit_records ENABLE TRIGGER audit_records_no_update`)
			},
			wantAudits: 0,
			wantOutbox: 1,
		},
		{
			name: "audit identity drift",
			mutate: func(t *testing.T, database *pgxpool.Pool, created assetcatalog.SourceRevisionMutation) {
				t.Helper()
				execAssetSQL(t, database, `ALTER TABLE public.audit_records DISABLE TRIGGER audit_records_no_update`)
				execAssetSQL(t, database, `
UPDATE audit_records
SET details=jsonb_set(details,'{command_sha256}',to_jsonb(repeat('f',64)::text),false)
WHERE id=$1::uuid
`, created.Receipt.AuditID)
				execAssetSQL(t, database, `ALTER TABLE public.audit_records ENABLE TRIGGER audit_records_no_update`)
			},
			wantAudits: 1,
			wantOutbox: 1,
		},
		{
			name: "audit run tuple drift",
			mutate: func(t *testing.T, database *pgxpool.Pool, created assetcatalog.SourceRevisionMutation) {
				t.Helper()
				execAssetSQL(t, database, `ALTER TABLE public.audit_records DISABLE TRIGGER audit_records_no_update`)
				execAssetSQL(t, database, `
UPDATE audit_records
SET details=jsonb_set(
	jsonb_set(details,'{run_id}',to_jsonb('70000000-0000-4000-8000-000000000005'::text),true),
	'{run_version}','1'::jsonb,true
)
WHERE id=$1::uuid
`, created.Receipt.AuditID)
				execAssetSQL(t, database, `ALTER TABLE public.audit_records ENABLE TRIGGER audit_records_no_update`)
			},
			wantAudits: 1,
			wantOutbox: 1,
		},
		{
			name: "audit row identity drift",
			mutate: func(t *testing.T, database *pgxpool.Pool, created assetcatalog.SourceRevisionMutation) {
				t.Helper()
				execAssetSQL(t, database, `ALTER TABLE public.audit_records DISABLE TRIGGER audit_records_no_update`)
				execAssetSQL(t, database, `
UPDATE audit_records
SET id='70000000-0000-4000-8000-000000000006'::uuid
WHERE id=$1::uuid
`, created.Receipt.AuditID)
				execAssetSQL(t, database, `ALTER TABLE public.audit_records ENABLE TRIGGER audit_records_no_update`)
			},
			wantAudits: 1,
			wantOutbox: 1,
		},
		{
			name: "outbox payload drift",
			mutate: func(t *testing.T, database *pgxpool.Pool, created assetcatalog.SourceRevisionMutation) {
				t.Helper()
				execAssetSQL(t, database, `
UPDATE outbox_events
SET payload=jsonb_set(payload,'{source_version}','99'::jsonb,false)
WHERE aggregate_type='ASSET_SOURCE' AND aggregate_id=$1::uuid
  AND event_type='asset.source.revision.created.v1'
`, created.Source.ID)
			},
			wantAudits: 1,
			wantOutbox: 1,
		},
		{
			name: "outbox row identity drift",
			mutate: func(t *testing.T, database *pgxpool.Pool, created assetcatalog.SourceRevisionMutation) {
				t.Helper()
				execAssetSQL(t, database, `
UPDATE outbox_events
SET id='70000000-0000-4000-8000-000000000007'::uuid
WHERE aggregate_type='ASSET_SOURCE' AND aggregate_id=$1::uuid
  AND event_type='asset.source.revision.created.v1'
`, created.Source.ID)
			},
			wantAudits: 1,
			wantOutbox: 1,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedSourceCreationScope(t, harness.db)
			repository, err := assetpostgres.New(
				harness.application,
				func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
				deterministicAssetIDGenerator(),
			)
			if err != nil {
				t.Fatal(err)
			}
			command := manualSourceCreateCommand(t, fixture, "create-source-drift", "4")
			created, err := repository.CreateSource(context.Background(), command)
			if err != nil {
				t.Fatalf("CreateSource() error = %v", err)
			}
			testCase.mutate(t, harness.db, created)

			if replay, err := repository.CreateSource(context.Background(), command); err == nil {
				t.Fatalf("CreateSource(replay with %s) = %#v, want fail closed", testCase.name, replay)
			}
			assertSourceCreateClosureCounts(
				t, harness.db, fixture.workspaceID,
				1, 1, 1, testCase.wantAudits, testCase.wantOutbox,
			)
		})
	}
}

func TestSourceRevisionIntegrationConcurrentCreateSourceHasOneAtomicClosure(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	command := manualSourceCreateCommand(t, fixture, "concurrent-create-source", "2")
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	start := make(chan struct{})
	results := make(chan callResult, 2)
	for range 2 {
		go func() {
			<-start
			value, callErr := repository.CreateSource(context.Background(), command)
			results <- callResult{value: value, err: callErr}
		}()
	}
	close(start)
	var first assetcatalog.SourceRevisionMutation
	replays := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent CreateSource() error = %v", result.err)
		}
		if first.Source.ID == "" {
			first = result.value
		} else if result.value.Source.ID != first.Source.ID ||
			result.value.Revision.ID != first.Revision.ID ||
			result.value.Receipt.AuditID != first.Receipt.AuditID {
			t.Fatalf("concurrent CreateSource results diverged: first=%#v other=%#v", first, result.value)
		}
		if result.value.Receipt.IdempotentReplay {
			replays++
		}
	}
	if replays != 1 {
		t.Fatalf("concurrent CreateSource replay count = %d, want 1", replays)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 1, 1, 1, 1, 1)
}

func TestSourceRevisionIntegrationConcurrentCreateSourceRetriesStaleSerializableSnapshot(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	const barrierKey int64 = 15000180081
	execAssetSQL(t, harness.db, `
CREATE SEQUENCE source_create_snapshot_attempts`)
	execAssetSQL(t, harness.db, `
GRANT USAGE,SELECT,UPDATE ON SEQUENCE source_create_snapshot_attempts
TO aiops_control_plane_workload`)
	execAssetSQL(t, harness.db, `
CREATE FUNCTION source_create_snapshot_barrier() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE
	attempt bigint;
BEGIN
	attempt := pg_catalog.nextval('public.source_create_snapshot_attempts'::pg_catalog.regclass);
	IF attempt=1 THEN
		PERFORM pg_catalog.pg_advisory_xact_lock(15000180081::bigint);
	ELSIF attempt=2 THEN
		RAISE EXCEPTION 'controlled concurrent Source create unique race'
			USING ERRCODE='23505',
			      SCHEMA='public',
			      TABLE='asset_sources',
			      CONSTRAINT='asset_sources_workspace_id_create_idempotency_key_key';
	END IF;
	RETURN NEW;
END
$$`)
	execAssetSQL(t, harness.db, `
CREATE TRIGGER aaa_source_create_snapshot_barrier
BEFORE INSERT ON asset_sources FOR EACH ROW
EXECUTE FUNCTION source_create_snapshot_barrier()`)

	holder, err := harness.db.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire Source create barrier holder: %v", err)
	}
	barrierHeld := true
	t.Cleanup(func() {
		if barrierHeld {
			_, _ = holder.Exec(
				context.Background(),
				`SELECT pg_catalog.pg_advisory_unlock($1::bigint)`,
				barrierKey,
			)
		}
		holder.Release()
	})
	if _, err := holder.Exec(
		context.Background(),
		`SELECT pg_catalog.pg_advisory_lock($1::bigint)`,
		barrierKey,
	); err != nil {
		t.Fatalf("hold Source create barrier: %v", err)
	}

	command := manualSourceCreateCommand(t, fixture, "controlled-concurrent-create", "8")
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	callContext, cancelCalls := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCalls()
	firstResult := make(chan callResult, 1)
	go func() {
		value, callErr := repository.CreateSource(callContext, command)
		firstResult <- callResult{value: value, err: callErr}
	}()
	firstPID := waitForSourceCreateAdvisoryWait(
		t, harness.db, "INSERT INTO asset_sources", 0,
	)

	secondResult := make(chan callResult, 1)
	go func() {
		value, callErr := repository.CreateSource(callContext, command)
		secondResult <- callResult{value: value, err: callErr}
	}()
	secondPID := waitForSourceCreateAdvisoryWait(
		t, harness.db, "asset-management-idempotency.v1:", firstPID,
	)
	var exactWait bool
	if err := harness.db.QueryRow(context.Background(), `
SELECT EXISTS (
	SELECT 1
	FROM pg_catalog.pg_locks AS waiting
	JOIN pg_catalog.pg_locks AS held
	  ON held.locktype=waiting.locktype
	 AND held.database IS NOT DISTINCT FROM waiting.database
	 AND held.classid IS NOT DISTINCT FROM waiting.classid
	 AND held.objid IS NOT DISTINCT FROM waiting.objid
	 AND held.objsubid IS NOT DISTINCT FROM waiting.objsubid
	WHERE waiting.pid=$1
	  AND held.pid=$2
	  AND waiting.locktype='advisory'
	  AND NOT waiting.granted
	  AND held.granted
)
`, secondPID, firstPID).Scan(&exactWait); err != nil {
		t.Fatalf("read exact Source idempotency lock wait: %v", err)
	}
	if !exactWait {
		t.Fatalf("second Source create pid %d did not wait on first pid %d exact advisory lock",
			secondPID, firstPID)
	}

	var unlocked bool
	if err := holder.QueryRow(
		context.Background(),
		`SELECT pg_catalog.pg_advisory_unlock($1::bigint)`,
		barrierKey,
	).Scan(&unlocked); err != nil || !unlocked {
		t.Fatalf("release Source create barrier: unlocked=%t error=%v", unlocked, err)
	}
	barrierHeld = false

	first := <-firstResult
	if first.err != nil || first.value.Receipt.IdempotentReplay {
		t.Fatalf("first controlled CreateSource() = (%#v, %v)", first.value, first.err)
	}
	second := <-secondResult
	if second.err != nil ||
		second.value.Source.ID != first.value.Source.ID ||
		second.value.Revision.ID != first.value.Revision.ID ||
		second.value.Receipt.AuditID != first.value.Receipt.AuditID ||
		!second.value.Receipt.IdempotentReplay {
		t.Fatalf("second controlled CreateSource() = (%#v, %v), want replay of %#v",
			second.value, second.err, first.value)
	}

	changed := command
	changed.Name = "changed controlled concurrent source"
	if _, err := repository.CreateSource(context.Background(), changed); !errors.Is(
		err, assetcatalog.ErrIdempotency,
	) {
		t.Fatalf("CreateSource(changed controlled replay) error = %v", err)
	}
	crossScope := command
	crossScope.Context = sourceRevisionMutationContext(
		t,
		assetcatalog.SourceScope{
			TenantID: fixture.tenantID, WorkspaceID: fixture.otherWorkspaceID,
		},
		command.Context.IdempotencyKey(),
		"8",
	)
	if _, err := repository.CreateSource(context.Background(), crossScope); !errors.Is(
		err, assetcatalog.ErrScopeViolation,
	) {
		t.Fatalf("CreateSource(cross-scope controlled replay) error = %v", err)
	}
	var insertAttempts int64
	if err := harness.db.QueryRow(
		context.Background(),
		`SELECT last_value FROM source_create_snapshot_attempts`,
	).Scan(&insertAttempts); err != nil || insertAttempts != 2 {
		t.Fatalf("controlled Source insert attempts = %d, %v; want 2", insertAttempts, err)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 1, 1, 1, 1, 1)
}

func waitForSourceCreateAdvisoryWait(
	t *testing.T,
	database *pgxpool.Pool,
	queryFragment string,
	excludedPID int32,
) int32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var pid int32
	var snapshotEstablished bool
	for time.Now().Before(deadline) {
		err := database.QueryRow(context.Background(), `
SELECT activity.pid,activity.backend_xmin IS NOT NULL
FROM pg_catalog.pg_stat_activity AS activity
JOIN pg_catalog.pg_locks AS waiting ON waiting.pid=activity.pid
WHERE activity.datname=pg_catalog.current_database()
  AND activity.usename='aiops_control_plane_workload'
  AND activity.pid<>$1
  AND waiting.locktype='advisory'
  AND NOT waiting.granted
  AND pg_catalog.strpos(activity.query,$2)>0
ORDER BY activity.query_start
LIMIT 1
`, excludedPID, queryFragment).Scan(&pid, &snapshotEstablished)
		if err == nil {
			if !snapshotEstablished {
				t.Fatalf("blocked Source create pid %d has no established serializable snapshot", pid)
			}
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("observe blocked Source create: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Source create did not reach advisory wait for query fragment %q", queryFragment)
	return 0
}

func TestSourceRevisionIntegrationCreateSourceProfileSelectorErrorsHaveNoSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}

	unknown := manualSourceCreateCommand(t, fixture, "unknown-profile", "3")
	unknown.SourceProfileID = "future-v1"
	if _, err := repository.CreateSource(context.Background(), unknown); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("CreateSource(unknown profile) error = %v", err)
	}
	invalid := manualSourceCreateCommand(t, fixture, "invalid-profile", "4")
	invalid.SourceProfileID = "MANUAL_V1"
	if _, err := repository.CreateSource(context.Background(), invalid); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("CreateSource(invalid profile selector) error = %v", err)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 0, 0, 0, 0, 0)
}

func TestSourceRevisionIntegrationCreateRevisionProfileSelectorErrorsPrecedeSourceLookup(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
	}
	command := func(key, digest, selector string) assetcatalog.CreateSourceRevisionCommand {
		return assetcatalog.CreateSourceRevisionCommand{
			Context:                 sourceRevisionMutationContext(t, scope, key, digest),
			SourceID:                "60000000-0000-4000-8000-000000000299",
			SourceProfileID:         assetcatalog.SourceProfileID(selector),
			AuthorityEnvironmentIDs: []string{fixture.environmentID},
			ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
			ExpectedSourceVersion:   1,
		}
	}
	if _, err := repository.CreateRevision(
		context.Background(), command("unknown-revision-profile", "5", "future-v1"),
	); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("CreateRevision(unknown profile) error = %v", err)
	}
	if _, err := repository.CreateRevision(
		context.Background(), command("invalid-revision-profile", "6", "MANUAL_V1"),
	); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("CreateRevision(invalid profile selector) error = %v", err)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 0, 0, 0, 0, 0)
}

func TestSourceRevisionIntegrationCreateSourceRejectsAuthorityDriftWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}

	crossScope := manualSourceCreateCommand(t, fixture, "cross-scope-authority", "4")
	crossScope.AuthorityEnvironmentIDs = []string{fixture.otherEnvironmentID}
	if _, err := repository.CreateSource(context.Background(), crossScope); !errors.Is(err, assetcatalog.ErrScopeViolation) {
		t.Fatalf("CreateSource(cross-scope authority) error = %v", err)
	}
	multiple := manualSourceCreateCommand(t, fixture, "multiple-authorities", "5")
	multiple.AuthorityEnvironmentIDs = []string{fixture.environmentID, fixture.secondEnvironmentID}
	if _, err := repository.CreateSource(context.Background(), multiple); !errors.Is(err, assetcatalog.ErrScopeViolation) {
		t.Fatalf("CreateSource(multiple MANUAL authorities) error = %v", err)
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 0, 0, 0, 0, 0)
}

func TestSourceRevisionIntegrationCreateSourceRollsBackWhenAuditInsertFails(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	const conflictingAuditID = "70000000-0000-4000-8000-000000000003"
	execAssetSQL(t, harness.db, `
INSERT INTO audit_records (
    id,tenant_id,workspace_id,actor_type,actor_id,action,
    resource_type,resource_id,request_id,trace_id,payload_hash
) VALUES (
    $1::uuid,$2::uuid,$3::uuid,'SYSTEM','source-create-test','TEST_BLOCKER',
    'ASSET_SOURCE',$3::text,'source-create-audit-blocker','audit-blocker-trace',repeat('a',64)
)
`, conflictingAuditID, fixture.tenantID, fixture.workspaceID)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repository.CreateSource(
		context.Background(),
		manualSourceCreateCommand(t, fixture, "audit-failure", "6"),
	); err == nil {
		t.Fatal("CreateSource(audit failure) succeeded")
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 0, 0, 0, 0, 0)
}

func TestSourceRevisionIntegrationCreateSourceRollsBackWhenOutboxInsertFails(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedSourceCreationScope(t, harness.db)
	const conflictingOutboxID = "70000000-0000-4000-8000-000000000004"
	execAssetSQL(t, harness.db, `
INSERT INTO outbox_events (
    id,tenant_id,workspace_id,aggregate_type,aggregate_id,
    aggregate_version,event_type,payload
) VALUES ($1::uuid,$2::uuid,$3::uuid,'TEST',$3::uuid,1,'test.blocker.v1','{}'::jsonb)
`, conflictingOutboxID, fixture.tenantID, fixture.workspaceID)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repository.CreateSource(
		context.Background(),
		manualSourceCreateCommand(t, fixture, "outbox-failure", "6"),
	); err == nil {
		t.Fatal("CreateSource(outbox failure) succeeded")
	}
	assertSourceCreateClosureCounts(t, harness.db, fixture.workspaceID, 0, 0, 0, 0, 0)
}

func TestSourceRevisionIntegrationManualLifecycleAndReplay(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}

	create := assetcatalog.CreateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "create-source-revision-2", "1"),
		SourceID: fixture.sourceID, SourceProfileID: assetcatalog.SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{fixture.environmentID},
		ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
		ExpectedSourceVersion:   2,
	}
	created, err := repository.CreateRevision(context.Background(), create)
	if err != nil {
		t.Fatalf("CreateRevision() error = %v", err)
	}
	if created.Source.Version != 3 || created.Revision.Revision != 2 ||
		created.Revision.Status != assetcatalog.SourceRevisionDraft ||
		created.Revision.ExpectedSourceVersion != 2 ||
		created.Receipt.IdempotentReplay {
		t.Fatalf("CreateRevision() = %#v", created)
	}
	replay, err := repository.CreateRevision(context.Background(), create)
	if err != nil || !replay.Receipt.IdempotentReplay ||
		replay.Receipt.AuditID != created.Receipt.AuditID ||
		replay.Revision.CanonicalRevisionDigest != created.Revision.CanonicalRevisionDigest {
		t.Fatalf("CreateRevision(replay) = (%#v, %v)", replay, err)
	}
	changed := create
	changed.ChangeReasonCode = "DIFFERENT_REASON"
	if _, err := repository.CreateRevision(context.Background(), changed); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("CreateRevision(hash drift) error = %v", err)
	}

	validateCommand := assetcatalog.ValidateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "validate-source-revision-2", "2"),
		SourceID: fixture.sourceID, Revision: 2,
		ExpectedSourceVersion:   created.Source.Version,
		ExpectedRevisionVersion: created.Revision.Version,
		ExpectedRevisionDigest:  created.Revision.CanonicalRevisionDigest,
	}
	validated, err := repository.RequestValidation(context.Background(), validateCommand)
	if err != nil {
		t.Fatalf("RequestValidation() error = %v", err)
	}
	if validated.Source.GateStatus != assetcatalog.SourceGateValidating ||
		validated.Revision.Status != assetcatalog.SourceRevisionValidated ||
		validated.Run.Status != assetcatalog.RunStatusSucceeded ||
		validated.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupNoCredential ||
		validated.Run.ValidationProofDigest == "" {
		t.Fatalf("RequestValidation() = %#v", validated)
	}
	assertSourceValidationSystemReceipts(t, harness.db, validated.Run.ID)
	validationReplay, err := repository.RequestValidation(context.Background(), validateCommand)
	if err != nil || !validationReplay.Receipt.IdempotentReplay ||
		validationReplay.Run.ID != validated.Run.ID {
		t.Fatalf("RequestValidation(replay) = (%#v, %v)", validationReplay, err)
	}

	publishCommand := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-source-revision-2", "3"),
		SourceID: fixture.sourceID, Revision: 2, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion:    validated.Source.Version,
		ExpectedRevisionVersion:  validated.Revision.Version,
		ExpectedRevisionDigest:   validated.Revision.CanonicalRevisionDigest,
		ExpectedValidationRunID:  validated.Run.ID,
		ExpectedValidationDigest: validated.Run.ValidationProofDigest,
	}
	published, err := repository.Publish(context.Background(), publishCommand)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if published.Source.Status != assetcatalog.SourceStatusActive ||
		published.Source.GateStatus != assetcatalog.SourceGateAvailable ||
		published.Source.PublishedRevision != 2 ||
		published.Revision.Status != assetcatalog.SourceRevisionPublished ||
		published.Source.ValidatedRunID != validated.Run.ID {
		t.Fatalf("Publish() = %#v", published)
	}
	publishReplay, err := repository.Publish(context.Background(), publishCommand)
	if err != nil || !publishReplay.Receipt.IdempotentReplay ||
		publishReplay.Revision.Revision != published.Revision.Revision {
		t.Fatalf("Publish(replay) = (%#v, %v)", publishReplay, err)
	}

	disableCommand := assetcatalog.DisableSourceCommand{
		Context:  sourceRevisionMutationContext(t, scope, "disable-source", "4"),
		SourceID: fixture.sourceID, ReasonCode: "OPERATOR_DISABLED",
		ExpectedSourceVersion: published.Source.Version,
	}
	disabled, err := repository.Disable(context.Background(), disableCommand)
	if err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	if disabled.Source.Status != assetcatalog.SourceStatusDisabled ||
		disabled.Source.GateStatus != assetcatalog.SourceGateUnavailable ||
		disabled.Source.GateReasonCode != "SOURCE_NOT_ACTIVE" {
		t.Fatalf("Disable() = %#v", disabled)
	}
	disableReplay, err := repository.Disable(context.Background(), disableCommand)
	if err != nil || !disableReplay.Receipt.IdempotentReplay ||
		disableReplay.Source.ID != disabled.Source.ID {
		t.Fatalf("Disable(replay) = (%#v, %v)", disableReplay, err)
	}
	assertSourceMutationSideEffectsDLP(
		t,
		harness.db,
		fixture.workspaceID,
		correctiveManualProfileManifestV1,
		`{"additionalProperties":false,"properties":{},"type":"object"}`,
		"MANUAL_V1",
		"additionalProperties",
		"canonical_profile_manifest",
		"canonical_provider_schema",
		"opaque://sanitized",
		"secret-canary",
		"https://endpoint.invalid",
		"authorization",
		"header-canary",
		"body-canary",
	)
}

func TestSourceRevisionIntegrationConcurrentCreateRevisionHasOneCASWinner(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	commands := []assetcatalog.CreateSourceRevisionCommand{
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-revision-a", "a"),
			SourceID: fixture.sourceID, SourceProfileID: assetcatalog.SourceProfileIDManualV1,
			AuthorityEnvironmentIDs: []string{fixture.environmentID},
			ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
			ExpectedSourceVersion:   2,
		},
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-revision-b", "b"),
			SourceID: fixture.sourceID, SourceProfileID: assetcatalog.SourceProfileIDManualV1,
			AuthorityEnvironmentIDs: []string{fixture.environmentID},
			ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
			ExpectedSourceVersion:   2,
		},
	}
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	start := make(chan struct{})
	results := make(chan callResult, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			value, callErr := repository.CreateRevision(context.Background(), command)
			results <- callResult{value: value, err: callErr}
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	var winner assetcatalog.SourceRevisionMutation
	for range commands {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.value
		case errors.Is(result.err, assetcatalog.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent CreateRevision() error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 ||
		winner.Source.Version != 3 || winner.Revision.Revision != 2 {
		t.Fatalf("concurrent CreateRevision outcomes = success:%d conflict:%d winner:%#v",
			successes, conflicts, winner)
	}
	var revisionCount, auditCount, auditResourceCount, outboxCount, outboxAggregateCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_source_revisions
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid),
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND action='asset.source.revision.created.v1'),
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND resource_type='ASSET_SOURCE' AND resource_id=$3
     AND action='asset.source.revision.created.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND event_type='asset.source.revision.created.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND aggregate_type='ASSET_SOURCE' AND aggregate_id=$3::uuid
     AND event_type='asset.source.revision.created.v1')
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID).Scan(
		&revisionCount, &auditCount, &auditResourceCount, &outboxCount, &outboxAggregateCount,
	); err != nil {
		t.Fatal(err)
	}
	if revisionCount != 2 || auditCount != 1 || auditResourceCount != 1 ||
		outboxCount != 1 || outboxAggregateCount != 1 {
		t.Fatalf("concurrent CreateRevision side effects = revisions:%d audit:%d/%d outbox:%d/%d",
			revisionCount, auditResourceCount, auditCount, outboxAggregateCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationCreateRevisionOwnsCallerAuthorityMemoryBeforeAllocation(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	firstAllocationEntered := make(chan struct{})
	releaseAllocation := make(chan struct{})
	baseGenerator := deterministicAssetIDGenerator()
	allocationCount := 0
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		func() string {
			allocationCount++
			if allocationCount == 1 {
				close(firstAllocationEntered)
				<-releaseAllocation
			}
			return baseGenerator()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	callerAuthorities := []string{fixture.environmentID}
	command := assetcatalog.CreateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "owned-authority-memory", "6"),
		SourceID: fixture.sourceID, SourceProfileID: assetcatalog.SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: callerAuthorities,
		ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
		ExpectedSourceVersion:   2,
	}
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	result := make(chan callResult, 1)
	go func() {
		value, callErr := repository.CreateRevision(context.Background(), command)
		result <- callResult{value: value, err: callErr}
	}()
	<-firstAllocationEntered
	callerAuthorities[0] = "30000000-0000-4000-8000-000000000099"
	close(releaseAllocation)
	created := <-result
	if created.err != nil {
		t.Fatalf("CreateRevision(owned authority memory) error = %v", created.err)
	}
	if len(created.value.Revision.AuthorityEnvironmentIDs) != 1 ||
		created.value.Revision.AuthorityEnvironmentIDs[0] != fixture.environmentID {
		t.Fatalf("CreateRevision consumed caller mutation: %#v", created.value.Revision)
	}
}

func TestSourceRevisionIntegrationConcurrentManualPublishHasOneCASWinner(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	validated, err := repository.RequestValidation(context.Background(), assetcatalog.ValidateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "prepare-concurrent-publish", "c"),
		SourceID: fixture.sourceID, Revision: 1,
		ExpectedSourceVersion: 2, ExpectedRevisionVersion: 1,
		ExpectedRevisionDigest: fixture.revisionDigest,
	})
	if err != nil {
		t.Fatalf("RequestValidation() error = %v", err)
	}
	commands := []assetcatalog.PublishSourceRevisionCommand{
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-publish-a", "a"),
			SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
			ExpectedSourceVersion:   validated.Source.Version,
			ExpectedRevisionVersion: validated.Revision.Version,
			ExpectedRevisionDigest:  validated.Revision.CanonicalRevisionDigest,
			ExpectedValidationRunID: validated.Run.ID, ExpectedValidationDigest: validated.Run.ValidationProofDigest,
		},
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-publish-b", "b"),
			SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
			ExpectedSourceVersion:   validated.Source.Version,
			ExpectedRevisionVersion: validated.Revision.Version,
			ExpectedRevisionDigest:  validated.Revision.CanonicalRevisionDigest,
			ExpectedValidationRunID: validated.Run.ID, ExpectedValidationDigest: validated.Run.ValidationProofDigest,
		},
	}
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	start := make(chan struct{})
	results := make(chan callResult, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			value, callErr := repository.Publish(context.Background(), command)
			results <- callResult{value: value, err: callErr}
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	var winner assetcatalog.SourceRevisionMutation
	for range commands {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.value
		case errors.Is(result.err, assetcatalog.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Publish() error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 ||
		winner.Revision.Status != assetcatalog.SourceRevisionPublished ||
		winner.Source.GateStatus != assetcatalog.SourceGateAvailable {
		t.Fatalf("concurrent Publish outcomes = success:%d conflict:%d winner:%#v",
			successes, conflicts, winner)
	}
	var auditCount, auditResourceCount, outboxCount, outboxAggregateCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND action='asset.source.revision.published.v1'),
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND resource_type='ASSET_SOURCE' AND resource_id=$3
     AND action='asset.source.revision.published.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND event_type='asset.source.revision.published.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND aggregate_type='ASSET_SOURCE' AND aggregate_id=$3::uuid
     AND event_type='asset.source.revision.published.v1')
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID).Scan(
		&auditCount, &auditResourceCount, &outboxCount, &outboxAggregateCount,
	); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || auditResourceCount != 1 ||
		outboxCount != 1 || outboxAggregateCount != 1 {
		t.Fatalf("concurrent Publish side effects = audit:%d/%d outbox:%d/%d",
			auditResourceCount, auditCount, outboxAggregateCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationPublishRejectsUnvalidatedRevisionWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revisionVersion int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,revision.version
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
WHERE source.id=$1::uuid
`, fixture.sourceID).Scan(&sourceVersion, &revisionVersion); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	command := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-unvalidated", "9"),
		SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion:    sourceVersion,
		ExpectedRevisionVersion:  revisionVersion,
		ExpectedRevisionDigest:   fixture.revisionDigest,
		ExpectedValidationRunID:  fixture.validationRunID,
		ExpectedValidationDigest: strings.Repeat("9", 64),
	}
	if _, err := repository.Publish(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrSourceRevisionNotValidated,
	) {
		t.Fatalf("Publish(unvalidated) error = %v", err)
	}
	var state, gateStatus string
	var persistedSourceVersion, persistedRevisionVersion int64
	var publishedRevision *int64
	var auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  source.version,source.published_revision,source.gate_status,
  revision.version,revision.state,
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND request_id=$3),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.revision.published.v1')
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&persistedSourceVersion, &publishedRevision, &gateStatus,
		&persistedRevisionVersion, &state, &auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if persistedSourceVersion != sourceVersion || publishedRevision != nil ||
		gateStatus != "UNAVAILABLE" || persistedRevisionVersion != revisionVersion ||
		state != "DRAFT" || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("Publish(unvalidated) side effects = source-version:%d/%d published:%v gate:%s revision-version:%d/%d state:%s audit:%d outbox:%d",
			persistedSourceVersion, sourceVersion, publishedRevision, gateStatus,
			persistedRevisionVersion, revisionVersion, state, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationExternalValidatedPublishFailsClosedWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	proof := strings.Repeat("7", 64)
	finishSourceRevisionExternalValidationOnly(t, harness.db, fixture, proof)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revisionVersion, runVersion int64
	var gateStatus, revisionStatus, runStatus, sourceRunID string
	var publishedRevision *int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.gate_status,source.published_revision,
       source.validated_run_id::text,revision.version,revision.state,
       run.version,run.status
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID).Scan(
		&sourceVersion, &gateStatus, &publishedRevision, &sourceRunID,
		&revisionVersion, &revisionStatus, &runVersion, &runStatus,
	); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	command := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-external-closed", "5"),
		SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion: sourceVersion, ExpectedRevisionVersion: revisionVersion,
		ExpectedRevisionDigest:  fixture.revisionDigest,
		ExpectedValidationRunID: fixture.validationRunID, ExpectedValidationDigest: proof,
	}
	if _, err := repository.Publish(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrUnavailable,
	) {
		t.Fatalf("Publish(external unsupported) error = %v", err)
	}
	var persistedSourceVersion, persistedRevisionVersion, persistedRunVersion int64
	var persistedGateStatus, persistedRevisionStatus, persistedRunStatus, persistedSourceRunID string
	var persistedPublishedRevision *int64
	var auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.gate_status,source.published_revision,
       source.validated_run_id::text,revision.version,revision.state,
       run.version,run.status,
       (SELECT count(*) FROM audit_records
        WHERE workspace_id=$2::uuid AND request_id=$3),
       (SELECT count(*) FROM outbox_events
        WHERE workspace_id=$2::uuid AND event_type='asset.source.revision.published.v1')
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&persistedSourceVersion, &persistedGateStatus, &persistedPublishedRevision,
		&persistedSourceRunID, &persistedRevisionVersion, &persistedRevisionStatus,
		&persistedRunVersion, &persistedRunStatus, &auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if persistedSourceVersion != sourceVersion || persistedGateStatus != gateStatus ||
		persistedPublishedRevision != nil || publishedRevision != nil ||
		persistedSourceRunID != sourceRunID || persistedRevisionVersion != revisionVersion ||
		persistedRevisionStatus != revisionStatus || persistedRunVersion != runVersion ||
		persistedRunStatus != runStatus || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("Publish(external unsupported) side effects = source-version:%d/%d gate:%s/%s published:%v/%v source-run:%s/%s revision-version:%d/%d revision:%s/%s run-version:%d/%d run:%s/%s audit:%d outbox:%d",
			persistedSourceVersion, sourceVersion, persistedGateStatus, gateStatus,
			persistedPublishedRevision, publishedRevision, persistedSourceRunID, sourceRunID,
			persistedRevisionVersion, revisionVersion, persistedRevisionStatus, revisionStatus,
			persistedRunVersion, runVersion, persistedRunStatus, runStatus, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationPublishRejectsVisibleValidationGateBindingDriftWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	revisionOneID := fixture.revisionID
	revisionOneDigest := fixture.revisionDigest
	revisionOneRunID := fixture.validationRunID
	revisionOneProof := strings.Repeat("7", 64)
	finishSourceRevisionExternalValidationOnly(t, harness.db, fixture, revisionOneProof)
	fixture = seedClosureExternalSuccessorDefinition(
		t, harness.db, fixture,
		"8f520000-0000-4000-8000-000000000002", 2, "EXTERNAL_V1",
		[]byte(`{"type":"object","version":2}`), "DEFINITION_CHANGE",
	)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	var sourceVersion int64
	if err := harness.db.QueryRow(context.Background(),
		`SELECT version FROM asset_sources WHERE id=$1::uuid`,
		fixture.sourceID,
	).Scan(&sourceVersion); err != nil {
		t.Fatal(err)
	}
	revisionTwoValidation, err := repository.RequestValidation(
		context.Background(),
		assetcatalog.ValidateSourceRevisionCommand{
			Context:  sourceRevisionMutationContext(t, scope, "validate-revision-two-gate-drift", "4"),
			SourceID: fixture.sourceID, Revision: 2,
			ExpectedSourceVersion: sourceVersion, ExpectedRevisionVersion: 1,
			ExpectedRevisionDigest: fixture.revisionDigest,
		},
	)
	if err != nil {
		t.Fatalf("RequestValidation(revision two) error = %v", err)
	}
	if revisionTwoValidation.Run.Status != assetcatalog.RunStatusQueued {
		t.Fatalf("revision two validation run = %#v", revisionTwoValidation.Run)
	}
	before := readSourceRevisionGateBindingSnapshot(
		t, harness.db, fixture.sourceID, revisionOneID, fixture.revisionID,
	)
	if before.GateStatus != "VALIDATING" ||
		before.GateReasonCode != "VALIDATION_IN_PROGRESS" ||
		before.SourceValidationDigest != "" || before.SourceBindingDigest != "" ||
		before.SourceValidationRunID != revisionTwoValidation.Run.ID ||
		before.RevisionOneValidationRunID != revisionOneRunID ||
		before.RevisionOneStatus != "VALIDATED" ||
		before.RevisionTwoStatus != "VALIDATING" ||
		before.RevisionTwoRunStatus != "QUEUED" {
		t.Fatalf("gate-binding drift fixture = %#v", before)
	}
	command := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-gate-binding-drift", "3"),
		SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion:   before.SourceVersion,
		ExpectedRevisionVersion: before.RevisionOneVersion,
		ExpectedRevisionDigest:  revisionOneDigest,
		ExpectedValidationRunID: revisionOneRunID, ExpectedValidationDigest: revisionOneProof,
	}
	if _, err := repository.Publish(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrStateConflict,
	) {
		t.Fatalf("Publish(gate binding drift) error = %v", err)
	}
	after := readSourceRevisionGateBindingSnapshot(
		t, harness.db, fixture.sourceID, revisionOneID, fixture.revisionID,
	)
	var auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$1::uuid AND request_id=$2),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$1::uuid AND event_type='asset.source.revision.published.v1')
`, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if after != before || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("Publish(gate binding drift) side effects = before:%#v after:%#v audit:%d outbox:%d",
			before, after, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationDisableRejectsClaimedValidationWithoutSideEffects(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		finalizing bool
		wantStatus string
	}{
		{name: "running", wantStatus: "RUNNING"},
		{name: "finalizing", finalizing: true, wantStatus: "FINALIZING"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedDraftAssetCatalog(t, harness.db)
			fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
			if testCase.finalizing {
				prepareCleanupUncertainValidationRun(t, harness.db, fixture)
			}
			repository, err := assetpostgres.New(
				harness.application,
				func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
				deterministicAssetIDGenerator(),
			)
			if err != nil {
				t.Fatal(err)
			}
			var sourceVersion, revisionVersion, runVersion int64
			var sourceRunID, revisionRunID, cleanupStatus string
			if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.validated_run_id::text,
       revision.version,revision.validation_run_id::text,
       run.version,run.cleanup_status
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.validation_run_id=$2::uuid
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.validationRunID).Scan(
				&sourceVersion, &sourceRunID, &revisionVersion, &revisionRunID,
				&runVersion, &cleanupStatus,
			); err != nil {
				t.Fatal(err)
			}
			scope := assetcatalog.SourceScope{
				TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
			}
			command := assetcatalog.DisableSourceCommand{
				Context: sourceRevisionMutationContext(
					t, scope, "disable-"+testCase.name+"-validation", "8",
				),
				SourceID: fixture.sourceID, ReasonCode: "OPERATOR_DISABLED",
				ExpectedSourceVersion: sourceVersion,
			}
			if _, err := repository.Disable(context.Background(), command); !errors.Is(
				err, assetcatalog.ErrStateConflict,
			) {
				t.Fatalf("Disable(%s validation) error = %v", testCase.name, err)
			}
			var sourceStatus, gateStatus, runStatus, persistedSourceRunID string
			var persistedRevisionRunID, persistedCleanupStatus string
			var persistedSourceVersion, persistedRevisionVersion, persistedRunVersion int64
			var auditCount, outboxCount int
			if err := harness.db.QueryRow(context.Background(), `
SELECT
  source.version,source.status,source.gate_status,source.validated_run_id::text,
  revision.version,revision.validation_run_id::text,
  run.version,run.status,run.cleanup_status,
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$3::uuid AND request_id=$4),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$3::uuid AND event_type='asset.source.disabled.v1')
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.validation_run_id=$2::uuid
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.validationRunID, fixture.workspaceID,
				command.Context.IdempotencyKey()).Scan(
				&persistedSourceVersion, &sourceStatus, &gateStatus, &persistedSourceRunID,
				&persistedRevisionVersion, &persistedRevisionRunID,
				&persistedRunVersion, &runStatus, &persistedCleanupStatus,
				&auditCount, &outboxCount,
			); err != nil {
				t.Fatal(err)
			}
			if persistedSourceVersion != sourceVersion || sourceStatus != "ACTIVE" ||
				gateStatus != "VALIDATING" || persistedSourceRunID != sourceRunID ||
				persistedRevisionVersion != revisionVersion ||
				persistedRevisionRunID != revisionRunID ||
				persistedRunVersion != runVersion || runStatus != testCase.wantStatus ||
				persistedCleanupStatus != cleanupStatus || auditCount != 0 || outboxCount != 0 {
				t.Fatalf("Disable(%s validation) side effects = source-version:%d/%d source:%s gate:%s source-run:%s/%s revision-version:%d/%d revision-run:%s/%s run-version:%d/%d run:%s cleanup:%s/%s audit:%d outbox:%d",
					testCase.name, persistedSourceVersion, sourceVersion, sourceStatus, gateStatus,
					persistedSourceRunID, sourceRunID, persistedRevisionVersion, revisionVersion,
					persistedRevisionRunID, revisionRunID, persistedRunVersion, runVersion,
					runStatus, persistedCleanupStatus, cleanupStatus, auditCount, outboxCount)
			}
		})
	}
}

func TestSourceRevisionIntegrationRequestSyncRejectsManualWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revision, checkpointVersion int64
	var revisionDigest string
	var checkpointSHA *string
	if err := harness.db.QueryRow(context.Background(), `
SELECT version,published_revision,published_revision_digest,
       checkpoint_version,checkpoint_sha256
FROM asset_sources
WHERE id=$1::uuid
`, fixture.sourceID).Scan(
		&sourceVersion, &revision, &revisionDigest, &checkpointVersion, &checkpointSHA,
	); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	command := assetcatalog.RequestSyncCommand{
		Context:  sourceRevisionMutationContext(t, scope, "request-manual-sync", "7"),
		SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
		ExpectedRevision: revision, ExpectedRevisionDigest: revisionDigest,
		ExpectedCheckpointVersion: checkpointVersion,
		ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
	}
	if _, err := repository.RequestSync(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrStateConflict,
	) {
		t.Fatalf("RequestSync(MANUAL) error = %v", err)
	}
	var runCount, auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_source_runs
   WHERE source_id=$1::uuid AND run_kind='DISCOVERY'),
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND request_id=$3),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.sync.requested.v1')
`, fixture.sourceID, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&runCount, &auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if runCount != 0 || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("RequestSync(MANUAL) side effects = run:%d audit:%d outbox:%d",
			runCount, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationValidationClosesAvailableGateBeforeCancellingQueuedDiscovery(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	fixture = seedClosureExternalSuccessorDefinition(
		t, harness.db, fixture,
		"8f510000-0000-4000-8000-000000000002", 2, "EXTERNAL_V1",
		[]byte(`{"type":"object","version":2}`), "DEFINITION_CHANGE",
	)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	var sourceVersion int64
	if err := harness.db.QueryRow(context.Background(),
		`SELECT version FROM asset_sources WHERE id=$1`, fixture.sourceID).Scan(&sourceVersion); err != nil {
		t.Fatal(err)
	}
	execAssetSQL(t, harness.db, `
INSERT INTO asset_source_runs (
    id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
    run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
    checkpoint_version,cursor_before_sha256
) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
         'DISCOVERY','HUMAN',gate_revision,'queued-before-validation',repeat('6',64),
         checkpoint_version,checkpoint_sha256
  FROM asset_sources WHERE id=$4
`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID)

	validated, err := repository.RequestValidation(context.Background(), assetcatalog.ValidateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "replace-queued-with-validation", "7"),
		SourceID: fixture.sourceID, Revision: 2,
		ExpectedSourceVersion:   sourceVersion,
		ExpectedRevisionVersion: 1,
		ExpectedRevisionDigest:  fixture.revisionDigest,
	})
	if err != nil {
		t.Fatalf("RequestValidation() error = %v", err)
	}
	var oldStatus string
	if err := harness.db.QueryRow(context.Background(),
		`SELECT status FROM asset_source_runs WHERE id=$1`, fixture.runID).Scan(&oldStatus); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "CANCELLED" || validated.Source.GateStatus != assetcatalog.SourceGateValidating ||
		validated.Run.Status != assetcatalog.RunStatusQueued {
		t.Fatalf("replacement = old:%s new:%#v", oldStatus, validated)
	}
}

func TestSourceRevisionIntegrationExternalSyncReplaySurvivesClaimWithoutDuplicateRun(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	proof := strings.Repeat("7", 64)
	finishClosureExternalValidation(t, harness.db, fixture, 1, proof)
	execAssetSQL(t, harness.db, `
UPDATE integrations
SET secret_ref='secret-canary',
    config='{"endpoint":"https://endpoint.invalid","headers":{"authorization":"header-canary"},"body":"body-canary"}'::jsonb
WHERE id=$1::uuid
`, fixture.integrationID)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	var sourceVersion, revisionVersion, checkpointVersion int64
	var revisionDigest string
	var checkpointSHA *string
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.published_revision_digest,source.checkpoint_version,
       source.checkpoint_sha256,revision.version
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=source.published_revision
WHERE source.id=$1
`, fixture.sourceID).Scan(
		&sourceVersion, &revisionDigest, &checkpointVersion, &checkpointSHA, &revisionVersion,
	); err != nil {
		t.Fatal(err)
	}
	_ = revisionVersion
	command := assetcatalog.RequestSyncCommand{
		Context:  sourceRevisionMutationContext(t, scope, "request-external-sync", "8"),
		SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
		ExpectedRevision: 1, ExpectedRevisionDigest: revisionDigest,
		ExpectedCheckpointVersion: checkpointVersion,
		ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
	}
	first, err := repository.RequestSync(context.Background(), command)
	if err != nil {
		t.Fatalf("RequestSync() error = %v", err)
	}
	if first.Run.Status != assetcatalog.RunStatusQueued ||
		first.Source.Version != sourceVersion || first.Receipt.IdempotentReplay {
		t.Fatalf("RequestSync() = %#v", first)
	}
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET status='RUNNING',stage_code='READING',lease_owner='sync-replay-worker',
    lease_expires_at=clock_timestamp()+interval '5 minutes',fence_epoch=1,
    fence_token_hash=repeat('9',64),heartbeat_sequence=1,version=version+1
WHERE id=$1
`, first.Run.ID)
	replay, err := repository.RequestSync(context.Background(), command)
	if err != nil {
		t.Fatalf("RequestSync(claimed replay) error = %v", err)
	}
	if !replay.Receipt.IdempotentReplay || replay.Run.ID != first.Run.ID ||
		replay.Run.Status != assetcatalog.RunStatusRunning {
		t.Fatalf("RequestSync(claimed replay) = %#v", replay)
	}
	var runCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT count(*) FROM asset_source_runs
WHERE source_id=$1 AND run_kind='DISCOVERY'
`, fixture.sourceID).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 {
		t.Fatalf("DISCOVERY run count = %d", runCount)
	}
	assertSourceMutationSideEffectsDLP(
		t,
		harness.db,
		fixture.workspaceID,
		closureExternalProfileManifestV1,
		`{"type":"object"}`,
		`{"endpoint":"https://endpoint.invalid","headers":{"authorization":"header-canary"},"body":"body-canary"}`,
		"EXTERNAL_V1",
		"additionalProperties",
		"opaque-credential",
		"secret-canary",
		"https://endpoint.invalid",
		"authorization",
		"header-canary",
		"body-canary",
		"canonical_profile_manifest",
		"canonical_provider_schema",
	)
}

func TestSourceRevisionIntegrationConcurrentExternalSyncHasOneNonterminalWinner(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revision, checkpointVersion int64
	var revisionDigest string
	var checkpointSHA *string
	if err := harness.db.QueryRow(context.Background(), `
SELECT version,published_revision,published_revision_digest,
       checkpoint_version,checkpoint_sha256
FROM asset_sources
WHERE id=$1::uuid
`, fixture.sourceID).Scan(
		&sourceVersion, &revision, &revisionDigest, &checkpointVersion, &checkpointSHA,
	); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	commands := []assetcatalog.RequestSyncCommand{
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-external-sync-a", "a"),
			SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
			ExpectedRevision: revision, ExpectedRevisionDigest: revisionDigest,
			ExpectedCheckpointVersion: checkpointVersion,
			ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
		},
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-external-sync-b", "b"),
			SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
			ExpectedRevision: revision, ExpectedRevisionDigest: revisionDigest,
			ExpectedCheckpointVersion: checkpointVersion,
			ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
		},
	}
	type callResult struct {
		value assetcatalog.SourceRunMutation
		err   error
	}
	start := make(chan struct{})
	results := make(chan callResult, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			value, callErr := repository.RequestSync(context.Background(), command)
			results <- callResult{value: value, err: callErr}
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	var winner assetcatalog.SourceRunMutation
	for range commands {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.value
		case errors.Is(result.err, assetcatalog.ErrStateConflict):
			conflicts++
		default:
			t.Fatalf("concurrent RequestSync() error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 ||
		winner.Run.Status != assetcatalog.RunStatusQueued ||
		winner.Source.Version != sourceVersion {
		t.Fatalf("concurrent RequestSync outcomes = success:%d conflict:%d winner:%#v",
			successes, conflicts, winner)
	}
	var runCount, auditCount, auditResourceCount, outboxCount, outboxAggregateCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_source_runs
   WHERE source_id=$1::uuid AND run_kind='DISCOVERY'),
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND action='asset.source.sync.requested.v1'),
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND action='asset.source.sync.requested.v1'
     AND resource_type='ASSET_SOURCE' AND resource_id=$1),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.sync.requested.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.sync.requested.v1'
     AND aggregate_type='ASSET_SOURCE_RUN' AND aggregate_id=$3::uuid)
`, fixture.sourceID, fixture.workspaceID, winner.Run.ID).Scan(
		&runCount, &auditCount, &auditResourceCount, &outboxCount, &outboxAggregateCount,
	); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 || auditCount != 1 || auditResourceCount != 1 ||
		outboxCount != 1 || outboxAggregateCount != 1 {
		t.Fatalf("concurrent RequestSync side effects = run:%d audit:%d/%d outbox:%d/%d",
			runCount, auditResourceCount, auditCount, outboxAggregateCount, outboxCount)
	}
}

type sourceCreationScopeFixture struct {
	tenantID, workspaceID, environmentID string
	secondEnvironmentID                  string
	otherWorkspaceID, otherEnvironmentID string
}

func seedSourceCreationScope(t *testing.T, database *pgxpool.Pool) sourceCreationScopeFixture {
	t.Helper()
	fixture := sourceCreationScopeFixture{
		tenantID:            "10000000-0000-4000-8000-000000000211",
		workspaceID:         "20000000-0000-4000-8000-000000000211",
		environmentID:       "30000000-0000-4000-8000-000000000211",
		secondEnvironmentID: "30000000-0000-4000-8000-000000000212",
		otherWorkspaceID:    "20000000-0000-4000-8000-000000000219",
		otherEnvironmentID:  "30000000-0000-4000-8000-000000000219",
	}
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin Source creation fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx,
		`INSERT INTO tenants (id,name) VALUES ($1,'source-create-tenant')`,
		fixture.tenantID)
	execAssetSQL(t, tx,
		`INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,'source-create-workspace')`,
		fixture.workspaceID, fixture.tenantID)
	execAssetSQL(t, tx,
		`INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,'other-source-workspace')`,
		fixture.otherWorkspaceID, fixture.tenantID)
	execAssetSQL(t, tx, `
INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
VALUES ($1,$2,$3,'source-create-production','PROD')
`, fixture.environmentID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, tx, `
INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
VALUES ($1,$2,$3,'source-create-staging','STAGING')
`, fixture.secondEnvironmentID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, tx, `
INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
VALUES ($1,$2,$3,'other-source-production','PROD')
`, fixture.otherEnvironmentID, fixture.tenantID, fixture.otherWorkspaceID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit Source creation fixture: %v", err)
	}
	return fixture
}

func manualSourceCreateCommand(
	t *testing.T,
	fixture sourceCreationScopeFixture,
	key, digestCharacter string,
) assetcatalog.CreateSourceCommand {
	t.Helper()
	scope := assetcatalog.SourceScope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
	}
	return assetcatalog.CreateSourceCommand{
		Context:                 sourceRevisionMutationContext(t, scope, key, digestCharacter),
		Name:                    "fixture manual source",
		SourceProfileID:         assetcatalog.SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{fixture.environmentID},
	}
}

func assertSourceCreateClosureCounts(
	t *testing.T,
	database *pgxpool.Pool,
	workspaceID string,
	wantSources, wantRevisions, wantAuthorities, wantAudits, wantOutbox int,
) {
	t.Helper()
	var sources, revisions, authorities, audits, outbox int
	if err := database.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_sources WHERE workspace_id=$1::uuid),
  (SELECT count(*) FROM asset_source_revisions WHERE workspace_id=$1::uuid),
  (SELECT count(*) FROM asset_source_revision_authorities WHERE workspace_id=$1::uuid),
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$1::uuid AND resource_type='ASSET_SOURCE'
     AND action='asset.source.revision.created.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$1::uuid AND aggregate_type='ASSET_SOURCE'
     AND event_type='asset.source.revision.created.v1')
`, workspaceID).Scan(&sources, &revisions, &authorities, &audits, &outbox); err != nil {
		t.Fatalf("read Source creation closure counts: %v", err)
	}
	if sources != wantSources || revisions != wantRevisions ||
		authorities != wantAuthorities || audits != wantAudits || outbox != wantOutbox {
		t.Fatalf(
			"Source creation closure = sources:%d revisions:%d authorities:%d audit:%d outbox:%d; want %d/%d/%d/%d/%d",
			sources, revisions, authorities, audits, outbox,
			wantSources, wantRevisions, wantAuthorities, wantAudits, wantOutbox,
		)
	}
}

func sourceRevisionMutationContext(
	t *testing.T,
	scope assetcatalog.SourceScope,
	key string,
	digestCharacter string,
) assetcatalog.MutationContext {
	t.Helper()
	value, err := assetcatalog.NewSourceMutationContext(authn.Principal{
		Subject: "source-manager", TenantID: scope.TenantID,
		AuthenticatedAt: time.Date(2026, 7, 17, 3, 0, 0, 0, time.UTC),
	}, scope, assetcatalog.MutationMetadata{
		TraceID: "trace-" + key, IdempotencyKey: key,
		RequestHash: strings.Repeat(digestCharacter, 64),
	})
	if err != nil {
		t.Fatalf("NewSourceMutationContext() error = %v", err)
	}
	return value
}

func assertSourceValidationSystemReceipts(t *testing.T, database *pgxpool.Pool, runID string) {
	t.Helper()
	var cleanup, terminal int
	if err := database.QueryRow(context.Background(), `
		SELECT
			count(*) FILTER (WHERE action='ATTEMPT_CLEANED' AND request_id='source-attempt:'||$1::text||':0'),
			count(*) FILTER (WHERE action='TERMINAL_COMMITTED' AND request_id='source-terminal:'||$1::text)
		FROM audit_records
		WHERE resource_type='ASSET_SOURCE_RUN' AND resource_id=$1::text
	`, runID).Scan(&cleanup, &terminal); err != nil {
		t.Fatalf("read validation SYSTEM receipts: %v", err)
	}
	if cleanup != 1 || terminal != 1 {
		t.Fatalf("validation SYSTEM receipts = cleanup:%d terminal:%d", cleanup, terminal)
	}
}

func finishSourceRevisionExternalValidationOnly(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	proof string,
) {
	t.Helper()
	execAssetSQL(t, database, `
UPDATE asset_source_runs
SET stage_code='CLEANING_UP',cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
    cleanup_attempt_epoch=fence_epoch,version=version+1
WHERE id=$1::uuid
`, fixture.validationRunID)
	execAssetSQL(t, database, `
UPDATE asset_source_runs
SET status='FINALIZING',work_result_kind='VALIDATION_PROOF',
    work_result_status='SUCCEEDED',work_result_digest=$2,
    work_result_recorded_at=statement_timestamp(),validation_outcome='SUCCEEDED',
    validation_digest=$2,validation_proof_digest=$2,version=version+1
WHERE id=$1::uuid
`, fixture.validationRunID, proof)
	revokeClosureAttempt(t, database, fixture, fixture.validationRunID, strings.Repeat("6", 64))
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external validation-only terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, fixture.validationRunID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
UPDATE asset_source_runs
SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
    version=version+1
WHERE id=$1::uuid
`, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
UPDATE asset_source_revisions
SET state='VALIDATED',validation_digest=$2,version=version+1
WHERE id=$1::uuid
`, fixture.revisionID, proof)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external validation-only terminal closure: %v", err)
	}
}

type sourceRevisionGateBindingSnapshot struct {
	SourceVersion               int64
	SourceStatus                string
	GateStatus                  string
	GateReasonCode              string
	SourceValidationRunID       string
	SourceValidationDigest      string
	SourceBindingDigest         string
	RevisionOneVersion          int64
	RevisionOneStatus           string
	RevisionOneValidationRunID  string
	RevisionOneValidationDigest string
	RevisionTwoVersion          int64
	RevisionTwoStatus           string
	RevisionTwoValidationRunID  string
	RevisionTwoValidationDigest string
	RevisionTwoRunVersion       int64
	RevisionTwoRunStatus        string
	RevisionTwoCleanupStatus    string
}

func readSourceRevisionGateBindingSnapshot(
	t *testing.T,
	database *pgxpool.Pool,
	sourceID, revisionOneID, revisionTwoID string,
) sourceRevisionGateBindingSnapshot {
	t.Helper()
	var snapshot sourceRevisionGateBindingSnapshot
	if err := database.QueryRow(context.Background(), `
SELECT source.version,source.status,source.gate_status,source.gate_reason_code,
       source.validated_run_id::text,COALESCE(source.validation_digest,''),
       COALESCE(source.validated_binding_digest,''),
       revision_one.version,revision_one.state,revision_one.validation_run_id::text,
       COALESCE(revision_one.validation_digest,''),
       revision_two.version,revision_two.state,revision_two.validation_run_id::text,
       COALESCE(revision_two.validation_digest,''),
       run.version,run.status,run.cleanup_status
FROM asset_sources AS source
JOIN asset_source_revisions AS revision_one ON revision_one.id=$2::uuid
JOIN asset_source_revisions AS revision_two ON revision_two.id=$3::uuid
JOIN asset_source_runs AS run ON run.id=revision_two.validation_run_id
WHERE source.id=$1::uuid
  AND revision_one.source_id=source.id
  AND revision_two.source_id=source.id
`, sourceID, revisionOneID, revisionTwoID).Scan(
		&snapshot.SourceVersion, &snapshot.SourceStatus,
		&snapshot.GateStatus, &snapshot.GateReasonCode,
		&snapshot.SourceValidationRunID, &snapshot.SourceValidationDigest,
		&snapshot.SourceBindingDigest, &snapshot.RevisionOneVersion,
		&snapshot.RevisionOneStatus, &snapshot.RevisionOneValidationRunID,
		&snapshot.RevisionOneValidationDigest, &snapshot.RevisionTwoVersion,
		&snapshot.RevisionTwoStatus, &snapshot.RevisionTwoValidationRunID,
		&snapshot.RevisionTwoValidationDigest, &snapshot.RevisionTwoRunVersion,
		&snapshot.RevisionTwoRunStatus, &snapshot.RevisionTwoCleanupStatus,
	); err != nil {
		t.Fatalf("read source revision gate binding snapshot: %v", err)
	}
	return snapshot
}

func assertSourceMutationSideEffectsDLP(
	t *testing.T,
	database *pgxpool.Pool,
	workspaceID string,
	forbidden ...string,
) {
	t.Helper()
	var auditDetails, outboxPayloads string
	if err := database.QueryRow(context.Background(), `
SELECT COALESCE(string_agg(details::text,E'\n'),'')
FROM audit_records
WHERE workspace_id=$1::uuid AND action LIKE 'asset.source.%'
`, workspaceID).Scan(&auditDetails); err != nil {
		t.Fatalf("read source mutation audit DLP surface: %v", err)
	}
	if err := database.QueryRow(context.Background(), `
SELECT COALESCE(string_agg(payload::text,E'\n'),'')
FROM outbox_events
WHERE workspace_id=$1::uuid AND event_type LIKE 'asset.source.%'
`, workspaceID).Scan(&outboxPayloads); err != nil {
		t.Fatalf("read source mutation outbox DLP surface: %v", err)
	}
	if auditDetails == "" || outboxPayloads == "" {
		t.Fatalf("source mutation DLP surfaces are empty: audit=%q outbox=%q",
			auditDetails, outboxPayloads)
	}
	persisted := strings.ToLower(auditDetails + "\n" + outboxPayloads)
	for _, value := range forbidden {
		normalized := strings.ToLower(value)
		encoded := strings.ToLower(base64.StdEncoding.EncodeToString([]byte(value)))
		if strings.Contains(persisted, normalized) ||
			strings.Contains(persisted, encoded) {
			t.Errorf("source mutation Audit/Outbox persisted forbidden value %q", value)
		}
	}
}

func optionalIntegrationString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
