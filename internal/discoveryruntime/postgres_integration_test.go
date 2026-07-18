package discoveryruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	queuepostgres "github.com/seaworld008/aiops-system/internal/discoveryqueue/postgres"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/discoveryworker"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

func TestPostgresExternalCMDBRuntimeAuthorityIntegration(t *testing.T) {
	harness := newRuntimePostgresHarness(t)
	harness.applyMigrations(t)
	assertRuntimePostgresTLSIdentity(t, harness)
	fixture := seedRuntimeValidationAttempt(t, harness)
	resolver, err := NewPostgres(harness.application)
	if err != nil {
		t.Fatalf("NewPostgres() error = %v", err)
	}
	key, err := newExternalCMDBAttemptKey(fixture.open)
	if err != nil {
		t.Fatal(err)
	}
	adminResolver, err := NewPostgres(harness.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adminResolver.resolveExternalCMDBAttempt(
		t.Context(),
		key,
	); !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("test-admin identity runtime resolve error = %v", err)
	}

	snapshot, err := resolver.resolveExternalCMDBAttempt(t.Context(), key)
	if err != nil {
		t.Fatalf("resolveExternalCMDBAttempt() error = %v", err)
	}
	if snapshot.binding != fixture.binding ||
		snapshot.references.integrationID != fixture.integrationID ||
		snapshot.references.credentialReferenceID != fixture.credentialReferenceID ||
		snapshot.references.trustReferenceID != fixture.trustReferenceID ||
		snapshot.references.networkPolicyReferenceID != fixture.networkReferenceID ||
		snapshot.environmentID != fixture.environmentID ||
		!snapshot.initialAllowed {
		t.Fatalf("PostgreSQL snapshot = %#v", snapshot)
	}
	var forbidden string
	err = harness.application.QueryRow(
		t.Context(),
		`SELECT secret_ref FROM public.integrations WHERE id=$1::uuid`,
		fixture.integrationID,
	).Scan(&forbidden)
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
		t.Fatalf("application identity read integrations.secret_ref error = %v, want 42501", err)
	}
	_, err = harness.application.Exec(
		t.Context(),
		`UPDATE public.asset_source_revisions
SET credential_reference_id='drifted-runtime-reference'
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid`,
		fixture.tenantID,
		fixture.workspaceID,
		fixture.revisionID,
	)
	databaseError = nil
	if !errors.As(err, &databaseError) ||
		databaseError.Code != "55000" ||
		databaseError.ConstraintName !=
			"asset_source_revisions_canonical_immutable_guard" {
		t.Fatalf("application identity immutable-reference drift error = %v", err)
	}

	materials := &recordingMaterialResolver{want: snapshot}
	authority, err := newExternalCMDBAuthority(resolver, materials)
	if err != nil {
		t.Fatalf("newExternalCMDBAuthority(real PostgreSQL) error = %v", err)
	}
	t.Cleanup(authority.Destroy)
	binding, err := authority.ResolveRuntimeBinding(t.Context(), fixture.open)
	if err != nil || binding != fixture.binding {
		t.Fatalf("ResolveRuntimeBinding(real PostgreSQL) = %#v,%v", binding, err)
	}
	bound, lifecycle, err := authority.materialize(t.Context(), key, binding)
	if err != nil || bound.Binding() != binding || lifecycle == nil || materials.calls != 1 {
		t.Fatalf("materialize(real PostgreSQL) = %#v,%#v,%v calls=%d", bound, lifecycle, err, materials.calls)
	}
	bound.Clear()
	if err := lifecycle.Revoke(t.Context()); err != nil {
		t.Fatalf("lifecycle.Revoke() error = %v", err)
	}
	lifecycle.Destroy()

	wrongScope := key
	wrongScope.coordinates.Scope.WorkspaceID = uuid.NewString()
	if _, err := resolver.resolveExternalCMDBAttempt(
		t.Context(), wrongScope,
	); !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("wrong-Scope resolve error = %v", err)
	}
	staleAttempt := key
	staleAttempt.attempt.AttemptID = uuid.NewString()
	if _, err := resolver.resolveExternalCMDBAttempt(
		t.Context(), staleAttempt,
	); !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("stale-attempt resolve error = %v", err)
	}
	staleEpoch := key
	staleEpoch.attempt.AttemptEpoch++
	if _, err := resolver.resolveExternalCMDBAttempt(
		t.Context(), staleEpoch,
	); !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("stale-epoch resolve error = %v", err)
	}

	driftMaterials := &recordingMaterialResolver{want: snapshot}
	driftAuthority, err := newExternalCMDBAuthority(resolver, driftMaterials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driftAuthority.Destroy)
	if _, err := driftAuthority.ResolveRuntimeBinding(t.Context(), fixture.open); err != nil {
		t.Fatalf("prime drift authority error = %v", err)
	}
	driftedBinding := fixture.binding
	driftedBinding.SourceRevisionDigest = strings.Repeat("c", 64)
	if runtime, runtimeLifecycle, err := driftAuthority.materialize(
		t.Context(), key, driftedBinding,
	); !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		runtime.Clear()
		if runtimeLifecycle != nil {
			runtimeLifecycle.Destroy()
		}
		t.Fatalf("binding-drift materialize error = %v", err)
	}
	if driftMaterials.calls != 0 {
		t.Fatalf("binding drift reached material resolver: %d calls", driftMaterials.calls)
	}

	admissionMaterials := &recordingMaterialResolver{
		want:           snapshot,
		resolveStarted: make(chan struct{}),
		resolveRelease: make(chan struct{}),
	}
	admissionAuthority, err := newExternalCMDBAuthority(
		resolver,
		admissionMaterials,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admissionAuthority.Destroy)
	admissionBinding, err := admissionAuthority.ResolveRuntimeBinding(
		t.Context(),
		fixture.open,
	)
	if err != nil {
		t.Fatalf("prime locked-admission authority error = %v", err)
	}
	type materializeResult struct {
		runtime   discoverysource.BoundRuntime
		lifecycle discoveryworker.InitialRuntimeLifecycle
		err       error
	}
	materialized := make(chan materializeResult, 1)
	go func() {
		runtime, lifecycle, materializeErr := admissionAuthority.materialize(
			t.Context(),
			key,
			admissionBinding,
		)
		materialized <- materializeResult{
			runtime: runtime, lifecycle: lifecycle, err: materializeErr,
		}
	}()
	<-admissionMaterials.resolveStarted
	blockedMutations := []struct {
		name      string
		statement string
		arguments []any
	}{
		{
			name: "source disable and gate drift",
			statement: `
UPDATE public.asset_sources
SET status='DISABLED',gate_status='UNAVAILABLE',
    version=version+1,updated_at=statement_timestamp()
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`,
			arguments: []any{
				fixture.tenantID,
				fixture.workspaceID,
				fixture.sourceID,
			},
		},
		{
			name: "run lease expiry and fence drift",
			statement: `
UPDATE public.asset_source_runs
SET lease_expires_at=clock_timestamp(),fence_epoch=fence_epoch+1,
    version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`,
			arguments: []any{
				fixture.tenantID,
				fixture.workspaceID,
				fixture.runID,
			},
		},
	}
	for _, mutation := range blockedMutations {
		updateContext, cancelUpdate := context.WithTimeout(
			t.Context(),
			250*time.Millisecond,
		)
		_, updateErr := harness.application.Exec(
			updateContext,
			mutation.statement,
			mutation.arguments...,
		)
		cancelUpdate()
		if !errors.Is(updateErr, context.DeadlineExceeded) {
			close(admissionMaterials.resolveRelease)
			result := <-materialized
			result.runtime.Clear()
			if result.lifecycle != nil {
				result.lifecycle.Destroy()
			}
			t.Fatalf(
				"%s during material admission error = %v, want lock deadline",
				mutation.name,
				updateErr,
			)
		}
	}
	close(admissionMaterials.resolveRelease)
	result := <-materialized
	if result.err != nil || result.runtime.Binding() != admissionBinding ||
		result.lifecycle == nil {
		result.runtime.Clear()
		if result.lifecycle != nil {
			result.lifecycle.Destroy()
		}
		t.Fatalf(
			"locked material admission = %#v,%#v,%v",
			result.runtime,
			result.lifecycle,
			result.err,
		)
	}
	result.runtime.Clear()
	if err := result.lifecycle.Revoke(t.Context()); err != nil {
		t.Fatalf("locked material lifecycle Revoke() error = %v", err)
	}
	result.lifecycle.Destroy()

	betweenMaterials := &recordingMaterialResolver{want: snapshot}
	betweenAuthority, err := newExternalCMDBAuthority(resolver, betweenMaterials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(betweenAuthority.Destroy)
	betweenBinding, err := betweenAuthority.ResolveRuntimeBinding(
		t.Context(),
		fixture.open,
	)
	if err != nil {
		t.Fatalf("prime between-read authority error = %v", err)
	}
	runtimeExec(t, harness.db, `
UPDATE public.asset_sources
SET status='DISABLED',version=version+1,updated_at=statement_timestamp()
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	if runtime, runtimeLifecycle, err := betweenAuthority.materialize(
		t.Context(), key, betweenBinding,
	); !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		runtime.Clear()
		if runtimeLifecycle != nil {
			runtimeLifecycle.Destroy()
		}
		t.Fatalf("between-read disable materialize error = %v", err)
	}
	if betweenMaterials.calls != 0 {
		t.Fatalf(
			"between-read disable reached material resolver: %d calls",
			betweenMaterials.calls,
		)
	}
	disabledMaterials := &recordingMaterialResolver{want: snapshot}
	disabledAuthority, err := newExternalCMDBAuthority(resolver, disabledMaterials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(disabledAuthority.Destroy)
	disabledBinding, err := disabledAuthority.ResolveRuntimeBinding(
		t.Context(),
		fixture.open,
	)
	if err != nil || disabledBinding != fixture.binding {
		t.Fatalf(
			"disabled Source recovery binding = %#v,%v",
			disabledBinding,
			err,
		)
	}
	if runtime, runtimeLifecycle, materializeErr :=
		disabledAuthority.materialize(
			t.Context(),
			key,
			disabledBinding,
		); !errors.Is(
		materializeErr,
		ErrExternalCMDBRuntimeAuthority,
	) {
		runtime.Clear()
		if runtimeLifecycle != nil {
			runtimeLifecycle.Destroy()
		}
		t.Fatalf(
			"disabled Source initial materialize error = %v",
			materializeErr,
		)
	}
	if replay, replayErr := disabledAuthority.ResolveRuntimeBinding(
		t.Context(), fixture.open,
	); replayErr != nil || replay != fixture.binding {
		t.Fatalf("disabled Source recovery binding replay = %#v,%v", replay, replayErr)
	}
	if disabledMaterials.calls != 0 {
		t.Fatalf(
			"disabled Source recovery reached material resolver: %d calls",
			disabledMaterials.calls,
		)
	}

	reclaimedFixture := seedRuntimeValidationAttemptWithLease(
		t,
		harness,
		75*time.Millisecond,
	)
	reclaimedKey, err := newExternalCMDBAttemptKey(reclaimedFixture.open)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(125 * time.Millisecond)
	reclaimQueue, err := queuepostgres.New(
		harness.application,
		runtimeCleanupVerifier{},
		runtimeRolloverVerifier{},
	)
	if err != nil {
		t.Fatal(err)
	}
	reclaimed, err := reclaimQueue.Reclaim(
		t.Context(),
		discoveryqueue.ReclaimCommand{
			Owner:         "runtime-postgres-replacement-worker",
			LeaseDuration: 30 * time.Second,
			ProviderKinds: []string{"CMDB_CATALOG_V1"},
		},
	)
	if err != nil {
		t.Fatalf("Reclaim(pending External CMDB attempt) error = %v", err)
	}
	t.Cleanup(reclaimed.Destroy)
	if reclaimed.Mode != discoveryqueue.ClaimModeCleanupOnly ||
		reclaimed.CleanupAttempt == nil ||
		*reclaimed.CleanupAttempt != reclaimedFixture.open.Attempt ||
		reclaimed.Run.FenceEpoch !=
			reclaimedFixture.open.Attempt.AttemptEpoch+1 {
		t.Fatalf(
			"reclaimed cleanup claim = mode:%s attempt:%#v fence:%d",
			reclaimed.Mode,
			reclaimed.CleanupAttempt,
			reclaimed.Run.FenceEpoch,
		)
	}

	reclaimedSnapshot, err := resolver.resolveExternalCMDBAttempt(
		t.Context(),
		reclaimedKey,
	)
	if err != nil {
		t.Fatalf("resolve reclaimed cleanup attempt error = %v", err)
	}
	if reclaimedSnapshot.binding != reclaimedFixture.binding ||
		reclaimedSnapshot.initialAllowed {
		t.Fatalf(
			"reclaimed cleanup snapshot binding=%#v initialAllowed=%t",
			reclaimedSnapshot.binding,
			reclaimedSnapshot.initialAllowed,
		)
	}
	reclaimedMaterials := &recordingMaterialResolver{want: reclaimedSnapshot}
	reclaimedAuthority, err := newExternalCMDBAuthority(
		resolver,
		reclaimedMaterials,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reclaimedAuthority.Destroy)
	reclaimedBinding, err := reclaimedAuthority.ResolveRuntimeBinding(
		t.Context(),
		reclaimedFixture.open,
	)
	if err != nil || reclaimedBinding != reclaimedFixture.binding {
		t.Fatalf(
			"reclaimed cleanup binding = %#v,%v",
			reclaimedBinding,
			err,
		)
	}
	if runtime, runtimeLifecycle, materializeErr :=
		reclaimedAuthority.materialize(
			t.Context(),
			reclaimedKey,
			reclaimedBinding,
		); !errors.Is(
		materializeErr,
		ErrExternalCMDBRuntimeAuthority,
	) {
		runtime.Clear()
		if runtimeLifecycle != nil {
			runtimeLifecycle.Destroy()
		}
		t.Fatalf(
			"reclaimed cleanup initial materialize error = %v",
			materializeErr,
		)
	}
	if reclaimedMaterials.calls != 0 {
		t.Fatalf(
			"reclaimed cleanup reached material resolver: %d calls",
			reclaimedMaterials.calls,
		)
	}
}

type runtimeValidationFixture struct {
	tenantID, workspaceID, environmentID, integrationID string
	sourceID, revisionID, runID                         string
	credentialReferenceID, trustReferenceID             string
	networkReferenceID                                  string
	binding                                             discoverysource.RuntimeBinding
	open                                                discoverycleanup.OpenAttemptRequest
}

func seedRuntimeValidationAttempt(
	t *testing.T,
	harness *runtimePostgresHarness,
) runtimeValidationFixture {
	t.Helper()
	return seedRuntimeValidationAttemptWithLease(t, harness, 30*time.Second)
}

func seedRuntimeValidationAttemptWithLease(
	t *testing.T,
	harness *runtimePostgresHarness,
	leaseDuration time.Duration,
) runtimeValidationFixture {
	t.Helper()
	fixture := runtimeValidationFixture{
		tenantID: uuid.NewString(), workspaceID: uuid.NewString(),
		environmentID: uuid.NewString(), integrationID: uuid.NewString(),
		sourceID: uuid.NewString(), revisionID: uuid.NewString(), runID: uuid.NewString(),
		credentialReferenceID: "external-cmdb-postgres-credential",
		trustReferenceID:      "external-cmdb-postgres-trust",
		networkReferenceID:    "external-cmdb-postgres-network",
	}
	runtimeExec(t, harness.db, `INSERT INTO public.tenants(id,name) VALUES($1,'runtime-tenant')`, fixture.tenantID)
	runtimeExec(t, harness.db, `INSERT INTO public.workspaces(id,tenant_id,name) VALUES($1,$2,'runtime-workspace')`, fixture.workspaceID, fixture.tenantID)
	runtimeExec(t, harness.db, `INSERT INTO public.environments(id,tenant_id,workspace_id,name,kind) VALUES($1,$2,$3,'runtime-environment','PROD')`, fixture.environmentID, fixture.tenantID, fixture.workspaceID)
	runtimeExec(t, harness.db, `INSERT INTO public.integrations(id,tenant_id,workspace_id,provider,name,secret_ref,config) VALUES($1,$2,$3,'external','runtime-integration','opaque://must-not-read','{"endpoint":"must-not-read"}')`, fixture.integrationID, fixture.tenantID, fixture.workspaceID)

	descriptor := sourceprofile.ExternalCMDBV1()
	registration, err := descriptor.Registration(sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID:            fixture.integrationID,
		CredentialReferenceID:    assetcatalog.CredentialReferenceID(fixture.credentialReferenceID),
		TrustReferenceID:         assetcatalog.TrustReferenceID(fixture.trustReferenceID),
		NetworkPolicyReferenceID: assetcatalog.NetworkPolicyReferenceID(fixture.networkReferenceID),
	})
	if err != nil {
		t.Fatalf("External CMDB registration: %v", err)
	}
	profile := registration.Profile
	authorityIDs := []string{fixture.environmentID}
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(authorityIDs)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	revision := assetcatalog.SourceRevision{
		ID: fixture.revisionID, SourceID: fixture.sourceID,
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
		Revision: 1, Status: assetcatalog.SourceRevisionDraft,
		CanonicalProfileManifest:      profile.CanonicalProfileManifest,
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchema:       profile.CanonicalProviderSchema,
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 fixture.integrationID, SyncMode: profile.SyncMode,
		CredentialReferenceID:    profile.CredentialReferenceID,
		TrustReferenceID:         profile.TrustReferenceID,
		NetworkPolicyReferenceID: profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:  authorityIDs, AuthorityScopeDigest: authorityDigest,
		RateLimitRequests:       profile.RateLimitRequests,
		RateLimitWindowSeconds:  profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds: profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:  profile.BackpressureMaxSeconds,
		ProfileCode:             profile.ProfileCode, CreatedBy: "runtime-integration",
		ChangeReasonCode: "INITIAL_CREATE", ExpectedSourceVersion: 1,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	revision.SourceDefinitionDigest, err = assetcatalog.SourceDefinitionDigest(
		assetcatalog.Source{
			Kind:         assetcatalog.SourceKindExternalCMDB,
			ProviderKind: descriptor.ProviderKind(),
		},
		revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()

	tx, err := harness.db.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	runtimeExec(t, tx, `
INSERT INTO public.asset_sources(
 id,tenant_id,workspace_id,source_kind,provider_kind,name,
 create_idempotency_key,create_request_hash
) VALUES($1,$2,$3,'EXTERNAL_CMDB','CMDB_CATALOG_V1','runtime external cmdb',
         $4,repeat('1',64))
`, fixture.sourceID, fixture.tenantID, fixture.workspaceID, "runtime-source-"+fixture.sourceID)
	runtimeExec(t, tx, `
INSERT INTO public.asset_source_revisions(
 id,tenant_id,workspace_id,source_id,revision,state,
 canonical_profile_manifest,profile_manifest_sha256,
 canonical_provider_schema,canonical_provider_schema_sha256,
 integration_id,sync_mode,authority_scope_digest,source_definition_digest,
 canonical_revision_digest,credential_reference_id,trust_reference_id,
 network_policy_reference_id,rate_limit_requests,rate_limit_window_seconds,
 backpressure_base_seconds,backpressure_max_seconds,profile_code,
 created_by,change_reason_code,expected_source_version
) VALUES(
 $1,$2,$3,$4,1,'DRAFT',$5,$6,$7,$8,$9,'ON_DEMAND',$10,$11,$12,
 $13,$14,$15,5,1,1,60,'CMDB_CATALOG_V1',
 'runtime-integration','INITIAL_CREATE',1
)
`, revision.ID, revision.TenantID, revision.WorkspaceID, revision.SourceID,
		revision.CanonicalProfileManifest, revision.ProfileManifestSHA256,
		revision.CanonicalProviderSchema, revision.CanonicalProviderSchemaSHA256,
		revision.IntegrationID, revision.AuthorityScopeDigest,
		revision.SourceDefinitionDigest, revision.CanonicalRevisionDigest,
		revision.CredentialReferenceID, revision.TrustReferenceID,
		revision.NetworkPolicyReferenceID)
	runtimeExec(t, tx, `
INSERT INTO public.asset_source_revision_authorities(
 tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
) VALUES($1,$2,$3,1,$4,1)
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit External CMDB definition: %v", err)
	}

	tx, err = harness.db.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	runtimeExec(t, tx, `
INSERT INTO public.asset_source_runs(
 id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
 run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,$6,repeat('2',64),0
  FROM public.asset_sources WHERE id=$4::uuid
`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		revision.CanonicalRevisionDigest, "runtime-run-"+fixture.runID)
	runtimeExec(t, tx, `
UPDATE public.asset_source_revisions
SET state='VALIDATING',validation_run_id=$2::uuid,version=version+1
WHERE id=$1::uuid
`, fixture.revisionID, fixture.runID)
	runtimeExec(t, tx, `
UPDATE public.asset_sources
SET gate_status='VALIDATING',gate_revision=gate_revision+1,
    validated_run_id=$2::uuid,validation_digest=NULL,
    validated_binding_digest=NULL,version=version+1
WHERE id=$1::uuid
`, fixture.sourceID, fixture.runID)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit External CMDB validation admission: %v", err)
	}

	queue, err := queuepostgres.New(
		harness.application,
		runtimeCleanupVerifier{},
		runtimeRolloverVerifier{},
	)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := queue.Claim(t.Context(), discoveryqueue.ClaimCommand{
		Owner: "runtime-postgres-worker", LeaseDuration: leaseDuration,
		ProviderKinds: []string{"CMDB_CATALOG_V1"},
	})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	t.Cleanup(claim.Destroy)
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{
			TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
		},
		RunID: fixture.runID,
	}
	attempt, err := queue.ReserveCleanupAttempt(
		t.Context(),
		claim.Fence,
		discoveryqueue.RunCommand{Coordinates: coordinates},
	)
	if err != nil {
		t.Fatalf("ReserveCleanupAttempt() error = %v", err)
	}
	fixture.open = discoverycleanup.OpenAttemptRequest{
		Coordinates: coordinates,
		Attempt:     attempt,
	}
	fixture.binding = discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: coordinates.Scope, SourceID: fixture.sourceID,
		},
		SourceRevision:       1,
		SourceRevisionDigest: revision.CanonicalRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionValidating,
		ProviderKind:         "CMDB_CATALOG_V1", ProfileCode: "CMDB_CATALOG_V1",
	}
	return fixture
}

type runtimeCleanupVerifier struct{}

func (runtimeCleanupVerifier) VerifyCleanupProof(
	context.Context,
	discoveryqueue.CleanupProof,
) error {
	return nil
}

type runtimeRolloverVerifier struct{}

func (runtimeRolloverVerifier) VerifyCheckpointLineageRollover(
	context.Context,
	discoveryqueue.CheckpointLineageRolloverRequest,
) error {
	return nil
}

type runtimePostgresHarness struct {
	admin, db, migration, application *pgxpool.Pool
	name                              string
}

var safeRuntimeControlDatabase = regexp.MustCompile(`^aiops_test(_[a-z0-9]+)*$`)

func newRuntimePostgresHarness(t *testing.T) *runtimePostgresHarness {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN"))
	migrationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_MIGRATION_DSN"))
	applicationDSN := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_APPLICATION_DSN"))
	if adminDSN == "" || migrationDSN == "" || applicationDSN == "" {
		t.Fatal("all three PostgreSQL 18.4 TLS identity DSNs are required; this test may not skip")
	}
	if adminDSN == migrationDSN || adminDSN == applicationDSN || migrationDSN == applicationDSN {
		t.Fatal("PostgreSQL test-control, migration, and application identities must be distinct")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !safeRuntimeControlDatabase.MatchString(adminConfig.ConnConfig.Database) {
		t.Fatal("PostgreSQL test-control DSN must name a dedicated aiops_test database")
	}
	controlName := adminConfig.ConnConfig.Database
	migrationConfig := runtimeRoleConfig(t, migrationDSN, controlName, "aiops_migrator")
	applicationConfig := runtimeRoleConfig(
		t,
		applicationDSN,
		controlName,
		"aiops_control_plane_workload",
	)
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect PostgreSQL test-control database")
	}
	databaseName := "aiops_runtime_test_" + randomRuntimeHex(t, 16)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	harness := &runtimePostgresHarness{admin: admin, name: databaseName}
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
			if _, err := admin.Exec(
				context.Background(),
				"DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)",
			); err != nil {
				t.Errorf("drop isolated runtime database: %v", err)
			}
		}
		admin.Close()
	})
	if _, err := admin.Exec(
		ctx,
		"CREATE DATABASE "+identifier+" WITH TEMPLATE template0 OWNER aiops_schema_owner",
	); err != nil {
		t.Fatalf("create isolated runtime database; cleanup ownership unconfirmed: %v", err)
	}
	created = true
	if _, err := admin.Exec(ctx, `SET ROLE aiops_schema_owner;
REVOKE ALL ON DATABASE `+identifier+` FROM PUBLIC;
REVOKE ALL ON DATABASE `+identifier+` FROM aiops_control_plane_runtime;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_migrator;
GRANT CONNECT ON DATABASE `+identifier+` TO aiops_control_plane_workload;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision isolated runtime database ACL: %v", err)
	}
	dbConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse isolated runtime database config")
	}
	dbConfig.ConnConfig.Database = databaseName
	dbConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	dbConfig.ConnConfig.RuntimeParams["search_path"] = "public"
	dbConfig.MaxConns = max(dbConfig.MaxConns, 12)
	harness.db, err = pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		t.Fatal("connect isolated runtime test-control database")
	}
	if _, err := harness.db.Exec(ctx, `ALTER SCHEMA public OWNER TO aiops_schema_owner;
SET ROLE aiops_schema_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM aiops_migrator;
REVOKE ALL ON SCHEMA public FROM aiops_control_plane_workload;
GRANT CREATE,USAGE ON SCHEMA public TO aiops_schema_owner;
GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
RESET ROLE;`); err != nil {
		t.Fatalf("preprovision isolated runtime schema ACL: %v", err)
	}
	migrationConfig.ConnConfig.Database = databaseName
	harness.migration, err = pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal("connect isolated runtime migration identity")
	}
	applicationConfig.ConnConfig.Database = databaseName
	harness.application, err = pgxpool.NewWithConfig(ctx, applicationConfig)
	if err != nil {
		t.Fatal("connect isolated runtime application identity")
	}
	return harness
}

func runtimeRoleConfig(
	t *testing.T,
	dsn string,
	controlName string,
	expectedUser string,
) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil ||
		config.ConnConfig.Database != controlName ||
		config.ConnConfig.User != expectedUser {
		t.Fatalf("invalid PostgreSQL identity config for %s", expectedUser)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	config.MaxConns = max(config.MaxConns, 12)
	return config
}

func assertRuntimePostgresTLSIdentity(
	t *testing.T,
	harness *runtimePostgresHarness,
) {
	t.Helper()
	for name, candidate := range map[string]struct {
		pool     *pgxpool.Pool
		identity string
	}{
		"migration": {
			pool: harness.migration, identity: "aiops_migrator",
		},
		"application": {
			pool: harness.application, identity: "aiops_control_plane_workload",
		},
	} {
		var version int
		var sessionUser, currentUser, tlsVersion string
		var ssl bool
		if err := candidate.pool.QueryRow(t.Context(), `
SELECT current_setting('server_version_num')::integer,session_user,current_user,
       ssl,version
FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()
`).Scan(&version, &sessionUser, &currentUser, &ssl, &tlsVersion); err != nil {
			t.Fatalf("read %s PostgreSQL TLS identity: %v", name, err)
		}
		if version < 180004 || version >= 190000 || !ssl ||
			tlsVersion != "TLSv1.3" ||
			sessionUser != candidate.identity ||
			currentUser != candidate.identity {
			t.Fatalf(
				"%s PostgreSQL contract version=%d TLS=%t/%q identity=%q/%q",
				name,
				version,
				ssl,
				tlsVersion,
				sessionUser,
				currentUser,
			)
		}
	}
}

func (harness *runtimePostgresHarness) applyMigrations(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(runtimeMigrationDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() &&
			strings.HasSuffix(entry.Name(), ".up.sql") &&
			entry.Name() <= "000015_assets_catalog.up.sql" {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) != 15 {
		t.Fatalf("migration files through 000015 = %d, want 15", len(files))
	}
	for _, name := range files {
		harness.applyMigration(t, name)
	}
}

func (harness *runtimePostgresHarness) applyMigration(t *testing.T, name string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(runtimeMigrationDirectory(t), name))
	if err != nil {
		t.Fatal(err)
	}
	if name == "000012_outbox_event_routing.up.sql" {
		config := harness.migration.Config().ConnConfig.Copy()
		connection, err := pgx.ConnectConfig(t.Context(), config)
		if err != nil {
			t.Fatalf("connect nontransactional migration %s: %v", name, err)
		}
		defer func() { _ = connection.Close(context.Background()) }()
		if _, err := connection.Exec(
			t.Context(),
			`SET search_path=pg_catalog,public,pg_temp; SET ROLE aiops_schema_owner`,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(t.Context(), string(source)); err != nil {
			failRuntimeMigration(t, name, err)
		}
		if _, err := connection.Exec(t.Context(), `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		return
	}
	text := string(source)
	if name != "000015_assets_catalog.up.sql" {
		index := strings.Index(text, "BEGIN;")
		if index < 0 {
			t.Fatalf("migration %s does not begin transaction", name)
		}
		index += len("BEGIN;")
		text = text[:index] +
			"\nSET LOCAL ROLE aiops_schema_owner;\nSET LOCAL search_path=public,pg_catalog,pg_temp;" +
			text[index:]
	}
	connection, err := harness.migration.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(t.Context(), text); err != nil {
		failRuntimeMigration(t, name, err)
	}
	if _, err := connection.Exec(t.Context(), `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
}

func failRuntimeMigration(t *testing.T, name string, err error) {
	t.Helper()
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		t.Fatalf(
			"apply migration %s: %s (SQLSTATE %s, constraint %s)",
			name,
			databaseError.Message,
			databaseError.Code,
			databaseError.ConstraintName,
		)
	}
	t.Fatalf("apply migration %s: %v", name, err)
}

type runtimeSQLExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func runtimeExec(
	t *testing.T,
	executor runtimeSQLExecutor,
	statement string,
	arguments ...any,
) {
	t.Helper()
	if _, err := executor.Exec(t.Context(), statement, arguments...); err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) {
			t.Fatalf(
				"runtime fixture SQL: %s (SQLSTATE %s, constraint %s)",
				databaseError.Message,
				databaseError.Code,
				databaseError.ConstraintName,
			)
		}
		t.Fatalf("runtime fixture SQL: %v", err)
	}
}

func runtimeMigrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve discoveryruntime test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../migrations"))
}

func randomRuntimeHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}
