package postgres_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
)

func TestSourceReadRepositoryResolvesWorkspaceScopeIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, func() string {
		return "70000000-0000-4000-8000-000000000201"
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	scope, err := repository.ResolveSourceScope(context.Background(), fixture.workspaceID)
	if err != nil {
		t.Fatalf("ResolveSourceScope() error = %v", err)
	}
	if scope.TenantID != fixture.tenantID || scope.WorkspaceID != fixture.workspaceID {
		t.Fatalf("ResolveSourceScope() = %+v, want tenant=%s workspace=%s", scope, fixture.tenantID, fixture.workspaceID)
	}
	if _, err := repository.ResolveSourceScope(context.Background(), "20000000-0000-4000-8000-000000000299"); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("ResolveSourceScope() unknown workspace error = %v, want ErrNotFound", err)
	}
}

func TestSourceReadRepositoryEnforcesScopeAccessAndSafeProjectionIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository := newSourceReadRepository(t, harness.application)
	allowed := sourceReadConstraint(t, fixture.environmentID)
	denied := sourceReadConstraint(t, "30000000-0000-4000-8000-000000000299")
	empty := sourceReadConstraint(t)
	locator := assetcatalog.SourceLocator{
		Scope:    assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID},
		SourceID: fixture.sourceID,
	}

	model, err := repository.GetSource(context.Background(), locator, allowed)
	if err != nil {
		t.Fatalf("GetSource() error = %v", err)
	}
	if model.Source.ID != fixture.sourceID || model.LatestRevision.ID != fixture.revisionID {
		t.Fatalf("GetSource() identity = source:%s revision:%s", model.Source.ID, model.LatestRevision.ID)
	}
	if model.PublishedRevision == nil || model.PublishedRevision.ID != fixture.revisionID {
		t.Fatalf("GetSource() published revision = %+v", model.PublishedRevision)
	}
	if model.LastSuccessfulRun == nil || model.LastSuccessfulRun.ID != fixture.runID {
		t.Fatalf("GetSource() last success = %+v, want exact pointer %s", model.LastSuccessfulRun, fixture.runID)
	}
	assertSafeSourceRevisionProjection(t, model.LatestRevision)
	assertSafeSourceRevisionProjection(t, *model.PublishedRevision)
	assertSafeSourceRunProjection(t, *model.LastSuccessfulRun)

	run, err := repository.GetSourceRun(context.Background(), assetcatalog.SourceRunLocator{
		Scope: locator.Scope,
		RunID: fixture.runID,
	}, allowed)
	if err != nil {
		t.Fatalf("GetSourceRun() error = %v", err)
	}
	if run.ID != fixture.runID || run.SourceID != fixture.sourceID {
		t.Fatalf("GetSourceRun() = run:%s source:%s", run.ID, run.SourceID)
	}
	assertSafeSourceRunProjection(t, run)

	if _, err := repository.GetSource(context.Background(), locator, denied); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("GetSource() denied error = %v, want ErrNotFound", err)
	}
	if _, err := repository.GetSource(context.Background(), locator, empty); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("GetSource() restricted-empty error = %v, want ErrNotFound", err)
	}
	emptyPage, err := repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: locator.Scope, Access: empty, Limit: 10,
	})
	if err != nil || len(emptyPage.Items) != 0 || emptyPage.Next != nil {
		t.Fatalf("ListSources() restricted-empty page = %+v error=%v", emptyPage, err)
	}
	if _, err := repository.GetSourceRun(context.Background(), assetcatalog.SourceRunLocator{
		Scope: locator.Scope,
		RunID: fixture.runID,
	}, denied); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("GetSourceRun() denied error = %v, want ErrNotFound", err)
	}
	crossScope := locator
	crossScope.Scope.TenantID = "10000000-0000-4000-8000-000000000299"
	if _, err := repository.GetSource(context.Background(), crossScope, allowed); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("GetSource() cross-scope error = %v, want ErrNotFound", err)
	}
}

func TestSourceReadRepositoryRequiresCompleteAuthoritySetIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	candidate := newCorrectiveMatrixCandidate(t, 2)
	digests := requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	runID := correctiveMatrixUUID(t)
	execAssetSQL(t, harness.db, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
			'source-read-multi-authority-run',repeat('8',64),checkpoint_version
		FROM asset_sources WHERE id=$4
	`, runID, candidate.tenantID, candidate.workspaceID, candidate.sourceID, digests.binding)
	repository := newSourceReadRepository(t, harness.application)
	scope := assetcatalog.SourceScope{TenantID: candidate.tenantID, WorkspaceID: candidate.workspaceID}
	locator := assetcatalog.SourceLocator{Scope: scope, SourceID: candidate.sourceID}
	partial := sourceReadConstraint(t, candidate.environmentIDs[0])
	complete := sourceReadConstraint(t, candidate.environmentIDs...)

	if _, err := repository.GetSource(context.Background(), locator, partial); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("GetSource() partial authority error = %v, want ErrNotFound", err)
	}
	model, err := repository.GetSource(context.Background(), locator, complete)
	if err != nil {
		t.Fatalf("GetSource() complete authority error = %v", err)
	}
	if got := model.LatestRevision.AuthorityEnvironmentIDs; len(got) != 2 || got[0] != candidate.environmentIDs[0] || got[1] != candidate.environmentIDs[1] {
		t.Fatalf("GetSource() authorities = %v, want %v", got, candidate.environmentIDs)
	}
	if _, err := repository.GetSourceRun(context.Background(), assetcatalog.SourceRunLocator{
		Scope: scope, RunID: runID,
	}, partial); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("GetSourceRun() partial authority error = %v, want ErrNotFound", err)
	}
	run, err := repository.GetSourceRun(context.Background(), assetcatalog.SourceRunLocator{
		Scope: scope, RunID: runID,
	}, complete)
	if err != nil || run.ID != runID {
		t.Fatalf("GetSourceRun() complete authority = run:%s error:%v", run.ID, err)
	}

	page, err := repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: partial, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListSources() partial authority error = %v", err)
	}
	if len(page.Items) != 0 || page.Next != nil {
		t.Fatalf("ListSources() partial authority = %+v, want empty page", page)
	}
	page, err = repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: complete, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListSources() complete authority error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Source.ID != candidate.sourceID {
		t.Fatalf("ListSources() complete authority items = %+v", page.Items)
	}
}

func TestSourceReadRepositoryListsManualUsageAndKeysetIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	seedSourceReadKeysetCandidates(t, harness.db, fixture)
	repository := newSourceReadRepository(t, harness.application)
	access := sourceReadConstraint(t, fixture.environmentID)
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}

	manual, err := repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: access, Usage: assetcatalog.SourceUsageManualAssetCreate,
		EnvironmentID: fixture.environmentID, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListSources() manual usage error = %v", err)
	}
	if len(manual.Items) != 1 || manual.Items[0].Source.ID != fixture.sourceID {
		t.Fatalf("ListSources() manual usage items = %+v", manual.Items)
	}
	wrongEnvironmentAccess := sourceReadConstraint(t, fixture.environmentID, "30000000-0000-4000-8000-000000000299")
	wrongEnvironment, err := repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: wrongEnvironmentAccess, Usage: assetcatalog.SourceUsageManualAssetCreate,
		EnvironmentID: "30000000-0000-4000-8000-000000000299", Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListSources() wrong manual Environment error = %v", err)
	}
	if len(wrongEnvironment.Items) != 0 {
		t.Fatalf("ListSources() wrong manual Environment returned %d items", len(wrongEnvironment.Items))
	}

	var got []string
	var cursor *assetcatalog.SourceCursor
	for {
		page, pageErr := repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
			Scope: scope, Access: access, Limit: 1, Cursor: cursor,
		})
		if pageErr != nil {
			t.Fatalf("ListSources() keyset error = %v", pageErr)
		}
		if len(page.Items) != 1 {
			t.Fatalf("ListSources() keyset page size = %d, want 1", len(page.Items))
		}
		got = append(got, page.Items[0].Source.ID)
		if page.Next == nil {
			break
		}
		cursor = page.Next
	}
	want := append([]string(nil), got...)
	sort.Strings(want)
	if len(got) != 3 || !equalStrings(got, want) {
		t.Fatalf("ListSources() keyset IDs = %v, want three IDs in ascending order", got)
	}

	filtered, err := repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: access, Kinds: []assetcatalog.SourceKind{assetcatalog.SourceKindManual}, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListSources() filter error = %v", err)
	}
	if len(filtered.Items) != 1 || filtered.Items[0].Source.ID != fixture.sourceID {
		t.Fatalf("ListSources() manual filter items = %+v", filtered.Items)
	}
	filtered, err = repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: access, GateStatuses: []assetcatalog.SourceGateStatus{assetcatalog.SourceGateAvailable}, Limit: 10,
	})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].Source.ID != fixture.sourceID {
		t.Fatalf("ListSources() gate filter items = %+v error=%v", filtered.Items, err)
	}
	filtered, err = repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: access, Statuses: []assetcatalog.SourceStatus{assetcatalog.SourceStatusPaused}, Limit: 10,
	})
	if err != nil || len(filtered.Items) != 0 {
		t.Fatalf("ListSources() status filter items = %+v error=%v", filtered.Items, err)
	}
}

func TestSourceReadRepositoryUsesExactCurrentRunIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	candidate := newCorrectiveMatrixCandidate(t, 1)
	digests := requireCorrectiveMatrixCandidateCommit(t, harness.db, candidate)
	runID := correctiveMatrixUUID(t)
	execAssetSQL(t, harness.db, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
			'source-read-current-run',repeat('7',64),checkpoint_version
		FROM asset_sources WHERE id=$4
	`, runID, candidate.tenantID, candidate.workspaceID, candidate.sourceID, digests.binding)
	repository := newSourceReadRepository(t, harness.application)
	access := sourceReadConstraint(t, candidate.environmentIDs[0])
	scope := assetcatalog.SourceScope{TenantID: candidate.tenantID, WorkspaceID: candidate.workspaceID}

	model, err := repository.GetSource(context.Background(), assetcatalog.SourceLocator{
		Scope: scope, SourceID: candidate.sourceID,
	}, access)
	if err != nil {
		t.Fatalf("GetSource() current run error = %v", err)
	}
	if model.CurrentRun == nil || model.CurrentRun.ID != runID ||
		model.CurrentRun.Status != assetcatalog.RunStatusQueued {
		t.Fatalf("GetSource() current run = %+v", model.CurrentRun)
	}
	run, err := repository.GetSourceRun(context.Background(), assetcatalog.SourceRunLocator{
		Scope: scope, RunID: runID,
	}, access)
	if err != nil {
		t.Fatalf("GetSourceRun() current run error = %v", err)
	}
	if run.ID != runID || run.Status != assetcatalog.RunStatusQueued {
		t.Fatalf("GetSourceRun() = %+v", run)
	}
}

func newSourceReadRepository(t *testing.T, pool *pgxpool.Pool) *assetpostgres.Repository {
	t.Helper()
	repository, err := assetpostgres.New(pool, time.Now, func() string {
		return "70000000-0000-4000-8000-000000000201"
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return repository
}

func sourceReadConstraint(t *testing.T, environmentIDs ...string) assetcatalog.SourceReadConstraint {
	t.Helper()
	constraint, err := assetcatalog.NewSourceReadConstraint(environmentIDs)
	if err != nil {
		t.Fatalf("NewSourceReadConstraint(%v) error = %v", environmentIDs, err)
	}
	return constraint
}

func assertSafeSourceRevisionProjection(t *testing.T, revision assetcatalog.SourceRevision) {
	t.Helper()
	if revision.CanonicalProfileManifest != nil || revision.CanonicalProviderSchema != nil ||
		revision.IntegrationID != "" || revision.CredentialReferenceID != "" ||
		revision.TrustReferenceID != "" || revision.NetworkPolicyReferenceID != "" {
		t.Fatalf("SourceRevision unsafe fields escaped safe projection: %+v", revision)
	}
}

func assertSafeSourceRunProjection(t *testing.T, run assetcatalog.SourceRun) {
	t.Helper()
	if run.LeaseExpiresAt != nil || run.FenceEpoch != 0 {
		t.Fatalf("SourceRun lease/fence escaped safe projection: lease=%v fence=%d", run.LeaseExpiresAt, run.FenceEpoch)
	}
}

func seedSourceReadKeysetCandidates(t *testing.T, database *pgxpool.Pool, fixture assetCatalogFixture) {
	t.Helper()
	for index, sourceID := range []string{
		"60000000-0000-4000-8000-000000000101",
		"60000000-0000-4000-8000-000000000301",
	} {
		candidate := newCorrectiveMatrixCandidate(t, 1)
		candidate.tenantID = fixture.tenantID
		candidate.workspaceID = fixture.workspaceID
		candidate.sourceID = sourceID
		candidate.revisionID = []string{
			"61000000-0000-4000-8000-000000000101",
			"61000000-0000-4000-8000-000000000301",
		}[index]
		candidate.environmentIDs = []string{fixture.environmentID}
		candidate.authorities = []correctiveMatrixAuthority{{environmentID: fixture.environmentID, ordinal: 1}}
		candidate.environmentMappingMode = "SINGLE_ENVIRONMENT"
		candidate.refreshProfileManifest()
		insertSourceReadCandidate(t, database, candidate)
	}
}

func insertSourceReadCandidate(t *testing.T, database *pgxpool.Pool, candidate correctiveMatrixCandidate) {
	t.Helper()
	digests := candidate.digests(t)
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin source-read candidate transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,repeat('a',64))
	`, candidate.sourceID, candidate.tenantID, candidate.workspaceID, candidate.sourceKind,
		candidate.providerKind, "source-read-"+candidate.label, "source-read-"+candidate.label)
	execAssetSQL(t, tx, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_profile_manifest,profile_manifest_sha256,
			canonical_provider_schema,canonical_provider_schema_sha256,
			integration_id,sync_mode,authority_scope_digest,source_definition_digest,
			canonical_revision_digest,credential_reference_id,trust_reference_id,
			network_policy_reference_id,rate_limit_requests,rate_limit_window_seconds,
			backpressure_base_seconds,backpressure_max_seconds,profile_code,
			schedule_expression,typed_extension_code,prepared_extension_digest,
			created_by,change_reason_code,expected_source_version
		) VALUES (
			$1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,$22,$23,$24,'source-read-reviewer','INITIAL_CREATE',1
		)
	`, candidate.revisionID, candidate.tenantID, candidate.workspaceID, candidate.sourceID,
		candidate.profileManifest, digests.profileManifest, candidate.providerSchema, digests.providerSchema,
		correctiveMatrixOptionalValue(candidate.integrationID), candidate.syncMode, digests.authority,
		digests.definition, digests.binding, correctiveMatrixOptionalValue(candidate.credentialReference),
		correctiveMatrixOptionalValue(candidate.trustReference), correctiveMatrixOptionalValue(candidate.networkReference),
		candidate.rateLimitRequests, candidate.rateLimitWindowSeconds, candidate.backpressureBaseSeconds,
		candidate.backpressureMaxSeconds, candidate.profileCode, correctiveMatrixOptionalValue(candidate.scheduleExpression),
		correctiveMatrixOptionalValue(candidate.typedExtensionCode), correctiveMatrixOptionalValue(candidate.preparedExtensionDigest))
	execAssetSQL(t, tx, `
		INSERT INTO asset_source_revision_authorities (
			tenant_id,workspace_id,source_id,source_revision,environment_id,canonical_ordinal
		) VALUES ($1,$2,$3,1,$4,1)
	`, candidate.tenantID, candidate.workspaceID, candidate.sourceID, candidate.environmentIDs[0])
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit source-read candidate: %v", err)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
