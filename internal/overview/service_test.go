package overview_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/overview"
)

const (
	testTenantID      = "11111111-1111-4111-8111-111111111111"
	testWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	testEnvironmentID = "33333333-3333-4333-8333-333333333333"
)

var testNow = time.Date(2026, time.July, 18, 8, 30, 0, 0, time.UTC)

func TestOverviewDoesNotTurnUnimplementedPhasesGreen(t *testing.T) {
	t.Parallel()
	service := newTestService(t, &recordingRepository{
		states: map[overview.Feature]overview.ImplementationState{
			overview.FeatureAssets:         overview.StateAvailable,
			overview.FeatureSources:        overview.StateAvailable,
			overview.FeatureConnections:    overview.StateAvailable,
			overview.FeatureInvestigations: overview.StateAvailable,
			overview.FeatureActions:        overview.StateAvailable,
			overview.FeatureReleases:       overview.StateAvailable,
		},
		assets:  validAssetFacts(testNow),
		sources: validSourceFacts(testNow),
	}, overview.Options{})

	snapshot, err := service.Get(context.Background(), testPrincipal(), testWorkspaceID, testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Scope != testScope() {
		t.Fatalf("Scope = %#v, want exact composite scope", snapshot.Scope)
	}
	if snapshot.GeneratedAt != testNow {
		t.Fatalf("GeneratedAt = %s, want %s", snapshot.GeneratedAt, testNow)
	}
	if snapshot.Sections[overview.FeatureAssets].State != overview.StateAvailable ||
		snapshot.Sections[overview.FeatureSources].State != overview.StateAvailable {
		t.Fatalf("implemented sections = %#v", snapshot.Sections)
	}
	for _, key := range []overview.Feature{
		overview.FeatureConnections,
		overview.FeatureInvestigations,
		overview.FeatureActions,
		overview.FeatureReleases,
	} {
		section, ok := snapshot.Sections[key]
		if !ok || section.State != overview.StateNotStarted ||
			section.Code != overview.CodeNotImplemented ||
			section.AssetFacts != nil || section.SourceFacts != nil {
			t.Errorf("%s section = %#v, want explicit NOT_STARTED without fake facts", key, section)
		}
	}
	if len(snapshot.Sections) != len(overview.AllFeatures()) {
		t.Fatalf("section count = %d, want %d", len(snapshot.Sections), len(overview.AllFeatures()))
	}
}

func TestOverviewCrossScopeIsIndistinguishableFromNotFound(t *testing.T) {
	t.Parallel()
	repository := &recordingRepository{
		resolved: assetcatalog.Scope{
			TenantID:    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		},
	}
	service := newTestService(t, repository, overview.Options{})
	_, err := service.Get(context.Background(), testPrincipal(), testWorkspaceID, testEnvironmentID)
	if !errors.Is(err, overview.ErrNotFound) {
		t.Fatalf("Get(cross tenant) error = %v, want ErrNotFound", err)
	}

	principal := testPrincipal()
	principal.EnvironmentIDs = []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
	repository.resolved = testScope()
	repository.mu.Lock()
	repository.resolveCalls = 0
	repository.mu.Unlock()
	_, err = service.Get(context.Background(), principal, testWorkspaceID, testEnvironmentID)
	if !errors.Is(err, overview.ErrNotFound) {
		t.Fatalf("Get(out-of-token-scope) error = %v, want ErrNotFound", err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.resolveCalls != 0 {
		t.Fatalf("out-of-token-scope request reached repository %d times", repository.resolveCalls)
	}
}

func TestOverviewSectionTimeoutIsBoundedAndOnlyMakesThatSectionPartial(t *testing.T) {
	t.Parallel()
	repository := &recordingRepository{
		states: map[overview.Feature]overview.ImplementationState{
			overview.FeatureAssets:  overview.StateAvailable,
			overview.FeatureSources: overview.StateAvailable,
		},
		assets:      validAssetFacts(testNow),
		sources:     validSourceFacts(testNow),
		blockAssets: true,
	}
	service := newTestService(t, repository, overview.Options{QueryTimeout: 25 * time.Millisecond})

	started := time.Now()
	snapshot, err := service.Get(context.Background(), testPrincipal(), testWorkspaceID, testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Get() elapsed = %s, section timeout was not bounded", elapsed)
	}
	assets := snapshot.Sections[overview.FeatureAssets]
	if assets.State != overview.StatePartial || assets.Code != overview.CodeAggregatePartial ||
		assets.AssetFacts != nil {
		t.Fatalf("ASSETS section = %#v, want safe PARTIAL without untrusted facts", assets)
	}
	sources := snapshot.Sections[overview.FeatureSources]
	if sources.State != overview.StateAvailable || sources.SourceFacts == nil ||
		sources.SourceFacts.Total != repository.sources.Total {
		t.Fatalf("SOURCES section = %#v, want preserved trusted facts", sources)
	}
	for _, key := range []overview.Feature{
		overview.FeatureConnections,
		overview.FeatureInvestigations,
		overview.FeatureActions,
		overview.FeatureReleases,
	} {
		if got := snapshot.Sections[key].State; got != overview.StateNotStarted {
			t.Errorf("%s state = %s, want NOT_STARTED", key, got)
		}
	}
}

func TestOverviewStaleEvidenceDegradesOnlyObservedSection(t *testing.T) {
	t.Parallel()
	repository := &recordingRepository{
		states: map[overview.Feature]overview.ImplementationState{
			overview.FeatureAssets:  overview.StateAvailable,
			overview.FeatureSources: overview.StateAvailable,
		},
		assets:  validAssetFacts(testNow.Add(-3 * time.Minute)),
		sources: validSourceFacts(testNow),
	}
	service := newTestService(t, repository, overview.Options{})
	snapshot, err := service.Get(context.Background(), testPrincipal(), testWorkspaceID, testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if section := snapshot.Sections[overview.FeatureAssets]; section.State != overview.StateDegraded ||
		section.Code != overview.CodeStaleEvidence || section.AssetFacts == nil {
		t.Fatalf("stale ASSETS section = %#v", section)
	}
	if section := snapshot.Sections[overview.FeatureSources]; section.State != overview.StateAvailable ||
		section.Code != overview.CodeReady {
		t.Fatalf("fresh SOURCES section = %#v", section)
	}
}

func TestOverviewRejectsInvalidFactsAsPartialAndProjectsOnlyAllowedActions(t *testing.T) {
	t.Parallel()
	badAssets := validAssetFacts(testNow)
	badAssets.Total = -1
	repository := &recordingRepository{
		states: map[overview.Feature]overview.ImplementationState{
			overview.FeatureAssets:  overview.StateAvailable,
			overview.FeatureSources: overview.StateUnavailable,
		},
		assets:  badAssets,
		sources: validSourceFacts(testNow),
	}
	service := newTestService(t, repository, overview.Options{})
	snapshot, err := service.Get(context.Background(), testPrincipal(), testWorkspaceID, testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshot.Sections[overview.FeatureAssets].State; got != overview.StatePartial {
		t.Fatalf("invalid ASSETS facts state = %s, want PARTIAL", got)
	}
	if got := snapshot.Sections[overview.FeatureSources].State; got != overview.StateUnavailable {
		t.Fatalf("unavailable SOURCES state = %s", got)
	}
	if len(snapshot.EffectiveActions) != 0 {
		t.Fatalf("effective actions = %#v, want none for non-navigable sections", snapshot.EffectiveActions)
	}
	for _, queue := range snapshot.WorkQueues {
		if queue.Count != nil {
			t.Errorf("queue %s count = %d, want null when its section is not trustworthy", queue.Key, *queue.Count)
		}
	}

	repository.assets = validAssetFacts(testNow)
	repository.states[overview.FeatureSources] = overview.StateAvailable
	snapshot, err = service.Get(context.Background(), testPrincipal(), testWorkspaceID, testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(
		snapshot.EffectiveActions,
		[]overview.EffectiveAction{overview.ActionViewAssets, overview.ActionViewSources},
	) {
		t.Fatalf("effective actions = %#v", snapshot.EffectiveActions)
	}
}

func TestOverviewRequiresAssetReadBeforeAggregating(t *testing.T) {
	t.Parallel()
	repository := &recordingRepository{resolved: testScope()}
	service := newTestService(t, repository, overview.Options{})
	principal := testPrincipal()
	principal.Roles = nil
	_, err := service.Get(context.Background(), principal, testWorkspaceID, testEnvironmentID)
	if !errors.Is(err, overview.ErrForbidden) {
		t.Fatalf("Get(without ASSET_READ) error = %v, want ErrForbidden", err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.stateCalls != 0 || repository.assetCalls != 0 || repository.sourceCalls != 0 {
		t.Fatalf(
			"unauthorized request queried facts: state=%d assets=%d sources=%d",
			repository.stateCalls,
			repository.assetCalls,
			repository.sourceCalls,
		)
	}
}

func newTestService(
	t *testing.T,
	repository *recordingRepository,
	options overview.Options,
) *overview.Service {
	t.Helper()
	if repository.resolved == (assetcatalog.Scope{}) {
		repository.resolved = testScope()
	}
	authorizer, err := authz.NewAuthorizer(5*time.Minute, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	options.Clock = func() time.Time { return testNow }
	service, err := overview.NewService(repository, repository, authorizer, options)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func testScope() assetcatalog.Scope {
	return assetcatalog.Scope{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
	}
}

func testPrincipal() authn.Principal {
	return authn.Principal{
		Subject: "overview-user", TenantID: testTenantID,
		Roles:           []authn.Role{authn.RoleViewer},
		WorkspaceIDs:    []string{testWorkspaceID},
		EnvironmentIDs:  []string{testEnvironmentID},
		AuthenticatedAt: testNow.Add(-time.Minute),
		ExpiresAt:       testNow.Add(time.Hour),
	}
}

func validAssetFacts(observedAt time.Time) overview.AssetFacts {
	return overview.AssetFacts{
		ObservedAt: observedAt,
		Total:      6,
		Lifecycles: []overview.StateCount{
			{State: string(assetcatalog.LifecycleDiscovered), Count: 1},
			{State: string(assetcatalog.LifecycleActive), Count: 2},
			{State: string(assetcatalog.LifecycleStale), Count: 1},
			{State: string(assetcatalog.LifecycleQuarantined), Count: 1},
			{State: string(assetcatalog.LifecycleRetired), Count: 1},
		},
		MappingStatuses: []overview.StateCount{
			{State: string(domain.MappingExact), Count: 2},
			{State: string(domain.MappingUnresolved), Count: 2},
			{State: string(domain.MappingAmbiguous), Count: 2},
		},
		StaleCount:        1,
		OldestStaleAt:     timePointer(observedAt.Add(-time.Hour)),
		OpenConflictCount: 2,
	}
}

func validSourceFacts(observedAt time.Time) overview.SourceFacts {
	return overview.SourceFacts{
		ObservedAt: observedAt,
		Total:      3,
		Statuses: []overview.StateCount{
			{State: string(assetcatalog.SourceStatusActive), Count: 1},
			{State: string(assetcatalog.SourceStatusPaused), Count: 1},
			{State: string(assetcatalog.SourceStatusDegraded), Count: 1},
			{State: string(assetcatalog.SourceStatusDisabled), Count: 0},
		},
		RevisionStatuses: []overview.StateCount{
			{State: string(assetcatalog.SourceRevisionDraft), Count: 1},
			{State: string(assetcatalog.SourceRevisionValidating), Count: 0},
			{State: string(assetcatalog.SourceRevisionValidated), Count: 0},
			{State: string(assetcatalog.SourceRevisionRejected), Count: 0},
			{State: string(assetcatalog.SourceRevisionPublished), Count: 2},
			{State: string(assetcatalog.SourceRevisionSuperseded), Count: 0},
		},
		GateStatuses: []overview.StateCount{
			{State: string(assetcatalog.SourceGateUnavailable), Count: 1},
			{State: string(assetcatalog.SourceGateValidating), Count: 0},
			{State: string(assetcatalog.SourceGateAvailable), Count: 1},
			{State: string(assetcatalog.SourceGateDegraded), Count: 1},
			{State: string(assetcatalog.SourceGateSuspended), Count: 0},
		},
		RunStatuses: []overview.StateCount{
			{State: string(assetcatalog.RunStatusQueued), Count: 0},
			{State: string(assetcatalog.RunStatusDelayed), Count: 0},
			{State: string(assetcatalog.RunStatusRunning), Count: 1},
			{State: string(assetcatalog.RunStatusFinalizing), Count: 0},
			{State: string(assetcatalog.RunStatusSucceeded), Count: 1},
			{State: string(assetcatalog.RunStatusPartial), Count: 0},
			{State: string(assetcatalog.RunStatusFailed), Count: 1},
			{State: string(assetcatalog.RunStatusCancelled), Count: 0},
		},
		BackpressuredCount: 1,
		ProviderGates: []overview.ProviderGateSummary{
			{
				ProviderKind: "MANUAL_V1",
				GateStatus:   assetcatalog.SourceGateAvailable,
				SourceCount:  1,
				EvidenceAt:   timePointer(observedAt),
			},
			{
				ProviderKind: "VSPHERE_V1",
				GateStatus:   assetcatalog.SourceGateUnavailable,
				SourceCount:  2,
			},
		},
	}
}

func timePointer(value time.Time) *time.Time { return &value }

type recordingRepository struct {
	mu           sync.Mutex
	resolved     assetcatalog.Scope
	resolveErr   error
	states       map[overview.Feature]overview.ImplementationState
	stateErrors  map[overview.Feature]error
	assets       overview.AssetFacts
	assetErr     error
	sources      overview.SourceFacts
	sourceErr    error
	blockAssets  bool
	resolveCalls int
	stateCalls   int
	assetCalls   int
	sourceCalls  int
}

func (repository *recordingRepository) ResolveScope(
	_ context.Context,
	workspaceID string,
	environmentID string,
) (assetcatalog.Scope, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.resolveCalls++
	if repository.resolveErr != nil {
		return assetcatalog.Scope{}, repository.resolveErr
	}
	if repository.resolved.WorkspaceID != workspaceID ||
		repository.resolved.EnvironmentID != environmentID {
		return assetcatalog.Scope{}, assetcatalog.ErrNotFound
	}
	return repository.resolved, nil
}

func (repository *recordingRepository) State(
	_ context.Context,
	_ assetcatalog.Scope,
	feature overview.Feature,
) (overview.ImplementationState, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.stateCalls++
	if err := repository.stateErrors[feature]; err != nil {
		return "", err
	}
	if state, ok := repository.states[feature]; ok {
		return state, nil
	}
	return overview.StateNotStarted, nil
}

func (repository *recordingRepository) ReadAssetFacts(
	ctx context.Context,
	_ assetcatalog.Scope,
) (overview.AssetFacts, error) {
	repository.mu.Lock()
	repository.assetCalls++
	block := repository.blockAssets
	facts := repository.assets
	err := repository.assetErr
	repository.mu.Unlock()
	if block {
		<-ctx.Done()
		return overview.AssetFacts{}, ctx.Err()
	}
	return facts, err
}

func (repository *recordingRepository) ReadSourceFacts(
	_ context.Context,
	_ assetcatalog.Scope,
) (overview.SourceFacts, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.sourceCalls++
	return repository.sources, repository.sourceErr
}
