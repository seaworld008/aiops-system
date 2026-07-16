package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

const (
	sourceTestRunID      = "99999999-9999-4999-8999-999999999999"
	sourceTestRevisionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	sourceTestBasePath   = "/api/v1/workspaces/" + assetTestWorkspaceID + "/asset-sources"
)

func TestAssetSourceRoutesAreReadOnlyAndPreserveManualUsageScope(t *testing.T) {
	t.Parallel()
	view := safeSourceView()
	manager := &recordingSourceManager{
		page: assetcatalog.SourceViewPage{Items: []assetcatalog.SourceView{view}},
		view: view,
		run:  assetcatalog.SourceRunView{Run: safeSourceRun(), EffectiveActions: []assetcatalog.EffectiveAction{}},
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:  manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	listPath := sourceTestBasePath + "?usage=manual_asset_create&environment_id=" +
		assetTestEnvironmentID + "&kinds=MANUAL&statuses=ACTIVE&gate_statuses=AVAILABLE&limit=10"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, listPath, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET sources = %d %s", response.Code, response.Body.String())
	}
	if manager.collection.WorkspaceID != assetTestWorkspaceID ||
		manager.input.Usage != assetcatalog.SourceUsageManualAssetCreate ||
		manager.input.EnvironmentID != assetTestEnvironmentID || manager.input.Limit != 10 {
		t.Fatalf("manager request = %#v %#v", manager.collection, manager.input)
	}
	if !strings.Contains(response.Body.String(), `"effective_actions":["CREATE_ASSET"]`) {
		t.Fatalf("source response = %s", response.Body.String())
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath+"/"+assetTestSourceID, nil))
	if response.Code != http.StatusOK || manager.path.SourceID != assetTestSourceID {
		t.Fatalf("GET source = %d %s / %#v", response.Code, response.Body.String(), manager.path)
	}
	if got := response.Header().Get("ETag"); got != `"asset-source:`+assetTestSourceID+`:v3"` {
		t.Fatalf("source ETag = %q", got)
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/workspaces/"+assetTestWorkspaceID+"/asset-source-runs/"+sourceTestRunID,
		nil,
	))
	if response.Code != http.StatusOK || manager.runPath.RunID != sourceTestRunID {
		t.Fatalf("GET source run = %d %s / %#v", response.Code, response.Body.String(), manager.runPath)
	}
	if got := response.Header().Get("ETag"); got != `"asset-source-run:`+sourceTestRunID+`:v4"` {
		t.Fatalf("run ETag = %q", got)
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, sourceTestBasePath, strings.NewReader(`{}`)))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST source = %d %s, want read-only 405", response.Code, response.Body.String())
	}
}

func TestAssetSourceDTOOmitsCheckpointCiphertextLeaseAndCleanupAttemptMaterial(t *testing.T) {
	t.Parallel()
	manager := &recordingSourceManager{view: safeSourceView()}
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:  manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath+"/"+assetTestSourceID, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET source = %d %s", response.Code, response.Body.String())
	}
	lower := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		"canonical_profile_manifest", "canonical_provider_schema", "checkpoint_ciphertext",
		"checkpoint_key_id", "cleanup_attempt", "lease_owner", "lease_token", "integration_id",
		"credential_reference", "trust_reference", "network_policy_reference",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("source DTO contains %q: %s", forbidden, lower)
		}
	}
}

func TestAssetSourceRoutesRejectInvalidQueriesAndMissingManager(t *testing.T) {
	t.Parallel()
	for _, query := range []string{
		"?usage=manual_asset_create",
		"?environment_id=" + assetTestEnvironmentID,
		"?unknown=value",
		"?limit=01",
		"?kinds=MANUAL,UNKNOWN",
	} {
		manager := &recordingSourceManager{}
		response := httptest.NewRecorder()
		httpapi.NewRouter(httpapi.Dependencies{
			Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()},
			AssetSources:  manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
		}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath+query, nil))
		if response.Code != http.StatusBadRequest || manager.collection.WorkspaceID != "" {
			t.Errorf("%s response/request = %d %s / %#v", query, response.Code, response.Body.String(), manager.collection)
		}
	}
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager response = %d %s", response.Code, response.Body.String())
	}
}

type recordingSourceManager struct {
	page       assetcatalog.SourceViewPage
	view       assetcatalog.SourceView
	run        assetcatalog.SourceRunView
	err        error
	collection assetcatalog.SourceCollectionRequest
	path       assetcatalog.SourcePathRequest
	runPath    assetcatalog.SourceRunPathRequest
	input      assetcatalog.SourceListInput
}

func (manager *recordingSourceManager) ListSources(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.SourceCollectionRequest,
	input assetcatalog.SourceListInput,
) (assetcatalog.SourceViewPage, error) {
	manager.collection, manager.input = collection, input
	return manager.page, manager.err
}

func (manager *recordingSourceManager) GetSource(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourcePathRequest,
) (assetcatalog.SourceView, error) {
	manager.path = path
	return manager.view, manager.err
}

func (manager *recordingSourceManager) GetSourceRun(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourceRunPathRequest,
) (assetcatalog.SourceRunView, error) {
	manager.runPath = path
	return manager.run, manager.err
}

func safeSourceView() assetcatalog.SourceView {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	run := safeSourceRun()
	revision := assetcatalog.SourceRevision{
		ID: sourceTestRevisionID, SourceID: assetTestSourceID,
		TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
		Revision: 1, Status: assetcatalog.SourceRevisionPublished,
		SourceDefinitionDigest:  strings.Repeat("a", 64),
		CanonicalRevisionDigest: strings.Repeat("b", 64),
		CreatedAt:               now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Hour),
	}
	return assetcatalog.SourceView{
		ReadModel: assetcatalog.SourceReadModel{
			Source: assetcatalog.Source{
				ID: assetTestSourceID, TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
				ProviderKind: "MANUAL_V1", Name: "manual", Kind: assetcatalog.SourceKindManual,
				Status: assetcatalog.SourceStatusActive, PublishedRevision: 1,
				PublishedRevisionDigest: strings.Repeat("b", 64),
				GateStatus:              assetcatalog.SourceGateAvailable, GateReasonCode: "READY", GateRevision: 2,
				CheckpointSHA256: strings.Repeat("c", 64), CheckpointVersion: 1,
				LastSuccessRunID: sourceTestRunID, LastSuccessAt: pointerTime(now.Add(-time.Minute)),
				LastCompleteSnapshotRunID: "", LastCompleteSnapshotAt: nil,
				Version: 3, CreatedAt: now.Add(-3 * time.Hour), UpdatedAt: now,
			},
			LatestRevision: revision, PublishedRevision: &revision,
			CurrentRun: nil, LastSuccessfulRun: &run,
		},
		EffectiveActions: []assetcatalog.EffectiveAction{assetcatalog.ActionCreateAsset},
	}
}

func safeSourceRun() assetcatalog.SourceRun {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	return assetcatalog.SourceRun{
		ID: sourceTestRunID, SourceID: assetTestSourceID,
		Scope:          assetcatalog.SourceScope{TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID},
		SourceRevision: 1, SourceRevisionDigest: strings.Repeat("b", 64),
		Kind: assetcatalog.RunKindManualMutation, Status: assetcatalog.RunStatusSucceeded,
		Stage: assetcatalog.RunStageCompleted, StageChangedAt: now,
		TriggerType: assetcatalog.TriggerHuman, GateRevision: 2,
		PageSequence: 1, RelationPageSequence: 1,
		CursorBeforeSHA256: strings.Repeat("d", 64), CursorAfterSHA256: strings.Repeat("e", 64),
		CheckpointVersion: 1, NotBefore: now.Add(-time.Minute),
		FinalPage: true, CompleteSnapshot: false, EffectiveCompleteSnapshot: false,
		WorkResultKind:   assetcatalog.WorkResultDataProjection,
		WorkResultStatus: assetcatalog.WorkResultStatusSucceeded,
		WorkResultDigest: strings.Repeat("f", 64), WorkResultRecordedAt: pointerTime(now),
		CredentialCleanupStatus: assetcatalog.CredentialCleanupNoCredential,
		Observed:                1, Created: 1, Changed: 0, Unchanged: 0, Conflicts: 0,
		Missing: 0, Stale: 0, Restored: 0, Tombstoned: 0, Rejected: 0,
		TraceID: "0123456789abcdef0123456789abcdef", Version: 4,
		CreatedAt: now.Add(-time.Minute), StartedAt: pointerTime(now.Add(-30 * time.Second)),
		HeartbeatAt: pointerTime(now.Add(-10 * time.Second)), CompletedAt: pointerTime(now),
	}
}

func pointerTime(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}

var _ assetcatalog.SourceManager = (*recordingSourceManager)(nil)
