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
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

const (
	conflictTestID        = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	conflictObservationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	conflictCandidateID   = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	conflictTestBasePath  = "/api/v1/workspaces/" + assetTestWorkspaceID + "/asset-conflicts"
)

func TestAssetConflictListRequiresEnvironmentAndPreservesScope(t *testing.T) {
	t.Parallel()
	manager := &recordingConflictManager{page: assetcatalog.ConflictViewPage{
		Items: []assetcatalog.ConflictView{safeConflictView()},
	}}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:  fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetConflicts: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		conflictTestBasePath+"?environment_id="+assetTestEnvironmentID+"&statuses=OPEN&limit=15",
		nil,
	))
	if response.Code != http.StatusOK {
		t.Fatalf("GET conflicts = %d %s", response.Code, response.Body.String())
	}
	if manager.collection.WorkspaceID != assetTestWorkspaceID ||
		manager.collection.EnvironmentID != assetTestEnvironmentID ||
		manager.input.Limit != 15 || len(manager.input.Statuses) != 1 {
		t.Fatalf("manager request = %#v %#v", manager.collection, manager.input)
	}
	if strings.Contains(strings.ToLower(response.Body.String()), "raw") ||
		!strings.Contains(response.Body.String(), `"existing_value_sha256"`) {
		t.Fatalf("conflict response = %s", response.Body.String())
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, conflictTestBasePath, nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing environment response = %d %s", response.Code, response.Body.String())
	}
}

func TestResolveAssetConflictRequiresClosedDiscriminatedBodyAndTrustedHeaders(t *testing.T) {
	t.Parallel()
	manager := &recordingConflictManager{mutation: assetcatalog.ConflictMutationView{
		View:    safeConflictView(),
		Binding: pointerBinding(safeBinding()),
	}}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:  fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetConflicts: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	path := conflictTestBasePath + "/" + conflictTestID + ":resolve"
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(
		`{"resolution":"CONFIRM_EXACT","service_id":"`+assetTestServiceID+
			`","binding_role":"PRIMARY_RUNTIME","reason_code":"CONFIRMED_MATCH"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "asset:conflict:request-1")
	request.Header.Set("If-Match", `"asset-conflict:`+conflictTestID+`:v5"`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("POST resolve = %d %s", response.Code, response.Body.String())
	}
	if manager.path.WorkspaceID != assetTestWorkspaceID || manager.path.ConflictID != conflictTestID ||
		manager.resolve.Resolution != assetcatalog.ConflictResolutionConfirmExact ||
		manager.resolve.ServiceID != assetTestServiceID ||
		manager.metadata.ExpectedVersion != 5 ||
		manager.metadata.IdempotencyKey != "asset:conflict:request-1" {
		t.Fatalf("manager request = %#v %#v %#v", manager.path, manager.input, manager.metadata)
	}
	if got := response.Header().Get("ETag"); got != `"asset-conflict:`+conflictTestID+`:v5"` {
		t.Fatalf("ETag = %q", got)
	}
	if !strings.Contains(response.Body.String(), `"binding"`) ||
		!strings.Contains(response.Body.String(), `"audit_id":"`+assetTestAuditID+`"`) {
		t.Fatalf("resolve response = %s", response.Body.String())
	}

	for name, body := range map[string]string{
		"confirm missing service": `{"resolution":"CONFIRM_EXACT","binding_role":"PRIMARY_RUNTIME","reason_code":"CONFIRMED_MATCH"}`,
		"reject with service": `{"resolution":"REJECT_CANDIDATE","service_id":"` + assetTestServiceID +
			`","reason_code":"REJECTED_MATCH"}`,
		"reject with null service": `{"resolution":"REJECT_CANDIDATE","service_id":null,"reason_code":"REJECTED_MATCH"}`,
		"invalid reason":           `{"resolution":"KEEP_UNRESOLVED","reason_code":"unsafe reason"}`,
		"unknown field":            `{"resolution":"KEEP_UNRESOLVED","reason_code":"KEEP_OPEN","actor":"forged"}`,
	} {
		before := manager.resolveCalls
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "asset:conflict:request-2")
		request.Header.Set("If-Match", `"asset-conflict:`+conflictTestID+`:v5"`)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || manager.resolveCalls != before {
			t.Errorf("%s response/calls = %d %s / %d->%d", name, response.Code, response.Body.String(), before, manager.resolveCalls)
		}
	}
}

func TestAssetConflictRoutesFailClosedWithoutManager(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, conflictTestBasePath+"?environment_id="+assetTestEnvironmentID, nil,
	))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager response = %d %s", response.Code, response.Body.String())
	}
}

type recordingConflictManager struct {
	page         assetcatalog.ConflictViewPage
	mutation     assetcatalog.ConflictMutationView
	err          error
	collection   assetcatalog.ConflictCollectionRequest
	path         assetcatalog.ConflictPathRequest
	input        assetcatalog.ConflictListInput
	resolve      assetcatalog.ResolveConflictInput
	metadata     assetcatalog.ServerRequestMetadata
	resolveCalls int
}

func (manager *recordingConflictManager) ListConflicts(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.ConflictCollectionRequest,
	input assetcatalog.ConflictListInput,
) (assetcatalog.ConflictViewPage, error) {
	manager.collection, manager.input = collection, input
	return manager.page, manager.err
}

func (manager *recordingConflictManager) ResolveConflict(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.ConflictPathRequest,
	input assetcatalog.ResolveConflictInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.ConflictMutationView, error) {
	manager.resolveCalls++
	manager.path, manager.input, manager.resolve, manager.metadata = path, assetcatalog.ConflictListInput{}, input, metadata
	result := manager.mutation
	result.Receipt = assetcatalog.MutationReceipt{
		AuditID: assetTestAuditID, TraceID: metadata.TraceID,
	}
	return result, manager.err
}

func safeConflictView() assetcatalog.ConflictView {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	return assetcatalog.ConflictView{
		ReadModel: assetcatalog.ConflictReadModel{
			Conflict: assetcatalog.Conflict{
				ID: conflictTestID,
				Scope: assetcatalog.Scope{
					TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
					EnvironmentID: assetTestEnvironmentID,
				},
				AssetID: assetTestAssetID, CandidateAssetID: conflictCandidateID,
				CandidateServiceID: assetTestServiceID, SourceID: assetTestSourceID,
				ObservationID: conflictObservationID, Type: "FIELD_CONFLICT", FieldName: "display_name",
				ExistingValueSHA256:  strings.Repeat("a", 64),
				CandidateValueSHA256: strings.Repeat("b", 64),
				Status:               assetcatalog.ConflictStatusOpen, Version: 5,
				CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
			},
			Observation: assetcatalog.ConflictObservationReference{
				ID: conflictObservationID, SourceID: assetTestSourceID, SourceRevision: 1, ObservedAt: now,
			},
			Asset: assetcatalog.ConflictAssetReference{
				ID: assetTestAssetID, DisplayName: "api-01",
				Kind: assetcatalog.KindLinuxVM, Lifecycle: assetcatalog.LifecycleDiscovered,
			},
			CandidateAsset: &assetcatalog.ConflictAssetReference{
				ID: conflictCandidateID, DisplayName: "api-candidate",
				Kind: assetcatalog.KindLinuxVM, Lifecycle: assetcatalog.LifecycleDiscovered,
			},
			CandidateService: &assetcatalog.ConflictServiceReference{
				ID: assetTestServiceID, Name: "api",
			},
			Impact: assetcatalog.ConflictImpactCounts{
				AssetActiveBindings: 1, AssetActiveRelationships: 2,
				CandidateAssetActiveBindings: 3, CandidateAssetActiveRelationships: 4,
				CandidateServiceActiveBindings: 5,
			},
		},
		EffectiveActions: []assetcatalog.EffectiveAction{assetcatalog.ActionResolveConflict},
	}
}

func safeBinding() assetcatalog.ServiceAssetBinding {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	return assetcatalog.ServiceAssetBinding{
		ID:        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		ServiceID: assetTestServiceID, AssetID: assetTestAssetID,
		Scope: assetcatalog.Scope{
			TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
			EnvironmentID: assetTestEnvironmentID,
		},
		Role: assetcatalog.BindingRolePrimaryRuntime, MappingStatus: domain.MappingExact,
		Provenance: assetcatalog.ProvenanceMergeDecision, Status: assetcatalog.BindingStatusActive,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func pointerBinding(value assetcatalog.ServiceAssetBinding) *assetcatalog.ServiceAssetBinding {
	return &value
}

var _ assetcatalog.ConflictManager = (*recordingConflictManager)(nil)
