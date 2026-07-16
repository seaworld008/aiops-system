package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	assetTestTenantID      = "11111111-1111-4111-8111-111111111111"
	assetTestWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	assetTestEnvironmentID = "33333333-3333-4333-8333-333333333333"
	assetTestAssetID       = "44444444-4444-4444-8444-444444444444"
	assetTestSourceID      = "55555555-5555-4555-8555-555555555555"
	assetTestServiceID     = "66666666-6666-4666-8666-666666666666"
	assetTestAuditID       = "77777777-7777-4777-8777-777777777777"
	assetTestBasePath      = "/api/v1/workspaces/" + assetTestWorkspaceID +
		"/environments/" + assetTestEnvironmentID + "/assets"
)

func TestAssetRoutesRequireAuthenticationAndPreservePathScope(t *testing.T) {
	t.Parallel()
	manager := &recordingAssetManager{page: assetcatalog.AssetViewPage{
		Items: []assetcatalog.AssetSummaryView{assetSummary(safeAssetView())},
	}}
	codec := mustControlPlaneCursorCodec(t)

	unauthenticated := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{err: authn.ErrUnauthenticated}, Assets: manager,
		ControlPlaneCursor: codec,
	}).ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, assetTestBasePath+"?limit=25", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}

	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, Assets: manager,
		ControlPlaneCursor: codec,
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, assetTestBasePath+"?limit=25", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET assets = %d %s", response.Code, response.Body.String())
	}
	if manager.collection.WorkspaceID != assetTestWorkspaceID ||
		manager.collection.EnvironmentID != assetTestEnvironmentID || manager.listInput.Limit != 25 {
		t.Fatalf("manager request = %#v %#v", manager.collection, manager.listInput)
	}
	assertControlPlaneResponseHeaders(t, response)
}

func TestAssetDTOContainsNoRuntimeCredentialOrProviderMaterial(t *testing.T) {
	t.Parallel()
	manager := &recordingAssetManager{view: safeAssetView()}
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, Assets: manager,
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, assetTestBasePath+"/"+assetTestAssetID, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET asset = %d %s", response.Code, response.Body.String())
	}
	lower := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		"secret", "token", "password", "private_key", "dsn", "endpoint",
		"normalized_document", "raw_payload", "command", "sql", "header", "request_body",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("asset DTO contains %q: %s", forbidden, lower)
		}
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode asset: %v", err)
	}
	if body["id"] != assetTestAssetID || body["provider_kind"] != "MANUAL_V1" {
		t.Fatalf("asset DTO = %#v", body)
	}
	if got := response.Header().Get("ETag"); got != `"asset:`+assetTestAssetID+`:v2"` {
		t.Fatalf("ETag = %q", got)
	}
}

func TestAssetCrossScopeUnknownAndNoStoreProjection(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		err      error
		status   int
		codePart string
	}{
		"cross scope": {err: assetcatalog.ErrScopeViolation, status: http.StatusForbidden, codePart: `"code":"asset_scope_forbidden"`},
		"unknown":     {err: assetcatalog.ErrNotFound, status: http.StatusNotFound, codePart: `"code":"asset_not_found"`},
	} {
		manager := &recordingAssetManager{err: test.err}
		response := httptest.NewRecorder()
		httpapi.NewRouter(httpapi.Dependencies{
			Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, Assets: manager,
			ControlPlaneCursor: mustControlPlaneCursorCodec(t),
		}).ServeHTTP(response, httptest.NewRequest(
			http.MethodGet, assetTestBasePath+"/"+assetTestAssetID, nil,
		))
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.codePart) {
			t.Errorf("%s response = %d %s", name, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), assetTestAssetID) ||
			strings.Contains(response.Body.String(), assetTestWorkspaceID) ||
			strings.Contains(response.Body.String(), assetTestEnvironmentID) {
			t.Errorf("%s response enumerates route scope: %s", name, response.Body.String())
		}
		assertControlPlaneResponseHeaders(t, response)
	}
}

func TestAssetCatalogErrorsSeparateUnavailableStateAndUnknown(t *testing.T) {
	t.Parallel()

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	tests := map[string]struct {
		err    error
		status int
		code   string
	}{
		"unavailable": {
			err: fmt.Errorf(
				"SQLSTATE 08006 sensitive database detail dsn=postgres://secret endpoint=https://internal.example: %w",
				assetcatalog.ErrUnavailable,
			),
			status: http.StatusServiceUnavailable,
			code:   "asset_catalog_unavailable",
		},
		"state conflict": {
			err:    assetcatalog.ErrStateConflict,
			status: http.StatusConflict,
			code:   "invalid_asset_state",
		},
		"unknown": {
			err:    errors.New("internal program failure"),
			status: http.StatusInternalServerError,
			code:   "asset_catalog_failed",
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manager := &recordingAssetManager{err: test.err}
			request := httptest.NewRequest(http.MethodGet, assetTestBasePath+"/"+assetTestAssetID, nil)
			request.Header.Set("traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")
			response := httptest.NewRecorder()
			httpapi.NewRouter(httpapi.Dependencies{
				Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
				Assets:             manager,
				ControlPlaneCursor: mustControlPlaneCursorCodec(t),
			}).ServeHTTP(response, request)

			body := response.Body.String()
			if response.Code != test.status ||
				!strings.Contains(body, `"code":"`+test.code+`"`) ||
				!strings.Contains(body, `"trace_id":"`+traceID+`"`) {
				t.Fatalf("response = %d %s, want %d %s with trace", response.Code, body, test.status, test.code)
			}
			for _, forbidden := range []string{
				"sqlstate", "sensitive database detail", "postgres://", "internal.example",
				"internal program failure", assetTestAssetID, assetTestWorkspaceID, assetTestEnvironmentID,
			} {
				if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
					t.Errorf("response leaked %q: %s", forbidden, body)
				}
			}
			assertControlPlaneResponseHeaders(t, response)
		})
	}
}

func TestAssetCreateUsesStrictBodyTrustedMetadataAndPersistedReceipt(t *testing.T) {
	t.Parallel()
	manager := &recordingAssetManager{view: safeAssetView()}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, Assets: manager,
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	body := `{
		"source_id":"` + assetTestSourceID + `",
		"kind":"LINUX_VM",
		"external_id":"manual-host-1",
		"display_name":"api-01",
		"owner_group":"platform",
		"criticality":"HIGH",
		"data_classification":"INTERNAL",
		"labels":[{"key":"region","value":"cn-east-1"}]
	}`
	request := httptest.NewRequest(http.MethodPost, assetTestBasePath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "asset:create:request-1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("POST asset = %d %s", response.Code, response.Body.String())
	}
	if manager.createInput.SourceID != assetTestSourceID || manager.createInput.Labels["region"] != "cn-east-1" {
		t.Fatalf("Create input = %#v", manager.createInput)
	}
	if manager.metadata.IdempotencyKey != "asset:create:request-1" ||
		len(manager.metadata.TraceID) != 32 || manager.metadata.ExpectedVersion != 0 {
		t.Fatalf("metadata = %#v", manager.metadata)
	}
	if got := response.Header().Get("Location"); got != assetTestBasePath+"/"+assetTestAssetID {
		t.Fatalf("Location = %q", got)
	}
	if !strings.Contains(response.Body.String(), `"audit_id":"`+assetTestAuditID+`"`) ||
		!strings.Contains(response.Body.String(), `"trace_id":"`+manager.metadata.TraceID+`"`) {
		t.Fatalf("mutation receipt = %s", response.Body.String())
	}

	for name, invalidBody := range map[string]string{
		"unknown":   strings.TrimSuffix(body, "\n\t}") + `,"tenant_id":"` + assetTestTenantID + `"}`,
		"duplicate": strings.Replace(body, `"source_id":"`+assetTestSourceID+`",`, `"source_id":"`+assetTestSourceID+`","source_id":"`+assetTestSourceID+`",`, 1),
	} {
		request := httptest.NewRequest(http.MethodPost, assetTestBasePath, strings.NewReader(invalidBody))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "asset:create:request-2")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s body response = %d %s", name, response.Code, response.Body.String())
		}
	}
}

func TestAssetPatchRequiresExactIfMatchAndIdempotencyKey(t *testing.T) {
	t.Parallel()
	manager := &recordingAssetManager{view: safeAssetView()}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, Assets: manager,
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	body := `{"display_name":"api-02","owner_group":null,"criticality":"CRITICAL","data_classification":"CONFIDENTIAL","labels":[]}`
	for name, mutate := range map[string]func(*http.Request){
		"missing idempotency": func(request *http.Request) {
			request.Header.Set("If-Match", `"asset:`+assetTestAssetID+`:v2"`)
		},
		"weak etag": func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "asset:update:request-1")
			request.Header.Set("If-Match", `W/"asset:`+assetTestAssetID+`:v2"`)
		},
		"wrong resource": func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "asset:update:request-1")
			request.Header.Set("If-Match", `"source:`+assetTestAssetID+`:v2"`)
		},
	} {
		request := httptest.NewRequest(http.MethodPatch, assetTestBasePath+"/"+assetTestAssetID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		mutate(request)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s response = %d %s", name, response.Code, response.Body.String())
		}
	}
}

func TestAssetUnknownDuplicateAndInvalidUUIDBodiesNeverReachManager(t *testing.T) {
	t.Parallel()
	routerFor := func(manager *recordingAssetManager) http.Handler {
		return httpapi.NewRouter(httpapi.Dependencies{
			Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, Assets: manager,
			ControlPlaneCursor: mustControlPlaneCursorCodec(t),
		})
	}
	validCreateBody := `{
		"source_id":"` + assetTestSourceID + `",
		"kind":"LINUX_VM",
		"external_id":"manual-host-1",
		"display_name":"api-01",
		"owner_group":"platform",
		"criticality":"HIGH",
		"data_classification":"INTERNAL",
		"labels":[]
	}`
	for name, body := range map[string]string{
		"invalid UUID": strings.Replace(validCreateBody, assetTestSourceID, "not-a-uuid", 1),
		"invalid kind": strings.Replace(validCreateBody, `"LINUX_VM"`, `"UNKNOWN"`, 1),
		"unsafe text":  strings.Replace(validCreateBody, `"api-01"`, `" api-01"`, 1),
	} {
		manager := &recordingAssetManager{view: safeAssetView()}
		request := httptest.NewRequest(http.MethodPost, assetTestBasePath, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "asset:create:invalid-1")
		response := httptest.NewRecorder()
		routerFor(manager).ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || manager.createCalls != 0 {
			t.Errorf("%s response/calls = %d %s / %d", name, response.Code, response.Body.String(), manager.createCalls)
		}
	}

	manager := &recordingAssetManager{view: safeAssetView()}
	request := httptest.NewRequest(
		http.MethodPatch, assetTestBasePath+"/"+assetTestAssetID,
		strings.NewReader(`{"display_name":" api-02","owner_group":null,"criticality":"CRITICAL","data_classification":"CONFIDENTIAL","labels":[]}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "asset:update:invalid-1")
	request.Header.Set("If-Match", `"asset:`+assetTestAssetID+`:v2"`)
	response := httptest.NewRecorder()
	routerFor(manager).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || manager.updateCalls != 0 {
		t.Fatalf("invalid patch response/calls = %d %s / %d", response.Code, response.Body.String(), manager.updateCalls)
	}

	manager = &recordingAssetManager{view: safeAssetView()}
	request = httptest.NewRequest(
		http.MethodPost, assetTestBasePath+"/"+assetTestAssetID+":quarantine",
		strings.NewReader(`{"reason_code":"unsafe reason"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "asset:transition:invalid-1")
	request.Header.Set("If-Match", `"asset:`+assetTestAssetID+`:v2"`)
	response = httptest.NewRecorder()
	routerFor(manager).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || manager.transitionCalls != 0 {
		t.Fatalf("invalid transition response/calls = %d %s / %d", response.Code, response.Body.String(), manager.transitionCalls)
	}
}

func TestAssetRoutesFailClosedWhenManagerOrCursorDependencyIsMissing(t *testing.T) {
	t.Parallel()
	tests := []httpapi.Dependencies{
		{Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, ControlPlaneCursor: mustControlPlaneCursorCodec(t)},
		{Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()}, Assets: &recordingAssetManager{}},
	}
	for _, dependencies := range tests {
		response := httptest.NewRecorder()
		httpapi.NewRouter(dependencies).ServeHTTP(response, httptest.NewRequest(http.MethodGet, assetTestBasePath, nil))
		if response.Code != http.StatusServiceUnavailable ||
			!strings.Contains(response.Body.String(), `"code":"asset_catalog_unavailable"`) {
			t.Fatalf("dependency omission response = %d %s", response.Code, response.Body.String())
		}
	}
}

type recordingAssetManager struct {
	page            assetcatalog.AssetViewPage
	view            assetcatalog.AssetView
	err             error
	collection      assetcatalog.AssetCollectionRequest
	path            assetcatalog.AssetPathRequest
	listInput       assetcatalog.AssetListInput
	createInput     assetcatalog.CreateAssetInput
	updateInput     assetcatalog.UpdateGovernanceInput
	transition      assetcatalog.TransitionInput
	metadata        assetcatalog.ServerRequestMetadata
	createCalls     int
	updateCalls     int
	transitionCalls int
}

func (manager *recordingAssetManager) ListAssets(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.AssetCollectionRequest,
	input assetcatalog.AssetListInput,
) (assetcatalog.AssetViewPage, error) {
	manager.collection, manager.listInput = collection, input
	return manager.page, manager.err
}

func (manager *recordingAssetManager) GetAsset(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.AssetPathRequest,
) (assetcatalog.AssetView, error) {
	manager.path = path
	return manager.view, manager.err
}

func (manager *recordingAssetManager) CreateAsset(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.AssetCollectionRequest,
	input assetcatalog.CreateAssetInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.AssetMutationView, error) {
	manager.createCalls++
	manager.collection, manager.createInput, manager.metadata = collection, input, metadata
	view := manager.view
	return assetcatalog.AssetMutationView{
		View: view,
		Receipt: assetcatalog.MutationReceipt{
			AuditID: assetTestAuditID, TraceID: metadata.TraceID,
		},
	}, manager.err
}

func (manager *recordingAssetManager) UpdateAsset(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.AssetPathRequest,
	input assetcatalog.UpdateGovernanceInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.AssetMutationView, error) {
	manager.updateCalls++
	manager.path, manager.updateInput, manager.metadata = path, input, metadata
	return assetcatalog.AssetMutationView{
		View: manager.view,
		Receipt: assetcatalog.MutationReceipt{
			AuditID: assetTestAuditID, TraceID: metadata.TraceID,
		},
	}, manager.err
}

func (manager *recordingAssetManager) QuarantineAsset(
	ctx context.Context,
	principal authn.Principal,
	path assetcatalog.AssetPathRequest,
	input assetcatalog.TransitionInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.AssetMutationView, error) {
	manager.transitionCalls++
	manager.transition = input
	return manager.UpdateAsset(ctx, principal, path, assetcatalog.UpdateGovernanceInput{}, metadata)
}

func (manager *recordingAssetManager) RetireAsset(
	ctx context.Context,
	principal authn.Principal,
	path assetcatalog.AssetPathRequest,
	input assetcatalog.TransitionInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.AssetMutationView, error) {
	manager.transitionCalls++
	manager.transition = input
	return manager.UpdateAsset(ctx, principal, path, assetcatalog.UpdateGovernanceInput{}, metadata)
}

func safeAssetView() assetcatalog.AssetView {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	owner := "platform"
	return assetcatalog.AssetView{
		ReadModel: assetcatalog.AssetDetailReadModel{
			AssetReadModel: assetcatalog.AssetReadModel{
				Asset: assetcatalog.Asset{
					ID: assetTestAssetID, SourceID: assetTestSourceID, ProviderKind: "MANUAL_V1",
					ExternalID: "manual-host-1", DisplayName: "api-01",
					Scope: assetcatalog.Scope{
						TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
						EnvironmentID: assetTestEnvironmentID,
					},
					Kind: assetcatalog.KindLinuxVM, Lifecycle: assetcatalog.LifecycleDiscovered,
					MappingStatus: domain.MappingExact, OwnerGroup: &owner,
					Criticality:        assetcatalog.CriticalityHigh,
					DataClassification: assetcatalog.DataClassificationInternal,
					Labels:             map[string]string{"region": "cn-east-1"},
					LastObservedAt:     now, LastSourceRevision: 1, Version: 2,
					CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
				},
				Source: assetcatalog.AssetSourceReference{
					ID: assetTestSourceID, Name: "manual", Kind: assetcatalog.SourceKindManual,
				},
				Services: []assetcatalog.AssetServiceReference{{
					ID: assetTestServiceID, Name: "api", Role: assetcatalog.BindingRolePrimaryRuntime,
				}},
				Connection: assetcatalog.ConnectionSummary{Status: assetcatalog.OperationalSummaryNotConfigured},
				Capability: assetcatalog.CapabilitySummary{
					Status: assetcatalog.OperationalSummaryNotConfigured, Count: 0,
				},
			},
			FieldProvenance: []assetcatalog.FieldProvenanceSummary{{
				FieldCode: "display_name", SourceID: assetTestSourceID, ProviderKind: "MANUAL_V1",
				SourceRevision: 1, ObservedAt: now, ProviderPathCode: "display_name",
				Confidence: 100, Ownership: assetcatalog.FieldOwnershipGovernance,
			}},
			Relations: assetcatalog.AssetRelationCounts{Incoming: 1, Outgoing: 2},
		},
		EffectiveActions: []assetcatalog.EffectiveAction{
			assetcatalog.ActionEditGovernance, assetcatalog.ActionQuarantine, assetcatalog.ActionRetire,
		},
	}
}

func assetSummary(view assetcatalog.AssetView) assetcatalog.AssetSummaryView {
	return assetcatalog.AssetSummaryView{
		ReadModel:        view.ReadModel.AssetReadModel.Clone(),
		EffectiveActions: append([]assetcatalog.EffectiveAction(nil), view.EffectiveActions...),
	}
}

func assetHTTPPrincipal() authn.Principal {
	now := time.Now().UTC()
	return authn.Principal{
		Subject: "asset-user", TenantID: assetTestTenantID, Roles: []authn.Role{authn.RoleAdmin},
		WorkspaceIDs: []string{assetTestWorkspaceID}, EnvironmentIDs: []string{assetTestEnvironmentID},
		ServiceIDs: []string{assetTestServiceID}, AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func mustControlPlaneCursorCodec(t *testing.T) *httpapi.ControlPlaneCursorCodec {
	t.Helper()
	codec, err := httpapi.NewControlPlaneCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewControlPlaneCursorCodec() error = %v", err)
	}
	return codec
}

func assertControlPlaneResponseHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if traceID := response.Header().Get("X-Trace-ID"); len(traceID) != 32 {
		t.Errorf("X-Trace-ID = %q", traceID)
	}
}

var _ assetcatalog.AssetManager = (*recordingAssetManager)(nil)
