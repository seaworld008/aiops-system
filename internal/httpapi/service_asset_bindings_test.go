package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

const (
	bindingTestID       = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	bindingTestBasePath = "/api/v1/workspaces/" + assetTestWorkspaceID + "/environments/" +
		assetTestEnvironmentID + "/service-asset-bindings"
)

func TestServiceAssetBindingListAndCreateUseExactScopeAndReceipt(t *testing.T) {
	t.Parallel()
	binding := safeBinding()
	manager := &recordingBindingManager{
		page: assetcatalog.BindingViewPage{Items: []assetcatalog.BindingView{{
			Binding: binding, EffectiveActions: []assetcatalog.EffectiveAction{assetcatalog.ActionDeleteBinding},
		}}},
		mutation: assetcatalog.BindingMutationView{
			View: assetcatalog.BindingView{
				Binding: binding, EffectiveActions: []assetcatalog.EffectiveAction{assetcatalog.ActionDeleteBinding},
			},
		},
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:        fakeAuthenticator{principal: assetHTTPPrincipal()},
		ServiceAssetBindings: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		bindingTestBasePath+"?service_id="+assetTestServiceID+"&roles=PRIMARY_RUNTIME&statuses=ACTIVE&limit=30",
		nil,
	))
	if response.Code != http.StatusOK {
		t.Fatalf("GET bindings = %d %s", response.Code, response.Body.String())
	}
	if manager.collection.WorkspaceID != assetTestWorkspaceID ||
		manager.collection.EnvironmentID != assetTestEnvironmentID ||
		manager.listInput.ServiceID != assetTestServiceID || manager.listInput.Limit != 30 {
		t.Fatalf("manager request = %#v %#v", manager.collection, manager.listInput)
	}

	request := httptest.NewRequest(http.MethodPost, bindingTestBasePath, strings.NewReader(
		`{"service_id":"`+assetTestServiceID+`","asset_id":"`+assetTestAssetID+
			`","role":"PRIMARY_RUNTIME","reason_code":"PRIMARY_RUNTIME_CONFIRMED"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "asset:binding:create-1")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("POST binding = %d %s", response.Code, response.Body.String())
	}
	if manager.createInput.ServiceID != assetTestServiceID ||
		manager.createInput.AssetID != assetTestAssetID ||
		manager.metadata.IdempotencyKey != "asset:binding:create-1" {
		t.Fatalf("create request = %#v %#v", manager.createInput, manager.metadata)
	}
	if got := response.Header().Get("Location"); got != bindingTestBasePath+"/"+bindingTestID {
		t.Fatalf("Location = %q", got)
	}
	if !strings.Contains(response.Body.String(), `"audit_id":"`+assetTestAuditID+`"`) {
		t.Fatalf("create response = %s", response.Body.String())
	}
}

func TestDeleteServiceAssetBindingUsesPersistedReceiptHeaders(t *testing.T) {
	t.Parallel()
	manager := &recordingBindingManager{deleteReceipt: assetcatalog.MutationReceipt{
		AuditID: assetTestAuditID, IdempotentReplay: true,
	}}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:        fakeAuthenticator{principal: assetHTTPPrincipal()},
		ServiceAssetBindings: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	request := httptest.NewRequest(
		http.MethodDelete, bindingTestBasePath+"/"+bindingTestID,
		strings.NewReader(`{"reason_code":"NO_LONGER_PRIMARY"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "asset:binding:delete-1")
	request.Header.Set("If-Match", `"service-asset-binding:`+bindingTestID+`:v1"`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("DELETE binding = %d %s", response.Code, response.Body.String())
	}
	if manager.path.BindingID != bindingTestID || manager.deleteInput.ReasonCode != "NO_LONGER_PRIMARY" ||
		manager.metadata.ExpectedVersion != 1 {
		t.Fatalf("delete request = %#v %#v %#v", manager.path, manager.deleteInput, manager.metadata)
	}
	if response.Header().Get("X-Audit-ID") != assetTestAuditID ||
		response.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("receipt headers = %#v", response.Header())
	}
}

func TestServiceAssetBindingRoutesRejectMissingDependenciesAndMalformedHeaders(t *testing.T) {
	t.Parallel()
	manager := &recordingBindingManager{}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:        fakeAuthenticator{principal: assetHTTPPrincipal()},
		ServiceAssetBindings: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	request := httptest.NewRequest(
		http.MethodDelete, bindingTestBasePath+"/"+bindingTestID,
		strings.NewReader(`{"reason_code":"NO_LONGER_PRIMARY"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "asset:binding:delete-1")
	request.Header.Set("If-Match", `W/"service-asset-binding:`+bindingTestID+`:v1"`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || manager.path.BindingID != "" {
		t.Fatalf("weak ETag response/request = %d %s / %#v", response.Code, response.Body.String(), manager.path)
	}

	response = httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, bindingTestBasePath, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager response = %d %s", response.Code, response.Body.String())
	}
}

func TestServiceAssetBindingInvalidReasonCodeNeverReachesManager(t *testing.T) {
	t.Parallel()
	manager := &recordingBindingManager{}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:        fakeAuthenticator{principal: assetHTTPPrincipal()},
		ServiceAssetBindings: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	create := httptest.NewRequest(http.MethodPost, bindingTestBasePath, strings.NewReader(
		`{"service_id":"`+assetTestServiceID+`","asset_id":"`+assetTestAssetID+
			`","role":"PRIMARY_RUNTIME","reason_code":"unsafe reason"}`,
	))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "asset:binding:create-invalid")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, create)
	if response.Code != http.StatusBadRequest || manager.createCalls != 0 {
		t.Fatalf("invalid create response/calls = %d %s / %d", response.Code, response.Body.String(), manager.createCalls)
	}

	deleteRequest := httptest.NewRequest(
		http.MethodDelete, bindingTestBasePath+"/"+bindingTestID,
		strings.NewReader(`{"reason_code":"unsafe reason"}`),
	)
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteRequest.Header.Set("Idempotency-Key", "asset:binding:delete-invalid")
	deleteRequest.Header.Set("If-Match", `"service-asset-binding:`+bindingTestID+`:v1"`)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, deleteRequest)
	if response.Code != http.StatusBadRequest || manager.deleteCalls != 0 {
		t.Fatalf("invalid delete response/calls = %d %s / %d", response.Code, response.Body.String(), manager.deleteCalls)
	}
}

type recordingBindingManager struct {
	page          assetcatalog.BindingViewPage
	mutation      assetcatalog.BindingMutationView
	deleteReceipt assetcatalog.MutationReceipt
	err           error
	collection    assetcatalog.AssetCollectionRequest
	path          assetcatalog.BindingPathRequest
	listInput     assetcatalog.BindingListInput
	createInput   assetcatalog.CreateBindingInput
	deleteInput   assetcatalog.DeleteBindingInput
	metadata      assetcatalog.ServerRequestMetadata
	createCalls   int
	deleteCalls   int
}

func (manager *recordingBindingManager) ListBindings(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.AssetCollectionRequest,
	input assetcatalog.BindingListInput,
) (assetcatalog.BindingViewPage, error) {
	manager.collection, manager.listInput = collection, input
	return manager.page, manager.err
}

func (manager *recordingBindingManager) CreateBinding(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.AssetCollectionRequest,
	input assetcatalog.CreateBindingInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.BindingMutationView, error) {
	manager.createCalls++
	manager.collection, manager.createInput, manager.metadata = collection, input, metadata
	result := manager.mutation
	result.Receipt = assetcatalog.MutationReceipt{
		AuditID: assetTestAuditID, TraceID: metadata.TraceID,
	}
	return result, manager.err
}

func (manager *recordingBindingManager) DeleteBinding(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.BindingPathRequest,
	input assetcatalog.DeleteBindingInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.MutationReceipt, error) {
	manager.deleteCalls++
	manager.path, manager.deleteInput, manager.metadata = path, input, metadata
	result := manager.deleteReceipt
	result.TraceID = metadata.TraceID
	return result, manager.err
}

var _ assetcatalog.BindingManager = (*recordingBindingManager)(nil)
