package credentialadmin_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/credentialadmin"
)

const (
	testWorkspaceID   = "11111111-1111-4111-8111-111111111111"
	testEnvironmentID = "22222222-2222-4222-8222-222222222222"
	testRevocationID  = "33333333-3333-4333-8333-333333333333"
)

func TestServiceListDerivesTrustedActorAndDefaults(t *testing.T) {
	t.Parallel()

	record := validManagementRecord()
	store := &managementStoreStub{page: credential.ManagementPage{Items: []credential.ManagementRecord{record}}}
	authorizer := &authorizerStub{}
	service, err := credentialadmin.New(store, authorizer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	principal := validPrincipal(authn.RoleSRE)

	page, err := service.List(context.Background(), principal, credentialadmin.ListRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if !reflect.DeepEqual(page.Items, []credential.ManagementRecord{record}) {
		t.Fatalf("List() page = %#v", page)
	}
	wantRequest := credential.ManagementListRequest{
		Scope:  credential.ManagementScope{WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID},
		Actor:  credential.ManagementActor{Subject: "oidc:subject-1"},
		Status: credential.StatusManualRequired,
		Limit:  credential.DefaultManagementPageSize,
	}
	if !reflect.DeepEqual(store.listRequest, wantRequest) {
		t.Fatalf("store List request = %#v, want %#v", store.listRequest, wantRequest)
	}
	wantAuthorization := authz.Request{
		Permission:  authz.PermissionCredentialRevocationRead,
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
	}
	if !reflect.DeepEqual(authorizer.request, wantAuthorization) || authorizer.principal.Subject != principal.Subject {
		t.Fatalf("authorization = %#v/%#v, want %#v/%#v", authorizer.principal, authorizer.request, principal, wantAuthorization)
	}
}

func TestServiceGetRequiresExactTrustedStoreResult(t *testing.T) {
	t.Parallel()

	store := &managementStoreStub{record: validManagementRecord()}
	authorizer := &authorizerStub{}
	service, err := credentialadmin.New(store, authorizer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := credentialadmin.ItemRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID, RevocationID: testRevocationID,
	}
	record, err := service.Get(context.Background(), validPrincipal(authn.RoleAdmin), request)
	if err != nil || record.ID != testRevocationID {
		t.Fatalf("Get() = %#v, %v", record, err)
	}
	if store.getRequest.Actor.Subject != "oidc:subject-1" || !store.getRequest.Actor.PlatformAdmin {
		t.Fatalf("Get() actor = %#v", store.getRequest.Actor)
	}
	if authorizer.request.Permission != authz.PermissionCredentialRevocationRead {
		t.Fatalf("Get() permission = %q", authorizer.request.Permission)
	}

	store.record.EnvironmentID = "44444444-4444-4444-8444-444444444444"
	if _, err := service.Get(context.Background(), validPrincipal(authn.RoleAdmin), request); !errors.Is(err, credentialadmin.ErrUnsafeStoreResult) {
		t.Fatalf("Get(hostile scope) error = %v, want ErrUnsafeStoreResult", err)
	}
	store.record = validManagementRecord()
	store.record.ID = "55555555-5555-4555-8555-555555555555"
	if _, err := service.Get(context.Background(), validPrincipal(authn.RoleAdmin), request); !errors.Is(err, credentialadmin.ErrUnsafeStoreResult) {
		t.Fatalf("Get(hostile id) error = %v, want ErrUnsafeStoreResult", err)
	}
}

func TestServiceMutationsDeriveActorAndUseDedicatedPermissions(t *testing.T) {
	t.Parallel()

	store := &managementStoreStub{record: validManagementRecord()}
	authorizer := &authorizerStub{}
	service, err := credentialadmin.New(store, authorizer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	item := credentialadmin.ItemRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID, RevocationID: testRevocationID,
	}
	store.record.Status = credential.StatusRevocationPending
	if _, err := service.Requeue(context.Background(), validPrincipal(authn.RoleAdmin), item); err != nil {
		t.Fatalf("Requeue() error = %v", err)
	}
	if authorizer.request.Permission != authz.PermissionCredentialRevocationRequeue ||
		store.requeueRequest.Actor.Subject != "oidc:subject-1" || !store.requeueRequest.Actor.PlatformAdmin {
		t.Fatalf("Requeue() authorization/request = %#v/%#v", authorizer.request, store.requeueRequest)
	}

	evidenceHash := credential.SHA256Hex([]byte("external-evidence"))
	store.record.Status = credential.StatusManualRequired
	store.record.EvidenceHash = evidenceHash
	store.record.ConfirmationCount = 1
	if _, err := service.Confirm(context.Background(), validPrincipal(authn.RoleSRE), credentialadmin.ConfirmationRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		RevocationID: testRevocationID, EvidenceHash: evidenceHash,
	}); err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if authorizer.request.Permission != authz.PermissionCredentialRevocationConfirm ||
		store.confirmationRequest.Actor.Subject != "oidc:subject-1" || store.confirmationRequest.Actor.PlatformAdmin ||
		store.confirmationRequest.EvidenceHash != evidenceHash {
		t.Fatalf("Confirm() authorization/request = %#v/%#v", authorizer.request, store.confirmationRequest)
	}
	if _, err := service.Confirm(context.Background(), validPrincipal(authn.RoleSRE), credentialadmin.ConfirmationRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		RevocationID: testRevocationID, EvidenceHash: strings.Repeat("A", 64),
	}); !errors.Is(err, credentialadmin.ErrInvalidRequest) {
		t.Fatalf("Confirm(non-canonical evidence) error = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceFailsClosedForUnauthorizedScopeAndHostileList(t *testing.T) {
	t.Parallel()

	record := validManagementRecord()
	store := &managementStoreStub{page: credential.ManagementPage{Items: []credential.ManagementRecord{record}}}
	authorizer := &authorizerStub{}
	service, err := credentialadmin.New(store, authorizer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	principal := validPrincipal(authn.RoleSRE)
	principal.WorkspaceIDs = []string{"44444444-4444-4444-8444-444444444444"}
	if _, err := service.List(context.Background(), principal, credentialadmin.ListRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
	}); !errors.Is(err, credential.ErrRevocationNotFound) {
		t.Fatalf("List(cross scope) error = %v, want ErrRevocationNotFound", err)
	}
	if store.listRequest.Scope.WorkspaceID != "" {
		t.Fatal("cross-scope request reached store")
	}

	store.page.Items[0].WorkspaceID = "44444444-4444-4444-8444-444444444444"
	if _, err := service.List(context.Background(), validPrincipal(authn.RoleSRE), credentialadmin.ListRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
	}); !errors.Is(err, credentialadmin.ErrUnsafeStoreResult) {
		t.Fatalf("List(hostile scope) error = %v, want ErrUnsafeStoreResult", err)
	}
}

func TestServiceListValidatesDescendingKeysetPage(t *testing.T) {
	t.Parallel()

	newer := validManagementRecord()
	newer.ID = "44444444-4444-4444-8444-444444444444"
	newer.CreatedAt = newer.CreatedAt.Add(time.Minute)
	newer.UpdatedAt = newer.UpdatedAt.Add(time.Minute)
	older := validManagementRecord()
	next := credential.ManagementCursor{CreatedAt: older.CreatedAt, RevocationID: older.ID}
	store := &managementStoreStub{page: credential.ManagementPage{
		Items: []credential.ManagementRecord{newer, older}, Next: &next,
	}}
	service, err := credentialadmin.New(store, &authorizerStub{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := credentialadmin.ListRequest{
		WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		Status: credential.StatusManualRequired, Limit: 2,
	}
	if _, err := service.List(context.Background(), validPrincipal(authn.RoleSRE), request); err != nil {
		t.Fatalf("List(valid keyset page) error = %v", err)
	}

	tests := map[string]credential.ManagementPage{
		"next on partial page": {Items: []credential.ManagementRecord{newer}, Next: &credential.ManagementCursor{
			CreatedAt: newer.CreatedAt, RevocationID: newer.ID,
		}},
		"next differs from last item": {Items: []credential.ManagementRecord{newer, older}, Next: &credential.ManagementCursor{
			CreatedAt: newer.CreatedAt, RevocationID: newer.ID,
		}},
		"ascending order": {Items: []credential.ManagementRecord{older, newer}},
		"duplicate":       {Items: []credential.ManagementRecord{newer, newer}},
	}
	for name, page := range tests {
		name, page := name, page
		t.Run(name, func(t *testing.T) {
			store.page = page
			if _, err := service.List(context.Background(), validPrincipal(authn.RoleSRE), request); !errors.Is(err, credentialadmin.ErrUnsafeStoreResult) {
				t.Fatalf("List() error = %v, want ErrUnsafeStoreResult", err)
			}
		})
	}

	after := credential.ManagementCursor{CreatedAt: older.CreatedAt, RevocationID: older.ID}
	store.page = credential.ManagementPage{Items: []credential.ManagementRecord{newer}}
	request.After = &after
	request.Limit = 1
	if _, err := service.List(context.Background(), validPrincipal(authn.RoleSRE), request); !errors.Is(err, credentialadmin.ErrUnsafeStoreResult) {
		t.Fatalf("List(item before cursor) error = %v, want ErrUnsafeStoreResult", err)
	}
}

func TestServiceRejectsNilDependenciesAndInvalidBounds(t *testing.T) {
	t.Parallel()

	var typedNilStore *managementStoreStub
	if _, err := credentialadmin.New(typedNilStore, &authorizerStub{}); err == nil {
		t.Fatal("New(typed nil store) unexpectedly succeeded")
	}
	var typedNilAuthorizer *authorizerStub
	if _, err := credentialadmin.New(&managementStoreStub{}, typedNilAuthorizer); err == nil {
		t.Fatal("New(typed nil authorizer) unexpectedly succeeded")
	}

	store := &managementStoreStub{}
	service, err := credentialadmin.New(store, &authorizerStub{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, limit := range []int{-1, credential.MaxManagementPageSize + 1} {
		if _, err := service.List(context.Background(), validPrincipal(authn.RoleSRE), credentialadmin.ListRequest{
			WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID, Limit: limit,
		}); !errors.Is(err, credentialadmin.ErrInvalidRequest) {
			t.Fatalf("List(limit=%d) error = %v, want ErrInvalidRequest", limit, err)
		}
	}
}

type authorizerStub struct {
	principal authn.Principal
	request   authz.Request
	err       error
}

func (stub *authorizerStub) Authorize(principal authn.Principal, request authz.Request) error {
	stub.principal = principal
	stub.request = request
	return stub.err
}

type managementStoreStub struct {
	page                credential.ManagementPage
	record              credential.ManagementRecord
	err                 error
	listRequest         credential.ManagementListRequest
	getRequest          credential.ManagementGetRequest
	requeueRequest      credential.ManagementRequeueRequest
	confirmationRequest credential.ManagementConfirmationRequest
}

func (stub *managementStoreStub) ListManagement(_ context.Context, request credential.ManagementListRequest) (credential.ManagementPage, error) {
	stub.listRequest = request
	return stub.page, stub.err
}

func (stub *managementStoreStub) GetManagement(_ context.Context, request credential.ManagementGetRequest) (credential.ManagementRecord, error) {
	stub.getRequest = request
	return stub.record, stub.err
}

func (stub *managementStoreStub) RequeueManagement(_ context.Context, request credential.ManagementRequeueRequest) (credential.ManagementRecord, error) {
	stub.requeueRequest = request
	return stub.record, stub.err
}

func (stub *managementStoreStub) ConfirmManagement(_ context.Context, request credential.ManagementConfirmationRequest) (credential.ManagementRecord, error) {
	stub.confirmationRequest = request
	return stub.record, stub.err
}

func validPrincipal(roles ...authn.Role) authn.Principal {
	now := time.Now().UTC()
	return authn.Principal{
		Subject: "subject-1", Roles: roles,
		WorkspaceIDs: []string{testWorkspaceID}, EnvironmentIDs: []string{testEnvironmentID},
		AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func validManagementRecord() credential.ManagementRecord {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	return credential.ManagementRecord{
		ID: testRevocationID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID,
		ActionID: "action-1", TargetKey: "kubernetes:cluster/ns/deployment", ActionType: "KUBERNETES_SCALE",
		ConnectorID: "connector-1", Status: credential.StatusManualRequired, AccessorPresent: true,
		CredentialExpiresAt: now.Add(-5 * time.Minute), Attempt: 12, FailureCount: 12,
		FailureCode: credential.FailureTimeout, FailureDetailSHA256: credential.SHA256Hex([]byte("sanitized")),
		AvailableAt: now, ManualRequiredAt: now, Version: 13, CreatedAt: now.Add(-10 * time.Minute), UpdatedAt: now,
	}
}
