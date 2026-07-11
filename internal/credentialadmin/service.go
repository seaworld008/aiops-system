package credentialadmin

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/credential"
)

var (
	ErrInvalidRequest    = errors.New("invalid credential revocation management request")
	ErrUnsafeStoreResult = errors.New("unsafe credential revocation management store result")
)

type Authorizer interface {
	Authorize(authn.Principal, authz.Request) error
}

type ListRequest struct {
	WorkspaceID   string
	EnvironmentID string
	Status        credential.RevocationStatus
	Limit         int
	After         *credential.ManagementCursor
}

type ItemRequest struct {
	WorkspaceID   string
	EnvironmentID string
	RevocationID  string
}

type ConfirmationRequest struct {
	WorkspaceID   string
	EnvironmentID string
	RevocationID  string
	EvidenceHash  string
}

type Service struct {
	store      credential.ManagementStore
	authorizer Authorizer
}

func New(store credential.ManagementStore, authorizer Authorizer) (*Service, error) {
	if nilInterface(store) || nilInterface(authorizer) {
		return nil, errors.New("credential management store and authorizer are required")
	}
	return &Service{store: store, authorizer: authorizer}, nil
}

func (service *Service) List(ctx context.Context, principal authn.Principal, request ListRequest) (credential.ManagementPage, error) {
	if request.Status == "" {
		request.Status = credential.StatusManualRequired
	}
	if request.Limit == 0 {
		request.Limit = credential.DefaultManagementPageSize
	}
	scope := credential.ManagementScope{WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID}
	actor, err := service.authorize(principal, scope, authz.PermissionCredentialRevocationRead)
	if err != nil {
		return credential.ManagementPage{}, err
	}
	if !credential.ValidRevocationStatus(request.Status) || request.Limit < 1 || request.Limit > credential.MaxManagementPageSize ||
		!credential.ValidManagementCursor(request.After) {
		return credential.ManagementPage{}, ErrInvalidRequest
	}
	storeRequest := credential.ManagementListRequest{
		Scope: scope, Actor: actor, Status: request.Status, Limit: request.Limit, After: request.After,
	}
	page, err := service.store.ListManagement(ctx, storeRequest)
	if err != nil {
		return credential.ManagementPage{}, err
	}
	if !validStorePage(page, storeRequest) {
		return credential.ManagementPage{}, unsafeStoreResult("list")
	}
	return page, nil
}

func (service *Service) Get(ctx context.Context, principal authn.Principal, request ItemRequest) (credential.ManagementRecord, error) {
	scope, actor, err := service.authorizeItem(principal, request, authz.PermissionCredentialRevocationRead)
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	record, err := service.store.GetManagement(ctx, credential.ManagementGetRequest{
		Scope: scope, Actor: actor, RevocationID: request.RevocationID,
	})
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validStoreRecord(record, scope, request.RevocationID) {
		return credential.ManagementRecord{}, unsafeStoreResult("get")
	}
	return record, nil
}

func (service *Service) Requeue(ctx context.Context, principal authn.Principal, request ItemRequest) (credential.ManagementRecord, error) {
	scope, actor, err := service.authorizeItem(principal, request, authz.PermissionCredentialRevocationRequeue)
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	record, err := service.store.RequeueManagement(ctx, credential.ManagementRequeueRequest{
		Scope: scope, Actor: actor, RevocationID: request.RevocationID,
	})
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validStoreRecord(record, scope, request.RevocationID) || record.Status != credential.StatusRevocationPending ||
		record.EvidenceHash != "" || record.ConfirmationCount != 0 || record.PlatformAdminConfirmed {
		return credential.ManagementRecord{}, unsafeStoreResult("requeue")
	}
	return record, nil
}

func (service *Service) Confirm(ctx context.Context, principal authn.Principal, request ConfirmationRequest) (credential.ManagementRecord, error) {
	item := ItemRequest{
		WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID, RevocationID: request.RevocationID,
	}
	scope, actor, err := service.authorizeItem(principal, item, authz.PermissionCredentialRevocationConfirm)
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	if !credential.ValidSHA256(request.EvidenceHash) {
		return credential.ManagementRecord{}, ErrInvalidRequest
	}
	record, err := service.store.ConfirmManagement(ctx, credential.ManagementConfirmationRequest{
		Scope: scope, Actor: actor, RevocationID: request.RevocationID, EvidenceHash: request.EvidenceHash,
	})
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validStoreRecord(record, scope, request.RevocationID) || record.EvidenceHash != request.EvidenceHash ||
		(record.Status != credential.StatusManualRequired && record.Status != credential.StatusRevoked) {
		return credential.ManagementRecord{}, unsafeStoreResult("confirmation")
	}
	return record, nil
}

func (service *Service) authorize(principal authn.Principal, scope credential.ManagementScope, permission authz.Permission) (credential.ManagementActor, error) {
	if !credential.ValidManagementScope(scope) {
		return credential.ManagementActor{}, ErrInvalidRequest
	}
	authorization := authz.Request{
		Permission: permission, WorkspaceID: scope.WorkspaceID, EnvironmentID: scope.EnvironmentID,
	}
	authorizationErr := service.authorizer.Authorize(principal, authorization)
	if !slices.Contains(principal.WorkspaceIDs, scope.WorkspaceID) ||
		!slices.Contains(principal.EnvironmentIDs, scope.EnvironmentID) {
		return credential.ManagementActor{}, credential.ErrRevocationNotFound
	}
	if authorizationErr != nil {
		return credential.ManagementActor{}, authorizationErr
	}
	actor := credential.ManagementActor{
		Subject: "oidc:" + principal.Subject, PlatformAdmin: authz.IsPlatformAdmin(principal),
	}
	if !credential.ValidManagementActor(actor) {
		return credential.ManagementActor{}, ErrInvalidRequest
	}
	return actor, nil
}

func (service *Service) authorizeItem(principal authn.Principal, request ItemRequest, permission authz.Permission) (credential.ManagementScope, credential.ManagementActor, error) {
	scope := credential.ManagementScope{WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID}
	actor, err := service.authorize(principal, scope, permission)
	if err != nil {
		return credential.ManagementScope{}, credential.ManagementActor{}, err
	}
	if !credential.ValidRevocationID(request.RevocationID) {
		return credential.ManagementScope{}, credential.ManagementActor{}, ErrInvalidRequest
	}
	return scope, actor, nil
}

func validStoreRecord(record credential.ManagementRecord, scope credential.ManagementScope, revocationID string) bool {
	return credential.ValidManagementRecord(record) && record.WorkspaceID == scope.WorkspaceID &&
		record.EnvironmentID == scope.EnvironmentID && (revocationID == "" || record.ID == revocationID)
}

func validStorePage(page credential.ManagementPage, request credential.ManagementListRequest) bool {
	if len(page.Items) > request.Limit || !credential.ValidManagementCursor(page.Next) ||
		(page.Next != nil && len(page.Items) != request.Limit) {
		return false
	}
	for index, record := range page.Items {
		if !validStoreRecord(record, request.Scope, "") || record.Status != request.Status ||
			record.CreatedAt.Location() != time.UTC || record.CreatedAt != credential.CanonicalCredentialExpiry(record.CreatedAt) {
			return false
		}
		if request.After != nil && !managementKeyAfterCursor(record.CreatedAt, record.ID, *request.After) {
			return false
		}
		if index > 0 {
			previous := page.Items[index-1]
			if !managementKeyAfterCursor(record.CreatedAt, record.ID, credential.ManagementCursor{
				CreatedAt: previous.CreatedAt, RevocationID: previous.ID,
			}) {
				return false
			}
		}
	}
	if page.Next != nil {
		last := page.Items[len(page.Items)-1]
		if !page.Next.CreatedAt.Equal(last.CreatedAt) || page.Next.RevocationID != last.ID {
			return false
		}
	}
	return true
}

func managementKeyAfterCursor(createdAt time.Time, revocationID string, cursor credential.ManagementCursor) bool {
	return createdAt.Before(cursor.CreatedAt) || (createdAt.Equal(cursor.CreatedAt) && revocationID < cursor.RevocationID)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

func unsafeStoreResult(operation string) error {
	return fmt.Errorf("%w: %s", ErrUnsafeStoreResult, operation)
}
