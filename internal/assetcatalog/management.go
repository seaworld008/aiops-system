package assetcatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"

	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
)

type EffectiveAction string

const (
	ActionCreateAsset            EffectiveAction = "CREATE_ASSET"
	ActionEditGovernance         EffectiveAction = "EDIT_GOVERNANCE"
	ActionQuarantine             EffectiveAction = "QUARANTINE"
	ActionRetire                 EffectiveAction = "RETIRE"
	ActionCreateBinding          EffectiveAction = "CREATE_BINDING"
	ActionDeleteBinding          EffectiveAction = "DELETE_BINDING"
	ActionResolveConflict        EffectiveAction = "RESOLVE_CONFLICT"
	ActionCreateSource           EffectiveAction = "CREATE_SOURCE"
	ActionCreateSourceRevision   EffectiveAction = "CREATE_SOURCE_REVISION"
	ActionValidateSourceRevision EffectiveAction = "VALIDATE_SOURCE_REVISION"
	ActionPublishSourceRevision  EffectiveAction = "PUBLISH_SOURCE_REVISION"
	ActionDisableSource          EffectiveAction = "DISABLE_SOURCE"
	ActionSyncSource             EffectiveAction = "SYNC_SOURCE"
	ActionImportCSV              EffectiveAction = "IMPORT_CSV"
)

type AssetSummaryView struct {
	ReadModel        AssetReadModel
	EffectiveActions []EffectiveAction
}

type AssetView struct {
	ReadModel        AssetDetailReadModel
	EffectiveActions []EffectiveAction
}

type AssetViewPage struct {
	Items            []AssetSummaryView
	Next             *AssetCursor
	EffectiveActions []EffectiveAction
}

type AssetMutationView struct {
	View    AssetView
	Receipt MutationReceipt
}

type AssetCollectionRequest struct {
	WorkspaceID, EnvironmentID string
}

type AssetPathRequest struct {
	WorkspaceID, EnvironmentID, AssetID string
}

type AssetListInput struct {
	Filter AssetFilter
	Sort   AssetSort
	Limit  int
	Cursor *AssetCursor
}

type ServerRequestMetadata struct {
	TraceID, IdempotencyKey string
	ExpectedVersion         int64
	ExpectedRevisionVersion int64
}

type CreateAssetInput struct {
	SourceID                string
	Kind                    Kind
	ExternalID, DisplayName string
	OwnerGroup              *string
	Criticality             Criticality
	DataClassification      DataClassification
	Labels                  map[string]string
}

type UpdateGovernanceInput struct {
	DisplayName        string
	OwnerGroup         *string
	Criticality        Criticality
	DataClassification DataClassification
	Labels             map[string]string
}

type TransitionInput struct{ ReasonCode string }

type AssetManager interface {
	ListAssets(context.Context, authn.Principal, AssetCollectionRequest, AssetListInput) (AssetViewPage, error)
	GetAsset(context.Context, authn.Principal, AssetPathRequest) (AssetView, error)
	CreateAsset(context.Context, authn.Principal, AssetCollectionRequest, CreateAssetInput, ServerRequestMetadata) (AssetMutationView, error)
	UpdateAsset(context.Context, authn.Principal, AssetPathRequest, UpdateGovernanceInput, ServerRequestMetadata) (AssetMutationView, error)
	QuarantineAsset(context.Context, authn.Principal, AssetPathRequest, TransitionInput, ServerRequestMetadata) (AssetMutationView, error)
	RetireAsset(context.Context, authn.Principal, AssetPathRequest, TransitionInput, ServerRequestMetadata) (AssetMutationView, error)
}

type SourceCollectionRequest struct{ WorkspaceID string }
type SourcePathRequest struct{ WorkspaceID, SourceID string }
type SourceRunPathRequest struct{ WorkspaceID, RunID string }
type SourceRevisionPathRequest struct {
	WorkspaceID, SourceID string
	Revision              int64
}

type SourceListInput struct {
	Kinds         []SourceKind
	Statuses      []SourceStatus
	GateStatuses  []SourceGateStatus
	Usage         SourceUsage
	EnvironmentID string
	Limit         int
	Cursor        *SourceCursor
}

type SourceView struct {
	ReadModel        SourceReadModel
	EffectiveActions []EffectiveAction
}

type SourceViewPage struct {
	Items            []SourceView
	Next             *SourceCursor
	EffectiveActions []EffectiveAction
}

type SourceRunView struct {
	Run              SourceRun
	EffectiveActions []EffectiveAction
}

type CreateSourceInput struct {
	Name                    string
	SourceProfileID         SourceProfileID
	AuthorityEnvironmentIDs []string
}

type CreateSourceRevisionInput struct {
	SourceProfileID         SourceProfileID
	AuthorityEnvironmentIDs []string
	ChangeReasonCode        string
}

type SourceReasonInput struct{ ReasonCode string }

type SourceActionAdmission struct {
	CanValidate bool
	CanPublish  bool
	CanSync     bool
	CanImport   bool
}

type SourceRevisionMutationView struct {
	Source           Source
	Revision         SourceRevision
	Receipt          MutationReceipt
	EffectiveActions []EffectiveAction
}

type SourceMutationView struct {
	Source           Source
	Receipt          MutationReceipt
	EffectiveActions []EffectiveAction
}

type SourceRunMutationView struct {
	Source           Source
	Revision         SourceRevision
	Run              SourceRun
	Receipt          MutationReceipt
	EffectiveActions []EffectiveAction
}

type SourceManager interface {
	ListSources(context.Context, authn.Principal, SourceCollectionRequest, SourceListInput) (SourceViewPage, error)
	GetSource(context.Context, authn.Principal, SourcePathRequest) (SourceView, error)
	GetSourceRun(context.Context, authn.Principal, SourceRunPathRequest) (SourceRunView, error)
	CreateSource(context.Context, authn.Principal, SourceCollectionRequest, CreateSourceInput, ServerRequestMetadata) (SourceRevisionMutationView, error)
	CreateSourceRevision(context.Context, authn.Principal, SourcePathRequest, CreateSourceRevisionInput, ServerRequestMetadata) (SourceRevisionMutationView, error)
	ValidateSourceRevision(context.Context, authn.Principal, SourceRevisionPathRequest, ServerRequestMetadata) (SourceRunMutationView, error)
	PublishSourceRevision(context.Context, authn.Principal, SourceRevisionPathRequest, SourceReasonInput, ServerRequestMetadata) (SourceRevisionMutationView, error)
	DisableSource(context.Context, authn.Principal, SourcePathRequest, SourceReasonInput, ServerRequestMetadata) (SourceMutationView, error)
	SyncSource(context.Context, authn.Principal, SourcePathRequest, ServerRequestMetadata) (SourceRunMutationView, error)
}

type SourceManagementRepository interface {
	SourceReadRepository
	SourceRevisionRepository
}

type RelationshipListInput struct {
	AssetID, SourceID string
	Types             []RelationshipType
	Statuses          []RelationshipStatus
	Limit             int
	Cursor            *RelationshipCursor
}

type RelationshipViewPage struct {
	Items []Relationship
	Next  *RelationshipCursor
}

type RelationshipManager interface {
	ListRelationships(context.Context, authn.Principal, AssetCollectionRequest, RelationshipListInput) (RelationshipViewPage, error)
}

type ConflictCollectionRequest struct {
	WorkspaceID, EnvironmentID string
}

type ConflictPathRequest struct{ WorkspaceID, ConflictID string }

type ConflictListInput struct {
	AssetID, SourceID string
	Statuses          []ConflictStatus
	Limit             int
	Cursor            *ConflictCursor
}

type ResolveConflictInput struct {
	ServiceID   string
	Resolution  ConflictResolution
	BindingRole BindingRole
	ReasonCode  string
}

type ConflictView struct {
	ReadModel        ConflictReadModel
	EffectiveActions []EffectiveAction
}

type ConflictViewPage struct {
	Items []ConflictView
	Next  *ConflictCursor
}

type ConflictMutationView struct {
	View    ConflictView
	Binding *ServiceAssetBinding
	Receipt MutationReceipt
}

type ConflictManager interface {
	ListConflicts(context.Context, authn.Principal, ConflictCollectionRequest, ConflictListInput) (ConflictViewPage, error)
	ResolveConflict(context.Context, authn.Principal, ConflictPathRequest, ResolveConflictInput, ServerRequestMetadata) (ConflictMutationView, error)
}

type BindingPathRequest struct {
	WorkspaceID, EnvironmentID, BindingID string
}

type BindingListInput struct {
	ServiceID, AssetID string
	Roles              []BindingRole
	Statuses           []BindingStatus
	Limit              int
	Cursor             *BindingCursor
}

type CreateBindingInput struct {
	ServiceID, AssetID string
	Role               BindingRole
	ReasonCode         string
}

type DeleteBindingInput struct{ ReasonCode string }

type BindingView struct {
	Binding          ServiceAssetBinding
	EffectiveActions []EffectiveAction
}

type BindingViewPage struct {
	Items []BindingView
	Next  *BindingCursor
}

type BindingMutationView struct {
	View    BindingView
	Receipt MutationReceipt
}

type BindingManager interface {
	ListBindings(context.Context, authn.Principal, AssetCollectionRequest, BindingListInput) (BindingViewPage, error)
	CreateBinding(context.Context, authn.Principal, AssetCollectionRequest, CreateBindingInput, ServerRequestMetadata) (BindingMutationView, error)
	DeleteBinding(context.Context, authn.Principal, BindingPathRequest, DeleteBindingInput, ServerRequestMetadata) (MutationReceipt, error)
}

type Management struct {
	assets     Repository
	mappings   MappingRepository
	sources    SourceManagementRepository
	profiles   SourceProfileAdmissionResolver
	authorizer *authz.Authorizer
}

func NewManagement(
	assets Repository,
	mappings MappingRepository,
	sources SourceManagementRepository,
	authorizer *authz.Authorizer,
) (*Management, error) {
	if nilManagementDependency(assets) || nilManagementDependency(mappings) ||
		nilManagementDependency(sources) || authorizer == nil {
		return nil, errors.New("asset catalog management dependencies are required")
	}
	profiles := SourceProfileAdmissionResolver(NewBuiltinSourceProfileAdmissionResolver())
	if installed, ok := any(sources).(SourceProfileAdmissionResolver); ok &&
		!nilManagementDependency(installed) {
		profiles = installed
	}
	return &Management{
		assets: assets, mappings: mappings, sources: sources,
		profiles: profiles, authorizer: authorizer,
	}, nil
}

func (management *Management) ListAssets(
	ctx context.Context,
	principal authn.Principal,
	route AssetCollectionRequest,
	input AssetListInput,
) (AssetViewPage, error) {
	if !validAssetCollectionRoute(route) {
		return AssetViewPage{}, ErrInvalidRequest
	}
	access, err := assetAccessForPrincipal(principal)
	if err != nil {
		return AssetViewPage{}, authz.ErrForbidden
	}
	if !validAssetListInputShape(route, input, access) {
		return AssetViewPage{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, route)
	if err != nil {
		return AssetViewPage{}, err
	}
	request := ListAssetsRequest{
		Scope: scope, Access: access, Filter: input.Filter.Clone(), Sort: input.Sort,
		Limit: input.Limit, Cursor: clonePointer(input.Cursor),
	}
	if _, err := request.QueryDigest(); err != nil {
		return AssetViewPage{}, ErrInvalidRequest
	}
	if err := management.authorize(principal, authz.PermissionAssetRead, scope, ""); err != nil {
		return AssetViewPage{}, err
	}
	page, err := management.assets.List(ctx, request)
	if err != nil {
		return AssetViewPage{}, err
	}
	result := AssetViewPage{
		Items:            make([]AssetSummaryView, len(page.Items)),
		Next:             clonePointer(page.Next),
		EffectiveActions: []EffectiveAction{},
	}
	for index := range page.Items {
		result.Items[index] = AssetSummaryView{
			ReadModel:        page.Items[index].Clone(),
			EffectiveActions: management.assetActions(principal, scope, page.Items[index].Lifecycle),
		}
	}
	if page.ManualCreateEligible &&
		management.authorize(principal, authz.PermissionAssetManage, scope, "") == nil {
		result.EffectiveActions = []EffectiveAction{ActionCreateAsset}
	}
	return result, nil
}

func (management *Management) GetAsset(
	ctx context.Context,
	principal authn.Principal,
	route AssetPathRequest,
) (AssetView, error) {
	if !validAssetPathRoute(route) {
		return AssetView{}, ErrInvalidRequest
	}
	access, err := assetAccessForPrincipal(principal)
	if err != nil {
		return AssetView{}, authz.ErrForbidden
	}
	scope, err := management.resolveAssetScope(ctx, principal, AssetCollectionRequest{
		WorkspaceID: route.WorkspaceID, EnvironmentID: route.EnvironmentID,
	})
	if err != nil {
		return AssetView{}, err
	}
	if err := management.authorize(principal, authz.PermissionAssetRead, scope, ""); err != nil {
		return AssetView{}, err
	}
	model, err := management.assets.GetReadModel(ctx, AssetLocator{Scope: scope, AssetID: route.AssetID}, access)
	if err != nil {
		return AssetView{}, err
	}
	return AssetView{
		ReadModel:        model.Clone(),
		EffectiveActions: management.assetActions(principal, scope, model.Lifecycle),
	}, nil
}

func (management *Management) CreateAsset(
	ctx context.Context,
	principal authn.Principal,
	route AssetCollectionRequest,
	input CreateAssetInput,
	metadata ServerRequestMetadata,
) (AssetMutationView, error) {
	input = cloneCreateAssetInput(input)
	if !validAssetCollectionRoute(route) || !validCreateAssetInput(input) ||
		!validCreateMetadata(metadata) {
		return AssetMutationView{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, route)
	if err != nil {
		return AssetMutationView{}, err
	}
	if err := management.authorize(principal, authz.PermissionAssetManage, scope, ""); err != nil {
		return AssetMutationView{}, err
	}
	requestHash, err := createAssetRequestHash(scope, input)
	if err != nil {
		return AssetMutationView{}, err
	}
	mutationContext, err := NewMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	result, err := management.assets.Create(ctx, CreateAssetCommand{
		Context: mutationContext, SourceID: input.SourceID, Kind: input.Kind,
		ExternalID: input.ExternalID, DisplayName: input.DisplayName, OwnerGroup: input.OwnerGroup,
		Criticality: input.Criticality, DataClassification: input.DataClassification, Labels: input.Labels,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	return management.assetMutationView(principal, scope, result), nil
}

func (management *Management) UpdateAsset(
	ctx context.Context,
	principal authn.Principal,
	route AssetPathRequest,
	input UpdateGovernanceInput,
	metadata ServerRequestMetadata,
) (AssetMutationView, error) {
	input = cloneUpdateGovernanceInput(input)
	if !validAssetPathRoute(route) || !validUpdateGovernanceInput(input) ||
		!validVersionedMetadata(metadata) {
		return AssetMutationView{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, AssetCollectionRequest{
		WorkspaceID: route.WorkspaceID, EnvironmentID: route.EnvironmentID,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	if err := management.authorize(principal, authz.PermissionAssetManage, scope, ""); err != nil {
		return AssetMutationView{}, err
	}
	requestHash, err := updateAssetRequestHash(scope, route.AssetID, input, metadata.ExpectedVersion)
	if err != nil {
		return AssetMutationView{}, err
	}
	mutationContext, err := NewMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	result, err := management.assets.UpdateGovernance(ctx, UpdateGovernanceCommand{
		Context: mutationContext, AssetID: route.AssetID, DisplayName: input.DisplayName,
		OwnerGroup: input.OwnerGroup, Criticality: input.Criticality,
		DataClassification: input.DataClassification, Labels: input.Labels,
		ExpectedVersion: metadata.ExpectedVersion,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	return management.assetMutationView(principal, scope, result), nil
}

func (management *Management) QuarantineAsset(
	ctx context.Context,
	principal authn.Principal,
	route AssetPathRequest,
	input TransitionInput,
	metadata ServerRequestMetadata,
) (AssetMutationView, error) {
	return management.transitionAsset(
		ctx, principal, route, input, metadata, LifecycleQuarantined, "asset.quarantined.v1",
	)
}

func (management *Management) RetireAsset(
	ctx context.Context,
	principal authn.Principal,
	route AssetPathRequest,
	input TransitionInput,
	metadata ServerRequestMetadata,
) (AssetMutationView, error) {
	return management.transitionAsset(
		ctx, principal, route, input, metadata, LifecycleRetired, "asset.retired.v1",
	)
}

func (management *Management) transitionAsset(
	ctx context.Context,
	principal authn.Principal,
	route AssetPathRequest,
	input TransitionInput,
	metadata ServerRequestMetadata,
	to Lifecycle,
	operation string,
) (AssetMutationView, error) {
	if !validAssetPathRoute(route) || !validReasonCode(input.ReasonCode) ||
		!validVersionedMetadata(metadata) {
		return AssetMutationView{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, AssetCollectionRequest{
		WorkspaceID: route.WorkspaceID, EnvironmentID: route.EnvironmentID,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	if err := management.authorize(principal, authz.PermissionAssetManage, scope, ""); err != nil {
		return AssetMutationView{}, err
	}
	requestHash, err := transitionAssetRequestHash(
		operation, scope, route.AssetID, to, input.ReasonCode, metadata.ExpectedVersion,
	)
	if err != nil {
		return AssetMutationView{}, err
	}
	mutationContext, err := NewMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	result, err := management.assets.Transition(ctx, TransitionCommand{
		Context: mutationContext, AssetID: route.AssetID, To: to,
		ReasonCode: input.ReasonCode, ExpectedVersion: metadata.ExpectedVersion,
	})
	if err != nil {
		return AssetMutationView{}, err
	}
	return management.assetMutationView(principal, scope, result), nil
}

func (management *Management) ListRelationships(
	ctx context.Context,
	principal authn.Principal,
	route AssetCollectionRequest,
	input RelationshipListInput,
) (RelationshipViewPage, error) {
	if !validAssetCollectionRoute(route) {
		return RelationshipViewPage{}, ErrInvalidRequest
	}
	access, err := assetAccessForPrincipal(principal)
	if err != nil {
		return RelationshipViewPage{}, authz.ErrForbidden
	}
	if !validRelationshipListInputShape(route, input, access) {
		return RelationshipViewPage{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, route)
	if err != nil {
		return RelationshipViewPage{}, err
	}
	request := ListRelationshipsRequest{
		Scope: scope, Access: access, AssetID: input.AssetID, SourceID: input.SourceID,
		Types: slices.Clone(input.Types), Statuses: slices.Clone(input.Statuses),
		Limit: input.Limit, Cursor: clonePointer(input.Cursor),
	}
	if _, err := request.QueryDigest(); err != nil {
		return RelationshipViewPage{}, ErrInvalidRequest
	}
	if err := management.authorize(principal, authz.PermissionAssetRead, scope, ""); err != nil {
		return RelationshipViewPage{}, err
	}
	page, err := management.mappings.ListRelationships(ctx, request)
	if err != nil {
		return RelationshipViewPage{}, err
	}
	return RelationshipViewPage{
		Items: cloneSlice(page.Items, func(value Relationship) Relationship { return value.Clone() }),
		Next:  clonePointer(page.Next),
	}, nil
}

func (management *Management) ListSources(
	ctx context.Context,
	principal authn.Principal,
	route SourceCollectionRequest,
	input SourceListInput,
) (SourceViewPage, error) {
	if !validSourceCollectionRoute(route) {
		return SourceViewPage{}, ErrInvalidRequest
	}
	access, err := NewSourceReadConstraint(principal.EnvironmentIDs)
	if err != nil {
		return SourceViewPage{}, authz.ErrForbidden
	}
	if !validSourceListInputShape(route, input, access) {
		return SourceViewPage{}, ErrInvalidRequest
	}
	scope, err := management.resolveSourceScope(ctx, principal, route.WorkspaceID)
	if err != nil {
		return SourceViewPage{}, err
	}
	request := ListSourcesRequest{
		Scope: scope, Access: access, Kinds: slices.Clone(input.Kinds),
		Statuses: slices.Clone(input.Statuses), GateStatuses: slices.Clone(input.GateStatuses),
		Usage: input.Usage, EnvironmentID: input.EnvironmentID, Limit: input.Limit,
		Cursor: clonePointer(input.Cursor),
	}
	if _, err := request.QueryDigest(); err != nil {
		return SourceViewPage{}, ErrInvalidRequest
	}
	authorizationEnvironment, err := sourceAuthorizationEnvironment(principal, input.EnvironmentID)
	if err != nil {
		return SourceViewPage{}, authz.ErrForbidden
	}
	environmentScope := Scope{
		TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID,
		EnvironmentID: authorizationEnvironment,
	}
	if err := management.authorize(principal, authz.PermissionAssetSourceRead, environmentScope, ""); err != nil {
		return SourceViewPage{}, err
	}
	page, err := management.sources.ListSources(ctx, request)
	if err != nil {
		return SourceViewPage{}, err
	}
	result := SourceViewPage{
		Items: make([]SourceView, len(page.Items)), Next: clonePointer(page.Next),
		EffectiveActions: []EffectiveAction{},
	}
	if management.authorize(principal, authz.PermissionAssetSourceManage, environmentScope, "") == nil {
		result.EffectiveActions = []EffectiveAction{ActionCreateSource}
	}
	for index := range page.Items {
		actions := management.sourceActions(ctx, principal, page.Items[index])
		if input.Usage == SourceUsageManualAssetCreate &&
			management.manualAssetCreateEligible(ctx, page.Items[index]) &&
			management.authorize(principal, authz.PermissionAssetManage, environmentScope, "") == nil {
			actions = append(actions, ActionCreateAsset)
			slices.Sort(actions)
			actions = slices.Compact(actions)
		}
		result.Items[index] = SourceView{
			ReadModel:        page.Items[index].Clone(),
			EffectiveActions: actions,
		}
	}
	return result, nil
}

func (management *Management) GetSource(
	ctx context.Context,
	principal authn.Principal,
	route SourcePathRequest,
) (SourceView, error) {
	if !validSourcePathRoute(route) {
		return SourceView{}, ErrInvalidRequest
	}
	access, err := NewSourceReadConstraint(principal.EnvironmentIDs)
	if err != nil {
		return SourceView{}, authz.ErrForbidden
	}
	scope, err := management.resolveSourceScope(ctx, principal, route.WorkspaceID)
	if err != nil {
		return SourceView{}, err
	}
	environmentID, err := sourceAuthorizationEnvironment(principal, "")
	if err != nil {
		return SourceView{}, authz.ErrForbidden
	}
	if err := management.authorize(principal, authz.PermissionAssetSourceRead, Scope{
		TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, EnvironmentID: environmentID,
	}, ""); err != nil {
		return SourceView{}, err
	}
	model, err := management.sources.GetSource(ctx, SourceLocator{Scope: scope, SourceID: route.SourceID}, access)
	if err != nil {
		return SourceView{}, err
	}
	return SourceView{ReadModel: model.Clone(), EffectiveActions: management.sourceActions(ctx, principal, model)}, nil
}

func (management *Management) GetSourceRun(
	ctx context.Context,
	principal authn.Principal,
	route SourceRunPathRequest,
) (SourceRunView, error) {
	if !validSourceRunPathRoute(route) {
		return SourceRunView{}, ErrInvalidRequest
	}
	access, err := NewSourceReadConstraint(principal.EnvironmentIDs)
	if err != nil {
		return SourceRunView{}, authz.ErrForbidden
	}
	scope, err := management.resolveSourceScope(ctx, principal, route.WorkspaceID)
	if err != nil {
		return SourceRunView{}, err
	}
	environmentID, err := sourceAuthorizationEnvironment(principal, "")
	if err != nil {
		return SourceRunView{}, authz.ErrForbidden
	}
	if err := management.authorize(principal, authz.PermissionAssetSourceRead, Scope{
		TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, EnvironmentID: environmentID,
	}, ""); err != nil {
		return SourceRunView{}, err
	}
	run, err := management.sources.GetSourceRun(ctx, SourceRunLocator{Scope: scope, RunID: route.RunID}, access)
	if err != nil {
		return SourceRunView{}, err
	}
	return SourceRunView{Run: run.Clone(), EffectiveActions: []EffectiveAction{}}, nil
}

func (management *Management) CreateSource(
	ctx context.Context,
	principal authn.Principal,
	route SourceCollectionRequest,
	input CreateSourceInput,
	metadata ServerRequestMetadata,
) (SourceRevisionMutationView, error) {
	input = cloneCreateSourceInput(input)
	if !validSourceCollectionRoute(route) || !validCreateSourceInput(input) ||
		!validCreateMetadata(metadata) {
		return SourceRevisionMutationView{}, ErrInvalidRequest
	}
	scope, err := management.resolveSourceScope(ctx, principal, route.WorkspaceID)
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	if err := management.authorizeSourceAuthorities(
		principal, scope, input.AuthorityEnvironmentIDs, authz.PermissionAssetSourceManage, false,
	); err != nil {
		return SourceRevisionMutationView{}, err
	}
	requestHash, err := createSourceRequestHash(scope, input)
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	mutationContext, err := NewSourceMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	result, err := management.sources.CreateSource(ctx, CreateSourceCommand{
		Context: mutationContext, Name: input.Name, SourceProfileID: input.SourceProfileID,
		AuthorityEnvironmentIDs: slices.Clone(input.AuthorityEnvironmentIDs),
	})
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	return management.sourceRevisionMutationView(ctx, principal, result), nil
}

func (management *Management) CreateSourceRevision(
	ctx context.Context,
	principal authn.Principal,
	route SourcePathRequest,
	input CreateSourceRevisionInput,
	metadata ServerRequestMetadata,
) (SourceRevisionMutationView, error) {
	input = cloneCreateSourceRevisionInput(input)
	if !validSourcePathRoute(route) || !validCreateSourceRevisionInput(input) ||
		!validSourceVersionMetadata(metadata) {
		return SourceRevisionMutationView{}, ErrInvalidRequest
	}
	scope, _, err := management.loadSourceForMutation(
		ctx, principal, SourcePathRequest{WorkspaceID: route.WorkspaceID, SourceID: route.SourceID},
		authz.PermissionAssetSourceManage, false,
	)
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	if err := management.authorizeSourceAuthorities(
		principal, scope, input.AuthorityEnvironmentIDs, authz.PermissionAssetSourceManage, false,
	); err != nil {
		return SourceRevisionMutationView{}, err
	}
	requestHash, err := createSourceRevisionRequestHash(scope, route.SourceID, input, metadata.ExpectedVersion)
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	mutationContext, err := NewSourceMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	result, err := management.sources.CreateRevision(ctx, CreateSourceRevisionCommand{
		Context: mutationContext, SourceID: route.SourceID, SourceProfileID: input.SourceProfileID,
		AuthorityEnvironmentIDs: slices.Clone(input.AuthorityEnvironmentIDs),
		ChangeReasonCode:        input.ChangeReasonCode, ExpectedSourceVersion: metadata.ExpectedVersion,
	})
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	return management.sourceRevisionMutationView(ctx, principal, result), nil
}

func (management *Management) ValidateSourceRevision(
	ctx context.Context,
	principal authn.Principal,
	route SourceRevisionPathRequest,
	metadata ServerRequestMetadata,
) (SourceRunMutationView, error) {
	if !validSourceRevisionPathRoute(route) || !validSourceRevisionVersionMetadata(metadata) {
		return SourceRunMutationView{}, ErrInvalidRequest
	}
	scope, model, err := management.loadSourceForMutation(
		ctx, principal, SourcePathRequest{WorkspaceID: route.WorkspaceID, SourceID: route.SourceID},
		authz.PermissionAssetSourceValidate, false,
	)
	if err != nil {
		return SourceRunMutationView{}, err
	}
	if model.LatestRevision.Revision != route.Revision {
		return SourceRunMutationView{}, ErrVersionConflict
	}
	command := ValidateSourceRevisionCommand{
		SourceID: route.SourceID, Revision: route.Revision,
		ExpectedSourceVersion: metadata.ExpectedVersion, ExpectedRevisionVersion: metadata.ExpectedRevisionVersion,
		ExpectedRevisionDigest: model.LatestRevision.CanonicalRevisionDigest,
	}
	requestHash, err := validateSourceRevisionRequestHash(scope, command)
	if err != nil {
		return SourceRunMutationView{}, err
	}
	command.Context, err = NewSourceMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return SourceRunMutationView{}, err
	}
	result, err := management.sources.RequestValidation(ctx, command)
	if err != nil {
		return SourceRunMutationView{}, err
	}
	return management.sourceRunMutationView(ctx, principal, result), nil
}

func (management *Management) PublishSourceRevision(
	ctx context.Context,
	principal authn.Principal,
	route SourceRevisionPathRequest,
	input SourceReasonInput,
	metadata ServerRequestMetadata,
) (SourceRevisionMutationView, error) {
	if !validSourceRevisionPathRoute(route) || !validReasonCode(input.ReasonCode) ||
		!validSourceRevisionVersionMetadata(metadata) {
		return SourceRevisionMutationView{}, ErrInvalidRequest
	}
	scope, model, err := management.loadSourceForMutation(
		ctx, principal, SourcePathRequest{WorkspaceID: route.WorkspaceID, SourceID: route.SourceID},
		authz.PermissionAssetSourcePublish, true,
	)
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	if model.LatestRevision.Revision != route.Revision {
		return SourceRevisionMutationView{}, ErrVersionConflict
	}
	command := PublishSourceRevisionCommand{
		SourceID: route.SourceID, Revision: route.Revision, ReasonCode: input.ReasonCode,
		ExpectedSourceVersion: metadata.ExpectedVersion, ExpectedRevisionVersion: metadata.ExpectedRevisionVersion,
		ExpectedRevisionDigest:   model.LatestRevision.CanonicalRevisionDigest,
		ExpectedValidationRunID:  model.LatestRevision.ValidationRunID,
		ExpectedValidationDigest: model.LatestRevision.ValidationDigest,
	}
	requestHash, err := publishSourceRevisionRequestHash(scope, command)
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	command.Context, err = NewSourceMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	result, err := management.sources.Publish(ctx, command)
	if err != nil {
		return SourceRevisionMutationView{}, err
	}
	return management.sourceRevisionMutationView(ctx, principal, result), nil
}

func (management *Management) DisableSource(
	ctx context.Context,
	principal authn.Principal,
	route SourcePathRequest,
	input SourceReasonInput,
	metadata ServerRequestMetadata,
) (SourceMutationView, error) {
	if !validSourcePathRoute(route) || !validReasonCode(input.ReasonCode) ||
		!validSourceVersionMetadata(metadata) {
		return SourceMutationView{}, ErrInvalidRequest
	}
	scope, _, err := management.loadSourceForMutation(
		ctx, principal, route, authz.PermissionAssetSourceManage, true,
	)
	if err != nil {
		return SourceMutationView{}, err
	}
	requestHash, err := disableSourceRequestHash(scope, route.SourceID, input.ReasonCode, metadata.ExpectedVersion)
	if err != nil {
		return SourceMutationView{}, err
	}
	mutationContext, err := NewSourceMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return SourceMutationView{}, err
	}
	result, err := management.sources.Disable(ctx, DisableSourceCommand{
		Context: mutationContext, SourceID: route.SourceID, ReasonCode: input.ReasonCode,
		ExpectedSourceVersion: metadata.ExpectedVersion,
	})
	if err != nil {
		return SourceMutationView{}, err
	}
	model := SourceReadModel{Source: result.Source.Clone()}
	return SourceMutationView{
		Source: result.Source.Clone(), Receipt: result.Receipt,
		EffectiveActions: management.sourceActions(ctx, principal, model),
	}, nil
}

func (management *Management) SyncSource(
	ctx context.Context,
	principal authn.Principal,
	route SourcePathRequest,
	metadata ServerRequestMetadata,
) (SourceRunMutationView, error) {
	if !validSourcePathRoute(route) || !validSourceVersionMetadata(metadata) {
		return SourceRunMutationView{}, ErrInvalidRequest
	}
	scope, model, err := management.loadSourceForMutation(
		ctx, principal, route, authz.PermissionAssetSourceSync, false,
	)
	if err != nil {
		return SourceRunMutationView{}, err
	}
	command := RequestSyncCommand{
		SourceID: route.SourceID, ExpectedSourceVersion: metadata.ExpectedVersion,
		ExpectedRevision:          model.Source.PublishedRevision,
		ExpectedRevisionDigest:    model.Source.PublishedRevisionDigest,
		ExpectedCheckpointVersion: model.Source.CheckpointVersion,
		ExpectedCheckpointSHA256:  model.Source.CheckpointSHA256,
	}
	requestHash, err := syncSourceRequestHash(scope, command)
	if err != nil {
		return SourceRunMutationView{}, err
	}
	command.Context, err = NewSourceMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return SourceRunMutationView{}, err
	}
	result, err := management.sources.RequestSync(ctx, command)
	if err != nil {
		return SourceRunMutationView{}, err
	}
	return management.sourceRunMutationView(ctx, principal, result), nil
}

func (management *Management) ListConflicts(
	ctx context.Context,
	principal authn.Principal,
	route ConflictCollectionRequest,
	input ConflictListInput,
) (ConflictViewPage, error) {
	assetRoute := AssetCollectionRequest{
		WorkspaceID: route.WorkspaceID, EnvironmentID: route.EnvironmentID,
	}
	if !validAssetCollectionRoute(assetRoute) {
		return ConflictViewPage{}, ErrInvalidRequest
	}
	access, err := assetAccessForPrincipal(principal)
	if err != nil {
		return ConflictViewPage{}, authz.ErrForbidden
	}
	if !validConflictListInputShape(route, input, access) {
		return ConflictViewPage{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, assetRoute)
	if err != nil {
		return ConflictViewPage{}, err
	}
	request := ListConflictsRequest{
		Scope: scope, Access: access, AssetID: input.AssetID, SourceID: input.SourceID,
		Statuses: slices.Clone(input.Statuses), Limit: input.Limit, Cursor: clonePointer(input.Cursor),
	}
	if _, err := request.QueryDigest(); err != nil {
		return ConflictViewPage{}, ErrInvalidRequest
	}
	if err := management.authorize(principal, authz.PermissionAssetRead, scope, ""); err != nil {
		return ConflictViewPage{}, err
	}
	page, err := management.mappings.ListConflicts(ctx, request)
	if err != nil {
		return ConflictViewPage{}, err
	}
	result := ConflictViewPage{Items: make([]ConflictView, len(page.Items)), Next: clonePointer(page.Next)}
	canResolve := management.authorize(
		principal, authz.PermissionAssetConflictResolve, scope, "",
	) == nil
	for index := range page.Items {
		actions := []EffectiveAction{}
		if canResolve && page.Items[index].Status == ConflictStatusOpen {
			actions = []EffectiveAction{ActionResolveConflict}
		}
		result.Items[index] = ConflictView{
			ReadModel: page.Items[index].Clone(), EffectiveActions: actions,
		}
	}
	return result, nil
}

func (management *Management) ResolveConflict(
	ctx context.Context,
	principal authn.Principal,
	route ConflictPathRequest,
	input ResolveConflictInput,
	metadata ServerRequestMetadata,
) (ConflictMutationView, error) {
	if !validConflictPathRoute(route) || !validResolveConflictInput(input) ||
		!validVersionedMetadata(metadata) {
		return ConflictMutationView{}, ErrInvalidRequest
	}
	scope, err := management.mappings.ResolveConflictScope(ctx, route.WorkspaceID, route.ConflictID)
	if err != nil {
		return ConflictMutationView{}, err
	}
	if err := resolvedEnvironmentScopeMatchesPrincipal(principal, scope, AssetCollectionRequest{
		WorkspaceID: route.WorkspaceID, EnvironmentID: scope.EnvironmentID,
	}); err != nil {
		return ConflictMutationView{}, err
	}
	if err := management.authorize(
		principal, authz.PermissionAssetConflictResolve, scope, "",
	); err != nil {
		return ConflictMutationView{}, err
	}
	requestHash, err := resolveConflictRequestHash(
		scope, route.ConflictID, input, metadata.ExpectedVersion,
	)
	if err != nil {
		return ConflictMutationView{}, err
	}
	mutationContext, err := NewMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return ConflictMutationView{}, err
	}
	result, err := management.mappings.ResolveConflict(ctx, MappingDecision{
		Context: mutationContext, ConflictID: route.ConflictID, ServiceID: input.ServiceID,
		Resolution: input.Resolution, BindingRole: input.BindingRole,
		ReasonCode: input.ReasonCode, ExpectedVersion: metadata.ExpectedVersion,
	})
	if err != nil {
		return ConflictMutationView{}, err
	}
	return ConflictMutationView{
		View: ConflictView{
			ReadModel: result.Conflict.Clone(), EffectiveActions: []EffectiveAction{},
		},
		Binding: clonePointer(result.Binding), Receipt: result.Receipt,
	}, nil
}

func (management *Management) ListBindings(
	ctx context.Context,
	principal authn.Principal,
	route AssetCollectionRequest,
	input BindingListInput,
) (BindingViewPage, error) {
	if !validAssetCollectionRoute(route) {
		return BindingViewPage{}, ErrInvalidRequest
	}
	access, err := assetAccessForPrincipal(principal)
	if err != nil {
		return BindingViewPage{}, authz.ErrForbidden
	}
	if !validBindingListInputShape(route, input, access) {
		return BindingViewPage{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, route)
	if err != nil {
		return BindingViewPage{}, err
	}
	request := ListBindingsRequest{
		Scope: scope, Access: access, ServiceID: input.ServiceID, AssetID: input.AssetID,
		Roles: slices.Clone(input.Roles), Statuses: slices.Clone(input.Statuses),
		Limit: input.Limit, Cursor: clonePointer(input.Cursor),
	}
	if _, err := request.QueryDigest(); err != nil {
		return BindingViewPage{}, ErrInvalidRequest
	}
	if err := management.authorize(principal, authz.PermissionAssetRead, scope, ""); err != nil {
		return BindingViewPage{}, err
	}
	page, err := management.mappings.ListBindings(ctx, request)
	if err != nil {
		return BindingViewPage{}, err
	}
	result := BindingViewPage{Items: make([]BindingView, len(page.Items)), Next: clonePointer(page.Next)}
	canDelete := management.authorize(principal, authz.PermissionAssetManage, scope, "") == nil
	for index := range page.Items {
		actions := []EffectiveAction{}
		if canDelete && page.Items[index].Status == BindingStatusActive {
			actions = []EffectiveAction{ActionDeleteBinding}
		}
		result.Items[index] = BindingView{
			Binding: page.Items[index], EffectiveActions: actions,
		}
	}
	return result, nil
}

func (management *Management) CreateBinding(
	ctx context.Context,
	principal authn.Principal,
	route AssetCollectionRequest,
	input CreateBindingInput,
	metadata ServerRequestMetadata,
) (BindingMutationView, error) {
	if !validAssetCollectionRoute(route) || !validCreateBindingInput(input) ||
		!validCreateMetadata(metadata) {
		return BindingMutationView{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, route)
	if err != nil {
		return BindingMutationView{}, err
	}
	if err := management.authorize(
		principal, authz.PermissionAssetBind, scope, input.ServiceID,
	); err != nil {
		return BindingMutationView{}, err
	}
	requestHash, err := createBindingRequestHash(scope, input)
	if err != nil {
		return BindingMutationView{}, err
	}
	mutationContext, err := NewMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return BindingMutationView{}, err
	}
	result, err := management.mappings.CreateBinding(ctx, CreateBindingCommand{
		Context: mutationContext, ServiceID: input.ServiceID, AssetID: input.AssetID,
		Role: input.Role, ReasonCode: input.ReasonCode,
	})
	if err != nil {
		return BindingMutationView{}, err
	}
	actions := []EffectiveAction{}
	if result.Binding.Status == BindingStatusActive &&
		management.authorize(principal, authz.PermissionAssetManage, scope, "") == nil {
		actions = []EffectiveAction{ActionDeleteBinding}
	}
	return BindingMutationView{
		View:    BindingView{Binding: result.Binding, EffectiveActions: actions},
		Receipt: result.Receipt,
	}, nil
}

func (management *Management) DeleteBinding(
	ctx context.Context,
	principal authn.Principal,
	route BindingPathRequest,
	input DeleteBindingInput,
	metadata ServerRequestMetadata,
) (MutationReceipt, error) {
	if !validBindingPathRoute(route) || !validReasonCode(input.ReasonCode) ||
		!validVersionedMetadata(metadata) {
		return MutationReceipt{}, ErrInvalidRequest
	}
	scope, err := management.resolveAssetScope(ctx, principal, AssetCollectionRequest{
		WorkspaceID: route.WorkspaceID, EnvironmentID: route.EnvironmentID,
	})
	if err != nil {
		return MutationReceipt{}, err
	}
	if err := management.authorize(principal, authz.PermissionAssetManage, scope, ""); err != nil {
		return MutationReceipt{}, err
	}
	requestHash, err := deleteBindingRequestHash(
		scope, route.BindingID, input.ReasonCode, metadata.ExpectedVersion,
	)
	if err != nil {
		return MutationReceipt{}, err
	}
	mutationContext, err := NewMutationContext(principal, scope, MutationMetadata{
		TraceID: metadata.TraceID, IdempotencyKey: metadata.IdempotencyKey, RequestHash: requestHash,
	})
	if err != nil {
		return MutationReceipt{}, err
	}
	return management.mappings.DeleteBinding(ctx, DeleteBindingCommand{
		Context: mutationContext, BindingID: route.BindingID,
		ReasonCode: input.ReasonCode, ExpectedVersion: metadata.ExpectedVersion,
	})
}

func (management *Management) resolveAssetScope(
	ctx context.Context,
	principal authn.Principal,
	route AssetCollectionRequest,
) (Scope, error) {
	scope, err := management.assets.ResolveScope(ctx, route.WorkspaceID, route.EnvironmentID)
	if err != nil {
		return Scope{}, err
	}
	if err := resolvedEnvironmentScopeMatchesPrincipal(principal, scope, route); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

func (management *Management) resolveSourceScope(
	ctx context.Context,
	principal authn.Principal,
	workspaceID string,
) (SourceScope, error) {
	scope, err := management.sources.ResolveSourceScope(ctx, workspaceID)
	if err != nil {
		return SourceScope{}, err
	}
	if !scope.Valid() {
		return SourceScope{}, ErrStateConflict
	}
	if scope.WorkspaceID != workspaceID {
		return SourceScope{}, ErrScopeViolation
	}
	if scope.TenantID != principal.TenantID {
		return SourceScope{}, authz.ErrForbidden
	}
	return scope, nil
}

func (management *Management) authorize(
	principal authn.Principal,
	permission authz.Permission,
	scope Scope,
	serviceID string,
) error {
	return management.authorizer.Authorize(principal, authz.Request{
		Permission: permission, WorkspaceID: scope.WorkspaceID,
		EnvironmentID: scope.EnvironmentID, ServiceID: serviceID,
	})
}

func (management *Management) authorizeSource(
	principal authn.Principal,
	permission authz.Permission,
	scope Scope,
	requireRecentAuthentication bool,
) error {
	return management.authorizer.Authorize(principal, authz.Request{
		Permission: permission, WorkspaceID: scope.WorkspaceID,
		EnvironmentID:               scope.EnvironmentID,
		RequireRecentAuthentication: requireRecentAuthentication,
	})
}

func (management *Management) authorizeSourceAuthorities(
	principal authn.Principal,
	scope SourceScope,
	authorityEnvironmentIDs []string,
	permission authz.Permission,
	requireRecentAuthentication bool,
) error {
	authorities := slices.Clone(authorityEnvironmentIDs)
	slices.Sort(authorities)
	if !scope.Valid() || !validUniqueUUIDs(authorities, false) {
		return ErrStateConflict
	}
	for _, environmentID := range authorities {
		if err := management.authorizeSource(principal, permission, Scope{
			TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, EnvironmentID: environmentID,
		}, requireRecentAuthentication); err != nil {
			return err
		}
	}
	return nil
}

func (management *Management) loadSourceForMutation(
	ctx context.Context,
	principal authn.Principal,
	route SourcePathRequest,
	permission authz.Permission,
	requireRecentAuthentication bool,
) (SourceScope, SourceReadModel, error) {
	access, err := NewSourceReadConstraint(principal.EnvironmentIDs)
	if err != nil {
		return SourceScope{}, SourceReadModel{}, authz.ErrForbidden
	}
	scope, err := management.resolveSourceScope(ctx, principal, route.WorkspaceID)
	if err != nil {
		return SourceScope{}, SourceReadModel{}, err
	}
	environmentID, err := sourceAuthorizationEnvironment(principal, "")
	if err != nil {
		return SourceScope{}, SourceReadModel{}, authz.ErrForbidden
	}
	if err := management.authorizeSource(principal, permission, Scope{
		TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, EnvironmentID: environmentID,
	}, requireRecentAuthentication); err != nil {
		return SourceScope{}, SourceReadModel{}, err
	}
	model, err := management.sources.GetSource(
		ctx, SourceLocator{Scope: scope, SourceID: route.SourceID}, access,
	)
	if err != nil {
		return SourceScope{}, SourceReadModel{}, err
	}
	if model.Source.ID != route.SourceID || model.Source.TenantID != scope.TenantID ||
		model.Source.WorkspaceID != scope.WorkspaceID {
		return SourceScope{}, SourceReadModel{}, ErrScopeViolation
	}
	if err := management.authorizeSourceAuthorities(
		principal, scope, model.LatestRevision.AuthorityEnvironmentIDs,
		permission, requireRecentAuthentication,
	); err != nil {
		return SourceScope{}, SourceReadModel{}, err
	}
	return scope, model.Clone(), nil
}

func (management *Management) sourceActions(
	ctx context.Context,
	principal authn.Principal,
	model SourceReadModel,
) []EffectiveAction {
	source := model.Source
	revision := model.LatestRevision
	if source.Status == SourceStatusDisabled || !source.Status.Valid() ||
		!source.Kind.Valid() || !revision.Status.Valid() {
		return []EffectiveAction{}
	}
	scope := SourceScope{TenantID: source.TenantID, WorkspaceID: source.WorkspaceID}
	actions := make([]EffectiveAction, 0, 6)
	if management.authorizeSourceAuthorities(
		principal, scope, revision.AuthorityEnvironmentIDs,
		authz.PermissionAssetSourceManage, false,
	) == nil {
		actions = append(actions, ActionCreateSourceRevision, ActionDisableSource)
	}
	admission := management.sourceActionAdmission(ctx, model)
	if admission.CanValidate && management.authorizeSourceAuthorities(
		principal, scope, revision.AuthorityEnvironmentIDs,
		authz.PermissionAssetSourceValidate, false,
	) == nil {
		actions = append(actions, ActionValidateSourceRevision)
	}
	if admission.CanPublish && management.authorizeSourceAuthorities(
		principal, scope, revision.AuthorityEnvironmentIDs,
		authz.PermissionAssetSourcePublish, false,
	) == nil {
		actions = append(actions, ActionPublishSourceRevision)
	}
	if admission.CanSync && management.authorizeSourceAuthorities(
		principal, scope, publishedSourceAuthorities(model),
		authz.PermissionAssetSourceSync, false,
	) == nil {
		actions = append(actions, ActionSyncSource)
	}
	if admission.CanImport && management.authorizeSourceAuthorities(
		principal, scope, publishedSourceAuthorities(model),
		authz.PermissionAssetSourceManage, false,
	) == nil {
		actions = append(actions, ActionImportCSV)
	}
	slices.Sort(actions)
	return slices.Compact(actions)
}

func (management *Management) sourceActionAdmission(
	ctx context.Context,
	model SourceReadModel,
) SourceActionAdmission {
	source := model.Source
	revision := model.LatestRevision
	if management.profiles == nil || source.Status == SourceStatusDisabled ||
		!source.Status.Valid() || !source.GateStatus.Valid() ||
		!source.Kind.Valid() || !revision.Status.Valid() {
		return SourceActionAdmission{}
	}
	latestProfile, err := management.profiles.ResolveProfileAdmission(ctx, revision.ProfileCode)
	if err != nil || !exactInstalledRevisionProfile(source, revision, latestProfile) {
		latestProfile = BuiltinSourceProfile{}
	}
	publishedProfile, published := management.installedPublishedProfile(ctx, model)
	admission := SourceActionAdmission{
		CanValidate: sourceValidationRuntimeAvailable(latestProfile.ProfileCode) &&
			source.Status == SourceStatusActive &&
			source.GateStatus != SourceGateDegraded &&
			source.GateStatus != SourceGateSuspended &&
			(revision.Status == SourceRevisionDraft || revision.Status == SourceRevisionRejected),
		CanPublish: latestProfile.ProfileCode != "" &&
			source.Status == SourceStatusActive &&
			source.GateStatus == SourceGateValidating &&
			source.GateReasonCode == "VALIDATION_IN_PROGRESS" &&
			revision.Status == SourceRevisionValidated &&
			revision.ValidationRunID != "" &&
			revision.ValidationDigest != "" &&
			source.ValidatedRunID == revision.ValidationRunID &&
			source.ValidationDigest == "" &&
			source.ValidatedBindingDigest == "",
	}
	if published && source.Status == SourceStatusActive &&
		source.GateStatus == SourceGateAvailable {
		admission.CanSync = publishedProfile.SourceKind != SourceKindManual &&
			publishedProfile.SourceKind != SourceKindCSVImport &&
			publishedProfile.SourceKind != SourceKindControlPlaneAPI
		admission.CanImport = publishedProfile.SourceKind == SourceKindCSVImport
	}
	return admission
}

func sourceValidationRuntimeAvailable(profileCode ProfileCode) bool {
	switch profileCode {
	case ProfileCode("MANUAL_V1"):
		return true
	default:
		return false
	}
}

func (management *Management) installedPublishedProfile(
	ctx context.Context,
	model SourceReadModel,
) (BuiltinSourceProfile, bool) {
	if management.profiles == nil || model.PublishedRevision == nil {
		return BuiltinSourceProfile{}, false
	}
	source := model.Source
	revision := *model.PublishedRevision
	if revision.SourceID != source.ID ||
		revision.TenantID != source.TenantID ||
		revision.WorkspaceID != source.WorkspaceID ||
		revision.Status != SourceRevisionPublished ||
		source.PublishedRevision <= 0 ||
		source.PublishedRevision != revision.Revision ||
		source.PublishedRevisionDigest == "" ||
		source.PublishedRevisionDigest != revision.CanonicalRevisionDigest {
		return BuiltinSourceProfile{}, false
	}
	profile, err := management.profiles.ResolveProfileAdmission(ctx, revision.ProfileCode)
	if err != nil || !exactInstalledRevisionProfile(source, revision, profile) {
		return BuiltinSourceProfile{}, false
	}
	return profile.Clone(), true
}

func exactInstalledRevisionProfile(
	source Source,
	revision SourceRevision,
	profile BuiltinSourceProfile,
) bool {
	if revision.CanonicalProfileManifest != nil &&
		!bytes.Equal(revision.CanonicalProfileManifest, profile.CanonicalProfileManifest) ||
		revision.CanonicalProviderSchema != nil &&
			!bytes.Equal(revision.CanonicalProviderSchema, profile.CanonicalProviderSchema) {
		return false
	}
	canonicalRevision := revision.Clone()
	canonicalRevision.CanonicalProfileManifest = slices.Clone(profile.CanonicalProfileManifest)
	canonicalRevision.CanonicalProviderSchema = slices.Clone(profile.CanonicalProviderSchema)
	definitionDigest, definitionErr := SourceDefinitionDigest(source, canonicalRevision)
	authorityDigest, authorityErr := AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	return definitionErr == nil && authorityErr == nil &&
		source.Kind == profile.SourceKind &&
		source.ProviderKind == profile.ProviderKind &&
		revision.ProfileCode == profile.ProfileCode &&
		revision.ProfileManifestSHA256 == profile.ProfileManifestSHA256 &&
		revision.CanonicalProviderSchemaSHA256 == profile.CanonicalProviderSchemaSHA256 &&
		revision.IntegrationID == profile.IntegrationID &&
		revision.SyncMode == profile.SyncMode &&
		revision.CredentialReferenceID == profile.CredentialReferenceID &&
		revision.TrustReferenceID == profile.TrustReferenceID &&
		revision.NetworkPolicyReferenceID == profile.NetworkPolicyReferenceID &&
		revision.RateLimitRequests == profile.RateLimitRequests &&
		revision.RateLimitWindowSeconds == profile.RateLimitWindowSeconds &&
		revision.BackpressureBaseSeconds == profile.BackpressureBaseSeconds &&
		revision.BackpressureMaxSeconds == profile.BackpressureMaxSeconds &&
		revision.ScheduleExpression == profile.ScheduleExpression &&
		revision.TypedExtensionCode == profile.TypedExtensionCode &&
		revision.PreparedExtensionDigest == profile.PreparedExtensionDigest &&
		revision.SourceDefinitionDigest == definitionDigest &&
		revision.AuthorityScopeDigest == authorityDigest &&
		revision.CanonicalRevisionDigest != "" &&
		revision.BindingDigest() == revision.CanonicalRevisionDigest
}

func (management *Management) manualAssetCreateEligible(
	ctx context.Context,
	model SourceReadModel,
) bool {
	profile, installed := management.installedPublishedProfile(ctx, model)
	return installed &&
		profile.SourceKind == SourceKindManual &&
		model.Source.Status == SourceStatusActive &&
		model.Source.GateStatus == SourceGateAvailable
}

func publishedSourceAuthorities(model SourceReadModel) []string {
	if model.PublishedRevision == nil {
		return nil
	}
	return slices.Clone(model.PublishedRevision.AuthorityEnvironmentIDs)
}

func (management *Management) sourceRevisionMutationView(
	ctx context.Context,
	principal authn.Principal,
	result SourceRevisionMutation,
) SourceRevisionMutationView {
	model := SourceReadModel{Source: result.Source.Clone(), LatestRevision: result.Revision.Clone()}
	if result.Source.PublishedRevision == result.Revision.Revision {
		published := result.Revision.Clone()
		model.PublishedRevision = &published
	}
	return SourceRevisionMutationView{
		Source: result.Source.Clone(), Revision: result.Revision.Clone(), Receipt: result.Receipt,
		EffectiveActions: management.sourceActions(ctx, principal, model),
	}
}

func (management *Management) sourceRunMutationView(
	ctx context.Context,
	principal authn.Principal,
	result SourceRunMutation,
) SourceRunMutationView {
	model := SourceReadModel{
		Source: result.Source.Clone(), LatestRevision: result.Revision.Clone(),
		CurrentRun: cloneWith(&result.Run, func(value SourceRun) SourceRun { return value.Clone() }),
	}
	if result.Source.PublishedRevision == result.Revision.Revision {
		published := result.Revision.Clone()
		model.PublishedRevision = &published
	}
	return SourceRunMutationView{
		Source: result.Source.Clone(), Revision: result.Revision.Clone(), Run: result.Run.Clone(),
		Receipt: result.Receipt, EffectiveActions: management.sourceActions(ctx, principal, model),
	}
}

func (management *Management) assetActions(
	principal authn.Principal,
	scope Scope,
	lifecycle Lifecycle,
) []EffectiveAction {
	if management.authorize(principal, authz.PermissionAssetManage, scope, "") != nil {
		return []EffectiveAction{}
	}
	actions := make([]EffectiveAction, 0, 3)
	if lifecycle != LifecycleRetired {
		actions = append(actions, ActionEditGovernance, ActionRetire)
	}
	if lifecycle != LifecycleQuarantined && lifecycle != LifecycleRetired {
		actions = append(actions, ActionQuarantine)
	}
	slices.Sort(actions)
	return slices.Compact(actions)
}

func (management *Management) assetMutationView(
	principal authn.Principal,
	scope Scope,
	result AssetMutationResult,
) AssetMutationView {
	return AssetMutationView{
		View: AssetView{
			ReadModel:        result.Asset.Clone(),
			EffectiveActions: management.assetActions(principal, scope, result.Asset.Lifecycle),
		},
		Receipt: result.Receipt,
	}
}

func resolvedEnvironmentScopeMatchesPrincipal(
	principal authn.Principal,
	scope Scope,
	route AssetCollectionRequest,
) error {
	if !scope.Valid() {
		return ErrStateConflict
	}
	if scope.WorkspaceID != route.WorkspaceID || scope.EnvironmentID != route.EnvironmentID {
		return ErrScopeViolation
	}
	if scope.TenantID != principal.TenantID {
		return authz.ErrForbidden
	}
	return nil
}

func assetAccessForPrincipal(principal authn.Principal) (AssetReadConstraint, error) {
	unrestricted := false
	serviceOwner := false
	for _, role := range principal.Roles {
		switch role {
		case authn.RoleViewer, authn.RoleSRE, authn.RoleApprover, authn.RoleAuditor, authn.RoleAdmin:
			unrestricted = true
		case authn.RoleServiceOwner:
			serviceOwner = true
		}
	}
	if unrestricted {
		return NewAssetReadConstraint(true, nil)
	}
	if serviceOwner {
		return NewAssetReadConstraint(false, principal.ServiceIDs)
	}
	return NewAssetReadConstraint(false, nil)
}

func sourceAuthorizationEnvironment(principal authn.Principal, requested string) (string, error) {
	if requested != "" {
		if !validUUID(requested) || !slices.Contains(principal.EnvironmentIDs, requested) {
			return "", authz.ErrForbidden
		}
		return requested, nil
	}
	environmentIDs := slices.Clone(principal.EnvironmentIDs)
	slices.Sort(environmentIDs)
	if len(environmentIDs) == 0 || !validUUID(environmentIDs[0]) {
		return "", authz.ErrForbidden
	}
	return environmentIDs[0], nil
}

const managementValidationTenantID = "00000000-0000-4000-8000-000000000001"

func validAssetListInputShape(
	route AssetCollectionRequest,
	input AssetListInput,
	access AssetReadConstraint,
) bool {
	request := ListAssetsRequest{
		Scope: Scope{
			TenantID: managementValidationTenantID, WorkspaceID: route.WorkspaceID,
			EnvironmentID: route.EnvironmentID,
		},
		Access: access, Filter: input.Filter.Clone(), Sort: input.Sort, Limit: input.Limit,
	}
	digest, err := request.QueryDigest()
	if err != nil {
		return false
	}
	if input.Cursor != nil {
		cursor := *input.Cursor
		cursor.QueryDigest = digest
		request.Cursor = &cursor
		_, err = request.QueryDigest()
	}
	return err == nil
}

func validRelationshipListInputShape(
	route AssetCollectionRequest,
	input RelationshipListInput,
	access AssetReadConstraint,
) bool {
	request := ListRelationshipsRequest{
		Scope: Scope{
			TenantID: managementValidationTenantID, WorkspaceID: route.WorkspaceID,
			EnvironmentID: route.EnvironmentID,
		},
		Access: access, AssetID: input.AssetID, SourceID: input.SourceID,
		Types: slices.Clone(input.Types), Statuses: slices.Clone(input.Statuses), Limit: input.Limit,
	}
	digest, err := request.QueryDigest()
	if err != nil {
		return false
	}
	if input.Cursor != nil {
		cursor := *input.Cursor
		cursor.QueryDigest = digest
		request.Cursor = &cursor
		_, err = request.QueryDigest()
	}
	return err == nil
}

func validSourceListInputShape(
	route SourceCollectionRequest,
	input SourceListInput,
	access SourceReadConstraint,
) bool {
	request := ListSourcesRequest{
		Scope:  SourceScope{TenantID: managementValidationTenantID, WorkspaceID: route.WorkspaceID},
		Access: access, Kinds: slices.Clone(input.Kinds), Statuses: slices.Clone(input.Statuses),
		GateStatuses: slices.Clone(input.GateStatuses), Usage: input.Usage,
		EnvironmentID: input.EnvironmentID, Limit: input.Limit,
	}
	digest, err := request.QueryDigest()
	if err != nil {
		return false
	}
	if input.Cursor != nil {
		cursor := *input.Cursor
		cursor.QueryDigest = digest
		request.Cursor = &cursor
		_, err = request.QueryDigest()
	}
	return err == nil
}

func validConflictListInputShape(
	route ConflictCollectionRequest,
	input ConflictListInput,
	access AssetReadConstraint,
) bool {
	request := ListConflictsRequest{
		Scope: Scope{
			TenantID: managementValidationTenantID, WorkspaceID: route.WorkspaceID,
			EnvironmentID: route.EnvironmentID,
		},
		Access: access, AssetID: input.AssetID, SourceID: input.SourceID,
		Statuses: slices.Clone(input.Statuses), Limit: input.Limit,
	}
	digest, err := request.QueryDigest()
	if err != nil {
		return false
	}
	if input.Cursor != nil {
		cursor := *input.Cursor
		cursor.QueryDigest = digest
		request.Cursor = &cursor
		_, err = request.QueryDigest()
	}
	return err == nil
}

func validBindingListInputShape(
	route AssetCollectionRequest,
	input BindingListInput,
	access AssetReadConstraint,
) bool {
	request := ListBindingsRequest{
		Scope: Scope{
			TenantID: managementValidationTenantID, WorkspaceID: route.WorkspaceID,
			EnvironmentID: route.EnvironmentID,
		},
		Access: access, ServiceID: input.ServiceID, AssetID: input.AssetID,
		Roles: slices.Clone(input.Roles), Statuses: slices.Clone(input.Statuses), Limit: input.Limit,
	}
	digest, err := request.QueryDigest()
	if err != nil {
		return false
	}
	if input.Cursor != nil {
		cursor := *input.Cursor
		cursor.QueryDigest = digest
		request.Cursor = &cursor
		_, err = request.QueryDigest()
	}
	return err == nil
}

func validAssetCollectionRoute(route AssetCollectionRequest) bool {
	return validUUID(route.WorkspaceID) && validUUID(route.EnvironmentID)
}

func validAssetPathRoute(route AssetPathRequest) bool {
	return validUUID(route.WorkspaceID) && validUUID(route.EnvironmentID) && validUUID(route.AssetID)
}

func validSourceCollectionRoute(route SourceCollectionRequest) bool {
	return validUUID(route.WorkspaceID)
}

func validSourcePathRoute(route SourcePathRequest) bool {
	return validUUID(route.WorkspaceID) && validUUID(route.SourceID)
}

func validSourceRunPathRoute(route SourceRunPathRequest) bool {
	return validUUID(route.WorkspaceID) && validUUID(route.RunID)
}

func validSourceRevisionPathRoute(route SourceRevisionPathRequest) bool {
	return validUUID(route.WorkspaceID) && validUUID(route.SourceID) && route.Revision > 0
}

func validConflictPathRoute(route ConflictPathRequest) bool {
	return validUUID(route.WorkspaceID) && validUUID(route.ConflictID)
}

func validBindingPathRoute(route BindingPathRequest) bool {
	return validUUID(route.WorkspaceID) && validUUID(route.EnvironmentID) && validUUID(route.BindingID)
}

func validCreateMetadata(metadata ServerRequestMetadata) bool {
	return validServerRequestMetadata(metadata) && metadata.ExpectedVersion == 0 &&
		metadata.ExpectedRevisionVersion == 0
}

func validVersionedMetadata(metadata ServerRequestMetadata) bool {
	return validServerRequestMetadata(metadata) && metadata.ExpectedVersion > 0 &&
		metadata.ExpectedRevisionVersion == 0
}

func validSourceVersionMetadata(metadata ServerRequestMetadata) bool {
	return validVersionedMetadata(metadata)
}

func validSourceRevisionVersionMetadata(metadata ServerRequestMetadata) bool {
	return validServerRequestMetadata(metadata) && metadata.ExpectedVersion > 0 &&
		metadata.ExpectedRevisionVersion > 0
}

func validServerRequestMetadata(metadata ServerRequestMetadata) bool {
	return validSafeToken(metadata.TraceID, 1, 128) && validIdempotencyKey(metadata.IdempotencyKey)
}

func validCreateAssetInput(input CreateAssetInput) bool {
	return validUUID(input.SourceID) && input.Kind.Valid() &&
		validSafeText(input.ExternalID, 1, 512) && validSafeText(input.DisplayName, 1, 256) &&
		(input.OwnerGroup == nil || validSafeText(*input.OwnerGroup, 1, 256)) &&
		input.Criticality.Valid() && input.DataClassification.Valid() &&
		validLabels(input.Labels)
}

func validUpdateGovernanceInput(input UpdateGovernanceInput) bool {
	return validSafeText(input.DisplayName, 1, 256) &&
		(input.OwnerGroup == nil || validSafeText(*input.OwnerGroup, 1, 256)) &&
		input.Criticality.Valid() && input.DataClassification.Valid() &&
		validLabels(input.Labels)
}

func validCreateSourceInput(input CreateSourceInput) bool {
	authorities := slices.Clone(input.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	return validSafeText(input.Name, 1, 256) && input.SourceProfileID.Valid() &&
		len(authorities) <= 100 &&
		validUniqueUUIDs(authorities, false)
}

func validCreateSourceRevisionInput(input CreateSourceRevisionInput) bool {
	authorities := slices.Clone(input.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	return input.SourceProfileID.Valid() && len(authorities) <= 100 &&
		validUniqueUUIDs(authorities, false) &&
		validReasonCode(input.ChangeReasonCode)
}

func validCreateBindingInput(input CreateBindingInput) bool {
	return validUUID(input.ServiceID) && validUUID(input.AssetID) &&
		input.Role.Valid() && validReasonCode(input.ReasonCode)
}

func validResolveConflictInput(input ResolveConflictInput) bool {
	if !input.Resolution.Valid() || !validReasonCode(input.ReasonCode) {
		return false
	}
	if input.Resolution == ConflictResolutionConfirmExact {
		return validUUID(input.ServiceID) && input.BindingRole.Valid()
	}
	return input.ServiceID == "" && input.BindingRole == ""
}

func validReasonCode(value string) bool { return validNamedCode(value) }

func cloneCreateAssetInput(input CreateAssetInput) CreateAssetInput {
	input.OwnerGroup = clonePointer(input.OwnerGroup)
	input.Labels = maps.Clone(input.Labels)
	return input
}

func cloneUpdateGovernanceInput(input UpdateGovernanceInput) UpdateGovernanceInput {
	input.OwnerGroup = clonePointer(input.OwnerGroup)
	input.Labels = maps.Clone(input.Labels)
	return input
}

func cloneCreateSourceInput(input CreateSourceInput) CreateSourceInput {
	input.AuthorityEnvironmentIDs = slices.Clone(input.AuthorityEnvironmentIDs)
	slices.Sort(input.AuthorityEnvironmentIDs)
	return input
}

func cloneCreateSourceRevisionInput(input CreateSourceRevisionInput) CreateSourceRevisionInput {
	input.AuthorityEnvironmentIDs = slices.Clone(input.AuthorityEnvironmentIDs)
	slices.Sort(input.AuthorityEnvironmentIDs)
	return input
}

func createAssetRequestHash(scope Scope, input CreateAssetInput) (string, error) {
	return managementSemanticHash(struct {
		Operation          string             `json:"operation"`
		Scope              Scope              `json:"scope"`
		SourceID           string             `json:"source_id"`
		Kind               Kind               `json:"kind"`
		ExternalID         string             `json:"external_id"`
		DisplayName        string             `json:"display_name"`
		OwnerGroup         *string            `json:"owner_group"`
		Criticality        Criticality        `json:"criticality"`
		DataClassification DataClassification `json:"data_classification"`
		Labels             map[string]string  `json:"labels"`
	}{
		Operation: "asset.created.v1", Scope: scope, SourceID: input.SourceID, Kind: input.Kind,
		ExternalID: input.ExternalID, DisplayName: input.DisplayName, OwnerGroup: input.OwnerGroup,
		Criticality: input.Criticality, DataClassification: input.DataClassification, Labels: input.Labels,
	})
}

func updateAssetRequestHash(
	scope Scope,
	assetID string,
	input UpdateGovernanceInput,
	expectedVersion int64,
) (string, error) {
	return managementSemanticHash(struct {
		Operation          string             `json:"operation"`
		Scope              Scope              `json:"scope"`
		AssetID            string             `json:"asset_id"`
		DisplayName        string             `json:"display_name"`
		OwnerGroup         *string            `json:"owner_group"`
		Criticality        Criticality        `json:"criticality"`
		DataClassification DataClassification `json:"data_classification"`
		Labels             map[string]string  `json:"labels"`
		ExpectedVersion    int64              `json:"expected_version"`
	}{
		Operation: "asset.governance.updated.v1", Scope: scope, AssetID: assetID,
		DisplayName: input.DisplayName, OwnerGroup: input.OwnerGroup, Criticality: input.Criticality,
		DataClassification: input.DataClassification, Labels: input.Labels, ExpectedVersion: expectedVersion,
	})
}

func transitionAssetRequestHash(
	operation string,
	scope Scope,
	assetID string,
	to Lifecycle,
	reasonCode string,
	expectedVersion int64,
) (string, error) {
	return managementSemanticHash(struct {
		Operation       string    `json:"operation"`
		Scope           Scope     `json:"scope"`
		AssetID         string    `json:"asset_id"`
		To              Lifecycle `json:"to"`
		ReasonCode      string    `json:"reason_code"`
		ExpectedVersion int64     `json:"expected_version"`
	}{operation, scope, assetID, to, reasonCode, expectedVersion})
}

func createBindingRequestHash(scope Scope, input CreateBindingInput) (string, error) {
	return managementSemanticHash(struct {
		Operation  string      `json:"operation"`
		Scope      Scope       `json:"scope"`
		ServiceID  string      `json:"service_id"`
		AssetID    string      `json:"asset_id"`
		Role       BindingRole `json:"role"`
		ReasonCode string      `json:"reason_code"`
	}{
		Operation: "service.asset.binding.created.v1", Scope: scope, ServiceID: input.ServiceID,
		AssetID: input.AssetID, Role: input.Role, ReasonCode: input.ReasonCode,
	})
}

func deleteBindingRequestHash(
	scope Scope,
	bindingID string,
	reasonCode string,
	expectedVersion int64,
) (string, error) {
	return managementSemanticHash(struct {
		Operation       string `json:"operation"`
		Scope           Scope  `json:"scope"`
		BindingID       string `json:"binding_id"`
		ReasonCode      string `json:"reason_code"`
		ExpectedVersion int64  `json:"expected_version"`
	}{
		Operation: "service.asset.binding.removed.v1", Scope: scope, BindingID: bindingID,
		ReasonCode: reasonCode, ExpectedVersion: expectedVersion,
	})
}

func resolveConflictRequestHash(
	scope Scope,
	conflictID string,
	input ResolveConflictInput,
	expectedVersion int64,
) (string, error) {
	return managementSemanticHash(struct {
		Operation       string             `json:"operation"`
		Scope           Scope              `json:"scope"`
		ConflictID      string             `json:"conflict_id"`
		ServiceID       string             `json:"service_id"`
		Resolution      ConflictResolution `json:"resolution"`
		BindingRole     BindingRole        `json:"binding_role"`
		ReasonCode      string             `json:"reason_code"`
		ExpectedVersion int64              `json:"expected_version"`
	}{
		Operation: "asset.conflict.resolved.v1", Scope: scope, ConflictID: conflictID,
		ServiceID: input.ServiceID, Resolution: input.Resolution, BindingRole: input.BindingRole,
		ReasonCode: input.ReasonCode, ExpectedVersion: expectedVersion,
	})
}

func createSourceRequestHash(scope SourceScope, input CreateSourceInput) (string, error) {
	authorities := slices.Clone(input.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	return managementSemanticHash(struct {
		Operation               string          `json:"operation"`
		Scope                   SourceScope     `json:"scope"`
		Name                    string          `json:"name"`
		SourceProfileID         SourceProfileID `json:"source_profile_id"`
		AuthorityEnvironmentIDs []string        `json:"authority_environment_ids"`
	}{
		Operation: "asset.source.revision.created.v1", Scope: scope, Name: input.Name,
		SourceProfileID: input.SourceProfileID, AuthorityEnvironmentIDs: authorities,
	})
}

func createSourceRevisionRequestHash(
	scope SourceScope,
	sourceID string,
	input CreateSourceRevisionInput,
	expectedSourceVersion int64,
) (string, error) {
	authorities := slices.Clone(input.AuthorityEnvironmentIDs)
	slices.Sort(authorities)
	return managementSemanticHash(struct {
		Operation               string          `json:"operation"`
		Scope                   SourceScope     `json:"scope"`
		SourceID                string          `json:"source_id"`
		SourceProfileID         SourceProfileID `json:"source_profile_id"`
		AuthorityEnvironmentIDs []string        `json:"authority_environment_ids"`
		ChangeReasonCode        string          `json:"change_reason_code"`
		ExpectedSourceVersion   int64           `json:"expected_source_version"`
	}{
		Operation: "asset.source.revision.created.v1", Scope: scope, SourceID: sourceID,
		SourceProfileID: input.SourceProfileID, AuthorityEnvironmentIDs: authorities,
		ChangeReasonCode: input.ChangeReasonCode, ExpectedSourceVersion: expectedSourceVersion,
	})
}

func validateSourceRevisionRequestHash(
	scope SourceScope,
	command ValidateSourceRevisionCommand,
) (string, error) {
	return managementSemanticHash(struct {
		Operation               string      `json:"operation"`
		Scope                   SourceScope `json:"scope"`
		SourceID                string      `json:"source_id"`
		Revision                int64       `json:"revision"`
		ExpectedSourceVersion   int64       `json:"expected_source_version"`
		ExpectedRevisionVersion int64       `json:"expected_revision_version"`
		ExpectedRevisionDigest  string      `json:"expected_revision_digest"`
	}{
		Operation: "asset.source.validation.requested.v1", Scope: scope,
		SourceID: command.SourceID, Revision: command.Revision,
		ExpectedSourceVersion:   command.ExpectedSourceVersion,
		ExpectedRevisionVersion: command.ExpectedRevisionVersion,
		ExpectedRevisionDigest:  command.ExpectedRevisionDigest,
	})
}

func publishSourceRevisionRequestHash(
	scope SourceScope,
	command PublishSourceRevisionCommand,
) (string, error) {
	return managementSemanticHash(struct {
		Operation                string      `json:"operation"`
		Scope                    SourceScope `json:"scope"`
		SourceID                 string      `json:"source_id"`
		Revision                 int64       `json:"revision"`
		ReasonCode               string      `json:"reason_code"`
		ExpectedSourceVersion    int64       `json:"expected_source_version"`
		ExpectedRevisionVersion  int64       `json:"expected_revision_version"`
		ExpectedRevisionDigest   string      `json:"expected_revision_digest"`
		ExpectedValidationRunID  string      `json:"expected_validation_run_id"`
		ExpectedValidationDigest string      `json:"expected_validation_digest"`
	}{
		Operation: "asset.source.revision.published.v1", Scope: scope,
		SourceID: command.SourceID, Revision: command.Revision, ReasonCode: command.ReasonCode,
		ExpectedSourceVersion:    command.ExpectedSourceVersion,
		ExpectedRevisionVersion:  command.ExpectedRevisionVersion,
		ExpectedRevisionDigest:   command.ExpectedRevisionDigest,
		ExpectedValidationRunID:  command.ExpectedValidationRunID,
		ExpectedValidationDigest: command.ExpectedValidationDigest,
	})
}

func disableSourceRequestHash(
	scope SourceScope,
	sourceID string,
	reasonCode string,
	expectedSourceVersion int64,
) (string, error) {
	return managementSemanticHash(struct {
		Operation             string      `json:"operation"`
		Scope                 SourceScope `json:"scope"`
		SourceID              string      `json:"source_id"`
		ReasonCode            string      `json:"reason_code"`
		ExpectedSourceVersion int64       `json:"expected_source_version"`
	}{
		Operation: "asset.source.disabled.v1", Scope: scope, SourceID: sourceID,
		ReasonCode: reasonCode, ExpectedSourceVersion: expectedSourceVersion,
	})
}

func syncSourceRequestHash(scope SourceScope, command RequestSyncCommand) (string, error) {
	return managementSemanticHash(struct {
		Operation                 string      `json:"operation"`
		Scope                     SourceScope `json:"scope"`
		SourceID                  string      `json:"source_id"`
		ExpectedSourceVersion     int64       `json:"expected_source_version"`
		ExpectedRevision          int64       `json:"expected_revision"`
		ExpectedRevisionDigest    string      `json:"expected_revision_digest"`
		ExpectedCheckpointVersion int64       `json:"expected_checkpoint_version"`
		ExpectedCheckpointSHA256  string      `json:"expected_checkpoint_sha256"`
	}{
		Operation: "asset.source.sync.requested.v1", Scope: scope, SourceID: command.SourceID,
		ExpectedSourceVersion:     command.ExpectedSourceVersion,
		ExpectedRevision:          command.ExpectedRevision,
		ExpectedRevisionDigest:    command.ExpectedRevisionDigest,
		ExpectedCheckpointVersion: command.ExpectedCheckpointVersion,
		ExpectedCheckpointSHA256:  command.ExpectedCheckpointSHA256,
	})
}

func managementSemanticHash(value any) (string, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidRequest
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func nilManagementDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ AssetManager        = (*Management)(nil)
	_ RelationshipManager = (*Management)(nil)
	_ SourceManager       = (*Management)(nil)
	_ ConflictManager     = (*Management)(nil)
	_ BindingManager      = (*Management)(nil)
)
