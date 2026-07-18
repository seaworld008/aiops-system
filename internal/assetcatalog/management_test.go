package assetcatalog

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	managementTenantID      = "11111111-1111-4111-8111-111111111111"
	managementOtherTenantID = "11111111-1111-4111-8111-111111111112"
	managementWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	managementEnvironmentID = "33333333-3333-4333-8333-333333333333"
	managementAssetID       = "44444444-4444-4444-8444-444444444444"
	managementSourceID      = "55555555-5555-4555-8555-555555555555"
	managementServiceID     = "66666666-6666-4666-8666-666666666666"
	managementBindingID     = "77777777-7777-4777-8777-777777777777"
	managementConflictID    = "88888888-8888-4888-8888-888888888888"
)

func TestManagementInterfacesHaveExactNarrowShape(t *testing.T) {
	t.Parallel()

	assertExactInterface(t, reflect.TypeOf((*AssetManager)(nil)).Elem(), reflect.TypeOf((*interface {
		ListAssets(context.Context, authn.Principal, AssetCollectionRequest, AssetListInput) (AssetViewPage, error)
		GetAsset(context.Context, authn.Principal, AssetPathRequest) (AssetView, error)
		CreateAsset(context.Context, authn.Principal, AssetCollectionRequest, CreateAssetInput, ServerRequestMetadata) (AssetMutationView, error)
		UpdateAsset(context.Context, authn.Principal, AssetPathRequest, UpdateGovernanceInput, ServerRequestMetadata) (AssetMutationView, error)
		QuarantineAsset(context.Context, authn.Principal, AssetPathRequest, TransitionInput, ServerRequestMetadata) (AssetMutationView, error)
		RetireAsset(context.Context, authn.Principal, AssetPathRequest, TransitionInput, ServerRequestMetadata) (AssetMutationView, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*RelationshipManager)(nil)).Elem(), reflect.TypeOf((*interface {
		ListRelationships(context.Context, authn.Principal, AssetCollectionRequest, RelationshipListInput) (RelationshipViewPage, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*SourceManager)(nil)).Elem(), reflect.TypeOf((*interface {
		ListSources(context.Context, authn.Principal, SourceCollectionRequest, SourceListInput) (SourceViewPage, error)
		GetSource(context.Context, authn.Principal, SourcePathRequest) (SourceView, error)
		GetSourceRun(context.Context, authn.Principal, SourceRunPathRequest) (SourceRunView, error)
		CreateSource(context.Context, authn.Principal, SourceCollectionRequest, CreateSourceInput, ServerRequestMetadata) (SourceRevisionMutationView, error)
		CreateSourceRevision(context.Context, authn.Principal, SourcePathRequest, CreateSourceRevisionInput, ServerRequestMetadata) (SourceRevisionMutationView, error)
		ValidateSourceRevision(context.Context, authn.Principal, SourceRevisionPathRequest, ServerRequestMetadata) (SourceRunMutationView, error)
		PublishSourceRevision(context.Context, authn.Principal, SourceRevisionPathRequest, SourceReasonInput, ServerRequestMetadata) (SourceRevisionMutationView, error)
		DisableSource(context.Context, authn.Principal, SourcePathRequest, SourceReasonInput, ServerRequestMetadata) (SourceMutationView, error)
		SyncSource(context.Context, authn.Principal, SourcePathRequest, ServerRequestMetadata) (SourceRunMutationView, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*ConflictManager)(nil)).Elem(), reflect.TypeOf((*interface {
		ListConflicts(context.Context, authn.Principal, ConflictCollectionRequest, ConflictListInput) (ConflictViewPage, error)
		ResolveConflict(context.Context, authn.Principal, ConflictPathRequest, ResolveConflictInput, ServerRequestMetadata) (ConflictMutationView, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*BindingManager)(nil)).Elem(), reflect.TypeOf((*interface {
		ListBindings(context.Context, authn.Principal, AssetCollectionRequest, BindingListInput) (BindingViewPage, error)
		CreateBinding(context.Context, authn.Principal, AssetCollectionRequest, CreateBindingInput, ServerRequestMetadata) (BindingMutationView, error)
		DeleteBinding(context.Context, authn.Principal, BindingPathRequest, DeleteBindingInput, ServerRequestMetadata) (MutationReceipt, error)
	})(nil)).Elem())
}

func TestSourceManagerOwnsCreateSourceMutation(t *testing.T) {
	t.Parallel()

	sourceManager := reflect.TypeOf((*SourceManager)(nil)).Elem()
	if _, exists := sourceManager.MethodByName("CreateSource"); !exists {
		t.Fatal("SourceManager lacks CreateSource; Management is not the Source mutation owner")
	}
}

func TestManagementCreateSourceCallsAtomicRepositoryOwner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	revision := SourceRevision{
		ID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		SourceID: managementSourceID, TenantID: managementTenantID, WorkspaceID: managementWorkspaceID,
		Revision: 1, Status: SourceRevisionDraft, ProfileCode: "MANUAL_V1",
		CanonicalRevisionDigest: strings.Repeat("a", 64),
		AuthorityEnvironmentIDs: []string{managementEnvironmentID},
		Version:                 1, CreatedAt: now, UpdatedAt: now,
	}
	source := Source{
		ID: managementSourceID, TenantID: managementTenantID, WorkspaceID: managementWorkspaceID,
		Kind: SourceKindManual, ProviderKind: "MANUAL_V1", Name: "Manual",
		Status: SourceStatusActive, GateStatus: SourceGateUnavailable, Version: 2,
		CreatedAt: now, UpdatedAt: now,
	}
	repository := &recordingManagementRepository{
		scope: managementScope(),
		sourceRevisionResult: SourceRevisionMutation{
			Source: source, Revision: revision,
			Receipt: MutationReceipt{
				AuditID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
				TraceID: "source-create-trace",
			},
		},
	}
	manager := mustManagement(t, repository)
	input := CreateSourceInput{
		Name: "Manual", SourceProfileID: SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{managementEnvironmentID},
	}
	metadata := ServerRequestMetadata{
		TraceID: "source-create-trace", IdempotencyKey: "source-create-1",
	}
	result, err := manager.CreateSource(
		context.Background(), managementPrincipal(authn.RoleAdmin),
		SourceCollectionRequest{WorkspaceID: managementWorkspaceID}, input, metadata,
	)
	if err != nil {
		t.Fatal(err)
	}
	if repository.createSourceCalls != 1 || repository.createAssetCalls != 0 ||
		repository.lastCreateSource.Name != input.Name ||
		repository.lastCreateSource.SourceProfileID != input.SourceProfileID ||
		!slices.Equal(repository.lastCreateSource.AuthorityEnvironmentIDs, input.AuthorityEnvironmentIDs) {
		t.Fatalf("CreateSource repository ownership drifted: calls=%d/%d command=%#v",
			repository.createSourceCalls, repository.createAssetCalls, repository.lastCreateSource)
	}
	scope := SourceScope{TenantID: managementTenantID, WorkspaceID: managementWorkspaceID}
	wantHash, err := createSourceRequestHash(scope, input)
	if err != nil {
		t.Fatal(err)
	}
	if repository.lastCreateSource.Context.SourceScope() != scope ||
		repository.lastCreateSource.Context.RequestHash() != wantHash ||
		repository.lastCreateSource.Context.IdempotencyKey() != metadata.IdempotencyKey ||
		result.Source.ID != managementSourceID || result.Revision.Revision != 1 {
		t.Fatalf("CreateSource trusted closure drifted: command=%#v result=%#v",
			repository.lastCreateSource, result)
	}
}

func TestManagementFailsClosedWhenAnyDependencyIsMissing(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{scope: managementScope()}
	authorizer := managementAuthorizer(t)
	tests := []struct {
		name       string
		assets     Repository
		mappings   MappingRepository
		sources    SourceManagementRepository
		authorizer *authz.Authorizer
	}{
		{name: "assets", mappings: repository, sources: repository, authorizer: authorizer},
		{name: "mappings", assets: repository, sources: repository, authorizer: authorizer},
		{name: "sources", assets: repository, mappings: repository, authorizer: authorizer},
		{name: "authorizer", assets: repository, mappings: repository, sources: repository},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if manager, err := NewManagement(test.assets, test.mappings, test.sources, test.authorizer); err == nil || manager != nil {
				t.Fatalf("NewManagement() = (%#v, %v), want closed error", manager, err)
			}
		})
	}
}

func TestManagementDoesNotCallMutationRepositoryWhenUnauthorized(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{scope: managementScope()}
	manager := mustManagement(t, repository)
	_, err := manager.CreateAsset(
		context.Background(),
		managementPrincipal(authn.RoleViewer),
		AssetCollectionRequest{WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID},
		validManagementCreateAssetInput(),
		validManagementCreateMetadata(),
	)
	if !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("CreateAsset() error = %v, want ErrForbidden", err)
	}
	if repository.resolveScopeCalls != 1 || repository.createAssetCalls != 0 {
		t.Fatalf("calls ResolveScope/Create = %d/%d, want 1/0", repository.resolveScopeCalls, repository.createAssetCalls)
	}
}

func TestManagementRejectsResolvedScopeFromAnotherTenant(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{
		scope: Scope{
			TenantID: managementOtherTenantID, WorkspaceID: managementWorkspaceID,
			EnvironmentID: managementEnvironmentID,
		},
	}
	manager := mustManagement(t, repository)
	_, err := manager.CreateAsset(
		context.Background(),
		managementPrincipal(authn.RoleAdmin),
		AssetCollectionRequest{WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID},
		validManagementCreateAssetInput(),
		validManagementCreateMetadata(),
	)
	if !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("CreateAsset(cross-tenant scope) error = %v, want ErrForbidden", err)
	}
	if repository.createAssetCalls != 0 {
		t.Fatalf("Create() calls = %d, want 0", repository.createAssetCalls)
	}
}

func TestEffectiveActionsComeFromAuthorizationAndObjectState(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{
		scope: managementScope(),
		assetDetail: AssetDetailReadModel{AssetReadModel: AssetReadModel{Asset: Asset{
			ID: managementAssetID, Scope: managementScope(), Lifecycle: LifecycleActive,
			MappingStatus: domain.MappingExact,
		}}},
	}
	manager := mustManagement(t, repository)
	admin := managementPrincipal(authn.RoleAdmin)
	request := AssetPathRequest{
		WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID, AssetID: managementAssetID,
	}

	view, err := manager.GetAsset(context.Background(), admin, request)
	if err != nil {
		t.Fatal(err)
	}
	want := []EffectiveAction{ActionEditGovernance, ActionQuarantine, ActionRetire}
	if !slices.Equal(view.EffectiveActions, want) {
		t.Fatalf("active effective actions = %v, want %v", view.EffectiveActions, want)
	}

	repository.assetDetail.Asset.Lifecycle = LifecycleRetired
	view, err = manager.GetAsset(context.Background(), admin, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.EffectiveActions) != 0 {
		t.Fatalf("retired effective actions = %v, want empty", view.EffectiveActions)
	}
}

func TestManagementPushesServiceOwnerAccessIntoRepositoryQuery(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{scope: managementScope()}
	manager := mustManagement(t, repository)
	owner := managementPrincipal(authn.RoleServiceOwner)
	owner.ServiceIDs = []string{
		"66666666-6666-4666-8666-666666666667",
		managementServiceID,
	}
	_, err := manager.ListAssets(
		context.Background(),
		owner,
		AssetCollectionRequest{WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID},
		AssetListInput{Sort: AssetSortDisplayNameAsc, Limit: 50},
	)
	if err != nil {
		t.Fatal(err)
	}
	if repository.listAssetCalls != 1 || repository.lastAssetList.Access.Unrestricted() {
		t.Fatalf("List()/access = %d/%#v, want one restricted query", repository.listAssetCalls, repository.lastAssetList.Access)
	}
	want := []string{managementServiceID, "66666666-6666-4666-8666-666666666667"}
	if got := repository.lastAssetList.Access.ServiceIDs(); !slices.Equal(got, want) {
		t.Fatalf("service constraint = %v, want %v", got, want)
	}
}

func TestManagementAuthorizesBindingAgainstRequestedOwnedService(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{
		scope: managementScope(),
		bindingResult: BindingMutationResult{Binding: ServiceAssetBinding{
			ID: managementBindingID, Scope: managementScope(), ServiceID: managementServiceID,
			AssetID: managementAssetID, Role: BindingRoleDependency, Status: BindingStatusActive, Version: 1,
		}},
	}
	manager := mustManagement(t, repository)
	owner := managementPrincipal(authn.RoleServiceOwner)

	_, err := manager.CreateBinding(
		context.Background(),
		owner,
		AssetCollectionRequest{WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID},
		CreateBindingInput{
			ServiceID: managementServiceID, AssetID: managementAssetID,
			Role: BindingRoleDependency, ReasonCode: "owner_binding",
		},
		validManagementCreateMetadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if repository.createBindingCalls != 1 {
		t.Fatalf("CreateBinding() calls = %d, want 1", repository.createBindingCalls)
	}

	other := CreateBindingInput{
		ServiceID: "66666666-6666-4666-8666-666666666667", AssetID: managementAssetID,
		Role: BindingRoleDependency, ReasonCode: "other_binding",
	}
	if _, err := manager.CreateBinding(
		context.Background(), owner,
		AssetCollectionRequest{WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID},
		other, validManagementCreateMetadata(),
	); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("CreateBinding(other service) error = %v, want ErrForbidden", err)
	}
	if repository.createBindingCalls != 1 {
		t.Fatalf("CreateBinding() calls after denial = %d, want 1", repository.createBindingCalls)
	}
}

func TestManagementResolveConflictUsesNarrowScopeLookupBeforeAuthorizedMutation(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{
		scope: managementScope(),
		conflictResult: MappingDecisionResult{Conflict: ConflictReadModel{Conflict: Conflict{
			ID: managementConflictID, Scope: managementScope(), Status: ConflictStatusResolved,
			Resolution: ConflictResolutionConfirmExact, Version: 2,
		}}},
	}
	manager := mustManagement(t, repository)
	view, err := manager.ResolveConflict(
		context.Background(),
		managementPrincipal(authn.RoleAdmin),
		ConflictPathRequest{WorkspaceID: managementWorkspaceID, ConflictID: managementConflictID},
		ResolveConflictInput{
			ServiceID: managementServiceID, Resolution: ConflictResolutionConfirmExact,
			BindingRole: BindingRoleDependency, ReasonCode: "confirm_exact",
		},
		ServerRequestMetadata{
			TraceID: "trace-conflict", IdempotencyKey: "conflict-resolution", ExpectedVersion: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if view.View.ReadModel.ID != managementConflictID ||
		repository.resolveConflictScopeCalls != 1 || repository.resolveConflictCalls != 1 {
		t.Fatalf("result/calls = %#v/%d/%d", view, repository.resolveConflictScopeCalls, repository.resolveConflictCalls)
	}
	scope, ok := repository.lastDecision.Context.EnvironmentScope()
	if !ok || scope != managementScope() || repository.lastDecision.Context.SubjectID() != "principal-subject" ||
		repository.lastDecision.Context.RequestHash() == "" {
		t.Fatalf("trusted decision context = %#v, scope=%#v/%t", repository.lastDecision.Context, scope, ok)
	}
}

func TestManagementResolveConflictStopsAfterScopeLookupWhenTenantOrAuthorizationFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scope     Scope
		principal authn.Principal
	}{
		{
			name: "cross tenant",
			scope: Scope{
				TenantID: managementOtherTenantID, WorkspaceID: managementWorkspaceID,
				EnvironmentID: managementEnvironmentID,
			},
			principal: managementPrincipal(authn.RoleAdmin),
		},
		{
			name:      "unauthorized role",
			scope:     managementScope(),
			principal: managementPrincipal(authn.RoleViewer),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := &recordingManagementRepository{scope: test.scope}
			manager := mustManagement(t, repository)
			_, err := manager.ResolveConflict(
				context.Background(),
				test.principal,
				ConflictPathRequest{WorkspaceID: managementWorkspaceID, ConflictID: managementConflictID},
				ResolveConflictInput{
					ServiceID: managementServiceID, Resolution: ConflictResolutionConfirmExact,
					BindingRole: BindingRoleDependency, ReasonCode: "confirm_exact",
				},
				ServerRequestMetadata{
					TraceID: "trace-conflict-denied", IdempotencyKey: "conflict-resolution-denied",
					ExpectedVersion: 1,
				},
			)
			if !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("ResolveConflict() error = %v, want ErrForbidden", err)
			}
			if repository.resolveConflictScopeCalls != 1 || repository.resolveConflictCalls != 0 {
				t.Fatalf("scope/mutation calls = %d/%d, want 1/0",
					repository.resolveConflictScopeCalls, repository.resolveConflictCalls)
			}
		})
	}
}

func TestManagementDeleteBindingRemainsAdminOnlyWithoutPreauthorizationServiceProof(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{scope: managementScope()}
	manager := mustManagement(t, repository)
	_, err := manager.DeleteBinding(
		context.Background(),
		managementPrincipal(authn.RoleServiceOwner),
		BindingPathRequest{
			WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID, BindingID: managementBindingID,
		},
		DeleteBindingInput{ReasonCode: "remove_binding"},
		ServerRequestMetadata{
			TraceID: "trace-delete", IdempotencyKey: "delete-binding", ExpectedVersion: 1,
		},
	)
	if !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("DeleteBinding(service owner) error = %v, want ErrForbidden", err)
	}
	if repository.deleteBindingCalls != 0 {
		t.Fatalf("DeleteBinding() calls = %d, want 0", repository.deleteBindingCalls)
	}
}

func TestManagementRejectsMalformedListInputsBeforeScopeResolution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(*Management, *recordingManagementRepository) error
	}{
		{
			name: "assets",
			call: func(manager *Management, repository *recordingManagementRepository) error {
				_, err := manager.ListAssets(
					context.Background(), managementPrincipal(authn.RoleAdmin),
					AssetCollectionRequest{
						WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
					},
					AssetListInput{Sort: AssetSortDisplayNameAsc, Limit: 0},
				)
				return err
			},
		},
		{
			name: "relationships",
			call: func(manager *Management, repository *recordingManagementRepository) error {
				_, err := manager.ListRelationships(
					context.Background(), managementPrincipal(authn.RoleAdmin),
					AssetCollectionRequest{
						WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
					},
					RelationshipListInput{Limit: 0},
				)
				return err
			},
		},
		{
			name: "sources",
			call: func(manager *Management, repository *recordingManagementRepository) error {
				_, err := manager.ListSources(
					context.Background(), managementPrincipal(authn.RoleAdmin),
					SourceCollectionRequest{WorkspaceID: managementWorkspaceID},
					SourceListInput{Limit: 0},
				)
				return err
			},
		},
		{
			name: "conflicts",
			call: func(manager *Management, repository *recordingManagementRepository) error {
				_, err := manager.ListConflicts(
					context.Background(), managementPrincipal(authn.RoleAdmin),
					ConflictCollectionRequest{
						WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
					},
					ConflictListInput{Limit: 0},
				)
				return err
			},
		},
		{
			name: "bindings",
			call: func(manager *Management, repository *recordingManagementRepository) error {
				_, err := manager.ListBindings(
					context.Background(), managementPrincipal(authn.RoleAdmin),
					AssetCollectionRequest{
						WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
					},
					BindingListInput{Limit: 0},
				)
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &recordingManagementRepository{scope: managementScope()}
			manager := mustManagement(t, repository)
			if err := test.call(manager, repository); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("list error = %v, want ErrInvalidRequest", err)
			}
			if repository.resolveScopeCalls != 0 || repository.resolveSourceScopeCalls != 0 {
				t.Fatalf("scope calls = environment:%d source:%d, want 0/0",
					repository.resolveScopeCalls, repository.resolveSourceScopeCalls)
			}
		})
	}
}

func TestManagementProjectsMappingAndSourceActionsFromAuthorizationAndState(t *testing.T) {
	t.Parallel()

	manualSource, manualRevision := exactManagementManualSourceRevision(t)
	manualSource.GateStatus = SourceGateAvailable
	manualSource.PublishedRevision = manualRevision.Revision
	manualSource.PublishedRevisionDigest = manualRevision.CanonicalRevisionDigest
	manualRevision.Status = SourceRevisionPublished
	publishedRevision := manualRevision.Clone()
	repository := &recordingManagementRepository{
		scope: managementScope(),
		bindingPage: BindingPage{Items: []ServiceAssetBinding{
			{ID: managementBindingID, Scope: managementScope(), Status: BindingStatusActive},
			{ID: "77777777-7777-4777-8777-777777777778", Scope: managementScope(), Status: BindingStatusInactive},
		}},
		conflictPage: ConflictPage{Items: []ConflictReadModel{
			{Conflict: Conflict{ID: managementConflictID, Scope: managementScope(), Status: ConflictStatusOpen}},
			{Conflict: Conflict{
				ID: "88888888-8888-4888-8888-888888888889", Scope: managementScope(),
				Status: ConflictStatusResolved, Resolution: ConflictResolutionKeepUnresolved,
			}},
		}},
		sourcePage: SourcePage{Items: []SourceReadModel{{
			Source: manualSource, LatestRevision: manualRevision,
			PublishedRevision: &publishedRevision,
		}}},
		relationPage: RelationshipPage{Items: []Relationship{{
			ID: "99999999-9999-4999-8999-999999999999",
		}}},
	}
	manager := mustManagement(t, repository)
	admin := managementPrincipal(authn.RoleAdmin)
	collection := AssetCollectionRequest{
		WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
	}

	bindings, err := manager.ListBindings(
		context.Background(), admin, collection, BindingListInput{Limit: 10},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bindings.Items[0].EffectiveActions, []EffectiveAction{ActionDeleteBinding}) ||
		len(bindings.Items[1].EffectiveActions) != 0 {
		t.Fatalf("binding effective actions = %#v", bindings.Items)
	}

	conflicts, err := manager.ListConflicts(
		context.Background(), admin,
		ConflictCollectionRequest{
			WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
		},
		ConflictListInput{Limit: 10},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(conflicts.Items[0].EffectiveActions, []EffectiveAction{ActionResolveConflict}) ||
		len(conflicts.Items[1].EffectiveActions) != 0 {
		t.Fatalf("conflict effective actions = %#v", conflicts.Items)
	}

	sources, err := manager.ListSources(
		context.Background(), admin,
		SourceCollectionRequest{WorkspaceID: managementWorkspaceID},
		SourceListInput{
			Usage: SourceUsageManualAssetCreate, EnvironmentID: managementEnvironmentID, Limit: 10,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources.Items) != 1 ||
		!slices.Equal(sources.EffectiveActions, []EffectiveAction{ActionCreateSource}) ||
		!slices.Equal(sources.Items[0].EffectiveActions, []EffectiveAction{
			ActionCreateAsset, ActionCreateSourceRevision, ActionDisableSource,
		}) {
		t.Fatalf("source effective actions = %#v / %#v", sources.EffectiveActions, sources.Items)
	}

	relationships, err := manager.ListRelationships(
		context.Background(), admin, collection, RelationshipListInput{Limit: 10},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships.Items) != 1 || repository.listRelationshipCalls != 1 ||
		repository.listBindingCalls != 1 || repository.listConflictCalls != 1 ||
		repository.listSourceCalls != 1 {
		t.Fatalf("mapping/source projections or calls drifted: %#v, calls=%d/%d/%d/%d",
			relationships, repository.listRelationshipCalls, repository.listBindingCalls,
			repository.listConflictCalls, repository.listSourceCalls)
	}
}

func TestSourceEffectiveActionsArePermissionAndStateAware(t *testing.T) {
	t.Parallel()

	manager := mustManagement(t, &recordingManagementRepository{scope: managementScope()})
	source, revision := exactManagementManualSourceRevision(t)
	csvSource, csvRevision, csvProfile := exactManagementClosedValidationSourceRevision(
		t, ProfileCode("CSV_RFC4180_V1"),
	)
	futureSource, futureRevision, futureProfile := exactManagementClosedValidationSourceRevision(
		t, ProfileCode("FUTURE_RUNTIME_V1"),
	)
	manager.profiles = managementSourceProfileResolver{
		ProfileCode("MANUAL_V1"):         ManualProfileV1(),
		ProfileCode("CSV_RFC4180_V1"):    csvProfile,
		ProfileCode("FUTURE_RUNTIME_V1"): futureProfile,
	}
	base := SourceReadModel{
		Source: source, LatestRevision: revision,
	}
	admin := managementPrincipal(authn.RoleAdmin)
	publishableProfile := func(model SourceReadModel) SourceReadModel {
		value := model.Clone()
		value.LatestRevision.Status = SourceRevisionValidated
		value.LatestRevision.ValidationRunID = "99999999-9999-4999-8999-999999999999"
		value.LatestRevision.ValidationDigest = strings.Repeat("b", 64)
		value.Source.GateStatus = SourceGateValidating
		value.Source.GateReasonCode = "VALIDATION_IN_PROGRESS"
		value.Source.ValidatedRunID = value.LatestRevision.ValidationRunID
		value.Source.ValidationDigest = ""
		value.Source.ValidatedBindingDigest = ""
		return value
	}
	publishable := func() SourceReadModel {
		return publishableProfile(base)
	}
	tests := []struct {
		name      string
		principal authn.Principal
		model     SourceReadModel
		want      []EffectiveAction
	}{
		{
			name: "manual draft validates", principal: admin, model: base,
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource, ActionValidateSourceRevision},
		},
		{
			name: "installed CSV draft keeps closed validation runtime hidden", principal: admin,
			model: SourceReadModel{Source: csvSource, LatestRevision: csvRevision},
			want:  []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "future installed profile defaults validation runtime closed", principal: admin,
			model: SourceReadModel{Source: futureSource, LatestRevision: futureRevision},
			want:  []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "installed profile canonical drift closes validation", principal: admin,
			model: func() SourceReadModel {
				value := base.Clone()
				value.LatestRevision.ProfileManifestSHA256 = strings.Repeat("f", 64)
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "nonprojection canonical bytes drift closes validation", principal: admin,
			model: func() SourceReadModel {
				value := base.Clone()
				value.LatestRevision.CanonicalProfileManifest = []byte(`{"drift":true}`)
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "viewer has no mutations", principal: managementPrincipal(authn.RoleViewer), model: base,
			want: []EffectiveAction{},
		},
		{
			name: "disabled has no mutations", principal: admin,
			model: func() SourceReadModel {
				value := base.Clone()
				value.Source.Status = SourceStatusDisabled
				return value
			}(),
			want: []EffectiveAction{},
		},
		{
			name: "manual runtime and repository publish preconditions expose publication", principal: admin,
			model: publishable(),
			want:  []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource, ActionPublishSourceRevision},
		},
		{
			name: "installed CSV publishable state keeps closed publication runtime hidden", principal: admin,
			model: publishableProfile(SourceReadModel{Source: csvSource, LatestRevision: csvRevision}),
			want:  []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "future installed profile defaults publication runtime closed", principal: admin,
			model: publishableProfile(SourceReadModel{Source: futureSource, LatestRevision: futureRevision}),
			want:  []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "revision state drift closes publication", principal: admin,
			model: func() SourceReadModel {
				value := publishable()
				value.LatestRevision.Status = SourceRevisionValidating
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "gate state drift closes publication", principal: admin,
			model: func() SourceReadModel {
				value := publishable()
				value.Source.GateStatus = SourceGateUnavailable
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "gate reason drift closes publication", principal: admin,
			model: func() SourceReadModel {
				value := publishable()
				value.Source.GateReasonCode = "VALIDATION_SUPERSEDED"
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "validated run drift closes publication", principal: admin,
			model: func() SourceReadModel {
				value := publishable()
				value.Source.ValidatedRunID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "source validation digest before publish closes publication", principal: admin,
			model: func() SourceReadModel {
				value := publishable()
				value.Source.ValidationDigest = value.LatestRevision.ValidationDigest
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "source binding digest before publish closes publication", principal: admin,
			model: func() SourceReadModel {
				value := publishable()
				value.Source.ValidatedBindingDigest = value.LatestRevision.CanonicalRevisionDigest
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "legacy post-publish digests close publication", principal: admin,
			model: func() SourceReadModel {
				value := publishable()
				value.Source.ValidationDigest = value.LatestRevision.ValidationDigest
				value.Source.ValidatedBindingDigest = value.LatestRevision.CanonicalRevisionDigest
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "manual published never syncs or imports", principal: admin,
			model: func() SourceReadModel {
				value := base.Clone()
				value.LatestRevision.Status = SourceRevisionPublished
				value.Source.GateStatus = SourceGateAvailable
				value.Source.PublishedRevision = 1
				value.Source.PublishedRevisionDigest = value.LatestRevision.CanonicalRevisionDigest
				published := value.LatestRevision.Clone()
				value.PublishedRevision = &published
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
		{
			name: "missing installed profile exposes no runtime action", principal: admin,
			model: func() SourceReadModel {
				value := base.Clone()
				value.Source.Kind = SourceKindCSVImport
				value.Source.ProviderKind = "CSV_RFC4180_V1"
				value.Source.GateStatus = SourceGateAvailable
				value.Source.PublishedRevision = 1
				value.Source.PublishedRevisionDigest = value.LatestRevision.CanonicalRevisionDigest
				value.LatestRevision.Status = SourceRevisionPublished
				value.LatestRevision.ProfileCode = "CSV_RFC4180_V1"
				return value
			}(),
			want: []EffectiveAction{ActionCreateSourceRevision, ActionDisableSource},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := manager.sourceActions(context.Background(), test.principal, test.model); !slices.Equal(got, test.want) {
				t.Fatalf("sourceActions() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestSourceEffectiveActionsConsumeExactValidationActionAdmission(t *testing.T) {
	t.Parallel()

	source, revision, profile := exactManagementCMDBSourceRevision(t)
	revision.IntegrationID = ""
	revision.CredentialReferenceID = ""
	revision.TrustReferenceID = ""
	revision.NetworkPolicyReferenceID = ""
	expectedDefinitionDigest := revision.SourceDefinitionDigest
	expectedBindingDigest := revision.CanonicalRevisionDigest
	baseRepository := &recordingManagementRepository{scope: managementScope()}
	profileRepository := &managementSourceProfileRepository{
		recordingManagementRepository: baseRepository,
		profiles: managementSourceProfileResolver{
			ProfileCode("MANUAL_V1"): ManualProfileV1(),
			profile.ProfileCode:      profile,
		},
	}
	admittedRepository := &managementSourceValidationActionRepository{
		managementSourceProfileRepository: profileRepository,
		admit: func(_ context.Context, candidateSource Source, candidateRevision SourceRevision) error {
			if candidateSource.Kind != SourceKindExternalCMDB ||
				candidateSource.ProviderKind != "CMDB_CATALOG_V1" ||
				candidateRevision.ProfileCode != ProfileCode("CMDB_CATALOG_V1") ||
				candidateRevision.CanonicalProfileManifest != nil ||
				candidateRevision.CanonicalProviderSchema != nil ||
				candidateRevision.IntegrationID != "" ||
				candidateRevision.CredentialReferenceID != "" ||
				candidateRevision.TrustReferenceID != "" ||
				candidateRevision.NetworkPolicyReferenceID != "" ||
				candidateRevision.SourceDefinitionDigest != expectedDefinitionDigest ||
				candidateRevision.CanonicalRevisionDigest != expectedBindingDigest {
				return ErrUnavailable
			}
			switch candidateRevision.Status {
			case SourceRevisionDraft, SourceRevisionRejected:
				if candidateSource.Status == SourceStatusActive &&
					candidateSource.GateStatus == SourceGateUnavailable {
					return nil
				}
			case SourceRevisionValidated:
				if candidateSource.Status == SourceStatusActive &&
					candidateSource.GateStatus == SourceGateValidating &&
					candidateSource.GateReasonCode == "VALIDATION_IN_PROGRESS" &&
					candidateSource.ValidatedRunID == candidateRevision.ValidationRunID &&
					candidateSource.ValidationDigest == "" &&
					candidateSource.ValidatedBindingDigest == "" {
					return nil
				}
			}
			return ErrUnavailable
		},
	}
	manager, err := NewManagement(
		baseRepository, baseRepository, admittedRepository, managementAuthorizer(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	admin := managementPrincipal(authn.RoleAdmin)
	draft := SourceReadModel{Source: source, LatestRevision: revision}
	publishable := draft.Clone()
	publishable.LatestRevision.Status = SourceRevisionValidated
	publishable.LatestRevision.ValidationRunID = "99999999-9999-4999-8999-999999999999"
	publishable.LatestRevision.ValidationDigest = strings.Repeat("b", 64)
	publishable.Source.GateStatus = SourceGateValidating
	publishable.Source.GateReasonCode = "VALIDATION_IN_PROGRESS"
	publishable.Source.ValidatedRunID = publishable.LatestRevision.ValidationRunID

	for _, test := range []struct {
		name  string
		model SourceReadModel
		want  []EffectiveAction
	}{
		{
			name:  "exact configured CMDB draft exposes validation",
			model: draft,
			want: []EffectiveAction{
				ActionCreateSourceRevision, ActionDisableSource, ActionValidateSourceRevision,
			},
		},
		{
			name:  "exact configured CMDB validated revision exposes publication",
			model: publishable,
			want: []EffectiveAction{
				ActionCreateSourceRevision, ActionDisableSource, ActionPublishSourceRevision,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := manager.sourceActions(t.Context(), admin, test.model)
			if !slices.Equal(got, test.want) {
				t.Fatalf("sourceActions() = %#v, want %#v", got, test.want)
			}
		})
	}

	closedAdmissionRepository := &managementSourceValidationActionRepository{
		managementSourceProfileRepository: profileRepository,
		admit: func(context.Context, Source, SourceRevision) error {
			return ErrUnavailable
		},
	}
	closedAdmissionManager, err := NewManagement(
		baseRepository, baseRepository, closedAdmissionRepository, managementAuthorizer(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	missingAdmissionManager, err := NewManagement(
		baseRepository, baseRepository, profileRepository, managementAuthorizer(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	drifted := draft.Clone()
	drifted.LatestRevision.CanonicalRevisionDigest = strings.Repeat("f", 64)
	degraded := draft.Clone()
	degraded.Source.GateStatus = SourceGateDegraded
	suspended := draft.Clone()
	suspended.Source.GateStatus = SourceGateSuspended

	for _, test := range []struct {
		name    string
		manager *Management
		model   SourceReadModel
	}{
		{name: "registry only stays closed", manager: missingAdmissionManager, model: draft},
		{name: "missing runtime admission stays closed", manager: closedAdmissionManager, model: draft},
		{name: "binding drift stays closed", manager: manager, model: drifted},
		{name: "degraded gate stays closed", manager: manager, model: degraded},
		{name: "suspended gate stays closed", manager: manager, model: suspended},
	} {
		t.Run(test.name, func(t *testing.T) {
			actions := test.manager.sourceActions(t.Context(), admin, test.model)
			if slices.Contains(actions, ActionValidateSourceRevision) ||
				slices.Contains(actions, ActionPublishSourceRevision) ||
				slices.Contains(actions, ActionSyncSource) {
				t.Fatalf("sourceActions() exposed closed runtime action: %#v", actions)
			}
		})
	}

	manualSource, manualRevision := exactManagementManualSourceRevision(t)
	manualActions := missingAdmissionManager.sourceActions(
		t.Context(), admin,
		SourceReadModel{Source: manualSource, LatestRevision: manualRevision},
	)
	if !slices.Contains(manualActions, ActionValidateSourceRevision) {
		t.Fatalf("MANUAL_V1 validation action regressed: %#v", manualActions)
	}
}

func TestSourcePublishAndDisableRequireRecentAuthenticationBeforeRepositoryMutation(t *testing.T) {
	t.Parallel()
	repository := &recordingManagementRepository{
		scope: managementScope(),
		sourceModel: SourceReadModel{
			Source: Source{
				ID: managementSourceID, TenantID: managementTenantID, WorkspaceID: managementWorkspaceID,
				Kind: SourceKindManual, ProviderKind: "MANUAL_V1", Status: SourceStatusActive,
				GateStatus: SourceGateValidating, Version: 3,
			},
			LatestRevision: SourceRevision{
				SourceID: managementSourceID, TenantID: managementTenantID, WorkspaceID: managementWorkspaceID,
				Revision: 1, Status: SourceRevisionValidated, ProfileCode: "MANUAL_V1",
				AuthorityEnvironmentIDs: []string{managementEnvironmentID},
				CanonicalRevisionDigest: strings.Repeat("a", 64), Version: 1,
			},
		},
	}
	manager := mustManagement(t, repository)
	staleAdmin := managementPrincipal(authn.RoleAdmin)
	staleAdmin.AuthenticatedAt = time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	metadata := ServerRequestMetadata{
		TraceID: "source-high-risk-trace", IdempotencyKey: "source-high-risk-1",
		ExpectedVersion: 3, ExpectedRevisionVersion: 1,
	}

	_, err := manager.PublishSourceRevision(
		context.Background(), staleAdmin,
		SourceRevisionPathRequest{
			WorkspaceID: managementWorkspaceID, SourceID: managementSourceID, Revision: 1,
		},
		SourceReasonInput{ReasonCode: "SOURCE_VALIDATED"}, metadata,
	)
	if !errors.Is(err, authz.ErrReauthenticationRequired) {
		t.Fatalf("PublishSourceRevision(stale) error = %v, want reauthentication", err)
	}
	_, err = manager.DisableSource(
		context.Background(), staleAdmin,
		SourcePathRequest{WorkspaceID: managementWorkspaceID, SourceID: managementSourceID},
		SourceReasonInput{ReasonCode: "SOURCE_RETIRED"}, ServerRequestMetadata{
			TraceID: "source-high-risk-trace", IdempotencyKey: "source-high-risk-2",
			ExpectedVersion: 3,
		},
	)
	if !errors.Is(err, authz.ErrReauthenticationRequired) {
		t.Fatalf("DisableSource(stale) error = %v, want reauthentication", err)
	}
	if repository.publishSourceCalls != 0 || repository.disableSourceCalls != 0 {
		t.Fatalf("high-risk repository calls = publish:%d disable:%d, want zero",
			repository.publishSourceCalls, repository.disableSourceCalls)
	}
}

func TestManagementAssetMutationsConstructOpaqueTrustedCommands(t *testing.T) {
	t.Parallel()

	repository := &recordingManagementRepository{
		scope: managementScope(),
		assetResult: AssetMutationResult{Asset: AssetDetailReadModel{
			AssetReadModel: AssetReadModel{Asset: Asset{
				ID: managementAssetID, Scope: managementScope(), Lifecycle: LifecycleActive,
			}},
		}},
	}
	manager := mustManagement(t, repository)
	admin := managementPrincipal(authn.RoleAdmin)
	collection := AssetCollectionRequest{
		WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
	}
	path := AssetPathRequest{
		WorkspaceID: managementWorkspaceID, EnvironmentID: managementEnvironmentID,
		AssetID: managementAssetID,
	}

	if _, err := manager.CreateAsset(
		context.Background(), admin, collection,
		validManagementCreateAssetInput(), validManagementCreateMetadata(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.UpdateAsset(
		context.Background(), admin, path,
		UpdateGovernanceInput{
			DisplayName: "Updated host", Criticality: CriticalityHigh,
			DataClassification: DataClassificationConfidential, Labels: map[string]string{"team": "sre"},
		},
		ServerRequestMetadata{
			TraceID: "trace-update", IdempotencyKey: "update-asset", ExpectedVersion: 1,
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.QuarantineAsset(
		context.Background(), admin, path, TransitionInput{ReasonCode: "SECURITY_REVIEW"},
		ServerRequestMetadata{
			TraceID: "trace-quarantine", IdempotencyKey: "quarantine-asset", ExpectedVersion: 2,
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RetireAsset(
		context.Background(), admin, path, TransitionInput{ReasonCode: "DECOMMISSIONED"},
		ServerRequestMetadata{
			TraceID: "trace-retire", IdempotencyKey: "retire-asset", ExpectedVersion: 3,
		},
	); err != nil {
		t.Fatal(err)
	}

	contexts := []MutationContext{
		repository.lastCreateAsset.Context,
		repository.lastUpdateAsset.Context,
		repository.lastTransitions[0].Context,
		repository.lastTransitions[1].Context,
	}
	hashes := make([]string, len(contexts))
	for index, mutationContext := range contexts {
		scope, ok := mutationContext.EnvironmentScope()
		if !ok || scope != managementScope() ||
			mutationContext.SubjectID() != "principal-subject" ||
			mutationContext.ActorID() != "oidc:principal-subject" {
			t.Fatalf("mutation context %d = %#v, scope=%#v/%t", index, mutationContext, scope, ok)
		}
		hashes[index] = mutationContext.RequestHash()
	}
	sortedHashes := slices.Clone(hashes)
	slices.Sort(sortedHashes)
	if len(slices.Compact(sortedHashes)) != len(hashes) ||
		repository.lastUpdateAsset.ExpectedVersion != 1 ||
		repository.lastTransitions[0].To != LifecycleQuarantined ||
		repository.lastTransitions[1].To != LifecycleRetired {
		t.Fatalf("trusted mutation commands drifted: hashes=%v update=%#v transitions=%#v",
			hashes, repository.lastUpdateAsset, repository.lastTransitions)
	}
}

func mustManagement(t *testing.T, repository *recordingManagementRepository) *Management {
	t.Helper()
	manager, err := NewManagement(repository, repository, repository, managementAuthorizer(t))
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func managementAuthorizer(t *testing.T) *authz.Authorizer {
	t.Helper()
	value, err := authz.NewAuthorizer(5*time.Minute, func() time.Time {
		return time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func managementPrincipal(role authn.Role) authn.Principal {
	return authn.Principal{
		Subject: "principal-subject", TenantID: managementTenantID,
		AuthenticatedAt: time.Date(2026, 7, 16, 9, 59, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 7, 16, 11, 0, 0, 0, time.UTC),
		Roles:           []authn.Role{role},
		WorkspaceIDs:    []string{managementWorkspaceID},
		EnvironmentIDs:  []string{managementEnvironmentID},
		ServiceIDs:      []string{managementServiceID},
	}
}

func managementScope() Scope {
	return Scope{
		TenantID: managementTenantID, WorkspaceID: managementWorkspaceID,
		EnvironmentID: managementEnvironmentID,
	}
}

func exactManagementManualSourceRevision(t *testing.T) (Source, SourceRevision) {
	t.Helper()
	profile := ManualProfileV1()
	source := Source{
		ID: managementSourceID, TenantID: managementTenantID, WorkspaceID: managementWorkspaceID,
		Kind: SourceKindManual, ProviderKind: profile.ProviderKind,
		Status: SourceStatusActive, GateStatus: SourceGateUnavailable,
	}
	revision := SourceRevision{
		SourceID: managementSourceID, TenantID: managementTenantID, WorkspaceID: managementWorkspaceID,
		Revision: 1, Status: SourceRevisionDraft,
		CanonicalProfileManifest:      slices.Clone(profile.CanonicalProfileManifest),
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchema:       slices.Clone(profile.CanonicalProviderSchema),
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 profile.IntegrationID,
		SyncMode:                      profile.SyncMode,
		CredentialReferenceID:         profile.CredentialReferenceID,
		TrustReferenceID:              profile.TrustReferenceID,
		NetworkPolicyReferenceID:      profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:       []string{managementEnvironmentID},
		RateLimitRequests:             profile.RateLimitRequests,
		RateLimitWindowSeconds:        profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        profile.BackpressureMaxSeconds,
		ProfileCode:                   profile.ProfileCode,
		ScheduleExpression:            profile.ScheduleExpression,
		TypedExtensionCode:            profile.TypedExtensionCode,
		PreparedExtensionDigest:       profile.PreparedExtensionDigest,
	}
	var err error
	revision.AuthorityScopeDigest, err = AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	if err != nil {
		t.Fatal(err)
	}
	revision.SourceDefinitionDigest, err = SourceDefinitionDigest(source, revision)
	if err != nil {
		t.Fatal(err)
	}
	revision.CanonicalProfileManifest = nil
	revision.CanonicalProviderSchema = nil
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	if revision.CanonicalRevisionDigest == "" {
		t.Fatal("exact management Source revision has empty BindingDigest")
	}
	return source, revision
}

func exactManagementClosedValidationSourceRevision(
	t *testing.T,
	profileCode ProfileCode,
) (Source, SourceRevision, BuiltinSourceProfile) {
	t.Helper()
	source, revision := validLocallyClosedUninstalledBinding(t)
	previousProfileCode := string(revision.ProfileCode)
	source.ID = managementSourceID
	source.ProviderKind = string(profileCode)
	source.GateStatus = SourceGateUnavailable
	source.GateReasonCode = ""
	source.PublishedRevision = 0
	source.PublishedRevisionDigest = ""
	source.ValidatedRunID = ""
	source.ValidationDigest = ""
	source.ValidatedBindingDigest = ""
	revision.SourceID = source.ID
	revision.Status = SourceRevisionDraft
	revision.ProfileCode = profileCode
	revision.CanonicalProfileManifest = []byte(strings.ReplaceAll(
		string(revision.CanonicalProfileManifest), previousProfileCode, string(profileCode),
	))
	revision.AuthorityEnvironmentIDs = []string{managementEnvironmentID}
	revision.ValidationRunID = ""
	revision.ValidationDigest = ""
	var err error
	revision.ProfileManifestSHA256, err = ProfileManifestDigest(revision.CanonicalProfileManifest)
	if err != nil {
		t.Fatal(err)
	}
	revision.AuthorityScopeDigest, err = AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	if err != nil {
		t.Fatal(err)
	}
	revision.SourceDefinitionDigest, err = SourceDefinitionDigest(source, revision)
	if err != nil {
		t.Fatal(err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	if revision.CanonicalRevisionDigest == "" {
		t.Fatal("exact closed-validation Source revision has empty BindingDigest")
	}
	profile := BuiltinSourceProfile{
		SourceKind: source.Kind, ProviderKind: source.ProviderKind, ProfileCode: revision.ProfileCode,
		SyncMode: revision.SyncMode, FreshnessKind: FreshnessObjectSequence,
		EnvironmentMapping: EnvironmentMappingExplicitItem,
		IntegrationMode:    "NONE", CredentialPurpose: "NONE", TrustMode: "NONE", NetworkMode: "NONE", ScheduleMode: "NONE",
		ParserCode: string(profileCode), CompatibilityClass: string(profileCode), DLPPolicyCode: "ASSET_SAFE_V1",
		MaxPageItems: 100, MaxPageRelations: 0, MaxPageBytes: 1048576, MaxDocumentBytes: 65536,
		TrustedPathCodes:              []string{string(profileCode) + "_DISPLAY_NAME"},
		RelationshipTypes:             []RelationshipType{},
		CanonicalProfileManifest:      slices.Clone(revision.CanonicalProfileManifest),
		CanonicalProviderSchema:       slices.Clone(revision.CanonicalProviderSchema),
		ProfileManifestSHA256:         revision.ProfileManifestSHA256,
		CanonicalProviderSchemaSHA256: revision.CanonicalProviderSchemaSHA256,
		IntegrationID:                 revision.IntegrationID,
		CredentialReferenceID:         revision.CredentialReferenceID,
		TrustReferenceID:              revision.TrustReferenceID,
		NetworkPolicyReferenceID:      revision.NetworkPolicyReferenceID,
		RateLimitRequests:             revision.RateLimitRequests,
		RateLimitWindowSeconds:        revision.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       revision.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        revision.BackpressureMaxSeconds,
		ScheduleExpression:            revision.ScheduleExpression,
		TypedExtensionCode:            revision.TypedExtensionCode,
		PreparedExtensionDigest:       revision.PreparedExtensionDigest,
	}
	revision.CanonicalProfileManifest = nil
	revision.CanonicalProviderSchema = nil
	return source, revision, profile
}

func exactManagementCMDBSourceRevision(
	t *testing.T,
) (Source, SourceRevision, BuiltinSourceProfile) {
	t.Helper()

	const manifest = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":"CMDB_CATALOG_V1","credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_TIME_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":65536,"max_page_bytes":4194304,"max_page_items":500,"max_page_relations":2000,"network_mode":"REQUIRED","parser_code":"CMDB_CATALOG_V1","profile_code":"CMDB_CATALOG_V1","provider_kind":"CMDB_CATALOG_V1","rate_limit_requests":5,"rate_limit_window_seconds":1,"relationship_types":["CONTAINS","DELIVERED_BY","DEPENDS_ON","LOGS_TO","MANAGED_BY","MONITORED_BY","PRIMARY_RUNTIME_FOR","RUNS_ON","TRACES_TO"],"schedule_mode":"NONE","source_kind":"EXTERNAL_CMDB","sync_mode":"ON_DEMAND","trust_mode":"REQUIRED","trusted_path_codes":["CMDB_V1_DISPLAY_NAME","CMDB_V1_ENVIRONMENT_ID","CMDB_V1_EXTERNAL_ID","CMDB_V1_KIND","CMDB_V1_PROVIDER_KIND","CMDB_V1_RELATION","CMDB_V1_TYPE_DETAILS"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
	const schema = `{"additionalProperties":false,"properties":{},"type":"object"}`

	source, revision, _ := exactManagementClosedValidationSourceRevision(
		t, ProfileCode("CMDB_CATALOG_V1"),
	)
	source.Kind = SourceKindExternalCMDB
	source.ProviderKind = "CMDB_CATALOG_V1"
	revision.SyncMode = SyncModeOnDemand
	revision.CanonicalProfileManifest = []byte(manifest)
	revision.CanonicalProviderSchema = []byte(schema)
	revision.IntegrationID = "44444444-4444-4444-8444-444444444444"
	revision.CredentialReferenceID = "55555555-5555-4555-8555-555555555556"
	revision.TrustReferenceID = "66666666-6666-4666-8666-666666666667"
	revision.NetworkPolicyReferenceID = "77777777-7777-4777-8777-777777777778"
	revision.RateLimitRequests = 5
	revision.RateLimitWindowSeconds = 1
	revision.BackpressureBaseSeconds = 1
	revision.BackpressureMaxSeconds = 60
	revision.ScheduleExpression = ""
	revision.TypedExtensionCode = ""
	revision.PreparedExtensionDigest = ""
	var err error
	revision.ProfileManifestSHA256, err = ProfileManifestDigest(revision.CanonicalProfileManifest)
	if err != nil {
		t.Fatal(err)
	}
	revision.CanonicalProviderSchemaSHA256 = testSHA256Hex(revision.CanonicalProviderSchema)
	revision.SourceDefinitionDigest, err = SourceDefinitionDigest(source, revision)
	if err != nil {
		t.Fatal(err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	profile := BuiltinSourceProfile{
		SourceKind: SourceKindExternalCMDB, ProviderKind: "CMDB_CATALOG_V1",
		ProfileCode: ProfileCode("CMDB_CATALOG_V1"), SyncMode: SyncModeOnDemand,
		FreshnessKind: FreshnessObjectTimeSequence, EnvironmentMapping: EnvironmentMappingSingle,
		IntegrationMode: "REQUIRED", CredentialPurpose: "DISCOVERY_READ",
		TrustMode: "REQUIRED", NetworkMode: "REQUIRED", ScheduleMode: "NONE",
		ParserCode: "CMDB_CATALOG_V1", CompatibilityClass: "CMDB_CATALOG_V1",
		DLPPolicyCode: "ASSET_SAFE_V1", MaxPageItems: 500, MaxPageRelations: 2_000,
		MaxPageBytes: 4 << 20, MaxDocumentBytes: 64 << 10,
		TrustedPathCodes: []string{
			"CMDB_V1_DISPLAY_NAME", "CMDB_V1_ENVIRONMENT_ID", "CMDB_V1_EXTERNAL_ID",
			"CMDB_V1_KIND", "CMDB_V1_PROVIDER_KIND", "CMDB_V1_RELATION",
			"CMDB_V1_TYPE_DETAILS",
		},
		RelationshipTypes: []RelationshipType{
			RelationshipContains, RelationshipDeliveredBy, RelationshipDependsOn,
			RelationshipLogsTo, RelationshipManagedBy, RelationshipMonitoredBy,
			RelationshipPrimaryRuntimeFor, RelationshipRunsOn, RelationshipTracesTo,
		},
		CanonicalProfileManifest:      []byte(manifest),
		CanonicalProviderSchema:       []byte(schema),
		ProfileManifestSHA256:         revision.ProfileManifestSHA256,
		CanonicalProviderSchemaSHA256: revision.CanonicalProviderSchemaSHA256,
		IntegrationID:                 revision.IntegrationID,
		CredentialReferenceID:         revision.CredentialReferenceID,
		TrustReferenceID:              revision.TrustReferenceID,
		NetworkPolicyReferenceID:      revision.NetworkPolicyReferenceID,
		RateLimitRequests:             revision.RateLimitRequests,
		RateLimitWindowSeconds:        revision.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       revision.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        revision.BackpressureMaxSeconds,
	}
	registry, err := NewSourceProfileRegistry(SourceProfileRegistration{
		Selector: SourceProfileID("external-cmdb-catalog-v1"),
		Profile:  profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = registry.Resolve(SourceProfileID("external-cmdb-catalog-v1"))
	if err != nil {
		t.Fatal(err)
	}
	revision.CanonicalProfileManifest = nil
	revision.CanonicalProviderSchema = nil
	if !exactInstalledRevisionProfile(source, revision, profile) {
		t.Fatal("exact CMDB management fixture is not an installed-profile match")
	}
	return source, revision, profile
}

type managementSourceProfileResolver map[ProfileCode]BuiltinSourceProfile

func (resolver managementSourceProfileResolver) ResolveProfileAdmission(
	_ context.Context,
	code ProfileCode,
) (BuiltinSourceProfile, error) {
	profile, ok := resolver[code]
	if !ok {
		return BuiltinSourceProfile{}, ErrNotFound
	}
	return profile.Clone(), nil
}

type managementSourceProfileRepository struct {
	*recordingManagementRepository
	profiles managementSourceProfileResolver
}

func (repository *managementSourceProfileRepository) ResolveProfileAdmission(
	ctx context.Context,
	code ProfileCode,
) (BuiltinSourceProfile, error) {
	return repository.profiles.ResolveProfileAdmission(ctx, code)
}

type managementSourceValidationActionRepository struct {
	*managementSourceProfileRepository
	admit func(context.Context, Source, SourceRevision) error
}

func (repository *managementSourceValidationActionRepository) AdmitSourceValidationAction(
	ctx context.Context,
	source Source,
	revision SourceRevision,
) error {
	if repository == nil || repository.admit == nil {
		return ErrUnavailable
	}
	return repository.admit(ctx, source.Clone(), revision.Clone())
}

func validManagementCreateAssetInput() CreateAssetInput {
	return CreateAssetInput{
		SourceID: managementSourceID, Kind: KindLinuxVM,
		ExternalID: "host-1", DisplayName: "Host 1", Criticality: CriticalityMedium,
		DataClassification: DataClassificationInternal, Labels: map[string]string{"team": "platform"},
	}
}

func validManagementCreateMetadata() ServerRequestMetadata {
	return ServerRequestMetadata{TraceID: "trace-create", IdempotencyKey: "create-asset"}
}

type recordingManagementRepository struct {
	scope       Scope
	sourceScope SourceScope

	assetDetail          AssetDetailReadModel
	assetPage            AssetPage
	bindingPage          BindingPage
	conflictPage         ConflictPage
	relationPage         RelationshipPage
	sourcePage           SourcePage
	sourceModel          SourceReadModel
	sourceRun            SourceRun
	sourceRevisionResult SourceRevisionMutation
	sourceMutationResult SourceMutation
	sourceRunResult      SourceRunMutation
	assetResult          AssetMutationResult
	bindingResult        BindingMutationResult
	conflictResult       MappingDecisionResult
	receipt              MutationReceipt

	resolveScopeCalls         int
	resolveSourceScopeCalls   int
	resolveConflictScopeCalls int
	listAssetCalls            int
	getAssetCalls             int
	createAssetCalls          int
	updateAssetCalls          int
	transitionAssetCalls      int
	listRelationshipCalls     int
	listBindingCalls          int
	createBindingCalls        int
	deleteBindingCalls        int
	listConflictCalls         int
	resolveConflictCalls      int
	listSourceCalls           int
	getSourceCalls            int
	getSourceRunCalls         int
	createSourceCalls         int
	createSourceRevisionCalls int
	validateSourceCalls       int
	publishSourceCalls        int
	disableSourceCalls        int
	syncSourceCalls           int

	lastAssetList            ListAssetsRequest
	lastDecision             MappingDecision
	lastCreateAsset          CreateAssetCommand
	lastUpdateAsset          UpdateGovernanceCommand
	lastTransitions          []TransitionCommand
	lastCreateSource         CreateSourceCommand
	lastCreateSourceRevision CreateSourceRevisionCommand
	lastValidateSource       ValidateSourceRevisionCommand
	lastPublishSource        PublishSourceRevisionCommand
	lastDisableSource        DisableSourceCommand
	lastSyncSource           RequestSyncCommand
}

func (repository *recordingManagementRepository) ResolveScope(_ context.Context, workspaceID, environmentID string) (Scope, error) {
	repository.resolveScopeCalls++
	if repository.scope == (Scope{}) {
		repository.scope = managementScope()
	}
	return repository.scope, nil
}

func (repository *recordingManagementRepository) ResolveSourceScope(_ context.Context, workspaceID string) (SourceScope, error) {
	repository.resolveSourceScopeCalls++
	if repository.sourceScope == (SourceScope{}) {
		repository.sourceScope = SourceScope{TenantID: managementTenantID, WorkspaceID: managementWorkspaceID}
	}
	return repository.sourceScope, nil
}

func (repository *recordingManagementRepository) ResolveConflictScope(_ context.Context, workspaceID, conflictID string) (Scope, error) {
	repository.resolveConflictScopeCalls++
	if repository.scope == (Scope{}) {
		repository.scope = managementScope()
	}
	return repository.scope, nil
}

func (repository *recordingManagementRepository) Get(_ context.Context, locator AssetLocator) (Asset, error) {
	return repository.assetDetail.Asset.Clone(), nil
}

func (repository *recordingManagementRepository) GetReadModel(_ context.Context, locator AssetLocator, access AssetReadConstraint) (AssetDetailReadModel, error) {
	repository.getAssetCalls++
	return repository.assetDetail.Clone(), nil
}

func (repository *recordingManagementRepository) List(_ context.Context, request ListAssetsRequest) (AssetPage, error) {
	repository.listAssetCalls++
	repository.lastAssetList = request.Clone()
	return repository.assetPage.Clone(), nil
}

func (repository *recordingManagementRepository) Create(_ context.Context, command CreateAssetCommand) (AssetMutationResult, error) {
	repository.createAssetCalls++
	repository.lastCreateAsset = command.Clone()
	return repository.assetResult.Clone(), nil
}

func (repository *recordingManagementRepository) UpdateGovernance(_ context.Context, command UpdateGovernanceCommand) (AssetMutationResult, error) {
	repository.updateAssetCalls++
	repository.lastUpdateAsset = command.Clone()
	return repository.assetResult.Clone(), nil
}

func (repository *recordingManagementRepository) Transition(_ context.Context, command TransitionCommand) (AssetMutationResult, error) {
	repository.transitionAssetCalls++
	repository.lastTransitions = append(repository.lastTransitions, command)
	return repository.assetResult.Clone(), nil
}

func (repository *recordingManagementRepository) ListRelationships(_ context.Context, request ListRelationshipsRequest) (RelationshipPage, error) {
	repository.listRelationshipCalls++
	return repository.relationPage.Clone(), nil
}

func (repository *recordingManagementRepository) ListBindings(_ context.Context, request ListBindingsRequest) (BindingPage, error) {
	repository.listBindingCalls++
	return repository.bindingPage.Clone(), nil
}

func (repository *recordingManagementRepository) CreateBinding(_ context.Context, command CreateBindingCommand) (BindingMutationResult, error) {
	repository.createBindingCalls++
	return repository.bindingResult.Clone(), nil
}

func (repository *recordingManagementRepository) DeleteBinding(_ context.Context, command DeleteBindingCommand) (MutationReceipt, error) {
	repository.deleteBindingCalls++
	return repository.receipt, nil
}

func (repository *recordingManagementRepository) ListConflicts(_ context.Context, request ListConflictsRequest) (ConflictPage, error) {
	repository.listConflictCalls++
	return repository.conflictPage.Clone(), nil
}

func (repository *recordingManagementRepository) ResolveConflict(_ context.Context, decision MappingDecision) (MappingDecisionResult, error) {
	repository.resolveConflictCalls++
	repository.lastDecision = decision
	return repository.conflictResult.Clone(), nil
}

func (repository *recordingManagementRepository) GetSource(_ context.Context, locator SourceLocator, access SourceReadConstraint) (SourceReadModel, error) {
	repository.getSourceCalls++
	return repository.sourceModel.Clone(), nil
}

func (repository *recordingManagementRepository) ListSources(_ context.Context, request ListSourcesRequest) (SourcePage, error) {
	repository.listSourceCalls++
	return repository.sourcePage.Clone(), nil
}

func (repository *recordingManagementRepository) GetSourceRun(_ context.Context, locator SourceRunLocator, access SourceReadConstraint) (SourceRun, error) {
	repository.getSourceRunCalls++
	return repository.sourceRun.Clone(), nil
}

func (repository *recordingManagementRepository) CreateSource(_ context.Context, command CreateSourceCommand) (SourceRevisionMutation, error) {
	repository.createSourceCalls++
	repository.lastCreateSource = command.Clone()
	return repository.sourceRevisionResult.Clone(), nil
}

func (repository *recordingManagementRepository) CreateRevision(_ context.Context, command CreateSourceRevisionCommand) (SourceRevisionMutation, error) {
	repository.createSourceRevisionCalls++
	repository.lastCreateSourceRevision = command.Clone()
	return repository.sourceRevisionResult.Clone(), nil
}

func (repository *recordingManagementRepository) RequestValidation(_ context.Context, command ValidateSourceRevisionCommand) (SourceRunMutation, error) {
	repository.validateSourceCalls++
	repository.lastValidateSource = command
	return repository.sourceRunResult.Clone(), nil
}

func (repository *recordingManagementRepository) Publish(_ context.Context, command PublishSourceRevisionCommand) (SourceRevisionMutation, error) {
	repository.publishSourceCalls++
	repository.lastPublishSource = command
	return repository.sourceRevisionResult.Clone(), nil
}

func (repository *recordingManagementRepository) Disable(_ context.Context, command DisableSourceCommand) (SourceMutation, error) {
	repository.disableSourceCalls++
	repository.lastDisableSource = command
	return repository.sourceMutationResult.Clone(), nil
}

func (repository *recordingManagementRepository) RequestSync(_ context.Context, command RequestSyncCommand) (SourceRunMutation, error) {
	repository.syncSourceCalls++
	repository.lastSyncSource = command
	return repository.sourceRunResult.Clone(), nil
}
