package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
)

func TestMappingIntegrationConfirmExactIsAtomicAndReplaySafe(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	decision := assetcatalog.MappingDecision{
		Context:    assetMutationContext(t, scope, "mapping-confirm-exact", "1"),
		ConflictID: fixture.conflictID, ServiceID: fixture.serviceID,
		Resolution:      assetcatalog.ConflictResolutionConfirmExact,
		BindingRole:     assetcatalog.BindingRoleDependency,
		ReasonCode:      "HUMAN_CONFIRMED",
		ExpectedVersion: 1,
	}

	first, err := repository.ResolveConflict(context.Background(), decision)
	if err != nil {
		t.Fatalf("ResolveConflict() error = %v", err)
	}
	if first.Conflict.Status != assetcatalog.ConflictStatusResolved ||
		first.Conflict.Resolution != assetcatalog.ConflictResolutionConfirmExact ||
		first.Binding == nil || first.Binding.ServiceID != fixture.serviceID ||
		first.Binding.AssetID != fixture.assetID ||
		first.Binding.Role != assetcatalog.BindingRoleDependency ||
		first.Binding.Status != assetcatalog.BindingStatusActive ||
		first.Receipt.AuditID == "" || first.Receipt.TraceID != decision.Context.TraceID() ||
		first.Receipt.IdempotentReplay {
		t.Fatalf("ResolveConflict() = %#v", first)
	}
	replay, err := repository.ResolveConflict(context.Background(), decision)
	if err != nil {
		t.Fatalf("ResolveConflict(replay) error = %v", err)
	}
	if replay.Binding == nil || replay.Binding.ID != first.Binding.ID ||
		replay.Receipt.AuditID != first.Receipt.AuditID || !replay.Receipt.IdempotentReplay {
		t.Fatalf("ResolveConflict(replay) = %#v, want exact persisted result", replay)
	}
	changed := decision
	changed.ReasonCode = "DIFFERENT_REASON"
	if _, err := repository.ResolveConflict(context.Background(), changed); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("ResolveConflict(changed replay) error = %v, want ErrIdempotency", err)
	}
	changed = decision
	changed.ConflictID = "89000000-0000-4000-8000-000000000001"
	if _, err := repository.ResolveConflict(context.Background(), changed); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("ResolveConflict(changed resource replay) error = %v, want ErrIdempotency", err)
	}

	assertMappingMutationCounts(t, harness, fixture, 1, 1, 1)
}

func TestMappingIntegrationRejectsIneligibleServicesAndRollsBack(t *testing.T) {
	tests := []struct {
		name        string
		seedService func(*testing.T, *assetCatalogHarness, assetCatalogFixture) string
	}{
		{
			name: "same workspace without environment binding",
			seedService: func(t *testing.T, harness *assetCatalogHarness, fixture assetCatalogFixture) string {
				serviceID := "50000000-0000-4000-8000-000000000203"
				execAssetSQL(t, harness.db, `
					INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels)
					VALUES ($1,$2,$3,'unbound-service','fixture-sre','{}')
				`, serviceID, fixture.tenantID, fixture.workspaceID)
				return serviceID
			},
		},
		{
			name: "other tenant service",
			seedService: func(t *testing.T, harness *assetCatalogHarness, fixture assetCatalogFixture) string {
				tenantID := "10000000-0000-4000-8000-000000000299"
				workspaceID := "20000000-0000-4000-8000-000000000299"
				serviceID := "50000000-0000-4000-8000-000000000299"
				execAssetSQL(t, harness.db,
					`INSERT INTO tenants (id,name) VALUES ($1,'other-tenant')`, tenantID)
				execAssetSQL(t, harness.db,
					`INSERT INTO workspaces (id,tenant_id,name) VALUES ($1,$2,'other-workspace')`,
					workspaceID, tenantID)
				execAssetSQL(t, harness.db, `
					INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels)
					VALUES ($1,$2,$3,'other-service','other-sre','{}')
				`, serviceID, tenantID, workspaceID)
				return serviceID
			},
		},
	}
	for index, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedGovernedManualCatalog(t, harness.db)
			serviceID := test.seedService(t, harness, fixture)
			repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
			if err != nil {
				t.Fatal(err)
			}
			scope := assetcatalog.Scope{
				TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
			}
			decision := assetcatalog.MappingDecision{
				Context: assetMutationContext(
					t, scope, fmt.Sprintf("mapping-ineligible-service-%d", index+1), fmt.Sprintf("%d", index+1),
				),
				ConflictID: fixture.conflictID, ServiceID: serviceID,
				Resolution:  assetcatalog.ConflictResolutionConfirmExact,
				BindingRole: assetcatalog.BindingRoleDependency,
				ReasonCode:  "HUMAN_CONFIRMED", ExpectedVersion: 1,
			}
			if _, err := repository.ResolveConflict(
				context.Background(), decision,
			); !errors.Is(err, assetcatalog.ErrScopeViolation) {
				t.Fatalf("ResolveConflict(ineligible service) error = %v, want ErrScopeViolation", err)
			}
			assertMappingMutationCounts(t, harness, fixture, 0, 0, 0)
		})
	}
}

func TestMappingIntegrationRejectsDriftedParentBindingAndRollsBack(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	execAssetSQL(t, harness.db, `
		UPDATE service_bindings
		SET mapping_status='AMBIGUOUS'
		WHERE service_id=$1::uuid AND environment_id=$2::uuid
	`, fixture.serviceID, fixture.environmentID)
	repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	decision := assetcatalog.MappingDecision{
		Context:    assetMutationContext(t, scope, "mapping-drifted-parent", "2"),
		ConflictID: fixture.conflictID, ServiceID: fixture.serviceID,
		Resolution:      assetcatalog.ConflictResolutionConfirmExact,
		BindingRole:     assetcatalog.BindingRoleDependency,
		ReasonCode:      "HUMAN_CONFIRMED",
		ExpectedVersion: 1,
	}

	if _, err := repository.ResolveConflict(context.Background(), decision); !errors.Is(err, assetcatalog.ErrScopeViolation) {
		t.Fatalf("ResolveConflict(drifted parent) error = %v, want ErrScopeViolation", err)
	}
	assertMappingMutationCounts(t, harness, fixture, 0, 0, 0)
}

func TestMappingIntegrationConcurrentConflictDecisionsHaveOneCASWinner(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	decisions := []assetcatalog.MappingDecision{
		{
			Context:    assetMutationContext(t, scope, "mapping-concurrent-a", "3"),
			ConflictID: fixture.conflictID, Resolution: assetcatalog.ConflictResolutionKeepUnresolved,
			ReasonCode: "HUMAN_UNRESOLVED", ExpectedVersion: 1,
		},
		{
			Context:    assetMutationContext(t, scope, "mapping-concurrent-b", "4"),
			ConflictID: fixture.conflictID, Resolution: assetcatalog.ConflictResolutionQuarantineAsset,
			ReasonCode: "SECURITY_REVIEW", ExpectedVersion: 1,
		},
	}

	start := make(chan struct{})
	results := make(chan error, len(decisions))
	for _, decision := range decisions {
		decision := decision
		go func() {
			<-start
			_, callErr := repository.ResolveConflict(context.Background(), decision)
			results <- callErr
		}()
	}
	close(start)
	var successes, conflicts int
	for range decisions {
		switch callErr := <-results; {
		case callErr == nil:
			successes++
		case errors.Is(callErr, assetcatalog.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("ResolveConflict(concurrent) error = %v", callErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes = success:%d conflict:%d, want 1/1", successes, conflicts)
	}
}

func TestMappingIntegrationNonBindingConflictDecisionsPersistExactClosedState(t *testing.T) {
	tests := []struct {
		name          string
		resolution    assetcatalog.ConflictResolution
		wantStatus    assetcatalog.ConflictStatus
		wantMapping   string
		wantLifecycle assetcatalog.Lifecycle
	}{
		{
			name: "reject candidate", resolution: assetcatalog.ConflictResolutionRejectCandidate,
			wantStatus: assetcatalog.ConflictStatusRejected, wantMapping: "UNRESOLVED",
			wantLifecycle: assetcatalog.LifecycleDiscovered,
		},
		{
			name: "keep unresolved", resolution: assetcatalog.ConflictResolutionKeepUnresolved,
			wantStatus: assetcatalog.ConflictStatusResolved, wantMapping: "UNRESOLVED",
			wantLifecycle: assetcatalog.LifecycleDiscovered,
		},
		{
			name: "quarantine asset", resolution: assetcatalog.ConflictResolutionQuarantineAsset,
			wantStatus: assetcatalog.ConflictStatusResolved, wantMapping: "UNRESOLVED",
			wantLifecycle: assetcatalog.LifecycleQuarantined,
		},
	}
	for index, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedGovernedManualCatalog(t, harness.db)
			repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
			if err != nil {
				t.Fatal(err)
			}
			scope := assetcatalog.Scope{
				TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
			}
			decision := assetcatalog.MappingDecision{
				Context: assetMutationContext(
					t, scope, fmt.Sprintf("mapping-nonbinding-%d", index+1), fmt.Sprintf("%d", index+6),
				),
				ConflictID: fixture.conflictID, Resolution: test.resolution,
				ReasonCode: "HUMAN_DECISION", ExpectedVersion: 1,
			}
			first, err := repository.ResolveConflict(context.Background(), decision)
			if err != nil {
				t.Fatalf("ResolveConflict() error = %v", err)
			}
			if first.Conflict.Status != test.wantStatus || first.Conflict.Resolution != test.resolution ||
				first.Binding != nil || first.Receipt.AuditID == "" || first.Receipt.IdempotentReplay {
				t.Fatalf("ResolveConflict() = %#v", first)
			}
			replay, err := repository.ResolveConflict(context.Background(), decision)
			if err != nil {
				t.Fatalf("ResolveConflict(replay) error = %v", err)
			}
			if replay.Receipt.AuditID != first.Receipt.AuditID || !replay.Receipt.IdempotentReplay {
				t.Fatalf("ResolveConflict(replay) = %#v", replay)
			}
			var mapping string
			var lifecycle assetcatalog.Lifecycle
			if err := harness.db.QueryRow(context.Background(), `
				SELECT mapping_status,lifecycle
				FROM assets
				WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
				  AND environment_id=$3::uuid AND id=$4::uuid
			`, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.assetID).Scan(
				&mapping, &lifecycle,
			); err != nil {
				t.Fatal(err)
			}
			if mapping != test.wantMapping || lifecycle != test.wantLifecycle {
				t.Fatalf("asset state = mapping:%s lifecycle:%s, want %s/%s",
					mapping, lifecycle, test.wantMapping, test.wantLifecycle)
			}
			assertMappingMutationCounts(t, harness, fixture, 1, 1, 0)
		})
	}
}

func TestMappingIntegrationListsEnforceServerAccessAndCursorDigest(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	secondServiceID := "50000000-0000-4000-8000-000000000202"
	secondBindingID := "68000000-0000-4000-8000-000000000202"
	seedExactMappingService(t, harness, fixture, secondServiceID)
	seedMappingAccessBinding(t, harness, fixture, secondBindingID, secondServiceID, fixture.secondAssetID)
	repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	empty, err := assetcatalog.NewAssetReadConstraint(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	serviceOne, err := assetcatalog.NewAssetReadConstraint(false, []string{fixture.serviceID})
	if err != nil {
		t.Fatal(err)
	}
	union, err := assetcatalog.NewAssetReadConstraint(false, []string{secondServiceID, fixture.serviceID})
	if err != nil {
		t.Fatal(err)
	}
	unrestricted, err := assetcatalog.NewAssetReadConstraint(true, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, access := range map[string]assetcatalog.AssetReadConstraint{
		"restricted empty": empty,
		"one service":      serviceOne,
	} {
		relationships, err := repository.ListRelationships(context.Background(), assetcatalog.ListRelationshipsRequest{
			Scope: scope, Access: access, Limit: 10,
		})
		if err != nil {
			t.Fatalf("ListRelationships(%s) error = %v", name, err)
		}
		conflicts, err := repository.ListConflicts(context.Background(), assetcatalog.ListConflictsRequest{
			Scope: scope, Access: access, Limit: 10,
		})
		if err != nil {
			t.Fatalf("ListConflicts(%s) error = %v", name, err)
		}
		if len(relationships.Items) != 0 || len(conflicts.Items) != 0 {
			t.Fatalf("%s disclosed relationship/conflict = %d/%d", name, len(relationships.Items), len(conflicts.Items))
		}
	}
	oneServiceBindings, err := repository.ListBindings(context.Background(), assetcatalog.ListBindingsRequest{
		Scope: scope, Access: serviceOne, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(oneServiceBindings.Items) != 1 || oneServiceBindings.Items[0].ID != fixture.bindingID {
		t.Fatalf("one-service bindings = %#v", oneServiceBindings)
	}

	for name, access := range map[string]assetcatalog.AssetReadConstraint{
		"two-service union": union,
		"unrestricted":      unrestricted,
	} {
		relationships, err := repository.ListRelationships(context.Background(), assetcatalog.ListRelationshipsRequest{
			Scope: scope, Access: access, Limit: 10,
		})
		if err != nil {
			t.Fatalf("ListRelationships(%s) error = %v", name, err)
		}
		bindings, err := repository.ListBindings(context.Background(), assetcatalog.ListBindingsRequest{
			Scope: scope, Access: access, Limit: 10,
		})
		if err != nil {
			t.Fatalf("ListBindings(%s) error = %v", name, err)
		}
		conflicts, err := repository.ListConflicts(context.Background(), assetcatalog.ListConflictsRequest{
			Scope: scope, Access: access, Limit: 10,
		})
		if err != nil {
			t.Fatalf("ListConflicts(%s) error = %v", name, err)
		}
		if len(relationships.Items) != 1 || relationships.Items[0].ID != fixture.relationshipID ||
			len(bindings.Items) != 2 || len(conflicts.Items) != 1 ||
			conflicts.Items[0].ID != fixture.conflictID {
			t.Fatalf("%s pages = relationships:%#v bindings:%#v conflicts:%#v",
				name, relationships, bindings, conflicts)
		}
	}

	first, err := repository.ListBindings(context.Background(), assetcatalog.ListBindingsRequest{
		Scope: scope, Access: union, Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 1 || first.Next == nil {
		t.Fatalf("first binding page = %#v, want one item and cursor", first)
	}
	second, err := repository.ListBindings(context.Background(), assetcatalog.ListBindingsRequest{
		Scope: scope, Access: union, Limit: 1, Cursor: first.Next,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].ID == first.Items[0].ID || second.Next != nil {
		t.Fatalf("second binding page = %#v after %#v", second, first)
	}
	if _, err := repository.ListBindings(context.Background(), assetcatalog.ListBindingsRequest{
		Scope: scope, Access: serviceOne, Limit: 1, Cursor: first.Next,
	}); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ListBindings(cursor across access) error = %v, want ErrInvalidRequest", err)
	}

	resolved, err := repository.ResolveConflictScope(context.Background(), fixture.workspaceID, fixture.conflictID)
	if err != nil || resolved != scope {
		t.Fatalf("ResolveConflictScope() = (%#v, %v), want %#v", resolved, err, scope)
	}
	if _, err := repository.ResolveConflictScope(
		context.Background(), "20000000-0000-4000-8000-000000000299", fixture.conflictID,
	); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("ResolveConflictScope(cross workspace) error = %v, want ErrNotFound", err)
	}
}

func TestMappingIntegrationManagementHashesStandaloneBindingCreateDeleteAndReplay(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	secondServiceID := "50000000-0000-4000-8000-000000000202"
	seedExactMappingService(t, harness, fixture, secondServiceID)
	repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	authorizer, err := authz.NewAuthorizer(5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	management, err := assetcatalog.NewManagement(repository, repository, repository, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{
		Subject: "mapping-admin", TenantID: fixture.tenantID,
		AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Roles:          []authn.Role{authn.RoleAdmin},
		WorkspaceIDs:   []string{fixture.workspaceID},
		EnvironmentIDs: []string{fixture.environmentID},
	}
	route := assetcatalog.AssetCollectionRequest{
		WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	createInput := assetcatalog.CreateBindingInput{
		ServiceID: secondServiceID, AssetID: fixture.secondAssetID,
		Role: assetcatalog.BindingRoleManagedTarget, ReasonCode: "MANUAL_BIND",
	}
	createMetadata := assetcatalog.ServerRequestMetadata{
		TraceID: "trace-management-binding-create", IdempotencyKey: "management-binding-create",
	}

	first, err := management.CreateBinding(
		context.Background(), principal, route, createInput, createMetadata,
	)
	if err != nil {
		t.Fatalf("Management.CreateBinding() error = %v", err)
	}
	if first.View.Binding.Status != assetcatalog.BindingStatusActive ||
		first.View.Binding.Version != 1 || first.Receipt.AuditID == "" ||
		first.Receipt.TraceID != createMetadata.TraceID || first.Receipt.IdempotentReplay {
		t.Fatalf("Management.CreateBinding() = %#v", first)
	}
	replay, err := management.CreateBinding(
		context.Background(), principal, route, createInput, createMetadata,
	)
	if err != nil {
		t.Fatalf("Management.CreateBinding(replay) error = %v", err)
	}
	if replay.View.Binding.ID != first.View.Binding.ID ||
		replay.Receipt.AuditID != first.Receipt.AuditID || !replay.Receipt.IdempotentReplay {
		t.Fatalf("Management.CreateBinding(replay) = %#v", replay)
	}
	changedCreate := createInput
	changedCreate.ReasonCode = "DIFFERENT_BIND"
	if _, err := management.CreateBinding(
		context.Background(), principal, route, changedCreate, createMetadata,
	); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("Management.CreateBinding(changed replay) error = %v, want ErrIdempotency", err)
	}
	changedCreate = createInput
	changedCreate.AssetID = "89000000-0000-4000-8000-000000000002"
	if _, err := management.CreateBinding(
		context.Background(), principal, route, changedCreate, createMetadata,
	); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Errorf("Management.CreateBinding(changed resource replay) error = %v, want ErrIdempotency", err)
	}
	assertMappingAuditHashParity(t, harness, first.Receipt.AuditID)

	if _, err := management.DeleteBinding(
		context.Background(), principal,
		assetcatalog.BindingPathRequest{
			WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
			BindingID: first.View.Binding.ID,
		},
		assetcatalog.DeleteBindingInput{ReasonCode: "WRONG_VERSION"},
		assetcatalog.ServerRequestMetadata{
			TraceID:        "trace-management-binding-wrong-version",
			IdempotencyKey: "management-binding-wrong-version", ExpectedVersion: 99,
		},
	); !errors.Is(err, assetcatalog.ErrVersionConflict) {
		t.Fatalf("Management.DeleteBinding(wrong version) error = %v, want ErrVersionConflict", err)
	}

	deleteRoute := assetcatalog.BindingPathRequest{
		WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
		BindingID: first.View.Binding.ID,
	}
	deleteInput := assetcatalog.DeleteBindingInput{ReasonCode: "MANUAL_UNBIND"}
	deleteMetadata := assetcatalog.ServerRequestMetadata{
		TraceID: "trace-management-binding-delete", IdempotencyKey: "management-binding-delete",
		ExpectedVersion: 1,
	}
	deleted, err := management.DeleteBinding(
		context.Background(), principal, deleteRoute, deleteInput, deleteMetadata,
	)
	if err != nil {
		t.Fatalf("Management.DeleteBinding() error = %v", err)
	}
	if deleted.AuditID == "" || deleted.TraceID != deleteMetadata.TraceID || deleted.IdempotentReplay {
		t.Fatalf("Management.DeleteBinding() = %#v", deleted)
	}
	deleteReplay, err := management.DeleteBinding(
		context.Background(), principal, deleteRoute, deleteInput, deleteMetadata,
	)
	if err != nil {
		t.Fatalf("Management.DeleteBinding(replay) error = %v", err)
	}
	if deleteReplay.AuditID != deleted.AuditID || !deleteReplay.IdempotentReplay {
		t.Fatalf("Management.DeleteBinding(replay) = %#v", deleteReplay)
	}
	changedDelete := assetcatalog.DeleteBindingInput{ReasonCode: "DIFFERENT_UNBIND"}
	if _, err := management.DeleteBinding(
		context.Background(), principal, deleteRoute, changedDelete, deleteMetadata,
	); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("Management.DeleteBinding(changed replay) error = %v, want ErrIdempotency", err)
	}
	changedDeleteRoute := deleteRoute
	changedDeleteRoute.BindingID = "89000000-0000-4000-8000-000000000003"
	if _, err := management.DeleteBinding(
		context.Background(), principal, changedDeleteRoute, deleteInput, deleteMetadata,
	); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Errorf("Management.DeleteBinding(changed resource replay) error = %v, want ErrIdempotency", err)
	}
	assertMappingAuditHashParity(t, harness, deleted.AuditID)

	var status string
	var version int64
	var createAudit, createOutbox, deleteAudit, deleteOutbox int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT binding.status,binding.version,
		  (SELECT count(*) FROM audit_records
		   WHERE resource_type='SERVICE_ASSET_BINDING' AND resource_id=binding.id::text
		     AND action='service.asset.binding.created.v1'),
		  (SELECT count(*) FROM outbox_events
		   WHERE aggregate_type='SERVICE_ASSET_BINDING' AND aggregate_id=binding.id
		     AND event_type='service.asset.binding.created.v1'),
		  (SELECT count(*) FROM audit_records
		   WHERE resource_type='SERVICE_ASSET_BINDING' AND resource_id=binding.id::text
		     AND action='service.asset.binding.removed.v1'),
		  (SELECT count(*) FROM outbox_events
		   WHERE aggregate_type='SERVICE_ASSET_BINDING' AND aggregate_id=binding.id
		     AND event_type='service.asset.binding.removed.v1')
		FROM service_asset_bindings AS binding
		WHERE binding.id=$1::uuid
	`, first.View.Binding.ID).Scan(
		&status, &version, &createAudit, &createOutbox, &deleteAudit, &deleteOutbox,
	); err != nil {
		t.Fatal(err)
	}
	if status != string(assetcatalog.BindingStatusInactive) || version != 2 ||
		!slices.Equal(
			[]int{createAudit, createOutbox, deleteAudit, deleteOutbox},
			[]int{1, 1, 1, 1},
		) {
		t.Fatalf("binding closure = status:%s version:%d counts:%d/%d/%d/%d",
			status, version, createAudit, createOutbox, deleteAudit, deleteOutbox)
	}
}

func TestMappingIntegrationStandaloneCreateRejectsNonExactAsset(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	command := assetcatalog.CreateBindingCommand{
		Context:   assetMutationContext(t, scope, "mapping-nonexact-create", "9"),
		ServiceID: fixture.serviceID, AssetID: fixture.secondAssetID,
		Role: assetcatalog.BindingRoleManagedTarget, ReasonCode: "MANUAL_BIND",
	}
	if _, err := repository.CreateBinding(
		context.Background(), command,
	); !errors.Is(err, assetcatalog.ErrStateConflict) {
		t.Fatalf("CreateBinding(non-EXACT asset) error = %v, want ErrStateConflict", err)
	}
	var count int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*)
		FROM service_asset_bindings
		WHERE service_id=$1::uuid AND asset_id=$2::uuid AND binding_role='MANAGED_TARGET'
	`, fixture.serviceID, fixture.secondAssetID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("non-EXACT create left %d binding rows", count)
	}
}

func TestMappingIntegrationOutboxFailureRollsBackBindingAndAudit(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	secondServiceID := "50000000-0000-4000-8000-000000000202"
	seedExactMappingService(t, harness, fixture, secondServiceID)
	execAssetSQL(t, harness.db, `
		SET ROLE aiops_schema_owner;
		CREATE FUNCTION reject_mapping_binding_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.event_type = 'service.asset.binding.created.v1' THEN
				RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='test mapping outbox rejection';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_mapping_binding_outbox
			BEFORE INSERT ON outbox_events FOR EACH ROW EXECUTE FUNCTION reject_mapping_binding_outbox();
		RESET ROLE;
	`)
	repository, err := assetpostgres.New(harness.application, time.Now, mappingIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	command := assetcatalog.CreateBindingCommand{
		Context:   assetMutationContext(t, scope, "mapping-outbox-rollback", "5"),
		ServiceID: secondServiceID, AssetID: fixture.secondAssetID,
		Role: assetcatalog.BindingRoleManagedTarget, ReasonCode: "MANUAL_BIND",
	}
	_, createErr := repository.CreateBinding(context.Background(), command)
	if createErr == nil || createErr.Error() != "asset catalog repository failure" {
		t.Fatalf("CreateBinding(outbox failure) error = %v, want sanitized repository failure", createErr)
	}
	if errors.Is(createErr, assetcatalog.ErrStateConflict) ||
		errors.Is(createErr, assetcatalog.ErrUnavailable) {
		t.Fatalf("CreateBinding(outbox failure) error = %v, must not masquerade as state conflict or unavailable", createErr)
	}
	if strings.Contains(createErr.Error(), "test mapping outbox rejection") ||
		strings.Contains(createErr.Error(), "55000") {
		t.Fatalf("CreateBinding(outbox failure) leaked injected PostgreSQL detail: %v", createErr)
	}
	var bindingCount, auditCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT
		  (SELECT count(*) FROM service_asset_bindings
		   WHERE service_id=$1::uuid AND asset_id=$2::uuid AND binding_role='MANAGED_TARGET'),
		  (SELECT count(*) FROM audit_records WHERE request_id=$3)
	`, secondServiceID, fixture.secondAssetID, command.Context.IdempotencyKey()).Scan(
		&bindingCount, &auditCount,
	); err != nil {
		t.Fatal(err)
	}
	if bindingCount != 0 || auditCount != 0 {
		t.Fatalf("outbox rollback left binding/audit = %d/%d", bindingCount, auditCount)
	}
}

func assertMappingMutationCounts(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	wantAudit int,
	wantOutbox int,
	wantNewBinding int,
) {
	t.Helper()
	var auditCount, outboxCount, bindingCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT
		  (SELECT count(*) FROM audit_records
		   WHERE resource_type='ASSET_CONFLICT' AND resource_id=$1
		     AND action='asset.conflict.resolved.v1'),
		  (SELECT count(*) FROM outbox_events
		   WHERE aggregate_type='ASSET_CONFLICT' AND aggregate_id=$1::uuid
		     AND event_type='asset.conflict.resolved.v1'),
		  (SELECT count(*) FROM service_asset_bindings
		   WHERE tenant_id=$2::uuid AND workspace_id=$3::uuid AND environment_id=$4::uuid
		     AND service_id=$5::uuid AND asset_id=$6::uuid
		     AND binding_role='DEPENDENCY' AND status='ACTIVE')
	`, fixture.conflictID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.serviceID, fixture.assetID).Scan(&auditCount, &outboxCount, &bindingCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != wantAudit || outboxCount != wantOutbox || bindingCount != wantNewBinding {
		t.Fatalf("mapping mutation counts = audit:%d outbox:%d binding:%d, want %d/%d/%d",
			auditCount, outboxCount, bindingCount, wantAudit, wantOutbox, wantNewBinding)
	}
}

func seedExactMappingService(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	serviceID string,
) {
	t.Helper()
	execAssetSQL(t, harness.db, `
		UPDATE assets
		SET mapping_status='EXACT',version=version+1
		WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND environment_id=$3::uuid
		  AND id=$4::uuid
	`, fixture.tenantID, fixture.workspaceID, fixture.environmentID, fixture.secondAssetID)
	execAssetSQL(t, harness.db, `
		INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels)
		VALUES ($1,$2,$3,'fixture-second-service','fixture-sre','{}')
	`, serviceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, harness.db, `
		INSERT INTO service_bindings (
			id,tenant_id,workspace_id,service_id,environment_id,mapping_status
		) VALUES (
			'51000000-0000-4000-8000-000000000202',$1,$2,$3,$4,'EXACT'
		)
	`, fixture.tenantID, fixture.workspaceID, serviceID, fixture.environmentID)
}

func seedMappingAccessBinding(
	t *testing.T,
	harness *assetCatalogHarness,
	fixture assetCatalogFixture,
	bindingID string,
	serviceID string,
	assetID string,
) {
	t.Helper()
	execAssetSQL(t, harness.db, `
		INSERT INTO service_asset_bindings (
			id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,mapping_status,
			provenance,provenance_source_id,status,idempotency_key,request_hash
		) VALUES (
			$1,$2,$3,$4,$5,$6,'DEPENDENCY','EXACT','DISCOVERED',$7,
			'ACTIVE','mapping-access-binding',repeat('c',64)
		)
	`, bindingID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		serviceID, assetID, fixture.sourceID)
}

func assertMappingAuditHashParity(
	t *testing.T,
	harness *assetCatalogHarness,
	auditID string,
) {
	t.Helper()
	var requestHash, semanticHash string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT payload_hash,details->>'command_sha256'
		FROM audit_records
		WHERE id=$1::uuid
	`, auditID).Scan(&requestHash, &semanticHash); err != nil {
		t.Fatal(err)
	}
	if requestHash == "" || requestHash != semanticHash {
		t.Fatalf("management/repository hash parity = request:%q semantic:%q", requestHash, semanticHash)
	}
}

func mappingIDGenerator() func() string {
	var (
		mutex sync.Mutex
		next  = 1
	)
	return func() string {
		mutex.Lock()
		defer mutex.Unlock()
		id := fmt.Sprintf("71000000-0000-4000-8000-%012d", next)
		next++
		return id
	}
}
