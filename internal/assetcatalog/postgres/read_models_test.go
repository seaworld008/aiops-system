package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/domain"
)

func TestAssetReadModelsIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, func() string {
		return "70000000-0000-4000-8000-000000000203"
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	locator := assetcatalog.AssetLocator{Scope: scope, AssetID: fixture.assetID}

	if _, err := repository.GetReadModel(context.Background(), locator, assetcatalog.AssetReadConstraint{}); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("GetReadModel(zero access) error = %v, want ErrInvalidRequest", err)
	}
	denyAll, err := assetcatalog.NewAssetReadConstraint(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetReadModel(context.Background(), locator, denyAll); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("GetReadModel(deny all) error = %v, want ErrNotFound", err)
	}
	allowed, err := assetcatalog.NewAssetReadConstraint(false, []string{fixture.serviceID})
	if err != nil {
		t.Fatal(err)
	}
	detail, err := repository.GetReadModel(context.Background(), locator, allowed)
	if err != nil {
		t.Fatalf("GetReadModel() error = %v", err)
	}
	if detail.Asset.ID != fixture.assetID || len(detail.Services) != 1 || detail.Services[0].ID != fixture.serviceID {
		t.Fatalf("GetReadModel() = %#v, want scoped service binding", detail)
	}
	if detail.Connection.Status != assetcatalog.OperationalSummaryNotConfigured ||
		detail.Capability.Status != assetcatalog.OperationalSummaryNotConfigured || detail.Capability.Count != 0 {
		t.Fatalf("GetReadModel() operational summaries = (%#v, %#v)", detail.Connection, detail.Capability)
	}
	if detail.Relations.Outgoing != 1 || detail.Relations.Incoming != 0 || len(detail.FieldProvenance) != 1 {
		t.Fatalf("GetReadModel() safe detail = provenance:%#v relations:%#v", detail.FieldProvenance, detail.Relations)
	}

	page, err := repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Access: denyAll, Sort: assetcatalog.AssetSortDisplayNameAsc, Limit: 20,
	})
	if err != nil {
		t.Fatalf("List(deny all) error = %v", err)
	}
	if len(page.Items) != 0 || !page.ManualCreateEligible {
		t.Fatalf("List(deny all) = %#v, want empty assets and independent MANUAL eligibility", page)
	}
	page, err = repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Access: allowed, Sort: assetcatalog.AssetSortDisplayNameAsc, Limit: 20,
	})
	if err != nil {
		t.Fatalf("List(allowed service) error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != fixture.assetID || len(page.Items[0].Services) != 1 {
		t.Fatalf("List(allowed service) = %#v, want union constrained asset", page)
	}
	secondServiceID := "50000000-0000-4000-8000-000000000202"
	execAssetSQL(t, harness.db, `
		INSERT INTO services (id,tenant_id,workspace_id,name,owner_group,labels)
		VALUES ($1,$2,$3,'fixture-service-two','fixture-sre','{}')
	`, secondServiceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, harness.db, `
		INSERT INTO service_bindings (id,tenant_id,workspace_id,service_id,environment_id,mapping_status)
		VALUES ('51000000-0000-4000-8000-000000000202',$1,$2,$3,$4,'EXACT')
	`, fixture.tenantID, fixture.workspaceID, secondServiceID, fixture.environmentID)
	execAssetSQL(t, harness.db, `
		INSERT INTO service_asset_bindings (
			id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,mapping_status,
			provenance,provenance_source_id,status,idempotency_key,request_hash
		) VALUES (
			'68000000-0000-4000-8000-000000000202',$1,$2,$3,$4,$5,'DEPENDENCY','EXACT',
			'DISCOVERED',$6,'ACTIVE','binding-create-two',repeat('b',64)
		)
	`, fixture.tenantID, fixture.workspaceID, fixture.environmentID, secondServiceID, fixture.secondAssetID, fixture.sourceID)
	multiService, err := assetcatalog.NewAssetReadConstraint(false, []string{fixture.serviceID, secondServiceID})
	if err != nil {
		t.Fatal(err)
	}
	page, err = repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Access: multiService, Sort: assetcatalog.AssetSortDisplayNameAsc, Limit: 20,
	})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("List(two-service union) = (%#v, %v), want both bound assets", page, err)
	}
	filtered, err := repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope,
		Filter: assetcatalog.AssetFilter{
			Search: "fixture-host", ServiceID: fixture.serviceID,
			Kinds: []assetcatalog.Kind{assetcatalog.KindLinuxVM}, SourceIDs: []string{fixture.sourceID},
			Lifecycles:          []assetcatalog.Lifecycle{assetcatalog.LifecycleDiscovered},
			MappingStatuses:     []domain.MappingStatus{domain.MappingUnresolved},
			Criticalities:       []assetcatalog.Criticality{assetcatalog.CriticalityLow},
			DataClassifications: []assetcatalog.DataClassification{assetcatalog.DataClassificationInternal},
		},
		Access: multiService, Sort: assetcatalog.AssetSortDisplayNameAsc, Limit: 20,
	})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].ID != fixture.assetID {
		t.Fatalf("List(all filters) = (%#v, %v), want exact first asset", filtered, err)
	}
	wildcard, err := repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Filter: assetcatalog.AssetFilter{Search: "%"},
		Access: multiService, Sort: assetcatalog.AssetSortDisplayNameAsc, Limit: 20,
	})
	if err != nil || len(wildcard.Items) != 0 {
		t.Fatalf("List(escaped wildcard) = (%#v, %v), want no literal-percent match", wildcard, err)
	}
	unrestricted, err := assetcatalog.NewAssetReadConstraint(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err = repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Access: unrestricted, Sort: assetcatalog.AssetSortDisplayNameAsc, Limit: 1,
	})
	if err != nil {
		t.Fatalf("List(unrestricted) error = %v", err)
	}
	if len(page.Items) != 1 || page.Next == nil {
		t.Fatalf("List(unrestricted first page) = %#v, want keyset cursor", page)
	}
	second, err := repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Access: unrestricted, Sort: assetcatalog.AssetSortDisplayNameAsc, Limit: 1, Cursor: page.Next,
	})
	if err != nil {
		t.Fatalf("List(cursor) error = %v", err)
	}
	if len(second.Items) != 1 || second.Items[0].ID == page.Items[0].ID || second.Next != nil {
		t.Fatalf("List(cursor) = %#v, want stable second row", second)
	}
	observedPage, err := repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Access: unrestricted, Sort: assetcatalog.AssetSortLastObservedDesc, Limit: 1,
	})
	if err != nil || len(observedPage.Items) != 1 || observedPage.Next == nil {
		t.Fatalf("List(last observed first page) = (%#v, %v)", observedPage, err)
	}
	observedSecond, err := repository.List(context.Background(), assetcatalog.ListAssetsRequest{
		Scope: scope, Access: unrestricted, Sort: assetcatalog.AssetSortLastObservedDesc, Limit: 1,
		Cursor: observedPage.Next,
	})
	if err != nil || len(observedSecond.Items) != 1 || observedSecond.Items[0].ID == observedPage.Items[0].ID {
		t.Fatalf("List(last observed cursor) = (%#v, %v)", observedSecond, err)
	}
	drifted := assetcatalog.ListAssetsRequest{
		Scope: scope, Filter: assetcatalog.AssetFilter{Search: "changed"}, Access: unrestricted,
		Sort: assetcatalog.AssetSortLastObservedDesc, Limit: 1, Cursor: observedPage.Next,
	}
	if _, err := repository.List(context.Background(), drifted); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("List(cursor drift) error = %v, want ErrInvalidRequest", err)
	}
}
