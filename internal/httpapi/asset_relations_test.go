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

const assetRelationTestID = "88888888-8888-4888-8888-888888888888"

func TestAssetRelationRouteParsesClosedFiltersAndProjectsSafeCoordinates(t *testing.T) {
	t.Parallel()
	manager := &recordingRelationshipManager{page: assetcatalog.RelationshipViewPage{
		Items: []assetcatalog.Relationship{safeRelationship()},
	}}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:  fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetRelations: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	path := "/api/v1/workspaces/" + assetTestWorkspaceID + "/environments/" +
		assetTestEnvironmentID + "/asset-relations?asset_id=" + assetTestAssetID +
		"&types=RUNS_ON,DEPENDS_ON&statuses=ACTIVE&limit=20"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET relations = %d %s", response.Code, response.Body.String())
	}
	if manager.collection.WorkspaceID != assetTestWorkspaceID ||
		manager.collection.EnvironmentID != assetTestEnvironmentID ||
		manager.input.AssetID != assetTestAssetID || manager.input.Limit != 20 ||
		len(manager.input.Types) != 2 || len(manager.input.Statuses) != 1 {
		t.Fatalf("manager request = %#v %#v", manager.collection, manager.input)
	}
	body := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		"from_external_id", "to_external_id", "canonical_revision_digest",
		"provider_path_code", "cross_environment_policy_reference_id",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("relation response contains %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(response.Body.String(), `"relation_fact_sha256"`) ||
		!strings.Contains(response.Body.String(), `"run_fence_epoch":4`) {
		t.Fatalf("relation response = %s", response.Body.String())
	}
}

func TestAssetRelationRouteRejectsDuplicateUnknownAndMissingDependencies(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + assetTestWorkspaceID + "/environments/" +
		assetTestEnvironmentID + "/asset-relations"
	for _, query := range []string{
		"?unknown=value",
		"?limit=1&limit=2",
		"?asset_id=not-a-uuid",
		"?types=RUNS_ON,UNKNOWN",
	} {
		manager := &recordingRelationshipManager{}
		response := httptest.NewRecorder()
		httpapi.NewRouter(httpapi.Dependencies{
			Authenticator:  fakeAuthenticator{principal: assetHTTPPrincipal()},
			AssetRelations: manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
		}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, base+query, nil))
		if response.Code != http.StatusBadRequest || manager.collection.WorkspaceID != "" {
			t.Errorf("%s response/request = %d %s / %#v", query, response.Code, response.Body.String(), manager.collection)
		}
	}

	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, base, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager response = %d %s", response.Code, response.Body.String())
	}
}

type recordingRelationshipManager struct {
	page       assetcatalog.RelationshipViewPage
	err        error
	collection assetcatalog.AssetCollectionRequest
	input      assetcatalog.RelationshipListInput
}

func (manager *recordingRelationshipManager) ListRelationships(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.AssetCollectionRequest,
	input assetcatalog.RelationshipListInput,
) (assetcatalog.RelationshipViewPage, error) {
	manager.collection, manager.input = collection, input
	return manager.page, manager.err
}

func safeRelationship() assetcatalog.Relationship {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	return assetcatalog.Relationship{
		ID: assetRelationTestID, SourceID: assetTestSourceID,
		CanonicalRevisionDigest: strings.Repeat("a", 64),
		LastRunID:               "99999999-9999-4999-8999-999999999999",
		SourceScope: assetcatalog.SourceScope{
			TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
		},
		SourceRevision: 1, LastPageSequence: 3, AcceptedCheckpointVersion: 2, RunFenceEpoch: 4,
		RelationPageSHA256:  strings.Repeat("b", 64),
		SourceEnvironmentID: assetTestEnvironmentID,
		TargetEnvironmentID: assetTestEnvironmentID,
		SourceAssetID:       assetTestAssetID,
		TargetAssetID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		FromExternalID:      "hidden-source", ToExternalID: "hidden-target",
		Type: assetcatalog.RelationshipRunsOn, ProviderPathCode: "hidden.path", Confidence: 100,
		FreshnessKind:          assetcatalog.FreshnessCatalogSequence,
		FreshnessOrderSequence: 2, ProviderVersionSHA256: strings.Repeat("c", 64),
		RelationFactSHA256: strings.Repeat("d", 64), Provenance: assetcatalog.ProvenanceDiscovered,
		CrossEnvironmentPolicyReferenceID: assetcatalog.PolicyReferenceID("opaque-policy-reference"),
		Status:                            assetcatalog.RelationshipStatusActive, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

var _ assetcatalog.RelationshipManager = (*recordingRelationshipManager)(nil)
