package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/httpapi"
	"github.com/seaworld008/aiops-system/internal/overview"
)

const (
	overviewTestTenantID      = "81111111-1111-4111-8111-111111111111"
	overviewTestWorkspaceID   = "82222222-2222-4222-8222-222222222222"
	overviewTestEnvironmentID = "83333333-3333-4333-8333-333333333333"
	overviewTestPath          = "/api/v1/workspaces/" + overviewTestWorkspaceID +
		"/environments/" + overviewTestEnvironmentID + "/overview"
)

var overviewTestNow = time.Date(2026, time.July, 18, 9, 0, 0, 0, time.UTC)

func TestOverviewRouteProjectsClosedSafeSnapshotAndStrongDigest(t *testing.T) {
	t.Parallel()
	manager := &recordingOverviewManager{snapshot: overviewHTTPSnapshot()}
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: overviewHTTPPrincipal()},
		Overview:      manager,
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, overviewTestPath, nil))

	if response.Code != http.StatusOK {
		t.Fatalf("GET overview = %d %s", response.Code, response.Body.String())
	}
	if manager.workspaceID != overviewTestWorkspaceID ||
		manager.environmentID != overviewTestEnvironmentID ||
		manager.principal.TenantID != overviewTestTenantID {
		t.Fatalf(
			"manager request = principal:%#v workspace:%q environment:%q",
			manager.principal,
			manager.workspaceID,
			manager.environmentID,
		)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	etag := response.Header().Get("ETag")
	if !strings.HasPrefix(etag, `"overview:`) || !strings.HasSuffix(etag, `"`) ||
		len(etag) != len(`"overview:`)+64+1 {
		t.Fatalf("ETag = %q, want safe strong overview digest", etag)
	}
	if strings.Contains(etag, overviewTestTenantID) ||
		strings.Contains(etag, overviewTestWorkspaceID) ||
		strings.Contains(etag, overviewTestEnvironmentID) {
		t.Fatalf("ETag leaks scope: %q", etag)
	}
	assertControlPlaneResponseHeaders(t, response)

	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	scope, ok := body["scope"].(map[string]any)
	if !ok || len(scope) != 2 ||
		scope["workspace_id"] != overviewTestWorkspaceID ||
		scope["environment_id"] != overviewTestEnvironmentID {
		t.Fatalf("safe scope = %#v", body["scope"])
	}
	sections, ok := body["sections"].(map[string]any)
	if !ok || len(sections) != 6 {
		t.Fatalf("sections = %#v", body["sections"])
	}
	for _, key := range []string{"CONNECTIONS", "INVESTIGATIONS", "ACTIONS", "RELEASES"} {
		section, ok := sections[key].(map[string]any)
		if !ok || section["state"] != string(overview.StateNotStarted) ||
			section["asset_facts"] != nil || section["source_facts"] != nil {
			t.Errorf("%s section = %#v", key, sections[key])
		}
	}
	lower := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		overviewTestTenantID,
		`"tenant_id"`,
		`"external_id"`,
		`"endpoint"`,
		`"credential"`,
		`"checkpoint"`,
		`"lease_`,
		`"fence_`,
		`"provider_error"`,
		"postgres://",
	} {
		if strings.Contains(lower, strings.ToLower(forbidden)) {
			t.Errorf("overview DTO leaked %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestOverviewCrossScopeAndUnknownAreIndistinguishableNotFound(t *testing.T) {
	t.Parallel()
	for _, overviewErr := range []error{
		overview.ErrNotFound,
		fmtWrappedOverviewError(overview.ErrNotFound),
	} {
		manager := &recordingOverviewManager{err: overviewErr}
		response := httptest.NewRecorder()
		httpapi.NewRouter(httpapi.Dependencies{
			Authenticator: fakeAuthenticator{principal: overviewHTTPPrincipal()},
			Overview:      manager,
		}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, overviewTestPath, nil))
		if response.Code != http.StatusNotFound ||
			!strings.Contains(response.Body.String(), `"code":"overview_not_found"`) {
			t.Fatalf("not-found response = %d %s", response.Code, response.Body.String())
		}
		for _, forbidden := range []string{
			overviewTestTenantID,
			overviewTestWorkspaceID,
			overviewTestEnvironmentID,
			"sensitive repository detail",
		} {
			if strings.Contains(strings.ToLower(response.Body.String()), strings.ToLower(forbidden)) {
				t.Errorf("not-found response leaked %q: %s", forbidden, response.Body.String())
			}
		}
	}
}

func TestOverviewErrorsAndMissingDependencyFailClosed(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		manager overview.Manager
		status  int
		code    string
	}{
		"missing": {
			status: http.StatusServiceUnavailable,
			code:   "overview_unavailable",
		},
		"forbidden": {
			manager: &recordingOverviewManager{err: overview.ErrForbidden},
			status:  http.StatusForbidden,
			code:    "overview_forbidden",
		},
		"invalid": {
			manager: &recordingOverviewManager{err: overview.ErrInvalidRequest},
			status:  http.StatusBadRequest,
			code:    "invalid_overview_request",
		},
		"unavailable": {
			manager: &recordingOverviewManager{err: overview.ErrUnavailable},
			status:  http.StatusServiceUnavailable,
			code:    "overview_unavailable",
		},
		"unknown": {
			manager: &recordingOverviewManager{err: errors.New("endpoint=https://private credential=secret")},
			status:  http.StatusInternalServerError,
			code:    "overview_failed",
		},
	}
	for name, test := range cases {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			response := httptest.NewRecorder()
			httpapi.NewRouter(httpapi.Dependencies{
				Authenticator: fakeAuthenticator{principal: overviewHTTPPrincipal()},
				Overview:      test.manager,
			}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, overviewTestPath, nil))
			if response.Code != test.status ||
				!strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body.String(), test.status, test.code)
			}
			for _, forbidden := range []string{"private", "credential", "secret", "endpoint"} {
				if strings.Contains(strings.ToLower(response.Body.String()), forbidden) {
					t.Errorf("problem leaked %q: %s", forbidden, response.Body.String())
				}
			}
		})
	}
}

func overviewHTTPPrincipal() authn.Principal {
	return authn.Principal{
		Subject: "overview-http-user", TenantID: overviewTestTenantID,
		Roles:           []authn.Role{authn.RoleViewer},
		WorkspaceIDs:    []string{overviewTestWorkspaceID},
		EnvironmentIDs:  []string{overviewTestEnvironmentID},
		AuthenticatedAt: overviewTestNow.Add(-time.Minute),
		ExpiresAt:       overviewTestNow.Add(time.Hour),
	}
}

func overviewHTTPSnapshot() overview.Snapshot {
	openConflicts := int64(2)
	staleAssets := int64(1)
	unavailableSources := int64(1)
	degradedSources := int64(1)
	sections := make(map[overview.Feature]overview.Section, len(overview.AllFeatures()))
	sections[overview.FeatureAssets] = overview.Section{
		State: overview.StateAvailable, Code: overview.CodeReady, ObservedAt: overviewTestNow,
		AssetFacts: &overview.AssetFacts{
			ObservedAt: overviewTestNow, Total: 4,
			Lifecycles: []overview.StateCount{
				{State: "DISCOVERED", Count: 1},
				{State: "ACTIVE", Count: 1},
				{State: "STALE", Count: 1},
				{State: "QUARANTINED", Count: 1},
				{State: "RETIRED", Count: 0},
			},
			MappingStatuses: []overview.StateCount{
				{State: "EXACT", Count: 2},
				{State: "AMBIGUOUS", Count: 1},
				{State: "UNRESOLVED", Count: 1},
			},
			StaleCount: staleAssets, OldestStaleAt: overviewTimePointer(overviewTestNow.Add(-time.Hour)),
			OpenConflictCount: openConflicts,
		},
	}
	sections[overview.FeatureSources] = overview.Section{
		State: overview.StateAvailable, Code: overview.CodeReady, ObservedAt: overviewTestNow,
		SourceFacts: &overview.SourceFacts{
			ObservedAt: overviewTestNow, Total: 3,
			Statuses: []overview.StateCount{
				{State: "ACTIVE", Count: 1},
				{State: "PAUSED", Count: 0},
				{State: "DEGRADED", Count: 1},
				{State: "DISABLED", Count: 1},
			},
			RevisionStatuses: []overview.StateCount{
				{State: "DRAFT", Count: 1},
				{State: "VALIDATING", Count: 0},
				{State: "VALIDATED", Count: 0},
				{State: "REJECTED", Count: 0},
				{State: "PUBLISHED", Count: 2},
				{State: "SUPERSEDED", Count: 0},
			},
			GateStatuses: []overview.StateCount{
				{State: "UNAVAILABLE", Count: 1},
				{State: "VALIDATING", Count: 0},
				{State: "AVAILABLE", Count: 1},
				{State: "DEGRADED", Count: 1},
				{State: "SUSPENDED", Count: 0},
			},
			RunStatuses: []overview.StateCount{
				{State: "QUEUED", Count: 0},
				{State: "DELAYED", Count: 0},
				{State: "RUNNING", Count: 1},
				{State: "FINALIZING", Count: 0},
				{State: "SUCCEEDED", Count: 1},
				{State: "PARTIAL", Count: 0},
				{State: "FAILED", Count: 1},
				{State: "CANCELLED", Count: 0},
			},
			BackpressuredCount: 1,
			ProviderGates: []overview.ProviderGateSummary{
				{
					ProviderKind: "MANUAL_V1", GateStatus: assetcatalog.SourceGateAvailable,
					SourceCount: 1, EvidenceAt: overviewTimePointer(overviewTestNow),
				},
				{
					ProviderKind: "VSPHERE_V1", GateStatus: assetcatalog.SourceGateUnavailable,
					SourceCount: 2,
				},
			},
		},
	}
	for _, feature := range []overview.Feature{
		overview.FeatureConnections,
		overview.FeatureInvestigations,
		overview.FeatureActions,
		overview.FeatureReleases,
	} {
		sections[feature] = overview.Section{
			State: overview.StateNotStarted, Code: overview.CodeNotImplemented, ObservedAt: overviewTestNow,
		}
	}
	return overview.Snapshot{
		Scope:       overviewHTTPScope(),
		GeneratedAt: overviewTestNow,
		Sections:    sections,
		WorkQueues: []overview.WorkQueue{
			{Key: overview.QueueOpenConflicts, Section: overview.FeatureAssets, State: overview.StateAvailable, Count: &openConflicts},
			{Key: overview.QueueStaleAssets, Section: overview.FeatureAssets, State: overview.StateAvailable, Count: &staleAssets},
			{Key: overview.QueueUnavailableSources, Section: overview.FeatureSources, State: overview.StateAvailable, Count: &unavailableSources},
			{Key: overview.QueueDegradedSources, Section: overview.FeatureSources, State: overview.StateAvailable, Count: &degradedSources},
		},
		EffectiveActions: []overview.EffectiveAction{overview.ActionViewAssets, overview.ActionViewSources},
	}
}

func overviewTimePointer(value time.Time) *time.Time { return &value }

func overviewHTTPScope() assetcatalog.Scope {
	return assetcatalog.Scope{
		TenantID: overviewTestTenantID, WorkspaceID: overviewTestWorkspaceID, EnvironmentID: overviewTestEnvironmentID,
	}
}

func fmtWrappedOverviewError(err error) error {
	return errors.Join(errors.New("sensitive repository detail"), err)
}

type recordingOverviewManager struct {
	snapshot      overview.Snapshot
	err           error
	principal     authn.Principal
	workspaceID   string
	environmentID string
}

func (manager *recordingOverviewManager) Get(
	_ context.Context,
	principal authn.Principal,
	workspaceID string,
	environmentID string,
) (overview.Snapshot, error) {
	manager.principal = principal
	manager.workspaceID = workspaceID
	manager.environmentID = environmentID
	return manager.snapshot, manager.err
}
