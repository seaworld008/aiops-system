package assetcatalog

import (
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

func TestLifecycleAllowsOnlyReviewedTransitions(t *testing.T) {
	t.Parallel()

	lifecycles := []Lifecycle{
		Lifecycle("DISCOVERED"),
		Lifecycle("ACTIVE"),
		Lifecycle("STALE"),
		Lifecycle("QUARANTINED"),
		Lifecycle("RETIRED"),
	}
	reviewed := map[Lifecycle]map[Lifecycle]bool{
		Lifecycle("DISCOVERED"):  {Lifecycle("ACTIVE"): true, Lifecycle("QUARANTINED"): true, Lifecycle("RETIRED"): true},
		Lifecycle("ACTIVE"):      {Lifecycle("STALE"): true, Lifecycle("QUARANTINED"): true, Lifecycle("RETIRED"): true},
		Lifecycle("STALE"):       {Lifecycle("ACTIVE"): true, Lifecycle("QUARANTINED"): true, Lifecycle("RETIRED"): true},
		Lifecycle("QUARANTINED"): {Lifecycle("ACTIVE"): true, Lifecycle("RETIRED"): true},
		Lifecycle("RETIRED"):     {},
	}
	for _, from := range lifecycles {
		for _, to := range lifecycles {
			want := reviewed[from][to]
			got := IsLifecycleEdge(from, to)
			if got != want {
				t.Errorf("IsLifecycleEdge(%q, %q) = %v, want %v", from, to, got, want)
			}
			if from == to && got {
				t.Errorf("self-edge %q was accepted", from)
			}
		}
	}
	for _, invalid := range []Lifecycle{"", "UNKNOWN", "active"} {
		if IsLifecycleEdge(invalid, Lifecycle("ACTIVE")) || IsLifecycleEdge(Lifecycle("ACTIVE"), invalid) {
			t.Errorf("invalid lifecycle %q participated in an edge", invalid)
		}
	}
}

func TestCatalogEligibilityIsOnlyTheLocalAssetProjection(t *testing.T) {
	t.Parallel()

	asset := validAsset()
	lifecycles := []Lifecycle{"DISCOVERED", "ACTIVE", "STALE", "QUARANTINED", "RETIRED", "UNKNOWN"}
	mappings := []domain.MappingStatus{domain.MappingExact, domain.MappingAmbiguous, domain.MappingUnresolved, domain.MappingStatus("UNKNOWN")}
	for _, lifecycle := range lifecycles {
		for _, mapping := range mappings {
			candidate := asset.Clone()
			candidate.Lifecycle = lifecycle
			candidate.MappingStatus = mapping
			want := lifecycle == Lifecycle("ACTIVE") && mapping == domain.MappingExact
			if got := candidate.CatalogEligible(); got != want {
				t.Errorf("CatalogEligible(lifecycle=%q, mapping=%q) = %v, want %v", lifecycle, mapping, got, want)
			}
		}
	}
	invalid := asset.Clone()
	invalid.Version = 0
	if invalid.CatalogEligible() {
		t.Fatal("invalid ACTIVE+EXACT asset was catalog eligible")
	}
}

func TestSourceAvailabilityRequiresCurrentValidatedBinding(t *testing.T) {
	t.Parallel()

	source, revision := validPublishedBinding(t)
	if !source.PublishedBindingEligible(revision) {
		t.Fatal("exact ACTIVE+AVAILABLE published validated binding was rejected")
	}

	tests := map[string]func(*Source, *SourceRevision){
		"source inactive":                func(source *Source, _ *SourceRevision) { source.Status = SourceStatus("PAUSED") },
		"source kind drift":              func(source *Source, _ *SourceRevision) { source.Kind = SourceKind("CSV_IMPORT") },
		"source provider drift":          func(source *Source, _ *SourceRevision) { source.ProviderKind = "OTHER_V1" },
		"gate unavailable":               func(source *Source, _ *SourceRevision) { source.GateStatus = SourceGateStatus("UNAVAILABLE") },
		"gate revision zero":             func(source *Source, _ *SourceRevision) { source.GateRevision = 0 },
		"published revision drift":       func(source *Source, _ *SourceRevision) { source.PublishedRevision++ },
		"published digest drift":         func(source *Source, _ *SourceRevision) { source.PublishedRevisionDigest = testDigestB },
		"validated run missing":          func(source *Source, _ *SourceRevision) { source.ValidatedRunID = "" },
		"validation digest missing":      func(source *Source, _ *SourceRevision) { source.ValidationDigest = "" },
		"validated binding digest drift": func(source *Source, _ *SourceRevision) { source.ValidatedBindingDigest = testDigestB },
		"revision not published":         func(_ *Source, revision *SourceRevision) { revision.Status = SourceRevisionStatus("VALIDATED") },
		"revision tenant drift":          func(_ *Source, revision *SourceRevision) { revision.TenantID = "77777777-7777-4777-8777-777777777777" },
		"revision workspace drift": func(_ *Source, revision *SourceRevision) {
			revision.WorkspaceID = "77777777-7777-4777-8777-777777777777"
		},
		"revision source drift":           func(_ *Source, revision *SourceRevision) { revision.SourceID = "77777777-7777-4777-8777-777777777777" },
		"revision number drift":           func(_ *Source, revision *SourceRevision) { revision.Revision++ },
		"revision canonical digest drift": func(_ *Source, revision *SourceRevision) { revision.CanonicalRevisionDigest = testDigestB },
		"revision manifest bytes drift": func(_ *Source, revision *SourceRevision) {
			revision.CanonicalProfileManifest = []byte(strings.Replace(string(revision.CanonicalProfileManifest), `"max_page_bytes":65536`, `"max_page_bytes":65537`, 1))
		},
		"revision provider schema drift": func(_ *Source, revision *SourceRevision) {
			revision.CanonicalProviderSchema = []byte(`{"additionalProperties":false,"properties":{"safe":{"type":"string"}},"type":"object"}`)
		},
		"revision definition drift":      func(_ *Source, revision *SourceRevision) { revision.SourceDefinitionDigest = testDigestB },
		"revision binding content drift": func(_ *Source, revision *SourceRevision) { revision.RateLimitRequests++ },
		"revision validation run drift": func(_ *Source, revision *SourceRevision) {
			revision.ValidationRunID = "99999999-9999-4999-8999-999999999999"
		},
		"revision validation digest drift": func(_ *Source, revision *SourceRevision) { revision.ValidationDigest = testDigestB },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidateSource := source
			candidateRevision := revision.Clone()
			mutate(&candidateSource, &candidateRevision)
			if candidateSource.PublishedBindingEligible(candidateRevision) {
				t.Fatal("one-field binding drift remained eligible")
			}
		})
	}

	// A known SourceKind alone is only taxonomy. Without the exact loaded row
	// closure it must never imply that a Profile or Adapter is installed.
	for _, kind := range []SourceKind{"MANUAL", "KUBERNETES_OPERATOR", "AWX_INVENTORY"} {
		if (Source{Kind: kind}).PublishedBindingEligible(SourceRevision{}) {
			t.Errorf("SourceKind %q alone implied provider availability", kind)
		}
	}
	// Conversely, this local helper must not smuggle in a registry/support check.
	// A syntactically valid but deliberately uninstalled test profile can close
	// the two loaded rows; production admission must still check external facts.
	uninstalledSource, uninstalledRevision := validLocallyClosedUninstalledBinding(t)
	if !uninstalledSource.PublishedBindingEligible(uninstalledRevision) {
		t.Fatal("PublishedBindingEligible assumed external Profile/Adapter installation")
	}
}

func validPublishedBinding(t *testing.T) (Source, SourceRevision) {
	t.Helper()

	revision := validManualRevision()
	authorityDigest, err := AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	if err != nil {
		t.Fatalf("AuthorityScopeDigest() error = %v", err)
	}
	revision.AuthorityScopeDigest = authorityDigest
	revision.ValidationRunID = "88888888-8888-4888-8888-888888888888"
	revision.ValidationDigest = testDigestA
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	source := Source{
		ID: revision.SourceID, TenantID: revision.TenantID, WorkspaceID: revision.WorkspaceID,
		ProviderKind: "MANUAL_V1", Name: "manual source", Kind: SourceKind("MANUAL"), Status: SourceStatus("ACTIVE"),
		PublishedRevision: revision.Revision, PublishedRevisionDigest: revision.CanonicalRevisionDigest,
		GateStatus: SourceGateStatus("AVAILABLE"), GateRevision: 3,
		ValidatedRunID: revision.ValidationRunID, ValidationDigest: revision.ValidationDigest,
		ValidatedBindingDigest:   revision.CanonicalRevisionDigest,
		CheckpointSourceRevision: revision.Revision,
		Version:                  1, CreatedAt: now, UpdatedAt: now,
	}
	return source, revision
}

func validLocallyClosedUninstalledBinding(t *testing.T) (Source, SourceRevision) {
	t.Helper()

	const manifest = `{"backpressure_base_seconds":2,"backpressure_max_seconds":30,"compatibility_class":"TEST_CSV_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"EXPLICIT_ITEM_ENVIRONMENT","freshness_kind":"OBJECT_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":1048576,"max_page_items":100,"max_page_relations":0,"network_mode":"NONE","parser_code":"TEST_CSV_V1","profile_code":"TEST_CSV_V1","provider_kind":"TEST_CSV_V1","rate_limit_requests":10,"rate_limit_window_seconds":60,"relationship_types":[],"schedule_mode":"NONE","source_kind":"CSV_IMPORT","sync_mode":"ON_DEMAND","trust_mode":"NONE","trusted_path_codes":["TEST_CSV_V1_DISPLAY_NAME"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
	const schema = `{"additionalProperties":false,"properties":{},"type":"object"}`
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	source := Source{
		ID: testSourceID, TenantID: testTenantID, WorkspaceID: testWorkspaceID,
		Kind: SourceKind("CSV_IMPORT"), ProviderKind: "TEST_CSV_V1", Name: "uninstalled test profile", Status: SourceStatus("ACTIVE"),
		GateStatus: SourceGateStatus("AVAILABLE"), GateRevision: 5,
		ValidatedRunID: "88888888-8888-4888-8888-888888888888", ValidationDigest: testDigestA,
		CheckpointSourceRevision: 1,
		Version:                  1, CreatedAt: now, UpdatedAt: now,
	}
	authorityDigest, err := AuthorityScopeDigest([]string{testEnvironmentID})
	if err != nil {
		t.Fatal(err)
	}
	revision := SourceRevision{
		ID: "77777777-7777-4777-8777-777777777777", SourceID: source.ID, TenantID: source.TenantID, WorkspaceID: source.WorkspaceID,
		Revision: 1, Status: SourceRevisionStatus("PUBLISHED"), CanonicalProfileManifest: []byte(manifest), CanonicalProviderSchema: []byte(schema),
		SyncMode: SyncMode("ON_DEMAND"), AuthorityEnvironmentIDs: []string{testEnvironmentID}, AuthorityScopeDigest: authorityDigest,
		RateLimitRequests: 10, RateLimitWindowSeconds: 60, BackpressureBaseSeconds: 2, BackpressureMaxSeconds: 30,
		ProfileCode: ProfileCode("TEST_CSV_V1"), ValidationRunID: source.ValidatedRunID, ValidationDigest: source.ValidationDigest,
		CreatedBy: "oidc:subject-1", ChangeReasonCode: "TEST_FIXTURE", ExpectedSourceVersion: 1, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	revision.ProfileManifestSHA256, err = ProfileManifestDigest(revision.CanonicalProfileManifest)
	if err != nil {
		t.Fatal(err)
	}
	revision.CanonicalProviderSchemaSHA256 = testSHA256Hex(revision.CanonicalProviderSchema)
	revision.SourceDefinitionDigest, err = SourceDefinitionDigest(source, revision)
	if err != nil {
		t.Fatalf("SourceDefinitionDigest(uninstalled profile) error = %v", err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	source.PublishedRevision = revision.Revision
	source.PublishedRevisionDigest = revision.CanonicalRevisionDigest
	source.ValidatedBindingDigest = revision.CanonicalRevisionDigest
	return source, revision
}
