package externalcmdb_test

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

func TestExternalCMDBTask18BReconciliationConsumesExactNeutralDescriptor(t *testing.T) {
	neutral := sourceprofile.ExternalCMDBV1()
	descriptor, err := externalcmdb.NewReconciliationDescriptor(neutral)
	if err != nil {
		t.Fatalf("NewReconciliationDescriptor() error = %v", err)
	}
	if descriptor.DescriptorDigestSHA256() != neutral.DigestSHA256() ||
		descriptor.SourceKind() != assetcatalog.SourceKindExternalCMDB ||
		descriptor.ProviderKind() != "CMDB_CATALOG_V1" ||
		descriptor.ProfileCode() != "CMDB_CATALOG_V1" {
		t.Fatalf("reconciliation identity = %#v", descriptor)
	}
	if descriptor.Limits() != (discoverysource.Limits{
		MaxPageItems: 500, MaxPageRelations: 2000,
		MaxPageBytes: 4 << 20, MaxDocumentBytes: 64 << 10,
	}) {
		t.Fatalf("reconciliation limits = %#v", descriptor.Limits())
	}
	if _, err := externalcmdb.NewReconciliationDescriptor(sourceprofile.ExternalCMDBDescriptor{}); !errors.Is(
		err, externalcmdb.ErrReconciliationRejected,
	) {
		t.Fatalf("zero neutral descriptor error = %v", err)
	}
}

func TestExternalCMDBTask18BFactPolicyIsClosedCompleteAndImmutable(t *testing.T) {
	descriptor := mustExternalCMDBReconciliation(t)
	environmentID := "30000000-0000-4000-8000-000000000301"
	policy, err := descriptor.FactPolicy([]string{environmentID})
	if err != nil {
		t.Fatalf("FactPolicy() error = %v", err)
	}
	if policy.ProviderKind != "CMDB_CATALOG_V1" ||
		policy.FreshnessKind != assetcatalog.FreshnessObjectTimeSequence ||
		policy.EnvironmentMapping != assetcatalog.EnvironmentMappingSingle ||
		!slices.Equal(policy.AuthorityEnvironmentIDs, []string{environmentID}) ||
		!slices.Equal(policy.TrustedPathCodes, externalCMDBTrustedPaths()) ||
		!slices.Equal(policy.RelationshipTypes, externalCMDBRelationshipTypes()) ||
		assetdiscovery.ValidateFacts(nil, nil, policy) != nil {
		t.Fatalf("FactPolicy() = %#v", policy)
	}
	if len(policy.AllowedDocumentFields) != 17 {
		t.Fatalf("allowed asset kinds = %d, want 17", len(policy.AllowedDocumentFields))
	}
	for kind, fields := range policy.AllowedDocumentFields {
		if !kind.Valid() || !slices.Equal(fields, externalCMDBDocumentFields()) {
			t.Fatalf("allowed fields for %q = %v", kind, fields)
		}
	}
	policy.AuthorityEnvironmentIDs[0] = "30000000-0000-4000-8000-000000000399"
	policy.TrustedPathCodes[0] = "DRIFTED"
	policy.RelationshipTypes[0] = assetcatalog.RelationshipRunsOn
	policy.AllowedDocumentFields[assetcatalog.KindService][0] = "drifted"
	again, err := descriptor.FactPolicy([]string{environmentID})
	if err != nil ||
		again.AuthorityEnvironmentIDs[0] != environmentID ||
		again.TrustedPathCodes[0] != "CMDB_V1_DISPLAY_NAME" ||
		again.RelationshipTypes[0] != assetcatalog.RelationshipContains ||
		again.AllowedDocumentFields[assetcatalog.KindService][0] != "architecture" {
		t.Fatalf("FactPolicy() returned shared state: %#v, %v", again, err)
	}

	for _, authorities := range [][]string{
		nil,
		{},
		{"not-a-uuid"},
		{environmentID, "30000000-0000-4000-8000-000000000302"},
	} {
		if policy, err := descriptor.FactPolicy(authorities); policy.ProviderKind != "" ||
			!errors.Is(err, externalcmdb.ErrReconciliationRejected) {
			t.Fatalf("FactPolicy(%v) = (%#v,%v)", authorities, policy, err)
		}
	}
}

func TestExternalCMDBTask18BPagePolicyResolverRejectsEveryRevisionDrift(t *testing.T) {
	descriptor := mustExternalCMDBReconciliation(t)
	revision := externalCMDBRevision(t)
	policy, err := descriptor.ResolvePageFactPolicy(t.Context(), revision)
	if err != nil || policy.ProviderKind != "CMDB_CATALOG_V1" ||
		!slices.Equal(policy.AuthorityEnvironmentIDs, revision.AuthorityEnvironmentIDs) {
		t.Fatalf("ResolvePageFactPolicy(exact) = (%#v,%v)", policy, err)
	}

	tests := []struct {
		name   string
		mutate func(*assetcatalog.SourceRevision)
	}{
		{name: "profile code", mutate: func(value *assetcatalog.SourceRevision) {
			value.ProfileCode = "VSPHERE_VCENTER_V1"
		}},
		{name: "manifest bytes", mutate: func(value *assetcatalog.SourceRevision) {
			value.CanonicalProfileManifest = append([]byte(nil), value.CanonicalProfileManifest...)
			value.CanonicalProfileManifest[0] = '!'
		}},
		{name: "manifest digest", mutate: func(value *assetcatalog.SourceRevision) {
			value.ProfileManifestSHA256 = strings.Repeat("a", 64)
		}},
		{name: "provider schema", mutate: func(value *assetcatalog.SourceRevision) {
			value.CanonicalProviderSchema = []byte(`{"type":"object"}`)
		}},
		{name: "authority", mutate: func(value *assetcatalog.SourceRevision) {
			value.AuthorityEnvironmentIDs = append(
				value.AuthorityEnvironmentIDs,
				"30000000-0000-4000-8000-000000000302",
			)
		}},
		{name: "credential reference", mutate: func(value *assetcatalog.SourceRevision) {
			value.CredentialReferenceID = "drifted-reference"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			drifted := revision.Clone()
			test.mutate(&drifted)
			policy, err := descriptor.ResolvePageFactPolicy(t.Context(), drifted)
			if policy.ProviderKind != "" || !errors.Is(err, externalcmdb.ErrReconciliationRejected) {
				t.Fatalf("ResolvePageFactPolicy(drift) = (%#v,%v)", policy, err)
			}
		})
	}

	if reference, err := descriptor.ResolveCrossEnvironmentRelationPolicy(
		t.Context(),
		revision,
		discoverysource.CrossEnvironmentRelationPolicyCoordinates{
			SourceEnvironmentID: revision.AuthorityEnvironmentIDs[0],
			TargetEnvironmentID: "30000000-0000-4000-8000-000000000302",
			RelationshipType:    assetcatalog.RelationshipDependsOn,
			ProviderPathCode:    "CMDB_V1_RELATION",
		},
	); reference != "" || !errors.Is(err, externalcmdb.ErrReconciliationRejected) {
		t.Fatalf("cross-environment resolution = (%q,%v)", reference, err)
	}
}

func TestExternalCMDBTask18BRuntimeFactoryIsExactAndStartsEmpty(t *testing.T) {
	descriptor := mustExternalCMDBReconciliation(t)
	revision := externalCMDBRevision(t)
	binding := discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID: revision.TenantID, WorkspaceID: revision.WorkspaceID,
			},
			SourceID: revision.SourceID,
		},
		SourceRevision:       revision.Revision,
		SourceRevisionDigest: revision.CanonicalRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionPublished,
		ProviderKind:         "CMDB_CATALOG_V1",
		ProfileCode:          "CMDB_CATALOG_V1",
	}
	provider, err := descriptor.NewProvider(binding)
	if err != nil || provider.Kind() != assetcatalog.SourceKindExternalCMDB ||
		provider.ProviderKind() != "CMDB_CATALOG_V1" {
		t.Fatalf("NewProvider() = (%#v,%v)", provider, err)
	}
	checkpoint, err := descriptor.NewCheckpoint()
	if err != nil || checkpoint.ProfileCode() != "CMDB_CATALOG_V1" || !checkpoint.IsEmpty() {
		t.Fatalf("NewCheckpoint() = (%#v,%v)", checkpoint, err)
	}
	checkpoint.Clear()

	drifted := binding
	drifted.SourceRevisionDigest = strings.Repeat("a", 64)
	drifted.ProviderKind = "VSPHERE_VCENTER_V1"
	if provider, err := descriptor.NewProvider(drifted); provider != nil ||
		!errors.Is(err, externalcmdb.ErrReconciliationRejected) {
		t.Fatalf("NewProvider(drift) = (%#v,%v)", provider, err)
	}
}

func mustExternalCMDBReconciliation(t *testing.T) externalcmdb.ReconciliationDescriptor {
	t.Helper()
	descriptor, err := externalcmdb.NewReconciliationDescriptor(sourceprofile.ExternalCMDBV1())
	if err != nil {
		t.Fatalf("NewReconciliationDescriptor() error = %v", err)
	}
	return descriptor
}

func externalCMDBRevision(t *testing.T) assetcatalog.SourceRevision {
	t.Helper()
	references := sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID:            "40000000-0000-4000-8000-000000000301",
		CredentialReferenceID:    "external-cmdb-read-v1",
		TrustReferenceID:         "external-cmdb-trust-v1",
		NetworkPolicyReferenceID: "external-cmdb-network-v1",
	}
	registration, err := sourceprofile.ExternalCMDBV1().Registration(references)
	if err != nil {
		t.Fatalf("Registration() error = %v", err)
	}
	profile := registration.Profile
	authority := []string{"30000000-0000-4000-8000-000000000301"}
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(authority)
	if err != nil {
		t.Fatalf("AuthorityScopeDigest() error = %v", err)
	}
	revision := assetcatalog.SourceRevision{
		ID:                            "61000000-0000-4000-8000-000000000301",
		SourceID:                      "60000000-0000-4000-8000-000000000301",
		TenantID:                      "10000000-0000-4000-8000-000000000301",
		WorkspaceID:                   "20000000-0000-4000-8000-000000000301",
		Revision:                      1,
		Status:                        assetcatalog.SourceRevisionPublished,
		CanonicalProfileManifest:      profile.CanonicalProfileManifest,
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchema:       profile.CanonicalProviderSchema,
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 profile.IntegrationID,
		SyncMode:                      profile.SyncMode,
		CredentialReferenceID:         profile.CredentialReferenceID,
		TrustReferenceID:              profile.TrustReferenceID,
		NetworkPolicyReferenceID:      profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:       authority,
		AuthorityScopeDigest:          authorityDigest,
		RateLimitRequests:             profile.RateLimitRequests,
		RateLimitWindowSeconds:        profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        profile.BackpressureMaxSeconds,
		ProfileCode:                   profile.ProfileCode,
		ValidationRunID:               "62000000-0000-4000-8000-000000000301",
		ValidationDigest:              strings.Repeat("7", 64),
		CreatedBy:                     "task18b-test",
		ChangeReasonCode:              "INITIAL_CREATE",
		ExpectedSourceVersion:         1,
		Version:                       4,
		CreatedAt:                     time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC),
		UpdatedAt:                     time.Date(2026, 7, 18, 0, 0, 1, 0, time.UTC),
	}
	revision.SourceDefinitionDigest, err = assetcatalog.SourceDefinitionDigest(
		assetcatalog.Source{
			Kind: assetcatalog.SourceKindExternalCMDB, ProviderKind: "CMDB_CATALOG_V1",
		},
		revision,
	)
	if err != nil {
		t.Fatalf("SourceDefinitionDigest() error = %v", err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	if revision.Validate() != nil {
		t.Fatalf("external CMDB revision fixture is invalid: %#v", revision)
	}
	return revision
}

func externalCMDBTrustedPaths() []string {
	return []string{
		"CMDB_V1_DISPLAY_NAME",
		"CMDB_V1_ENVIRONMENT_ID",
		"CMDB_V1_EXTERNAL_ID",
		"CMDB_V1_KIND",
		"CMDB_V1_PROVIDER_KIND",
		"CMDB_V1_RELATION",
		"CMDB_V1_TYPE_DETAILS",
	}
}

func externalCMDBRelationshipTypes() []assetcatalog.RelationshipType {
	return []assetcatalog.RelationshipType{
		assetcatalog.RelationshipContains,
		assetcatalog.RelationshipDeliveredBy,
		assetcatalog.RelationshipDependsOn,
		assetcatalog.RelationshipLogsTo,
		assetcatalog.RelationshipManagedBy,
		assetcatalog.RelationshipMonitoredBy,
		assetcatalog.RelationshipPrimaryRuntimeFor,
		assetcatalog.RelationshipRunsOn,
		assetcatalog.RelationshipTracesTo,
	}
}

func externalCMDBDocumentFields() []string {
	return []string{
		"architecture",
		"cluster_name",
		"cpu_count",
		"database_engine",
		"hostname",
		"memory_mb",
		"name",
		"os_name",
		"os_version",
		"region",
		"resource_class",
		"runtime",
		"version",
		"zone",
	}
}

var (
	_ discoverysource.PageFactPolicyResolver = externalcmdb.ReconciliationDescriptor{}
	_                                        = reflect.TypeOf(externalcmdb.ReconciliationDescriptor{})
)
