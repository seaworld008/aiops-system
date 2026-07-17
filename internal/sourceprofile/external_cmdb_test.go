package sourceprofile_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const externalCMDBManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":"CMDB_CATALOG_V1","credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_TIME_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":65536,"max_page_bytes":4194304,"max_page_items":500,"max_page_relations":2000,"network_mode":"REQUIRED","parser_code":"CMDB_CATALOG_V1","profile_code":"CMDB_CATALOG_V1","provider_kind":"CMDB_CATALOG_V1","rate_limit_requests":5,"rate_limit_window_seconds":1,"relationship_types":["CONTAINS","DELIVERED_BY","DEPENDS_ON","LOGS_TO","MANAGED_BY","MONITORED_BY","PRIMARY_RUNTIME_FOR","RUNS_ON","TRACES_TO"],"schedule_mode":"NONE","source_kind":"EXTERNAL_CMDB","sync_mode":"ON_DEMAND","trust_mode":"REQUIRED","trusted_path_codes":["CMDB_V1_DISPLAY_NAME","CMDB_V1_ENVIRONMENT_ID","CMDB_V1_EXTERNAL_ID","CMDB_V1_KIND","CMDB_V1_PROVIDER_KIND","CMDB_V1_RELATION","CMDB_V1_TYPE_DETAILS"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`

const externalCMDBDescriptorV1 = `{"profile_code":"CMDB_CATALOG_V1","profile_manifest_sha256":"dc3314265cfad172aff0b9b77616b0f966502964782777216b7f1b8e6742bc28","provider_kind":"CMDB_CATALOG_V1","provider_schema_sha256":"99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa","runtime_binding_requirements":{"cleanup_proof_required":true,"credential_purpose":"DISCOVERY_READ","integration_required":true,"minimum_tls_version":"TLS1.3","network_required":true,"pinned_authority_required":true,"same_attempt_runtime_required":true,"trust_required":true},"selector":"external-cmdb-catalog-v1","source_kind":"EXTERNAL_CMDB","version":"external-cmdb-profile-descriptor.v1"}`

func TestExternalCMDBTask18BNeutralDescriptorIsExactImmutableContract(t *testing.T) {
	descriptor := sourceprofile.ExternalCMDBV1()
	if !descriptor.Valid() ||
		descriptor.Selector() != sourceprofile.ExternalCMDBProfileSelector ||
		descriptor.Selector() != assetcatalog.SourceProfileID("external-cmdb-catalog-v1") ||
		descriptor.SourceKind() != assetcatalog.SourceKindExternalCMDB ||
		descriptor.ProviderKind() != "CMDB_CATALOG_V1" ||
		descriptor.ProfileCode() != assetcatalog.ProfileCode("CMDB_CATALOG_V1") {
		t.Fatalf("ExternalCMDBV1 identity = %#v", descriptor)
	}
	if got := string(descriptor.CanonicalJSON()); got != externalCMDBDescriptorV1 {
		t.Fatalf("canonical descriptor drifted:\n%s", got)
	}
	if descriptor.DigestSHA256() != "04a55074842e641d87ad67c42f1020b9b097ad15c3e781aaeffa3887837fdd08" {
		t.Fatalf("descriptor digest = %q", descriptor.DigestSHA256())
	}

	first := descriptor.CanonicalJSON()
	first[0] = '!'
	if got := string(sourceprofile.ExternalCMDBV1().CanonicalJSON()); got != externalCMDBDescriptorV1 {
		t.Fatal("descriptor returned shared mutable canonical bytes")
	}

	requirements := descriptor.RuntimeBindingRequirements()
	if requirements != (sourceprofile.ExternalCMDBRuntimeBindingRequirements{
		IntegrationRequired:        true,
		CredentialPurpose:          "DISCOVERY_READ",
		TrustRequired:              true,
		NetworkRequired:            true,
		MinimumTLSVersion:          "TLS1.3",
		PinnedAuthorityRequired:    true,
		SameAttemptRuntimeRequired: true,
		CleanupProofRequired:       true,
	}) {
		t.Fatalf("runtime requirements = %#v", requirements)
	}
	requirementType := reflect.TypeOf(requirements)
	for _, forbidden := range []string{
		"Endpoint", "URL", "Header", "Body", "Token", "Secret", "Credential",
		"CredentialReferenceID", "TrustReferenceID", "NetworkPolicyReferenceID",
	} {
		if field, found := requirementType.FieldByName(forbidden); found {
			t.Fatalf("safe runtime requirements expose %s as %#v", forbidden, field)
		}
	}
}

func TestExternalCMDBTask18BRegistrationBindsOnlyOpaqueReferencesAndClones(t *testing.T) {
	descriptor := sourceprofile.ExternalCMDBV1()
	references := validExternalCMDBReferences()
	registration, err := descriptor.Registration(references)
	if err != nil {
		t.Fatalf("Registration() error = %v", err)
	}
	profile := registration.Profile
	if registration.Selector != sourceprofile.ExternalCMDBProfileSelector ||
		profile.SourceKind != assetcatalog.SourceKindExternalCMDB ||
		profile.ProviderKind != "CMDB_CATALOG_V1" ||
		profile.ProfileCode != "CMDB_CATALOG_V1" ||
		profile.IntegrationID != references.IntegrationID ||
		profile.CredentialReferenceID != references.CredentialReferenceID ||
		profile.TrustReferenceID != references.TrustReferenceID ||
		profile.NetworkPolicyReferenceID != references.NetworkPolicyReferenceID {
		t.Fatalf("registration identity/reference closure = %#v", registration)
	}
	if string(profile.CanonicalProfileManifest) != externalCMDBManifestV1 ||
		len(profile.CanonicalProfileManifest) != 1061 ||
		profile.ProfileManifestSHA256 != "dc3314265cfad172aff0b9b77616b0f966502964782777216b7f1b8e6742bc28" ||
		string(profile.CanonicalProviderSchema) != `{"additionalProperties":false,"properties":{},"type":"object"}` ||
		profile.CanonicalProviderSchemaSHA256 != "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa" {
		t.Fatal("registration canonical profile bytes or digest drifted")
	}
	registry, err := assetcatalog.NewSourceProfileRegistry(registration)
	if err != nil {
		t.Fatalf("NewSourceProfileRegistry() error = %v", err)
	}
	bySelector, err := registry.Resolve(sourceprofile.ExternalCMDBProfileSelector)
	if err != nil {
		t.Fatalf("Resolve(selector) error = %v", err)
	}
	byCode, err := registry.ResolveProfileAdmission(t.Context(), "CMDB_CATALOG_V1")
	if err != nil {
		t.Fatalf("ResolveProfileAdmission(code) error = %v", err)
	}
	if !reflect.DeepEqual(bySelector, byCode) {
		t.Fatal("selector and admission registration semantics differ")
	}

	profile.CanonicalProfileManifest[0] = '!'
	profile.CanonicalProviderSchema[0] = '!'
	profile.TrustedPathCodes[0] = "DRIFTED"
	profile.RelationshipTypes[0] = assetcatalog.RelationshipRunsOn
	again, err := descriptor.Registration(references)
	if err != nil ||
		string(again.Profile.CanonicalProfileManifest) != externalCMDBManifestV1 ||
		again.Profile.TrustedPathCodes[0] != "CMDB_V1_DISPLAY_NAME" ||
		again.Profile.RelationshipTypes[0] != assetcatalog.RelationshipContains {
		t.Fatalf("descriptor registration shared mutable state: %#v, %v", again, err)
	}
}

func TestExternalCMDBTask18BRegistrationRejectsReferenceDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sourceprofile.ExternalCMDBProfileReferences)
	}{
		{name: "integration missing", mutate: func(value *sourceprofile.ExternalCMDBProfileReferences) {
			value.IntegrationID = ""
		}},
		{name: "integration malformed", mutate: func(value *sourceprofile.ExternalCMDBProfileReferences) {
			value.IntegrationID = "not-a-uuid"
		}},
		{name: "credential missing", mutate: func(value *sourceprofile.ExternalCMDBProfileReferences) {
			value.CredentialReferenceID = ""
		}},
		{name: "trust missing", mutate: func(value *sourceprofile.ExternalCMDBProfileReferences) {
			value.TrustReferenceID = ""
		}},
		{name: "network missing", mutate: func(value *sourceprofile.ExternalCMDBProfileReferences) {
			value.NetworkPolicyReferenceID = ""
		}},
		{name: "credential shaped like endpoint", mutate: func(value *sourceprofile.ExternalCMDBProfileReferences) {
			value.CredentialReferenceID = "https://cmdb.invalid"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			references := validExternalCMDBReferences()
			test.mutate(&references)
			registration, err := sourceprofile.ExternalCMDBV1().Registration(references)
			if !reflect.DeepEqual(registration, assetcatalog.SourceProfileRegistration{}) ||
				!errors.Is(err, assetcatalog.ErrInvalidRequest) {
				t.Fatalf("Registration(drift) = (%#v,%v), want ErrInvalidRequest", registration, err)
			}
		})
	}
	if registration, err := (sourceprofile.ExternalCMDBDescriptor{}).Registration(
		validExternalCMDBReferences(),
	); !reflect.DeepEqual(registration, assetcatalog.SourceProfileRegistration{}) ||
		!errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("zero descriptor Registration() = (%#v,%v)", registration, err)
	}
}

func validExternalCMDBReferences() sourceprofile.ExternalCMDBProfileReferences {
	return sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID:            "40000000-0000-4000-8000-000000000301",
		CredentialReferenceID:    "external-cmdb-read-v1",
		TrustReferenceID:         "external-cmdb-trust-v1",
		NetworkPolicyReferenceID: "external-cmdb-network-v1",
	}
}
