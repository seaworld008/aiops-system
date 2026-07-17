package sourceprofile

import "github.com/seaworld008/aiops-system/internal/assetcatalog"

const (
	ExternalCMDBProfileSelector assetcatalog.SourceProfileID = "external-cmdb-catalog-v1"

	externalCMDBProfileCode  = assetcatalog.ProfileCode("CMDB_CATALOG_V1")
	externalCMDBProviderKind = "CMDB_CATALOG_V1"

	externalCMDBProfileManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":"CMDB_CATALOG_V1","credential_purpose":"DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_TIME_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":65536,"max_page_bytes":4194304,"max_page_items":500,"max_page_relations":2000,"network_mode":"REQUIRED","parser_code":"CMDB_CATALOG_V1","profile_code":"CMDB_CATALOG_V1","provider_kind":"CMDB_CATALOG_V1","rate_limit_requests":5,"rate_limit_window_seconds":1,"relationship_types":["CONTAINS","DELIVERED_BY","DEPENDS_ON","LOGS_TO","MANAGED_BY","MONITORED_BY","PRIMARY_RUNTIME_FOR","RUNS_ON","TRACES_TO"],"schedule_mode":"NONE","source_kind":"EXTERNAL_CMDB","sync_mode":"ON_DEMAND","trust_mode":"REQUIRED","trusted_path_codes":["CMDB_V1_DISPLAY_NAME","CMDB_V1_ENVIRONMENT_ID","CMDB_V1_EXTERNAL_ID","CMDB_V1_KIND","CMDB_V1_PROVIDER_KIND","CMDB_V1_RELATION","CMDB_V1_TYPE_DETAILS"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
	externalCMDBProviderSchemaV1  = `{"additionalProperties":false,"properties":{},"type":"object"}`
	externalCMDBDescriptorV1      = `{"profile_code":"CMDB_CATALOG_V1","profile_manifest_sha256":"dc3314265cfad172aff0b9b77616b0f966502964782777216b7f1b8e6742bc28","provider_kind":"CMDB_CATALOG_V1","provider_schema_sha256":"99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa","runtime_binding_requirements":{"cleanup_proof_required":true,"credential_purpose":"DISCOVERY_READ","integration_required":true,"minimum_tls_version":"TLS1.3","network_required":true,"pinned_authority_required":true,"same_attempt_runtime_required":true,"trust_required":true},"selector":"external-cmdb-catalog-v1","source_kind":"EXTERNAL_CMDB","version":"external-cmdb-profile-descriptor.v1"}`

	externalCMDBProfileManifestSHA256 = "dc3314265cfad172aff0b9b77616b0f966502964782777216b7f1b8e6742bc28"
	externalCMDBProviderSchemaSHA256  = "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa"
	externalCMDBDescriptorSHA256      = "04a55074842e641d87ad67c42f1020b9b097ad15c3e781aaeffa3887837fdd08"
)

type ExternalCMDBRuntimeBindingRequirements struct {
	IntegrationRequired        bool
	CredentialPurpose          string
	TrustRequired              bool
	NetworkRequired            bool
	MinimumTLSVersion          string
	PinnedAuthorityRequired    bool
	SameAttemptRuntimeRequired bool
	CleanupProofRequired       bool
}

type ExternalCMDBProfileReferences struct {
	IntegrationID            string
	CredentialReferenceID    assetcatalog.CredentialReferenceID
	TrustReferenceID         assetcatalog.TrustReferenceID
	NetworkPolicyReferenceID assetcatalog.NetworkPolicyReferenceID
}

type ExternalCMDBDescriptor struct {
	installed bool
}

func ExternalCMDBV1() ExternalCMDBDescriptor {
	return ExternalCMDBDescriptor{installed: true}
}

func (descriptor ExternalCMDBDescriptor) Valid() bool {
	return descriptor.installed
}

func (descriptor ExternalCMDBDescriptor) Selector() assetcatalog.SourceProfileID {
	if !descriptor.Valid() {
		return ""
	}
	return ExternalCMDBProfileSelector
}

func (descriptor ExternalCMDBDescriptor) SourceKind() assetcatalog.SourceKind {
	if !descriptor.Valid() {
		return ""
	}
	return assetcatalog.SourceKindExternalCMDB
}

func (descriptor ExternalCMDBDescriptor) ProviderKind() string {
	if !descriptor.Valid() {
		return ""
	}
	return externalCMDBProviderKind
}

func (descriptor ExternalCMDBDescriptor) ProfileCode() assetcatalog.ProfileCode {
	if !descriptor.Valid() {
		return ""
	}
	return externalCMDBProfileCode
}

func (descriptor ExternalCMDBDescriptor) CanonicalJSON() []byte {
	if !descriptor.Valid() {
		return nil
	}
	return []byte(externalCMDBDescriptorV1)
}

func (descriptor ExternalCMDBDescriptor) DigestSHA256() string {
	if !descriptor.Valid() {
		return ""
	}
	return externalCMDBDescriptorSHA256
}

func (descriptor ExternalCMDBDescriptor) RuntimeBindingRequirements() ExternalCMDBRuntimeBindingRequirements {
	if !descriptor.Valid() {
		return ExternalCMDBRuntimeBindingRequirements{}
	}
	return ExternalCMDBRuntimeBindingRequirements{
		IntegrationRequired:        true,
		CredentialPurpose:          "DISCOVERY_READ",
		TrustRequired:              true,
		NetworkRequired:            true,
		MinimumTLSVersion:          "TLS1.3",
		PinnedAuthorityRequired:    true,
		SameAttemptRuntimeRequired: true,
		CleanupProofRequired:       true,
	}
}

func (descriptor ExternalCMDBDescriptor) Registration(
	references ExternalCMDBProfileReferences,
) (assetcatalog.SourceProfileRegistration, error) {
	if !descriptor.Valid() ||
		references.IntegrationID == "" ||
		!references.CredentialReferenceID.Valid() ||
		!references.TrustReferenceID.Valid() ||
		!references.NetworkPolicyReferenceID.Valid() {
		return assetcatalog.SourceProfileRegistration{}, assetcatalog.ErrInvalidRequest
	}
	registration := assetcatalog.SourceProfileRegistration{
		Selector: ExternalCMDBProfileSelector,
		Profile: assetcatalog.BuiltinSourceProfile{
			SourceKind:                    assetcatalog.SourceKindExternalCMDB,
			ProviderKind:                  externalCMDBProviderKind,
			ProfileCode:                   externalCMDBProfileCode,
			SyncMode:                      assetcatalog.SyncModeOnDemand,
			FreshnessKind:                 assetcatalog.FreshnessObjectTimeSequence,
			EnvironmentMapping:            assetcatalog.EnvironmentMappingSingle,
			IntegrationMode:               "REQUIRED",
			CredentialPurpose:             "DISCOVERY_READ",
			TrustMode:                     "REQUIRED",
			NetworkMode:                   "REQUIRED",
			ScheduleMode:                  "NONE",
			ParserCode:                    externalCMDBProviderKind,
			CompatibilityClass:            externalCMDBProviderKind,
			DLPPolicyCode:                 "ASSET_SAFE_V1",
			MaxPageItems:                  500,
			MaxPageRelations:              2_000,
			MaxPageBytes:                  4 << 20,
			MaxDocumentBytes:              64 << 10,
			TrustedPathCodes:              externalCMDBTrustedPathCodes(),
			RelationshipTypes:             externalCMDBRelationshipTypes(),
			CanonicalProfileManifest:      []byte(externalCMDBProfileManifestV1),
			CanonicalProviderSchema:       []byte(externalCMDBProviderSchemaV1),
			ProfileManifestSHA256:         externalCMDBProfileManifestSHA256,
			CanonicalProviderSchemaSHA256: externalCMDBProviderSchemaSHA256,
			IntegrationID:                 references.IntegrationID,
			CredentialReferenceID:         references.CredentialReferenceID,
			TrustReferenceID:              references.TrustReferenceID,
			NetworkPolicyReferenceID:      references.NetworkPolicyReferenceID,
			RateLimitRequests:             5,
			RateLimitWindowSeconds:        1,
			BackpressureBaseSeconds:       1,
			BackpressureMaxSeconds:        60,
		},
	}
	if _, err := assetcatalog.NewSourceProfileRegistry(registration); err != nil {
		return assetcatalog.SourceProfileRegistration{}, assetcatalog.ErrInvalidRequest
	}
	return registration, nil
}

func externalCMDBTrustedPathCodes() []string {
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
