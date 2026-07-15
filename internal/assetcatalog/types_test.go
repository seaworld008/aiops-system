package assetcatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	testTenantID      = "11111111-1111-4111-8111-111111111111"
	testWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	testSourceID      = "33333333-3333-4333-8333-333333333333"
	testEnvironmentID = "44444444-4444-4444-8444-444444444444"
	testAssetID       = "55555555-5555-4555-8555-555555555555"
	testServiceID     = "66666666-6666-4666-8666-666666666666"
	testLetteredUUID  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testDigestA       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

const manualProfileManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":1,"compatibility_class":"MANUAL_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CATALOG_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":65536,"max_page_items":1,"max_page_relations":0,"network_mode":"NONE","parser_code":"MANUAL_ASSET_V1","profile_code":"MANUAL_V1","provider_kind":"MANUAL_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":[],"schedule_mode":"NONE","source_kind":"MANUAL","sync_mode":"MANUAL","trust_mode":"NONE","trusted_path_codes":["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
const manualProviderSchemaV1 = `{"additionalProperties":false,"properties":{},"type":"object"}`

func TestExactEnumVocabularyAndUnknownsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		valid  func(string) bool
	}{
		{"Kind", strings.Fields("SERVICE LINUX_VM WINDOWS_VM BARE_METAL_HOST KUBERNETES_CLUSTER KUBERNETES_NAMESPACE KUBERNETES_WORKLOAD DATABASE_INSTANCE DATABASE METRICS_SOURCE LOG_SOURCE TRACE_SOURCE AWX_INVENTORY ARGO_APPLICATION CI_PIPELINE GIT_REPOSITORY CLOUD_RESOURCE"), func(value string) bool { return Kind(value).Valid() }},
		{"SourceKind", strings.Fields("MANUAL CSV_IMPORT CONTROL_PLANE_API EXTERNAL_CMDB VSPHERE PROXMOX OPENSTACK CLOUD_PROVIDER KUBERNETES_OPERATOR AWX_INVENTORY"), func(value string) bool { return SourceKind(value).Valid() }},
		{"SourceStatus", strings.Fields("ACTIVE PAUSED DEGRADED DISABLED"), func(value string) bool { return SourceStatus(value).Valid() }},
		{"SourceGateStatus", strings.Fields("UNAVAILABLE VALIDATING AVAILABLE DEGRADED SUSPENDED"), func(value string) bool { return SourceGateStatus(value).Valid() }},
		{"SourceRevisionStatus", strings.Fields("DRAFT VALIDATING VALIDATED REJECTED PUBLISHED SUPERSEDED"), func(value string) bool { return SourceRevisionStatus(value).Valid() }},
		{"SyncMode", strings.Fields("MANUAL ON_DEMAND SCHEDULED"), func(value string) bool { return SyncMode(value).Valid() }},
		{"RunKind", strings.Fields("VALIDATION DISCOVERY CSV_IMPORT API_INGESTION MANUAL_MUTATION"), func(value string) bool { return RunKind(value).Valid() }},
		{"RunStatus", strings.Fields("QUEUED DELAYED RUNNING FINALIZING SUCCEEDED PARTIAL FAILED CANCELLED"), func(value string) bool { return RunStatus(value).Valid() }},
		{"RunStage", strings.Fields("WAITING DELAYED VALIDATING READING NORMALIZING APPLYING CLEANING_UP COMPLETED"), func(value string) bool { return RunStage(value).Valid() }},
		{"TriggerType", strings.Fields("HUMAN API SCHEDULED"), func(value string) bool { return TriggerType(value).Valid() }},
		{"WorkResultKind", strings.Fields("DATA_PROJECTION VALIDATION_PROOF FAILURE_INTENT"), func(value string) bool { return WorkResultKind(value).Valid() }},
		{"WorkResultStatus", strings.Fields("SUCCEEDED PARTIAL FAILED"), func(value string) bool { return WorkResultStatus(value).Valid() }},
		{"ValidationOutcome", strings.Fields("SUCCEEDED FAILED"), func(value string) bool { return ValidationOutcome(value).Valid() }},
		{"CredentialCleanupStatus", strings.Fields("NOT_OPENED PENDING REVOKED NO_CREDENTIAL UNCERTAIN"), func(value string) bool { return CredentialCleanupStatus(value).Valid() }},
		{"FreshnessKind", strings.Fields("CATALOG_SEQUENCE OBJECT_SEQUENCE OBJECT_TIME_SEQUENCE CHECKPOINT_SEQUENCE"), func(value string) bool { return FreshnessKind(value).Valid() }},
		{"Lifecycle", strings.Fields("DISCOVERED ACTIVE STALE QUARANTINED RETIRED"), func(value string) bool { return Lifecycle(value).Valid() }},
		{"Criticality", strings.Fields("LOW MEDIUM HIGH CRITICAL"), func(value string) bool { return Criticality(value).Valid() }},
		{"DataClassification", strings.Fields("PUBLIC INTERNAL CONFIDENTIAL RESTRICTED"), func(value string) bool { return DataClassification(value).Valid() }},
		{"RelationshipType", strings.Fields("RUNS_ON CONTAINS DEPENDS_ON MONITORED_BY LOGS_TO TRACES_TO DELIVERED_BY MANAGED_BY PRIMARY_RUNTIME_FOR"), func(value string) bool { return RelationshipType(value).Valid() }},
		{"RelationshipStatus", strings.Fields("ACTIVE INACTIVE"), func(value string) bool { return RelationshipStatus(value).Valid() }},
		{"BindingRole", strings.Fields("PRIMARY_RUNTIME DEPENDENCY OBSERVABILITY_SOURCE DELIVERY_TARGET MANAGED_TARGET"), func(value string) bool { return BindingRole(value).Valid() }},
		{"BindingStatus", strings.Fields("ACTIVE INACTIVE"), func(value string) bool { return BindingStatus(value).Valid() }},
		{"Provenance", strings.Fields("MANUAL DISCOVERED MERGE_DECISION"), func(value string) bool { return Provenance(value).Valid() }},
		{"ConflictStatus", strings.Fields("OPEN RESOLVED REJECTED"), func(value string) bool { return ConflictStatus(value).Valid() }},
		{"ConflictResolution", strings.Fields("CONFIRM_EXACT REJECT_CANDIDATE KEEP_UNRESOLVED QUARANTINE_ASSET"), func(value string) bool { return ConflictResolution(value).Valid() }},
		{"EnvironmentMappingMode", strings.Fields("SINGLE_ENVIRONMENT EXPLICIT_ITEM_ENVIRONMENT"), func(value string) bool { return EnvironmentMappingMode(value).Valid() }},
		{"FieldOwnership", strings.Fields("SOURCE GOVERNANCE MERGE_DECISION"), func(value string) bool { return FieldOwnership(value).Valid() }},
		{"AssetSort", strings.Fields("display_name_asc last_observed_at_desc"), func(value string) bool { return AssetSort(value).Valid() }},
		{"SourceUsage", strings.Fields("manual_asset_create"), func(value string) bool { return SourceUsage(value).Valid() }},
		{"OperationalSummaryStatus", strings.Fields("NOT_CONFIGURED"), func(value string) bool { return OperationalSummaryStatus(value).Valid() }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, value := range test.values {
				if !test.valid(value) {
					t.Errorf("%s(%q).Valid() = false", test.name, value)
				}
			}
			unknowns := []string{"", "UNKNOWN", "FUTURE_VALUE", "RESERVED", test.values[0] + " ", test.values[0] + "_V2"}
			if lowercase := strings.ToLower(test.values[0]); lowercase != test.values[0] {
				unknowns = append(unknowns, lowercase)
			}
			if uppercase := strings.ToUpper(test.values[0]); uppercase != test.values[0] {
				unknowns = append(unknowns, uppercase)
			}
			for _, unknown := range unknowns {
				if test.valid(unknown) {
					t.Errorf("%s(%q).Valid() = true, want fail closed", test.name, unknown)
				}
			}
		})
	}
	if EnvironmentMappingSingle != EnvironmentMappingMode("SINGLE_ENVIRONMENT") ||
		EnvironmentMappingExplicitItem != EnvironmentMappingMode("EXPLICIT_ITEM_ENVIRONMENT") {
		t.Fatalf("EnvironmentMappingMode constants drifted: %q/%q", EnvironmentMappingSingle, EnvironmentMappingExplicitItem)
	}
	if EnvironmentMappingMode("MULTI_ENVIRONMENT").Valid() {
		t.Fatal("legacy MULTI_ENVIRONMENT remained a valid or aliased EnvironmentMappingMode")
	}
}

func TestRepositoryInterfacesAreReadSafeAndDoNotPreemptSourceLifecycle(t *testing.T) {
	t.Parallel()

	assertExactInterface(t, reflect.TypeOf((*Reader)(nil)).Elem(), reflect.TypeOf((*interface {
		Get(context.Context, AssetLocator) (Asset, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*ScopeResolver)(nil)).Elem(), reflect.TypeOf((*interface {
		ResolveScope(context.Context, string, string) (Scope, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*SourceScopeResolver)(nil)).Elem(), reflect.TypeOf((*interface {
		ResolveSourceScope(context.Context, string) (SourceScope, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*ConflictScopeResolver)(nil)).Elem(), reflect.TypeOf((*interface {
		ResolveConflictScope(context.Context, string, string) (Scope, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*AssetReadRepository)(nil)).Elem(), reflect.TypeOf((*interface {
		GetReadModel(context.Context, AssetLocator, AssetReadConstraint) (AssetDetailReadModel, error)
		List(context.Context, ListAssetsRequest) (AssetPage, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*Repository)(nil)).Elem(), reflect.TypeOf((*interface {
		Get(context.Context, AssetLocator) (Asset, error)
		GetReadModel(context.Context, AssetLocator, AssetReadConstraint) (AssetDetailReadModel, error)
		List(context.Context, ListAssetsRequest) (AssetPage, error)
		ResolveScope(context.Context, string, string) (Scope, error)
		Create(context.Context, CreateAssetCommand) (AssetMutationResult, error)
		UpdateGovernance(context.Context, UpdateGovernanceCommand) (AssetMutationResult, error)
		Transition(context.Context, TransitionCommand) (AssetMutationResult, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*MappingRepository)(nil)).Elem(), reflect.TypeOf((*interface {
		ResolveConflictScope(context.Context, string, string) (Scope, error)
		ListRelationships(context.Context, ListRelationshipsRequest) (RelationshipPage, error)
		ListBindings(context.Context, ListBindingsRequest) (BindingPage, error)
		CreateBinding(context.Context, CreateBindingCommand) (BindingMutationResult, error)
		DeleteBinding(context.Context, DeleteBindingCommand) (MutationReceipt, error)
		ListConflicts(context.Context, ListConflictsRequest) (ConflictPage, error)
		ResolveConflict(context.Context, MappingDecision) (MappingDecisionResult, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*SourceReadRepository)(nil)).Elem(), reflect.TypeOf((*interface {
		ResolveSourceScope(context.Context, string) (SourceScope, error)
		GetSource(context.Context, SourceLocator, SourceReadConstraint) (SourceReadModel, error)
		ListSources(context.Context, ListSourcesRequest) (SourcePage, error)
		GetSourceRun(context.Context, SourceRunLocator, SourceReadConstraint) (SourceRun, error)
	})(nil)).Elem())
	assertExactInterface(t, reflect.TypeOf((*SourceProfileAdmissionResolver)(nil)).Elem(), reflect.TypeOf((*interface {
		ResolveProfileAdmission(context.Context, ProfileCode) (BuiltinSourceProfile, error)
	})(nil)).Elem())

	for name, err := range map[string]error{
		"invalid request":  ErrInvalidRequest,
		"not found":        ErrNotFound,
		"scope violation":  ErrScopeViolation,
		"version conflict": ErrVersionConflict,
		"state conflict":   ErrStateConflict,
		"idempotency":      ErrIdempotency,
	} {
		if err == nil || strings.TrimSpace(err.Error()) == "" {
			t.Errorf("stable error %s is empty", name)
		}
		for _, unsafe := range []string{"postgres", "sqlstate", "provider", "endpoint", "password", "dsn"} {
			if strings.Contains(strings.ToLower(err.Error()), unsafe) {
				t.Errorf("stable error %s leaks implementation token %q", name, unsafe)
			}
		}
	}
}

func TestManualProfileV1IsExactImmutableBootstrapContract(t *testing.T) {
	t.Parallel()

	profile := ManualProfileV1()
	if profile.SourceKind != SourceKind("MANUAL") || profile.ProviderKind != "MANUAL_V1" || profile.ProfileCode != ProfileCode("MANUAL_V1") ||
		profile.SyncMode != SyncMode("MANUAL") || profile.FreshnessKind != FreshnessKind("CATALOG_SEQUENCE") || profile.EnvironmentMapping != EnvironmentMappingMode("SINGLE_ENVIRONMENT") ||
		profile.ParserCode != "MANUAL_ASSET_V1" || profile.CompatibilityClass != "MANUAL_V1" || profile.DLPPolicyCode != "ASSET_SAFE_V1" {
		t.Fatalf("ManualProfileV1 identity = %#v", profile)
	}
	if profile.RateLimitRequests != 1 || profile.RateLimitWindowSeconds != 1 || profile.BackpressureBaseSeconds != 1 || profile.BackpressureMaxSeconds != 1 ||
		profile.MaxPageItems != 1 || profile.MaxPageRelations != 0 || profile.MaxPageBytes != 65536 || profile.MaxDocumentBytes != 65536 {
		t.Fatalf("ManualProfileV1 limits = %#v", profile)
	}
	if profile.IntegrationMode != "NONE" || profile.CredentialPurpose != "NONE" || profile.TrustMode != "NONE" || profile.NetworkMode != "NONE" || profile.ScheduleMode != "NONE" ||
		profile.IntegrationID != "" || profile.CredentialReferenceID != "" || profile.TrustReferenceID != "" || profile.NetworkPolicyReferenceID != "" || profile.ScheduleExpression != "" || profile.TypedExtensionCode != "" || profile.PreparedExtensionDigest != "" {
		t.Fatalf("ManualProfileV1 nullable/reference boundary = %#v", profile)
	}
	if string(profile.CanonicalProfileManifest) != manualProfileManifestV1 || len(profile.CanonicalProfileManifest) != 794 ||
		profile.ProfileManifestSHA256 != "57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96" {
		t.Fatalf("ManualProfileV1 manifest bytes/hash drifted")
	}
	if string(profile.CanonicalProviderSchema) != manualProviderSchemaV1 || len(profile.CanonicalProviderSchema) != 62 ||
		profile.CanonicalProviderSchemaSHA256 != "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa" {
		t.Fatalf("ManualProfileV1 provider schema bytes/hash drifted")
	}
	if !slices.Equal(profile.TrustedPathCodes, []string{"MANUAL_V1_DISPLAY_NAME", "MANUAL_V1_EXTERNAL_ID", "MANUAL_V1_KIND"}) || len(profile.RelationshipTypes) != 0 {
		t.Fatalf("ManualProfileV1 closed paths/relationships = %#v/%#v", profile.TrustedPathCodes, profile.RelationshipTypes)
	}

	manifestDigest, err := ProfileManifestDigest(profile.CanonicalProfileManifest)
	if err != nil || manifestDigest != profile.ProfileManifestSHA256 {
		t.Fatalf("ProfileManifestDigest() = (%q, %v)", manifestDigest, err)
	}
	source := Source{Kind: profile.SourceKind, ProviderKind: profile.ProviderKind}
	revision := SourceRevision{
		ProfileCode: profile.ProfileCode, CanonicalProfileManifest: profile.CanonicalProfileManifest, CanonicalProviderSchema: profile.CanonicalProviderSchema,
		SyncMode: profile.SyncMode, RateLimitRequests: profile.RateLimitRequests, RateLimitWindowSeconds: profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds: profile.BackpressureBaseSeconds, BackpressureMaxSeconds: profile.BackpressureMaxSeconds,
	}
	definition, err := SourceDefinitionDigest(source, revision)
	if err != nil || definition != "7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c" {
		t.Fatalf("SourceDefinitionDigest(MANUAL_V1) = (%q, %v)", definition, err)
	}

	other := ManualProfileV1()
	profile.CanonicalProfileManifest[0] ^= 0xff
	profile.CanonicalProviderSchema[0] ^= 0xff
	profile.TrustedPathCodes[0] = "MUTATED"
	if string(other.CanonicalProfileManifest) != manualProfileManifestV1 || string(other.CanonicalProviderSchema) != manualProviderSchemaV1 || other.TrustedPathCodes[0] != "MANUAL_V1_DISPLAY_NAME" {
		t.Fatal("ManualProfileV1 returned shared mutable state")
	}

	resolver := NewBuiltinSourceProfileAdmissionResolver()
	first, err := resolver.ResolveProfileAdmission(context.Background(), ProfileCode("MANUAL_V1"))
	if err != nil {
		t.Fatalf("ResolveProfileAdmission(MANUAL_V1) error = %v", err)
	}
	first.CanonicalProfileManifest[0] ^= 0xff
	first.CanonicalProviderSchema[0] ^= 0xff
	first.TrustedPathCodes[0] = "MUTATED"
	second, err := resolver.ResolveProfileAdmission(context.Background(), ProfileCode("MANUAL_V1"))
	if err != nil || string(second.CanonicalProfileManifest) != manualProfileManifestV1 || string(second.CanonicalProviderSchema) != manualProviderSchemaV1 ||
		second.TrustedPathCodes[0] != "MANUAL_V1_DISPLAY_NAME" || len(second.RelationshipTypes) != 0 {
		t.Fatalf("built-in resolver leaked mutable state: (%#v, %v)", second, err)
	}
	if _, err := resolver.ResolveProfileAdmission(context.Background(), ProfileCode("KUBERNETES_OPERATOR")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown built-in profile error = %v, want ErrNotFound", err)
	}
}

func TestProfileManifestDigestRequiresTheExactClosedCanonicalSchema(t *testing.T) {
	t.Parallel()

	if digest, err := ProfileManifestDigest([]byte(manualProfileManifestV1)); err != nil || digest != "57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96" {
		t.Fatalf("ProfileManifestDigest(exact MANUAL_V1) = (%q, %v)", digest, err)
	}
	explicitItemManifest := manualProfileManifestV1
	for _, replacement := range [][2]string{
		{`"source_kind":"MANUAL"`, `"source_kind":"CSV_IMPORT"`},
		{`"provider_kind":"MANUAL_V1"`, `"provider_kind":"TEST_CSV_V1"`},
		{`"profile_code":"MANUAL_V1"`, `"profile_code":"TEST_CSV_V1"`},
		{`"environment_mapping_mode":"SINGLE_ENVIRONMENT"`, `"environment_mapping_mode":"EXPLICIT_ITEM_ENVIRONMENT"`},
		{`"parser_code":"MANUAL_ASSET_V1"`, `"parser_code":"TEST_CSV_V1"`},
		{`"compatibility_class":"MANUAL_V1"`, `"compatibility_class":"TEST_CSV_V1"`},
		{`["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"]`, `["TEST_CSV_V1_DISPLAY_NAME"]`},
	} {
		explicitItemManifest = strings.Replace(explicitItemManifest, replacement[0], replacement[1], 1)
	}
	if digest, err := ProfileManifestDigest([]byte(explicitItemManifest)); err != nil || digest == "" {
		t.Fatalf("ProfileManifestDigest(EXPLICIT_ITEM_ENVIRONMENT) = (%q, %v), want accepted unique contract", digest, err)
	}
	tests := map[string]string{
		"leading whitespace": " " + manualProfileManifestV1,
		"trailing newline":   manualProfileManifestV1 + "\n",
		"noncanonical key order": strings.Replace(manualProfileManifestV1,
			`"backpressure_base_seconds":1,"backpressure_max_seconds":1`,
			`"backpressure_max_seconds":1,"backpressure_base_seconds":1`, 1),
		"duplicate key": strings.Replace(manualProfileManifestV1,
			`"version":"asset-source-profile-manifest.v1"}`,
			`"version":"asset-source-profile-manifest.v1","version":"asset-source-profile-manifest.v1"}`, 1),
		"missing key": strings.Replace(manualProfileManifestV1,
			`"typed_extension_code":null,`, "", 1),
		"unknown key": strings.Replace(manualProfileManifestV1,
			`"version":"asset-source-profile-manifest.v1"}`,
			`"unknown":"value","version":"asset-source-profile-manifest.v1"}`, 1),
		"wrong integer type": strings.Replace(manualProfileManifestV1,
			`"rate_limit_requests":1`, `"rate_limit_requests":"1"`, 1),
		"nonminimal integer": strings.Replace(manualProfileManifestV1,
			`"rate_limit_requests":1`, `"rate_limit_requests":1.0`, 1),
		"negative limit": strings.Replace(manualProfileManifestV1,
			`"rate_limit_requests":1`, `"rate_limit_requests":-1`, 1),
		"wrong version": strings.Replace(manualProfileManifestV1,
			`"version":"asset-source-profile-manifest.v1"`, `"version":"asset-source-profile-manifest.v2"`, 1),
		"unknown source kind": strings.Replace(manualProfileManifestV1,
			`"source_kind":"MANUAL"`, `"source_kind":"UNKNOWN"`, 1),
		"unknown sync mode": strings.Replace(manualProfileManifestV1,
			`"sync_mode":"MANUAL"`, `"sync_mode":"UNKNOWN"`, 1),
		"unknown freshness kind": strings.Replace(manualProfileManifestV1,
			`"freshness_kind":"CATALOG_SEQUENCE"`, `"freshness_kind":"UNKNOWN"`, 1),
		"legacy environment mapping": strings.Replace(manualProfileManifestV1,
			`"environment_mapping_mode":"SINGLE_ENVIRONMENT"`, `"environment_mapping_mode":"MULTI_ENVIRONMENT"`, 1),
		"unknown environment mapping": strings.Replace(manualProfileManifestV1,
			`"environment_mapping_mode":"SINGLE_ENVIRONMENT"`, `"environment_mapping_mode":"UNKNOWN"`, 1),
		"unknown integration mode": strings.Replace(manualProfileManifestV1,
			`"integration_mode":"NONE"`, `"integration_mode":"UNKNOWN"`, 1),
		"unsafe credential purpose": strings.Replace(manualProfileManifestV1,
			`"credential_purpose":"NONE"`, `"credential_purpose":"READ/AUTH"`, 1),
		"unknown trust mode": strings.Replace(manualProfileManifestV1,
			`"trust_mode":"NONE"`, `"trust_mode":"UNKNOWN"`, 1),
		"unknown network mode": strings.Replace(manualProfileManifestV1,
			`"network_mode":"NONE"`, `"network_mode":"UNKNOWN"`, 1),
		"unknown schedule mode": strings.Replace(manualProfileManifestV1,
			`"schedule_mode":"NONE"`, `"schedule_mode":"UNKNOWN"`, 1),
		"zero page items": strings.Replace(manualProfileManifestV1,
			`"max_page_items":1`, `"max_page_items":0`, 1),
		"zero page bytes": strings.Replace(manualProfileManifestV1,
			`"max_page_bytes":65536`, `"max_page_bytes":0`, 1),
		"zero document bytes": strings.Replace(manualProfileManifestV1,
			`"max_document_bytes":65536`, `"max_document_bytes":0`, 1),
		"document exceeds page": strings.Replace(manualProfileManifestV1,
			`"max_document_bytes":65536`, `"max_document_bytes":65537`, 1),
		"integer exceeds 18 digits": strings.Replace(manualProfileManifestV1,
			`"rate_limit_requests":1`, `"rate_limit_requests":1000000000000000000`, 1),
		"too many trusted paths": strings.Replace(manualProfileManifestV1,
			`["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"]`, testCanonicalJSONCodes(129), 1),
		"empty trusted paths": strings.Replace(manualProfileManifestV1,
			`["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"]`, `[]`, 1),
		"unsorted trusted paths": strings.Replace(manualProfileManifestV1,
			`["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"]`,
			`["MANUAL_V1_KIND","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_DISPLAY_NAME"]`, 1),
		"duplicate trusted path": strings.Replace(manualProfileManifestV1,
			`["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"]`,
			`["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_DISPLAY_NAME","MANUAL_V1_KIND"]`, 1),
		"unsorted relationships": strings.Replace(manualProfileManifestV1,
			`"relationship_types":[]`, `"relationship_types":["RUNS_ON","CONTAINS"]`, 1),
		"duplicate relationship": strings.Replace(manualProfileManifestV1,
			`"relationship_types":[]`, `"relationship_types":["RUNS_ON","RUNS_ON"]`, 1),
		"unsafe relationship token": strings.Replace(manualProfileManifestV1,
			`"relationship_types":[]`, `"relationship_types":["runs/on"]`, 1),
		"wrong typed extension type": strings.Replace(manualProfileManifestV1,
			`"typed_extension_code":null`, `"typed_extension_code":1`, 1),
		"unsafe parser token": strings.Replace(manualProfileManifestV1,
			`"parser_code":"MANUAL_ASSET_V1"`, `"parser_code":"https://endpoint.invalid"`, 1),
		"oversized": strings.Replace(manualProfileManifestV1,
			`"parser_code":"MANUAL_ASSET_V1"`, `"parser_code":"`+strings.Repeat("A", 17<<10)+`"`, 1),
	}
	for name, manifest := range tests {
		if digest, err := ProfileManifestDigest([]byte(manifest)); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("ProfileManifestDigest(%s) = (%q, %v), want empty ErrInvalidRequest", name, digest, err)
		}
	}
}

func TestSourceDefinitionDigestRecomputesBytesAndRejectsSemanticDrift(t *testing.T) {
	t.Parallel()

	source := Source{Kind: SourceKind("MANUAL"), ProviderKind: "MANUAL_V1"}
	revision := SourceRevision{
		ProfileCode: ProfileCode("MANUAL_V1"), CanonicalProfileManifest: []byte(manualProfileManifestV1), CanonicalProviderSchema: []byte(manualProviderSchemaV1),
		ProfileManifestSHA256: testDigestA, CanonicalProviderSchemaSHA256: testDigestB,
		SyncMode: SyncMode("MANUAL"), RateLimitRequests: 1, RateLimitWindowSeconds: 1, BackpressureBaseSeconds: 1, BackpressureMaxSeconds: 1,
	}
	digest, err := SourceDefinitionDigest(source, revision)
	if err != nil || digest != "7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c" {
		t.Fatalf("SourceDefinitionDigest() = (%q, %v)", digest, err)
	}
	revision.ProfileManifestSHA256, revision.CanonicalProviderSchemaSHA256 = testDigestB, testDigestA
	if got, err := SourceDefinitionDigest(source, revision); err != nil || got != digest {
		t.Fatalf("caller precomputed hashes became truth: (%q, %v), want %q", got, err, digest)
	}

	changedManifest := revision.Clone()
	changedManifest.CanonicalProfileManifest = []byte(strings.Replace(manualProfileManifestV1, `"max_page_bytes":65536`, `"max_page_bytes":65537`, 1))
	if got, err := SourceDefinitionDigest(source, changedManifest); err != nil || got == "" || got == digest {
		t.Fatalf("changed manifest bytes = (%q, %v), want a new exact digest", got, err)
	}
	changedSchema := revision.Clone()
	changedSchema.CanonicalProviderSchema = []byte(`{"additionalProperties":false,"properties":{"safe":{"type":"string"}},"type":"object"}`)
	if got, err := SourceDefinitionDigest(source, changedSchema); err != nil || got == "" || got == digest {
		t.Fatalf("changed provider schema bytes = (%q, %v), want a new exact digest", got, err)
	}
	for _, test := range []struct {
		name     string
		source   Source
		revision SourceRevision
	}{
		{"source kind mismatch", func() Source { value := source; value.Kind = SourceKind("CSV_IMPORT"); return value }(), revision},
		{"provider mismatch", func() Source { value := source; value.ProviderKind = "OTHER_V1"; return value }(), revision},
		{"profile mismatch", source, func() SourceRevision {
			value := revision.Clone()
			value.ProfileCode = ProfileCode("OTHER_V1")
			return value
		}()},
		{"sync mismatch", source, func() SourceRevision { value := revision.Clone(); value.SyncMode = SyncMode("ON_DEMAND"); return value }()},
		{"rate request mismatch", source, func() SourceRevision { value := revision.Clone(); value.RateLimitRequests = 2; return value }()},
		{"rate window mismatch", source, func() SourceRevision { value := revision.Clone(); value.RateLimitWindowSeconds = 2; return value }()},
		{"backpressure base mismatch", source, func() SourceRevision { value := revision.Clone(); value.BackpressureBaseSeconds = 2; return value }()},
		{"backpressure max mismatch", source, func() SourceRevision { value := revision.Clone(); value.BackpressureMaxSeconds = 2; return value }()},
		{"integration mode mismatch", source, func() SourceRevision {
			value := revision.Clone()
			value.IntegrationID = testEnvironmentID
			return value
		}()},
		{"credential mode mismatch", source, func() SourceRevision {
			value := revision.Clone()
			value.CredentialReferenceID = "cred-ref-v1"
			return value
		}()},
		{"trust mode mismatch", source, func() SourceRevision {
			value := revision.Clone()
			value.TrustReferenceID = "trust-ref-v1"
			return value
		}()},
		{"network mode mismatch", source, func() SourceRevision {
			value := revision.Clone()
			value.NetworkPolicyReferenceID = "network-ref-v1"
			return value
		}()},
		{"schedule mode mismatch", source, func() SourceRevision {
			value := revision.Clone()
			value.ScheduleExpression = "0 */5 * * * *"
			return value
		}()},
		{"typed extension mismatch", source, func() SourceRevision {
			value := revision.Clone()
			value.TypedExtensionCode = "TEST_V1"
			value.PreparedExtensionDigest = testDigestA
			return value
		}()},
		{"noncanonical schema", source, func() SourceRevision {
			value := revision.Clone()
			value.CanonicalProviderSchema = []byte(" " + manualProviderSchemaV1)
			return value
		}()},
		{"blank schema", source, func() SourceRevision {
			value := revision.Clone()
			value.CanonicalProviderSchema = []byte(" \t\n")
			return value
		}()},
	} {
		if got, err := SourceDefinitionDigest(test.source, test.revision); !errors.Is(err, ErrInvalidRequest) || got != "" {
			t.Errorf("SourceDefinitionDigest(%s) = (%q, %v), want empty ErrInvalidRequest", test.name, got, err)
		}
	}
}

func TestSourceRevisionCloneOwnsAuthorityAndCanonicalBytes(t *testing.T) {
	t.Parallel()

	revision := validManualRevision()
	clone := revision.Clone()
	clone.AuthorityEnvironmentIDs[0] = "77777777-7777-4777-8777-777777777777"
	clone.CanonicalProfileManifest[0] ^= 0xff
	clone.CanonicalProviderSchema[0] ^= 0xff
	if revision.AuthorityEnvironmentIDs[0] != testEnvironmentID || string(revision.CanonicalProfileManifest) != manualProfileManifestV1 || string(revision.CanonicalProviderSchema) != manualProviderSchemaV1 {
		t.Fatal("SourceRevision.Clone() retained caller-owned slices")
	}
}

func TestMutableDomainClonesAreBidirectionallyIsolated(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	later := now.Add(time.Minute)
	filter := AssetFilter{
		Kinds:               []Kind{"DATABASE"},
		SourceIDs:           []string{testSourceID},
		Lifecycles:          []Lifecycle{"ACTIVE"},
		MappingStatuses:     []domain.MappingStatus{domain.MappingExact},
		Criticalities:       []Criticality{"HIGH"},
		DataClassifications: []DataClassification{"CONFIDENTIAL"},
	}
	filterClone := filter.Clone()
	filterClone.Kinds[0] = "SERVICE"
	filterClone.SourceIDs[0] = testAssetID
	filterClone.Lifecycles[0] = "STALE"
	filter.MappingStatuses[0] = domain.MappingAmbiguous
	filter.Criticalities[0] = "LOW"
	filter.DataClassifications[0] = "PUBLIC"
	if filter.Kinds[0] != "DATABASE" || filter.SourceIDs[0] != testSourceID || filter.Lifecycles[0] != "ACTIVE" ||
		filterClone.MappingStatuses[0] != domain.MappingExact || filterClone.Criticalities[0] != "HIGH" || filterClone.DataClassifications[0] != "CONFIDENTIAL" {
		t.Fatal("AssetFilter.Clone() retained caller-owned slices")
	}

	asset := validAsset()
	assetClone := asset.Clone()
	*assetClone.OwnerGroup = "changed-clone"
	assetClone.Labels["clone"] = "changed"
	*asset.OwnerGroup = "changed-original"
	asset.Labels["original"] = "changed"
	if *asset.OwnerGroup != "changed-original" || asset.Labels["clone"] != "" || *assetClone.OwnerGroup != "changed-clone" || assetClone.Labels["original"] != "" {
		t.Fatal("Asset.Clone() retained labels or OwnerGroup pointer")
	}

	createOwner := "sre-platform"
	create := CreateAssetCommand{OwnerGroup: &createOwner, Labels: map[string]string{"team": "platform"}}
	createClone := create.Clone()
	*createClone.OwnerGroup = "changed-clone"
	createClone.Labels["clone"] = "changed"
	*create.OwnerGroup = "changed-original"
	create.Labels["original"] = "changed"
	if *create.OwnerGroup != "changed-original" || create.Labels["clone"] != "" || *createClone.OwnerGroup != "changed-clone" || createClone.Labels["original"] != "" {
		t.Fatal("CreateAssetCommand.Clone() retained labels or OwnerGroup pointer")
	}

	updateOwner := "sre-platform"
	update := UpdateGovernanceCommand{OwnerGroup: &updateOwner, Labels: map[string]string{"team": "platform"}}
	updateClone := update.Clone()
	*updateClone.OwnerGroup = "changed-clone"
	updateClone.Labels["clone"] = "changed"
	*update.OwnerGroup = "changed-original"
	update.Labels["original"] = "changed"
	if *update.OwnerGroup != "changed-original" || update.Labels["clone"] != "" || *updateClone.OwnerGroup != "changed-clone" || updateClone.Labels["original"] != "" {
		t.Fatal("UpdateGovernanceCommand.Clone() retained labels or OwnerGroup pointer")
	}

	assetRequest := ListAssetsRequest{
		Filter: filter,
		Cursor: &AssetCursor{Sort: "display_name_asc", QueryDigest: testDigestA, Value: "asset", AssetID: testAssetID},
	}
	assetRequestClone := assetRequest.Clone()
	assetRequestClone.Filter.Kinds[0] = "SERVICE"
	assetRequestClone.Cursor.Value = "changed"
	assetRequest.Filter.SourceIDs[0] = testServiceID
	if assetRequest.Filter.Kinds[0] != "DATABASE" || assetRequest.Cursor.Value != "asset" || assetRequestClone.Filter.SourceIDs[0] != testSourceID {
		t.Fatal("ListAssetsRequest.Clone() retained filter or cursor state")
	}

	relationshipRequest := ListRelationshipsRequest{
		Types: []RelationshipType{"DEPENDS_ON"}, Statuses: []RelationshipStatus{"ACTIVE"},
		Cursor: &RelationshipCursor{QueryDigest: testDigestA, Type: "DEPENDS_ON", SourceAssetID: testAssetID, TargetAssetID: testServiceID, RelationshipID: testSourceID},
	}
	relationshipRequestClone := relationshipRequest.Clone()
	relationshipRequestClone.Types[0] = "RUNS_ON"
	relationshipRequestClone.Cursor.RelationshipID = testAssetID
	relationshipRequest.Statuses[0] = "INACTIVE"
	if relationshipRequest.Types[0] != "DEPENDS_ON" || relationshipRequest.Cursor.RelationshipID != testSourceID || relationshipRequestClone.Statuses[0] != "ACTIVE" {
		t.Fatal("ListRelationshipsRequest.Clone() retained filter or cursor state")
	}

	bindingRequest := ListBindingsRequest{
		Roles: []BindingRole{"DEPENDENCY"}, Statuses: []BindingStatus{"ACTIVE"},
		Cursor: &BindingCursor{QueryDigest: testDigestA, ServiceID: testServiceID, AssetID: testAssetID, BindingID: testSourceID, Role: "DEPENDENCY"},
	}
	bindingRequestClone := bindingRequest.Clone()
	bindingRequestClone.Roles[0] = "PRIMARY_RUNTIME"
	bindingRequestClone.Cursor.BindingID = testAssetID
	bindingRequest.Statuses[0] = "INACTIVE"
	if bindingRequest.Roles[0] != "DEPENDENCY" || bindingRequest.Cursor.BindingID != testSourceID || bindingRequestClone.Statuses[0] != "ACTIVE" {
		t.Fatal("ListBindingsRequest.Clone() retained filter or cursor state")
	}

	conflictRequest := ListConflictsRequest{
		Statuses: []ConflictStatus{"OPEN"},
		Cursor:   &ConflictCursor{QueryDigest: testDigestA, CreatedAt: now, ConflictID: testSourceID},
	}
	conflictRequestClone := conflictRequest.Clone()
	conflictRequestClone.Statuses[0] = "RESOLVED"
	conflictRequestClone.Cursor.ConflictID = testAssetID
	conflictRequest.Statuses[0] = "REJECTED"
	if conflictRequest.Cursor.ConflictID != testSourceID || conflictRequestClone.Statuses[0] != "RESOLVED" || conflictRequestClone.Cursor.ConflictID != testAssetID {
		t.Fatal("ListConflictsRequest.Clone() retained filter or cursor state")
	}

	sourceRequest := ListSourcesRequest{
		Kinds: []SourceKind{"MANUAL"}, Statuses: []SourceStatus{"ACTIVE"}, GateStatuses: []SourceGateStatus{"AVAILABLE"},
		Cursor: &SourceCursor{QueryDigest: testDigestA, SourceID: testSourceID},
	}
	sourceRequestClone := sourceRequest.Clone()
	sourceRequestClone.Kinds[0] = "CSV_IMPORT"
	sourceRequestClone.Cursor.SourceID = testAssetID
	sourceRequest.Statuses[0] = "PAUSED"
	sourceRequest.GateStatuses[0] = "DEGRADED"
	if sourceRequest.Kinds[0] != "MANUAL" || sourceRequest.Cursor.SourceID != testSourceID || sourceRequestClone.Statuses[0] != "ACTIVE" || sourceRequestClone.GateStatuses[0] != "AVAILABLE" {
		t.Fatal("ListSourcesRequest.Clone() retained filter or cursor state")
	}

	relationship := Relationship{FreshnessOrderTime: &now}
	relationshipClone := relationship.Clone()
	*relationshipClone.FreshnessOrderTime = later
	if !relationship.FreshnessOrderTime.Equal(now) {
		t.Fatal("Relationship.Clone() retained time pointer")
	}

	conflictResolvedAt := now
	conflict := Conflict{ResolvedAt: &conflictResolvedAt}
	conflictClone := conflict.Clone()
	*conflict.ResolvedAt = later
	if !conflictClone.ResolvedAt.Equal(now) {
		t.Fatal("Conflict.Clone() retained time pointer")
	}

	source := Source{NextAllowedAt: &now, LastSuccessAt: &now, LastCompleteSnapshotAt: &now}
	sourceClone := source.Clone()
	*sourceClone.NextAllowedAt = later
	*sourceClone.LastSuccessAt = later
	*sourceClone.LastCompleteSnapshotAt = later
	if !source.NextAllowedAt.Equal(now) || !source.LastSuccessAt.Equal(now) || !source.LastCompleteSnapshotAt.Equal(now) {
		t.Fatal("Source.Clone() retained time pointers")
	}

	observation := Observation{FreshnessOrderTime: &now, NormalizedDocument: []byte(`{"safe":"document"}`), FieldProvenance: []byte(`{"safe":"provenance"}`)}
	observationClone := observation.Clone()
	*observationClone.FreshnessOrderTime = later
	observationClone.NormalizedDocument[0] ^= 0xff
	observationClone.FieldProvenance[0] ^= 0xff
	if !observation.FreshnessOrderTime.Equal(now) || string(observation.NormalizedDocument) != `{"safe":"document"}` || string(observation.FieldProvenance) != `{"safe":"provenance"}` {
		t.Fatal("Observation.Clone() retained pointer/byte slices")
	}

	run := SourceRun{LeaseExpiresAt: &now, WorkResultRecordedAt: &now, StartedAt: &now, HeartbeatAt: &now, CompletedAt: &now}
	runClone := run.Clone()
	*runClone.LeaseExpiresAt = later
	*runClone.WorkResultRecordedAt = later
	*runClone.StartedAt = later
	*runClone.HeartbeatAt = later
	*runClone.CompletedAt = later
	if !run.LeaseExpiresAt.Equal(now) || !run.WorkResultRecordedAt.Equal(now) || !run.StartedAt.Equal(now) || !run.HeartbeatAt.Equal(now) || !run.CompletedAt.Equal(now) {
		t.Fatal("SourceRun.Clone() retained time pointers")
	}

	assetPage := AssetPage{
		Items: []AssetReadModel{{Asset: validAsset(), Services: []AssetServiceReference{{ID: testServiceID, Name: "payments", Role: BindingRole("DEPENDENCY")}}}},
		Next:  &AssetCursor{Sort: AssetSort("display_name_asc"), QueryDigest: testDigestA, Value: "asset", AssetID: testAssetID}, ManualCreateEligible: true,
	}
	assetPageClone := assetPage.Clone()
	assetPageClone.Items[0].Labels["changed"] = "yes"
	*assetPageClone.Items[0].OwnerGroup = "changed"
	assetPageClone.Items[0].Services[0].Name = "changed"
	assetPageClone.Next.Value = "changed"
	if assetPage.Items[0].Labels["changed"] != "" || assetPage.Items[0].OwnerGroup == nil || *assetPage.Items[0].OwnerGroup != "sre-platform" || assetPage.Items[0].Services[0].Name != "payments" || assetPage.Next.Value != "asset" {
		t.Fatal("AssetPage.Clone() retained nested item/services/cursor state")
	}

	relationshipPage := RelationshipPage{Items: []Relationship{relationship}, Next: &RelationshipCursor{QueryDigest: testDigestA, RelationshipID: testAssetID}}
	relationshipPageClone := relationshipPage.Clone()
	*relationshipPageClone.Items[0].FreshnessOrderTime = later
	relationshipPageClone.Next.RelationshipID = testServiceID
	if !relationshipPage.Items[0].FreshnessOrderTime.Equal(now) || relationshipPage.Next.RelationshipID != testAssetID {
		t.Fatal("RelationshipPage.Clone() retained nested state")
	}

	bindingPage := BindingPage{Items: []ServiceAssetBinding{{ID: testAssetID}}, Next: &BindingCursor{QueryDigest: testDigestA, BindingID: testAssetID}}
	bindingPageClone := bindingPage.Clone()
	bindingPageClone.Items[0].ID = testServiceID
	bindingPageClone.Next.BindingID = testServiceID
	if bindingPage.Items[0].ID != testAssetID || bindingPage.Next.BindingID != testAssetID {
		t.Fatal("BindingPage.Clone() retained item/cursor state")
	}

	conflictPageResolvedAt := now
	conflictPage := ConflictPage{
		Items: []ConflictReadModel{{Conflict: Conflict{ResolvedAt: &conflictPageResolvedAt}, CandidateAsset: &ConflictAssetReference{ID: testAssetID}, CandidateService: &ConflictServiceReference{ID: testServiceID}}},
		Next:  &ConflictCursor{QueryDigest: testDigestA, CreatedAt: now, ConflictID: testAssetID},
	}
	conflictPageClone := conflictPage.Clone()
	*conflictPageClone.Items[0].ResolvedAt = later
	conflictPageClone.Items[0].CandidateAsset.ID = testServiceID
	conflictPageClone.Items[0].CandidateService.ID = testAssetID
	conflictPageClone.Next.ConflictID = testServiceID
	if !conflictPage.Items[0].ResolvedAt.Equal(now) || conflictPage.Items[0].CandidateAsset.ID != testAssetID || conflictPage.Items[0].CandidateService.ID != testServiceID || conflictPage.Next.ConflictID != testAssetID {
		t.Fatal("ConflictPage.Clone() retained candidate/time/cursor state")
	}

	revision := validManualRevision()
	sourcePage := SourcePage{
		Items: []SourceReadModel{{Source: source, LatestRevision: revision, PublishedRevision: &revision, CurrentRun: &run, LastSuccessfulRun: &run}},
		Next:  &SourceCursor{QueryDigest: testDigestA, SourceID: testSourceID},
	}
	sourcePageClone := sourcePage.Clone()
	sourcePageClone.Items[0].LatestRevision.CanonicalProfileManifest[0] ^= 0xff
	sourcePageClone.Items[0].PublishedRevision.AuthorityEnvironmentIDs[0] = testAssetID
	*sourcePageClone.Items[0].CurrentRun.StartedAt = later
	*sourcePageClone.Items[0].LastSuccessfulRun.CompletedAt = later
	sourcePageClone.Next.SourceID = testAssetID
	if string(sourcePage.Items[0].LatestRevision.CanonicalProfileManifest) != manualProfileManifestV1 || sourcePage.Items[0].PublishedRevision.AuthorityEnvironmentIDs[0] != testEnvironmentID ||
		!sourcePage.Items[0].CurrentRun.StartedAt.Equal(now) || !sourcePage.Items[0].LastSuccessfulRun.CompletedAt.Equal(now) || sourcePage.Next.SourceID != testSourceID {
		t.Fatal("SourcePage.Clone() retained nested revision/run/cursor state")
	}

	assetResult := AssetMutationResult{Asset: AssetDetailReadModel{AssetReadModel: assetPage.Items[0], FieldProvenance: []FieldProvenanceSummary{{FieldCode: "display_name"}}}}
	assetResultClone := assetResult.Clone()
	assetResultClone.Asset.Labels["changed"] = "yes"
	assetResultClone.Asset.Services[0].Name = "changed"
	assetResultClone.Asset.FieldProvenance[0].FieldCode = "changed"
	if assetResult.Asset.Labels["changed"] != "" || assetResult.Asset.Services[0].Name != "payments" || assetResult.Asset.FieldProvenance[0].FieldCode != "display_name" {
		t.Fatal("AssetMutationResult.Clone() retained nested state")
	}

	bindingResult := BindingMutationResult{Binding: ServiceAssetBinding{ID: testAssetID}}
	bindingResultClone := bindingResult.Clone()
	bindingResultClone.Binding.ID = testServiceID
	if bindingResult.Binding.ID != testAssetID {
		t.Fatal("BindingMutationResult.Clone() changed original")
	}
	mappingResult := MappingDecisionResult{Conflict: conflictPage.Items[0], Binding: &bindingPage.Items[0]}
	mappingResultClone := mappingResult.Clone()
	mappingResultClone.Conflict.CandidateAsset.ID = testServiceID
	mappingResultClone.Binding.ID = testServiceID
	if mappingResult.Conflict.CandidateAsset.ID != testAssetID || mappingResult.Binding.ID != testAssetID {
		t.Fatal("MappingDecisionResult.Clone() retained nested state")
	}
}

func TestAuthorityDefinitionAndBindingDigestsUseExactFramedTuples(t *testing.T) {
	t.Parallel()

	environments := []string{"77777777-7777-4777-8777-777777777777", testEnvironmentID}
	digest, err := AuthorityScopeDigest(environments)
	if err != nil {
		t.Fatalf("AuthorityScopeDigest() error = %v", err)
	}
	sorted := slices.Clone(environments)
	slices.Sort(sorted)
	wantAuthority := testFramedDigest([][]byte{[]byte("asset-source-authority-scope.v1"), []byte("2"), []byte(sorted[0]), []byte(sorted[1])})
	if digest != wantAuthority {
		t.Fatalf("AuthorityScopeDigest() = %q, want %q", digest, wantAuthority)
	}
	reversed, err := AuthorityScopeDigest([]string{environments[1], environments[0]})
	if err != nil || reversed != digest {
		t.Fatalf("AuthorityScopeDigest(permutation) = (%q, %v), want %q", reversed, err, digest)
	}
	for name, candidate := range map[string][]string{
		"empty":           nil,
		"duplicate":       {testEnvironmentID, testEnvironmentID},
		"uppercase":       {strings.ToUpper(testLetteredUUID)},
		"version zero":    {"11111111-1111-0111-8111-111111111111"},
		"non-RFC variant": {"11111111-1111-4111-7111-111111111111"},
		"too many":        append(make([]string, 100), testEnvironmentID),
	} {
		if name == "too many" {
			for index := range candidate[:100] {
				candidate[index] = testUUID(index + 100)
			}
		}
		if got, err := AuthorityScopeDigest(candidate); err == nil || got != "" {
			t.Errorf("AuthorityScopeDigest(%s) = (%q, %v), want rejection", name, got, err)
		}
	}
	hundred := testUUIDs(100)
	hundredDigest, err := AuthorityScopeDigest(slices.Clone(hundred))
	if err != nil || hundredDigest == "" {
		t.Fatalf("AuthorityScopeDigest(100 environments) = (%q, %v)", hundredDigest, err)
	}
	hundredFrames := make([][]byte, 0, 102)
	hundredFrames = append(hundredFrames, []byte("asset-source-authority-scope.v1"), []byte("100"))
	for _, environmentID := range hundred {
		hundredFrames = append(hundredFrames, []byte(environmentID))
	}
	if want := testFramedDigest(hundredFrames); hundredDigest != want {
		t.Fatalf("AuthorityScopeDigest(100) = %q, want exact N+2 framing %q", hundredDigest, want)
	}

	present := SourceRevision{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID, SourceID: testSourceID, Revision: 7,
		SourceDefinitionDigest: strings.Repeat("11", 32), IntegrationID: "44444444-4444-4444-8444-444444444444", SyncMode: SyncMode("SCHEDULED"),
		CredentialReferenceID: "cred-ref-v1", TrustReferenceID: "trust-ref-v1", NetworkPolicyReferenceID: "network-ref-v1",
		AuthorityScopeDigest: strings.Repeat("22", 32), RateLimitRequests: 100, RateLimitWindowSeconds: 60, BackpressureBaseSeconds: 5, BackpressureMaxSeconds: 300,
		ProfileCode: ProfileCode("VICTORIAMETRICS_OPERATOR_V1"), ScheduleExpression: "0 */5 * * * *", TypedExtensionCode: ExtensionCode("VICTORIAMETRICS_OPERATOR_V1"), PreparedExtensionDigest: strings.Repeat("33", 32),
	}
	if got := present.BindingDigest(); got != "49f8013b8e3cccdcbeb1d125915b2bf424815306494318ee2d3b7e298f3f6b74" {
		t.Fatalf("present BindingDigest() = %q", got)
	}
	manual := SourceRevision{
		TenantID: testTenantID, WorkspaceID: testWorkspaceID, SourceID: testSourceID, Revision: 1,
		SourceDefinitionDigest: strings.Repeat("aa", 32), SyncMode: SyncMode("MANUAL"), AuthorityScopeDigest: strings.Repeat("bb", 32),
		RateLimitRequests: 1, RateLimitWindowSeconds: 1, BackpressureBaseSeconds: 1, BackpressureMaxSeconds: 1, ProfileCode: ProfileCode("MANUAL_V1"),
	}
	if got := manual.BindingDigest(); got != "88965ba68eb1d6450b1252a0a261bfaa282556e0ec569b6db2c0153d235912b5" {
		t.Fatalf("all-NULL optional BindingDigest() = %q", got)
	}

	baseDigest := present.BindingDigest()
	mutations := []func(*SourceRevision){
		func(value *SourceRevision) { value.TenantID = "77777777-7777-4777-8777-777777777777" },
		func(value *SourceRevision) { value.WorkspaceID = "77777777-7777-4777-8777-777777777777" },
		func(value *SourceRevision) { value.SourceID = "77777777-7777-4777-8777-777777777777" },
		func(value *SourceRevision) { value.Revision++ },
		func(value *SourceRevision) { value.SourceDefinitionDigest = strings.Repeat("44", 32) },
		func(value *SourceRevision) { value.IntegrationID = "77777777-7777-4777-8777-777777777777" },
		func(value *SourceRevision) { value.SyncMode = SyncMode("ON_DEMAND") },
		func(value *SourceRevision) { value.CredentialReferenceID = "cred-ref-v2" },
		func(value *SourceRevision) { value.TrustReferenceID = "trust-ref-v2" },
		func(value *SourceRevision) { value.NetworkPolicyReferenceID = "network-ref-v2" },
		func(value *SourceRevision) { value.AuthorityScopeDigest = strings.Repeat("55", 32) },
		func(value *SourceRevision) { value.RateLimitRequests++ },
		func(value *SourceRevision) { value.RateLimitWindowSeconds++ },
		func(value *SourceRevision) { value.BackpressureBaseSeconds++ },
		func(value *SourceRevision) { value.BackpressureMaxSeconds++ },
		func(value *SourceRevision) { value.ProfileCode = ProfileCode("VICTORIAMETRICS_OPERATOR_V2") },
		func(value *SourceRevision) { value.ScheduleExpression = "0 */10 * * * *" },
		func(value *SourceRevision) { value.TypedExtensionCode = ExtensionCode("VICTORIAMETRICS_OPERATOR_V2") },
		func(value *SourceRevision) { value.PreparedExtensionDigest = strings.Repeat("66", 32) },
	}
	for index, mutate := range mutations {
		candidate := present.Clone()
		mutate(&candidate)
		if got := candidate.BindingDigest(); got == "" || got == baseDigest {
			t.Errorf("included BindingDigest field mutation %d produced %q", index, got)
		}
	}
	excluded := present.Clone()
	excluded.ID = "77777777-7777-4777-8777-777777777777"
	excluded.Status = SourceRevisionStatus("SUPERSEDED")
	excluded.CanonicalProfileManifest = []byte(`{"excluded":true}`)
	excluded.CanonicalProviderSchema = []byte(`{"excluded":true}`)
	excluded.ProfileManifestSHA256 = testDigestA
	excluded.CanonicalProviderSchemaSHA256 = testDigestB
	excluded.CanonicalRevisionDigest = testDigestA
	excluded.AuthorityEnvironmentIDs = []string{testEnvironmentID}
	excluded.ValidationRunID = "77777777-7777-4777-8777-777777777777"
	excluded.ValidationDigest = testDigestA
	excluded.Version = 99
	excluded.CreatedBy = "another-actor"
	excluded.ChangeReasonCode = "ANOTHER_REASON"
	excluded.ExpectedSourceVersion = 99
	excluded.CreatedAt = time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	excluded.UpdatedAt = time.Date(2026, 7, 15, 2, 3, 4, 0, time.UTC)
	if got := excluded.BindingDigest(); got != baseDigest {
		t.Fatalf("excluded lifecycle fields changed BindingDigest: %q != %q", got, baseDigest)
	}
	halfExtension := present.Clone()
	halfExtension.PreparedExtensionDigest = ""
	if got := halfExtension.BindingDigest(); got != "" {
		t.Fatalf("half-present typed extension BindingDigest() = %q, want empty", got)
	}
	halfExtension = present.Clone()
	halfExtension.TypedExtensionCode = ""
	if got := halfExtension.BindingDigest(); got != "" {
		t.Fatalf("digest-only typed extension BindingDigest() = %q, want empty", got)
	}
	for name, mutate := range map[string]func(*SourceRevision){
		"present-empty integration": func(value *SourceRevision) { value.IntegrationID = " " },
		"present-empty credential":  func(value *SourceRevision) { value.CredentialReferenceID = CredentialReferenceID(" ") },
		"present-empty trust":       func(value *SourceRevision) { value.TrustReferenceID = TrustReferenceID(" ") },
		"present-empty network":     func(value *SourceRevision) { value.NetworkPolicyReferenceID = NetworkPolicyReferenceID(" ") },
		"present-empty schedule":    func(value *SourceRevision) { value.ScheduleExpression = " " },
	} {
		candidate := present.Clone()
		mutate(&candidate)
		if got := candidate.BindingDigest(); got != "" {
			t.Errorf("BindingDigest(%s) = %q, want invalid rather than a second empty semantic", name, got)
		}
	}
}

func FuzzBindingDigestFramingSeparatesFieldBoundaries(f *testing.F) {
	f.Add([]byte("left"), []byte("right"))
	f.Add([]byte{}, []byte{})
	f.Add(bytesOfLength(32, 0x00), bytesOfLength(32, 0xff))
	f.Fuzz(func(t *testing.T, leftBytes, rightBytes []byte) {
		if len(leftBytes) > 24 {
			leftBytes = leftBytes[:24]
		}
		if len(rightBytes) > 24 {
			rightBytes = rightBytes[:24]
		}
		left := hex.EncodeToString(leftBytes)
		tail := "c" + hex.EncodeToString(rightBytes)
		base := SourceRevision{
			TenantID: testTenantID, WorkspaceID: testWorkspaceID, SourceID: testSourceID, Revision: 1,
			SourceDefinitionDigest: testDigestA, SyncMode: SyncMode("ON_DEMAND"), AuthorityScopeDigest: testDigestB,
			RateLimitRequests: 10, RateLimitWindowSeconds: 60, BackpressureBaseSeconds: 2, BackpressureMaxSeconds: 30,
			ProfileCode: ProfileCode("TEST_CSV_V1"),
		}
		first := base.Clone()
		first.CredentialReferenceID = CredentialReferenceID("a" + left)
		first.TrustReferenceID = TrustReferenceID("b" + tail)
		second := base.Clone()
		second.CredentialReferenceID = CredentialReferenceID("a" + left + "b")
		second.TrustReferenceID = TrustReferenceID(tail)
		firstDigest, secondDigest := first.BindingDigest(), second.BindingDigest()
		if firstDigest == "" || secondDigest == "" {
			t.Fatalf("valid fuzz fixture produced empty digests: %q/%q", firstDigest, secondDigest)
		}
		if firstDigest == secondDigest {
			t.Fatalf("framing collision for shifted boundary: %q|%q and %q|%q", first.CredentialReferenceID, first.TrustReferenceID, second.CredentialReferenceID, second.TrustReferenceID)
		}
	})
}

func TestDomainValidationRejectsUnsafeIdentityLabelsTimesAndOpaqueReferences(t *testing.T) {
	t.Parallel()

	asset := validAsset()
	if err := asset.Validate(); err != nil {
		t.Fatalf("valid Asset.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*Asset){
		"uppercase UUID":         func(value *Asset) { value.ID = strings.ToUpper(testLetteredUUID) },
		"source UUID":            func(value *Asset) { value.SourceID = "not-a-uuid" },
		"scope":                  func(value *Asset) { value.Scope.EnvironmentID = "not-a-uuid" },
		"provider token":         func(value *Asset) { value.ProviderKind = "manual/v1" },
		"external identity":      func(value *Asset) { value.ExternalID = " external" },
		"display name":           func(value *Asset) { value.DisplayName = "name\nunsafe" },
		"unknown kind":           func(value *Asset) { value.Kind = Kind("UNKNOWN") },
		"unknown lifecycle":      func(value *Asset) { value.Lifecycle = Lifecycle("UNKNOWN") },
		"unknown mapping":        func(value *Asset) { value.MappingStatus = domain.MappingStatus("UNKNOWN") },
		"owner group":            func(value *Asset) { owner := " owner"; value.OwnerGroup = &owner },
		"unknown criticality":    func(value *Asset) { value.Criticality = Criticality("UNKNOWN") },
		"unknown classification": func(value *Asset) { value.DataClassification = DataClassification("UNKNOWN") },
		"secret label":           func(value *Asset) { value.Labels = map[string]string{"database_password": "redacted"} },
		"observation ID":         func(value *Asset) { value.LastObservationID = "not-a-uuid" },
		"observation chain":      func(value *Asset) { value.LastObservationChainSHA256 = strings.ToUpper(testDigestA) },
		"last observed time":     func(value *Asset) { value.LastObservedAt = value.LastObservedAt.Add(time.Nanosecond) },
		"source revision":        func(value *Asset) { value.LastSourceRevision = 0 },
		"non microsecond time":   func(value *Asset) { value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond) },
		"non UTC time":           func(value *Asset) { value.UpdatedAt = value.UpdatedAt.In(time.FixedZone("unsafe", 3600)) },
		"time order":             func(value *Asset) { value.CreatedAt = value.UpdatedAt.Add(time.Second) },
		"zero version":           func(value *Asset) { value.Version = 0 },
	} {
		candidate := asset.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Asset.Validate(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}
	tooMany := asset.Clone()
	tooMany.Labels = make(map[string]string, 65)
	for index := 0; index < 65; index++ {
		tooMany.Labels["label"+testDecimal(index)] = "value"
	}
	if err := tooMany.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("65 labels error = %v", err)
	}
	tooLarge := asset.Clone()
	tooLarge.Labels = map[string]string{"safe": strings.Repeat("x", 16<<10)}
	if err := tooLarge.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized labels error = %v", err)
	}
	for _, key := range []string{"api-token", "Credential.ID", "databaseDsn", "service_endpoint", "PASSWORD", "secret.key"} {
		candidate := asset.Clone()
		candidate.Labels = map[string]string{key: "redacted"}
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("normalized secret-bearing label key %q error = %v", key, err)
		}
	}
	invalidUTF8 := asset.Clone()
	invalidUTF8.Labels = map[string]string{"safe": string([]byte{0xff})}
	if err := invalidUTF8.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid UTF-8 labels error = %v", err)
	}
	for _, value := range []string{"ref-1", "A_b.c-9"} {
		if !CredentialReferenceID(value).Valid() || !TrustReferenceID(value).Valid() || !NetworkPolicyReferenceID(value).Valid() || !PolicyReferenceID(value).Valid() {
			t.Errorf("opaque reference %q rejected", value)
		}
	}
	for _, value := range []string{"", "https://example.com", "vault/path", "header:value", "line\nbreak", strings.Repeat("a", 129)} {
		if CredentialReferenceID(value).Valid() || TrustReferenceID(value).Valid() || NetworkPolicyReferenceID(value).Valid() || PolicyReferenceID(value).Valid() {
			t.Errorf("unsafe opaque reference %q accepted", value)
		}
	}
	for _, value := range []string{"MANUAL_V1", "Profile.v1", "a+b@c/d:e"} {
		if !ProfileCode(value).Valid() || !ExtensionCode(value).Valid() {
			t.Errorf("safe profile/extension token %q rejected", value)
		}
	}
	for _, value := range []string{"", " profile", "profile\nunsafe", strings.Repeat("a", 129)} {
		if ProfileCode(value).Valid() || ExtensionCode(value).Valid() {
			t.Errorf("unsafe profile/extension token %q accepted", value)
		}
	}
}

func TestScopeUsesExactLowercaseRFC4122UUIDVersionsAndVariants(t *testing.T) {
	t.Parallel()

	valid := make([]string, 0, 20)
	for _, version := range "12345" {
		for _, variant := range "89ab" {
			valid = append(valid, testUUIDVersionVariant(version, variant))
		}
	}
	for _, tenantID := range valid {
		scope := Scope{TenantID: tenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}
		sourceScope := SourceScope{TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID}
		if !scope.Valid() || !sourceScope.Valid() {
			t.Errorf("canonical UUID %q rejected by Scope", tenantID)
		}
	}
	invalidValues := []string{
		"", strings.ToUpper(testLetteredUUID), "11111111-1111-0111-8111-111111111111",
		"11111111-1111-6111-8111-111111111111", "11111111-1111-4111-7111-111111111111",
		"{11111111-1111-4111-8111-111111111111}", testTenantID + " ",
	}
	for _, version := range "06789abcdef" {
		invalidValues = append(invalidValues, testUUIDVersionVariant(version, '8'))
	}
	for _, variant := range "01234567cdef" {
		invalidValues = append(invalidValues, testUUIDVersionVariant('4', variant))
	}
	for _, invalid := range invalidValues {
		scope := Scope{TenantID: invalid, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}
		sourceScope := SourceScope{TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID}
		if scope.Valid() || sourceScope.Valid() {
			t.Errorf("noncanonical UUID %q accepted by Scope", invalid)
		}
	}
}

func TestAllPersistedModelsRejectOneFieldDrift(t *testing.T) {
	t.Parallel()

	source, revision := validPublishedBinding(t)
	if err := source.Validate(); err != nil {
		t.Fatalf("valid Source.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*Source){
		"id":                        func(value *Source) { value.ID = "not-a-uuid" },
		"tenant":                    func(value *Source) { value.TenantID = "not-a-uuid" },
		"workspace":                 func(value *Source) { value.WorkspaceID = "not-a-uuid" },
		"provider":                  func(value *Source) { value.ProviderKind = "manual/v1" },
		"name":                      func(value *Source) { value.Name = " source" },
		"kind":                      func(value *Source) { value.Kind = SourceKind("UNKNOWN") },
		"status":                    func(value *Source) { value.Status = SourceStatus("UNKNOWN") },
		"published revision":        func(value *Source) { value.PublishedRevision = 0 },
		"published digest":          func(value *Source) { value.PublishedRevisionDigest = strings.ToUpper(value.PublishedRevisionDigest) },
		"gate status":               func(value *Source) { value.GateStatus = SourceGateStatus("UNKNOWN") },
		"available gate reason":     func(value *Source) { value.GateReasonCode = "VALIDATED" },
		"gate revision":             func(value *Source) { value.GateRevision = 0 },
		"validated run":             func(value *Source) { value.ValidatedRunID = "not-a-uuid" },
		"validation digest":         func(value *Source) { value.ValidationDigest = "bad" },
		"binding digest":            func(value *Source) { value.ValidatedBindingDigest = "bad" },
		"checkpoint partial":        func(value *Source) { value.CheckpointSHA256 = testDigestA },
		"checkpoint revision drift": func(value *Source) { value.CheckpointSourceRevision = value.PublishedRevision + 1 },
		"next allowed time":         func(value *Source) { next := value.UpdatedAt.Add(time.Nanosecond); value.NextAllowedAt = &next },
		"negative failures":         func(value *Source) { value.ConsecutiveFailures = -1 },
		"last success partial":      func(value *Source) { value.LastSuccessRunID = "88888888-8888-4888-8888-888888888888" },
		"last success time partial": func(value *Source) { last := value.UpdatedAt; value.LastSuccessAt = &last },
		"last snapshot ID partial":  func(value *Source) { value.LastCompleteSnapshotRunID = "88888888-8888-4888-8888-888888888888" },
		"last snapshot partial":     func(value *Source) { last := value.UpdatedAt; value.LastCompleteSnapshotAt = &last },
		"version":                   func(value *Source) { value.Version = 0 },
		"created time":              func(value *Source) { value.CreatedAt = value.CreatedAt.In(time.FixedZone("unsafe", 3600)) },
		"updated time":              func(value *Source) { value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond) },
		"time order":                func(value *Source) { value.CreatedAt = value.UpdatedAt.Add(time.Second) },
	} {
		candidate := source.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Source.Validate(%s) error = %v", name, err)
		}
	}
	manualCheckpoint := source.Clone()
	manualCheckpoint.CheckpointVersion = 1
	if err := manualCheckpoint.Validate(); err != nil {
		t.Fatalf("MANUAL logical checkpoint Source.Validate() error = %v", err)
	}
	if manualCheckpoint.CheckpointSHA256 != "" || manualCheckpoint.CheckpointSourceRevision != manualCheckpoint.PublishedRevision {
		t.Fatal("MANUAL logical checkpoint acquired Provider checkpoint material or lost revision lineage")
	}
	sourceWithSuccessPointers := source.Clone()
	sourceWithSuccessPointers.LastSuccessRunID = "88888888-8888-4888-8888-888888888888"
	lastSuccessAt := sourceWithSuccessPointers.UpdatedAt
	sourceWithSuccessPointers.LastSuccessAt = &lastSuccessAt
	sourceWithSuccessPointers.LastCompleteSnapshotRunID = "99999999-9999-4999-8999-999999999999"
	lastSnapshotAt := sourceWithSuccessPointers.UpdatedAt
	sourceWithSuccessPointers.LastCompleteSnapshotAt = &lastSnapshotAt
	if err := sourceWithSuccessPointers.Validate(); err != nil {
		t.Fatalf("valid Source success/snapshot pointers error = %v", err)
	}

	if err := revision.Validate(); err != nil {
		t.Fatalf("valid SourceRevision.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*SourceRevision){
		"id":        func(value *SourceRevision) { value.ID = "not-a-uuid" },
		"source":    func(value *SourceRevision) { value.SourceID = "not-a-uuid" },
		"tenant":    func(value *SourceRevision) { value.TenantID = "not-a-uuid" },
		"workspace": func(value *SourceRevision) { value.WorkspaceID = "not-a-uuid" },
		"revision":  func(value *SourceRevision) { value.Revision = 0 },
		"status":    func(value *SourceRevision) { value.Status = SourceRevisionStatus("UNKNOWN") },
		"manifest bytes": func(value *SourceRevision) {
			value.CanonicalProfileManifest = append(value.CanonicalProfileManifest, ' ')
		},
		"manifest digest": func(value *SourceRevision) { value.ProfileManifestSHA256 = testDigestB },
		"schema bytes": func(value *SourceRevision) {
			value.CanonicalProviderSchema = append(value.CanonicalProviderSchema, ' ')
		},
		"schema digest":        func(value *SourceRevision) { value.CanonicalProviderSchemaSHA256 = testDigestA },
		"definition digest":    func(value *SourceRevision) { value.SourceDefinitionDigest = "bad" },
		"canonical binding":    func(value *SourceRevision) { value.CanonicalRevisionDigest = testDigestB },
		"integration":          func(value *SourceRevision) { value.IntegrationID = "not-a-uuid" },
		"sync mode":            func(value *SourceRevision) { value.SyncMode = SyncMode("UNKNOWN") },
		"credential reference": func(value *SourceRevision) { value.CredentialReferenceID = CredentialReferenceID("vault/path") },
		"trust reference":      func(value *SourceRevision) { value.TrustReferenceID = TrustReferenceID("trust path") },
		"network reference": func(value *SourceRevision) {
			value.NetworkPolicyReferenceID = NetworkPolicyReferenceID("https://network")
		},
		"authority members": func(value *SourceRevision) {
			value.AuthorityEnvironmentIDs = append(value.AuthorityEnvironmentIDs, value.AuthorityEnvironmentIDs[0])
		},
		"authority digest":        func(value *SourceRevision) { value.AuthorityScopeDigest = testDigestA },
		"rate requests":           func(value *SourceRevision) { value.RateLimitRequests = 0 },
		"rate window":             func(value *SourceRevision) { value.RateLimitWindowSeconds = 0 },
		"backpressure base":       func(value *SourceRevision) { value.BackpressureBaseSeconds = 0 },
		"backpressure max":        func(value *SourceRevision) { value.BackpressureMaxSeconds = 0 },
		"profile":                 func(value *SourceRevision) { value.ProfileCode = ProfileCode(" profile") },
		"schedule":                func(value *SourceRevision) { value.ScheduleExpression = " schedule" },
		"half extension":          func(value *SourceRevision) { value.TypedExtensionCode = ExtensionCode("TEST_V1") },
		"extension digest only":   func(value *SourceRevision) { value.PreparedExtensionDigest = testDigestA },
		"validation run":          func(value *SourceRevision) { value.ValidationRunID = "not-a-uuid" },
		"validation digest":       func(value *SourceRevision) { value.ValidationDigest = "bad" },
		"actor":                   func(value *SourceRevision) { value.CreatedBy = " actor" },
		"reason":                  func(value *SourceRevision) { value.ChangeReasonCode = "reason\nunsafe" },
		"expected source version": func(value *SourceRevision) { value.ExpectedSourceVersion = 0 },
		"version":                 func(value *SourceRevision) { value.Version = 0 },
		"created time":            func(value *SourceRevision) { value.CreatedAt = value.CreatedAt.In(time.FixedZone("unsafe", 3600)) },
		"updated time":            func(value *SourceRevision) { value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond) },
	} {
		candidate := revision.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("SourceRevision.Validate(%s) error = %v", name, err)
		}
	}

	relationship := validRelationship()
	if err := relationship.Validate(); err != nil {
		t.Fatalf("valid Relationship.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*Relationship){
		"id":                       func(value *Relationship) { value.ID = "not-a-uuid" },
		"source":                   func(value *Relationship) { value.SourceID = "not-a-uuid" },
		"scope":                    func(value *Relationship) { value.SourceScope.WorkspaceID = "not-a-uuid" },
		"revision":                 func(value *Relationship) { value.SourceRevision = 0 },
		"revision digest":          func(value *Relationship) { value.CanonicalRevisionDigest = "bad" },
		"run":                      func(value *Relationship) { value.LastRunID = "not-a-uuid" },
		"page":                     func(value *Relationship) { value.LastPageSequence = 0 },
		"checkpoint":               func(value *Relationship) { value.AcceptedCheckpointVersion = 0 },
		"fence":                    func(value *Relationship) { value.RunFenceEpoch = 0 },
		"page digest":              func(value *Relationship) { value.RelationPageSHA256 = "bad" },
		"source environment":       func(value *Relationship) { value.SourceEnvironmentID = "not-a-uuid" },
		"target environment":       func(value *Relationship) { value.TargetEnvironmentID = "not-a-uuid" },
		"source asset":             func(value *Relationship) { value.SourceAssetID = "not-a-uuid" },
		"target asset":             func(value *Relationship) { value.TargetAssetID = "not-a-uuid" },
		"external identity":        func(value *Relationship) { value.FromExternalID = " external" },
		"target external identity": func(value *Relationship) { value.ToExternalID = " target" },
		"type":                     func(value *Relationship) { value.Type = RelationshipType("UNKNOWN") },
		"path":                     func(value *Relationship) { value.ProviderPathCode = "path\nunsafe" },
		"confidence":               func(value *Relationship) { value.Confidence = 101 },
		"freshness":                func(value *Relationship) { value.FreshnessKind = FreshnessKind("UNKNOWN") },
		"freshness coordinate":     func(value *Relationship) { when := value.UpdatedAt; value.FreshnessOrderTime = &when },
		"freshness sequence":       func(value *Relationship) { value.FreshnessOrderSequence = 0 },
		"provider digest":          func(value *Relationship) { value.ProviderVersionSHA256 = "bad" },
		"fact digest":              func(value *Relationship) { value.RelationFactSHA256 = "bad" },
		"provenance":               func(value *Relationship) { value.Provenance = Provenance("UNKNOWN") },
		"provenance source":        func(value *Relationship) { value.ProvenanceSourceID = "not-a-uuid" },
		"cross environment policy": func(value *Relationship) {
			value.CrossEnvironmentPolicyReferenceID = PolicyReferenceID("https://policy")
		},
		"same environment policy": func(value *Relationship) { value.CrossEnvironmentPolicyReferenceID = "policy-ref-v1" },
		"status":                  func(value *Relationship) { value.Status = RelationshipStatus("UNKNOWN") },
		"version":                 func(value *Relationship) { value.Version = 0 },
		"created time":            func(value *Relationship) { value.CreatedAt = value.CreatedAt.In(time.FixedZone("unsafe", 3600)) },
		"updated time":            func(value *Relationship) { value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond) },
	} {
		candidate := relationship.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Relationship.Validate(%s) error = %v", name, err)
		}
	}
	crossEnvironment := relationship.Clone()
	crossEnvironment.TargetEnvironmentID = "77777777-7777-4777-8777-777777777777"
	crossEnvironment.CrossEnvironmentPolicyReferenceID = PolicyReferenceID("policy-ref-v1")
	if err := crossEnvironment.Validate(); err != nil {
		t.Fatalf("valid cross-Environment Relationship.Validate() error = %v", err)
	}
	crossEnvironment.CrossEnvironmentPolicyReferenceID = ""
	if err := crossEnvironment.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("cross-Environment Relationship without policy error = %v, want ErrInvalidRequest", err)
	}
	timeOrderedRelationship := relationship.Clone()
	timeOrderedRelationship.FreshnessKind = FreshnessKind("OBJECT_TIME_SEQUENCE")
	freshnessTime := timeOrderedRelationship.UpdatedAt
	timeOrderedRelationship.FreshnessOrderTime = &freshnessTime
	if err := timeOrderedRelationship.Validate(); err != nil {
		t.Fatalf("valid OBJECT_TIME_SEQUENCE Relationship.Validate() error = %v", err)
	}

	conflict := validConflict()
	if err := conflict.Validate(); err != nil {
		t.Fatalf("valid Conflict.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*Conflict){
		"id":                func(value *Conflict) { value.ID = "not-a-uuid" },
		"scope":             func(value *Conflict) { value.Scope.EnvironmentID = "not-a-uuid" },
		"asset":             func(value *Conflict) { value.AssetID = "not-a-uuid" },
		"candidate":         func(value *Conflict) { value.CandidateAssetID = "not-a-uuid" },
		"candidate service": func(value *Conflict) { value.CandidateServiceID = "not-a-uuid" },
		"source":            func(value *Conflict) { value.SourceID = "not-a-uuid" },
		"observation":       func(value *Conflict) { value.ObservationID = "not-a-uuid" },
		"type":              func(value *Conflict) { value.Type = " conflict" },
		"field":             func(value *Conflict) { value.FieldName = "field\nunsafe" },
		"existing hash":     func(value *Conflict) { value.ExistingValueSHA256 = "bad" },
		"candidate hash":    func(value *Conflict) { value.CandidateValueSHA256 = "bad" },
		"missing candidate closure": func(value *Conflict) {
			value.CandidateAssetID = ""
			value.CandidateServiceID = ""
			value.FieldName = ""
			value.CandidateValueSHA256 = ""
		},
		"status":             func(value *Conflict) { value.Status = ConflictStatus("UNKNOWN") },
		"open resolution":    func(value *Conflict) { value.Resolution = ConflictResolution("REJECT_CANDIDATE") },
		"open reason":        func(value *Conflict) { value.ResolutionReasonCode = "REVIEWED" },
		"open resolver":      func(value *Conflict) { value.ResolvedBy = "oidc:subject-1" },
		"open resolved time": func(value *Conflict) { resolved := value.UpdatedAt; value.ResolvedAt = &resolved },
		"version":            func(value *Conflict) { value.Version = 0 },
		"created time":       func(value *Conflict) { value.CreatedAt = value.CreatedAt.In(time.FixedZone("unsafe", 3600)) },
		"updated time":       func(value *Conflict) { value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond) },
	} {
		candidate := conflict.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Conflict.Validate(%s) error = %v", name, err)
		}
	}
	serviceCandidate := conflict.Clone()
	serviceCandidate.CandidateAssetID = ""
	serviceCandidate.CandidateServiceID = testServiceID
	serviceCandidate.FieldName = ""
	serviceCandidate.CandidateValueSHA256 = ""
	if err := serviceCandidate.Validate(); err != nil {
		t.Fatalf("valid service-candidate Conflict.Validate() error = %v", err)
	}
	fieldCandidate := conflict.Clone()
	fieldCandidate.CandidateAssetID = ""
	if err := fieldCandidate.Validate(); err != nil {
		t.Fatalf("valid field-candidate Conflict.Validate() error = %v", err)
	}

	resolved := conflict.Clone()
	resolved.Status = ConflictStatus("RESOLVED")
	resolved.Resolution = ConflictResolution("REJECT_CANDIDATE")
	resolved.ResolutionReasonCode = "REVIEWED"
	resolved.ResolvedBy = "oidc:subject-1"
	resolvedAt := resolved.UpdatedAt
	resolved.ResolvedAt = &resolvedAt
	if err := resolved.Validate(); err != nil {
		t.Fatalf("valid resolved Conflict.Validate() error = %v", err)
	}
	rejected := resolved.Clone()
	rejected.Status = ConflictStatus("REJECTED")
	if err := rejected.Validate(); err != nil {
		t.Fatalf("valid rejected Conflict.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*Conflict){
		"terminal resolution": func(value *Conflict) { value.Resolution = "" },
		"terminal reason":     func(value *Conflict) { value.ResolutionReasonCode = "" },
		"terminal resolver":   func(value *Conflict) { value.ResolvedBy = "" },
		"terminal time":       func(value *Conflict) { value.ResolvedAt = nil },
		"unknown resolution":  func(value *Conflict) { value.Resolution = ConflictResolution("UNKNOWN") },
		"unsafe reason":       func(value *Conflict) { value.ResolutionReasonCode = "reviewed\nunsafe" },
		"unsafe resolver":     func(value *Conflict) { value.ResolvedBy = " oidc:subject-1" },
		"non-UTC time": func(value *Conflict) {
			when := value.ResolvedAt.In(time.FixedZone("unsafe", 3600))
			value.ResolvedAt = &when
		},
		"sub-microsecond time": func(value *Conflict) {
			when := value.ResolvedAt.Add(time.Nanosecond)
			value.ResolvedAt = &when
		},
	} {
		candidate := resolved.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("terminal Conflict.Validate(%s) error = %v", name, err)
		}
	}

	binding := validServiceAssetBinding()
	if err := binding.Validate(); err != nil {
		t.Fatalf("valid ServiceAssetBinding.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*ServiceAssetBinding){
		"id":                func(value *ServiceAssetBinding) { value.ID = "not-a-uuid" },
		"service":           func(value *ServiceAssetBinding) { value.ServiceID = "not-a-uuid" },
		"asset":             func(value *ServiceAssetBinding) { value.AssetID = "not-a-uuid" },
		"scope":             func(value *ServiceAssetBinding) { value.Scope.EnvironmentID = "not-a-uuid" },
		"role":              func(value *ServiceAssetBinding) { value.Role = BindingRole("UNKNOWN") },
		"mapping":           func(value *ServiceAssetBinding) { value.MappingStatus = domain.MappingStatus("UNKNOWN") },
		"provenance":        func(value *ServiceAssetBinding) { value.Provenance = Provenance("UNKNOWN") },
		"provenance source": func(value *ServiceAssetBinding) { value.ProvenanceSourceID = "not-a-uuid" },
		"discovered without provenance source": func(value *ServiceAssetBinding) {
			value.Provenance = Provenance("DISCOVERED")
		},
		"manual with provenance source": func(value *ServiceAssetBinding) { value.ProvenanceSourceID = testSourceID },
		"status":                        func(value *ServiceAssetBinding) { value.Status = BindingStatus("UNKNOWN") },
		"version":                       func(value *ServiceAssetBinding) { value.Version = 0 },
		"created time":                  func(value *ServiceAssetBinding) { value.CreatedAt = value.CreatedAt.In(time.FixedZone("unsafe", 3600)) },
		"updated time":                  func(value *ServiceAssetBinding) { value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond) },
	} {
		candidate := binding
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("ServiceAssetBinding.Validate(%s) error = %v", name, err)
		}
	}
	discoveredBinding := binding
	discoveredBinding.Provenance = Provenance("DISCOVERED")
	discoveredBinding.ProvenanceSourceID = testSourceID
	if err := discoveredBinding.Validate(); err != nil {
		t.Fatalf("valid discovered ServiceAssetBinding.Validate() error = %v", err)
	}
	mergeBinding := binding
	mergeBinding.Provenance = Provenance("MERGE_DECISION")
	if err := mergeBinding.Validate(); err != nil {
		t.Fatalf("valid merge-decision ServiceAssetBinding.Validate() error = %v", err)
	}

	observation := validObservation()
	if err := observation.Validate(); err != nil {
		t.Fatalf("valid Observation.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*Observation){
		"id":                    func(value *Observation) { value.ID = "not-a-uuid" },
		"source":                func(value *Observation) { value.SourceID = "not-a-uuid" },
		"run":                   func(value *Observation) { value.RunID = "not-a-uuid" },
		"provider":              func(value *Observation) { value.ProviderKind = "manual/v1" },
		"external":              func(value *Observation) { value.ExternalID = " external" },
		"scope":                 func(value *Observation) { value.Scope.EnvironmentID = "not-a-uuid" },
		"revision":              func(value *Observation) { value.SourceRevision = 0 },
		"revision digest":       func(value *Observation) { value.CanonicalRevisionDigest = "bad" },
		"definition digest":     func(value *Observation) { value.SourceDefinitionDigest = "bad" },
		"observed":              func(value *Observation) { value.ObservedAt = value.ObservedAt.Add(time.Nanosecond) },
		"freshness":             func(value *Observation) { value.FreshnessKind = FreshnessKind("UNKNOWN") },
		"freshness coordinate":  func(value *Observation) { when := value.ObservedAt; value.FreshnessOrderTime = &when },
		"freshness sequence":    func(value *Observation) { value.FreshnessOrderSequence = 0 },
		"provider version":      func(value *Observation) { value.ProviderVersionSHA256 = "bad" },
		"provider fact":         func(value *Observation) { value.ProviderFactSHA256 = "bad" },
		"fingerprint":           func(value *Observation) { value.FingerprintSHA256 = "bad" },
		"provenance digest":     func(value *Observation) { value.ProviderProvenanceSHA256 = "bad" },
		"previous half":         func(value *Observation) { value.PreviousObservationID = testAssetID },
		"previous chain half":   func(value *Observation) { value.PreviousChainSHA256 = testDigestA },
		"chain":                 func(value *Observation) { value.ObservationChainSHA256 = "bad" },
		"checkpoint":            func(value *Observation) { value.AcceptedCheckpointVersion = 0 },
		"fence":                 func(value *Observation) { value.RunFenceEpoch = 0 },
		"page":                  func(value *Observation) { value.RunPageSequence = 0 },
		"schema":                func(value *Observation) { value.SchemaVersion = " schema" },
		"document":              func(value *Observation) { value.NormalizedDocument = []byte(`[]`) },
		"document hash":         func(value *Observation) { value.DocumentSHA256 = testDigestB },
		"field provenance":      func(value *Observation) { value.FieldProvenance = []byte(`[]`) },
		"field provenance hash": func(value *Observation) { value.FieldProvenanceSHA256 = testDigestB },
		"unknown field ownership": func(value *Observation) {
			value.FieldProvenance = bytes.Replace(value.FieldProvenance, []byte(`"ownership":"SOURCE"`), []byte(`"ownership":"UNKNOWN"`), 1)
			value.FieldProvenanceSHA256 = testSHA256Hex(value.FieldProvenance)
			value.ProviderProvenanceSHA256 = value.FieldProvenanceSHA256
		},
		"tombstone without reason": func(value *Observation) { value.Tombstone = true },
		"tombstone reason":         func(value *Observation) { value.TombstoneReasonCode = "UNEXPECTED" },
		"created":                  func(value *Observation) { value.CreatedAt = value.CreatedAt.In(time.FixedZone("unsafe", 3600)) },
	} {
		candidate := observation.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Observation.Validate(%s) error = %v", name, err)
		}
	}
	timeOrderedObservation := observation.Clone()
	timeOrderedObservation.FreshnessKind = FreshnessKind("OBJECT_TIME_SEQUENCE")
	observationTime := timeOrderedObservation.ObservedAt
	timeOrderedObservation.FreshnessOrderTime = &observationTime
	if err := timeOrderedObservation.Validate(); err != nil {
		t.Fatalf("valid OBJECT_TIME_SEQUENCE Observation.Validate() error = %v", err)
	}
	checkpointObservation := observation.Clone()
	checkpointObservation.FreshnessKind = FreshnessKind("CHECKPOINT_SEQUENCE")
	if err := checkpointObservation.Validate(); err != nil {
		t.Fatalf("valid CHECKPOINT_SEQUENCE Observation.Validate() error = %v", err)
	}
	previousObservation := observation.Clone()
	previousObservation.PreviousObservationID = testAssetID
	previousObservation.PreviousChainSHA256 = testDigestB
	if err := previousObservation.Validate(); err != nil {
		t.Fatalf("valid chained Observation.Validate() error = %v", err)
	}
	tombstoneObservation := observation.Clone()
	tombstoneObservation.NormalizedDocument = nil
	tombstoneObservation.DocumentSHA256 = ""
	tombstoneObservation.Tombstone = true
	tombstoneObservation.TombstoneReasonCode = "PROVIDER_DELETED"
	if err := tombstoneObservation.Validate(); err != nil {
		t.Fatalf("valid tombstone Observation.Validate() error = %v", err)
	}

	run := validQueuedSourceRun()
	if err := run.Validate(); err != nil {
		t.Fatalf("valid SourceRun.Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*SourceRun){
		"id":                           func(value *SourceRun) { value.ID = "not-a-uuid" },
		"source":                       func(value *SourceRun) { value.SourceID = "not-a-uuid" },
		"scope":                        func(value *SourceRun) { value.Scope.WorkspaceID = "not-a-uuid" },
		"revision":                     func(value *SourceRun) { value.SourceRevision = 0 },
		"revision digest":              func(value *SourceRun) { value.SourceRevisionDigest = "bad" },
		"kind":                         func(value *SourceRun) { value.Kind = RunKind("UNKNOWN") },
		"status":                       func(value *SourceRun) { value.Status = RunStatus("UNKNOWN") },
		"stage":                        func(value *SourceRun) { value.Stage = RunStage("UNKNOWN") },
		"stage time":                   func(value *SourceRun) { value.StageChangedAt = value.StageChangedAt.Add(time.Nanosecond) },
		"trigger":                      func(value *SourceRun) { value.TriggerType = TriggerType("UNKNOWN") },
		"negative gate":                func(value *SourceRun) { value.GateRevision = -1 },
		"negative page":                func(value *SourceRun) { value.PageSequence = -1 },
		"page without digest":          func(value *SourceRun) { value.PageSequence = 1 },
		"page digest without page":     func(value *SourceRun) { value.PageDigest = testDigestA },
		"negative relation page":       func(value *SourceRun) { value.RelationPageSequence = -1 },
		"relation page without digest": func(value *SourceRun) { value.RelationPageSequence = 1 },
		"relation digest without page": func(value *SourceRun) { value.RelationPageDigest = testDigestA },
		"malformed cursor before":      func(value *SourceRun) { value.CursorBeforeSHA256 = "bad" },
		"malformed cursor after":       func(value *SourceRun) { value.CursorAfterSHA256 = "bad" },
		"negative checkpoint":          func(value *SourceRun) { value.CheckpointVersion = -1 },
		"not before":                   func(value *SourceRun) { value.NotBefore = value.NotBefore.In(time.FixedZone("unsafe", 3600)) },
		"queued lease":                 func(value *SourceRun) { lease := value.CreatedAt.Add(time.Minute); value.LeaseExpiresAt = &lease },
		"queued fence":                 func(value *SourceRun) { value.FenceEpoch = 1 },
		"queued heartbeat sequence":    func(value *SourceRun) { value.HeartbeatSequence = 1 },
		"queued final page":            func(value *SourceRun) { value.FinalPage = true },
		"queued complete snapshot":     func(value *SourceRun) { value.CompleteSnapshot = true },
		"queued effective snapshot":    func(value *SourceRun) { value.EffectiveCompleteSnapshot = true },
		"work result kind partial":     func(value *SourceRun) { value.WorkResultKind = WorkResultKind("DATA_PROJECTION") },
		"work result status partial":   func(value *SourceRun) { value.WorkResultStatus = WorkResultStatus("SUCCEEDED") },
		"work result digest partial":   func(value *SourceRun) { value.WorkResultDigest = testDigestA },
		"work result time partial":     func(value *SourceRun) { recorded := value.CreatedAt; value.WorkResultRecordedAt = &recorded },
		"validation outcome partial":   func(value *SourceRun) { value.ValidationOutcome = ValidationOutcome("SUCCEEDED") },
		"validation proof partial":     func(value *SourceRun) { value.ValidationProofDigest = testDigestA },
		"negative observed":            func(value *SourceRun) { value.Observed = -1 },
		"negative created":             func(value *SourceRun) { value.Created = -1 },
		"negative changed":             func(value *SourceRun) { value.Changed = -1 },
		"negative unchanged":           func(value *SourceRun) { value.Unchanged = -1 },
		"negative conflicts":           func(value *SourceRun) { value.Conflicts = -1 },
		"negative missing":             func(value *SourceRun) { value.Missing = -1 },
		"negative stale":               func(value *SourceRun) { value.Stale = -1 },
		"negative restored":            func(value *SourceRun) { value.Restored = -1 },
		"negative tombstoned":          func(value *SourceRun) { value.Tombstoned = -1 },
		"negative rejected":            func(value *SourceRun) { value.Rejected = -1 },
		"cleanup":                      func(value *SourceRun) { value.CredentialCleanupStatus = CredentialCleanupStatus("UNKNOWN") },
		"queued failure":               func(value *SourceRun) { value.FailureCode = "SOURCE_FAILURE" },
		"trace":                        func(value *SourceRun) { value.TraceID = "trace\nunsafe" },
		"version":                      func(value *SourceRun) { value.Version = 0 },
		"created":                      func(value *SourceRun) { value.CreatedAt = value.CreatedAt.Add(time.Nanosecond) },
		"queued started":               func(value *SourceRun) { started := value.CreatedAt; value.StartedAt = &started },
		"queued heartbeat":             func(value *SourceRun) { heartbeat := value.CreatedAt; value.HeartbeatAt = &heartbeat },
		"queued completed":             func(value *SourceRun) { completed := value.CreatedAt; value.CompletedAt = &completed },
	} {
		candidate := run.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("SourceRun.Validate(%s) error = %v", name, err)
		}
	}
}

func TestSourceRunValidationCoversRunningWorkResultAndTerminalClosures(t *testing.T) {
	t.Parallel()

	running := validRunningSourceRun()
	delayed := validDelayedSourceRun()
	finalizing := validFinalizingDataSourceRun()
	succeeded := validSucceededDataSourceRun()
	partial := validPartialDataSourceRun()
	validation := validSucceededValidationSourceRun()
	failed := validFailedSourceRun()
	cancelled := validCancelledSourceRun()
	for name, run := range map[string]SourceRun{
		"delayed": delayed, "running": running, "finalizing data": finalizing,
		"succeeded data": succeeded, "partial data": partial, "succeeded validation": validation,
		"failed intent": failed, "cancelled": cancelled,
	} {
		if err := run.Validate(); err != nil {
			t.Errorf("valid %s SourceRun.Validate() error = %v", name, err)
		}
	}

	for name, mutate := range map[string]func(*SourceRun){
		"waiting stage":        func(value *SourceRun) { value.Stage = RunStage("WAITING") },
		"missing started":      func(value *SourceRun) { value.StartedAt = nil },
		"missing heartbeat":    func(value *SourceRun) { value.HeartbeatAt = nil },
		"missing live lease":   func(value *SourceRun) { value.LeaseExpiresAt = nil },
		"zero fence":           func(value *SourceRun) { value.FenceEpoch = 0 },
		"zero heartbeat seq":   func(value *SourceRun) { value.HeartbeatSequence = 0 },
		"premature completion": func(value *SourceRun) { completed := value.StageChangedAt; value.CompletedAt = &completed },
	} {
		candidate := running.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("running SourceRun.Validate(%s) error = %v", name, err)
		}
	}

	for name, mutate := range map[string]func(*SourceRun){
		"missing work kind":   func(value *SourceRun) { value.WorkResultKind = "" },
		"missing work status": func(value *SourceRun) { value.WorkResultStatus = "" },
		"missing work digest": func(value *SourceRun) { value.WorkResultDigest = "" },
		"missing work time":   func(value *SourceRun) { value.WorkResultRecordedAt = nil },
		"completed too early": func(value *SourceRun) { completed := value.StageChangedAt; value.CompletedAt = &completed },
		"missing lease":       func(value *SourceRun) { value.LeaseExpiresAt = nil },
	} {
		candidate := finalizing.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("finalizing SourceRun.Validate(%s) error = %v", name, err)
		}
	}

	for name, mutate := range map[string]func(*SourceRun){
		"nonterminal stage":  func(value *SourceRun) { value.Stage = RunStage("CLEANING_UP") },
		"missing completion": func(value *SourceRun) { value.CompletedAt = nil },
		"data work failed":   func(value *SourceRun) { value.WorkResultStatus = WorkResultStatus("FAILED") },
		"validation on data": func(value *SourceRun) { value.ValidationOutcome = ValidationOutcome("SUCCEEDED") },
		"complete without final": func(value *SourceRun) {
			value.FinalPage = false
			value.CompleteSnapshot = true
		},
		"effective without complete": func(value *SourceRun) {
			value.CompleteSnapshot = false
			value.EffectiveCompleteSnapshot = true
		},
		"effective with rejection": func(value *SourceRun) {
			value.CompleteSnapshot = true
			value.EffectiveCompleteSnapshot = true
			value.Rejected = 1
		},
		"completion before start": func(value *SourceRun) {
			completed := value.StartedAt.Add(-time.Second)
			value.CompletedAt = &completed
		},
		"sub-microsecond completion": func(value *SourceRun) {
			completed := value.CompletedAt.Add(time.Nanosecond)
			value.CompletedAt = &completed
		},
	} {
		candidate := succeeded.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("succeeded SourceRun.Validate(%s) error = %v", name, err)
		}
	}
	terminalWithPersistedLease := succeeded.Clone()
	persistedLease := terminalWithPersistedLease.HeartbeatAt.Add(time.Minute)
	terminalWithPersistedLease.LeaseExpiresAt = &persistedLease
	if err := terminalWithPersistedLease.Validate(); err != nil {
		t.Fatalf("terminal SourceRun with persisted lease evidence error = %v", err)
	}

	for name, mutate := range map[string]func(*SourceRun){
		"outcome mismatch":   func(value *SourceRun) { value.ValidationOutcome = ValidationOutcome("FAILED") },
		"missing outcome":    func(value *SourceRun) { value.ValidationOutcome = "" },
		"missing proof":      func(value *SourceRun) { value.ValidationProofDigest = "" },
		"non-validation run": func(value *SourceRun) { value.Kind = RunKind("DISCOVERY") },
		"data work kind":     func(value *SourceRun) { value.WorkResultKind = WorkResultKind("DATA_PROJECTION") },
	} {
		candidate := validation.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("validation SourceRun.Validate(%s) error = %v", name, err)
		}
	}

	for name, mutate := range map[string]func(*SourceRun){
		"failure intent succeeded": func(value *SourceRun) { value.WorkResultStatus = WorkResultStatus("SUCCEEDED") },
		"validation outcome":       func(value *SourceRun) { value.ValidationOutcome = ValidationOutcome("FAILED") },
		"validation proof":         func(value *SourceRun) { value.ValidationProofDigest = testDigestA },
		"missing failure intent":   func(value *SourceRun) { value.WorkResultKind = "" },
	} {
		candidate := failed.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("failed SourceRun.Validate(%s) error = %v", name, err)
		}
	}
}

func TestSourceValidationAcceptsInitialClosureAndRejectsMalformedRetainedFacts(t *testing.T) {
	t.Parallel()

	source, _ := validPublishedBinding(t)
	initial := source.Clone()
	initial.PublishedRevision = 0
	initial.PublishedRevisionDigest = ""
	initial.GateStatus = SourceGateUnavailable
	initial.GateRevision = 0
	initial.ValidatedRunID = ""
	initial.ValidationDigest = ""
	initial.ValidatedBindingDigest = ""
	initial.CheckpointSHA256 = ""
	initial.CheckpointVersion = 0
	initial.CheckpointSourceRevision = 0
	if err := initial.Validate(); err != nil {
		t.Fatalf("initial unpublished Source.Validate() error = %v", err)
	}

	for name, mutate := range map[string]func(*Source){
		"published revision without digest": func(value *Source) { value.PublishedRevisionDigest = "" },
		"published digest without revision": func(value *Source) { value.PublishedRevision = 0 },
		"malformed retained validation run": func(value *Source) {
			value.GateStatus = SourceGateDegraded
			value.ValidatedRunID = "not-a-uuid"
		},
		"malformed retained validation digest": func(value *Source) {
			value.GateStatus = SourceGateSuspended
			value.ValidationDigest = "bad"
		},
		"malformed retained binding digest": func(value *Source) {
			value.GateStatus = SourceGateUnavailable
			value.ValidatedBindingDigest = "bad"
		},
		"manual provider checkpoint hash": func(value *Source) {
			value.CheckpointVersion = 1
			value.CheckpointSHA256 = testDigestA
		},
	} {
		candidate := source.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Source.Validate(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestSourceRevisionValidationMatchesPersistentStateAndProfileClosure(t *testing.T) {
	t.Parallel()

	_, published := validPublishedBinding(t)
	for _, test := range []struct {
		name   string
		status SourceRevisionStatus
		runID  string
		digest string
	}{
		{"draft", SourceRevisionDraft, "", ""},
		{"validating", SourceRevisionValidating, published.ValidationRunID, ""},
		{"validated", SourceRevisionValidated, published.ValidationRunID, published.ValidationDigest},
		{"rejected", SourceRevisionRejected, published.ValidationRunID, published.ValidationDigest},
		{"published", SourceRevisionPublished, published.ValidationRunID, published.ValidationDigest},
		{"superseded", SourceRevisionSuperseded, published.ValidationRunID, published.ValidationDigest},
	} {
		candidate := published.Clone()
		candidate.Status = test.status
		candidate.ValidationRunID = test.runID
		candidate.ValidationDigest = test.digest
		if err := candidate.Validate(); err != nil {
			t.Errorf("valid %s SourceRevision.Validate() error = %v", test.name, err)
		}
	}

	for name, mutate := range map[string]func(*SourceRevision){
		"draft with validation":  func(value *SourceRevision) { value.Status = SourceRevisionDraft },
		"validating with digest": func(value *SourceRevision) { value.Status = SourceRevisionValidating },
		"validated without proof": func(value *SourceRevision) {
			value.Status = SourceRevisionValidated
			value.ValidationRunID = ""
			value.ValidationDigest = ""
		},
		"rejected without proof": func(value *SourceRevision) {
			value.Status = SourceRevisionRejected
			value.ValidationRunID = ""
			value.ValidationDigest = ""
		},
		"superseded without proof": func(value *SourceRevision) {
			value.Status = SourceRevisionSuperseded
			value.ValidationRunID = ""
			value.ValidationDigest = ""
		},
	} {
		candidate := published.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("SourceRevision.Validate(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}

	twoAuthorities := published.Clone()
	twoAuthorities.AuthorityEnvironmentIDs = []string{testEnvironmentID, "77777777-7777-4777-8777-777777777777"}
	twoAuthorities.AuthorityScopeDigest, _ = AuthorityScopeDigest(twoAuthorities.AuthorityEnvironmentIDs)
	twoAuthorities.CanonicalRevisionDigest = twoAuthorities.BindingDigest()
	if err := twoAuthorities.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("SINGLE_ENVIRONMENT revision with two authorities error = %v", err)
	}

	_, explicitRevision := validLocallyClosedUninstalledBinding(t)
	explicitRevision.AuthorityEnvironmentIDs = []string{testEnvironmentID, "77777777-7777-4777-8777-777777777777"}
	explicitRevision.AuthorityScopeDigest, _ = AuthorityScopeDigest(explicitRevision.AuthorityEnvironmentIDs)
	explicitRevision.CanonicalRevisionDigest = explicitRevision.BindingDigest()
	if err := explicitRevision.Validate(); err != nil {
		t.Fatalf("valid sorted EXPLICIT_ITEM_ENVIRONMENT revision error = %v", err)
	}
	unsortedAuthorities := explicitRevision.Clone()
	slices.Reverse(unsortedAuthorities.AuthorityEnvironmentIDs)
	if err := unsortedAuthorities.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unsorted revision authorities error = %v", err)
	}

	oversizeSchema := published.Clone()
	oversizeSchema.CanonicalProviderSchema = []byte(`{"safe":"` + strings.Repeat("a", 65536) + `"}`)
	oversizeSchema.CanonicalProviderSchemaSHA256 = testSHA256Hex(oversizeSchema.CanonicalProviderSchema)
	manifestRaw, _ := hex.DecodeString(oversizeSchema.ProfileManifestSHA256)
	schemaRaw, _ := hex.DecodeString(oversizeSchema.CanonicalProviderSchemaSHA256)
	oversizeSchema.SourceDefinitionDigest = framedDigest([][]byte{
		[]byte("asset-source-definition.v2"), []byte(SourceKindManual), []byte("MANUAL_V1"),
		[]byte("MANUAL_V1"), manifestRaw, schemaRaw,
	})
	oversizeSchema.CanonicalRevisionDigest = oversizeSchema.BindingDigest()
	if err := oversizeSchema.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversize provider schema error = %v", err)
	}

	for name, mutate := range map[string]func(*SourceRevision){
		"rate requests above SQL maximum": func(value *SourceRevision) { value.RateLimitRequests = 1_000_001 },
		"rate window above SQL maximum":   func(value *SourceRevision) { value.RateLimitWindowSeconds = 86_401 },
		"backpressure base above SQL maximum": func(value *SourceRevision) {
			value.BackpressureBaseSeconds = 86_401
			value.BackpressureMaxSeconds = 86_401
		},
		"backpressure max above SQL maximum": func(value *SourceRevision) { value.BackpressureMaxSeconds = 604_801 },
		"backpressure max below base": func(value *SourceRevision) {
			value.BackpressureBaseSeconds = 2
			value.BackpressureMaxSeconds = 1
		},
	} {
		candidate := published.Clone()
		mutate(&candidate)
		if digest := candidate.BindingDigest(); digest != "" {
			t.Errorf("BindingDigest(%s) = %q, want fail closed", name, digest)
		}
	}

	assertSourceKindExtensionMatrix(t)
}

func TestObservationAndRelationshipValidateReplayAndPayloadClosure(t *testing.T) {
	t.Parallel()

	observation := validObservation()
	if observation.ProviderProvenanceSHA256 == observation.FieldProvenanceSHA256 {
		t.Fatal("test fixture collapsed distinct provider and field provenance digests")
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("valid independent-provenance Observation.Validate() error = %v", err)
	}

	emptyProvenance := observation.Clone()
	emptyProvenance.FieldProvenance = []byte(`{}`)
	emptyProvenance.FieldProvenanceSHA256 = testSHA256Hex(emptyProvenance.FieldProvenance)
	if err := emptyProvenance.Validate(); err != nil {
		t.Fatalf("empty canonical field provenance error = %v", err)
	}

	for name, mutate := range map[string]func(*Observation){
		"catalog sequence drift": func(value *Observation) { value.FreshnessOrderSequence++ },
		"checkpoint sequence drift": func(value *Observation) {
			value.FreshnessKind = FreshnessCheckpointSequence
			value.FreshnessOrderSequence++
		},
		"oversize normalized document": func(value *Observation) {
			value.NormalizedDocument = []byte(`{"safe":"` + strings.Repeat("a", 65536) + `"}`)
			value.DocumentSHA256 = testSHA256Hex(value.NormalizedDocument)
		},
		"unknown provenance field": func(value *Observation) {
			value.FieldProvenance = bytes.Replace(value.FieldProvenance, []byte(`"display_name"`), []byte(`"unknown_field"`), 1)
			value.FieldProvenanceSHA256 = testSHA256Hex(value.FieldProvenance)
		},
		"provenance source drift": func(value *Observation) {
			value.FieldProvenance = bytes.Replace(value.FieldProvenance, []byte(testSourceID),
				[]byte("77777777-7777-4777-8777-777777777777"), 1)
			value.FieldProvenanceSHA256 = testSHA256Hex(value.FieldProvenance)
		},
	} {
		candidate := observation.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Observation.Validate(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}

	relationship := validRelationship()
	for name, mutate := range map[string]func(*Relationship){
		"self edge": func(value *Relationship) { value.TargetAssetID = value.SourceAssetID },
		"discovered source drift": func(value *Relationship) {
			value.ProvenanceSourceID = "77777777-7777-4777-8777-777777777777"
		},
		"catalog sequence drift": func(value *Relationship) { value.FreshnessOrderSequence++ },
		"checkpoint sequence drift": func(value *Relationship) {
			value.FreshnessKind = FreshnessCheckpointSequence
			value.FreshnessOrderSequence++
		},
	} {
		candidate := relationship.Clone()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Relationship.Validate(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestSourceRunValidationAcceptsRecoveryAndExactCleanupClosure(t *testing.T) {
	t.Parallel()

	runningCleanup := validRunningSourceRun()
	runningCleanup.Stage = RunStageCleaningUp
	if err := runningCleanup.Validate(); err != nil {
		t.Fatalf("RUNNING/CLEANING_UP SourceRun.Validate() error = %v", err)
	}

	finalizingPartial := validFinalizingDataSourceRun()
	finalizingPartial.WorkResultStatus = WorkResultStatusPartial
	if err := finalizingPartial.Validate(); err != nil {
		t.Fatalf("FINALIZING partial proposal error = %v", err)
	}

	finalizingValidationFailure := validFinalizingDataSourceRun()
	finalizingValidationFailure.Kind = RunKindValidation
	finalizingValidationFailure.GateRevision = 7
	finalizingValidationFailure.PageSequence = 0
	finalizingValidationFailure.PageDigest = ""
	finalizingValidationFailure.RelationPageSequence = 0
	finalizingValidationFailure.RelationPageDigest = ""
	finalizingValidationFailure.CheckpointVersion = 0
	finalizingValidationFailure.FinalPage = false
	finalizingValidationFailure.Observed = 0
	finalizingValidationFailure.Created = 0
	finalizingValidationFailure.WorkResultKind = WorkResultValidationProof
	finalizingValidationFailure.WorkResultStatus = WorkResultStatusFailed
	finalizingValidationFailure.ValidationOutcome = ValidationOutcomeFailed
	finalizingValidationFailure.ValidationProofDigest = testDigestB
	if err := finalizingValidationFailure.Validate(); err != nil {
		t.Fatalf("FINALIZING failed validation proposal error = %v", err)
	}

	finalizingFailureIntent := validFinalizingDataSourceRun()
	finalizingFailureIntent.WorkResultKind = WorkResultFailureIntent
	finalizingFailureIntent.WorkResultStatus = WorkResultStatusFailed
	finalizingFailureIntent.FinalPage = false
	if err := finalizingFailureIntent.Validate(); err != nil {
		t.Fatalf("FINALIZING failure intent error = %v", err)
	}

	failedValidation := validSucceededValidationSourceRun()
	failedValidation.Status = RunStatusFailed
	failedValidation.WorkResultStatus = WorkResultStatusFailed
	failedValidation.ValidationOutcome = ValidationOutcomeFailed
	failedValidation.FailureCode = "VALIDATION_REJECTED"
	if err := failedValidation.Validate(); err != nil {
		t.Fatalf("FAILED validation proof error = %v", err)
	}
	cleanupUncertain := validSucceededDataSourceRun()
	cleanupUncertain.Status = RunStatusFailed
	cleanupUncertain.CredentialCleanupStatus = CredentialCleanupUncertain
	cleanupUncertain.FailureCode = "CLEANUP_UNCERTAIN"
	if err := cleanupUncertain.Validate(); err != nil {
		t.Fatalf("FAILED cleanup-uncertain preserving data result error = %v", err)
	}
	notOpenedFailure := validFailedSourceRun()
	notOpenedFailure.CredentialCleanupStatus = CredentialCleanupNotOpened
	if err := notOpenedFailure.Validate(); err != nil {
		t.Fatalf("FAILED pre-credential failure intent error = %v", err)
	}
	notOpenedWithProgress := notOpenedFailure.Clone()
	notOpenedWithProgress.PageSequence = 1
	notOpenedWithProgress.PageDigest = testDigestA
	if err := notOpenedWithProgress.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("FAILED NOT_OPENED with committed progress error = %v, want ErrInvalidRequest", err)
	}

	cancelledAfterDelay := validDelayedSourceRun()
	cancelledAfterDelay.PageSequence = 1
	cancelledAfterDelay.PageDigest = testDigestA
	cancelledAfterDelay.CheckpointVersion = 1
	cancelledAfterDelay.Observed = 1
	completed := cancelledAfterDelay.NotBefore.Add(time.Second)
	cancelledAfterDelay.Status = RunStatusCancelled
	cancelledAfterDelay.Stage = RunStageCompleted
	cancelledAfterDelay.StageChangedAt = completed
	cancelledAfterDelay.CompletedAt = &completed
	if err := cancelledAfterDelay.Validate(); err != nil {
		t.Fatalf("CANCELLED released delayed attempt error = %v", err)
	}

	queuedWithCursorBaseline := validQueuedSourceRun()
	queuedWithCursorBaseline.CursorBeforeSHA256 = testDigestA
	queuedWithCursorBaseline.CheckpointVersion = 3
	if err := queuedWithCursorBaseline.Validate(); err != nil {
		t.Fatalf("QUEUED cursor-before/checkpoint baseline error = %v", err)
	}
	delayedAfterFirstPage := validDelayedSourceRun()
	delayedAfterFirstPage.CursorAfterSHA256 = testDigestB
	delayedAfterFirstPage.PageSequence = 1
	delayedAfterFirstPage.PageDigest = testDigestA
	delayedAfterFirstPage.CheckpointVersion = 1
	if err := delayedAfterFirstPage.Validate(); err != nil {
		t.Fatalf("DELAYED first-page cursor-after without cursor-before error = %v", err)
	}

	for name, candidate := range map[string]SourceRun{
		"data result without final page": func() SourceRun {
			value := validSucceededDataSourceRun()
			value.FinalPage = false
			return value
		}(),
		"succeeded without closed cleanup": func() SourceRun {
			value := validSucceededDataSourceRun()
			value.CredentialCleanupStatus = CredentialCleanupNotOpened
			return value
		}(),
		"partial with pending cleanup": func() SourceRun {
			value := validPartialDataSourceRun()
			value.CredentialCleanupStatus = CredentialCleanupPending
			return value
		}(),
		"cancelled with pending cleanup": func() SourceRun {
			value := cancelledAfterDelay.Clone()
			value.CredentialCleanupStatus = CredentialCleanupPending
			return value
		}(),
	} {
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("SourceRun.Validate(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}

	traceBoundary := validQueuedSourceRun()
	traceBoundary.TraceID = ""
	if err := traceBoundary.Validate(); err != nil {
		t.Fatalf("nullable SourceRun TraceID error = %v", err)
	}
	traceBoundary.TraceID = strings.Repeat("a", 128)
	if err := traceBoundary.Validate(); err != nil {
		t.Fatalf("128-byte SourceRun TraceID error = %v", err)
	}
	traceBoundary.TraceID += "a"
	if err := traceBoundary.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("129-byte SourceRun TraceID error = %v, want ErrInvalidRequest", err)
	}
}

func TestAssetCursorAndNullableConflictMatchRepositoryEncoding(t *testing.T) {
	t.Parallel()

	access, err := NewAssetReadConstraint(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := ListAssetsRequest{
		Scope:  Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID},
		Access: access, Sort: AssetSortDisplayNameAsc, Limit: 50,
	}
	displayDigest, err := base.QueryDigest()
	if err != nil {
		t.Fatal(err)
	}
	base.Cursor = &AssetCursor{Sort: AssetSortDisplayNameAsc, QueryDigest: displayDigest, Value: "payments-api", AssetID: testAssetID}
	if _, err := base.QueryDigest(); err != nil {
		t.Fatalf("canonical lower(display_name) cursor error = %v", err)
	}
	base.Cursor.Value = "Payments-API"
	if digest, err := base.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
		t.Fatalf("noncanonical display cursor = (%q, %v)", digest, err)
	}

	base.Cursor = nil
	base.Sort = AssetSortLastObservedDesc
	timeDigest, err := base.QueryDigest()
	if err != nil {
		t.Fatal(err)
	}
	base.Cursor = &AssetCursor{Sort: AssetSortLastObservedDesc, QueryDigest: timeDigest, Value: "2026-07-15T01:02:03Z", AssetID: testAssetID}
	if _, err := base.QueryDigest(); err != nil {
		t.Fatalf("canonical RFC3339Nano whole-second cursor error = %v", err)
	}
	for _, invalid := range []string{"2026-07-15T01:02:03.000000Z", "2026-07-15T01:02:03+00:00"} {
		base.Cursor.Value = invalid
		if digest, err := base.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("noncanonical time cursor %q = (%q, %v)", invalid, digest, err)
		}
	}

	conflict := validConflict()
	conflict.ExistingValueSHA256 = ""
	if err := conflict.Validate(); err != nil {
		t.Fatalf("nullable existing conflict digest error = %v", err)
	}

	asset := validAsset()
	asset.DisplayName = strings.Repeat("a", 256)
	if err := asset.Validate(); err != nil {
		t.Fatalf("256-byte Asset DisplayName error = %v", err)
	}
	asset.DisplayName += "a"
	if err := asset.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("257-byte Asset DisplayName error = %v, want ErrInvalidRequest", err)
	}
}

func TestEveryCursorQueryDigestBindsScopeFiltersAccessAndSort(t *testing.T) {
	t.Parallel()

	assetAccess, err := NewAssetReadConstraint(false, []string{testServiceID})
	if err != nil {
		t.Fatal(err)
	}
	sourceAccess, err := NewSourceReadConstraint([]string{testEnvironmentID})
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}

	assetRequest := ListAssetsRequest{Scope: scope, Access: assetAccess, Sort: AssetSort("display_name_asc"), Limit: 50, Filter: AssetFilter{Search: "database", ServiceID: testServiceID, Kinds: []Kind{Kind("DATABASE")}, SourceIDs: []string{testSourceID}, Lifecycles: []Lifecycle{Lifecycle("ACTIVE")}, MappingStatuses: []domain.MappingStatus{domain.MappingExact}, Criticalities: []Criticality{Criticality("HIGH")}, DataClassifications: []DataClassification{DataClassification("CONFIDENTIAL")}}}
	assertDigestMutation(t, "assets", assetRequest.QueryDigest, func() (string, error) {
		changed := assetRequest
		changed.Sort = AssetSort("last_observed_at_desc")
		return changed.QueryDigest()
	})
	assertDigestMutation(t, "assets access", assetRequest.QueryDigest, func() (string, error) {
		changed := assetRequest
		changed.Access, _ = NewAssetReadConstraint(true, nil)
		return changed.QueryDigest()
	})
	permuted := assetRequest
	permuted.Filter.Kinds = []Kind{Kind("DATABASE"), Kind("DATABASE")}
	if left, _ := assetRequest.QueryDigest(); left == "" {
		t.Fatal("asset query digest is empty")
	} else if right, err := permuted.QueryDigest(); err != nil || right != left {
		t.Fatalf("normalized asset filter digest = (%q, %v), want %q", right, err, left)
	}

	relationshipRequest := ListRelationshipsRequest{Scope: scope, Access: assetAccess, AssetID: testAssetID, SourceID: testSourceID, Types: []RelationshipType{RelationshipType("DEPENDS_ON")}, Statuses: []RelationshipStatus{RelationshipStatus("ACTIVE")}, Limit: 50}
	assertDigestMutation(t, "relationships", relationshipRequest.QueryDigest, func() (string, error) {
		changed := relationshipRequest
		changed.Types = []RelationshipType{RelationshipType("RUNS_ON")}
		return changed.QueryDigest()
	})
	bindingRequest := ListBindingsRequest{Scope: scope, Access: assetAccess, ServiceID: testServiceID, AssetID: testAssetID, Roles: []BindingRole{BindingRole("DEPENDENCY")}, Statuses: []BindingStatus{BindingStatus("ACTIVE")}, Limit: 50}
	assertDigestMutation(t, "bindings", bindingRequest.QueryDigest, func() (string, error) {
		changed := bindingRequest
		changed.Roles = []BindingRole{BindingRole("PRIMARY_RUNTIME")}
		return changed.QueryDigest()
	})
	conflictRequest := ListConflictsRequest{Scope: scope, Access: assetAccess, AssetID: testAssetID, SourceID: testSourceID, Statuses: []ConflictStatus{ConflictStatus("OPEN")}, Limit: 50}
	assertDigestMutation(t, "conflicts", conflictRequest.QueryDigest, func() (string, error) {
		changed := conflictRequest
		changed.Statuses = []ConflictStatus{ConflictStatus("RESOLVED")}
		return changed.QueryDigest()
	})
	sourceRequest := ListSourcesRequest{Scope: SourceScope{TenantID: testTenantID, WorkspaceID: testWorkspaceID}, Access: sourceAccess, Kinds: []SourceKind{SourceKind("MANUAL")}, Statuses: []SourceStatus{SourceStatus("ACTIVE")}, GateStatuses: []SourceGateStatus{SourceGateStatus("AVAILABLE")}, Usage: SourceUsage("manual_asset_create"), EnvironmentID: testEnvironmentID, Limit: 50}
	assertDigestMutation(t, "sources", sourceRequest.QueryDigest, func() (string, error) {
		changed := sourceRequest
		changed.EnvironmentID = "77777777-7777-4777-8777-777777777777"
		return changed.QueryDigest()
	})
}

func TestEveryCursorQueryDigestCoversEachIdentityFieldAndRejectsDrift(t *testing.T) {
	t.Parallel()

	assetAccess, err := NewAssetReadConstraint(false, []string{testServiceID})
	if err != nil {
		t.Fatal(err)
	}
	assetAccessOther, err := NewAssetReadConstraint(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceAccess, err := NewSourceReadConstraint([]string{testEnvironmentID})
	if err != nil {
		t.Fatal(err)
	}
	sourceAccessOther, err := NewSourceReadConstraint([]string{"77777777-7777-4777-8777-777777777777"})
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}
	otherScope := scope
	otherScope.EnvironmentID = "77777777-7777-4777-8777-777777777777"

	assets := ListAssetsRequest{
		Scope: scope, Access: assetAccess, Sort: AssetSort("display_name_asc"), Limit: 50,
		Filter: AssetFilter{
			Search: "database", ServiceID: testServiceID,
			Kinds: []Kind{"DATABASE", "LINUX_VM"}, SourceIDs: []string{testSourceID, "77777777-7777-4777-8777-777777777777"},
			Lifecycles: []Lifecycle{"ACTIVE", "STALE"}, MappingStatuses: []domain.MappingStatus{domain.MappingExact, domain.MappingAmbiguous},
			Criticalities: []Criticality{"HIGH", "CRITICAL"}, DataClassifications: []DataClassification{"INTERNAL", "CONFIDENTIAL"},
		},
	}
	assetDigest := mustQueryDigest(t, assets.QueryDigest)
	assetChanges := map[string]func() (string, error){
		"scope":  func() (string, error) { value := assets; value.Scope = otherScope; return value.QueryDigest() },
		"search": func() (string, error) { value := assets; value.Filter.Search = "host"; return value.QueryDigest() },
		"service filter": func() (string, error) {
			value := assets
			value.Filter.ServiceID = testAssetID
			return value.QueryDigest()
		},
		"kinds": func() (string, error) {
			value := assets
			value.Filter.Kinds = []Kind{"SERVICE"}
			return value.QueryDigest()
		},
		"sources": func() (string, error) {
			value := assets
			value.Filter.SourceIDs = []string{testSourceID}
			return value.QueryDigest()
		},
		"lifecycles": func() (string, error) {
			value := assets
			value.Filter.Lifecycles = []Lifecycle{"QUARANTINED"}
			return value.QueryDigest()
		},
		"mapping statuses": func() (string, error) {
			value := assets
			value.Filter.MappingStatuses = []domain.MappingStatus{domain.MappingUnresolved}
			return value.QueryDigest()
		},
		"criticalities": func() (string, error) {
			value := assets
			value.Filter.Criticalities = []Criticality{"LOW"}
			return value.QueryDigest()
		},
		"classifications": func() (string, error) {
			value := assets
			value.Filter.DataClassifications = []DataClassification{"PUBLIC"}
			return value.QueryDigest()
		},
		"server constraint": func() (string, error) { value := assets; value.Access = assetAccessOther; return value.QueryDigest() },
		"sort": func() (string, error) {
			value := assets
			value.Sort = AssetSort("last_observed_at_desc")
			return value.QueryDigest()
		},
	}
	assertEveryQueryDigestChanges(t, assetDigest, assetChanges)
	assetLimit := assets
	assetLimit.Limit = 100
	if got := mustQueryDigest(t, assetLimit.QueryDigest); got != assetDigest {
		t.Fatalf("asset Limit changed query identity: %q != %q", got, assetDigest)
	}
	assetPermuted := assets
	assetPermuted.Filter.Kinds = []Kind{"LINUX_VM", "DATABASE", "DATABASE"}
	assetPermuted.Filter.SourceIDs = []string{"77777777-7777-4777-8777-777777777777", testSourceID, testSourceID}
	assetPermuted.Filter.Lifecycles = []Lifecycle{"STALE", "ACTIVE", "ACTIVE"}
	assetPermuted.Filter.MappingStatuses = []domain.MappingStatus{domain.MappingAmbiguous, domain.MappingExact, domain.MappingExact}
	assetPermuted.Filter.Criticalities = []Criticality{"CRITICAL", "HIGH", "HIGH"}
	assetPermuted.Filter.DataClassifications = []DataClassification{"CONFIDENTIAL", "INTERNAL", "INTERNAL"}
	assetFilterBeforeDigest := cloneAssetFilterForTest(assetPermuted.Filter)
	if got := mustQueryDigest(t, assetPermuted.QueryDigest); got != assetDigest {
		t.Fatalf("asset set permutation/duplicates changed digest: %q != %q", got, assetDigest)
	}
	if !reflect.DeepEqual(assetPermuted.Filter, assetFilterBeforeDigest) {
		t.Fatal("Asset QueryDigest normalized caller-owned filter slices in place")
	}
	assets.Cursor = &AssetCursor{Sort: assets.Sort, QueryDigest: assetDigest, Value: "database", AssetID: testAssetID}
	if got := mustQueryDigest(t, assets.QueryDigest); got != assetDigest {
		t.Fatalf("matching AssetCursor changed digest: %q", got)
	}
	for name, mutate := range map[string]func(*ListAssetsRequest){
		"cursor digest":          func(value *ListAssetsRequest) { value.Cursor.QueryDigest = testDigestB },
		"cursor sort":            func(value *ListAssetsRequest) { value.Cursor.Sort = AssetSort("last_observed_at_desc") },
		"cursor control value":   func(value *ListAssetsRequest) { value.Cursor.Value = "bad\nvalue" },
		"cursor untrimmed value": func(value *ListAssetsRequest) { value.Cursor.Value = " database" },
		"cursor invalid UTF-8":   func(value *ListAssetsRequest) { value.Cursor.Value = string([]byte{0xff}) },
		"cursor asset UUID":      func(value *ListAssetsRequest) { value.Cursor.AssetID = "not-a-uuid" },
	} {
		candidate := assets
		cursor := *assets.Cursor
		candidate.Cursor = &cursor
		mutate(&candidate)
		if digest, err := candidate.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("AssetCursor %s drift = (%q, %v), want rejection", name, digest, err)
		}
	}
	lastObservedAssets := assets
	lastObservedAssets.Cursor = nil
	lastObservedAssets.Sort = AssetSort("last_observed_at_desc")
	lastObservedDigest := mustQueryDigest(t, lastObservedAssets.QueryDigest)
	lastObservedAssets.Cursor = &AssetCursor{
		Sort: lastObservedAssets.Sort, QueryDigest: lastObservedDigest,
		Value: "2026-07-15T01:02:03.123456Z", AssetID: testAssetID,
	}
	if got := mustQueryDigest(t, lastObservedAssets.QueryDigest); got != lastObservedDigest {
		t.Fatalf("matching last-observed AssetCursor changed digest: %q", got)
	}
	for name, value := range map[string]string{
		"noncanonical zero fraction": "2026-07-15T01:02:03.000000Z",
		"offset rather than UTC":     "2026-07-15T09:02:03.000000+08:00",
		"sub-microsecond":            "2026-07-15T01:02:03.000000001Z",
		"not a time":                 "database",
	} {
		candidate := lastObservedAssets
		cursor := *candidate.Cursor
		cursor.Value = value
		candidate.Cursor = &cursor
		if digest, err := candidate.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("last-observed AssetCursor %s = (%q, %v), want rejection", name, digest, err)
		}
	}

	relationships := ListRelationshipsRequest{Scope: scope, Access: assetAccess, AssetID: testAssetID, SourceID: testSourceID, Types: []RelationshipType{"DEPENDS_ON", "RUNS_ON"}, Statuses: []RelationshipStatus{"ACTIVE"}, Limit: 50}
	relationshipDigest := mustQueryDigest(t, relationships.QueryDigest)
	assertEveryQueryDigestChanges(t, relationshipDigest, map[string]func() (string, error){
		"scope": func() (string, error) { value := relationships; value.Scope = otherScope; return value.QueryDigest() },
		"access": func() (string, error) {
			value := relationships
			value.Access = assetAccessOther
			return value.QueryDigest()
		},
		"asset": func() (string, error) {
			value := relationships
			value.AssetID = testServiceID
			return value.QueryDigest()
		},
		"source": func() (string, error) {
			value := relationships
			value.SourceID = "77777777-7777-4777-8777-777777777777"
			return value.QueryDigest()
		},
		"types": func() (string, error) {
			value := relationships
			value.Types = []RelationshipType{"CONTAINS"}
			return value.QueryDigest()
		},
		"statuses": func() (string, error) {
			value := relationships
			value.Statuses = []RelationshipStatus{"INACTIVE"}
			return value.QueryDigest()
		},
	})
	permutedRelationships := relationships
	permutedRelationships.Types = []RelationshipType{"RUNS_ON", "DEPENDS_ON", "DEPENDS_ON"}
	permutedRelationships.Statuses = []RelationshipStatus{"ACTIVE", "ACTIVE"}
	relationshipTypesBefore := slices.Clone(permutedRelationships.Types)
	relationshipStatusesBefore := slices.Clone(permutedRelationships.Statuses)
	if got := mustQueryDigest(t, permutedRelationships.QueryDigest); got != relationshipDigest {
		t.Fatalf("relationship filter set permutation changed digest: %q != %q", got, relationshipDigest)
	}
	if !slices.Equal(permutedRelationships.Types, relationshipTypesBefore) || !slices.Equal(permutedRelationships.Statuses, relationshipStatusesBefore) {
		t.Fatal("Relationship QueryDigest normalized caller-owned slices in place")
	}
	relationships.Cursor = &RelationshipCursor{QueryDigest: relationshipDigest, Type: RelationshipType("DEPENDS_ON"), SourceAssetID: testAssetID, TargetAssetID: testServiceID, RelationshipID: "77777777-7777-4777-8777-777777777777"}
	assertCursorIdentity(t, "relationship", relationshipDigest, relationships.QueryDigest, func() (string, error) {
		value := relationships
		cursor := *value.Cursor
		cursor.QueryDigest = testDigestB
		value.Cursor = &cursor
		return value.QueryDigest()
	})
	for name, mutate := range map[string]func(*RelationshipCursor){
		"type":            func(cursor *RelationshipCursor) { cursor.Type = RelationshipType("UNKNOWN") },
		"source asset":    func(cursor *RelationshipCursor) { cursor.SourceAssetID = "not-a-uuid" },
		"target asset":    func(cursor *RelationshipCursor) { cursor.TargetAssetID = "not-a-uuid" },
		"relationship ID": func(cursor *RelationshipCursor) { cursor.RelationshipID = "not-a-uuid" },
	} {
		candidate := relationships
		cursor := *candidate.Cursor
		mutate(&cursor)
		candidate.Cursor = &cursor
		if digest, err := candidate.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("RelationshipCursor %s = (%q, %v), want rejection", name, digest, err)
		}
	}
	assertLimitIsNotQueryIdentity(t, "relationship", relationshipDigest, func(limit int) (string, error) {
		value := relationships
		value.Limit = limit
		return value.QueryDigest()
	})

	bindings := ListBindingsRequest{Scope: scope, Access: assetAccess, ServiceID: testServiceID, AssetID: testAssetID, Roles: []BindingRole{"DEPENDENCY", "PRIMARY_RUNTIME"}, Statuses: []BindingStatus{"ACTIVE"}, Limit: 50}
	bindingDigest := mustQueryDigest(t, bindings.QueryDigest)
	assertEveryQueryDigestChanges(t, bindingDigest, map[string]func() (string, error){
		"scope":   func() (string, error) { value := bindings; value.Scope = otherScope; return value.QueryDigest() },
		"access":  func() (string, error) { value := bindings; value.Access = assetAccessOther; return value.QueryDigest() },
		"service": func() (string, error) { value := bindings; value.ServiceID = testAssetID; return value.QueryDigest() },
		"asset":   func() (string, error) { value := bindings; value.AssetID = testServiceID; return value.QueryDigest() },
		"roles": func() (string, error) {
			value := bindings
			value.Roles = []BindingRole{"MANAGED_TARGET"}
			return value.QueryDigest()
		},
		"statuses": func() (string, error) {
			value := bindings
			value.Statuses = []BindingStatus{"INACTIVE"}
			return value.QueryDigest()
		},
	})
	permutedBindings := bindings
	permutedBindings.Roles = []BindingRole{"PRIMARY_RUNTIME", "DEPENDENCY", "DEPENDENCY"}
	permutedBindings.Statuses = []BindingStatus{"ACTIVE", "ACTIVE"}
	bindingRolesBefore := slices.Clone(permutedBindings.Roles)
	bindingStatusesBefore := slices.Clone(permutedBindings.Statuses)
	if got := mustQueryDigest(t, permutedBindings.QueryDigest); got != bindingDigest {
		t.Fatalf("binding filter set permutation changed digest: %q != %q", got, bindingDigest)
	}
	if !slices.Equal(permutedBindings.Roles, bindingRolesBefore) || !slices.Equal(permutedBindings.Statuses, bindingStatusesBefore) {
		t.Fatal("Binding QueryDigest normalized caller-owned slices in place")
	}
	bindings.Cursor = &BindingCursor{QueryDigest: bindingDigest, ServiceID: testServiceID, Role: BindingRole("DEPENDENCY"), AssetID: testAssetID, BindingID: "77777777-7777-4777-8777-777777777777"}
	assertCursorIdentity(t, "binding", bindingDigest, bindings.QueryDigest, func() (string, error) {
		value := bindings
		cursor := *value.Cursor
		cursor.QueryDigest = testDigestB
		value.Cursor = &cursor
		return value.QueryDigest()
	})
	for name, mutate := range map[string]func(*BindingCursor){
		"service":    func(cursor *BindingCursor) { cursor.ServiceID = "not-a-uuid" },
		"role":       func(cursor *BindingCursor) { cursor.Role = BindingRole("UNKNOWN") },
		"asset":      func(cursor *BindingCursor) { cursor.AssetID = "not-a-uuid" },
		"binding ID": func(cursor *BindingCursor) { cursor.BindingID = "not-a-uuid" },
	} {
		candidate := bindings
		cursor := *candidate.Cursor
		mutate(&cursor)
		candidate.Cursor = &cursor
		if digest, err := candidate.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("BindingCursor %s = (%q, %v), want rejection", name, digest, err)
		}
	}
	assertLimitIsNotQueryIdentity(t, "binding", bindingDigest, func(limit int) (string, error) { value := bindings; value.Limit = limit; return value.QueryDigest() })

	conflicts := ListConflictsRequest{Scope: scope, Access: assetAccess, AssetID: testAssetID, SourceID: testSourceID, Statuses: []ConflictStatus{"OPEN", "RESOLVED"}, Limit: 50}
	conflictDigest := mustQueryDigest(t, conflicts.QueryDigest)
	assertEveryQueryDigestChanges(t, conflictDigest, map[string]func() (string, error){
		"scope": func() (string, error) { value := conflicts; value.Scope = otherScope; return value.QueryDigest() },
		"access": func() (string, error) {
			value := conflicts
			value.Access = assetAccessOther
			return value.QueryDigest()
		},
		"asset": func() (string, error) { value := conflicts; value.AssetID = testServiceID; return value.QueryDigest() },
		"source": func() (string, error) {
			value := conflicts
			value.SourceID = "77777777-7777-4777-8777-777777777777"
			return value.QueryDigest()
		},
		"statuses": func() (string, error) {
			value := conflicts
			value.Statuses = []ConflictStatus{"REJECTED"}
			return value.QueryDigest()
		},
	})
	permutedConflicts := conflicts
	permutedConflicts.Statuses = []ConflictStatus{"RESOLVED", "OPEN", "OPEN"}
	conflictStatusesBefore := slices.Clone(permutedConflicts.Statuses)
	if got := mustQueryDigest(t, permutedConflicts.QueryDigest); got != conflictDigest {
		t.Fatalf("conflict filter set permutation changed digest: %q != %q", got, conflictDigest)
	}
	if !slices.Equal(permutedConflicts.Statuses, conflictStatusesBefore) {
		t.Fatal("Conflict QueryDigest normalized caller-owned slices in place")
	}
	conflicts.Cursor = &ConflictCursor{QueryDigest: conflictDigest, CreatedAt: time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC), ConflictID: "77777777-7777-4777-8777-777777777777"}
	assertCursorIdentity(t, "conflict", conflictDigest, conflicts.QueryDigest, func() (string, error) {
		value := conflicts
		cursor := *value.Cursor
		cursor.QueryDigest = testDigestB
		value.Cursor = &cursor
		return value.QueryDigest()
	})
	for name, mutate := range map[string]func(*ConflictCursor){
		"zero time":       func(cursor *ConflictCursor) { cursor.CreatedAt = time.Time{} },
		"non-UTC time":    func(cursor *ConflictCursor) { cursor.CreatedAt = cursor.CreatedAt.In(time.FixedZone("unsafe", 3600)) },
		"sub-microsecond": func(cursor *ConflictCursor) { cursor.CreatedAt = cursor.CreatedAt.Add(time.Nanosecond) },
		"conflict ID":     func(cursor *ConflictCursor) { cursor.ConflictID = "not-a-uuid" },
	} {
		candidate := conflicts
		cursor := *candidate.Cursor
		mutate(&cursor)
		candidate.Cursor = &cursor
		if digest, err := candidate.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("ConflictCursor %s = (%q, %v), want rejection", name, digest, err)
		}
	}
	assertLimitIsNotQueryIdentity(t, "conflict", conflictDigest, func(limit int) (string, error) { value := conflicts; value.Limit = limit; return value.QueryDigest() })

	sources := ListSourcesRequest{Scope: SourceScope{TenantID: testTenantID, WorkspaceID: testWorkspaceID}, Access: sourceAccess, Kinds: []SourceKind{"MANUAL", "CSV_IMPORT"}, Statuses: []SourceStatus{"ACTIVE", "PAUSED"}, GateStatuses: []SourceGateStatus{"AVAILABLE", "DEGRADED"}, Usage: SourceUsage("manual_asset_create"), EnvironmentID: testEnvironmentID, Limit: 50}
	sourceDigest := mustQueryDigest(t, sources.QueryDigest)
	assertEveryQueryDigestChanges(t, sourceDigest, map[string]func() (string, error){
		"scope": func() (string, error) {
			value := sources
			value.Scope.WorkspaceID = "77777777-7777-4777-8777-777777777777"
			return value.QueryDigest()
		},
		"access": func() (string, error) { value := sources; value.Access = sourceAccessOther; return value.QueryDigest() },
		"kinds": func() (string, error) {
			value := sources
			value.Kinds = []SourceKind{"CONTROL_PLANE_API"}
			return value.QueryDigest()
		},
		"statuses": func() (string, error) {
			value := sources
			value.Statuses = []SourceStatus{"DISABLED"}
			return value.QueryDigest()
		},
		"gates": func() (string, error) {
			value := sources
			value.GateStatuses = []SourceGateStatus{"SUSPENDED"}
			return value.QueryDigest()
		},
		"usage": func() (string, error) { value := sources; value.Usage = SourceUsage(""); return value.QueryDigest() },
		"environment": func() (string, error) {
			value := sources
			value.EnvironmentID = "77777777-7777-4777-8777-777777777777"
			return value.QueryDigest()
		},
	})
	permutedSources := sources
	permutedSources.Kinds = []SourceKind{"CSV_IMPORT", "MANUAL", "MANUAL"}
	permutedSources.Statuses = []SourceStatus{"PAUSED", "ACTIVE", "ACTIVE"}
	permutedSources.GateStatuses = []SourceGateStatus{"DEGRADED", "AVAILABLE", "AVAILABLE"}
	sourceKindsBefore := slices.Clone(permutedSources.Kinds)
	sourceStatusesBefore := slices.Clone(permutedSources.Statuses)
	sourceGatesBefore := slices.Clone(permutedSources.GateStatuses)
	if got := mustQueryDigest(t, permutedSources.QueryDigest); got != sourceDigest {
		t.Fatalf("source filter set permutation changed digest: %q != %q", got, sourceDigest)
	}
	if !slices.Equal(permutedSources.Kinds, sourceKindsBefore) || !slices.Equal(permutedSources.Statuses, sourceStatusesBefore) || !slices.Equal(permutedSources.GateStatuses, sourceGatesBefore) {
		t.Fatal("Source QueryDigest normalized caller-owned slices in place")
	}
	sources.Cursor = &SourceCursor{QueryDigest: sourceDigest, SourceID: testSourceID}
	assertCursorIdentity(t, "source", sourceDigest, sources.QueryDigest, func() (string, error) {
		value := sources
		cursor := *value.Cursor
		cursor.QueryDigest = testDigestB
		value.Cursor = &cursor
		return value.QueryDigest()
	})
	invalidSourceCursor := sources
	invalidCursor := *invalidSourceCursor.Cursor
	invalidCursor.SourceID = "not-a-uuid"
	invalidSourceCursor.Cursor = &invalidCursor
	if digest, err := invalidSourceCursor.QueryDigest(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
		t.Errorf("SourceCursor invalid UUID = (%q, %v), want rejection", digest, err)
	}
	assertLimitIsNotQueryIdentity(t, "source", sourceDigest, func(limit int) (string, error) { value := sources; value.Limit = limit; return value.QueryDigest() })

	invalidQueries := map[string]func() (string, error){
		"asset zero scope": func() (string, error) { value := assets; value.Scope = Scope{}; return value.QueryDigest() },
		"asset zero access": func() (string, error) {
			value := assets
			value.Access = AssetReadConstraint{}
			return value.QueryDigest()
		},
		"asset unknown sort": func() (string, error) {
			value := assets
			value.Cursor = nil
			value.Sort = AssetSort("unknown")
			return value.QueryDigest()
		},
		"asset invalid kind filter": func() (string, error) {
			value := assets
			value.Cursor = nil
			value.Filter.Kinds = []Kind{"UNKNOWN"}
			return value.QueryDigest()
		},
		"asset invalid source filter": func() (string, error) {
			value := assets
			value.Cursor = nil
			value.Filter.SourceIDs = []string{"not-a-uuid"}
			return value.QueryDigest()
		},
		"asset zero limit": func() (string, error) {
			value := assets
			value.Cursor = nil
			value.Limit = 0
			return value.QueryDigest()
		},
		"asset excessive limit": func() (string, error) {
			value := assets
			value.Cursor = nil
			value.Limit = 101
			return value.QueryDigest()
		},
		"relationship invalid type": func() (string, error) {
			value := relationships
			value.Cursor = nil
			value.Types = []RelationshipType{"UNKNOWN"}
			return value.QueryDigest()
		},
		"relationship zero access": func() (string, error) {
			value := relationships
			value.Cursor = nil
			value.Access = AssetReadConstraint{}
			return value.QueryDigest()
		},
		"binding invalid role": func() (string, error) {
			value := bindings
			value.Cursor = nil
			value.Roles = []BindingRole{"UNKNOWN"}
			return value.QueryDigest()
		},
		"conflict invalid status": func() (string, error) {
			value := conflicts
			value.Cursor = nil
			value.Statuses = []ConflictStatus{"UNKNOWN"}
			return value.QueryDigest()
		},
		"source zero scope": func() (string, error) {
			value := sources
			value.Cursor = nil
			value.Scope = SourceScope{}
			return value.QueryDigest()
		},
		"source zero access": func() (string, error) {
			value := sources
			value.Cursor = nil
			value.Access = SourceReadConstraint{}
			return value.QueryDigest()
		},
		"source invalid usage": func() (string, error) {
			value := sources
			value.Cursor = nil
			value.Usage = SourceUsage("unknown")
			return value.QueryDigest()
		},
		"source usage without environment": func() (string, error) {
			value := sources
			value.Cursor = nil
			value.EnvironmentID = ""
			return value.QueryDigest()
		},
	}
	for name, query := range invalidQueries {
		if digest, err := query(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
			t.Errorf("invalid query %s = (%q, %v), want empty ErrInvalidRequest", name, digest, err)
		}
	}
}

func TestCollectionManualAdmissionIsServerOwnedAndCloneSafe(t *testing.T) {
	t.Parallel()

	page := AssetPage{Items: []AssetReadModel{{Asset: validAsset()}}, Next: &AssetCursor{Sort: AssetSort("display_name_asc"), QueryDigest: testDigestA, Value: "asset", AssetID: testAssetID}, ManualCreateEligible: true}
	clone := page.Clone()
	clone.Items[0].Labels["changed"] = "yes"
	clone.Next.AssetID = "77777777-7777-4777-8777-777777777777"
	if !page.ManualCreateEligible || page.Items[0].Labels["changed"] != "" || page.Next.AssetID != testAssetID {
		t.Fatal("AssetPage.Clone() leaked nested mutable state or lost manual admission")
	}
	commandType := reflect.TypeOf(CreateAssetCommand{})
	for _, forbidden := range []string{"ManualCreateEligible", "ProviderKind", "Lifecycle", "MappingStatus", "SourceRevision", "FenceEpoch", "CheckpointVersion"} {
		if _, ok := commandType.FieldByName(forbidden); ok {
			t.Errorf("CreateAssetCommand exposes server-owned field %s", forbidden)
		}
	}
}

func TestConflictScopeResolverHasExactTrustedLookupShape(t *testing.T) {
	t.Parallel()

	interfaceType := reflect.TypeOf((*ConflictScopeResolver)(nil)).Elem()
	method, ok := interfaceType.MethodByName("ResolveConflictScope")
	if !ok || interfaceType.NumMethod() != 1 || method.Type.NumIn() != 3 || method.Type.NumOut() != 2 {
		t.Fatalf("ConflictScopeResolver shape = %#v", interfaceType)
	}
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if method.Type.In(0) != contextType || method.Type.In(1).Kind() != reflect.String || method.Type.In(2).Kind() != reflect.String ||
		method.Type.Out(0) != reflect.TypeOf(Scope{}) || method.Type.Out(1) != errorType {
		t.Fatalf("ResolveConflictScope signature = %v", method.Type)
	}
}

func assertSourceKindExtensionMatrix(t *testing.T) {
	t.Helper()

	baseSource, baseRevision := validLocallyClosedUninstalledBinding(t)

	kubernetesSource := baseSource.Clone()
	kubernetesSource.Kind = SourceKindKubernetesOperator
	kubernetesSource.ProviderKind = "TEST_K8S_V1"
	kubernetesRevision := baseRevision.Clone()
	kubernetesRevision.ProfileCode = ProfileCode("TEST_K8S_V1")
	manifest := strings.ReplaceAll(string(kubernetesRevision.CanonicalProfileManifest), "TEST_CSV_V1", "TEST_K8S_V1")
	manifest = strings.Replace(manifest, `"source_kind":"CSV_IMPORT"`, `"source_kind":"KUBERNETES_OPERATOR"`, 1)
	kubernetesRevision.CanonicalProfileManifest = []byte(manifest)
	refreshRevisionContentDigestsForTest(t, kubernetesSource, &kubernetesRevision)
	if err := kubernetesRevision.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("KUBERNETES_OPERATOR without typed extension error = %v", err)
	}
	validKubernetesRevision := kubernetesRevision.Clone()
	validKubernetesRevision.CanonicalProfileManifest = bytes.Replace(
		validKubernetesRevision.CanonicalProfileManifest,
		[]byte(`"typed_extension_code":null`),
		[]byte(`"typed_extension_code":"TEST_K8S_V1"`),
		1,
	)
	validKubernetesRevision.TypedExtensionCode = ExtensionCode("TEST_K8S_V1")
	validKubernetesRevision.PreparedExtensionDigest = testDigestA
	refreshRevisionContentDigestsForTest(t, kubernetesSource, &validKubernetesRevision)
	if err := validKubernetesRevision.Validate(); err != nil {
		t.Errorf("valid KUBERNETES_OPERATOR typed extension error = %v", err)
	}

	nonKubernetesRevision := baseRevision.Clone()
	nonKubernetesRevision.CanonicalProfileManifest = bytes.Replace(
		nonKubernetesRevision.CanonicalProfileManifest,
		[]byte(`"typed_extension_code":null`),
		[]byte(`"typed_extension_code":"TEST_CSV_V1"`),
		1,
	)
	nonKubernetesRevision.TypedExtensionCode = ExtensionCode("TEST_CSV_V1")
	nonKubernetesRevision.PreparedExtensionDigest = testDigestA
	refreshRevisionContentDigestsForTest(t, baseSource, &nonKubernetesRevision)
	if err := nonKubernetesRevision.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("non-Kubernetes revision with typed extension error = %v", err)
	}

	mismatchedKubernetes := kubernetesRevision.Clone()
	mismatchedKubernetes.CanonicalProfileManifest = bytes.Replace(
		mismatchedKubernetes.CanonicalProfileManifest,
		[]byte(`"typed_extension_code":null`),
		[]byte(`"typed_extension_code":"OTHER_K8S_V1"`),
		1,
	)
	mismatchedKubernetes.TypedExtensionCode = ExtensionCode("OTHER_K8S_V1")
	mismatchedKubernetes.PreparedExtensionDigest = testDigestA
	refreshRevisionContentDigestsForTest(t, kubernetesSource, &mismatchedKubernetes)
	if err := mismatchedKubernetes.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Kubernetes extension/profile mismatch error = %v", err)
	}
}

func refreshRevisionContentDigestsForTest(t *testing.T, source Source, revision *SourceRevision) {
	t.Helper()
	var err error
	revision.ProfileManifestSHA256, err = ProfileManifestDigest(revision.CanonicalProfileManifest)
	if err != nil {
		t.Fatalf("ProfileManifestDigest(test revision) error = %v", err)
	}
	revision.CanonicalProviderSchemaSHA256 = testSHA256Hex(revision.CanonicalProviderSchema)
	revision.SourceDefinitionDigest, err = SourceDefinitionDigest(source, *revision)
	if err != nil {
		t.Fatalf("SourceDefinitionDigest(test revision) error = %v", err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
}

func validRelationship() Relationship {
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	return Relationship{
		ID: "77777777-7777-4777-8777-777777777777", SourceID: testSourceID,
		CanonicalRevisionDigest: testDigestA, LastRunID: "88888888-8888-4888-8888-888888888888",
		SourceScope:    SourceScope{TenantID: testTenantID, WorkspaceID: testWorkspaceID},
		SourceRevision: 1, LastPageSequence: 1, AcceptedCheckpointVersion: 1, RunFenceEpoch: 1, RelationPageSHA256: testDigestA,
		SourceEnvironmentID: testEnvironmentID, TargetEnvironmentID: testEnvironmentID,
		SourceAssetID: testAssetID, TargetAssetID: testServiceID, FromExternalID: "manual-host-1", ToExternalID: "manual-service-1",
		Type: RelationshipType("DEPENDS_ON"), ProviderPathCode: "MANUAL_V1_DEPENDS_ON", Confidence: 100,
		FreshnessKind: FreshnessKind("CATALOG_SEQUENCE"), FreshnessOrderSequence: 1,
		ProviderVersionSHA256: testDigestA, RelationFactSHA256: testDigestB,
		Provenance: Provenance("DISCOVERED"), ProvenanceSourceID: testSourceID, Status: RelationshipStatus("ACTIVE"),
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func validConflict() Conflict {
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	return Conflict{
		ID:      "77777777-7777-4777-8777-777777777777",
		Scope:   Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID},
		AssetID: testAssetID, CandidateAssetID: testServiceID, SourceID: testSourceID,
		ObservationID: "88888888-8888-4888-8888-888888888888", Type: "IDENTITY_COLLISION", FieldName: "external_id",
		ExistingValueSHA256: testDigestA, CandidateValueSHA256: testDigestB, Status: ConflictStatus("OPEN"),
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func validServiceAssetBinding() ServiceAssetBinding {
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	return ServiceAssetBinding{
		ID: "77777777-7777-4777-8777-777777777777", ServiceID: testServiceID, AssetID: testAssetID,
		Scope: Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID},
		Role:  BindingRole("DEPENDENCY"), MappingStatus: domain.MappingExact, Provenance: Provenance("MANUAL"),
		Status: BindingStatus("ACTIVE"), Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func validObservation() Observation {
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	document := []byte(`{"kind":"LINUX_VM"}`)
	provenance := []byte(`{"display_name":{"confidence":100,"observed_at":"2026-07-15T01:02:03.000000Z","ownership":"SOURCE","provider_kind":"MANUAL_V1","provider_path_code":"MANUAL_V1_DISPLAY_NAME","source_id":"33333333-3333-4333-8333-333333333333","source_revision":1}}`)
	provenanceDigest := testSHA256Hex(provenance)
	return Observation{
		ID: "77777777-7777-4777-8777-777777777777", SourceID: testSourceID, RunID: "88888888-8888-4888-8888-888888888888",
		ProviderKind: "MANUAL_V1", ExternalID: "manual-host-1",
		Scope:          Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID},
		SourceRevision: 1, CanonicalRevisionDigest: testDigestA, SourceDefinitionDigest: testDigestB, ObservedAt: now,
		FreshnessKind: FreshnessKind("CATALOG_SEQUENCE"), FreshnessOrderSequence: 1,
		ProviderVersionSHA256: testDigestA, ProviderFactSHA256: testDigestB, FingerprintSHA256: testDigestA,
		ProviderProvenanceSHA256: testDigestB, ObservationChainSHA256: testDigestA,
		AcceptedCheckpointVersion: 1, RunFenceEpoch: 1, RunPageSequence: 1, SchemaVersion: "manual-asset.v1",
		NormalizedDocument: document, FieldProvenance: provenance, DocumentSHA256: testSHA256Hex(document), FieldProvenanceSHA256: provenanceDigest,
		CreatedAt: now,
	}
}

func cloneAssetFilterForTest(value AssetFilter) AssetFilter {
	value.Kinds = slices.Clone(value.Kinds)
	value.SourceIDs = slices.Clone(value.SourceIDs)
	value.Lifecycles = slices.Clone(value.Lifecycles)
	value.MappingStatuses = slices.Clone(value.MappingStatuses)
	value.Criticalities = slices.Clone(value.Criticalities)
	value.DataClassifications = slices.Clone(value.DataClassifications)
	return value
}

func validQueuedSourceRun() SourceRun {
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	return SourceRun{
		ID: "88888888-8888-4888-8888-888888888888", SourceID: testSourceID,
		Scope: SourceScope{TenantID: testTenantID, WorkspaceID: testWorkspaceID}, SourceRevision: 1, SourceRevisionDigest: testDigestA,
		Kind: RunKind("DISCOVERY"), Status: RunStatus("QUEUED"), Stage: RunStage("WAITING"), StageChangedAt: now,
		TriggerType: TriggerType("HUMAN"), GateRevision: 1, NotBefore: now,
		CredentialCleanupStatus: CredentialCleanupStatus("NOT_OPENED"), TraceID: strings.Repeat("a", 32),
		Version: 1, CreatedAt: now,
	}
}

func validRunningSourceRun() SourceRun {
	run := validQueuedSourceRun()
	run.Kind = RunKind("MANUAL_MUTATION")
	started := run.CreatedAt.Add(time.Second)
	heartbeat := started.Add(time.Second)
	lease := heartbeat.Add(5 * time.Minute)
	run.Status = RunStatus("RUNNING")
	run.Stage = RunStage("READING")
	run.StageChangedAt = heartbeat
	run.LeaseExpiresAt = &lease
	run.FenceEpoch = 1
	run.HeartbeatSequence = 1
	run.StartedAt = &started
	run.HeartbeatAt = &heartbeat
	run.Version = 2
	return run
}

func validDelayedSourceRun() SourceRun {
	run := validRunningSourceRun()
	run.Kind = RunKind("DISCOVERY")
	stageChanged := run.HeartbeatAt.Add(time.Second)
	notBefore := stageChanged.Add(time.Minute)
	run.Status = RunStatus("DELAYED")
	run.Stage = RunStage("DELAYED")
	run.StageChangedAt = stageChanged
	run.NotBefore = notBefore
	run.LeaseExpiresAt = nil
	run.CredentialCleanupStatus = CredentialCleanupStatus("NO_CREDENTIAL")
	run.Version = 3
	return run
}

func validFinalizingDataSourceRun() SourceRun {
	run := validRunningSourceRun()
	recorded := run.HeartbeatAt.Add(time.Second)
	run.Status = RunStatus("FINALIZING")
	run.Stage = RunStage("CLEANING_UP")
	run.StageChangedAt = recorded
	run.PageSequence = 1
	run.PageDigest = testDigestA
	run.RelationPageSequence = 1
	run.RelationPageDigest = testDigestB
	run.CheckpointVersion = 1
	run.FinalPage = true
	run.Observed = 2
	run.Created = 2
	run.WorkResultKind = WorkResultKind("DATA_PROJECTION")
	run.WorkResultStatus = WorkResultStatus("SUCCEEDED")
	run.WorkResultDigest = testDigestA
	run.WorkResultRecordedAt = &recorded
	run.CredentialCleanupStatus = CredentialCleanupStatus("NO_CREDENTIAL")
	run.HeartbeatSequence = 2
	run.HeartbeatAt = &recorded
	lease := recorded.Add(5 * time.Minute)
	run.LeaseExpiresAt = &lease
	run.Version = 3
	return run
}

func validSucceededDataSourceRun() SourceRun {
	run := validFinalizingDataSourceRun()
	completed := run.WorkResultRecordedAt.Add(time.Second)
	run.Status = RunStatus("SUCCEEDED")
	run.Stage = RunStage("COMPLETED")
	run.StageChangedAt = completed
	run.LeaseExpiresAt = nil
	run.CompletedAt = &completed
	run.Version = 4
	return run
}

func validPartialDataSourceRun() SourceRun {
	run := validSucceededDataSourceRun()
	run.Status = RunStatus("PARTIAL")
	run.WorkResultStatus = WorkResultStatus("PARTIAL")
	run.Version = 4
	return run
}

func validSucceededValidationSourceRun() SourceRun {
	run := validRunningSourceRun()
	run.Kind = RunKind("VALIDATION")
	run.GateRevision = 3
	recorded := run.HeartbeatAt.Add(time.Second)
	completed := recorded.Add(time.Second)
	run.Status = RunStatus("SUCCEEDED")
	run.Stage = RunStage("COMPLETED")
	run.StageChangedAt = completed
	run.LeaseExpiresAt = nil
	run.WorkResultKind = WorkResultKind("VALIDATION_PROOF")
	run.WorkResultStatus = WorkResultStatus("SUCCEEDED")
	run.WorkResultDigest = testDigestA
	run.WorkResultRecordedAt = &recorded
	run.ValidationOutcome = ValidationOutcome("SUCCEEDED")
	run.ValidationProofDigest = testDigestB
	run.CredentialCleanupStatus = CredentialCleanupStatus("NO_CREDENTIAL")
	run.CompletedAt = &completed
	run.Version = 4
	return run
}

func validFailedSourceRun() SourceRun {
	run := validRunningSourceRun()
	recorded := run.HeartbeatAt.Add(time.Second)
	completed := recorded.Add(time.Second)
	run.Status = RunStatus("FAILED")
	run.Stage = RunStage("COMPLETED")
	run.StageChangedAt = completed
	run.LeaseExpiresAt = nil
	run.WorkResultKind = WorkResultKind("FAILURE_INTENT")
	run.WorkResultStatus = WorkResultStatus("FAILED")
	run.WorkResultDigest = testDigestA
	run.WorkResultRecordedAt = &recorded
	run.CredentialCleanupStatus = CredentialCleanupStatus("NO_CREDENTIAL")
	run.FailureCode = "SOURCE_FAILURE"
	run.CompletedAt = &completed
	run.Version = 4
	return run
}

func validCancelledSourceRun() SourceRun {
	run := validQueuedSourceRun()
	completed := run.CreatedAt.Add(time.Second)
	run.Status = RunStatus("CANCELLED")
	run.Stage = RunStage("COMPLETED")
	run.StageChangedAt = completed
	run.CompletedAt = &completed
	run.Version = 2
	return run
}

func validAsset() Asset {
	now := time.Date(2026, 7, 15, 1, 2, 3, 456000000, time.UTC)
	owner := "sre-platform"
	return Asset{
		ID: testAssetID, SourceID: testSourceID, ProviderKind: "MANUAL_V1", ExternalID: "manual-host-1", DisplayName: "manual host 1",
		Scope: Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}, Kind: Kind("LINUX_VM"), Lifecycle: Lifecycle("ACTIVE"), MappingStatus: domain.MappingExact,
		OwnerGroup: &owner, Criticality: Criticality("HIGH"), DataClassification: DataClassification("INTERNAL"), Labels: map[string]string{"team": "platform"},
		LastObservationID: "77777777-7777-4777-8777-777777777777", LastObservationChainSHA256: testDigestA, LastObservedAt: now, LastSourceRevision: 1, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func validManualRevision() SourceRevision {
	profile := ManualProfileV1()
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	return SourceRevision{
		ID: "77777777-7777-4777-8777-777777777777", SourceID: testSourceID, TenantID: testTenantID, WorkspaceID: testWorkspaceID, Revision: 1, Status: SourceRevisionStatus("PUBLISHED"),
		CanonicalProfileManifest: profile.CanonicalProfileManifest, CanonicalProviderSchema: profile.CanonicalProviderSchema, ProfileManifestSHA256: profile.ProfileManifestSHA256, CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		SourceDefinitionDigest: "7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c", SyncMode: SyncMode("MANUAL"), AuthorityEnvironmentIDs: []string{testEnvironmentID},
		AuthorityScopeDigest: testDigestB, RateLimitRequests: 1, RateLimitWindowSeconds: 1, BackpressureBaseSeconds: 1, BackpressureMaxSeconds: 1, ProfileCode: ProfileCode("MANUAL_V1"),
		CreatedBy: "oidc:subject-1", ChangeReasonCode: "INITIAL_CREATE", ExpectedSourceVersion: 1, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func assertDigestMutation(t *testing.T, name string, original, changed func() (string, error)) {
	t.Helper()
	left, err := original()
	if err != nil || left == "" {
		t.Fatalf("%s original digest = (%q, %v)", name, left, err)
	}
	right, err := changed()
	if err != nil || right == "" || right == left {
		t.Fatalf("%s changed digest = (%q, %v), original %q", name, right, err, left)
	}
}

func mustQueryDigest(t *testing.T, digest func() (string, error)) string {
	t.Helper()
	value, err := digest()
	if err != nil || value == "" {
		t.Fatalf("QueryDigest() = (%q, %v)", value, err)
	}
	return value
}

func assertEveryQueryDigestChanges(t *testing.T, original string, changes map[string]func() (string, error)) {
	t.Helper()
	for name, changed := range changes {
		value, err := changed()
		if err != nil || value == "" || value == original {
			t.Errorf("QueryDigest(%s mutation) = (%q, %v), original %q", name, value, err, original)
		}
	}
}

func assertCursorIdentity(t *testing.T, name, original string, matching, drifted func() (string, error)) {
	t.Helper()
	if got := mustQueryDigest(t, matching); got != original {
		t.Errorf("matching %s cursor digest = %q, want %q", name, got, original)
	}
	if digest, err := drifted(); !errors.Is(err, ErrInvalidRequest) || digest != "" {
		t.Errorf("drifted %s cursor = (%q, %v), want empty ErrInvalidRequest", name, digest, err)
	}
}

func assertLimitIsNotQueryIdentity(t *testing.T, name, original string, digest func(int) (string, error)) {
	t.Helper()
	value, err := digest(100)
	if err != nil || value != original {
		t.Errorf("%s Limit changed query identity: (%q, %v), want %q", name, value, err, original)
	}
	if value, err = digest(0); !errors.Is(err, ErrInvalidRequest) || value != "" {
		t.Errorf("%s invalid Limit = (%q, %v), want empty ErrInvalidRequest", name, value, err)
	}
}

func assertExactInterface(t *testing.T, got, want reflect.Type) {
	t.Helper()
	if got.Kind() != reflect.Interface || want.Kind() != reflect.Interface {
		t.Fatalf("assertExactInterface requires interfaces, got %v and %v", got, want)
	}
	if got.NumMethod() != want.NumMethod() {
		t.Errorf("%s method count = %d, want %d", got.Name(), got.NumMethod(), want.NumMethod())
	}
	methodCount := min(got.NumMethod(), want.NumMethod())
	for index := 0; index < methodCount; index++ {
		gotMethod := got.Method(index)
		wantMethod := want.Method(index)
		if gotMethod.Name != wantMethod.Name || gotMethod.Type != wantMethod.Type {
			t.Errorf("%s method[%d] = %s %v, want %s %v", got.Name(), index, gotMethod.Name, gotMethod.Type, wantMethod.Name, wantMethod.Type)
		}
	}
}

func testFramedDigest(values [][]byte) string {
	hash := sha256.New()
	for _, value := range values {
		if value == nil {
			_, _ = hash.Write([]byte{0})
			continue
		}
		_, _ = hash.Write([]byte{1})
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func testSHA256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func bytesOfLength(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func testUUID(index int) string {
	return "aaaaaaaa-aaaa-4aaa-8aaa-" + testTwelveDigits(index)
}

func testUUIDVersionVariant(version, variant rune) string {
	return "11111111-1111-" + string(version) + "111-" + string(variant) + "111-111111111111"
}

func testCanonicalJSONCodes(count int) string {
	var result strings.Builder
	result.WriteByte('[')
	for index := 0; index < count; index++ {
		if index > 0 {
			result.WriteByte(',')
		}
		result.WriteString(`"CODE_`)
		result.WriteString(testTwelveDigits(index))
		result.WriteByte('"')
	}
	result.WriteByte(']')
	return result.String()
}

func testTwelveDigits(value int) string {
	text := testDecimal(value)
	return strings.Repeat("0", 12-len(text)) + text
}

func testDecimal(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
