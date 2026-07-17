package assetcatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
)

var (
	lowercaseRFC4122UUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	opaqueReference      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	providerToken        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	providerKindToken    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	labelKeyPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	lowercaseDigest      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (scope Scope) Valid() bool {
	return validUUID(scope.TenantID) && validUUID(scope.WorkspaceID) && validUUID(scope.EnvironmentID)
}

func (scope SourceScope) Valid() bool {
	return validUUID(scope.TenantID) && validUUID(scope.WorkspaceID)
}

func validUUID(value string) bool { return lowercaseRFC4122UUID.MatchString(value) }

func validDigest(value string) bool { return lowercaseDigest.MatchString(value) }

func (value CredentialReferenceID) Valid() bool { return opaqueReference.MatchString(string(value)) }
func (value TrustReferenceID) Valid() bool      { return opaqueReference.MatchString(string(value)) }
func (value NetworkPolicyReferenceID) Valid() bool {
	return opaqueReference.MatchString(string(value))
}
func (value PolicyReferenceID) Valid() bool { return opaqueReference.MatchString(string(value)) }
func (value ProfileCode) Valid() bool       { return validNamedCode(string(value)) }
func (value ExtensionCode) Valid() bool     { return validNamedCode(string(value)) }

func validNamedCode(value string) bool {
	if !validSafeText(value, 1, 128) || strings.ContainsAny(value, " \t") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._+@/:-", character) {
			continue
		}
		return false
	}
	return true
}

func validSafeText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == utf8.RuneError || character == 0 || character == '\r' || character == '\n' ||
			unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func validStoredTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 2000 && value.Year() <= 9999 &&
		value.Nanosecond()%1000 == 0 && value == value.Round(0)
}

func validOptionalTime(value *time.Time) bool { return value == nil || validStoredTime(*value) }

func validMappingStatus(value domain.MappingStatus) bool {
	switch value {
	case domain.MappingExact, domain.MappingAmbiguous, domain.MappingUnresolved:
		return true
	}
	return false
}

const manualProfileManifestTextV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":1,"compatibility_class":"MANUAL_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CATALOG_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":65536,"max_page_items":1,"max_page_relations":0,"network_mode":"NONE","parser_code":"MANUAL_ASSET_V1","profile_code":"MANUAL_V1","provider_kind":"MANUAL_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":[],"schedule_mode":"NONE","source_kind":"MANUAL","sync_mode":"MANUAL","trust_mode":"NONE","trusted_path_codes":["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
const manualProviderSchemaTextV1 = `{"additionalProperties":false,"properties":{},"type":"object"}`
const csvProfileManifestTextV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":60,"compatibility_class":"CSV_RFC4180_V1","credential_purpose":"IMPORT_SIGNATURE_VERIFY","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"EXPLICIT_ITEM_ENVIRONMENT","freshness_kind":"OBJECT_SEQUENCE","integration_mode":"NONE","max_document_bytes":33554432,"max_page_bytes":33554432,"max_page_items":2000,"max_page_relations":2000,"network_mode":"NONE","parser_code":"CSV_RFC4180_V1","profile_code":"CSV_RFC4180_V1","provider_kind":"CSV_RFC4180_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":["CONTAINS","DELIVERED_BY","DEPENDS_ON","LOGS_TO","MANAGED_BY","MONITORED_BY","PRIMARY_RUNTIME_FOR","RUNS_ON","TRACES_TO"],"schedule_mode":"NONE","source_kind":"CSV_IMPORT","sync_mode":"ON_DEMAND","trust_mode":"NONE","trusted_path_codes":["CSV_V1_DISPLAY_NAME_COLUMN","CSV_V1_ENVIRONMENT_ID_COLUMN","CSV_V1_EXTERNAL_ID_COLUMN","CSV_V1_KIND_COLUMN","CSV_V1_PROVIDER_KIND_COLUMN","CSV_V1_RELATION_COLUMNS","CSV_V1_TYPE_DETAILS_EMPTY"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
const csvProviderSchemaTextV1 = manualProviderSchemaTextV1

func ManualProfileV1() BuiltinSourceProfile {
	return BuiltinSourceProfile{
		SourceKind: SourceKindManual, ProviderKind: "MANUAL_V1", ProfileCode: ProfileCode("MANUAL_V1"),
		SyncMode: SyncModeManual, FreshnessKind: FreshnessCatalogSequence, EnvironmentMapping: EnvironmentMappingSingle,
		IntegrationMode: "NONE", CredentialPurpose: "NONE", TrustMode: "NONE", NetworkMode: "NONE", ScheduleMode: "NONE",
		ParserCode: "MANUAL_ASSET_V1", CompatibilityClass: "MANUAL_V1", DLPPolicyCode: "ASSET_SAFE_V1",
		MaxPageItems: 1, MaxPageRelations: 0, MaxPageBytes: 65536, MaxDocumentBytes: 65536,
		TrustedPathCodes:         []string{"MANUAL_V1_DISPLAY_NAME", "MANUAL_V1_EXTERNAL_ID", "MANUAL_V1_KIND"},
		RelationshipTypes:        []RelationshipType{},
		CanonicalProfileManifest: []byte(manualProfileManifestTextV1), CanonicalProviderSchema: []byte(manualProviderSchemaTextV1),
		ProfileManifestSHA256:         "57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96",
		CanonicalProviderSchemaSHA256: "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa",
		RateLimitRequests:             1, RateLimitWindowSeconds: 1, BackpressureBaseSeconds: 1, BackpressureMaxSeconds: 1,
	}
}

func CSVProfileV1(credentialReferenceID CredentialReferenceID) (BuiltinSourceProfile, error) {
	profile := BuiltinSourceProfile{
		SourceKind: SourceKindCSVImport, ProviderKind: "CSV_RFC4180_V1", ProfileCode: ProfileCode("CSV_RFC4180_V1"),
		SyncMode: SyncModeOnDemand, FreshnessKind: FreshnessObjectSequence, EnvironmentMapping: EnvironmentMappingExplicitItem,
		IntegrationMode: "NONE", CredentialPurpose: "IMPORT_SIGNATURE_VERIFY", TrustMode: "NONE", NetworkMode: "NONE", ScheduleMode: "NONE",
		ParserCode: "CSV_RFC4180_V1", CompatibilityClass: "CSV_RFC4180_V1", DLPPolicyCode: "ASSET_SAFE_V1",
		MaxPageItems: 2000, MaxPageRelations: 2000, MaxPageBytes: 33554432, MaxDocumentBytes: 33554432,
		TrustedPathCodes: []string{
			"CSV_V1_DISPLAY_NAME_COLUMN",
			"CSV_V1_ENVIRONMENT_ID_COLUMN",
			"CSV_V1_EXTERNAL_ID_COLUMN",
			"CSV_V1_KIND_COLUMN",
			"CSV_V1_PROVIDER_KIND_COLUMN",
			"CSV_V1_RELATION_COLUMNS",
			"CSV_V1_TYPE_DETAILS_EMPTY",
		},
		RelationshipTypes: []RelationshipType{
			RelationshipContains,
			RelationshipDeliveredBy,
			RelationshipDependsOn,
			RelationshipLogsTo,
			RelationshipManagedBy,
			RelationshipMonitoredBy,
			RelationshipPrimaryRuntimeFor,
			RelationshipRunsOn,
			RelationshipTracesTo,
		},
		CanonicalProfileManifest:      []byte(csvProfileManifestTextV1),
		CanonicalProviderSchema:       []byte(csvProviderSchemaTextV1),
		ProfileManifestSHA256:         "9a9739783fbb84a66653271202e06e2e6b2cdcffc268564151d0c6035cbf4941",
		CanonicalProviderSchemaSHA256: "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa",
		CredentialReferenceID:         credentialReferenceID,
		RateLimitRequests:             1,
		RateLimitWindowSeconds:        1,
		BackpressureBaseSeconds:       1,
		BackpressureMaxSeconds:        60,
	}
	if validateInstalledSourceProfile(profile) != nil {
		return BuiltinSourceProfile{}, ErrInvalidRequest
	}
	return profile.Clone(), nil
}

type profileManifest struct {
	Version                 string                 `json:"version"`
	SourceKind              SourceKind             `json:"source_kind"`
	ProviderKind            string                 `json:"provider_kind"`
	ProfileCode             string                 `json:"profile_code"`
	SyncMode                SyncMode               `json:"sync_mode"`
	FreshnessKind           FreshnessKind          `json:"freshness_kind"`
	EnvironmentMappingMode  EnvironmentMappingMode `json:"environment_mapping_mode"`
	IntegrationMode         string                 `json:"integration_mode"`
	CredentialPurpose       string                 `json:"credential_purpose"`
	TrustMode               string                 `json:"trust_mode"`
	NetworkMode             string                 `json:"network_mode"`
	RateLimitRequests       int64                  `json:"rate_limit_requests"`
	RateLimitWindowSeconds  int64                  `json:"rate_limit_window_seconds"`
	BackpressureBaseSeconds int64                  `json:"backpressure_base_seconds"`
	BackpressureMaxSeconds  int64                  `json:"backpressure_max_seconds"`
	ScheduleMode            string                 `json:"schedule_mode"`
	MaxPageItems            int64                  `json:"max_page_items"`
	MaxPageRelations        int64                  `json:"max_page_relations"`
	MaxPageBytes            int64                  `json:"max_page_bytes"`
	MaxDocumentBytes        int64                  `json:"max_document_bytes"`
	ParserCode              string                 `json:"parser_code"`
	CompatibilityClass      string                 `json:"compatibility_class"`
	DLPPolicyCode           string                 `json:"dlp_policy_code"`
	TrustedPathCodes        []string               `json:"trusted_path_codes"`
	RelationshipTypes       []string               `json:"relationship_types"`
	TypedExtensionCode      *string                `json:"typed_extension_code"`
}

var profileManifestKeys = map[string]struct{}{
	"version": {}, "source_kind": {}, "provider_kind": {}, "profile_code": {}, "sync_mode": {},
	"freshness_kind": {}, "environment_mapping_mode": {}, "integration_mode": {}, "credential_purpose": {},
	"trust_mode": {}, "network_mode": {}, "rate_limit_requests": {}, "rate_limit_window_seconds": {},
	"backpressure_base_seconds": {}, "backpressure_max_seconds": {}, "schedule_mode": {}, "max_page_items": {},
	"max_page_relations": {}, "max_page_bytes": {}, "max_document_bytes": {}, "parser_code": {},
	"compatibility_class": {}, "dlp_policy_code": {}, "trusted_path_codes": {}, "relationship_types": {},
	"typed_extension_code": {},
}

func ProfileManifestDigest(canonicalManifest []byte) (string, error) {
	if len(canonicalManifest) == 0 || len(canonicalManifest) > 16<<10 || !strictCanonicalJSONObject(canonicalManifest) {
		return "", ErrInvalidRequest
	}
	keys, ok := exactTopLevelKeys(canonicalManifest)
	if !ok || len(keys) != len(profileManifestKeys) {
		return "", ErrInvalidRequest
	}
	for key := range profileManifestKeys {
		if _, exists := keys[key]; !exists {
			return "", ErrInvalidRequest
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(canonicalManifest))
	decoder.DisallowUnknownFields()
	var manifest profileManifest
	if err := decoder.Decode(&manifest); err != nil {
		return "", ErrInvalidRequest
	}
	if !validProfileManifest(manifest) {
		return "", ErrInvalidRequest
	}
	return sha256Hex(canonicalManifest), nil
}

func validProfileManifest(manifest profileManifest) bool {
	if manifest.Version != "asset-source-profile-manifest.v1" || !manifest.SourceKind.Valid() ||
		!providerKindToken.MatchString(manifest.ProviderKind) || !providerToken.MatchString(manifest.ProfileCode) ||
		!manifest.SyncMode.Valid() || !manifest.FreshnessKind.Valid() || !manifest.EnvironmentMappingMode.Valid() ||
		!oneOf(manifest.IntegrationMode, "NONE", "REQUIRED") || !providerToken.MatchString(manifest.CredentialPurpose) ||
		!oneOf(manifest.TrustMode, "NONE", "REQUIRED") || !oneOf(manifest.NetworkMode, "NONE", "REQUIRED") ||
		!oneOf(manifest.ScheduleMode, "NONE", "REQUIRED") || !providerToken.MatchString(manifest.ParserCode) ||
		!providerToken.MatchString(manifest.CompatibilityClass) || !providerToken.MatchString(manifest.DLPPolicyCode) {
		return false
	}
	if manifest.RateLimitRequests < 0 || manifest.RateLimitWindowSeconds < 0 ||
		manifest.BackpressureBaseSeconds < 0 || manifest.BackpressureMaxSeconds < 0 ||
		manifest.MaxPageItems < 1 || manifest.MaxPageRelations < 0 || manifest.MaxPageBytes < 1 ||
		manifest.MaxDocumentBytes < 1 || manifest.MaxDocumentBytes > manifest.MaxPageBytes {
		return false
	}
	for _, value := range []int64{manifest.RateLimitRequests, manifest.RateLimitWindowSeconds, manifest.BackpressureBaseSeconds,
		manifest.BackpressureMaxSeconds, manifest.MaxPageItems, manifest.MaxPageRelations, manifest.MaxPageBytes, manifest.MaxDocumentBytes} {
		if len(strconv.FormatInt(value, 10)) > 18 {
			return false
		}
	}
	if !validSortedCodes(manifest.TrustedPathCodes, 1, 128) || !validSortedCodes(manifest.RelationshipTypes, 0, 128) {
		return false
	}
	return manifest.TypedExtensionCode == nil || providerToken.MatchString(*manifest.TypedExtensionCode)
}

func validSortedCodes(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !providerToken.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validateInstalledSourceProfile(profile BuiltinSourceProfile) error {
	profile = profile.Clone()
	manifestDigest, err := ProfileManifestDigest(profile.CanonicalProfileManifest)
	if err != nil || manifestDigest != profile.ProfileManifestSHA256 ||
		len(profile.CanonicalProviderSchema) < 2 || len(profile.CanonicalProviderSchema) > 65536 ||
		!strictCanonicalJSONObject(profile.CanonicalProviderSchema) ||
		sha256Hex(profile.CanonicalProviderSchema) != profile.CanonicalProviderSchemaSHA256 {
		return ErrInvalidRequest
	}
	var manifest profileManifest
	if json.Unmarshal(profile.CanonicalProfileManifest, &manifest) != nil {
		return ErrInvalidRequest
	}
	relationshipTypes := make([]string, len(profile.RelationshipTypes))
	for index, relationshipType := range profile.RelationshipTypes {
		if !relationshipType.Valid() {
			return ErrInvalidRequest
		}
		relationshipTypes[index] = string(relationshipType)
	}
	typedExtensionCode := ""
	if manifest.TypedExtensionCode != nil {
		typedExtensionCode = *manifest.TypedExtensionCode
	}
	if profile.SourceKind != manifest.SourceKind ||
		profile.ProviderKind != manifest.ProviderKind ||
		string(profile.ProfileCode) != manifest.ProfileCode ||
		profile.SyncMode != manifest.SyncMode ||
		profile.FreshnessKind != manifest.FreshnessKind ||
		profile.EnvironmentMapping != manifest.EnvironmentMappingMode ||
		profile.IntegrationMode != manifest.IntegrationMode ||
		profile.CredentialPurpose != manifest.CredentialPurpose ||
		profile.TrustMode != manifest.TrustMode ||
		profile.NetworkMode != manifest.NetworkMode ||
		profile.ScheduleMode != manifest.ScheduleMode ||
		profile.ParserCode != manifest.ParserCode ||
		profile.CompatibilityClass != manifest.CompatibilityClass ||
		profile.DLPPolicyCode != manifest.DLPPolicyCode ||
		profile.MaxPageItems != manifest.MaxPageItems ||
		profile.MaxPageRelations != manifest.MaxPageRelations ||
		profile.MaxPageBytes != manifest.MaxPageBytes ||
		profile.MaxDocumentBytes != manifest.MaxDocumentBytes ||
		profile.RateLimitRequests != manifest.RateLimitRequests ||
		profile.RateLimitWindowSeconds != manifest.RateLimitWindowSeconds ||
		profile.BackpressureBaseSeconds != manifest.BackpressureBaseSeconds ||
		profile.BackpressureMaxSeconds != manifest.BackpressureMaxSeconds ||
		!slices.Equal(profile.TrustedPathCodes, manifest.TrustedPathCodes) ||
		!slices.Equal(relationshipTypes, manifest.RelationshipTypes) ||
		string(profile.TypedExtensionCode) != typedExtensionCode {
		return ErrInvalidRequest
	}
	if profile.IntegrationMode == "NONE" {
		if profile.IntegrationID != "" {
			return ErrInvalidRequest
		}
	} else if !validUUID(profile.IntegrationID) {
		return ErrInvalidRequest
	}
	if profile.CredentialPurpose == "NONE" {
		if profile.CredentialReferenceID != "" {
			return ErrInvalidRequest
		}
	} else if !profile.CredentialReferenceID.Valid() {
		return ErrInvalidRequest
	}
	if profile.TrustMode == "NONE" {
		if profile.TrustReferenceID != "" {
			return ErrInvalidRequest
		}
	} else if !profile.TrustReferenceID.Valid() {
		return ErrInvalidRequest
	}
	if profile.NetworkMode == "NONE" {
		if profile.NetworkPolicyReferenceID != "" {
			return ErrInvalidRequest
		}
	} else if !profile.NetworkPolicyReferenceID.Valid() {
		return ErrInvalidRequest
	}
	if profile.ScheduleMode == "NONE" {
		if profile.ScheduleExpression != "" {
			return ErrInvalidRequest
		}
	} else if !validSafeText(profile.ScheduleExpression, 1, 256) {
		return ErrInvalidRequest
	}
	if profile.TypedExtensionCode == "" {
		if profile.PreparedExtensionDigest != "" {
			return ErrInvalidRequest
		}
	} else if profile.SourceKind != SourceKindKubernetesOperator ||
		profile.TypedExtensionCode != ExtensionCode(profile.ProfileCode) ||
		!validDigest(profile.PreparedExtensionDigest) {
		return ErrInvalidRequest
	}
	revision := SourceRevision{
		CanonicalProfileManifest: profile.CanonicalProfileManifest,
		CanonicalProviderSchema:  profile.CanonicalProviderSchema,
		IntegrationID:            profile.IntegrationID,
		SyncMode:                 profile.SyncMode,
		CredentialReferenceID:    profile.CredentialReferenceID,
		TrustReferenceID:         profile.TrustReferenceID,
		NetworkPolicyReferenceID: profile.NetworkPolicyReferenceID,
		RateLimitRequests:        profile.RateLimitRequests,
		RateLimitWindowSeconds:   profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds:  profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:   profile.BackpressureMaxSeconds,
		ProfileCode:              profile.ProfileCode,
		ScheduleExpression:       profile.ScheduleExpression,
		TypedExtensionCode:       profile.TypedExtensionCode,
		PreparedExtensionDigest:  profile.PreparedExtensionDigest,
	}
	if _, err := SourceDefinitionDigest(
		Source{Kind: profile.SourceKind, ProviderKind: profile.ProviderKind},
		revision,
	); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func SourceDefinitionDigest(source Source, revision SourceRevision) (string, error) {
	manifestDigest, err := ProfileManifestDigest(revision.CanonicalProfileManifest)
	if err != nil || len(revision.CanonicalProviderSchema) < 2 || len(revision.CanonicalProviderSchema) > 65536 ||
		!strictCanonicalJSONObject(revision.CanonicalProviderSchema) {
		return "", ErrInvalidRequest
	}
	var manifest profileManifest
	if err := json.Unmarshal(revision.CanonicalProfileManifest, &manifest); err != nil ||
		source.Kind != manifest.SourceKind || source.ProviderKind != manifest.ProviderKind ||
		string(revision.ProfileCode) != manifest.ProfileCode || revision.SyncMode != manifest.SyncMode ||
		revision.RateLimitRequests != manifest.RateLimitRequests || revision.RateLimitWindowSeconds != manifest.RateLimitWindowSeconds ||
		revision.BackpressureBaseSeconds != manifest.BackpressureBaseSeconds || revision.BackpressureMaxSeconds != manifest.BackpressureMaxSeconds ||
		(revision.IntegrationID == "") != (manifest.IntegrationMode == "NONE") ||
		(revision.CredentialReferenceID == "") != (manifest.CredentialPurpose == "NONE") ||
		(revision.TrustReferenceID == "") != (manifest.TrustMode == "NONE") ||
		(revision.NetworkPolicyReferenceID == "") != (manifest.NetworkMode == "NONE") ||
		(revision.ScheduleExpression == "") != (manifest.ScheduleMode == "NONE") {
		return "", ErrInvalidRequest
	}
	manifestExtension := ""
	if manifest.TypedExtensionCode != nil {
		manifestExtension = *manifest.TypedExtensionCode
	}
	if string(revision.TypedExtensionCode) != manifestExtension ||
		(revision.TypedExtensionCode == "") != (revision.PreparedExtensionDigest == "") {
		return "", ErrInvalidRequest
	}
	schemaDigest := sha256Hex(revision.CanonicalProviderSchema)
	manifestRaw, _ := hex.DecodeString(manifestDigest)
	schemaRaw, _ := hex.DecodeString(schemaDigest)
	return framedDigest([][]byte{
		[]byte("asset-source-definition.v2"), []byte(source.Kind), []byte(source.ProviderKind),
		[]byte(revision.ProfileCode), manifestRaw, schemaRaw,
	}), nil
}

func AuthorityScopeDigest(environmentIDs []string) (string, error) {
	values := slices.Clone(environmentIDs)
	if len(values) == 0 || len(values) > 100 {
		return "", ErrInvalidRequest
	}
	slices.Sort(values)
	if !validUniqueUUIDs(values, false) {
		return "", ErrInvalidRequest
	}
	frames := make([][]byte, 0, len(values)+2)
	frames = append(frames, []byte("asset-source-authority-scope.v1"), []byte(strconv.Itoa(len(values))))
	for _, value := range values {
		frames = append(frames, []byte(value))
	}
	return framedDigest(frames), nil
}

func (revision SourceRevision) BindingDigest() string {
	if !validUUID(revision.TenantID) || !validUUID(revision.WorkspaceID) || !validUUID(revision.SourceID) || revision.Revision <= 0 ||
		!validDigest(revision.SourceDefinitionDigest) || !revision.SyncMode.Valid() || !validDigest(revision.AuthorityScopeDigest) ||
		revision.RateLimitRequests < 1 || revision.RateLimitRequests > 1_000_000 ||
		revision.RateLimitWindowSeconds < 1 || revision.RateLimitWindowSeconds > 86_400 ||
		revision.BackpressureBaseSeconds < 1 || revision.BackpressureBaseSeconds > 86_400 ||
		revision.BackpressureMaxSeconds < revision.BackpressureBaseSeconds || revision.BackpressureMaxSeconds > 604_800 ||
		!revision.ProfileCode.Valid() ||
		(revision.TypedExtensionCode == "") != (revision.PreparedExtensionDigest == "") {
		return ""
	}
	if revision.IntegrationID != "" && !validUUID(revision.IntegrationID) ||
		revision.CredentialReferenceID != "" && !revision.CredentialReferenceID.Valid() ||
		revision.TrustReferenceID != "" && !revision.TrustReferenceID.Valid() ||
		revision.NetworkPolicyReferenceID != "" && !revision.NetworkPolicyReferenceID.Valid() ||
		revision.ScheduleExpression != "" && !validSafeText(revision.ScheduleExpression, 1, 256) ||
		revision.TypedExtensionCode != "" && (!revision.TypedExtensionCode.Valid() || !validDigest(revision.PreparedExtensionDigest)) {
		return ""
	}
	definition, _ := hex.DecodeString(revision.SourceDefinitionDigest)
	authority, _ := hex.DecodeString(revision.AuthorityScopeDigest)
	frames := [][]byte{
		[]byte("asset-source-revision-binding.v1"), []byte(revision.TenantID), []byte(revision.WorkspaceID), []byte(revision.SourceID),
		[]byte(strconv.FormatInt(revision.Revision, 10)), definition, optionalFrame(revision.IntegrationID), []byte(revision.SyncMode),
		optionalFrame(string(revision.CredentialReferenceID)), optionalFrame(string(revision.TrustReferenceID)), optionalFrame(string(revision.NetworkPolicyReferenceID)),
		authority, []byte(strconv.FormatInt(revision.RateLimitRequests, 10)), []byte(strconv.FormatInt(revision.RateLimitWindowSeconds, 10)),
		[]byte(strconv.FormatInt(revision.BackpressureBaseSeconds, 10)), []byte(strconv.FormatInt(revision.BackpressureMaxSeconds, 10)),
		[]byte(revision.ProfileCode), optionalFrame(revision.ScheduleExpression), optionalFrame(string(revision.TypedExtensionCode)), nil,
	}
	if revision.PreparedExtensionDigest != "" {
		frames[len(frames)-1], _ = hex.DecodeString(revision.PreparedExtensionDigest)
	}
	return framedDigest(frames)
}

func optionalFrame(value string) []byte {
	if value == "" {
		return nil
	}
	return []byte(value)
}

func framedDigest(frames [][]byte) string {
	hash := sha256.New()
	for _, frame := range frames {
		if frame == nil {
			_, _ = hash.Write([]byte{0})
			continue
		}
		_, _ = hash.Write([]byte{1})
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(frame)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(frame)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func oneOf(value string, values ...string) bool { return slices.Contains(values, value) }

func canonicalJSONObject(value []byte) bool { return strictCanonicalJSONObject(value) }

func strictCanonicalJSONObject(value []byte) bool {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || !utf8.Valid(value) || trimmed[0] != '{' || !strictJSONValue(value) {
		return false
	}
	canonical, err := jsoncanonicalizer.Transform(value)
	return err == nil && bytes.Equal(canonical, value)
}

func strictJSONValue(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || !consumeStrictJSONToken(decoder, token, 1) {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func consumeStrictJSONToken(decoder *json.Decoder, token json.Token, depth int) bool {
	if depth > 64 {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			child, err := decoder.Token()
			if err != nil || !consumeStrictJSONToken(decoder, child, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			child, err := decoder.Token()
			if err != nil || !consumeStrictJSONToken(decoder, child, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	}
	return false
}

func exactTopLevelKeys(value []byte) (map[string]struct{}, bool) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	keys := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := keys[key]; duplicate {
			return nil, false
		}
		keys[key] = struct{}{}
		var discard json.RawMessage
		if decoder.Decode(&discard) != nil {
			return nil, false
		}
	}
	return keys, true
}

func (asset Asset) Validate() error {
	if !validUUID(asset.ID) || !validUUID(asset.SourceID) || !asset.Scope.Valid() ||
		!providerKindToken.MatchString(asset.ProviderKind) || !validSafeText(asset.ExternalID, 1, 512) ||
		!validSafeText(asset.DisplayName, 1, 256) || !asset.Kind.Valid() || !asset.Lifecycle.Valid() ||
		!validMappingStatus(asset.MappingStatus) || !asset.Criticality.Valid() || !asset.DataClassification.Valid() ||
		asset.OwnerGroup != nil && !validSafeText(*asset.OwnerGroup, 1, 256) || !validLabels(asset.Labels) ||
		!validUUID(asset.LastObservationID) || !validDigest(asset.LastObservationChainSHA256) ||
		!validStoredTime(asset.LastObservedAt) || asset.LastSourceRevision <= 0 || asset.Version <= 0 ||
		!validStoredTime(asset.CreatedAt) || !validStoredTime(asset.UpdatedAt) || asset.CreatedAt.After(asset.UpdatedAt) {
		return ErrInvalidRequest
	}
	return nil
}

func validLabels(labels map[string]string) bool {
	if len(labels) > 64 {
		return false
	}
	wire, err := json.Marshal(labels)
	if err != nil || len(wire) > 16<<10 {
		return false
	}
	for key, value := range labels {
		if !labelKeyPattern.MatchString(key) || !validSafeText(value, 0, 16<<10) {
			return false
		}
		normalized := strings.ToLower(key)
		normalized = strings.NewReplacer("-", "", "_", "", ".", "").Replace(normalized)
		for _, unsafe := range []string{"secret", "token", "password", "credential", "dsn", "endpoint"} {
			if strings.Contains(normalized, unsafe) {
				return false
			}
		}
	}
	return true
}

func (source Source) Validate() error {
	if !validUUID(source.ID) || !validUUID(source.TenantID) || !validUUID(source.WorkspaceID) ||
		!providerKindToken.MatchString(source.ProviderKind) || !validSafeText(source.Name, 1, 256) ||
		!source.Kind.Valid() || !source.Status.Valid() || !source.GateStatus.Valid() || source.GateRevision < 0 ||
		source.CheckpointVersion < 0 || source.CheckpointSourceRevision < 0 ||
		!validOptionalTime(source.NextAllowedAt) || source.ConsecutiveFailures < 0 || source.Version <= 0 ||
		!validStoredTime(source.CreatedAt) || !validStoredTime(source.UpdatedAt) || source.CreatedAt.After(source.UpdatedAt) {
		return ErrInvalidRequest
	}
	if (source.PublishedRevision == 0) != (source.PublishedRevisionDigest == "") ||
		source.PublishedRevision < 0 || source.PublishedRevisionDigest != "" && !validDigest(source.PublishedRevisionDigest) ||
		source.ValidatedRunID != "" && !validUUID(source.ValidatedRunID) ||
		source.ValidationDigest != "" && !validDigest(source.ValidationDigest) ||
		source.ValidatedBindingDigest != "" && !validDigest(source.ValidatedBindingDigest) {
		return ErrInvalidRequest
	}
	if source.PublishedRevision == 0 {
		if source.CheckpointSourceRevision != 0 || source.CheckpointVersion != 0 || source.CheckpointSHA256 != "" {
			return ErrInvalidRequest
		}
	} else if source.CheckpointSourceRevision != source.PublishedRevision {
		return ErrInvalidRequest
	}
	if source.GateStatus == SourceGateAvailable {
		if source.GateRevision <= 0 || source.PublishedRevision <= 0 || source.GateReasonCode != "" ||
			source.ValidatedRunID == "" || source.ValidationDigest == "" || source.ValidatedBindingDigest == "" {
			return ErrInvalidRequest
		}
	} else if source.GateReasonCode != "" && !validSafeToken(source.GateReasonCode, 1, 128) {
		return ErrInvalidRequest
	}
	if source.CheckpointSHA256 != "" {
		if source.Kind == SourceKindManual || source.CheckpointVersion <= 0 || !validDigest(source.CheckpointSHA256) {
			return ErrInvalidRequest
		}
	} else if source.CheckpointVersion > 0 && source.Kind != SourceKindManual {
		return ErrInvalidRequest
	}
	if !validIDTimePair(source.LastSuccessRunID, source.LastSuccessAt) ||
		!validIDTimePair(source.LastCompleteSnapshotRunID, source.LastCompleteSnapshotAt) {
		return ErrInvalidRequest
	}
	return nil
}

func validIDTimePair(id string, at *time.Time) bool {
	if (id == "") != (at == nil) {
		return false
	}
	return id == "" || validUUID(id) && validStoredTime(*at)
}

func (revision SourceRevision) Validate() error {
	if !validUUID(revision.ID) || !validUUID(revision.SourceID) || !validUUID(revision.TenantID) ||
		!validUUID(revision.WorkspaceID) || revision.Revision <= 0 || !revision.Status.Valid() ||
		!validDigest(revision.ProfileManifestSHA256) || !validDigest(revision.CanonicalProviderSchemaSHA256) ||
		!validDigest(revision.SourceDefinitionDigest) || !validDigest(revision.CanonicalRevisionDigest) ||
		revision.IntegrationID != "" && !validUUID(revision.IntegrationID) || !revision.SyncMode.Valid() ||
		revision.CredentialReferenceID != "" && !revision.CredentialReferenceID.Valid() ||
		revision.TrustReferenceID != "" && !revision.TrustReferenceID.Valid() ||
		revision.NetworkPolicyReferenceID != "" && !revision.NetworkPolicyReferenceID.Valid() ||
		revision.RateLimitRequests < 1 || revision.RateLimitRequests > 1_000_000 ||
		revision.RateLimitWindowSeconds < 1 || revision.RateLimitWindowSeconds > 86_400 ||
		revision.BackpressureBaseSeconds < 1 || revision.BackpressureBaseSeconds > 86_400 ||
		revision.BackpressureMaxSeconds < revision.BackpressureBaseSeconds || revision.BackpressureMaxSeconds > 604_800 ||
		!revision.ProfileCode.Valid() ||
		revision.ScheduleExpression != "" && !validSafeText(revision.ScheduleExpression, 1, 256) ||
		(revision.TypedExtensionCode == "") != (revision.PreparedExtensionDigest == "") ||
		revision.TypedExtensionCode != "" && (!revision.TypedExtensionCode.Valid() || !validDigest(revision.PreparedExtensionDigest)) ||
		!validSafeText(revision.CreatedBy, 1, 256) || !validSafeToken(revision.ChangeReasonCode, 1, 128) ||
		revision.ExpectedSourceVersion <= 0 || revision.Version <= 0 || !validStoredTime(revision.CreatedAt) ||
		!validStoredTime(revision.UpdatedAt) || revision.CreatedAt.After(revision.UpdatedAt) {
		return ErrInvalidRequest
	}
	manifestDigest, err := ProfileManifestDigest(revision.CanonicalProfileManifest)
	if err != nil || manifestDigest != revision.ProfileManifestSHA256 || len(revision.CanonicalProviderSchema) < 2 ||
		len(revision.CanonicalProviderSchema) > 65536 || !strictCanonicalJSONObject(revision.CanonicalProviderSchema) ||
		sha256Hex(revision.CanonicalProviderSchema) != revision.CanonicalProviderSchemaSHA256 {
		return ErrInvalidRequest
	}
	if !slices.IsSorted(revision.AuthorityEnvironmentIDs) {
		return ErrInvalidRequest
	}
	authorityDigest, err := AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	if err != nil || authorityDigest != revision.AuthorityScopeDigest {
		return ErrInvalidRequest
	}
	var manifest profileManifest
	if json.Unmarshal(revision.CanonicalProfileManifest, &manifest) != nil {
		return ErrInvalidRequest
	}
	switch manifest.EnvironmentMappingMode {
	case EnvironmentMappingSingle:
		if len(revision.AuthorityEnvironmentIDs) != 1 {
			return ErrInvalidRequest
		}
	case EnvironmentMappingExplicitItem:
		if len(revision.AuthorityEnvironmentIDs) < 1 || len(revision.AuthorityEnvironmentIDs) > 100 {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	if manifest.SourceKind == SourceKindKubernetesOperator {
		if revision.TypedExtensionCode == "" || string(revision.TypedExtensionCode) != manifest.ProfileCode {
			return ErrInvalidRequest
		}
	} else if revision.TypedExtensionCode != "" || revision.PreparedExtensionDigest != "" {
		return ErrInvalidRequest
	}
	source := Source{Kind: manifest.SourceKind, ProviderKind: manifest.ProviderKind}
	definitionDigest, err := SourceDefinitionDigest(source, revision)
	if err != nil || definitionDigest != revision.SourceDefinitionDigest || revision.BindingDigest() != revision.CanonicalRevisionDigest {
		return ErrInvalidRequest
	}
	if !validRevisionValidationClosure(revision) {
		return ErrInvalidRequest
	}
	return nil
}

func validRevisionValidationClosure(revision SourceRevision) bool {
	switch revision.Status {
	case SourceRevisionDraft:
		return revision.ValidationRunID == "" && revision.ValidationDigest == ""
	case SourceRevisionValidating:
		return validUUID(revision.ValidationRunID) && revision.ValidationDigest == ""
	case SourceRevisionValidated, SourceRevisionRejected, SourceRevisionPublished, SourceRevisionSuperseded:
		return validUUID(revision.ValidationRunID) && validDigest(revision.ValidationDigest)
	}
	return false
}

func (relationship Relationship) Validate() error {
	if !validUUID(relationship.ID) || !validUUID(relationship.SourceID) || !relationship.SourceScope.Valid() ||
		relationship.SourceRevision <= 0 || !validDigest(relationship.CanonicalRevisionDigest) || !validUUID(relationship.LastRunID) ||
		relationship.LastPageSequence <= 0 || relationship.AcceptedCheckpointVersion <= 0 || relationship.RunFenceEpoch <= 0 ||
		!validDigest(relationship.RelationPageSHA256) || !validUUID(relationship.SourceEnvironmentID) ||
		!validUUID(relationship.TargetEnvironmentID) || !validUUID(relationship.SourceAssetID) || !validUUID(relationship.TargetAssetID) ||
		!validSafeText(relationship.FromExternalID, 1, 512) || !validSafeText(relationship.ToExternalID, 1, 512) ||
		!relationship.Type.Valid() || !validSafeToken(relationship.ProviderPathCode, 1, 128) ||
		relationship.Confidence < 0 || relationship.Confidence > 100 || !relationship.FreshnessKind.Valid() ||
		relationship.FreshnessOrderSequence <= 0 || !validDigest(relationship.ProviderVersionSHA256) ||
		!validDigest(relationship.RelationFactSHA256) || !relationship.Provenance.Valid() ||
		!relationship.Status.Valid() || relationship.Version <= 0 || !validStoredTime(relationship.CreatedAt) ||
		!validStoredTime(relationship.UpdatedAt) || relationship.CreatedAt.After(relationship.UpdatedAt) {
		return ErrInvalidRequest
	}
	if !validFreshnessCoordinate(relationship.FreshnessKind, relationship.FreshnessOrderTime) ||
		!validAcceptedFreshnessSequence(relationship.FreshnessKind, relationship.FreshnessOrderSequence, relationship.AcceptedCheckpointVersion) ||
		!validProvenanceSource(relationship.Provenance, relationship.ProvenanceSourceID) ||
		relationship.SourceAssetID == relationship.TargetAssetID ||
		relationship.Provenance == ProvenanceDiscovered && relationship.ProvenanceSourceID != relationship.SourceID {
		return ErrInvalidRequest
	}
	crossEnvironment := relationship.SourceEnvironmentID != relationship.TargetEnvironmentID
	if crossEnvironment != (relationship.CrossEnvironmentPolicyReferenceID != "") ||
		relationship.CrossEnvironmentPolicyReferenceID != "" && !relationship.CrossEnvironmentPolicyReferenceID.Valid() {
		return ErrInvalidRequest
	}
	return nil
}

func validFreshnessCoordinate(kind FreshnessKind, value *time.Time) bool {
	if kind == FreshnessObjectTimeSequence {
		return value != nil && validStoredTime(*value)
	}
	return value == nil
}

func validAcceptedFreshnessSequence(kind FreshnessKind, sequence, acceptedCheckpointVersion int64) bool {
	switch kind {
	case FreshnessCatalogSequence, FreshnessCheckpointSequence:
		return sequence == acceptedCheckpointVersion
	case FreshnessObjectSequence, FreshnessObjectTimeSequence:
		return true
	}
	return false
}

func validProvenanceSource(provenance Provenance, sourceID string) bool {
	switch provenance {
	case ProvenanceDiscovered:
		return validUUID(sourceID)
	case ProvenanceManual, ProvenanceMergeDecision:
		return sourceID == ""
	}
	return false
}

func (conflict Conflict) Validate() error {
	if !validUUID(conflict.ID) || !conflict.Scope.Valid() || !validUUID(conflict.AssetID) ||
		conflict.CandidateAssetID != "" && !validUUID(conflict.CandidateAssetID) ||
		conflict.CandidateServiceID != "" && !validUUID(conflict.CandidateServiceID) ||
		!validUUID(conflict.SourceID) || !validUUID(conflict.ObservationID) || !validSafeToken(conflict.Type, 1, 128) ||
		conflict.FieldName != "" && !validSafeToken(conflict.FieldName, 1, 128) ||
		conflict.ExistingValueSHA256 != "" && !validDigest(conflict.ExistingValueSHA256) ||
		conflict.CandidateValueSHA256 != "" && !validDigest(conflict.CandidateValueSHA256) || !conflict.Status.Valid() ||
		conflict.Version <= 0 || !validStoredTime(conflict.CreatedAt) || !validStoredTime(conflict.UpdatedAt) ||
		conflict.CreatedAt.After(conflict.UpdatedAt) {
		return ErrInvalidRequest
	}
	assetCandidate := conflict.CandidateAssetID != ""
	serviceCandidate := conflict.CandidateServiceID != ""
	fieldCandidate := conflict.FieldName != "" && conflict.CandidateValueSHA256 != ""
	if !assetCandidate && !serviceCandidate && !fieldCandidate || (conflict.FieldName == "") != (conflict.CandidateValueSHA256 == "") {
		return ErrInvalidRequest
	}
	if conflict.Status == ConflictStatusOpen {
		if conflict.Resolution != "" || conflict.ResolutionReasonCode != "" || conflict.ResolvedBy != "" || conflict.ResolvedAt != nil {
			return ErrInvalidRequest
		}
		return nil
	}
	if !conflict.Resolution.Valid() || !validSafeToken(conflict.ResolutionReasonCode, 1, 128) ||
		!validSafeText(conflict.ResolvedBy, 1, 256) || conflict.ResolvedAt == nil || !validStoredTime(*conflict.ResolvedAt) {
		return ErrInvalidRequest
	}
	return nil
}

func (binding ServiceAssetBinding) Validate() error {
	if !validUUID(binding.ID) || !validUUID(binding.ServiceID) || !validUUID(binding.AssetID) || !binding.Scope.Valid() ||
		!binding.Role.Valid() || !validMappingStatus(binding.MappingStatus) || !binding.Provenance.Valid() ||
		!validProvenanceSource(binding.Provenance, binding.ProvenanceSourceID) || !binding.Status.Valid() ||
		binding.Version <= 0 || !validStoredTime(binding.CreatedAt) || !validStoredTime(binding.UpdatedAt) ||
		binding.CreatedAt.After(binding.UpdatedAt) {
		return ErrInvalidRequest
	}
	return nil
}

func (observation Observation) Validate() error {
	if !validUUID(observation.ID) || !validUUID(observation.SourceID) || !validUUID(observation.RunID) ||
		!providerKindToken.MatchString(observation.ProviderKind) || !validSafeText(observation.ExternalID, 1, 512) ||
		!observation.Scope.Valid() || observation.SourceRevision <= 0 || !validDigest(observation.CanonicalRevisionDigest) ||
		!validDigest(observation.SourceDefinitionDigest) || !validStoredTime(observation.ObservedAt) || !observation.FreshnessKind.Valid() ||
		observation.FreshnessOrderSequence <= 0 || !validFreshnessCoordinate(observation.FreshnessKind, observation.FreshnessOrderTime) ||
		!validDigest(observation.ProviderVersionSHA256) || !validDigest(observation.ProviderFactSHA256) ||
		!validDigest(observation.FingerprintSHA256) || !validDigest(observation.ProviderProvenanceSHA256) ||
		!validDigest(observation.ObservationChainSHA256) || observation.AcceptedCheckpointVersion <= 0 ||
		observation.RunFenceEpoch <= 0 || observation.RunPageSequence <= 0 || !validSafeToken(observation.SchemaVersion, 1, 128) ||
		!validDigest(observation.FieldProvenanceSHA256) || observation.FieldProvenanceSHA256 != sha256Hex(observation.FieldProvenance) ||
		!validFieldProvenance(observation.FieldProvenance, observation.SourceID, observation.ProviderKind,
			observation.SourceRevision, observation.ObservedAt) ||
		!validStoredTime(observation.CreatedAt) {
		return ErrInvalidRequest
	}
	if !validAcceptedFreshnessSequence(observation.FreshnessKind, observation.FreshnessOrderSequence, observation.AcceptedCheckpointVersion) {
		return ErrInvalidRequest
	}
	if (observation.PreviousObservationID == "") != (observation.PreviousChainSHA256 == "") ||
		observation.PreviousObservationID != "" && (!validUUID(observation.PreviousObservationID) || !validDigest(observation.PreviousChainSHA256)) {
		return ErrInvalidRequest
	}
	if observation.Tombstone {
		if len(observation.NormalizedDocument) != 0 || observation.DocumentSHA256 != "" ||
			!validSafeToken(observation.TombstoneReasonCode, 1, 128) {
			return ErrInvalidRequest
		}
	} else if len(observation.NormalizedDocument) < 2 || len(observation.NormalizedDocument) > 65536 ||
		!strictCanonicalJSONObject(observation.NormalizedDocument) ||
		!validDigest(observation.DocumentSHA256) || observation.DocumentSHA256 != sha256Hex(observation.NormalizedDocument) ||
		observation.TombstoneReasonCode != "" {
		return ErrInvalidRequest
	}
	return nil
}

type fieldProvenanceValue struct {
	Confidence       int            `json:"confidence"`
	ObservedAt       string         `json:"observed_at"`
	Ownership        FieldOwnership `json:"ownership"`
	ProviderKind     string         `json:"provider_kind"`
	ProviderPathCode string         `json:"provider_path_code"`
	SourceID         string         `json:"source_id"`
	SourceRevision   int64          `json:"source_revision"`
}

var fieldProvenanceCodes = map[string]struct{}{
	"provider_kind": {}, "external_id": {}, "kind": {}, "display_name": {}, "owner_group": {},
	"criticality": {}, "data_classification": {}, "labels": {}, "environment_id": {},
	"lifecycle": {}, "mapping_status": {}, "type_details": {},
}

var fieldProvenanceValueKeys = map[string]struct{}{
	"source_id": {}, "provider_kind": {}, "source_revision": {}, "observed_at": {},
	"provider_path_code": {}, "confidence": {}, "ownership": {},
}

func validFieldProvenance(value []byte, sourceID, providerKind string, sourceRevision int64, observedAt time.Time) bool {
	if len(value) < 2 || len(value) > 32768 || !strictCanonicalJSONObject(value) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(value, &fields) != nil || len(fields) > len(fieldProvenanceCodes) {
		return false
	}
	for field, raw := range fields {
		if _, allowed := fieldProvenanceCodes[field]; !allowed {
			return false
		}
		keys, ok := exactTopLevelKeys(raw)
		if !ok || len(keys) != len(fieldProvenanceValueKeys) {
			return false
		}
		for key := range fieldProvenanceValueKeys {
			if _, present := keys[key]; !present {
				return false
			}
		}
		if !strictCanonicalJSONObject(raw) {
			return false
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var item fieldProvenanceValue
		if decoder.Decode(&item) != nil || item.Confidence < 0 || item.Confidence > 100 || !item.Ownership.Valid() ||
			!providerKindToken.MatchString(item.ProviderKind) || !validSafeToken(item.ProviderPathCode, 1, 128) ||
			!validUUID(item.SourceID) || item.SourceRevision <= 0 || item.SourceID != sourceID ||
			item.ProviderKind != providerKind || item.SourceRevision != sourceRevision {
			return false
		}
		const provenanceTimeLayout = "2006-01-02T15:04:05.000000Z"
		parsed, err := time.Parse(provenanceTimeLayout, item.ObservedAt)
		if err != nil || !validStoredTime(parsed) || parsed.Format(provenanceTimeLayout) != item.ObservedAt || parsed != observedAt {
			return false
		}
	}
	return true
}

func (run SourceRun) Validate() error {
	if !validUUID(run.ID) || !validUUID(run.SourceID) || !run.Scope.Valid() || run.SourceRevision <= 0 ||
		!validDigest(run.SourceRevisionDigest) || !run.Kind.Valid() || !run.Status.Valid() || !run.Stage.Valid() ||
		!validStoredTime(run.StageChangedAt) || !run.TriggerType.Valid() || run.GateRevision < 0 ||
		run.PageSequence < 0 || run.RelationPageSequence < 0 || run.CheckpointVersion < 0 ||
		!validStoredTime(run.NotBefore) || !validOptionalTime(run.LeaseExpiresAt) || run.FenceEpoch < 0 || run.HeartbeatSequence < 0 ||
		!run.CredentialCleanupStatus.Valid() || run.TraceID != "" && !validSafeText(run.TraceID, 1, 128) || run.Version <= 0 ||
		!validStoredTime(run.CreatedAt) || !validOptionalTime(run.StartedAt) || !validOptionalTime(run.HeartbeatAt) ||
		!validOptionalTime(run.WorkResultRecordedAt) || !validOptionalTime(run.CompletedAt) || !nonnegativeRunCounts(run) {
		return ErrInvalidRequest
	}
	if (run.PageSequence == 0) != (run.PageDigest == "") || run.PageDigest != "" && !validDigest(run.PageDigest) ||
		(run.RelationPageSequence == 0) != (run.RelationPageDigest == "") || run.RelationPageDigest != "" && !validDigest(run.RelationPageDigest) ||
		run.CursorBeforeSHA256 != "" && !validDigest(run.CursorBeforeSHA256) ||
		run.CursorAfterSHA256 != "" && !validDigest(run.CursorAfterSHA256) {
		return ErrInvalidRequest
	}
	if run.CompleteSnapshot && !run.FinalPage || run.EffectiveCompleteSnapshot && (!run.CompleteSnapshot || run.Rejected != 0) {
		return ErrInvalidRequest
	}
	resultPresent, resultValid := validRunWorkResult(run)
	if !resultValid {
		return ErrInvalidRequest
	}
	if run.StartedAt != nil && run.StartedAt.Before(run.CreatedAt) ||
		run.HeartbeatAt != nil && (run.StartedAt == nil || run.HeartbeatAt.Before(*run.StartedAt)) ||
		run.WorkResultRecordedAt != nil && (run.StartedAt == nil || run.WorkResultRecordedAt.Before(*run.StartedAt)) ||
		run.CompletedAt != nil && (run.CompletedAt.Before(run.CreatedAt) || run.StartedAt != nil && run.CompletedAt.Before(*run.StartedAt)) {
		return ErrInvalidRequest
	}
	if run.Kind == RunKindValidation && !zeroRunProjection(run) ||
		run.Kind == RunKindManualMutation && (run.CompleteSnapshot || run.EffectiveCompleteSnapshot) {
		return ErrInvalidRequest
	}
	switch run.Status {
	case RunStatusQueued:
		if run.Stage != RunStageWaiting || run.StartedAt != nil || run.HeartbeatAt != nil || run.LeaseExpiresAt != nil ||
			run.FenceEpoch != 0 || run.HeartbeatSequence != 0 || run.CompletedAt != nil || resultPresent ||
			run.FailureCode != "" || run.CredentialCleanupStatus != CredentialCleanupNotOpened || !zeroCommittedRunProgress(run) {
			return ErrInvalidRequest
		}
	case RunStatusDelayed:
		if run.Stage != RunStageDelayed || run.StartedAt == nil || run.HeartbeatAt == nil || run.LeaseExpiresAt != nil ||
			run.FenceEpoch <= 0 || run.HeartbeatSequence <= 0 || run.CompletedAt != nil || resultPresent ||
			run.FailureCode != "" || run.FinalPage || run.CompleteSnapshot || run.EffectiveCompleteSnapshot ||
			!oneOfCleanup(run.CredentialCleanupStatus, CredentialCleanupNotOpened, CredentialCleanupRevoked, CredentialCleanupNoCredential) {
			return ErrInvalidRequest
		}
	case RunStatusRunning:
		validationStage := run.Kind == RunKindValidation && oneOfRunStage(run.Stage, RunStageValidating, RunStageCleaningUp)
		dataStage := run.Kind != RunKindValidation && oneOfRunStage(run.Stage, RunStageReading, RunStageNormalizing, RunStageApplying, RunStageCleaningUp)
		cleanupStageValid := run.Stage == RunStageCleaningUp ||
			oneOfCleanup(run.CredentialCleanupStatus, CredentialCleanupNotOpened, CredentialCleanupPending)
		if !validationStage && !dataStage || !cleanupStageValid ||
			run.StartedAt == nil || run.HeartbeatAt == nil || run.LeaseExpiresAt == nil || run.FenceEpoch <= 0 ||
			run.HeartbeatSequence <= 0 || run.CompletedAt != nil || resultPresent || run.FailureCode != "" ||
			run.FinalPage || run.CompleteSnapshot || run.EffectiveCompleteSnapshot {
			return ErrInvalidRequest
		}
	case RunStatusFinalizing:
		if run.Stage != RunStageCleaningUp || run.StartedAt == nil || run.HeartbeatAt == nil || run.LeaseExpiresAt == nil ||
			run.FenceEpoch <= 0 || run.HeartbeatSequence <= 0 || run.CompletedAt != nil || !resultPresent || run.FailureCode != "" {
			return ErrInvalidRequest
		}
	case RunStatusSucceeded:
		if !validTerminalRun(run, resultPresent) || run.FailureCode != "" || !closedCleanup(run.CredentialCleanupStatus) {
			return ErrInvalidRequest
		}
		if run.Kind == RunKindValidation {
			if run.WorkResultKind != WorkResultValidationProof || run.WorkResultStatus != WorkResultStatusSucceeded ||
				run.ValidationOutcome != ValidationOutcomeSucceeded {
				return ErrInvalidRequest
			}
		} else if run.WorkResultKind != WorkResultDataProjection || run.WorkResultStatus != WorkResultStatusSucceeded {
			return ErrInvalidRequest
		}
	case RunStatusPartial:
		if !validTerminalRun(run, resultPresent) || run.Kind == RunKindValidation || run.FailureCode != "" ||
			!closedCleanup(run.CredentialCleanupStatus) || run.WorkResultKind != WorkResultDataProjection ||
			run.WorkResultStatus != WorkResultStatusPartial {
			return ErrInvalidRequest
		}
	case RunStatusFailed:
		if !validTerminalRun(run, resultPresent) || !validSafeToken(run.FailureCode, 1, 128) ||
			!oneOfCleanup(run.CredentialCleanupStatus, CredentialCleanupNotOpened, CredentialCleanupRevoked,
				CredentialCleanupNoCredential, CredentialCleanupUncertain) {
			return ErrInvalidRequest
		}
		if run.CredentialCleanupStatus == CredentialCleanupNotOpened {
			if run.WorkResultKind != WorkResultFailureIntent || !zeroCommittedRunProgress(run) {
				return ErrInvalidRequest
			}
		} else if run.CredentialCleanupStatus != CredentialCleanupUncertain {
			failureIntent := run.WorkResultKind == WorkResultFailureIntent && run.WorkResultStatus == WorkResultStatusFailed
			failedValidation := run.Kind == RunKindValidation && run.WorkResultKind == WorkResultValidationProof &&
				run.WorkResultStatus == WorkResultStatusFailed && run.ValidationOutcome == ValidationOutcomeFailed
			if !failureIntent && !failedValidation {
				return ErrInvalidRequest
			}
		}
	case RunStatusCancelled:
		if run.Stage != RunStageCompleted || run.CompletedAt == nil || run.LeaseExpiresAt != nil || resultPresent ||
			run.FailureCode != "" || run.FinalPage || run.CompleteSnapshot || run.EffectiveCompleteSnapshot {
			return ErrInvalidRequest
		}
		directCancellation := run.StartedAt == nil && run.HeartbeatAt == nil && run.FenceEpoch == 0 &&
			run.HeartbeatSequence == 0 && run.CredentialCleanupStatus == CredentialCleanupNotOpened && zeroCommittedRunProgress(run)
		releasedAttemptCancellation := run.StartedAt != nil && run.HeartbeatAt != nil && run.FenceEpoch > 0 &&
			run.HeartbeatSequence > 0 && closedCleanup(run.CredentialCleanupStatus)
		if !directCancellation && !releasedAttemptCancellation {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validRunWorkResult(run SourceRun) (bool, bool) {
	present := run.WorkResultKind != "" || run.WorkResultStatus != "" || run.WorkResultDigest != "" ||
		run.WorkResultRecordedAt != nil || run.ValidationOutcome != "" || run.ValidationProofDigest != ""
	if !present {
		return false, true
	}
	if !run.WorkResultKind.Valid() || !run.WorkResultStatus.Valid() || !validDigest(run.WorkResultDigest) ||
		run.WorkResultRecordedAt == nil {
		return true, false
	}
	switch run.WorkResultKind {
	case WorkResultDataProjection:
		return true, run.Kind != RunKindValidation &&
			oneOfWorkResultStatus(run.WorkResultStatus, WorkResultStatusSucceeded, WorkResultStatusPartial) &&
			run.FinalPage && run.ValidationOutcome == "" && run.ValidationProofDigest == ""
	case WorkResultValidationProof:
		return true, run.Kind == RunKindValidation &&
			oneOfWorkResultStatus(run.WorkResultStatus, WorkResultStatusSucceeded, WorkResultStatusFailed) &&
			run.ValidationOutcome.Valid() && string(run.ValidationOutcome) == string(run.WorkResultStatus) &&
			validDigest(run.ValidationProofDigest)
	case WorkResultFailureIntent:
		return true, run.WorkResultStatus == WorkResultStatusFailed &&
			!run.FinalPage && !run.CompleteSnapshot && !run.EffectiveCompleteSnapshot &&
			run.ValidationOutcome == "" && run.ValidationProofDigest == ""
	}
	return true, false
}

func oneOfRunStage(value RunStage, values ...RunStage) bool { return slices.Contains(values, value) }

func oneOfWorkResultStatus(value WorkResultStatus, values ...WorkResultStatus) bool {
	return slices.Contains(values, value)
}

func oneOfCleanup(value CredentialCleanupStatus, values ...CredentialCleanupStatus) bool {
	return slices.Contains(values, value)
}

func closedCleanup(value CredentialCleanupStatus) bool {
	return oneOfCleanup(value, CredentialCleanupRevoked, CredentialCleanupNoCredential)
}

func validTerminalRun(run SourceRun, resultPresent bool) bool {
	return run.Stage == RunStageCompleted && run.CompletedAt != nil &&
		run.StartedAt != nil && run.HeartbeatAt != nil && run.FenceEpoch > 0 && run.HeartbeatSequence > 0 && resultPresent
}

func zeroRunProjection(run SourceRun) bool {
	return run.PageSequence == 0 && run.PageDigest == "" && run.RelationPageSequence == 0 && run.RelationPageDigest == "" &&
		run.CursorBeforeSHA256 == "" && run.CursorAfterSHA256 == "" && run.CheckpointVersion == 0 &&
		!run.FinalPage && !run.CompleteSnapshot && !run.EffectiveCompleteSnapshot && zeroRunCounts(run)
}

func zeroCommittedRunProgress(run SourceRun) bool {
	return run.PageSequence == 0 && run.PageDigest == "" && run.RelationPageSequence == 0 && run.RelationPageDigest == "" &&
		run.CursorAfterSHA256 == "" && !run.FinalPage && !run.CompleteSnapshot && !run.EffectiveCompleteSnapshot &&
		zeroRunCounts(run)
}

func nonnegativeRunCounts(run SourceRun) bool {
	return run.Observed >= 0 && run.Created >= 0 && run.Changed >= 0 && run.Unchanged >= 0 && run.Conflicts >= 0 &&
		run.Missing >= 0 && run.Stale >= 0 && run.Restored >= 0 && run.Tombstoned >= 0 && run.Rejected >= 0
}

func zeroRunCounts(run SourceRun) bool {
	return run.Observed == 0 && run.Created == 0 && run.Changed == 0 && run.Unchanged == 0 && run.Conflicts == 0 &&
		run.Missing == 0 && run.Stale == 0 && run.Restored == 0 && run.Tombstoned == 0 && run.Rejected == 0
}

func (request ListAssetsRequest) QueryDigest() (string, error) {
	if !request.Scope.Valid() || request.Access.Validate() != nil || !request.Sort.Valid() || request.Limit < 1 || request.Limit > 100 ||
		!validOptionalSafeText(request.Filter.Search, 512) || request.Filter.ServiceID != "" && !validUUID(request.Filter.ServiceID) {
		return "", ErrInvalidRequest
	}
	kinds, ok := normalizeSet(request.Filter.Kinds, func(value Kind) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	sourceIDs, ok := normalizeSet(request.Filter.SourceIDs, validUUID)
	if !ok {
		return "", ErrInvalidRequest
	}
	lifecycles, ok := normalizeSet(request.Filter.Lifecycles, func(value Lifecycle) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	mappings, ok := normalizeSet(request.Filter.MappingStatuses, validMappingStatus)
	if !ok {
		return "", ErrInvalidRequest
	}
	criticalities, ok := normalizeSet(request.Filter.Criticalities, func(value Criticality) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	classifications, ok := normalizeSet(request.Filter.DataClassifications, func(value DataClassification) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	frames := queryFrames("asset-list-query.v1", request.Scope.TenantID, request.Scope.WorkspaceID, request.Scope.EnvironmentID,
		request.Filter.Search, request.Filter.ServiceID, string(request.Sort))
	frames = appendQuerySet(frames, kinds)
	frames = appendQuerySet(frames, sourceIDs)
	frames = appendQuerySet(frames, lifecycles)
	frames = appendQuerySet(frames, mappings)
	frames = appendQuerySet(frames, criticalities)
	frames = appendQuerySet(frames, classifications)
	frames = appendAssetAccess(frames, request.Access)
	digest := framedDigest(frames)
	if request.Cursor != nil && !validAssetCursor(*request.Cursor, request.Sort, digest) {
		return "", ErrInvalidRequest
	}
	return digest, nil
}

func (request ListRelationshipsRequest) QueryDigest() (string, error) {
	if !request.Scope.Valid() || request.Access.Validate() != nil || request.Limit < 1 || request.Limit > 100 ||
		request.AssetID != "" && !validUUID(request.AssetID) || request.SourceID != "" && !validUUID(request.SourceID) {
		return "", ErrInvalidRequest
	}
	types, ok := normalizeSet(request.Types, func(value RelationshipType) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	statuses, ok := normalizeSet(request.Statuses, func(value RelationshipStatus) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	frames := queryFrames("relationship-list-query.v1", request.Scope.TenantID, request.Scope.WorkspaceID,
		request.Scope.EnvironmentID, request.AssetID, request.SourceID, "type,source_asset_id,target_asset_id,id")
	frames = appendQuerySet(frames, types)
	frames = appendQuerySet(frames, statuses)
	frames = appendAssetAccess(frames, request.Access)
	digest := framedDigest(frames)
	if request.Cursor != nil && (!validDigest(request.Cursor.QueryDigest) || request.Cursor.QueryDigest != digest ||
		!request.Cursor.Type.Valid() || !validUUID(request.Cursor.SourceAssetID) || !validUUID(request.Cursor.TargetAssetID) ||
		!validUUID(request.Cursor.RelationshipID)) {
		return "", ErrInvalidRequest
	}
	return digest, nil
}

func (request ListBindingsRequest) QueryDigest() (string, error) {
	if !request.Scope.Valid() || request.Access.Validate() != nil || request.Limit < 1 || request.Limit > 100 ||
		request.ServiceID != "" && !validUUID(request.ServiceID) || request.AssetID != "" && !validUUID(request.AssetID) {
		return "", ErrInvalidRequest
	}
	roles, ok := normalizeSet(request.Roles, func(value BindingRole) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	statuses, ok := normalizeSet(request.Statuses, func(value BindingStatus) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	frames := queryFrames("binding-list-query.v1", request.Scope.TenantID, request.Scope.WorkspaceID,
		request.Scope.EnvironmentID, request.ServiceID, request.AssetID, "service_id,role,asset_id,id")
	frames = appendQuerySet(frames, roles)
	frames = appendQuerySet(frames, statuses)
	frames = appendAssetAccess(frames, request.Access)
	digest := framedDigest(frames)
	if request.Cursor != nil && (!validDigest(request.Cursor.QueryDigest) || request.Cursor.QueryDigest != digest ||
		!validUUID(request.Cursor.ServiceID) || !request.Cursor.Role.Valid() || !validUUID(request.Cursor.AssetID) ||
		!validUUID(request.Cursor.BindingID)) {
		return "", ErrInvalidRequest
	}
	return digest, nil
}

func (request ListConflictsRequest) QueryDigest() (string, error) {
	if !request.Scope.Valid() || request.Access.Validate() != nil || request.Limit < 1 || request.Limit > 100 ||
		request.AssetID != "" && !validUUID(request.AssetID) || request.SourceID != "" && !validUUID(request.SourceID) {
		return "", ErrInvalidRequest
	}
	statuses, ok := normalizeSet(request.Statuses, func(value ConflictStatus) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	frames := queryFrames("conflict-list-query.v1", request.Scope.TenantID, request.Scope.WorkspaceID,
		request.Scope.EnvironmentID, request.AssetID, request.SourceID, "created_at_desc,id_desc")
	frames = appendQuerySet(frames, statuses)
	frames = appendAssetAccess(frames, request.Access)
	digest := framedDigest(frames)
	if request.Cursor != nil && (!validDigest(request.Cursor.QueryDigest) || request.Cursor.QueryDigest != digest ||
		!validStoredTime(request.Cursor.CreatedAt) || !validUUID(request.Cursor.ConflictID)) {
		return "", ErrInvalidRequest
	}
	return digest, nil
}

func (request ListSourcesRequest) QueryDigest() (string, error) {
	if !request.Scope.Valid() || request.Access.Validate() != nil || request.Limit < 1 || request.Limit > 100 ||
		request.Usage != "" && !request.Usage.Valid() {
		return "", ErrInvalidRequest
	}
	if request.Usage == SourceUsageManualAssetCreate {
		if !validUUID(request.EnvironmentID) {
			return "", ErrInvalidRequest
		}
	} else if request.EnvironmentID != "" && !validUUID(request.EnvironmentID) {
		return "", ErrInvalidRequest
	}
	kinds, ok := normalizeSet(request.Kinds, func(value SourceKind) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	statuses, ok := normalizeSet(request.Statuses, func(value SourceStatus) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	gates, ok := normalizeSet(request.GateStatuses, func(value SourceGateStatus) bool { return value.Valid() })
	if !ok {
		return "", ErrInvalidRequest
	}
	frames := queryFrames("source-list-query.v1", request.Scope.TenantID, request.Scope.WorkspaceID,
		string(request.Usage), request.EnvironmentID, "id_asc")
	frames = appendQuerySet(frames, kinds)
	frames = appendQuerySet(frames, statuses)
	frames = appendQuerySet(frames, gates)
	frames = appendQuerySet(frames, request.Access.EnvironmentIDs())
	digest := framedDigest(frames)
	if request.Cursor != nil && (!validDigest(request.Cursor.QueryDigest) || request.Cursor.QueryDigest != digest || !validUUID(request.Cursor.SourceID)) {
		return "", ErrInvalidRequest
	}
	return digest, nil
}

func validOptionalSafeText(value string, maximum int) bool {
	return value == "" || validSafeText(value, 1, maximum)
}

func validAssetCursor(cursor AssetCursor, sort AssetSort, digest string) bool {
	if cursor.Sort != sort || !validDigest(cursor.QueryDigest) || cursor.QueryDigest != digest || !validUUID(cursor.AssetID) {
		return false
	}
	switch sort {
	case AssetSortDisplayNameAsc:
		return validSafeText(cursor.Value, 1, 256) && strings.ToLower(cursor.Value) == cursor.Value
	case AssetSortLastObservedDesc:
		parsed, err := time.Parse(time.RFC3339Nano, cursor.Value)
		return err == nil && validStoredTime(parsed) && parsed.Location() == time.UTC &&
			parsed.UTC().Format(time.RFC3339Nano) == cursor.Value
	}
	return false
}

func normalizeSet[T ~string](values []T, valid func(T) bool) ([]T, bool) {
	result := slices.Clone(values)
	for _, value := range result {
		if !valid(value) {
			return nil, false
		}
	}
	slices.Sort(result)
	result = slices.Compact(result)
	return result, true
}

func queryFrames(domain string, values ...string) [][]byte {
	frames := make([][]byte, 0, len(values)+1)
	frames = append(frames, []byte(domain))
	for _, value := range values {
		frames = append(frames, []byte(value))
	}
	return frames
}

func appendQuerySet[T ~string](frames [][]byte, values []T) [][]byte {
	frames = append(frames, []byte(strconv.Itoa(len(values))))
	for _, value := range values {
		frames = append(frames, []byte(value))
	}
	return frames
}

func appendAssetAccess(frames [][]byte, access AssetReadConstraint) [][]byte {
	mode := "restricted"
	if access.Unrestricted() {
		mode = "unrestricted"
	}
	frames = append(frames, []byte(mode))
	return appendQuerySet(frames, access.ServiceIDs())
}
