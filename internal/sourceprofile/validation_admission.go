package sourceprofile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const (
	sourceValidationRuntimeManifestSchemaVersion = "discovery-worker-runtime-admission.v1"
	// This is the already-merged Task 28C exact CMDB registry row, consumed as
	// a digest only; no recovery protocol or runtime material is reconstructed.
	externalCMDBRuntimeRecoveryCapabilityDigest = "92f56dca945425f4129703183c71ba9c0aa08f47c3f8e8ec2ed6cdea2951f5aa"
)

// SourceValidationRuntimeManifest is the safe, content-addressed Task 28C
// admission artifact. It contains metadata digests only.
type SourceValidationRuntimeManifest struct {
	CanonicalJSON []byte
	DigestSHA256  string
}

func (manifest SourceValidationRuntimeManifest) Clone() SourceValidationRuntimeManifest {
	manifest.CanonicalJSON = slices.Clone(manifest.CanonicalJSON)
	return manifest
}

// SourceValidationAdmissionRequest contains only locked Catalog facts and the
// server-installed Profile selected by the Repository.
type SourceValidationAdmissionRequest struct {
	Source   assetcatalog.Source
	Revision assetcatalog.SourceRevision
	Profile  assetcatalog.BuiltinSourceProfile
}

func (request SourceValidationAdmissionRequest) Clone() SourceValidationAdmissionRequest {
	request.Source = request.Source.Clone()
	request.Revision = request.Revision.Clone()
	request.Profile = request.Profile.Clone()
	return request
}

// SourceValidationRuntimeAdmission is immutable. Its zero value is closed.
type SourceValidationRuntimeAdmission struct {
	descriptorDigest      string
	runtimeManifestDigest string
	runtimeRecoveryDigest string
}

type sourceValidationRuntimeManifestDocument struct {
	SchemaVersion string                                 `json:"schema_version"`
	Providers     []sourceValidationRuntimeManifestEntry `json:"providers"`
}

type sourceValidationRuntimeManifestEntry struct {
	ProviderKind                    string `json:"provider_kind"`
	ProfileCode                     string `json:"profile_code"`
	CanonicalDescriptorDigest       string `json:"canonical_descriptor_digest"`
	RuntimeRecoveryCapabilityDigest string `json:"runtime_recovery_capability_digest"`
}

func NewSourceValidationRuntimeAdmission(
	descriptor ExternalCMDBDescriptor,
	manifest SourceValidationRuntimeManifest,
) (SourceValidationRuntimeAdmission, error) {
	if !exactExternalCMDBDescriptor(descriptor) ||
		!validSourceValidationDigest(manifest.DigestSHA256) ||
		len(manifest.CanonicalJSON) == 0 || len(manifest.CanonicalJSON) > 64<<10 {
		return SourceValidationRuntimeAdmission{}, assetcatalog.ErrUnavailable
	}
	manifestDigest := sha256.Sum256(manifest.CanonicalJSON)
	if subtle.ConstantTimeCompare(
		[]byte(manifest.DigestSHA256),
		[]byte(hex.EncodeToString(manifestDigest[:])),
	) != 1 {
		return SourceValidationRuntimeAdmission{}, assetcatalog.ErrUnavailable
	}
	var document sourceValidationRuntimeManifestDocument
	decoder := json.NewDecoder(bytes.NewReader(manifest.CanonicalJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil ||
		document.SchemaVersion != sourceValidationRuntimeManifestSchemaVersion ||
		len(document.Providers) != 1 {
		return SourceValidationRuntimeAdmission{}, assetcatalog.ErrUnavailable
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) == nil {
		return SourceValidationRuntimeAdmission{}, assetcatalog.ErrUnavailable
	}
	entry := document.Providers[0]
	if entry.ProviderKind != descriptor.ProviderKind() ||
		entry.ProfileCode != string(descriptor.ProfileCode()) ||
		!sameSourceValidationDigest(entry.CanonicalDescriptorDigest, descriptor.DigestSHA256()) ||
		!sameSourceValidationDigest(
			entry.RuntimeRecoveryCapabilityDigest,
			externalCMDBRuntimeRecoveryCapabilityDigest,
		) {
		return SourceValidationRuntimeAdmission{}, assetcatalog.ErrUnavailable
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, manifest.CanonicalJSON) {
		return SourceValidationRuntimeAdmission{}, assetcatalog.ErrUnavailable
	}
	return SourceValidationRuntimeAdmission{
		descriptorDigest:      descriptor.DigestSHA256(),
		runtimeManifestDigest: manifest.DigestSHA256,
		runtimeRecoveryDigest: entry.RuntimeRecoveryCapabilityDigest,
	}, nil
}

func (admission SourceValidationRuntimeAdmission) Valid() bool {
	return sameSourceValidationDigest(
		admission.descriptorDigest,
		ExternalCMDBV1().DigestSHA256(),
	) &&
		validSourceValidationDigest(admission.runtimeManifestDigest) &&
		sameSourceValidationDigest(
			admission.runtimeRecoveryDigest,
			externalCMDBRuntimeRecoveryCapabilityDigest,
		)
}

func (admission SourceValidationRuntimeAdmission) RuntimeManifestDigestSHA256() string {
	if !admission.Valid() {
		return ""
	}
	return admission.runtimeManifestDigest
}

func (admission SourceValidationRuntimeAdmission) Admit(
	ctx context.Context,
	request SourceValidationAdmissionRequest,
) error {
	if ctx == nil || !admission.Valid() {
		return assetcatalog.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	request = request.Clone()
	descriptor := ExternalCMDBV1()
	if !exactExternalCMDBDescriptor(descriptor) ||
		!sameSourceValidationDigest(admission.descriptorDigest, descriptor.DigestSHA256()) ||
		!exactSourceValidationGatePrerequisite(request.Source, request.Revision, descriptor) {
		return assetcatalog.ErrUnavailable
	}
	registration, err := descriptor.Registration(ExternalCMDBProfileReferences{
		IntegrationID:            request.Profile.IntegrationID,
		CredentialReferenceID:    request.Profile.CredentialReferenceID,
		TrustReferenceID:         request.Profile.TrustReferenceID,
		NetworkPolicyReferenceID: request.Profile.NetworkPolicyReferenceID,
	})
	if err != nil ||
		!exactSourceValidationProfile(registration.Profile, request.Profile) ||
		!exactSourceValidationRevision(request.Source, request.Revision, request.Profile) {
		return assetcatalog.ErrUnavailable
	}
	return nil
}

func exactExternalCMDBDescriptor(descriptor ExternalCMDBDescriptor) bool {
	expected := ExternalCMDBV1()
	if !descriptor.Valid() || !expected.Valid() ||
		descriptor.Selector() != expected.Selector() ||
		descriptor.SourceKind() != expected.SourceKind() ||
		descriptor.ProviderKind() != expected.ProviderKind() ||
		descriptor.ProfileCode() != expected.ProfileCode() ||
		!bytes.Equal(descriptor.CanonicalJSON(), expected.CanonicalJSON()) ||
		!sameSourceValidationDigest(descriptor.DigestSHA256(), expected.DigestSHA256()) {
		return false
	}
	digest := sha256.Sum256(descriptor.CanonicalJSON())
	return sameSourceValidationDigest(
		descriptor.DigestSHA256(),
		hex.EncodeToString(digest[:]),
	)
}

func exactSourceValidationGatePrerequisite(
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
	descriptor ExternalCMDBDescriptor,
) bool {
	if source.Validate() != nil || revision.Validate() != nil ||
		source.Kind != descriptor.SourceKind() ||
		source.ProviderKind != descriptor.ProviderKind() ||
		source.Status != assetcatalog.SourceStatusActive ||
		source.ID != revision.SourceID ||
		source.TenantID != revision.TenantID ||
		source.WorkspaceID != revision.WorkspaceID ||
		revision.ProfileCode != descriptor.ProfileCode() {
		return false
	}
	switch revision.Status {
	case assetcatalog.SourceRevisionDraft, assetcatalog.SourceRevisionRejected:
		return (source.GateStatus == assetcatalog.SourceGateUnavailable ||
			source.GateStatus == assetcatalog.SourceGateAvailable) &&
			source.PublishedRevision != revision.Revision
	case assetcatalog.SourceRevisionValidating, assetcatalog.SourceRevisionValidated:
		return source.GateStatus == assetcatalog.SourceGateValidating &&
			source.GateReasonCode == "VALIDATION_IN_PROGRESS" &&
			source.ValidatedRunID == revision.ValidationRunID &&
			source.ValidationDigest == "" &&
			source.ValidatedBindingDigest == "" &&
			source.PublishedRevision != revision.Revision
	case assetcatalog.SourceRevisionPublished:
		return source.GateStatus == assetcatalog.SourceGateUnavailable &&
			source.GateReasonCode == "PUBLISHED_VALIDATION_REFERENCE_DRIFT" &&
			source.PublishedRevision == revision.Revision &&
			source.PublishedRevisionDigest == revision.CanonicalRevisionDigest &&
			source.CheckpointSourceRevision == revision.Revision &&
			source.CheckpointVersion == 0 &&
			source.CheckpointSHA256 == "" &&
			source.ValidatedRunID == "" &&
			source.ValidationDigest == "" &&
			source.ValidatedBindingDigest == ""
	default:
		return false
	}
}

func exactSourceValidationProfile(
	expected assetcatalog.BuiltinSourceProfile,
	actual assetcatalog.BuiltinSourceProfile,
) bool {
	return expected.SourceKind == actual.SourceKind &&
		expected.ProviderKind == actual.ProviderKind &&
		expected.ProfileCode == actual.ProfileCode &&
		expected.SyncMode == actual.SyncMode &&
		expected.FreshnessKind == actual.FreshnessKind &&
		expected.EnvironmentMapping == actual.EnvironmentMapping &&
		expected.IntegrationMode == actual.IntegrationMode &&
		expected.CredentialPurpose == actual.CredentialPurpose &&
		expected.TrustMode == actual.TrustMode &&
		expected.NetworkMode == actual.NetworkMode &&
		expected.ScheduleMode == actual.ScheduleMode &&
		expected.ParserCode == actual.ParserCode &&
		expected.CompatibilityClass == actual.CompatibilityClass &&
		expected.DLPPolicyCode == actual.DLPPolicyCode &&
		expected.MaxPageItems == actual.MaxPageItems &&
		expected.MaxPageRelations == actual.MaxPageRelations &&
		expected.MaxPageBytes == actual.MaxPageBytes &&
		expected.MaxDocumentBytes == actual.MaxDocumentBytes &&
		slices.Equal(expected.TrustedPathCodes, actual.TrustedPathCodes) &&
		slices.Equal(expected.RelationshipTypes, actual.RelationshipTypes) &&
		bytes.Equal(expected.CanonicalProfileManifest, actual.CanonicalProfileManifest) &&
		bytes.Equal(expected.CanonicalProviderSchema, actual.CanonicalProviderSchema) &&
		expected.ProfileManifestSHA256 == actual.ProfileManifestSHA256 &&
		expected.CanonicalProviderSchemaSHA256 == actual.CanonicalProviderSchemaSHA256 &&
		expected.IntegrationID == actual.IntegrationID &&
		expected.CredentialReferenceID == actual.CredentialReferenceID &&
		expected.TrustReferenceID == actual.TrustReferenceID &&
		expected.NetworkPolicyReferenceID == actual.NetworkPolicyReferenceID &&
		expected.RateLimitRequests == actual.RateLimitRequests &&
		expected.RateLimitWindowSeconds == actual.RateLimitWindowSeconds &&
		expected.BackpressureBaseSeconds == actual.BackpressureBaseSeconds &&
		expected.BackpressureMaxSeconds == actual.BackpressureMaxSeconds &&
		expected.ScheduleExpression == actual.ScheduleExpression &&
		expected.TypedExtensionCode == actual.TypedExtensionCode &&
		expected.PreparedExtensionDigest == actual.PreparedExtensionDigest
}

func exactSourceValidationRevision(
	source assetcatalog.Source,
	revision assetcatalog.SourceRevision,
	profile assetcatalog.BuiltinSourceProfile,
) bool {
	if source.Kind != profile.SourceKind ||
		source.ProviderKind != profile.ProviderKind ||
		revision.ProfileCode != profile.ProfileCode ||
		revision.SyncMode != profile.SyncMode ||
		!bytes.Equal(revision.CanonicalProfileManifest, profile.CanonicalProfileManifest) ||
		revision.ProfileManifestSHA256 != profile.ProfileManifestSHA256 ||
		!bytes.Equal(revision.CanonicalProviderSchema, profile.CanonicalProviderSchema) ||
		revision.CanonicalProviderSchemaSHA256 != profile.CanonicalProviderSchemaSHA256 ||
		revision.IntegrationID != profile.IntegrationID ||
		revision.CredentialReferenceID != profile.CredentialReferenceID ||
		revision.TrustReferenceID != profile.TrustReferenceID ||
		revision.NetworkPolicyReferenceID != profile.NetworkPolicyReferenceID ||
		revision.RateLimitRequests != profile.RateLimitRequests ||
		revision.RateLimitWindowSeconds != profile.RateLimitWindowSeconds ||
		revision.BackpressureBaseSeconds != profile.BackpressureBaseSeconds ||
		revision.BackpressureMaxSeconds != profile.BackpressureMaxSeconds ||
		revision.ScheduleExpression != profile.ScheduleExpression ||
		revision.TypedExtensionCode != profile.TypedExtensionCode ||
		revision.PreparedExtensionDigest != profile.PreparedExtensionDigest {
		return false
	}
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	if err != nil || authorityDigest != revision.AuthorityScopeDigest {
		return false
	}
	definitionDigest, err := assetcatalog.SourceDefinitionDigest(source, revision)
	return err == nil &&
		definitionDigest == revision.SourceDefinitionDigest &&
		revision.BindingDigest() == revision.CanonicalRevisionDigest
}

func validSourceValidationDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func sameSourceValidationDigest(left, right string) bool {
	return validSourceValidationDigest(left) &&
		validSourceValidationDigest(right) &&
		subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
