package externalcmdb

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

var ErrReconciliationRejected = errors.New("external cmdb reconciliation rejected")

type ReconciliationDescriptor struct {
	neutral sourceprofile.ExternalCMDBDescriptor
}

func NewReconciliationDescriptor(
	neutral sourceprofile.ExternalCMDBDescriptor,
) (ReconciliationDescriptor, error) {
	expected := sourceprofile.ExternalCMDBV1()
	if !neutral.Valid() ||
		neutral.Selector() != expected.Selector() ||
		neutral.SourceKind() != expected.SourceKind() ||
		neutral.ProviderKind() != expected.ProviderKind() ||
		neutral.ProfileCode() != expected.ProfileCode() ||
		neutral.DigestSHA256() != expected.DigestSHA256() ||
		!bytes.Equal(neutral.CanonicalJSON(), expected.CanonicalJSON()) {
		return ReconciliationDescriptor{}, ErrReconciliationRejected
	}
	return ReconciliationDescriptor{neutral: neutral}, nil
}

func (descriptor ReconciliationDescriptor) DescriptorDigestSHA256() string {
	if !descriptor.valid() {
		return ""
	}
	return descriptor.neutral.DigestSHA256()
}

func (descriptor ReconciliationDescriptor) SourceKind() assetcatalog.SourceKind {
	if !descriptor.valid() {
		return ""
	}
	return descriptor.neutral.SourceKind()
}

func (descriptor ReconciliationDescriptor) ProviderKind() string {
	if !descriptor.valid() {
		return ""
	}
	return descriptor.neutral.ProviderKind()
}

func (descriptor ReconciliationDescriptor) ProfileCode() assetcatalog.ProfileCode {
	if !descriptor.valid() {
		return ""
	}
	return descriptor.neutral.ProfileCode()
}

func (descriptor ReconciliationDescriptor) Limits() discoverysource.Limits {
	if !descriptor.valid() {
		return discoverysource.Limits{}
	}
	return discoverysource.Limits{
		MaxPageItems:     500,
		MaxPageRelations: 2_000,
		MaxPageBytes:     4 << 20,
		MaxDocumentBytes: 64 << 10,
	}
}

func (descriptor ReconciliationDescriptor) FactPolicy(
	authorityEnvironmentIDs []string,
) (assetdiscovery.FactPolicy, error) {
	if !descriptor.valid() {
		return assetdiscovery.FactPolicy{}, ErrReconciliationRejected
	}
	fields := externalCMDBDocumentFields()
	allowed := make(map[assetcatalog.Kind][]string, len(externalCMDBAssetKinds()))
	for _, kind := range externalCMDBAssetKinds() {
		allowed[kind] = slices.Clone(fields)
	}
	policy := assetdiscovery.FactPolicy{
		ProviderKind:            descriptor.ProviderKind(),
		FreshnessKind:           assetcatalog.FreshnessObjectTimeSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: slices.Clone(authorityEnvironmentIDs),
		TrustedPathCodes:        externalCMDBTrustedPaths(),
		RelationshipTypes:       externalCMDBAllowedRelationshipTypes(),
		AllowedDocumentFields:   allowed,
	}
	if err := assetdiscovery.ValidateFacts(nil, nil, policy); err != nil {
		return assetdiscovery.FactPolicy{}, ErrReconciliationRejected
	}
	return policy, nil
}

func (descriptor ReconciliationDescriptor) ResolvePageFactPolicy(
	ctx context.Context,
	revision assetcatalog.SourceRevision,
) (assetdiscovery.FactPolicy, error) {
	if ctx == nil {
		return assetdiscovery.FactPolicy{}, ErrReconciliationRejected
	}
	if err := ctx.Err(); err != nil {
		return assetdiscovery.FactPolicy{}, err
	}
	if !descriptor.valid() ||
		revision.Status != assetcatalog.SourceRevisionPublished ||
		revision.Validate() != nil {
		return assetdiscovery.FactPolicy{}, ErrReconciliationRejected
	}
	registration, err := descriptor.neutral.Registration(sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID:            revision.IntegrationID,
		CredentialReferenceID:    revision.CredentialReferenceID,
		TrustReferenceID:         revision.TrustReferenceID,
		NetworkPolicyReferenceID: revision.NetworkPolicyReferenceID,
	})
	if err != nil || !externalCMDBRevisionMatchesProfile(revision, registration.Profile) {
		return assetdiscovery.FactPolicy{}, ErrReconciliationRejected
	}
	return descriptor.FactPolicy(revision.AuthorityEnvironmentIDs)
}

func (descriptor ReconciliationDescriptor) ResolveCrossEnvironmentRelationPolicy(
	ctx context.Context,
	_ assetcatalog.SourceRevision,
	_ discoverysource.CrossEnvironmentRelationPolicyCoordinates,
) (assetcatalog.PolicyReferenceID, error) {
	if ctx == nil {
		return "", ErrReconciliationRejected
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", ErrReconciliationRejected
}

func (descriptor ReconciliationDescriptor) NewProvider(
	binding discoverysource.RuntimeBinding,
) (discoverysource.Provider, error) {
	if !descriptor.valid() ||
		binding.RevisionStatus != assetcatalog.SourceRevisionPublished ||
		binding.ProviderKind != descriptor.ProviderKind() ||
		binding.ProfileCode != descriptor.ProfileCode() {
		return nil, ErrReconciliationRejected
	}
	checkpoint, err := descriptor.NewCheckpoint()
	if err != nil {
		return nil, ErrReconciliationRejected
	}
	defer checkpoint.Clear()
	if err := (discoverysource.DiscoverRequest{
		Locator:              binding.Locator,
		SourceRevision:       binding.SourceRevision,
		SourceRevisionDigest: binding.SourceRevisionDigest,
		Checkpoint:           checkpoint,
		Limits:               descriptor.Limits(),
	}).Validate(); err != nil {
		return nil, ErrReconciliationRejected
	}
	factory, err := NewClientFactory(binding)
	if err != nil {
		return nil, ErrReconciliationRejected
	}
	provider, err := New(factory)
	if err != nil {
		return nil, ErrReconciliationRejected
	}
	return provider, nil
}

func (descriptor ReconciliationDescriptor) NewCheckpoint() (discoverysource.Checkpoint, error) {
	if !descriptor.valid() {
		return discoverysource.Checkpoint{}, ErrReconciliationRejected
	}
	checkpoint, err := discoverysource.NewCheckpoint(descriptor.ProfileCode(), nil)
	if err != nil {
		return discoverysource.Checkpoint{}, ErrReconciliationRejected
	}
	return checkpoint, nil
}

func (descriptor ReconciliationDescriptor) valid() bool {
	return descriptor.neutral.Valid() &&
		descriptor.neutral.DigestSHA256() == sourceprofile.ExternalCMDBV1().DigestSHA256()
}

func externalCMDBRevisionMatchesProfile(
	revision assetcatalog.SourceRevision,
	profile assetcatalog.BuiltinSourceProfile,
) bool {
	return revision.ProfileCode == profile.ProfileCode &&
		revision.SyncMode == profile.SyncMode &&
		bytes.Equal(revision.CanonicalProfileManifest, profile.CanonicalProfileManifest) &&
		revision.ProfileManifestSHA256 == profile.ProfileManifestSHA256 &&
		bytes.Equal(revision.CanonicalProviderSchema, profile.CanonicalProviderSchema) &&
		revision.CanonicalProviderSchemaSHA256 == profile.CanonicalProviderSchemaSHA256 &&
		revision.IntegrationID == profile.IntegrationID &&
		revision.CredentialReferenceID == profile.CredentialReferenceID &&
		revision.TrustReferenceID == profile.TrustReferenceID &&
		revision.NetworkPolicyReferenceID == profile.NetworkPolicyReferenceID &&
		revision.RateLimitRequests == profile.RateLimitRequests &&
		revision.RateLimitWindowSeconds == profile.RateLimitWindowSeconds &&
		revision.BackpressureBaseSeconds == profile.BackpressureBaseSeconds &&
		revision.BackpressureMaxSeconds == profile.BackpressureMaxSeconds &&
		revision.ScheduleExpression == profile.ScheduleExpression &&
		revision.TypedExtensionCode == profile.TypedExtensionCode &&
		revision.PreparedExtensionDigest == profile.PreparedExtensionDigest
}

func externalCMDBAssetKinds() []assetcatalog.Kind {
	return []assetcatalog.Kind{
		assetcatalog.KindArgoApplication,
		assetcatalog.KindAWXInventory,
		assetcatalog.KindBareMetalHost,
		assetcatalog.KindCIPipeline,
		assetcatalog.KindCloudResource,
		assetcatalog.KindDatabase,
		assetcatalog.KindDatabaseInstance,
		assetcatalog.KindGitRepository,
		assetcatalog.KindKubernetesCluster,
		assetcatalog.KindKubernetesNamespace,
		assetcatalog.KindKubernetesWorkload,
		assetcatalog.KindLinuxVM,
		assetcatalog.KindLogSource,
		assetcatalog.KindMetricsSource,
		assetcatalog.KindService,
		assetcatalog.KindTraceSource,
		assetcatalog.KindWindowsVM,
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

func externalCMDBAllowedRelationshipTypes() []assetcatalog.RelationshipType {
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
