package assetcatalog

import "github.com/seaworld008/aiops-system/internal/domain"

func IsLifecycleEdge(from, to Lifecycle) bool {
	if !from.Valid() || !to.Valid() || from == to {
		return false
	}
	switch from {
	case LifecycleDiscovered:
		return to == LifecycleActive || to == LifecycleQuarantined || to == LifecycleRetired
	case LifecycleActive:
		return to == LifecycleStale || to == LifecycleQuarantined || to == LifecycleRetired
	case LifecycleStale:
		return to == LifecycleActive || to == LifecycleQuarantined || to == LifecycleRetired
	case LifecycleQuarantined:
		return to == LifecycleActive || to == LifecycleRetired
	case LifecycleRetired:
		return false
	}
	return false
}

func (asset Asset) CatalogEligible() bool {
	return asset.Validate() == nil && asset.Lifecycle == LifecycleActive && asset.MappingStatus == domain.MappingExact
}

func (source Source) PublishedBindingEligible(revision SourceRevision) bool {
	if source.Validate() != nil || revision.Validate() != nil ||
		source.Status != SourceStatusActive || source.GateStatus != SourceGateAvailable || source.GateRevision <= 0 ||
		revision.Status != SourceRevisionPublished ||
		source.ID != revision.SourceID || source.TenantID != revision.TenantID || source.WorkspaceID != revision.WorkspaceID ||
		source.PublishedRevision != revision.Revision || source.PublishedRevisionDigest != revision.CanonicalRevisionDigest ||
		source.ValidatedRunID == "" || source.ValidationDigest == "" || source.ValidatedBindingDigest == "" ||
		source.ValidatedBindingDigest != revision.CanonicalRevisionDigest ||
		revision.ValidationRunID != source.ValidatedRunID || revision.ValidationDigest != source.ValidationDigest {
		return false
	}
	manifestDigest, err := ProfileManifestDigest(revision.CanonicalProfileManifest)
	if err != nil || manifestDigest != revision.ProfileManifestSHA256 ||
		sha256Hex(revision.CanonicalProviderSchema) != revision.CanonicalProviderSchemaSHA256 ||
		!canonicalJSONObject(revision.CanonicalProviderSchema) {
		return false
	}
	authorityDigest, err := AuthorityScopeDigest(revision.AuthorityEnvironmentIDs)
	if err != nil || authorityDigest != revision.AuthorityScopeDigest {
		return false
	}
	definitionDigest, err := SourceDefinitionDigest(source, revision)
	if err != nil || definitionDigest != revision.SourceDefinitionDigest {
		return false
	}
	bindingDigest := revision.BindingDigest()
	return bindingDigest != "" && bindingDigest == revision.CanonicalRevisionDigest
}
