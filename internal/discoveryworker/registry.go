package discoveryworker

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const runtimeRecoveryCapabilityCanonical = `{"cleanup_only_recovery":true,"exact_attempt_binding":true,"provider_runtime_on_recovery":false,"protocol":"discovery-cleanup-session.v1","version":"discovery-runtime-recovery-capability.v1"}`

var ErrProviderRegistry = errors.New("discovery worker provider registry rejected")

// ProviderDeclaration is safe, immutable deployment input. The canonical
// Provider metadata remains owned by internal/sourceprofile; callers may only
// state the exact digests they expect the binary to have installed.
type ProviderDeclaration struct {
	SourceKind                      assetcatalog.SourceKind
	ProviderKind                    string
	ProfileCode                     assetcatalog.ProfileCode
	CanonicalDescriptorDigest       string
	RuntimeRecoveryCapabilityDigest string
}

// ProviderRegistry is an immutable exact-row registry. It deliberately has no
// family/default lookup and no mutable registration method.
type ProviderRegistry struct {
	self    *ProviderRegistry
	entries map[providerRegistryKey]providerRegistryEntry
	kinds   []string
}

type providerRegistryKey struct {
	provider string
	profile  assetcatalog.ProfileCode
}

type providerRegistryEntry struct {
	declaration    ProviderDeclaration
	neutral        sourceprofile.ExternalCMDBDescriptor
	reconciliation externalcmdb.ReconciliationDescriptor
}

// RuntimeRecoveryCapabilityDigest identifies the already-merged Task 28B
// exact-attempt recovery contract. It contains no address, peer, key, or
// runtime material.
func RuntimeRecoveryCapabilityDigest() string {
	digest := sha256.Sum256([]byte(runtimeRecoveryCapabilityCanonical))
	return fmt.Sprintf("%x", digest)
}

// ExternalCMDBDeclaration derives the deployable row only from the merged
// canonical neutral descriptor.
func ExternalCMDBDeclaration() ProviderDeclaration {
	descriptor := sourceprofile.ExternalCMDBV1()
	return ProviderDeclaration{
		SourceKind: descriptor.SourceKind(), ProviderKind: descriptor.ProviderKind(),
		ProfileCode:                     descriptor.ProfileCode(),
		CanonicalDescriptorDigest:       descriptor.DigestSHA256(),
		RuntimeRecoveryCapabilityDigest: RuntimeRecoveryCapabilityDigest(),
	}
}

func NewRegistry(declarations ...ProviderDeclaration) (*ProviderRegistry, error) {
	if len(declarations) == 0 {
		return nil, ErrProviderRegistry
	}
	entries := make(map[providerRegistryKey]providerRegistryEntry, len(declarations))
	kinds := make([]string, 0, len(declarations))
	for _, declaration := range declarations {
		entry, err := exactMergedProviderEntry(declaration)
		if err != nil {
			return nil, ErrProviderRegistry
		}
		key := providerRegistryKey{
			provider: declaration.ProviderKind,
			profile:  declaration.ProfileCode,
		}
		if _, exists := entries[key]; exists || slices.Contains(kinds, declaration.ProviderKind) {
			return nil, ErrProviderRegistry
		}
		entries[key] = entry
		kinds = append(kinds, declaration.ProviderKind)
	}
	sort.Strings(kinds)
	registry := &ProviderRegistry{entries: entries, kinds: kinds}
	registry.self = registry
	return registry, nil
}

func exactMergedProviderEntry(
	declaration ProviderDeclaration,
) (providerRegistryEntry, error) {
	neutral := sourceprofile.ExternalCMDBV1()
	expected := ExternalCMDBDeclaration()
	if declaration != expected || !neutral.Valid() ||
		declaration.SourceKind != neutral.SourceKind() ||
		declaration.ProviderKind != neutral.ProviderKind() ||
		declaration.ProfileCode != neutral.ProfileCode() ||
		declaration.CanonicalDescriptorDigest != neutral.DigestSHA256() ||
		declaration.RuntimeRecoveryCapabilityDigest != RuntimeRecoveryCapabilityDigest() {
		return providerRegistryEntry{}, ErrProviderRegistry
	}
	reconciliation, err := externalcmdb.NewReconciliationDescriptor(neutral)
	if err != nil ||
		reconciliation.SourceKind() != declaration.SourceKind ||
		reconciliation.ProviderKind() != declaration.ProviderKind ||
		reconciliation.ProfileCode() != declaration.ProfileCode ||
		reconciliation.DescriptorDigestSHA256() != declaration.CanonicalDescriptorDigest {
		return providerRegistryEntry{}, ErrProviderRegistry
	}
	return providerRegistryEntry{
		declaration: declaration, neutral: neutral, reconciliation: reconciliation,
	}, nil
}

func (registry *ProviderRegistry) valid() bool {
	if registry == nil || registry.self != registry || len(registry.entries) == 0 ||
		len(registry.kinds) != len(registry.entries) {
		return false
	}
	for key, entry := range registry.entries {
		if key.provider != entry.declaration.ProviderKind ||
			key.profile != entry.declaration.ProfileCode {
			return false
		}
	}
	return true
}

func (registry *ProviderRegistry) Registered(
	providerKind string,
	profileCode assetcatalog.ProfileCode,
) bool {
	if !registry.valid() {
		return false
	}
	_, exists := registry.entries[providerRegistryKey{
		provider: providerKind,
		profile:  profileCode,
	}]
	return exists
}

func (registry *ProviderRegistry) Lookup(
	providerKind string,
	profileCode assetcatalog.ProfileCode,
) (ProviderDeclaration, bool) {
	if !registry.valid() {
		return ProviderDeclaration{}, false
	}
	entry, exists := registry.entries[providerRegistryKey{
		provider: providerKind,
		profile:  profileCode,
	}]
	if !exists {
		return ProviderDeclaration{}, false
	}
	return entry.declaration, true
}

func (registry *ProviderRegistry) ProviderKinds() []string {
	if !registry.valid() {
		return nil
	}
	return slices.Clone(registry.kinds)
}

// ExternalCMDBDescriptors returns the exact merged code-owned descriptors used
// by the sole registered row. It never reconstructs their metadata.
func (registry *ProviderRegistry) ExternalCMDBDescriptors() (
	sourceprofile.ExternalCMDBDescriptor,
	externalcmdb.ReconciliationDescriptor,
	error,
) {
	if !registry.valid() {
		return sourceprofile.ExternalCMDBDescriptor{},
			externalcmdb.ReconciliationDescriptor{}, ErrProviderRegistry
	}
	expected := ExternalCMDBDeclaration()
	entry, exists := registry.entries[providerRegistryKey{
		provider: expected.ProviderKind,
		profile:  expected.ProfileCode,
	}]
	if !exists || entry.declaration != expected {
		return sourceprofile.ExternalCMDBDescriptor{},
			externalcmdb.ReconciliationDescriptor{}, ErrProviderRegistry
	}
	return entry.neutral, entry.reconciliation, nil
}
