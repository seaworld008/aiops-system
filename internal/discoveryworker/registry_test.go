package discoveryworker

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

func TestProductionRegistryConsumesExactExternalCMDBDescriptor(t *testing.T) {
	declaration := ExternalCMDBDeclaration()
	neutral := sourceprofile.ExternalCMDBV1()
	if declaration.SourceKind != neutral.SourceKind() ||
		declaration.ProviderKind != neutral.ProviderKind() ||
		declaration.ProfileCode != neutral.ProfileCode() ||
		declaration.CanonicalDescriptorDigest != neutral.DigestSHA256() ||
		declaration.RuntimeRecoveryCapabilityDigest != RuntimeRecoveryCapabilityDigest() {
		t.Fatalf("declaration = %#v, neutral digest = %q", declaration, neutral.DigestSHA256())
	}

	registry, err := NewRegistry(declaration)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if !registry.Registered(neutral.ProviderKind(), neutral.ProfileCode()) {
		t.Fatal("exact External CMDB row is not registered")
	}
	for _, provider := range []string{
		"KUBERNETES_OPERATOR",
		"AWX_INVENTORY",
		"VSPHERE_VCENTER_V1",
		"PROXMOX_VE_V1",
		"UNKNOWN_PROVIDER",
	} {
		if registry.Registered(provider, assetcatalog.ProfileCode(provider)) {
			t.Fatalf("unavailable provider %q was registered", provider)
		}
	}

	got, ok := registry.Lookup(neutral.ProviderKind(), neutral.ProfileCode())
	if !ok || got != declaration {
		t.Fatalf("Lookup() = %#v,%v, want %#v,true", got, ok, declaration)
	}
	kinds := registry.ProviderKinds()
	if !reflect.DeepEqual(kinds, []string{neutral.ProviderKind()}) {
		t.Fatalf("ProviderKinds() = %#v", kinds)
	}
	kinds[0] = "DRIFTED"
	if registry.ProviderKinds()[0] != neutral.ProviderKind() {
		t.Fatal("registry leaked mutable ProviderKinds storage")
	}
}

func TestProductionRegistryRejectsDuplicateUnknownMissingAndDriftedRows(t *testing.T) {
	valid := ExternalCMDBDeclaration()
	tests := map[string][]ProviderDeclaration{
		"empty": nil,
		"duplicate": {
			valid,
			valid,
		},
		"missing descriptor": {
			mutateProviderDeclaration(valid, func(value *ProviderDeclaration) {
				value.CanonicalDescriptorDigest = ""
			}),
		},
		"descriptor drift": {
			mutateProviderDeclaration(valid, func(value *ProviderDeclaration) {
				value.CanonicalDescriptorDigest = strings.Repeat("0", 64)
			}),
		},
		"runtime recovery drift": {
			mutateProviderDeclaration(valid, func(value *ProviderDeclaration) {
				value.RuntimeRecoveryCapabilityDigest = strings.Repeat("1", 64)
			}),
		},
		"source drift": {
			mutateProviderDeclaration(valid, func(value *ProviderDeclaration) {
				value.SourceKind = assetcatalog.SourceKindVSphere
			}),
		},
		"profile drift": {
			mutateProviderDeclaration(valid, func(value *ProviderDeclaration) {
				value.ProfileCode = "VSPHERE_VCENTER_V1"
			}),
		},
		"provider drift": {
			mutateProviderDeclaration(valid, func(value *ProviderDeclaration) {
				value.ProviderKind = "VSPHERE_VCENTER_V1"
			}),
		},
		"kubernetes": {{
			SourceKind:   assetcatalog.SourceKindKubernetesOperator,
			ProviderKind: "KUBERNETES_OPERATOR", ProfileCode: "KUBERNETES_OPERATOR",
			CanonicalDescriptorDigest:       valid.CanonicalDescriptorDigest,
			RuntimeRecoveryCapabilityDigest: valid.RuntimeRecoveryCapabilityDigest,
		}},
		"awx": {{
			SourceKind:   assetcatalog.SourceKindAWXInventory,
			ProviderKind: "AWX_INVENTORY", ProfileCode: "AWX_INVENTORY",
			CanonicalDescriptorDigest:       valid.CanonicalDescriptorDigest,
			RuntimeRecoveryCapabilityDigest: valid.RuntimeRecoveryCapabilityDigest,
		}},
		"proxmox": {{
			SourceKind:   assetcatalog.SourceKindProxmox,
			ProviderKind: "PROXMOX_VE_V1", ProfileCode: "PROXMOX_VE_V1",
			CanonicalDescriptorDigest:       valid.CanonicalDescriptorDigest,
			RuntimeRecoveryCapabilityDigest: valid.RuntimeRecoveryCapabilityDigest,
		}},
	}
	for name, declarations := range tests {
		t.Run(name, func(t *testing.T) {
			if registry, err := NewRegistry(declarations...); !errors.Is(err, ErrProviderRegistry) || registry != nil {
				t.Fatalf("NewRegistry() = %#v,%v, want nil, ErrProviderRegistry", registry, err)
			}
		})
	}
}

func TestProductionRegistryDoesNotRebuildExternalCMDBMetadata(t *testing.T) {
	source, err := os.ReadFile("registry.go")
	if err != nil {
		t.Fatalf("read registry.go: %v", err)
	}
	for _, required := range [][]byte{
		[]byte("sourceprofile.ExternalCMDBV1"),
		[]byte("externalcmdb.NewReconciliationDescriptor"),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("registry.go does not consume merged descriptor through %q", required)
		}
	}
	neutralCanonical := sourceprofile.ExternalCMDBV1().CanonicalJSON()
	if bytes.Contains(source, neutralCanonical) {
		t.Fatal("registry.go copied canonical External CMDB descriptor JSON")
	}
	if bytes.Contains(source, []byte(sourceprofile.ExternalCMDBV1().DigestSHA256())) {
		t.Fatal("registry.go copied canonical External CMDB descriptor digest")
	}
	for _, forbidden := range []string{
		"VSPHERE_VCENTER_V1",
		"PROXMOX_VE_V1",
		"KUBERNETES_OPERATOR",
		"AWX_INVENTORY",
		"defaultHTTP",
		"familyAdapter",
	} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("registry.go contains unavailable/fallback provider token %q", forbidden)
		}
	}
}

func TestRuntimeRecoveryCapabilityDigestIsStableAndDistinctFromProviderDescriptor(t *testing.T) {
	digest := RuntimeRecoveryCapabilityDigest()
	if len(digest) != 64 || strings.ToLower(digest) != digest ||
		!slices.ContainsFunc([]byte(digest), func(value byte) bool {
			return value >= 'a' && value <= 'f'
		}) {
		t.Fatalf("RuntimeRecoveryCapabilityDigest() = %q", digest)
	}
	if digest == sourceprofile.ExternalCMDBV1().DigestSHA256() {
		t.Fatal("runtime recovery and Provider descriptor reused one digest")
	}
}

func mutateProviderDeclaration(
	input ProviderDeclaration,
	mutate func(*ProviderDeclaration),
) ProviderDeclaration {
	mutate(&input)
	return input
}
