package readexecutor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEgressRegistryManifestLoadsOneImmutableStableSnapshot(t *testing.T) {
	first := validEgressPolicyDefinition()
	firstRef, err := BuildEgressPolicyRef("metrics-egress", first)
	if err != nil {
		t.Fatal(err)
	}
	first.PolicyRef = firstRef
	second := cloneEgressDefinition(first)
	second.Hostname = "logs.staging.internal"
	second.Port = 9443
	second.AllowedPrefixes = []string{"10.43.9.0/24"}
	second.PolicyRef = ""
	secondRef, err := BuildEgressPolicyRef("logs-egress", second)
	if err != nil {
		t.Fatal(err)
	}
	second.PolicyRef = secondRef

	path := writeEgressManifest(t, []EgressPolicyDefinition{first, second})
	registry, err := LoadEgressRegistryFile(path)
	if err != nil || registry == nil || !registry.Ready() {
		t.Fatalf("LoadEgressRegistryFile() = %#v, %v", registry, err)
	}
	digest := registry.Digest()
	if digest == "" {
		t.Fatal("registry digest is empty")
	}
	reordered := []EgressPolicyDefinition{second, first}
	reorderedRegistry, err := NewEgressRegistry(reordered)
	if err != nil || reorderedRegistry.Digest() != digest {
		t.Fatalf("order changed digest: %q / %q / %v", digest, reorderedRegistry.Digest(), err)
	}
	changed := cloneEgressDefinition(second)
	changed.AllowedPrefixes = []string{"10.44.9.0/24"}
	changed.PolicyRef = ""
	changedRef, err := BuildEgressPolicyRef("logs-egress", changed)
	if err != nil {
		t.Fatal(err)
	}
	changed.PolicyRef = changedRef
	changedRegistry, err := NewEgressRegistry([]EgressPolicyDefinition{first, changed})
	if err != nil || changedRegistry.Digest() == digest {
		t.Fatalf("policy content change did not change registry digest: %q / %q / %v", digest, changedRegistry.Digest(), err)
	}

	// Source and file mutations cannot hot-update the accepted snapshot.
	first.AllowedPrefixes[0] = "10.99.99.0/24"
	if err := os.WriteFile(path, []byte(`{"schema_version":"read-egress-policy-registry.v1","policies":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !registry.Ready() || registry.Digest() != digest {
		t.Fatal("accepted registry changed after source/file mutation")
	}

	copied := *registry
	if copied.Ready() || copied.Digest() != "" {
		t.Fatal("copied registry retained authority")
	}
	encoded, err := json.Marshal(registry)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(EgressRegistry) = %s, %v", encoded, err)
	}
	rendered := fmt.Sprintf("%s %+v %#v", registry, registry, registry)
	for _, forbidden := range []string{firstRef, secondRef, first.Hostname, second.Hostname, "10.42.9.0/24"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("registry rendering leaked %q: %s", forbidden, rendered)
		}
	}
	var decoded EgressRegistry
	if err := json.Unmarshal(encoded, &decoded); !errors.Is(err, ErrEgressRegistryRejected) {
		t.Fatalf("json.Unmarshal(EgressRegistry) error = %v", err)
	}
}

func TestEgressRegistryManifestFailsClosedAtEveryBoundary(t *testing.T) {
	definition := validEgressPolicyDefinition()
	ref, err := BuildEgressPolicyRef("metrics-egress", definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.PolicyRef = ref
	valid, err := json.Marshal(egressManifestDocument{
		SchemaVersion: EgressRegistrySchemaVersion, Policies: []EgressPolicyDefinition{definition},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		contents []byte
		want     error
	}{
		"unknown":   {append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"extra":true}`)...), ErrEgressManifestJSON},
		"duplicate": {[]byte(strings.Replace(string(valid), `"schema_version":`, `"schema_version":"read-egress-policy-registry.v1","schema_version":`, 1)), ErrEgressManifestJSON},
		"wrong schema": {[]byte(strings.Replace(string(valid), EgressRegistrySchemaVersion,
			EgressRegistrySchemaVersion+".drift", 1)), ErrEgressManifestJSON},
		"empty": {[]byte(`{"schema_version":"read-egress-policy-registry.v1","policies":[]}`), ErrEgressManifestDefinition},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "egress.json")
			if err := os.WriteFile(path, test.contents, 0o600); err != nil {
				t.Fatal(err)
			}
			registry, err := LoadEgressRegistryFile(path)
			if registry != nil || !errors.Is(err, test.want) {
				t.Fatalf("LoadEgressRegistryFile() = %#v, %v; want %v", registry, err, test.want)
			}
		})
	}
	if registry, err := LoadEgressRegistryFile("relative.json"); registry != nil || !errors.Is(err, ErrEgressManifestPath) {
		t.Fatalf("relative path = %#v, %v", registry, err)
	}
	insecure := filepath.Join(t.TempDir(), "egress.json")
	if err := os.WriteFile(insecure, valid, 0o622); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o622); err != nil {
		t.Fatal(err)
	}
	if registry, err := LoadEgressRegistryFile(insecure); registry != nil || !errors.Is(err, ErrEgressManifestFile) {
		t.Fatalf("insecure file = %#v, %v", registry, err)
	}

	duplicate := cloneEgressDefinition(definition)
	if registry, err := NewEgressRegistry([]EgressPolicyDefinition{definition, duplicate}); registry != nil ||
		!errors.Is(err, ErrEgressRegistryRejected) {
		t.Fatalf("duplicate registry = %#v, %v", registry, err)
	}
	alias := cloneEgressDefinition(definition)
	alias.PolicyRef = ""
	aliasRef, err := BuildEgressPolicyRef("metrics-egress-alias", alias)
	if err != nil {
		t.Fatal(err)
	}
	alias.PolicyRef = aliasRef
	if registry, err := NewEgressRegistry([]EgressPolicyDefinition{definition, alias}); registry != nil ||
		!errors.Is(err, ErrEgressRegistryRejected) {
		t.Fatalf("content alias registry = %#v, %v", registry, err)
	}
	drifted := cloneEgressDefinition(definition)
	drifted.AllowedPrefixes = slices.Clone(drifted.AllowedPrefixes)
	drifted.AllowedPrefixes[0] = "10.44.9.0/24"
	if registry, err := NewEgressRegistry([]EgressPolicyDefinition{drifted}); registry != nil ||
		!errors.Is(err, ErrEgressRegistryRejected) {
		t.Fatalf("content-address drift registry = %#v, %v", registry, err)
	}
}

func writeEgressManifest(t *testing.T, definitions []EgressPolicyDefinition) string {
	t.Helper()
	encoded, err := json.Marshal(egressManifestDocument{SchemaVersion: EgressRegistrySchemaVersion, Policies: definitions})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "egress.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
