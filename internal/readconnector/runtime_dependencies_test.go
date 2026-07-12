package readconnector_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readconnector"
)

func TestRuntimeDependenciesAreDeterministicDetachedAndRedacted(t *testing.T) {
	registry, err := readconnector.New(validDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	baselineDigest := registry.Digest()
	dependencies, err := registry.RuntimeDependencies()
	if err != nil || len(dependencies) != 2 {
		t.Fatalf("RuntimeDependencies() = %#v, %v", dependencies, err)
	}
	first := dependencies[0]
	copy := first
	if copy.Scope() != first.Scope() || copy.ConnectorID() != first.ConnectorID() ||
		copy.TargetRef() != first.TargetRef() || copy.Kind() != first.Kind() ||
		copy.Operation() != first.Operation() || copy.ContractDigest() != first.ContractDigest() {
		t.Fatal("copy of detached RuntimeDependency changed its value")
	}
	scope := first.Scope()
	scope.TenantID = "10000000-0000-4000-8000-000000000099"
	slices.Reverse(dependencies)
	reloaded, err := registry.RuntimeDependencies()
	if err != nil || len(reloaded) != 2 || registry.Digest() != baselineDigest ||
		reloaded[0].Scope().TenantID == scope.TenantID {
		t.Fatal("caller mutation changed immutable registry dependencies")
	}
	encoded, err := json.Marshal(first)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(RuntimeDependency) = %s, %v", encoded, err)
	}
	rendered := fmt.Sprintf("%s %+v %#v", first, first, first)
	for _, forbidden := range []string{first.ConnectorID(), first.TargetRef(), first.Scope().TenantID} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("RuntimeDependency rendering leaked %q: %s", forbidden, rendered)
		}
	}
	var decoded readconnector.RuntimeDependency
	if err := json.Unmarshal(encoded, &decoded); err == nil {
		t.Fatal("RuntimeDependency accepted JSON reconstruction")
	}
}
