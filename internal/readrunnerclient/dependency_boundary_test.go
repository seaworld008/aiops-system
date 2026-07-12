package readrunnerclient_test

import (
	"os/exec"
	"strings"
	"testing"
)

// This is a build-graph gate, not a source-text convention: future READ
// Runner assembly must not acquire mutation code transitively through a helper
// package that looks harmless at the direct import boundary.
func TestProductionDependencyGraphContainsNoWriteOrMutationPackages(t *testing.T) {
	command := exec.Command("go", "list", "-deps", ".")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list -deps . failed: %v", err)
	}
	dependencies := strings.Fields(string(output))
	for _, forbidden := range []string{
		"github.com/seaworld008/aiops-system/internal/action",
		"github.com/seaworld008/aiops-system/internal/execution",
		"github.com/seaworld008/aiops-system/internal/credential",
		"github.com/seaworld008/aiops-system/internal/credentialadmin",
		"github.com/seaworld008/aiops-system/internal/isolatedexec",
		"github.com/seaworld008/aiops-system/internal/executoripc",
		"github.com/seaworld008/aiops-system/internal/connectors/kubernetes",
		"github.com/seaworld008/aiops-system/internal/connectors/awx",
	} {
		for _, dependency := range dependencies {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") {
				t.Fatalf("READ Runner client production graph contains forbidden dependency %q", dependency)
			}
		}
	}
}
