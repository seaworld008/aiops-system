package readassembly_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSnapshotDependencyGraphExcludesMutationCredentialAndCommandCapabilities(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}
	dependencies := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, dependency := range dependencies {
		for _, forbidden := range []string{
			"os/exec",
			"github.com/seaworld008/aiops-system/internal/action",
			"github.com/seaworld008/aiops-system/internal/execution",
			"github.com/seaworld008/aiops-system/internal/credential",
			"github.com/seaworld008/aiops-system/internal/isolatedexec",
			"github.com/seaworld008/aiops-system/internal/executoripc",
			"github.com/seaworld008/aiops-system/internal/connectors/kubernetes",
			"github.com/seaworld008/aiops-system/internal/connectors/awx",
			"github.com/seaworld008/aiops-system/cmd/write-runner",
			"github.com/seaworld008/aiops-system/cmd/executor",
		} {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") ||
				strings.HasPrefix(dependency, "k8s.io/") || strings.Contains(strings.ToLower(dependency), "awx") {
				t.Fatalf("READ Snapshot production graph contains forbidden dependency %q", dependency)
			}
		}
	}
}
