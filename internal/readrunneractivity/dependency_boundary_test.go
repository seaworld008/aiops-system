package readrunneractivity_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReadRunnerActivityDependencyGraphExcludesMutationAndCommandPackages(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}
	dependencies := "\n" + string(output) + "\n"
	for _, forbidden := range []string{
		"github.com/seaworld008/aiops-system/internal/action",
		"github.com/seaworld008/aiops-system/internal/runnerclient",
		"github.com/seaworld008/aiops-system/internal/execution",
		"github.com/seaworld008/aiops-system/internal/credential",
		"github.com/seaworld008/aiops-system/internal/isolatedexec",
		"github.com/seaworld008/aiops-system/internal/executoripc",
		"github.com/seaworld008/aiops-system/internal/store/postgres",
		"github.com/seaworld008/aiops-system/internal/investigation/postgres",
		"github.com/seaworld008/aiops-system/internal/httpapi",
		"github.com/seaworld008/aiops-system/internal/connectors/kubernetes",
		"github.com/seaworld008/aiops-system/internal/connectors/awx",
		"github.com/seaworld008/aiops-system/cmd/write-runner",
		"os/exec",
		"k8s.io/",
		"awx",
	} {
		found := strings.Contains(dependencies, "\n"+forbidden+"\n") ||
			strings.Contains(dependencies, "\n"+forbidden+"/")
		if strings.HasSuffix(forbidden, "/") || forbidden == "awx" {
			found = strings.Contains(strings.ToLower(dependencies), strings.ToLower(forbidden))
		}
		if found {
			t.Fatalf("READ Activity dependency graph contains forbidden package %q", forbidden)
		}
	}
}
