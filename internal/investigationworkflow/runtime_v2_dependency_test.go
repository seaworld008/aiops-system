package investigationworkflow_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestInvestigationWorkflowProductionDependencyGraphExcludesRunnerAndMutationCapabilities(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "./internal/investigationworkflow")
	command.Dir = "../.."
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list -deps investigationworkflow error = %v", err)
	}
	dependencies := strings.Split(strings.TrimSpace(string(output)), "\n")
	banned := []string{
		"github.com/seaworld008/aiops-system/internal/readrunnerclient",
		"github.com/seaworld008/aiops-system/internal/readrunneractivity",
		"github.com/seaworld008/aiops-system/internal/readexecutor",
		"github.com/seaworld008/aiops-system/internal/readruntime",
		"github.com/seaworld008/aiops-system/internal/readtarget",
		"github.com/seaworld008/aiops-system/internal/action",
		"github.com/seaworld008/aiops-system/internal/execution",
		"github.com/seaworld008/aiops-system/internal/credential",
		"github.com/seaworld008/aiops-system/internal/isolatedexec",
		"os/exec",
	}
	for _, dependency := range dependencies {
		for _, prefix := range banned {
			if dependency == prefix || strings.HasPrefix(dependency, prefix+"/") ||
				strings.HasPrefix(dependency, "k8s.io/") || strings.Contains(strings.ToLower(dependency), "awx") {
				t.Fatalf("control Workflow production dependency graph contains forbidden capability %q", dependency)
			}
		}
	}
}
