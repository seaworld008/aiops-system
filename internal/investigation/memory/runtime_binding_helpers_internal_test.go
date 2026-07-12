package memory

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func boundCreateRequest(t *testing.T, request investigation.CreateOrGetInvestigationRequest) investigation.CreateOrGetInvestigationRequest {
	t.Helper()
	if !request.PlanBinding.IsZero() {
		return request
	}
	_, tasksHash, err := investigation.CanonicalTaskSpecs(request.Tasks)
	if err != nil {
		tasksHash = strings.Repeat("0", 64)
	}
	request.PlanBinding = domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: strings.Repeat("1", 64),
		RegistryDigest: strings.Repeat("2", 64),
		ProfileDigest:  strings.Repeat("3", 64),
		TasksHash:      tasksHash,
	}
	return request
}

func testTaskRuntimeBinder(
	_ context.Context,
	_ investigation.TaskSpecScope,
	_ domain.InvestigationPlanBinding,
	spec investigation.TaskSpec,
) (investigation.TaskRuntimeComponents, error) {
	separator := strings.LastIndex(spec.ConnectorID, "-v1-")
	if separator < 1 || separator+4 >= len(spec.ConnectorID) {
		return investigation.TaskRuntimeComponents{}, fmt.Errorf("connector is not content addressed")
	}
	connectorDigest := spec.ConnectorID[separator+4:]
	if !domain.ValidSHA256Hex(connectorDigest) {
		return investigation.TaskRuntimeComponents{}, fmt.Errorf("connector digest is invalid")
	}
	return investigation.TaskRuntimeComponents{
		ConnectorDigest: connectorDigest,
		TargetDigest:    strings.Repeat("d", 64),
		ExecutorDigest:  strings.Repeat("e", 64),
	}, nil
}
