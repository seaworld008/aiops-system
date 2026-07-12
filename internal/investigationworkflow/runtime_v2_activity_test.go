package investigationworkflow_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestPrepareActivityV2ProjectsTrustedEnvironmentServiceAndConsecutiveTaskReferences(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	recovery, err := investigationworkflow.NewRecoveryActivities(recoveryReaderFunc(func(
		context.Context,
		readtask.RecoveryRequest,
	) (readtask.RecoveryResult, error) {
		return readtask.RecoveryResult{}, nil
	}))
	if err != nil {
		t.Fatalf("NewRecoveryActivities() error = %v", err)
	}
	bundleDigest := strings.Repeat("5", 64)
	activities, err := investigationworkflow.NewRuntimeV2Activities(fixture.activities, recovery, bundleDigest, "default")
	if err != nil {
		t.Fatalf("NewRuntimeV2Activities() error = %v", err)
	}
	input := investigationworkflow.WorkflowInputV2{
		Version:       investigationworkflow.RuntimeV2SchemaVersion,
		OutboxEventID: fixture.input.OutboxEventID, TenantID: fixture.input.TenantID,
		WorkspaceID: fixture.input.WorkspaceID, SignalID: fixture.input.SignalID,
		AggregateVersion: fixture.input.AggregateVersion,
		ManifestDigest:   fixture.input.ManifestDigest, RegistryDigest: fixture.input.RegistryDigest,
		BundleDigest: bundleDigest,
	}
	first, err := investigationworkflow.PrepareActivityV2ForTest(activities, context.Background(), input)
	if err != nil || first.State != investigationworkflow.StatePrepared ||
		first.EnvironmentID != activityEnvironmentID || first.ServiceID != activityServiceID ||
		first.BundleDigest != bundleDigest || len(first.Tasks) != 1 || first.Tasks[0].Position != 1 ||
		first.Tasks[0].TaskID == "" || first.ValidateAgainst(input) != nil {
		t.Fatalf("PrepareActivityV2ForTest() = %#v, %v", first, err)
	}
	replay, err := investigationworkflow.PrepareActivityV2ForTest(activities, context.Background(), input)
	if err != nil || !reflect.DeepEqual(replay, first) {
		t.Fatalf("PrepareActivityV2ForTest(replay) = %#v, %v; want %#v", replay, err, first)
	}
}
