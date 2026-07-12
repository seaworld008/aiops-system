package investigationworkflow_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
)

func TestRuntimeV2QueuesBindFullImmutableIdentity(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	control, err := investigationworkflow.ControlTaskQueue(
		input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil || !strings.Contains(control, input.ManifestDigest) ||
		!strings.Contains(control, input.RegistryDigest) || !strings.Contains(control, input.BundleDigest) ||
		len(control) > 255 {
		t.Fatalf("ControlTaskQueue() = %q, %v", control, err)
	}
	runner, err := investigationworkflow.RunnerTaskQueue(runtimeV2Environment, input.BundleDigest)
	if err != nil || !strings.Contains(runner, runtimeV2Environment) ||
		!strings.Contains(runner, input.BundleDigest) || strings.Contains(runner, input.ManifestDigest) ||
		strings.Contains(runner, input.RegistryDigest) || len(runner) > 255 ||
		!strings.HasPrefix(runner, "aiops-investigation-read-task-v1-") {
		t.Fatalf("RunnerTaskQueue() = %q, %v", runner, err)
	}
	if _, err := investigationworkflow.ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, ""); !errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("ControlTaskQueue(missing Bundle) error = %v", err)
	}
	if _, err := investigationworkflow.RunnerTaskQueue(runtimeV2Environment, strings.Repeat("A", 64)); !errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("RunnerTaskQueue(uppercase Bundle) error = %v", err)
	}
}

func TestRuntimeV2DurableProtocolNamesAreFixedBeforeFirstRelease(t *testing.T) {
	if investigationworkflow.RecoveryActivityNameV1 != "aiops.investigation.read-result.recover.activity.v1" ||
		investigationworkflow.ExecuteActivityNameV1 != "aiops.investigation.read-task.execute.activity.v1" {
		t.Fatalf("durable Activity names = %q / %q",
			investigationworkflow.RecoveryActivityNameV1, investigationworkflow.ExecuteActivityNameV1)
	}
}

func TestRuntimeV2HistoryDTOsUseStrictBoundedExactJSON(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	prepared := validRuntimeV2PreparationReceipt()
	readInput := investigationworkflow.ReadTaskActivityInputV1{
		Version:       investigationworkflow.ReadTaskActivitySchemaVersion,
		OutboxEventID: input.OutboxEventID, TenantID: input.TenantID, WorkspaceID: input.WorkspaceID,
		EnvironmentID: prepared.EnvironmentID, ServiceID: prepared.ServiceID,
		IncidentID: prepared.IncidentID, InvestigationID: prepared.InvestigationID,
		TaskID: prepared.Tasks[0].TaskID, Position: 1, Round: 1,
		ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
		BundleDigest: input.BundleDigest, ProfileDigest: prepared.ProfileDigest, TasksHash: prepared.TasksHash,
	}
	readOutput := investigationworkflow.ReadTaskActivityOutputV1{
		Version:         investigationworkflow.ReadTaskActivitySchemaVersion,
		State:           investigationworkflow.ReadTaskActivityRecoveryRequired,
		InvestigationID: readInput.InvestigationID, TaskID: readInput.TaskID, Position: 1, Round: 1,
	}
	result := investigationworkflow.WorkflowResultV2{
		Version:       investigationworkflow.RuntimeV2SchemaVersion,
		State:         investigationworkflow.RuntimeStateReadTasksTerminal,
		OutboxEventID: input.OutboxEventID, TenantID: input.TenantID,
		WorkspaceID: input.WorkspaceID, SignalID: input.SignalID,
		IncidentID: prepared.IncidentID, InvestigationID: prepared.InvestigationID,
		Tasks: []investigationworkflow.TerminalReadTaskV2{{
			TaskID: readInput.TaskID, Position: 1, TaskStatus: domain.ReadTaskFailed,
		}},
		ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
		BundleDigest: input.BundleDigest, ProfileDigest: prepared.ProfileDigest, TasksHash: prepared.TasksHash,
	}

	tests := []struct {
		name     string
		value    any
		newValue func() any
		sentinel error
	}{
		{"workflow input", input, func() any { return &investigationworkflow.WorkflowInputV2{} }, investigationworkflow.ErrInvalidRuntimeV2Input},
		{"preparation receipt", prepared, func() any { return &investigationworkflow.PreparationReceiptV2{} }, investigationworkflow.ErrInvalidRuntimeV2Result},
		{"read input", readInput, func() any { return &investigationworkflow.ReadTaskActivityInputV1{} }, investigationworkflow.ErrInvalidRuntimeV2Input},
		{"read output", readOutput, func() any { return &investigationworkflow.ReadTaskActivityOutputV1{} }, investigationworkflow.ErrInvalidRuntimeV2Result},
		{"workflow result", result, func() any { return &investigationworkflow.WorkflowResultV2{} }, investigationworkflow.ErrInvalidRuntimeV2Result},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.value)
			if err != nil || len(encoded) > 4096 {
				t.Fatalf("json.Marshal() = %d bytes, %v", len(encoded), err)
			}
			roundTrip := test.newValue()
			if err := json.Unmarshal(encoded, roundTrip); err != nil ||
				!reflect.DeepEqual(reflect.ValueOf(roundTrip).Elem().Interface(), test.value) {
				t.Fatalf("strict round trip = %#v, %v", roundTrip, err)
			}
			unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
			unknown = append(unknown, []byte(`,"unknown_canary":true}`)...)
			if err := json.Unmarshal(unknown, test.newValue()); !errors.Is(err, test.sentinel) {
				t.Fatalf("unknown field error = %v", err)
			}
			duplicate := append([]byte(nil), encoded[:len(encoded)-1]...)
			duplicate = append(duplicate, []byte(`,"version":1}`)...)
			if err := json.Unmarshal(duplicate, test.newValue()); !errors.Is(err, test.sentinel) {
				t.Fatalf("duplicate field error = %v", err)
			}
			caseAlias := append([]byte(nil), encoded[:len(encoded)-1]...)
			caseAlias = append(caseAlias, []byte(`,"Version":1}`)...)
			if err := json.Unmarshal(caseAlias, test.newValue()); !errors.Is(err, test.sentinel) {
				t.Fatalf("case-folded alias error = %v", err)
			}
			trailing := append(append([]byte(nil), encoded...), []byte(`{}`)...)
			if err := json.Unmarshal(trailing, test.newValue()); err == nil {
				t.Fatal("trailing JSON document was accepted")
			}
			oversized := append([]byte(nil), encoded[:len(encoded)-1]...)
			oversized = append(oversized, []byte(`,"oversized_canary":"`)...)
			oversized = append(oversized, bytes.Repeat([]byte{'x'}, 4097)...)
			oversized = append(oversized, []byte(`"}`)...)
			if err := json.Unmarshal(oversized, test.newValue()); !errors.Is(err, test.sentinel) {
				t.Fatalf("oversized DTO error = %v", err)
			}
		})
	}
	for name, value := range map[string]any{
		"workflow input": input, "preparation receipt": prepared,
		"read input": readInput, "workflow result": result,
	} {
		t.Run(name+" missing bundle", func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			delete(document, "bundle_digest")
			missing, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			var destination any
			switch name {
			case "workflow input":
				destination = &investigationworkflow.WorkflowInputV2{}
			case "preparation receipt":
				destination = &investigationworkflow.PreparationReceiptV2{}
			case "read input":
				destination = &investigationworkflow.ReadTaskActivityInputV1{}
			default:
				destination = &investigationworkflow.WorkflowResultV2{}
			}
			if err := json.Unmarshal(missing, destination); err == nil {
				t.Fatal("missing Bundle digest was accepted")
			}
		})
	}
}

func TestRuntimeV2CanonicalMemoBindsBundleAndRejectsNonCanonicalIdentity(t *testing.T) {
	input := validRuntimeV2WorkflowInput()
	first, err := investigationworkflow.CanonicalWorkflowInputV2PayloadForTest(input)
	if err != nil {
		t.Fatalf("CanonicalWorkflowInputV2PayloadForTest() error = %v", err)
	}
	second, err := investigationworkflow.CanonicalWorkflowInputV2PayloadForTest(input)
	if err != nil || !reflect.DeepEqual(first, second) || len(first.Data) > 4096 ||
		string(first.Metadata["encoding"]) != "json/plain" || len(first.Metadata) != 1 ||
		!bytes.Contains(first.Data, []byte(input.BundleDigest)) {
		t.Fatalf("canonical payload = %#v / %#v, %v", first, second, err)
	}
	var decoded investigationworkflow.WorkflowInputV2
	if err := json.Unmarshal(first.Data, &decoded); err != nil || !reflect.DeepEqual(decoded, input) {
		t.Fatalf("canonical payload decode = %#v, %v", decoded, err)
	}
}

func TestRuntimeV2ActivityIdentifiersBindRoundPositionAndTask(t *testing.T) {
	for round := 1; round <= investigationworkflow.MaximumReadTaskRounds; round++ {
		execute, err := investigationworkflow.ReadTaskActivityID(round, 1, runtimeV2TaskOne)
		if err != nil || execute != "read-execute-r"+string(rune('0'+round))+"-p1-"+runtimeV2TaskOne {
			t.Fatalf("ReadTaskActivityID(%d) = %q, %v", round, execute, err)
		}
		for check := 1; check <= 2; check++ {
			if recovery, err := investigationworkflow.RecoveryActivityID(round, check, 1, runtimeV2TaskOne); err != nil || !strings.Contains(recovery, "-r"+string(rune('0'+round))+"-c"+string(rune('0'+check))+"-p1-") {
				t.Fatalf("RecoveryActivityID(%d,%d) = %q, %v", round, check, recovery, err)
			}
		}
	}
}
