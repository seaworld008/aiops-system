package investigationworkflow_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/outbox"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

func TestTemporalDevServerTerminateAllowsOnlyInflightAttemptAndStartsNoRetry(t *testing.T) {
	if os.Getenv("AIOPS_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("set AIOPS_TEMPORAL_INTEGRATION=1 to run the pinned Temporal dev-server contract")
	}
	if version := os.Getenv("AIOPS_TEMPORAL_CLI_VERSION"); version != "1.6.1" {
		t.Fatalf("AIOPS_TEMPORAL_CLI_VERSION = %q, want pinned 1.6.1", version)
	}
	address := os.Getenv("AIOPS_TEMPORAL_ADDRESS")
	if address == "" {
		t.Fatal("AIOPS_TEMPORAL_ADDRESS is required when integration is enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	temporalRuntimeClient, err := investigationworkflow.DialTemporalClient(ctx, client.Options{HostPort: address, Namespace: "default"})
	if err != nil {
		t.Fatalf("DialTemporalClient() error = %v", err)
	}
	defer temporalRuntimeClient.Close()
	temporalClient := investigationworkflow.SDKClientForTest(temporalRuntimeClient)
	if temporalClient == nil {
		t.Fatal("DialTemporalClient() returned no sealed SDK client")
	}
	fixture := newActivityFixture(t, "firing")
	gate := &inflightCreateGateRepository{
		Repository: fixture.repository, entered: make(chan struct{}), release: make(chan struct{}),
	}
	activities, err := investigationworkflow.NewActivities(fixture.repository, gate, fixture.authority, fixture.planner)
	if err != nil {
		t.Fatalf("NewActivities() error = %v", err)
	}
	runtimeWorker, err := investigationworkflow.NewWorker(
		temporalRuntimeClient, activities, fixture.input.ManifestDigest, fixture.input.RegistryDigest,
	)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	if err := runtimeWorker.Start(); err != nil {
		t.Fatalf("worker.Start() error = %v", err)
	}
	defer runtimeWorker.Stop()
	starter, err := investigationworkflow.NewStarter(temporalRuntimeClient, fixture.input.ManifestDigest, fixture.input.RegistryDigest)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	workflowID := uuid.NewString()
	start := outbox.SignalWorkflowStart{
		Version: 1, WorkflowID: workflowID, OutboxEventID: workflowID,
		TenantID: fixture.input.TenantID, WorkspaceID: fixture.input.WorkspaceID,
		SignalID: fixture.input.SignalID, AggregateVersion: 1,
	}
	if outcome, err := starter.Start(ctx, start); err != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("Start() = %s, %v", outcome, err)
	}
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatalf("waiting for in-flight create boundary: %v", ctx.Err())
	}
	described, err := temporalClient.DescribeWorkflowExecution(ctx, workflowID, "")
	if err != nil || described.WorkflowExecutionInfo == nil || described.WorkflowExecutionInfo.Execution == nil {
		t.Fatalf("DescribeWorkflowExecution() = %#v, %v", described, err)
	}
	runID := described.WorkflowExecutionInfo.Execution.RunId
	if err := temporalClient.TerminateWorkflow(ctx, workflowID, runID, "operator-inflight-attempt-gate"); err != nil {
		t.Fatalf("TerminateWorkflow(exact run) error = %v", err)
	}
	close(gate.release)
	waitForWorkflowStatus(t, ctx, temporalClient, workflowID, runID, enumspb.WORKFLOW_EXECUTION_STATUS_TERMINATED)

	deadline := time.NewTimer(2500 * time.Millisecond)
	defer deadline.Stop()
	select {
	case <-deadline.C:
	case <-ctx.Done():
		t.Fatalf("waiting for retry silence: %v", ctx.Err())
	}
	if attempts := gate.attempts.Load(); attempts != 1 {
		t.Fatalf("create attempts after Terminate = %d, want only the in-flight attempt", attempts)
	}
	investigations, err := fixture.repository.ListInvestigations(context.Background(), investigation.ListInvestigationsRequest{
		WorkspaceID: fixture.input.WorkspaceID,
	})
	if err != nil || len(investigations) != 1 {
		t.Fatalf("in-flight durable facts = %#v, %v; current attempt may commit exactly once", investigations, err)
	}
}

func TestTemporalDevServerCancelCannotInterruptPreparationButExactRunTerminateCan(t *testing.T) {
	if os.Getenv("AIOPS_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("set AIOPS_TEMPORAL_INTEGRATION=1 to run the pinned Temporal dev-server contract")
	}
	if version := os.Getenv("AIOPS_TEMPORAL_CLI_VERSION"); version != "1.6.1" {
		t.Fatalf("AIOPS_TEMPORAL_CLI_VERSION = %q, want pinned 1.6.1", version)
	}
	address := os.Getenv("AIOPS_TEMPORAL_ADDRESS")
	if address == "" {
		t.Fatal("AIOPS_TEMPORAL_ADDRESS is required when integration is enabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	temporalRuntimeClient, err := investigationworkflow.DialTemporalClient(ctx, client.Options{HostPort: address, Namespace: "default"})
	if err != nil {
		t.Fatalf("DialTemporalClient() error = %v", err)
	}
	defer temporalRuntimeClient.Close()
	temporalClient := investigationworkflow.SDKClientForTest(temporalRuntimeClient)
	if temporalClient == nil {
		t.Fatal("DialTemporalClient() returned no sealed SDK client")
	}

	const canary = "termination-history-secret-canary"
	fixture := newActivityFixture(t, "firing")
	reader := &switchableSignalReader{canary: canary, delegate: fixture.repository}
	activities, err := investigationworkflow.NewActivities(
		reader, fixture.repository, fixture.authority, fixture.planner,
	)
	if err != nil {
		t.Fatalf("NewActivities() error = %v", err)
	}
	runtimeWorker, err := investigationworkflow.NewWorker(
		temporalRuntimeClient, activities, fixture.input.ManifestDigest, fixture.input.RegistryDigest,
	)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	if err := runtimeWorker.Start(); err != nil {
		t.Fatalf("worker.Start() error = %v", err)
	}
	defer runtimeWorker.Stop()
	starter, err := investigationworkflow.NewStarter(temporalRuntimeClient, fixture.input.ManifestDigest, fixture.input.RegistryDigest)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	workflowID := uuid.NewString()
	start := outbox.SignalWorkflowStart{
		Version: 1, WorkflowID: workflowID, OutboxEventID: workflowID,
		TenantID: fixture.input.TenantID, WorkspaceID: fixture.input.WorkspaceID,
		SignalID: fixture.input.SignalID, AggregateVersion: 1,
	}
	if outcome, err := starter.Start(ctx, start); err != nil || outcome != outbox.StartOutcomeStarted {
		t.Fatalf("Start() = %s, %v", outcome, err)
	}
	described, err := temporalClient.DescribeWorkflowExecution(ctx, workflowID, "")
	if err != nil || described.WorkflowExecutionInfo == nil || described.WorkflowExecutionInfo.Execution == nil {
		t.Fatalf("DescribeWorkflowExecution() = %#v, %v", described, err)
	}
	runID := described.WorkflowExecutionInfo.Execution.RunId
	if runID == "" {
		t.Fatal("Temporal run ID is empty")
	}

	waitForSignalReaderAttempts(t, ctx, reader, 1)
	if err := temporalClient.CancelWorkflow(ctx, workflowID, runID); err != nil {
		t.Fatalf("CancelWorkflow(exact run) error = %v", err)
	}
	// The disconnected PREPARE critical section must continue retrying even
	// after Temporal records an ordinary cancellation request.
	beforeCancelRetry := reader.attempts.Load()
	waitForSignalReaderAttempts(t, ctx, reader, beforeCancelRetry+1)
	described, err = temporalClient.DescribeWorkflowExecution(ctx, workflowID, runID)
	if err != nil || described.WorkflowExecutionInfo == nil {
		t.Fatalf("DescribeWorkflowExecution(after cancel) = %#v, %v", described, err)
	}
	if status := described.WorkflowExecutionInfo.Status; status != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
		t.Fatalf("workflow status after Cancel = %s, want RUNNING", status)
	}

	if err := temporalClient.TerminateWorkflow(ctx, workflowID, runID, "operator-emergency-stop"); err != nil {
		t.Fatalf("TerminateWorkflow(exact run) error = %v", err)
	}
	waitForWorkflowStatus(t, ctx, temporalClient, workflowID, runID, enumspb.WORKFLOW_EXECUTION_STATUS_TERMINATED)

	originalHistory := readCompleteHistory(t, ctx, temporalClient, workflowID, runID)
	var cancelRequested, terminated, canceled bool
	var resetEventID int64
	for _, event := range originalHistory.Events {
		switch event.GetEventType() {
		case enumspb.EVENT_TYPE_WORKFLOW_TASK_COMPLETED:
			if resetEventID == 0 {
				resetEventID = event.GetEventId()
			}
		case enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_CANCEL_REQUESTED:
			cancelRequested = true
		case enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_TERMINATED:
			terminated = true
		case enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_CANCELED:
			canceled = true
		}
	}
	if !cancelRequested || !terminated || canceled {
		t.Fatalf("History terminal events: cancel_requested=%t terminated=%t canceled=%t", cancelRequested, terminated, canceled)
	}
	if resetEventID == 0 {
		t.Fatal("original History has no WORKFLOW_TASK_COMPLETED reset point")
	}
	if material := strings.ToLower(historyMaterial(t, originalHistory)); strings.Contains(material, strings.ToLower(canary)) {
		t.Fatalf("Temporal History contains dependency canary %q", canary)
	}

	// Terminate is the emergency stop. Once the dependency has recovered, an
	// operator can reset the exact terminated run to a known Workflow Task
	// boundary and let the durable preparation complete in a new run.
	reader.available.Store(true)
	reset, err := temporalClient.ResetWorkflowExecution(ctx, &workflowservicepb.ResetWorkflowExecutionRequest{
		Namespace: "default",
		WorkflowExecution: &commonpb.WorkflowExecution{
			WorkflowId: workflowID,
			RunId:      runID,
		},
		Reason:                    "operator-recovery-reset",
		WorkflowTaskFinishEventId: resetEventID,
		RequestId:                 uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("ResetWorkflowExecution(exact terminated run) error = %v", err)
	}
	resetRunID := reset.GetRunId()
	if resetRunID == "" || resetRunID == runID {
		t.Fatalf("ResetWorkflowExecution() run ID = %q, original = %q", resetRunID, runID)
	}
	var receipt investigationworkflow.PreparationReceipt
	if err := temporalClient.GetWorkflow(ctx, workflowID, resetRunID).Get(ctx, &receipt); err != nil {
		t.Fatalf("GetWorkflow(reset run).Get() error = %v", err)
	}
	if receipt.State != investigationworkflow.StatePrepared || receipt.OutboxEventID != workflowID {
		t.Fatalf("reset Workflow receipt = %#v", receipt)
	}
	waitForWorkflowStatus(t, ctx, temporalClient, workflowID, resetRunID, enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED)
	described, err = temporalClient.DescribeWorkflowExecution(ctx, workflowID, resetRunID)
	if err != nil || described.WorkflowExecutionInfo == nil || described.WorkflowExecutionInfo.Execution == nil {
		t.Fatalf("DescribeWorkflowExecution(reset run) = %#v, %v", described, err)
	}
	resetInfo := described.WorkflowExecutionInfo
	if resetInfo.Execution.WorkflowId != workflowID || resetInfo.Execution.RunId != resetRunID ||
		resetInfo.RootExecution == nil || resetInfo.RootExecution.WorkflowId != workflowID ||
		resetInfo.RootExecution.RunId != resetRunID || resetInfo.FirstRunId != runID ||
		resetInfo.ParentExecution != nil || resetInfo.ParentNamespaceId != "" {
		t.Fatalf(
			"reset lineage: execution=%#v root=%#v first=%q parent=%#v parent_namespace=%q",
			resetInfo.Execution, resetInfo.RootExecution, resetInfo.FirstRunId,
			resetInfo.ParentExecution, resetInfo.ParentNamespaceId,
		)
	}
	// An ACK-lost redelivery after emergency recovery must still resolve to the
	// same safe Workflow identity instead of attempting a second preparation.
	if outcome, err := starter.Start(ctx, start); err != nil || outcome != outbox.StartOutcomeAlreadyExists {
		t.Fatalf("Start(after reset) = %s, %v", outcome, err)
	}
	resetHistory := readCompleteHistory(t, ctx, temporalClient, workflowID, resetRunID)
	if material := strings.ToLower(historyMaterial(t, resetHistory)); strings.Contains(material, strings.ToLower(canary)) {
		t.Fatalf("reset Temporal History contains dependency canary %q", canary)
	}
}

type switchableSignalReader struct {
	canary    string
	delegate  investigation.SignalRegistrationReader
	attempts  atomic.Int64
	available atomic.Bool
}

type inflightCreateGateRepository struct {
	investigation.Repository
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	attempts atomic.Int64
}

func (repository *inflightCreateGateRepository) CreateOrGetInvestigation(
	_ context.Context,
	request investigation.CreateOrGetInvestigationRequest,
) (investigation.CreateOrGetInvestigationResult, error) {
	repository.attempts.Add(1)
	repository.once.Do(func() { close(repository.entered) })
	<-repository.release
	return repository.Repository.CreateOrGetInvestigation(context.Background(), request)
}

func (reader *switchableSignalReader) GetRegisteredSignal(ctx context.Context, signalID string) (investigation.RegisteredSignal, error) {
	reader.attempts.Add(1)
	if reader.available.Load() {
		return reader.delegate.GetRegisteredSignal(ctx, signalID)
	}
	return investigation.RegisteredSignal{}, errors.New(reader.canary)
}

func waitForSignalReaderAttempts(t *testing.T, ctx context.Context, reader *switchableSignalReader, want int64) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if got := reader.attempts.Load(); got >= want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for signal-reader attempts >= %d: got %d: %v", want, reader.attempts.Load(), ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForWorkflowStatus(
	t *testing.T,
	ctx context.Context,
	temporalClient client.Client,
	workflowID string,
	runID string,
	want enumspb.WorkflowExecutionStatus,
) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		described, err := temporalClient.DescribeWorkflowExecution(ctx, workflowID, runID)
		if err == nil && described.WorkflowExecutionInfo != nil && described.WorkflowExecutionInfo.Status == want {
			return
		}
		select {
		case <-ctx.Done():
			if err != nil {
				t.Fatalf("waiting for workflow status %s: %v: %v", want, err, ctx.Err())
			}
			if described == nil || described.WorkflowExecutionInfo == nil {
				t.Fatalf("waiting for workflow status %s: missing execution info: %v", want, ctx.Err())
			}
			t.Fatalf("waiting for workflow status %s: got %s: %v", want, described.WorkflowExecutionInfo.Status, ctx.Err())
		case <-ticker.C:
		}
	}
}
