package investigationworkflow

import (
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
)

const (
	prepareActivityStartToCloseTimeoutV2  = 30 * time.Second
	recoveryActivityStartToCloseTimeoutV1 = 30 * time.Second
)

func readWorkflowV2ForNamespace(
	ctx workflow.Context,
	input WorkflowInputV2,
	namespace string,
) (WorkflowResultV2, error) {
	if input.Validate() != nil {
		return WorkflowResultV2{}, runtimeV2NonRetryableError(
			"READ_WORKFLOW_INPUT_INVALID", ErrInvalidRuntimeV2Input.Error(),
		)
	}
	controlQueue, err := ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, input.BundleDigest)
	expectedIdentity, identityErr := canonicalWorkflowInputV2Payload(input)
	if err != nil || identityErr != nil || !ValidTemporalNamespace(namespace) ||
		!validRuntimeV2WorkflowInfo(workflow.GetInfo(ctx), input, controlQueue, expectedIdentity, namespace) {
		return WorkflowResultV2{}, runtimeV2NonRetryableError(
			"READ_WORKFLOW_EXECUTION_MISMATCH", "investigation READ workflow execution rejected",
		)
	}

	prepareContext, _ := workflow.NewDisconnectedContext(ctx)
	prepareContext = workflow.WithActivityOptions(
		prepareContext,
		prepareActivityOptionsV2(controlQueue, input.OutboxEventID),
	)
	var prepared PreparationReceiptV2
	if err := workflow.ExecuteActivity(prepareContext, PrepareActivityNameV2, input).Get(prepareContext, &prepared); err != nil {
		return WorkflowResultV2{}, err
	}
	if prepared.ValidateAgainst(input) != nil {
		return WorkflowResultV2{}, runtimeV2NonRetryableError(
			"READ_PREPARE_RESULT_INVALID", "investigation READ preparation result rejected",
		)
	}
	base := WorkflowResultV2{
		Version: RuntimeV2SchemaVersion, OutboxEventID: input.OutboxEventID,
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, SignalID: input.SignalID,
		ManifestDigest: prepared.ManifestDigest, RegistryDigest: prepared.RegistryDigest,
		BundleDigest:  prepared.BundleDigest,
		ProfileDigest: prepared.ProfileDigest, TasksHash: prepared.TasksHash,
	}
	if prepared.State == StateNoActiveIncident {
		base.State = RuntimeStateNoActiveIncident
		if base.ValidateAgainst(input) != nil {
			return WorkflowResultV2{}, runtimeV2NonRetryableError(
				"READ_WORKFLOW_RESULT_INVALID", ErrInvalidRuntimeV2Result.Error(),
			)
		}
		if ctx.Err() != nil {
			return WorkflowResultV2{}, ctx.Err()
		}
		return base, nil
	}

	base.IncidentID = prepared.IncidentID
	base.InvestigationID = prepared.InvestigationID
	base.Tasks = make([]TerminalReadTaskV2, 0, len(prepared.Tasks))
	orchestrationContext, _ := workflow.NewDisconnectedContext(ctx)
	for _, reference := range prepared.Tasks {
		terminal, err := orchestrateReadTaskV2(orchestrationContext, prepared, reference)
		if err != nil {
			return WorkflowResultV2{}, err
		}
		base.Tasks = append(base.Tasks, terminal)
	}
	base.State = RuntimeStateReadTasksTerminal
	if base.ValidateAgainst(input) != nil {
		return WorkflowResultV2{}, runtimeV2NonRetryableError(
			"READ_WORKFLOW_RESULT_INVALID", ErrInvalidRuntimeV2Result.Error(),
		)
	}
	if ctx.Err() != nil {
		return WorkflowResultV2{}, ctx.Err()
	}
	return base, nil
}

func (activities *RuntimeV2Activities) readWorkflowV2(
	ctx workflow.Context,
	input WorkflowInputV2,
) (WorkflowResultV2, error) {
	if activities == nil || !ValidTemporalNamespace(activities.namespace) {
		return WorkflowResultV2{}, runtimeV2NonRetryableError(
			"READ_WORKFLOW_EXECUTION_MISMATCH", "investigation READ workflow execution rejected",
		)
	}
	return readWorkflowV2ForNamespace(ctx, input, activities.namespace)
}

func orchestrateReadTaskV2(
	ctx workflow.Context,
	prepared PreparationReceiptV2,
	reference ReadTaskReferenceV2,
) (TerminalReadTaskV2, error) {
	for round := 1; round <= MaximumReadTaskRounds; round++ {
		input := readTaskActivityInput(prepared, reference, round)
		if input.Validate() != nil {
			return TerminalReadTaskV2{}, runtimeV2NonRetryableError(
				"READ_TASK_INPUT_INVALID", ErrInvalidRuntimeV2Input.Error(),
			)
		}
		queue, err := RunnerTaskQueue(
			input.EnvironmentID, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
		)
		if err != nil {
			return TerminalReadTaskV2{}, runtimeV2NonRetryableError(
				"READ_TASK_INPUT_INVALID", ErrInvalidRuntimeV2Input.Error(),
			)
		}
		activityID, err := ReadTaskActivityID(round, input.Position, input.TaskID)
		if err != nil {
			return TerminalReadTaskV2{}, runtimeV2NonRetryableError(
				"READ_TASK_INPUT_INVALID", ErrInvalidRuntimeV2Input.Error(),
			)
		}
		runnerContext := workflow.WithActivityOptions(ctx, runnerActivityOptionsV1(queue, activityID))
		var runnerOutput ReadTaskActivityOutputV1
		runnerErr := workflow.ExecuteActivity(runnerContext, ExecuteActivityNameV1, input).Get(runnerContext, &runnerOutput)
		runnerOutputValid := runnerErr == nil && runnerOutput.ValidateAgainst(input) == nil

		cleanupContext, _ := workflow.NewDisconnectedContext(ctx)
		firstRecovery, err := executeRecoveryV1(cleanupContext, input, round, 1)
		if err != nil {
			return TerminalReadTaskV2{}, err
		}
		if firstRecovery.State != readtask.RecoveryPending {
			terminal, err := terminalReadTask(firstRecovery)
			if err != nil {
				return TerminalReadTaskV2{}, runtimeV2NonRetryableError(
					"READ_RESULT_RECOVERY_RESULT_INVALID", ErrInvalidRecoveryResult.Error(),
				)
			}
			return terminal, nil
		}
		if runnerOutputValid && runnerOutput.State == ReadTaskActivityCompleteAcknowledged {
			return TerminalReadTaskV2{}, runtimeV2NonRetryableError(
				"READ_TASK_ACK_PENDING", "investigation READ completion acknowledgement conflicts with durable recovery",
			)
		}
		if err := workflow.NewTimer(cleanupContext, ReadTaskRecoveryWait).Get(cleanupContext, nil); err != nil {
			return TerminalReadTaskV2{}, err
		}
		secondRecovery, err := executeRecoveryV1(cleanupContext, input, round, 2)
		if err != nil {
			return TerminalReadTaskV2{}, err
		}
		if secondRecovery.State != readtask.RecoveryPending {
			terminal, err := terminalReadTask(secondRecovery)
			if err != nil {
				return TerminalReadTaskV2{}, runtimeV2NonRetryableError(
					"READ_RESULT_RECOVERY_RESULT_INVALID", ErrInvalidRecoveryResult.Error(),
				)
			}
			return terminal, nil
		}
	}
	// This fixed, non-retryable failure is the durable manual-reconciliation
	// handoff after the bounded three-round budget. It deliberately leaves the
	// PostgreSQL Task unchanged and must be monitored by C2-4c before claims can
	// ever open; a pending Task is never forged into FAILED or CANCELLED.
	return TerminalReadTaskV2{}, runtimeV2NonRetryableError(ReadTaskPendingErrorType, ErrReadTaskPending.Error())
}

func executeRecoveryV1(
	ctx workflow.Context,
	input ReadTaskActivityInputV1,
	round int,
	check int,
) (RecoveryActivityOutput, error) {
	activityID, err := RecoveryActivityID(round, check, input.Position, input.TaskID)
	if err != nil {
		return RecoveryActivityOutput{}, runtimeV2NonRetryableError(
			"READ_RESULT_RECOVERY_INPUT_INVALID", ErrInvalidRecoveryInput.Error(),
		)
	}
	queue, err := ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, input.BundleDigest)
	if err != nil {
		return RecoveryActivityOutput{}, runtimeV2NonRetryableError(
			"READ_RESULT_RECOVERY_INPUT_INVALID", ErrInvalidRecoveryInput.Error(),
		)
	}
	recoveryContext := workflow.WithActivityOptions(ctx, recoveryActivityOptionsV1(queue, activityID))
	recoveryInput := recoveryInputFromReadTask(input)
	var output RecoveryActivityOutput
	if err := workflow.ExecuteActivity(recoveryContext, RecoveryActivityNameV1, recoveryInput).Get(recoveryContext, &output); err != nil {
		return RecoveryActivityOutput{}, err
	}
	if output.validateAgainst(recoveryInput) != nil {
		return RecoveryActivityOutput{}, runtimeV2NonRetryableError(
			"READ_RESULT_RECOVERY_RESULT_INVALID", ErrInvalidRecoveryResult.Error(),
		)
	}
	return output, nil
}

func prepareActivityOptionsV2(queue, outboxEventID string) workflow.ActivityOptions {
	return workflow.ActivityOptions{
		TaskQueue: queue, ActivityID: "prepare-v2-" + outboxEventID,
		StartToCloseTimeout: prepareActivityStartToCloseTimeoutV2,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: time.Second, BackoffCoefficient: 2,
			MaximumInterval: 15 * time.Second, MaximumAttempts: 0,
			NonRetryableErrorTypes: prepareNonRetryableTypesV2(),
		},
		WaitForCancellation: true, DisableEagerExecution: true,
	}
}

func runnerActivityOptionsV1(queue, activityID string) workflow.ActivityOptions {
	return workflow.ActivityOptions{
		TaskQueue: queue, ActivityID: activityID,
		ScheduleToCloseTimeout: RunnerActivityScheduleToCloseTimeout,
		StartToCloseTimeout:    RunnerActivityStartToCloseTimeout,
		HeartbeatTimeout:       RunnerActivityHeartbeatTimeout,
		RetryPolicy:            &temporal.RetryPolicy{MaximumAttempts: 1},
		WaitForCancellation:    true, DisableEagerExecution: true,
	}
}

func recoveryActivityOptionsV1(queue, activityID string) workflow.ActivityOptions {
	return workflow.ActivityOptions{
		TaskQueue: queue, ActivityID: activityID,
		StartToCloseTimeout: recoveryActivityStartToCloseTimeoutV1,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: time.Second, BackoffCoefficient: 2,
			MaximumInterval: 15 * time.Second, MaximumAttempts: 0,
			NonRetryableErrorTypes: recoveryNonRetryableTypesV1(),
		},
		WaitForCancellation: true, DisableEagerExecution: true,
	}
}

func validRuntimeV2WorkflowInfo(
	info *workflow.Info,
	input WorkflowInputV2,
	queue string,
	expectedIdentity *commonpb.Payload,
	namespace string,
) bool {
	return info != nil && info.WorkflowExecution.ID == input.OutboxEventID &&
		ValidTemporalRunID(info.WorkflowExecution.RunID) && ValidTemporalNamespace(namespace) &&
		info.Namespace == namespace && info.WorkflowType.Name == WorkflowNameV2 &&
		info.TaskQueueName == queue && info.WorkflowExecutionTimeout == 0 && info.WorkflowRunTimeout == 0 &&
		info.WorkflowTaskTimeout == 10*time.Second && info.Attempt == 1 && info.RetryPolicy == nil &&
		info.CronSchedule == "" && info.ContinuedExecutionRunID == "" && info.ParentWorkflowNamespace == "" &&
		info.ParentWorkflowExecution == nil && info.RootWorkflowExecution == nil && expectedIdentity != nil &&
		info.Memo != nil && len(info.Memo.Fields) == 1 && info.Memo.Fields[RuntimeMemoIdentityKeyV2] != nil &&
		proto.Size(info.Memo.Fields[RuntimeMemoIdentityKeyV2]) <= maximumHistoryDTOBytes &&
		proto.Equal(info.Memo.Fields[RuntimeMemoIdentityKeyV2], expectedIdentity) &&
		(info.SearchAttributes == nil || len(info.SearchAttributes.IndexedFields) == 0) &&
		info.Priority.PriorityKey == 0 && info.Priority.FairnessKey == "" && info.Priority.FairnessWeight == 0
}

func runtimeV2NonRetryableError(errorType, message string) error {
	return temporal.NewNonRetryableApplicationError(message, errorType, nil)
}
