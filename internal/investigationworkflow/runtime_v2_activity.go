package investigationworkflow

import (
	"context"
	"slices"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
)

// RuntimeV2Activities binds both trusted control-plane Activities to one
// immutable Bundle digest. Recovery v1 intentionally does not carry that new
// field, so its queue identity is checked against this sealed worker binding.
type RuntimeV2Activities struct {
	preparation  *Activities
	recovery     *RecoveryActivities
	bundleDigest string
	namespace    string
}

func NewRuntimeV2Activities(
	preparation *Activities,
	recovery *RecoveryActivities,
	bundleDigest string,
	namespace string,
) (*RuntimeV2Activities, error) {
	created := &RuntimeV2Activities{
		preparation: preparation, recovery: recovery, bundleDigest: bundleDigest, namespace: namespace,
	}
	if !created.ready() {
		return nil, ErrInvalidRuntimeV2Input
	}
	return created, nil
}

func (activities *RuntimeV2Activities) ready() bool {
	return activities != nil && activities.preparation.ready() && activities.recovery != nil &&
		!nilInterface(activities.recovery.reader) && domain.ValidSHA256Hex(activities.bundleDigest) &&
		ValidTemporalNamespace(activities.namespace)
}

func (activities *RuntimeV2Activities) prepareActivityV2(
	ctx context.Context,
	input WorkflowInputV2,
) (output PreparationReceiptV2, returnedErr error) {
	defer func() {
		if recover() != nil {
			output = PreparationReceiptV2{}
			returnedErr = retryableDependencyError()
		}
	}()
	if ctx == nil || input.Validate() != nil || !activities.ready() || input.BundleDigest != activities.bundleDigest {
		return PreparationReceiptV2{}, runtimeV2NonRetryableError(
			"PREPARE_INPUT_INVALID", ErrInvalidRuntimeV2Input.Error(),
		)
	}
	if err := ctx.Err(); err != nil {
		return PreparationReceiptV2{}, err
	}
	if !activity.IsActivity(ctx) || !validPrepareActivityInfoV2(activity.GetInfo(ctx), input, activities.namespace) {
		return PreparationReceiptV2{}, runtimeV2NonRetryableError(
			"READ_PREPARE_EXECUTION_MISMATCH", "investigation READ preparation execution rejected",
		)
	}
	return activities.prepareV2(ctx, input)
}

func (activities *RuntimeV2Activities) prepareV2(
	ctx context.Context,
	input WorkflowInputV2,
) (PreparationReceiptV2, error) {
	legacyInput := WorkflowInput{
		Version: SchemaVersion, OutboxEventID: input.OutboxEventID,
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, SignalID: input.SignalID,
		AggregateVersion: input.AggregateVersion,
		ManifestDigest:   input.ManifestDigest, RegistryDigest: input.RegistryDigest,
	}
	legacy, err := activities.preparation.prepare(ctx, legacyInput)
	if err != nil {
		return PreparationReceiptV2{}, err
	}
	if validateReceipt(legacyInput, legacy) != nil {
		return PreparationReceiptV2{}, runtimeV2NonRetryableError(
			"READ_PREPARE_RESULT_INVALID", "investigation READ preparation result rejected",
		)
	}
	result := PreparationReceiptV2{
		Version: RuntimeV2SchemaVersion, State: legacy.State,
		OutboxEventID: legacy.OutboxEventID, TenantID: legacy.TenantID,
		WorkspaceID: legacy.WorkspaceID, SignalID: legacy.SignalID,
		ManifestDigest: legacy.ManifestDigest, RegistryDigest: legacy.RegistryDigest,
		BundleDigest:  input.BundleDigest,
		ProfileDigest: legacy.ProfileDigest, TasksHash: legacy.TasksHash,
	}
	if legacy.State == StateNoActiveIncident {
		if result.ValidateAgainst(input) != nil {
			return PreparationReceiptV2{}, runtimeV2NonRetryableError(
				"READ_PREPARE_RESULT_INVALID", "investigation READ preparation result rejected",
			)
		}
		return result, nil
	}
	incident, err := activities.preparation.repository.GetIncident(ctx, input.WorkspaceID, legacy.IncidentID)
	if err != nil {
		return PreparationReceiptV2{}, mapDependencyError(ctx, err)
	}
	tasks, err := activities.preparation.repository.ListTasks(ctx, investigation.ListTasksRequest{
		WorkspaceID: input.WorkspaceID, InvestigationID: legacy.InvestigationID,
	})
	if err != nil {
		return PreparationReceiptV2{}, mapDependencyError(ctx, err)
	}
	if !validRuntimeV2PreparedFacts(input, legacy, incident, tasks) {
		return PreparationReceiptV2{}, runtimeV2NonRetryableError(
			"PREPARE_FACT_CONFLICT", "investigation preparation fact rejected",
		)
	}
	result.IncidentID = incident.ID
	result.EnvironmentID = incident.EnvironmentID
	result.ServiceID = incident.ServiceID
	result.InvestigationID = legacy.InvestigationID
	result.Tasks = make([]ReadTaskReferenceV2, len(tasks))
	for index, task := range tasks {
		result.Tasks[index] = ReadTaskReferenceV2{TaskID: task.ID, Position: task.Position}
	}
	if result.ValidateAgainst(input) != nil {
		return PreparationReceiptV2{}, runtimeV2NonRetryableError(
			"READ_PREPARE_RESULT_INVALID", "investigation READ preparation result rejected",
		)
	}
	return result, nil
}

func validRuntimeV2PreparedFacts(
	input WorkflowInputV2,
	legacy PreparationReceipt,
	incident domain.Incident,
	tasks []domain.ReadTask,
) bool {
	if incident.Validate() != nil || incident.ID != legacy.IncidentID || incident.TenantID != input.TenantID ||
		incident.WorkspaceID != input.WorkspaceID || incident.MappingStatus != domain.MappingExact ||
		!workflowUUID.MatchString(incident.EnvironmentID) || !workflowUUID.MatchString(incident.ServiceID) ||
		len(tasks) != len(legacy.TaskIDs) || len(tasks) < 1 || len(tasks) > 12 {
		return false
	}
	for index, task := range tasks {
		if task.Validate() != nil || task.RuntimeBinding.IsZero() || task.ID != legacy.TaskIDs[index] ||
			task.Position != index+1 || task.WorkspaceID != input.WorkspaceID ||
			task.IncidentID != incident.ID || task.InvestigationID != legacy.InvestigationID {
			return false
		}
	}
	return true
}

func (activities *RuntimeV2Activities) recoverActivityV1(
	ctx context.Context,
	input RecoveryActivityInput,
) (output RecoveryActivityOutput, returnedErr error) {
	defer func() {
		if recover() != nil {
			output = RecoveryActivityOutput{}
			returnedErr = recoveryDependencyError()
		}
	}()
	if ctx == nil || !activities.ready() {
		return RecoveryActivityOutput{}, recoveryNonRetryableError(
			recoveryInputInvalidErrorType, ErrInvalidRecoveryInput.Error(),
		)
	}
	if err := ctx.Err(); err != nil {
		return RecoveryActivityOutput{}, err
	}
	if _, err := input.recoveryRequest(); err != nil {
		return RecoveryActivityOutput{}, recoveryNonRetryableError(
			recoveryInputInvalidErrorType, ErrInvalidRecoveryInput.Error(),
		)
	}
	if !activity.IsActivity(ctx) || !validRecoveryActivityInfoV1(
		activity.GetInfo(ctx), input, activities.bundleDigest, activities.namespace,
	) {
		return RecoveryActivityOutput{}, recoveryNonRetryableError(
			"READ_RESULT_RECOVERY_EXECUTION_MISMATCH", "investigation READ result recovery execution rejected",
		)
	}
	return activities.recovery.recoverActivity(ctx, input)
}

func validPrepareActivityInfoV2(info activity.Info, input WorkflowInputV2, namespace string) bool {
	queue, err := ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, input.BundleDigest)
	return err == nil && validControlActivityInfoV2(
		info, input.OutboxEventID, PrepareActivityNameV2, "prepare-v2-"+input.OutboxEventID,
		queue, namespace, prepareActivityStartToCloseTimeoutV2, prepareNonRetryableTypesV2(),
	)
}

func validRecoveryActivityInfoV1(
	info activity.Info,
	input RecoveryActivityInput,
	bundleDigest string,
	namespace string,
) bool {
	queue, err := ControlTaskQueue(input.ManifestDigest, input.RegistryDigest, bundleDigest)
	if err != nil {
		return false
	}
	validID := false
	for round := 1; round <= MaximumReadTaskRounds && !validID; round++ {
		for check := 1; check <= 2; check++ {
			expected, idErr := RecoveryActivityID(round, check, input.Position, input.TaskID)
			if idErr == nil && info.ActivityID == expected {
				validID = true
				break
			}
		}
	}
	return validID && validControlActivityInfoV2(
		info, "", RecoveryActivityNameV1, info.ActivityID, queue,
		namespace, recoveryActivityStartToCloseTimeoutV1, recoveryNonRetryableTypesV1(),
	)
}

func validControlActivityInfoV2(
	info activity.Info,
	expectedWorkflowID string,
	activityType string,
	activityID string,
	queue string,
	namespace string,
	startToClose time.Duration,
	nonRetryableTypes []string,
) bool {
	workflowIDValid := workflowUUID.MatchString(info.WorkflowExecution.ID)
	if expectedWorkflowID != "" {
		workflowIDValid = info.WorkflowExecution.ID == expectedWorkflowID
	}
	return workflowIDValid && ValidTemporalRunID(info.WorkflowExecution.RunID) &&
		ValidTemporalNamespace(namespace) && info.Namespace == namespace && info.WorkflowType != nil &&
		info.WorkflowType.Name == WorkflowNameV2 && info.ActivityType.Name == activityType &&
		info.ActivityID == activityID && info.ActivityRunID == "" && info.TaskQueue == queue &&
		(info.WorkflowNamespace == "" || info.WorkflowNamespace == namespace) &&
		info.StartToCloseTimeout == startToClose && info.ScheduleToCloseTimeout == 0 &&
		info.HeartbeatTimeout == 0 && info.Attempt >= 1 && !info.IsLocalActivity &&
		info.Priority.PriorityKey == 0 && info.Priority.FairnessKey == "" && info.Priority.FairnessWeight == 0 &&
		validControlRetryPolicy(info.RetryPolicy, nonRetryableTypes)
}

func validControlRetryPolicy(policy *temporal.RetryPolicy, nonRetryableTypes []string) bool {
	return policy != nil && policy.InitialInterval == time.Second && policy.BackoffCoefficient == 2 &&
		policy.MaximumInterval == 15*time.Second && policy.MaximumAttempts == 0 &&
		slices.Equal(policy.NonRetryableErrorTypes, nonRetryableTypes)
}

func prepareNonRetryableTypesV2() []string {
	return []string{
		"PREPARE_INPUT_INVALID", "PREPARE_FACT_CONFLICT", "PREPARE_INTEGRITY_REJECTED",
		"PREPARE_RECEIPT_INVALID", "READ_PREPARE_EXECUTION_MISMATCH", "READ_PREPARE_RESULT_INVALID",
	}
}

func recoveryNonRetryableTypesV1() []string {
	return []string{
		recoveryInputInvalidErrorType, recoveryNotFoundErrorType,
		recoveryIntegrityRejectedErrorType, recoveryResultInvalidErrorType,
		"READ_RESULT_RECOVERY_EXECUTION_MISMATCH",
	}
}
