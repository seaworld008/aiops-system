// Package readrunneractivity owns the READ-only Temporal Activity boundary.
// It deliberately exposes no WRITE, credential, command, or arbitrary
// executor surface.
package readrunneractivity

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"go.temporal.io/sdk/activity"
)

const (
	gatewayHeartbeatInterval  = 10 * time.Second
	temporalHeartbeatInterval = 5 * time.Second
	preStartReleaseTimeout    = 5 * time.Second
	maximumActivityPayload    = 4096
)

var ErrActivityRejected = errors.New("READ runner activity rejected")

type activitiesSeal struct{ value byte }

var trustedActivitiesSeal = &activitiesSeal{value: 1}

type activityRuntime struct {
	info      func(context.Context) activity.Info
	heartbeat func(context.Context)
	interval  time.Duration
}

// Activities is a sealed READ Activity set. Registration is package-owned so
// callers cannot accidentally register an alias or a WRITE-shaped method.
type Activities struct {
	gateway                 gatewayProtocol
	runtime                 runtimeProtocol
	credentials             readexecutor.BearerSource
	temporal                activityRuntime
	gatewayBeat             time.Duration
	namespace               string
	planManifestDigest      string
	connectorRegistryDigest string
	seal                    *activitiesSeal
	self                    *Activities
}

func (activities *Activities) ready() bool {
	return activities != nil && activities.self == activities && activities.seal == trustedActivitiesSeal &&
		!nilInterface(activities.gateway) && !nilInterface(activities.runtime) && activities.credentials != nil &&
		activities.temporal.info != nil && activities.temporal.heartbeat != nil &&
		activities.temporal.interval > 0 && activities.temporal.interval <= temporalHeartbeatInterval &&
		activities.gatewayBeat > 0 && activities.gatewayBeat <= gatewayHeartbeatInterval &&
		investigationworkflow.ValidTemporalNamespace(activities.namespace) &&
		domain.ValidSHA256Hex(activities.planManifestDigest) &&
		domain.ValidSHA256Hex(activities.connectorRegistryDigest)
}

func (Activities) String() string   { return "<aiops-read-runner-activities>" }
func (Activities) GoString() string { return "<aiops-read-runner-activities>" }
func (Activities) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-runner-activities>")
}
func (Activities) MarshalJSON() ([]byte, error) { return nil, ErrActivityRejected }
func (*Activities) UnmarshalJSON([]byte) error  { return ErrActivityRejected }

func newActivities(
	gateway gatewayProtocol,
	runtime runtimeProtocol,
	credentials readexecutor.BearerSource,
	temporal activityRuntime,
	gatewayBeat time.Duration,
	namespace string,
	planManifestDigest string,
	connectorRegistryDigest string,
) (*Activities, error) {
	if nilInterface(gateway) || nilInterface(runtime) || credentials == nil || temporal.info == nil ||
		temporal.heartbeat == nil || temporal.interval <= 0 || temporal.interval > temporalHeartbeatInterval ||
		gatewayBeat <= 0 || gatewayBeat > gatewayHeartbeatInterval ||
		!investigationworkflow.ValidTemporalNamespace(namespace) || !domain.ValidSHA256Hex(planManifestDigest) ||
		!domain.ValidSHA256Hex(connectorRegistryDigest) {
		return nil, ErrActivityRejected
	}
	created := &Activities{
		gateway: gateway, runtime: runtime, credentials: credentials, temporal: temporal, gatewayBeat: gatewayBeat,
		namespace: namespace, planManifestDigest: strings.Clone(planManifestDigest),
		connectorRegistryDigest: strings.Clone(connectorRegistryDigest), seal: trustedActivitiesSeal,
	}
	created.self = created
	return created, nil
}

func (activities *Activities) execute(
	ctx context.Context,
	input investigationworkflow.ReadTaskActivityInputV1,
) (output investigationworkflow.ReadTaskActivityOutputV1, returnedErr error) {
	if !activities.ready() || !validContext(ctx) || !validInput(input) {
		return investigationworkflow.ReadTaskActivityOutputV1{}, ErrActivityRejected
	}
	if !activities.acceptsPlan(input.ManifestDigest, input.RegistryDigest) {
		return investigationworkflow.ReadTaskActivityOutputV1{}, ErrActivityRejected
	}
	defer func() {
		if recover() != nil {
			output = recoveryOutput(input)
			returnedErr = nil
		}
	}()
	info, err := safeActivityInfo(activities.temporal.info, ctx)
	if err != nil || !validActivityInfo(info, input, activities.namespace) {
		return investigationworkflow.ReadTaskActivityOutputV1{}, ErrActivityRejected
	}
	operationContext, cancelOperations := context.WithCancel(ctx)
	if safeTemporalHeartbeat(activities.temporal.heartbeat, operationContext) != nil || operationContext.Err() != nil {
		cancelOperations()
		return recoveryOutput(input), nil
	}
	monitor := startTemporalHeartbeatMonitor(
		operationContext, cancelOperations, activities.temporal.heartbeat, activities.temporal.interval,
	)
	defer monitor.stop()
	defer cancelOperations()
	bundleDigest, err := safeBundleDigest(activities.runtime)
	if err != nil || !domain.ValidSHA256Hex(bundleDigest) ||
		subtle.ConstantTimeCompare([]byte(bundleDigest), []byte(input.BundleDigest)) != 1 {
		return investigationworkflow.ReadTaskActivityOutputV1{}, ErrActivityRejected
	}

	expected := readrunnerclient.ExpectedTask{
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, EnvironmentID: input.EnvironmentID,
		ServiceID: input.ServiceID, IncidentID: input.IncidentID, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position,
		PlanBinding: domain.InvestigationPlanBinding{
			SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
			ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
			ProfileDigest: input.ProfileDigest, TasksHash: input.TasksHash,
		},
	}
	lease, err := safeClaim(activities.gateway, operationContext, expected)
	if err != nil {
		safeDestroy(lease)
		return recoveryOutput(input), nil
	}
	if lease == nil {
		return stateOutput(input, investigationworkflow.ReadTaskActivityNotClaimed), nil
	}
	defer safeDestroy(lease)
	if operationContext.Err() != nil {
		if releaseBeforeStart(lease, readtask.ReleaseTransientRunnerFailure) == nil {
			return stateOutput(input, investigationworkflow.ReadTaskActivityNotClaimed), nil
		}
		return recoveryOutput(input), nil
	}

	prepared, err := safePrepare(
		activities.runtime, operationContext, lease.Descriptor(), lease.LeaseEpoch(), lease.ScopeRevision(),
	)
	if err != nil || nilInterface(prepared) {
		reason := readtask.ReleaseConnectorNotReady
		if operationContext.Err() != nil {
			reason = readtask.ReleaseTransientRunnerFailure
		}
		if releaseBeforeStart(lease, reason) == nil {
			return stateOutput(input, investigationworkflow.ReadTaskActivityNotClaimed), nil
		}
		return recoveryOutput(input), nil
	}
	if operationContext.Err() != nil {
		if releaseBeforeStart(lease, readtask.ReleaseTransientRunnerFailure) == nil {
			return stateOutput(input, investigationworkflow.ReadTaskActivityNotClaimed), nil
		}
		return recoveryOutput(input), nil
	}

	start, err := safeStart(lease, operationContext)
	if err != nil || nilInterface(start) {
		return recoveryOutput(input), nil
	}
	return activities.executeStarted(operationContext, input, lease, prepared, start)
}

func (activities *Activities) acceptsPlan(manifestDigest, registryDigest string) bool {
	return activities.ready() && domain.ValidSHA256Hex(manifestDigest) && domain.ValidSHA256Hex(registryDigest) &&
		subtle.ConstantTimeCompare([]byte(activities.planManifestDigest), []byte(manifestDigest)) == 1 &&
		subtle.ConstantTimeCompare([]byte(activities.connectorRegistryDigest), []byte(registryDigest)) == 1
}

// AcceptsPlanningIdentity reports whether this sealed Activity set is bound
// to one reviewed Plan/Connector/Bundle identity. It reveals no runtime
// component and is intended for process-assembly integrity checks.
func (activities *Activities) AcceptsPlanningIdentity(
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
) bool {
	if !activities.acceptsPlan(manifestDigest, registryDigest) || !domain.ValidSHA256Hex(bundleDigest) {
		return false
	}
	actual, err := safeBundleDigest(activities.runtime)
	return err == nil && domain.ValidSHA256Hex(actual) &&
		subtle.ConstantTimeCompare([]byte(actual), []byte(bundleDigest)) == 1
}

func (activities *Activities) executeStarted(
	ctx context.Context,
	input investigationworkflow.ReadTaskActivityInputV1,
	lease leaseSession,
	prepared preparedSession,
	start startSession,
) (investigationworkflow.ReadTaskActivityOutputV1, error) {
	executionContext, cancelExecution := context.WithCancel(ctx)
	defer cancelExecution()
	type executionOutcome struct {
		completion readrunnerclient.Completion
		err        error
	}
	outcomes := make(chan executionOutcome, 1)
	go func() {
		completion, err := safeExecute(prepared, executionContext, start, activities.credentials)
		outcomes <- executionOutcome{completion: completion, err: err}
	}()

	ticker := time.NewTicker(activities.gatewayBeat)
	defer ticker.Stop()
	sequence := int64(0)
	for {
		select {
		case <-ctx.Done():
			cancelExecution()
			outcome := <-outcomes
			destroyCompletion(&outcome.completion)
			return recoveryOutput(input), nil
		case outcome := <-outcomes:
			if outcome.err != nil || ctx.Err() != nil {
				destroyCompletion(&outcome.completion)
				return recoveryOutput(input), nil
			}
			completionErr := safeComplete(lease, ctx, start, outcome.completion)
			destroyCompletion(&outcome.completion)
			if completionErr != nil {
				return recoveryOutput(input), nil
			}
			return stateOutput(input, investigationworkflow.ReadTaskActivityCompleteAcknowledged), nil
		case <-ticker.C:
			sequence++
			heartbeat, err := safeGatewayHeartbeat(lease, ctx, start, sequence)
			if err != nil || heartbeat.Directive != readtask.HeartbeatContinue {
				cancelExecution()
				outcome := <-outcomes
				destroyCompletion(&outcome.completion)
				return recoveryOutput(input), nil
			}
		}
	}
}

func destroyCompletion(completion *readrunnerclient.Completion) {
	if completion == nil {
		return
	}
	if completion.Evidence != nil {
		for index := range completion.Evidence.Items {
			clear(completion.Evidence.Items[index])
			completion.Evidence.Items[index] = nil
		}
		completion.Evidence.Items = nil
		*completion.Evidence = readtask.EvidenceCompletion{}
	}
	*completion = readrunnerclient.Completion{}
}

func validInput(input investigationworkflow.ReadTaskActivityInputV1) bool {
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumActivityPayload {
		return false
	}
	binding := domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: input.ManifestDigest, RegistryDigest: input.RegistryDigest,
		ProfileDigest: input.ProfileDigest, TasksHash: input.TasksHash,
	}
	return input.Validate() == nil && binding.Validate() == nil
}

func validActivityInfo(
	info activity.Info,
	input investigationworkflow.ReadTaskActivityInputV1,
	namespace string,
) bool {
	queue, err := investigationworkflow.RunnerTaskQueue(
		input.EnvironmentID, input.ManifestDigest, input.RegistryDigest, input.BundleDigest,
	)
	if err != nil {
		return false
	}
	expectedID, err := investigationworkflow.ReadTaskActivityID(input.Round, input.Position, input.TaskID)
	if err != nil {
		return false
	}
	return info.WorkflowType != nil && info.WorkflowType.Name == investigationworkflow.WorkflowNameV2 &&
		info.WorkflowExecution.ID == input.OutboxEventID &&
		investigationworkflow.ValidTemporalRunID(info.WorkflowExecution.RunID) &&
		investigationworkflow.ValidTemporalNamespace(namespace) && info.Namespace == namespace &&
		(info.WorkflowNamespace == "" || info.WorkflowNamespace == namespace) &&
		info.ActivityType.Name == investigationworkflow.ExecuteActivityNameV1 && info.ActivityID == expectedID &&
		info.TaskQueue == queue && info.Attempt == 1 && !info.IsLocalActivity && info.ActivityRunID == "" &&
		info.ScheduleToCloseTimeout == investigationworkflow.RunnerActivityScheduleToCloseTimeout &&
		info.StartToCloseTimeout == investigationworkflow.RunnerActivityStartToCloseTimeout &&
		info.HeartbeatTimeout == investigationworkflow.RunnerActivityHeartbeatTimeout &&
		info.RetryPolicy != nil && info.RetryPolicy.MaximumAttempts == 1 &&
		info.Priority.PriorityKey == 0 && info.Priority.FairnessKey == "" && info.Priority.FairnessWeight == 0
}

func stateOutput(
	input investigationworkflow.ReadTaskActivityInputV1,
	state string,
) investigationworkflow.ReadTaskActivityOutputV1 {
	return investigationworkflow.ReadTaskActivityOutputV1{
		Version: investigationworkflow.ReadTaskActivitySchemaVersion, State: state, InvestigationID: input.InvestigationID,
		TaskID: input.TaskID, Position: input.Position, Round: input.Round,
	}
}

func recoveryOutput(input investigationworkflow.ReadTaskActivityInputV1) investigationworkflow.ReadTaskActivityOutputV1 {
	return stateOutput(input, investigationworkflow.ReadTaskActivityRecoveryRequired)
}

func validContext(ctx context.Context) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if ctx == nil {
		return false
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	return ctx.Err() == nil
}

func nilInterface(value any) (nilValue bool) {
	defer func() {
		if recover() != nil {
			nilValue = true
		}
	}()
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
