package investigationworkflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/store"
	"go.temporal.io/sdk/temporal"
)

type preparationRepository interface {
	CorrelateSignal(context.Context, investigation.CorrelateSignalRequest) (investigation.CorrelateSignalResult, error)
	CreateOrGetInvestigation(context.Context, investigation.CreateOrGetInvestigationRequest) (investigation.CreateOrGetInvestigationResult, error)
	GetIncident(context.Context, string, string) (domain.Incident, error)
	GetInvestigation(context.Context, string, string) (domain.Investigation, error)
	ListTasks(context.Context, investigation.ListTasksRequest) ([]domain.ReadTask, error)
}

type Activities struct {
	reader     investigation.SignalRegistrationReader
	repository preparationRepository
	authority  *investigationplan.ScopeAuthority
	planner    *investigationplan.Planner
}

// NewActivities is a low-level preparation constructor. Production v2
// callsites are repository-gated to readassembly.Snapshot so callers cannot
// inject a foreign Planner or authority into the live Temporal graph.
func NewActivities(
	reader investigation.SignalRegistrationReader,
	repository preparationRepository,
	authority *investigationplan.ScopeAuthority,
	planner *investigationplan.Planner,
) (*Activities, error) {
	created := &Activities{reader: reader, repository: repository, authority: authority, planner: planner}
	if !created.ready() {
		return nil, ErrInvalidInput
	}
	return created, nil
}

func (activities *Activities) ready() bool {
	return activities != nil && !nilInterface(activities.reader) && !nilInterface(activities.repository) &&
		activities.authority != nil && activities.planner != nil && activities.planner.Ready() &&
		activities.planner.AcceptsAuthority(activities.authority)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	item := reflect.ValueOf(value)
	switch item.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return item.IsNil()
	default:
		return false
	}
}

func (activities *Activities) prepareActivity(ctx context.Context, input WorkflowInput) (receipt PreparationReceipt, returnedErr error) {
	defer func() {
		if recover() != nil {
			receipt = PreparationReceipt{}
			returnedErr = retryableDependencyError()
		}
	}()
	return activities.prepare(ctx, input)
}

func (activities *Activities) prepare(ctx context.Context, input WorkflowInput) (PreparationReceipt, error) {
	if ctx == nil || validateInput(input) != nil || !activities.ready() {
		return PreparationReceipt{}, nonRetryableError("PREPARE_INPUT_INVALID", "investigation preparation input rejected")
	}
	if err := ctx.Err(); err != nil {
		return PreparationReceipt{}, err
	}
	if activities.planner.ManifestDigest() != input.ManifestDigest || activities.planner.RegistryDigest() != input.RegistryDigest {
		return PreparationReceipt{}, nonRetryableError("PREPARE_INTEGRITY_REJECTED", "investigation preparation integrity rejected")
	}
	registered, err := activities.reader.GetRegisteredSignal(ctx, input.SignalID)
	if err != nil {
		return PreparationReceipt{}, mapDependencyError(ctx, err)
	}
	if registered.Validate() != nil || registered.TenantID != input.TenantID ||
		registered.WorkspaceID != input.WorkspaceID || registered.Signal.ID != input.SignalID {
		return PreparationReceipt{}, nonRetryableError("PREPARE_FACT_CONFLICT", "investigation preparation fact rejected")
	}
	trustedScope, err := activities.authority.Attest(investigationplan.TrustedSignalRegistration{
		TenantID: registered.TenantID, WorkspaceID: registered.WorkspaceID,
	})
	if err != nil {
		return PreparationReceipt{}, nonRetryableError("PREPARE_INTEGRITY_REJECTED", "investigation preparation integrity rejected")
	}
	plan, err := activities.planner.Resolve(ctx, investigationplan.ResolveRequest{
		ExpectedPlanDigest: input.ManifestDigest, TrustedScope: trustedScope, Signal: registered.Signal,
	})
	if err != nil {
		if ctx.Err() != nil {
			return PreparationReceipt{}, ctx.Err()
		}
		return PreparationReceipt{}, nonRetryableError("PREPARE_INTEGRITY_REJECTED", "investigation preparation integrity rejected")
	}
	signalSnapshotHash, err := investigation.RegisteredSignalSnapshotHash(registered)
	if err != nil {
		return PreparationReceipt{}, nonRetryableError("PREPARE_INTEGRITY_REJECTED", "investigation preparation integrity rejected")
	}
	base := PreparationReceipt{
		Version: SchemaVersion, OutboxEventID: input.OutboxEventID,
		TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, SignalID: input.SignalID,
		ManifestDigest: plan.ManifestDigest(), RegistryDigest: plan.RegistryDigest(),
		ProfileDigest: plan.ProfileDigest(), TasksHash: plan.TasksHash(),
	}
	correlation := plan.CorrelateSignalRequest()
	correlation.ExpectedSignalHash = signalSnapshotHash
	correlated, err := activities.repository.CorrelateSignal(ctx, correlation)
	if err != nil {
		return PreparationReceipt{}, mapDependencyError(ctx, err)
	}
	if !correlated.Associated {
		if registered.Signal.Status != "resolved" || correlated.Incident.ID != "" || correlated.Created || correlated.Counted {
			return PreparationReceipt{}, nonRetryableError("PREPARE_FACT_CONFLICT", "investigation preparation fact rejected")
		}
		base.State = StateNoActiveIncident
		if validateReceipt(input, base) != nil {
			return PreparationReceipt{}, nonRetryableError("PREPARE_RECEIPT_INVALID", "investigation preparation receipt rejected")
		}
		return base, nil
	}
	if registered.Signal.Status != "firing" && registered.Signal.Status != "resolved" ||
		!validIncidentForPlan(correlated.Incident, plan) {
		return PreparationReceipt{}, nonRetryableError("PREPARE_FACT_CONFLICT", "investigation preparation fact rejected")
	}
	created, err := activities.repository.CreateOrGetInvestigation(ctx, investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: input.WorkspaceID, IncidentID: correlated.Incident.ID,
		IdempotencyKey: "temporal.prepare.v1/" + input.OutboxEventID,
		PlanBinding:    planBinding(plan), Tasks: plan.TaskSpecs(),
	})
	if err != nil {
		return PreparationReceipt{}, mapDependencyError(ctx, err)
	}
	incident, err := activities.repository.GetIncident(ctx, input.WorkspaceID, correlated.Incident.ID)
	if err != nil {
		return PreparationReceipt{}, mapDependencyError(ctx, err)
	}
	if incident.ID != correlated.Incident.ID || !validIncidentForPlan(incident, plan) {
		return PreparationReceipt{}, nonRetryableError("PREPARE_FACT_CONFLICT", "investigation preparation fact rejected")
	}
	persistedInvestigation, err := activities.repository.GetInvestigation(ctx, input.WorkspaceID, created.Investigation.ID)
	if err != nil {
		return PreparationReceipt{}, mapDependencyError(ctx, err)
	}
	persistedTasks, err := activities.repository.ListTasks(ctx, investigation.ListTasksRequest{
		WorkspaceID: input.WorkspaceID, InvestigationID: created.Investigation.ID,
	})
	if err != nil {
		return PreparationReceipt{}, mapDependencyError(ctx, err)
	}
	if !sameImmutableInvestigation(created.Investigation, persistedInvestigation) ||
		!sameImmutableTasks(created.Tasks, persistedTasks) ||
		!validInvestigationProjection(input, correlated.Incident.ID, persistedInvestigation, persistedTasks, plan) {
		return PreparationReceipt{}, nonRetryableError("PREPARE_FACT_CONFLICT", "investigation preparation fact rejected")
	}
	base.State = StatePrepared
	base.IncidentID = persistedInvestigation.IncidentID
	base.InvestigationID = persistedInvestigation.ID
	base.TaskIDs = make([]string, len(persistedTasks))
	for index := range persistedTasks {
		base.TaskIDs[index] = persistedTasks[index].ID
	}
	base.TaskCount = len(base.TaskIDs)
	if validateReceipt(input, base) != nil {
		return PreparationReceipt{}, nonRetryableError("PREPARE_RECEIPT_INVALID", "investigation preparation receipt rejected")
	}
	return base, nil
}

func validIncidentForPlan(incident domain.Incident, plan investigationplan.Plan) bool {
	scope := plan.Scope()
	correlation := plan.CorrelateSignalRequest()
	return incident.Validate() == nil && incident.TenantID == scope.TenantID && incident.WorkspaceID == scope.WorkspaceID &&
		incident.EnvironmentID == scope.EnvironmentID && incident.ServiceID == scope.ServiceID &&
		incident.MappingStatus == scope.MappingStatus && incident.CorrelationKey == correlation.CorrelationKey
}

func planBinding(plan investigationplan.Plan) domain.InvestigationPlanBinding {
	return domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: plan.ManifestDigest(), RegistryDigest: plan.RegistryDigest(),
		ProfileDigest: plan.ProfileDigest(), TasksHash: plan.TasksHash(),
	}
}

func validInvestigationProjection(
	input WorkflowInput,
	incidentID string,
	item domain.Investigation,
	tasks []domain.ReadTask,
	plan investigationplan.Plan,
) bool {
	expectedPlanBinding := planBinding(plan)
	if item.Validate() != nil || item.WorkspaceID != input.WorkspaceID || item.IncidentID != incidentID ||
		item.RequestHashVersion != domain.InvestigationCreateRequestVersionV2 || !item.PlanBinding.Equal(expectedPlanBinding) ||
		len(tasks) == 0 || len(tasks) > 12 {
		return false
	}
	expectedRequestHash, err := investigation.CreateOrGetInvestigationRequestHash(
		investigation.CreateOrGetInvestigationRequest{IncidentID: incidentID, PlanBinding: expectedPlanBinding}, plan.TasksHash(),
	)
	if err != nil || item.RequestHash != expectedRequestHash {
		return false
	}
	want := plan.TaskSpecs()
	if len(tasks) != len(want) {
		return false
	}
	reconstructed := make([]investigation.TaskSpec, len(tasks))
	for index, task := range tasks {
		if task.Validate() != nil || task.Position != index+1 || task.WorkspaceID != input.WorkspaceID ||
			task.IncidentID != incidentID || task.InvestigationID != item.ID || !workflowUUID.MatchString(task.ID) ||
			task.Key != want[index].Key || task.ConnectorID != want[index].ConnectorID ||
			task.Operation != want[index].Operation || !bytes.Equal(task.Input, want[index].Input) {
			return false
		}
		expectedRuntimeBinding, bindingErr := investigation.BuildReadTaskRuntimeBinding(
			plan.Scope(), expectedPlanBinding, want[index], index+1,
			investigation.TaskRuntimeComponents{
				ConnectorDigest: task.RuntimeBinding.ConnectorDigest,
				TargetDigest:    task.RuntimeBinding.TargetDigest, ExecutorDigest: task.RuntimeBinding.ExecutorDigest,
			}, task.RuntimeBinding.BoundAt,
		)
		if bindingErr != nil || !task.RuntimeBinding.Equal(expectedRuntimeBinding) {
			return false
		}
		inputHash := sha256.Sum256(task.Input)
		if task.InputHash != fmt.Sprintf("%x", inputHash[:]) {
			return false
		}
		reconstructed[index] = investigation.TaskSpec{
			Key: task.Key, ConnectorID: task.ConnectorID, Operation: task.Operation, Input: bytes.Clone(task.Input),
		}
	}
	canonical, hash, err := investigation.CanonicalTaskSpecs(reconstructed)
	if err != nil || hash != plan.TasksHash() || len(canonical) != len(reconstructed) {
		return false
	}
	for index := range canonical {
		if canonical[index].Key != reconstructed[index].Key || canonical[index].ConnectorID != reconstructed[index].ConnectorID ||
			canonical[index].Operation != reconstructed[index].Operation || !bytes.Equal(canonical[index].Input, reconstructed[index].Input) {
			return false
		}
	}
	return true
}

func sameImmutableInvestigation(left, right domain.Investigation) bool {
	return left.ID == right.ID && left.WorkspaceID == right.WorkspaceID && left.IncidentID == right.IncidentID &&
		left.IdempotencyKey == right.IdempotencyKey && left.RequestHash == right.RequestHash &&
		left.RequestHashVersion == right.RequestHashVersion && left.PlanBinding.Equal(right.PlanBinding) &&
		left.CreatedAt.Equal(right.CreatedAt)
}

func sameImmutableTasks(left, right []domain.ReadTask) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || left[index].WorkspaceID != right[index].WorkspaceID ||
			left[index].IncidentID != right[index].IncidentID || left[index].InvestigationID != right[index].InvestigationID ||
			left[index].Key != right[index].Key || left[index].Position != right[index].Position ||
			left[index].ConnectorID != right[index].ConnectorID || left[index].Operation != right[index].Operation ||
			left[index].InputHash != right[index].InputHash || !bytes.Equal(left[index].Input, right[index].Input) ||
			!left[index].RuntimeBinding.Equal(right[index].RuntimeBinding) ||
			!left[index].CreatedAt.Equal(right[index].CreatedAt) {
			return false
		}
	}
	return true
}

func mapDependencyError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, investigation.ErrInvalidRequest) || errors.Is(err, investigation.ErrInvalidTransition) ||
		errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrScopeViolation) ||
		errors.Is(err, store.ErrIdempotencyConflict) {
		return nonRetryableError("PREPARE_FACT_CONFLICT", "investigation preparation fact rejected")
	}
	return retryableDependencyError()
}

func nonRetryableError(errorType, message string) error {
	return temporal.NewNonRetryableApplicationError(message, errorType, nil)
}

func retryableDependencyError() error {
	return temporal.NewApplicationError("investigation preparation dependency unavailable", "PREPARE_DEPENDENCY_UNAVAILABLE")
}
