package investigation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

// TaskRuntimeComponents is the immutable, trusted output of a runtime binder.
// RuntimeDigest and BoundAt are intentionally absent: the repository derives
// them from locked facts and its own commit clock.
type TaskRuntimeComponents struct {
	ConnectorDigest string
	TargetDigest    string
	ExecutorDigest  string
}

func (components TaskRuntimeComponents) Validate() error {
	if !domain.ValidSHA256Hex(components.ConnectorDigest) ||
		!domain.ValidSHA256Hex(components.TargetDigest) ||
		!domain.ValidSHA256Hex(components.ExecutorDigest) {
		return fmt.Errorf("%w: task runtime components are invalid", ErrInvalidRequest)
	}
	return nil
}

// TaskRuntimeBinder authorizes one canonical TaskSpec against the exact locked
// scope and selected plan, then returns only trusted component digests. It
// cannot supply a repository timestamp or a self-asserted aggregate digest.
type TaskRuntimeBinder func(
	context.Context,
	TaskSpecScope,
	domain.InvestigationPlanBinding,
	TaskSpec,
) (TaskRuntimeComponents, error)

// ResolveTaskRuntimeComponents is the only safe adapter for invoking a trusted
// binder from a repository. It validates the full canonical task set against
// the selected plan, gives the binder detached inputs, preserves context
// termination and folds all other diagnostics and panics into one bounded
// repository request error.
func ResolveTaskRuntimeComponents(
	ctx context.Context,
	binder TaskRuntimeBinder,
	scope TaskSpecScope,
	plan domain.InvestigationPlanBinding,
	specs []TaskSpec,
) (resolved []TaskRuntimeComponents, returnedErr error) {
	defer func() {
		if recover() != nil {
			resolved = nil
			returnedErr = fmt.Errorf("%w: task runtime binding rejected", ErrInvalidRequest)
		}
	}()
	if ctx == nil || binder == nil || scope.Validate() != nil || plan.Validate() != nil {
		return nil, fmt.Errorf("%w: trusted task runtime binder is required", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, tasksHash, err := CanonicalTaskSpecs(specs)
	if err != nil || tasksHash != plan.TasksHash || !sameCanonicalTaskSpecs(canonical, specs) {
		return nil, fmt.Errorf("%w: task runtime binding set is invalid", ErrInvalidRequest)
	}
	resolved = make([]TaskRuntimeComponents, len(canonical))
	for index, spec := range canonical {
		detached := spec
		detached.Input = bytes.Clone(spec.Input)
		components, bindErr := binder(ctx, scope, plan, detached)
		if bindErr != nil {
			if errors.Is(bindErr, context.Canceled) {
				return nil, context.Canceled
			}
			if errors.Is(bindErr, context.DeadlineExceeded) {
				return nil, context.DeadlineExceeded
			}
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, contextErr
			}
			return nil, fmt.Errorf("%w: task runtime binding rejected", ErrInvalidRequest)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if components.Validate() != nil {
			return nil, fmt.Errorf("%w: task runtime binding rejected", ErrInvalidRequest)
		}
		if _, err := ReadTaskRuntimeDigest(scope, plan, spec, index+1, components); err != nil {
			return nil, fmt.Errorf("%w: task runtime binding rejected", ErrInvalidRequest)
		}
		resolved[index] = TaskRuntimeComponents{
			ConnectorDigest: strings.Clone(components.ConnectorDigest),
			TargetDigest:    strings.Clone(components.TargetDigest),
			ExecutorDigest:  strings.Clone(components.ExecutorDigest),
		}
	}
	return resolved, nil
}

func sameCanonicalTaskSpecs(canonical, original []TaskSpec) bool {
	if len(canonical) != len(original) {
		return false
	}
	for index := range canonical {
		if canonical[index].Key != original[index].Key || canonical[index].ConnectorID != original[index].ConnectorID ||
			canonical[index].Operation != original[index].Operation || !bytes.Equal(canonical[index].Input, original[index].Input) {
			return false
		}
	}
	return true
}

// ReadTaskRuntimeDigest returns the stable v1 aggregate digest for one exact
// READ task execution contract. The preimage binds the plan registry, trusted
// scope, task identity/input hash and every server-resolved runtime component.
func ReadTaskRuntimeDigest(
	scope TaskSpecScope,
	plan domain.InvestigationPlanBinding,
	spec TaskSpec,
	position int,
	components TaskRuntimeComponents,
) (string, error) {
	canonical, err := validateRuntimeDigestInput(scope, plan, spec, position, components)
	if err != nil {
		return "", err
	}
	inputDigest := sha256.Sum256(canonical.Input)
	return semanticRequestHash(domain.ReadTaskRuntimeBindingSchemaVersion, struct {
		RegistryDigest string                  `json:"registry_digest"`
		Scope          runtimeDigestScope      `json:"scope"`
		Task           runtimeDigestTask       `json:"task"`
		Components     runtimeDigestComponents `json:"components"`
	}{
		RegistryDigest: plan.RegistryDigest,
		Scope: runtimeDigestScope{
			TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID,
			EnvironmentID: scope.EnvironmentID, ServiceID: scope.ServiceID,
			MappingStatus: scope.MappingStatus,
		},
		Task: runtimeDigestTask{
			Key: canonical.Key, Position: position, ConnectorID: canonical.ConnectorID,
			Operation: canonical.Operation, InputHash: hex.EncodeToString(inputDigest[:]),
		},
		Components: runtimeDigestComponents{
			ConnectorDigest: components.ConnectorDigest,
			TargetDigest:    components.TargetDigest,
			ExecutorDigest:  components.ExecutorDigest,
		},
	})
}

type runtimeDigestScope struct {
	TenantID      string               `json:"tenant_id"`
	WorkspaceID   string               `json:"workspace_id"`
	EnvironmentID string               `json:"environment_id"`
	ServiceID     string               `json:"service_id"`
	MappingStatus domain.MappingStatus `json:"mapping_status"`
}

type runtimeDigestTask struct {
	Key         string `json:"key"`
	Position    int    `json:"position"`
	ConnectorID string `json:"connector_id"`
	Operation   string `json:"operation"`
	InputHash   string `json:"input_hash"`
}

type runtimeDigestComponents struct {
	ConnectorDigest string `json:"connector_digest"`
	TargetDigest    string `json:"target_digest"`
	ExecutorDigest  string `json:"executor_digest"`
}

// BuildReadTaskRuntimeBinding adds the repository-owned binding time to the
// deterministic digest. The supplied time must already be canonical UTC at
// PostgreSQL microsecond precision; this function never silently rewrites it.
func BuildReadTaskRuntimeBinding(
	scope TaskSpecScope,
	plan domain.InvestigationPlanBinding,
	spec TaskSpec,
	position int,
	components TaskRuntimeComponents,
	boundAt time.Time,
) (domain.ReadTaskRuntimeBinding, error) {
	runtimeDigest, err := ReadTaskRuntimeDigest(scope, plan, spec, position, components)
	if err != nil {
		return domain.ReadTaskRuntimeBinding{}, err
	}
	binding := domain.ReadTaskRuntimeBinding{
		SchemaVersion:   domain.ReadTaskRuntimeBindingSchemaVersion,
		ConnectorDigest: strings.Clone(components.ConnectorDigest),
		TargetDigest:    strings.Clone(components.TargetDigest),
		ExecutorDigest:  strings.Clone(components.ExecutorDigest),
		RuntimeDigest:   runtimeDigest,
		BoundAt:         boundAt,
	}
	if err := binding.Validate(); err != nil {
		return domain.ReadTaskRuntimeBinding{}, fmt.Errorf("%w: repository runtime binding time is invalid", ErrInvalidRequest)
	}
	return binding, nil
}

func validateRuntimeDigestInput(
	scope TaskSpecScope,
	plan domain.InvestigationPlanBinding,
	spec TaskSpec,
	position int,
	components TaskRuntimeComponents,
) (TaskSpec, error) {
	if scope.Validate() != nil || plan.Validate() != nil || position < 1 || position > 12 || components.Validate() != nil {
		return TaskSpec{}, fmt.Errorf("%w: runtime binding facts are invalid", ErrInvalidRequest)
	}
	canonical, _, err := CanonicalTaskSpecs([]TaskSpec{spec})
	if err != nil || len(canonical) != 1 || canonical[0].Key != spec.Key ||
		canonical[0].ConnectorID != spec.ConnectorID || canonical[0].Operation != spec.Operation ||
		!bytes.Equal(canonical[0].Input, spec.Input) {
		return TaskSpec{}, fmt.Errorf("%w: runtime binding task must be canonical", ErrInvalidRequest)
	}
	if !domain.ConnectorDigestMatchesID(spec.ConnectorID, components.ConnectorDigest) {
		return TaskSpec{}, fmt.Errorf("%w: runtime connector digest does not match its content-addressed ID", ErrInvalidRequest)
	}
	return canonical[0], nil
}
