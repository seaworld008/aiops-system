package investigation_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestBuildReadTaskRuntimeBindingBindsPlanScopeTaskAndComponents(t *testing.T) {
	scope, plan, spec, components, boundAt := runtimeBindingFixture()
	binding, err := investigation.BuildReadTaskRuntimeBinding(scope, plan, spec, 1, components, boundAt)
	if err != nil {
		t.Fatalf("BuildReadTaskRuntimeBinding() error = %v", err)
	}
	if binding.SchemaVersion != domain.ReadTaskRuntimeBindingSchemaVersion ||
		binding.ConnectorDigest != components.ConnectorDigest || binding.TargetDigest != components.TargetDigest ||
		binding.ExecutorDigest != components.ExecutorDigest || !domain.ValidSHA256Hex(binding.RuntimeDigest) ||
		!binding.BoundAt.Equal(boundAt) || binding.Validate() != nil {
		t.Fatalf("BuildReadTaskRuntimeBinding() = %#v, want complete immutable binding", binding)
	}
	digest, err := investigation.ReadTaskRuntimeDigest(scope, plan, spec, 1, components)
	if err != nil || digest != binding.RuntimeDigest {
		t.Fatalf("ReadTaskRuntimeDigest() = %q, %v; want %q", digest, err, binding.RuntimeDigest)
	}

	mutations := map[string]func(*investigation.TaskSpecScope, *domain.InvestigationPlanBinding, *investigation.TaskSpec, *int, *investigation.TaskRuntimeComponents){
		"registry": func(_ *investigation.TaskSpecScope, plan *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			plan.RegistryDigest = strings.Repeat("9", 64)
		},
		"tenant": func(scope *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			scope.TenantID = "tenant-2"
		},
		"workspace": func(scope *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			scope.WorkspaceID = "workspace-2"
		},
		"environment": func(scope *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			scope.EnvironmentID = "environment-2"
		},
		"service": func(scope *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			scope.ServiceID = "service-2"
		},
		"key": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, spec *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			spec.Key = "logs"
		},
		"position": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, position *int, _ *investigation.TaskRuntimeComponents) {
			*position = 2
		},
		"connector id": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, spec *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			spec.ConnectorID = "metrics-alt-v1-" + components.ConnectorDigest
		},
		"operation": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, spec *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			spec.Operation = "instant_query"
		},
		"input": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, spec *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents) {
			spec.Input = []byte(`{"lookback_minutes":30}`)
		},
		"connector digest": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, spec *investigation.TaskSpec, _ *int, components *investigation.TaskRuntimeComponents) {
			components.ConnectorDigest = strings.Repeat("a", 64)
			spec.ConnectorID = "metrics-v1-" + components.ConnectorDigest
		},
		"target digest": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, components *investigation.TaskRuntimeComponents) {
			components.TargetDigest = strings.Repeat("b", 64)
		},
		"executor digest": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, components *investigation.TaskRuntimeComponents) {
			components.ExecutorDigest = strings.Repeat("c", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changedScope, changedPlan, changedSpec, changedComponents, _ := runtimeBindingFixture()
			position := 1
			mutate(&changedScope, &changedPlan, &changedSpec, &position, &changedComponents)
			changed, changedErr := investigation.ReadTaskRuntimeDigest(
				changedScope, changedPlan, changedSpec, position, changedComponents,
			)
			if changedErr != nil {
				t.Fatalf("ReadTaskRuntimeDigest(changed) error = %v", changedErr)
			}
			if changed == digest {
				t.Fatal("security-relevant runtime fact did not change digest")
			}
		})
	}
}

func TestResolveTaskRuntimeComponentsIsDetachedBoundedAndLowSensitivity(t *testing.T) {
	scope, plan, spec, want, _ := runtimeBindingFixture()
	_, tasksHash, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{spec})
	if err != nil {
		t.Fatal(err)
	}
	plan.TasksHash = tasksHash
	original := string(spec.Input)
	resolved, err := investigation.ResolveTaskRuntimeComponents(
		context.Background(),
		func(_ context.Context, gotScope investigation.TaskSpecScope, gotPlan domain.InvestigationPlanBinding, got investigation.TaskSpec) (investigation.TaskRuntimeComponents, error) {
			if gotScope != scope || !gotPlan.Equal(plan) {
				t.Fatalf("binder trusted facts = %#v/%#v", gotScope, gotPlan)
			}
			got.Input[0] = 'X'
			return want, nil
		},
		scope, plan, []investigation.TaskSpec{spec},
	)
	if err != nil || len(resolved) != 1 || resolved[0] != want || string(spec.Input) != original {
		t.Fatalf("ResolveTaskRuntimeComponents() = %#v, %v; source=%q", resolved, err, spec.Input)
	}

	const canary = "runtime-binder-sensitive-canary"
	for name, binder := range map[string]investigation.TaskRuntimeBinder{
		"error": func(context.Context, investigation.TaskSpecScope, domain.InvestigationPlanBinding, investigation.TaskSpec) (investigation.TaskRuntimeComponents, error) {
			return investigation.TaskRuntimeComponents{}, errors.New(canary)
		},
		"panic": func(context.Context, investigation.TaskSpecScope, domain.InvestigationPlanBinding, investigation.TaskSpec) (investigation.TaskRuntimeComponents, error) {
			panic(canary)
		},
		"invalid components": func(context.Context, investigation.TaskSpecScope, domain.InvestigationPlanBinding, investigation.TaskSpec) (investigation.TaskRuntimeComponents, error) {
			invalid := want
			invalid.TargetDigest = ""
			return invalid, nil
		},
		"wrong connector digest": func(context.Context, investigation.TaskSpecScope, domain.InvestigationPlanBinding, investigation.TaskSpec) (investigation.TaskRuntimeComponents, error) {
			invalid := want
			invalid.ConnectorDigest = strings.Repeat("9", 64)
			return invalid, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, resolveErr := investigation.ResolveTaskRuntimeComponents(context.Background(), binder, scope, plan, []investigation.TaskSpec{spec})
			if !errors.Is(resolveErr, investigation.ErrInvalidRequest) || strings.Contains(resolveErr.Error(), canary) {
				t.Fatalf("ResolveTaskRuntimeComponents() error = %v, want low-sensitivity ErrInvalidRequest", resolveErr)
			}
		})
	}
	_, err = investigation.ResolveTaskRuntimeComponents(context.Background(), func(
		context.Context, investigation.TaskSpecScope, domain.InvestigationPlanBinding, investigation.TaskSpec,
	) (investigation.TaskRuntimeComponents, error) {
		return investigation.TaskRuntimeComponents{}, fmt.Errorf("%s: %w", canary, context.Canceled)
	}, scope, plan, []investigation.TaskSpec{spec})
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), canary) {
		t.Fatalf("ResolveTaskRuntimeComponents(wrapped cancellation) error = %v, want bounded context.Canceled", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, err = investigation.ResolveTaskRuntimeComponents(ctx, func(
		context.Context, investigation.TaskSpecScope, domain.InvestigationPlanBinding, investigation.TaskSpec,
	) (investigation.TaskRuntimeComponents, error) {
		cancel()
		return want, nil
	}, scope, plan, []investigation.TaskSpec{spec})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveTaskRuntimeComponents(cancelled) error = %v", err)
	}
}

func TestReadTaskRuntimeDigestRejectsUnboundOrCallerDerivedFacts(t *testing.T) {
	scope, plan, spec, components, boundAt := runtimeBindingFixture()

	for name, mutate := range map[string]func(*investigation.TaskSpecScope, *domain.InvestigationPlanBinding, *investigation.TaskSpec, *int, *investigation.TaskRuntimeComponents, *time.Time){
		"non exact mapping": func(scope *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents, _ *time.Time) {
			scope.MappingStatus = domain.MappingAmbiguous
		},
		"invalid plan": func(_ *investigation.TaskSpecScope, plan *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents, _ *time.Time) {
			plan.RegistryDigest = ""
		},
		"non canonical input": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, spec *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents, _ *time.Time) {
			spec.Input = []byte(`{ "lookback_minutes": 15 }`)
		},
		"wrong connector suffix": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, spec *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents, _ *time.Time) {
			spec.ConnectorID = "metrics-v1-" + strings.Repeat("f", 64)
		},
		"invalid position": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, position *int, _ *investigation.TaskRuntimeComponents, _ *time.Time) {
			*position = 0
		},
		"invalid target digest": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, components *investigation.TaskRuntimeComponents, _ *time.Time) {
			components.TargetDigest = strings.Repeat("A", 64)
		},
		"zero bound time": func(_ *investigation.TaskSpecScope, _ *domain.InvestigationPlanBinding, _ *investigation.TaskSpec, _ *int, _ *investigation.TaskRuntimeComponents, boundAt *time.Time) {
			*boundAt = time.Time{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedScope, changedPlan, changedSpec, changedComponents, changedBoundAt := runtimeBindingFixture()
			position := 1
			mutate(&changedScope, &changedPlan, &changedSpec, &position, &changedComponents, &changedBoundAt)
			if _, err := investigation.BuildReadTaskRuntimeBinding(
				changedScope, changedPlan, changedSpec, position, changedComponents, changedBoundAt,
			); err == nil {
				t.Fatal("BuildReadTaskRuntimeBinding() error = nil, want rejection")
			}
		})
	}

	var binder investigation.TaskRuntimeBinder = func(
		context.Context,
		investigation.TaskSpecScope,
		domain.InvestigationPlanBinding,
		investigation.TaskSpec,
	) (investigation.TaskRuntimeComponents, error) {
		return components, nil
	}
	got, err := binder(context.Background(), scope, plan, spec)
	if err != nil || got != components {
		t.Fatalf("TaskRuntimeBinder() = %#v, %v", got, err)
	}
	_ = boundAt
}

func runtimeBindingFixture() (
	investigation.TaskSpecScope,
	domain.InvestigationPlanBinding,
	investigation.TaskSpec,
	investigation.TaskRuntimeComponents,
	time.Time,
) {
	components := investigation.TaskRuntimeComponents{
		ConnectorDigest: strings.Repeat("5", 64),
		TargetDigest:    strings.Repeat("6", 64),
		ExecutorDigest:  strings.Repeat("7", 64),
	}
	return investigation.TaskSpecScope{
			TenantID: "tenant-1", WorkspaceID: "workspace-1", EnvironmentID: "environment-1", ServiceID: "service-1",
			MappingStatus: domain.MappingExact,
		}, validPlanBindingForInvestigation(), investigation.TaskSpec{
			Key: "metrics", ConnectorID: "metrics-v1-" + components.ConnectorDigest,
			Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}, components, time.Date(2026, 7, 12, 12, 0, 0, 123000, time.UTC)
}

func validPlanBindingForInvestigation() domain.InvestigationPlanBinding {
	return domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: strings.Repeat("1", 64), RegistryDigest: strings.Repeat("2", 64),
		ProfileDigest: strings.Repeat("3", 64), TasksHash: strings.Repeat("4", 64),
	}
}
