package readrunneractivity

import (
	"errors"
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"go.temporal.io/sdk/activity"
)

func TestRegisterInstallsExactlyOneCustomNamedReadActivity(t *testing.T) {
	input := validActivityInput()
	activities := newTestActivities(t, input, &fakeGateway{}, &fakeRuntime{}, 1, nil)
	registry := &fakeRegistry{}
	if err := Register(registry, activities); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if registry.calls != 1 || registry.options.Name != investigationworkflow.ExecuteActivityNameV1 || registry.value == nil {
		t.Fatalf("registration = calls:%d name:%q value:%#v", registry.calls, registry.options.Name, registry.value)
	}

	copy := *activities
	if err := Register(&fakeRegistry{}, &copy); !errors.Is(err, ErrActivityRejected) {
		t.Fatalf("Register(copied activities) error = %v", err)
	}
	var nilRegistry *fakeRegistry
	if err := Register(nilRegistry, activities); !errors.Is(err, ErrActivityRejected) {
		t.Fatalf("Register(typed nil registry) error = %v", err)
	}
}

type fakeRegistry struct {
	calls   int
	value   interface{}
	options activity.RegisterOptions
}

func (registry *fakeRegistry) RegisterActivityWithOptions(value interface{}, options activity.RegisterOptions) {
	registry.calls++
	registry.value = value
	registry.options = options
}
