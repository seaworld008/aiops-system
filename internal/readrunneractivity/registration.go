package readrunneractivity

import (
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"go.temporal.io/sdk/activity"
)

// Registry is the minimal Temporal registration surface. Register installs
// exactly one custom-named READ Activity and no workflow or alias.
type Registry interface {
	RegisterActivityWithOptions(interface{}, activity.RegisterOptions)
}

func Register(registry Registry, activities *Activities) (returnedErr error) {
	if nilInterface(registry) || !activities.ready() {
		return ErrActivityRejected
	}
	defer func() {
		if recover() != nil {
			returnedErr = ErrActivityRejected
		}
	}()
	registry.RegisterActivityWithOptions(
		activities.execute,
		activity.RegisterOptions{Name: investigationworkflow.ExecuteActivityNameV1},
	)
	return nil
}
