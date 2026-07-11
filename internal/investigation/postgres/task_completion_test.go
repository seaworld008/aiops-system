package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestCompleteTaskAlwaysFailsClosedBeforeDatabaseAccess(t *testing.T) {
	repository := &Repository{}
	for _, runnerID := range []string{"", "body-controlled-runner", "write-runner"} {
		result, err := repository.CompleteTask(context.Background(), investigation.CompleteTaskRequest{
			WorkspaceID: "20000000-0000-4000-8000-000000000001",
			RunnerID:    runnerID,
		})
		if !errors.Is(err, investigation.ErrInvalidRequest) || !reflect.DeepEqual(result, investigation.CompleteTaskResult{}) {
			t.Fatalf("CompleteTask(%q) = %#v, %v; want fail closed", runnerID, result, err)
		}
	}
}
