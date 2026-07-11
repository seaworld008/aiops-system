package postgres

import (
	"context"
	"fmt"

	"github.com/seaworld008/aiops-system/internal/investigation"
)

// CompleteTask is deliberately not a Runner ingress. The authenticated M5B
// path derives runner identity and exact scope from mTLS and performs those
// checks in the same transaction as the evidence receipt.
func (*Repository) CompleteTask(
	context.Context,
	investigation.CompleteTaskRequest,
) (investigation.CompleteTaskResult, error) {
	return investigation.CompleteTaskResult{}, fmt.Errorf(
		"%w: authenticated READ Runner ingress is required",
		investigation.ErrInvalidRequest,
	)
}
