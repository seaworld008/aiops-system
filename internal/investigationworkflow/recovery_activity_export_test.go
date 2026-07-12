package investigationworkflow

import "context"

func RecoverActivityForTest(
	activities *RecoveryActivities,
	ctx context.Context,
	input RecoveryActivityInput,
) (RecoveryActivityOutput, error) {
	return activities.recoverActivity(ctx, input)
}
