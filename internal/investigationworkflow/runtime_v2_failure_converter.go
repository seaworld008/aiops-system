package investigationworkflow

import (
	"errors"

	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	failurepb "go.temporal.io/api/failure/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/proto"
)

const (
	runtimeV2FailureSource       = "AIOPS"
	runtimeV2FailureMaximumDepth = 3
	runtimeV2FailureRejectedType = "READ_RUNTIME_FAILURE_REJECTED"
)

var (
	errRuntimeV2FailureRejected = errors.New("investigation READ runtime failure rejected")
	runtimeV2FailureSeal        = &runtimeV2FailureMarker{value: 1}
)

type runtimeV2FailureMarker struct{ value byte }

// runtimeV2FailureConverter is the package-owned failure wire profile. The
// SDK converter is used only after every Failure graph has been normalized to
// this closed schema; raw failureHolder passthrough, details, stack traces,
// encoded attributes, and unknown failure kinds never cross the boundary.
type runtimeV2FailureConverter struct {
	delegate converter.FailureConverter
	data     *runtimeV2DataConverter
	seal     *runtimeV2FailureMarker
	self     *runtimeV2FailureConverter
}

var (
	_ converter.FailureConverter                         = (*runtimeV2FailureConverter)(nil)
	_ converter.FailureConverterWithSerializationContext = (*runtimeV2FailureConverter)(nil)
)

func newRuntimeV2FailureConverter(
	dataConverter *runtimeV2DataConverter,
) (*runtimeV2FailureConverter, error) {
	if !dataConverter.valid() {
		return nil, errRuntimeV2FailureRejected
	}
	created := &runtimeV2FailureConverter{
		delegate: temporal.NewDefaultFailureConverter(temporal.DefaultFailureConverterOptions{
			DataConverter: dataConverter,
		}),
		data: dataConverter,
		seal: runtimeV2FailureSeal,
	}
	created.self = created
	return created, nil
}

func (failureConverter *runtimeV2FailureConverter) valid() bool {
	return failureConverter != nil && failureConverter.self == failureConverter &&
		failureConverter.seal == runtimeV2FailureSeal && failureConverter.data.valid() &&
		failureConverter.delegate != nil
}

func (failureConverter *runtimeV2FailureConverter) ErrorToFailure(
	err error,
) (failure *failurepb.Failure) {
	if err == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			failure = rejectedRuntimeV2Failure()
		}
	}()
	if !failureConverter.valid() {
		return rejectedRuntimeV2Failure()
	}
	candidate := failureConverter.delegate.ErrorToFailure(err)
	normalized, ok := normalizeRuntimeV2Failure(candidate, 0)
	if !ok {
		return rejectedRuntimeV2Failure()
	}
	return normalized
}

func (failureConverter *runtimeV2FailureConverter) FailureToError(
	failure *failurepb.Failure,
) (returnedErr error) {
	if failure == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			returnedErr = temporal.NewNonRetryableApplicationError(
				errRuntimeV2FailureRejected.Error(), runtimeV2FailureRejectedType, nil,
			)
		}
	}()
	if !failureConverter.valid() {
		return temporal.NewNonRetryableApplicationError(
			errRuntimeV2FailureRejected.Error(), runtimeV2FailureRejectedType, nil,
		)
	}
	normalized, ok := normalizeRuntimeV2Failure(failure, 0)
	if !ok {
		normalized = rejectedRuntimeV2Failure()
	}
	return failureConverter.delegate.FailureToError(normalized)
}

func (failureConverter *runtimeV2FailureConverter) WithSerializationContext(
	converter.SerializationContext,
) converter.FailureConverter {
	if !failureConverter.valid() {
		return &runtimeV2FailureConverter{}
	}
	return failureConverter
}

func normalizeRuntimeV2Failure(
	failure *failurepb.Failure,
	depth int,
) (*failurepb.Failure, bool) {
	return normalizeRuntimeV2FailureGraph(failure, depth, make(map[*failurepb.Failure]struct{}))
}

func normalizeRuntimeV2FailureGraph(
	failure *failurepb.Failure,
	depth int,
	visited map[*failurepb.Failure]struct{},
) (*failurepb.Failure, bool) {
	if failure == nil {
		return nil, true
	}
	if depth > runtimeV2FailureMaximumDepth || len(failure.Message) > maximumHistoryDTOBytes ||
		len(failure.Source) > maximumHistoryDTOBytes || len(failure.ProtoReflect().GetUnknown()) != 0 ||
		failure.EncodedAttributes != nil || failure.StackTrace != "" {
		return nil, false
	}
	if _, duplicate := visited[failure]; duplicate {
		return nil, false
	}
	visited[failure] = struct{}{}
	cause, causeOK := normalizeRuntimeV2FailureGraph(failure.Cause, depth+1, visited)
	if !causeOK {
		return nil, false
	}
	normalized := &failurepb.Failure{Source: runtimeV2FailureSource, Cause: cause}
	switch info := failure.FailureInfo.(type) {
	case *failurepb.Failure_ApplicationFailureInfo:
		if info == nil || info.ApplicationFailureInfo == nil ||
			len(info.ApplicationFailureInfo.ProtoReflect().GetUnknown()) != 0 ||
			info.ApplicationFailureInfo.Details != nil || info.ApplicationFailureInfo.NextRetryDelay != nil ||
			info.ApplicationFailureInfo.Category != enumspb.APPLICATION_ERROR_CATEGORY_UNSPECIFIED {
			return nil, false
		}
		nonRetryable, allowed := runtimeV2ApplicationFailurePolicy(info.ApplicationFailureInfo.Type)
		if !allowed || nonRetryable != info.ApplicationFailureInfo.NonRetryable {
			return nil, false
		}
		normalized.Message = "investigation READ application failure"
		if info.ApplicationFailureInfo.Type == runtimeV2FailureRejectedType {
			normalized.Message = errRuntimeV2FailureRejected.Error()
		}
		normalized.FailureInfo = &failurepb.Failure_ApplicationFailureInfo{
			ApplicationFailureInfo: &failurepb.ApplicationFailureInfo{
				Type: info.ApplicationFailureInfo.Type, NonRetryable: nonRetryable,
			},
		}
	case *failurepb.Failure_CanceledFailureInfo:
		if info == nil || info.CanceledFailureInfo == nil ||
			len(info.CanceledFailureInfo.ProtoReflect().GetUnknown()) != 0 ||
			info.CanceledFailureInfo.Details != nil {
			return nil, false
		}
		normalized.Message = "investigation READ operation canceled"
		normalized.FailureInfo = &failurepb.Failure_CanceledFailureInfo{
			CanceledFailureInfo: &failurepb.CanceledFailureInfo{},
		}
	case *failurepb.Failure_TimeoutFailureInfo:
		if info == nil || info.TimeoutFailureInfo == nil ||
			len(info.TimeoutFailureInfo.ProtoReflect().GetUnknown()) != 0 ||
			info.TimeoutFailureInfo.LastHeartbeatDetails != nil ||
			!validRuntimeV2TimeoutType(info.TimeoutFailureInfo.TimeoutType) {
			return nil, false
		}
		normalized.Message = "investigation READ operation timed out"
		normalized.FailureInfo = &failurepb.Failure_TimeoutFailureInfo{
			TimeoutFailureInfo: &failurepb.TimeoutFailureInfo{TimeoutType: info.TimeoutFailureInfo.TimeoutType},
		}
	case *failurepb.Failure_ActivityFailureInfo:
		if info == nil || info.ActivityFailureInfo == nil || cause == nil ||
			len(info.ActivityFailureInfo.ProtoReflect().GetUnknown()) != 0 ||
			len(info.ActivityFailureInfo.Identity) > maximumHistoryDTOBytes ||
			len(info.ActivityFailureInfo.ActivityId) > maximumHistoryDTOBytes ||
			info.ActivityFailureInfo.ScheduledEventId < 0 || info.ActivityFailureInfo.StartedEventId < 0 ||
			!validRuntimeV2RetryState(info.ActivityFailureInfo.RetryState) ||
			info.ActivityFailureInfo.ActivityType == nil ||
			len(info.ActivityFailureInfo.ActivityType.ProtoReflect().GetUnknown()) != 0 ||
			!runtimeV2ActivityFailureTypeAllowed(info.ActivityFailureInfo.ActivityType.Name) {
			return nil, false
		}
		normalized.Message = "investigation READ activity failure"
		normalized.FailureInfo = &failurepb.Failure_ActivityFailureInfo{
			ActivityFailureInfo: &failurepb.ActivityFailureInfo{
				ScheduledEventId: info.ActivityFailureInfo.ScheduledEventId,
				StartedEventId:   info.ActivityFailureInfo.StartedEventId,
				ActivityType:     &commonpb.ActivityType{Name: info.ActivityFailureInfo.ActivityType.Name},
				RetryState:       info.ActivityFailureInfo.RetryState,
			},
		}
	case *failurepb.Failure_TerminatedFailureInfo:
		if info == nil || info.TerminatedFailureInfo == nil ||
			len(info.TerminatedFailureInfo.ProtoReflect().GetUnknown()) != 0 {
			return nil, false
		}
		normalized.Message = "investigation READ operation terminated"
		normalized.FailureInfo = &failurepb.Failure_TerminatedFailureInfo{
			TerminatedFailureInfo: &failurepb.TerminatedFailureInfo{},
		}
	case *failurepb.Failure_ServerFailureInfo:
		if info == nil || info.ServerFailureInfo == nil ||
			len(info.ServerFailureInfo.ProtoReflect().GetUnknown()) != 0 {
			return nil, false
		}
		normalized.Message = "investigation READ service failure"
		normalized.FailureInfo = &failurepb.Failure_ServerFailureInfo{
			ServerFailureInfo: &failurepb.ServerFailureInfo{NonRetryable: info.ServerFailureInfo.NonRetryable},
		}
	default:
		return nil, false
	}
	if proto.Size(normalized) > maximumHistoryDTOBytes {
		return nil, false
	}
	return normalized, true
}

func rejectedRuntimeV2Failure() *failurepb.Failure {
	return &failurepb.Failure{
		Message: errRuntimeV2FailureRejected.Error(), Source: runtimeV2FailureSource,
		FailureInfo: &failurepb.Failure_ApplicationFailureInfo{
			ApplicationFailureInfo: &failurepb.ApplicationFailureInfo{
				Type: runtimeV2FailureRejectedType, NonRetryable: true,
			},
		},
	}
}

func runtimeV2ApplicationFailurePolicy(errorType string) (nonRetryable bool, allowed bool) {
	switch errorType {
	case "PREPARE_DEPENDENCY_UNAVAILABLE", recoveryDependencyErrorType:
		return false, true
	case "PREPARE_INPUT_INVALID", "PREPARE_INTEGRITY_REJECTED", "PREPARE_FACT_CONFLICT",
		"PREPARE_RECEIPT_INVALID", "READ_PREPARE_EXECUTION_MISMATCH", "READ_PREPARE_RESULT_INVALID",
		recoveryInputInvalidErrorType, recoveryNotFoundErrorType, recoveryIntegrityRejectedErrorType,
		recoveryResultInvalidErrorType, "READ_RESULT_RECOVERY_EXECUTION_MISMATCH",
		"READ_WORKFLOW_INPUT_INVALID", "READ_WORKFLOW_EXECUTION_MISMATCH", "READ_WORKFLOW_RESULT_INVALID",
		"READ_TASK_INPUT_INVALID", "READ_TASK_ACK_PENDING", ReadTaskPendingErrorType,
		runtimeV2FailureRejectedType:
		return true, true
	default:
		return false, false
	}
}

func runtimeV2ActivityFailureTypeAllowed(activityType string) bool {
	return activityType == PrepareActivityNameV2 || activityType == RecoveryActivityNameV1 ||
		activityType == ExecuteActivityNameV1
}

func validRuntimeV2TimeoutType(timeoutType enumspb.TimeoutType) bool {
	return timeoutType.Descriptor().Values().ByNumber(timeoutType.Number()) != nil
}

func validRuntimeV2RetryState(retryState enumspb.RetryState) bool {
	return retryState.Descriptor().Values().ByNumber(retryState.Number()) != nil
}
