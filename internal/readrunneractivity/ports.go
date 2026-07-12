package readrunneractivity

import (
	"context"

	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"go.temporal.io/sdk/activity"
)

type gatewayProtocol interface {
	Claim(context.Context, readrunnerclient.ExpectedTask) (leaseSession, error)
}

type leaseSession interface {
	Descriptor() readtask.Descriptor
	LeaseEpoch() int64
	ScopeRevision() int64
	Release(context.Context, readtask.ReleaseReason) error
	Start(context.Context) (startSession, error)
	Heartbeat(context.Context, startSession, int64) (readrunnerclient.HeartbeatResult, error)
	Complete(context.Context, startSession, readrunnerclient.Completion) error
	Destroy()
}

type startSession interface {
	readRunnerActivityStart()
}

type runtimeProtocol interface {
	BundleDigest() string
	Prepare(context.Context, readtask.Descriptor, int64, int64) (preparedSession, error)
}

type preparedSession interface {
	Execute(context.Context, startSession, readexecutor.BearerSource) (readrunnerclient.Completion, error)
}

func safeBundleDigest(runtime runtimeProtocol) (digest string, err error) {
	defer func() {
		if recover() != nil {
			digest = ""
			err = ErrActivityRejected
		}
	}()
	if nilInterface(runtime) {
		return "", ErrActivityRejected
	}
	return runtime.BundleDigest(), nil
}

func safeActivityInfo(provider func(context.Context) activity.Info, ctx context.Context) (info activity.Info, err error) {
	defer func() {
		if recover() != nil {
			info = activity.Info{}
			err = ErrActivityRejected
		}
	}()
	if provider == nil {
		return activity.Info{}, ErrActivityRejected
	}
	return provider(ctx), nil
}

func safeClaim(
	gateway gatewayProtocol,
	ctx context.Context,
	expected readrunnerclient.ExpectedTask,
) (lease leaseSession, err error) {
	defer func() {
		if recover() != nil {
			lease = nil
			err = ErrActivityRejected
		}
	}()
	return gateway.Claim(ctx, expected)
}

func safePrepare(
	runtime runtimeProtocol,
	ctx context.Context,
	descriptor readtask.Descriptor,
	epoch int64,
	scopeRevision int64,
) (prepared preparedSession, err error) {
	defer func() {
		if recover() != nil {
			prepared = nil
			err = ErrActivityRejected
		}
	}()
	return runtime.Prepare(ctx, descriptor, epoch, scopeRevision)
}

func safeRelease(lease leaseSession, ctx context.Context, reason readtask.ReleaseReason) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrActivityRejected
		}
	}()
	if nilInterface(lease) {
		return ErrActivityRejected
	}
	return lease.Release(ctx, reason)
}

func safeStart(lease leaseSession, ctx context.Context) (start startSession, err error) {
	defer func() {
		if recover() != nil {
			start = nil
			err = ErrActivityRejected
		}
	}()
	if nilInterface(lease) {
		return nil, ErrActivityRejected
	}
	return lease.Start(ctx)
}

func safeGatewayHeartbeat(
	lease leaseSession,
	ctx context.Context,
	start startSession,
	sequence int64,
) (result readrunnerclient.HeartbeatResult, err error) {
	defer func() {
		if recover() != nil {
			result = readrunnerclient.HeartbeatResult{}
			err = ErrActivityRejected
		}
	}()
	return lease.Heartbeat(ctx, start, sequence)
}

func safeTemporalHeartbeat(recorder func(context.Context), ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrActivityRejected
		}
	}()
	if recorder == nil {
		return ErrActivityRejected
	}
	recorder(ctx)
	return nil
}

func safeExecute(
	prepared preparedSession,
	ctx context.Context,
	start startSession,
	credentials readexecutor.BearerSource,
) (completion readrunnerclient.Completion, err error) {
	defer func() {
		if recover() != nil {
			completion = readrunnerclient.Completion{}
			err = ErrActivityRejected
		}
	}()
	return prepared.Execute(ctx, start, credentials)
}

func safeComplete(
	lease leaseSession,
	ctx context.Context,
	start startSession,
	completion readrunnerclient.Completion,
) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrActivityRejected
		}
	}()
	return lease.Complete(ctx, start, completion)
}

func safeDestroy(lease leaseSession) {
	defer func() { _ = recover() }()
	if !nilInterface(lease) {
		lease.Destroy()
	}
}
