package readrunneractivity

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/readruntime"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"go.temporal.io/sdk/activity"
)

// NewActivities accepts only the concrete, sealed READ Gateway client,
// immutable runtime Bundle, and exact reviewed Plan manifest digest. The
// connector registry identity is derived from the Bundle, never from a task.
// Tests use the private constructor; production has no fake, anonymous,
// unpinned, or credential-free fallback.
func NewActivities(
	client *readrunnerclient.Client,
	bundle *readruntime.Bundle,
	planManifestDigest string,
	credentials readexecutor.BearerSource,
	namespace string,
) (*Activities, error) {
	runtimeSummary := readruntime.Summary{}
	if bundle != nil {
		runtimeSummary = bundle.Summary()
	}
	if client == nil || !client.Ready() || bundle == nil || !bundle.Ready() || credentials == nil ||
		!investigationworkflow.ValidTemporalNamespace(namespace) || !domain.ValidSHA256Hex(planManifestDigest) ||
		runtimeSummary.Validate() != nil {
		return nil, ErrActivityRejected
	}
	registryDigest := runtimeSummary.ConnectorRegistryDigest
	runtime := &planBoundRuntime{
		inner: &bundleRuntime{bundle: bundle}, planManifestDigest: strings.Clone(planManifestDigest),
		connectorRegistryDigest: strings.Clone(registryDigest),
	}
	return newActivities(
		&clientGateway{client: client},
		runtime,
		credentials,
		activityRuntime{
			info:      activity.GetInfo,
			heartbeat: func(ctx context.Context) { activity.RecordHeartbeat(ctx) },
			interval:  temporalHeartbeatInterval,
		},
		gatewayHeartbeatInterval,
		namespace,
		planManifestDigest,
		registryDigest,
	)
}

type clientGateway struct{ client *readrunnerclient.Client }

func (gateway *clientGateway) Claim(
	ctx context.Context,
	expected readrunnerclient.ExpectedTask,
) (leaseSession, error) {
	if gateway == nil || gateway.client == nil || !gateway.client.Ready() {
		return nil, ErrActivityRejected
	}
	lease, err := gateway.client.Claim(ctx, expected)
	if err != nil {
		if lease != nil {
			lease.Destroy()
		}
		return nil, err
	}
	if lease == nil {
		return nil, nil
	}
	return &clientLease{client: gateway.client, lease: lease}, nil
}

type clientLease struct {
	client *readrunnerclient.Client
	lease  *readrunnerclient.Lease
}

func (lease *clientLease) Descriptor() readtask.Descriptor {
	if lease == nil || lease.lease == nil {
		return readtask.Descriptor{}
	}
	return lease.lease.Descriptor()
}
func (lease *clientLease) LeaseEpoch() int64 {
	if lease == nil || lease.lease == nil {
		return 0
	}
	return lease.lease.LeaseEpoch()
}
func (lease *clientLease) ScopeRevision() int64 {
	if lease == nil || lease.lease == nil {
		return 0
	}
	return lease.lease.ScopeRevision()
}
func (lease *clientLease) Release(ctx context.Context, reason readtask.ReleaseReason) error {
	if lease == nil || lease.client == nil || lease.lease == nil {
		return ErrActivityRejected
	}
	return lease.client.Release(ctx, lease.lease, reason)
}

type clientStart struct {
	capability *readrunnerclient.StartCapability
	execution  *readexecutor.ExecutionStart
}

func (*clientStart) readRunnerActivityStart() {}

func (lease *clientLease) Start(ctx context.Context) (startSession, error) {
	if lease == nil || lease.client == nil || lease.lease == nil {
		return nil, ErrActivityRejected
	}
	capability, err := lease.client.Start(ctx, lease.lease)
	if err != nil {
		return nil, err
	}
	execution, err := readexecutor.NewExecutionStart(capability)
	if err != nil {
		return nil, ErrActivityRejected
	}
	return &clientStart{capability: capability, execution: execution}, nil
}

func (lease *clientLease) Heartbeat(
	ctx context.Context,
	start startSession,
	sequence int64,
) (readrunnerclient.HeartbeatResult, error) {
	trusted, ok := start.(*clientStart)
	if !ok || trusted == nil || trusted.capability == nil || lease == nil || lease.client == nil || lease.lease == nil {
		return readrunnerclient.HeartbeatResult{}, ErrActivityRejected
	}
	return lease.client.Heartbeat(ctx, lease.lease, trusted.capability, sequence)
}

func (lease *clientLease) Complete(
	ctx context.Context,
	start startSession,
	completion readrunnerclient.Completion,
) error {
	trusted, ok := start.(*clientStart)
	if !ok || trusted == nil || trusted.capability == nil || lease == nil || lease.client == nil || lease.lease == nil {
		return ErrActivityRejected
	}
	_, err := lease.client.Complete(ctx, lease.lease, trusted.capability, completion)
	return err
}

func (lease *clientLease) Destroy() {
	if lease != nil && lease.lease != nil {
		lease.lease.Destroy()
	}
}

type planBoundRuntime struct {
	inner                   runtimeProtocol
	planManifestDigest      string
	connectorRegistryDigest string
}

func (runtime *planBoundRuntime) BundleDigest() string {
	if runtime == nil || nilInterface(runtime.inner) {
		return ""
	}
	return runtime.inner.BundleDigest()
}

func (runtime *planBoundRuntime) Prepare(
	ctx context.Context,
	descriptor readtask.Descriptor,
	epoch int64,
	scopeRevision int64,
) (preparedSession, error) {
	if runtime == nil || nilInterface(runtime.inner) {
		return nil, ErrActivityRejected
	}
	if descriptor.PlanBinding.Validate() != nil || !domain.ValidSHA256Hex(runtime.planManifestDigest) ||
		!domain.ValidSHA256Hex(runtime.connectorRegistryDigest) ||
		subtle.ConstantTimeCompare(
			[]byte(descriptor.PlanBinding.ManifestDigest), []byte(runtime.planManifestDigest),
		) != 1 || subtle.ConstantTimeCompare(
		[]byte(descriptor.PlanBinding.RegistryDigest), []byte(runtime.connectorRegistryDigest),
	) != 1 {
		return nil, ErrActivityRejected
	}
	return runtime.inner.Prepare(ctx, descriptor, epoch, scopeRevision)
}

type bundleRuntime struct{ bundle *readruntime.Bundle }

func (runtime *bundleRuntime) BundleDigest() string {
	if runtime == nil || runtime.bundle == nil || !runtime.bundle.Ready() {
		return ""
	}
	return runtime.bundle.Digest()
}

func (runtime *bundleRuntime) Prepare(
	ctx context.Context,
	descriptor readtask.Descriptor,
	epoch int64,
	scopeRevision int64,
) (preparedSession, error) {
	if runtime == nil || runtime.bundle == nil || !runtime.bundle.Ready() {
		return nil, ErrActivityRejected
	}
	prepared, err := runtime.bundle.Prepare(ctx, descriptor, epoch, scopeRevision)
	if err != nil {
		return nil, err
	}
	return &bundlePrepared{bundle: runtime.bundle, prepared: prepared}, nil
}

type bundlePrepared struct {
	bundle   *readruntime.Bundle
	prepared *readruntime.Prepared
}

func (prepared *bundlePrepared) Execute(
	ctx context.Context,
	start startSession,
	credentials readexecutor.BearerSource,
) (readrunnerclient.Completion, error) {
	trusted, ok := start.(*clientStart)
	if !ok || trusted == nil || trusted.execution == nil || prepared == nil || prepared.bundle == nil ||
		prepared.prepared == nil || credentials == nil {
		return readrunnerclient.Completion{}, ErrActivityRejected
	}
	result, err := prepared.bundle.Execute(ctx, prepared.prepared, trusted.execution, credentials)
	if err != nil {
		return readrunnerclient.Completion{}, err
	}
	completion, err := result.Completion(trusted.execution)
	if err != nil {
		return readrunnerclient.Completion{}, ErrActivityRejected
	}
	return completion, nil
}
