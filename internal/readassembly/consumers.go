package readassembly

import (
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readrunneractivity"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
)

// NewRuntimeV2TemporalRoles constructs both Temporal control roles from this
// exact Snapshot. The caller cannot override the namespace, task queue,
// planning digests, data converter, registrations, or Worker options.
//
// The two clients are caller-owned and deliberately remain separate so a
// process supervisor can enforce Worker.Stop -> control Close -> starter Close.
func (snapshot *Snapshot) NewRuntimeV2TemporalRoles(
	starterClient *investigationworkflow.RuntimeV2StarterClient,
	controlClient *investigationworkflow.RuntimeV2ControlClient,
	reader investigation.SignalRegistrationReader,
	repository investigation.Repository,
	recovery *investigationworkflow.RecoveryActivities,
) (
	starter *investigationworkflow.RuntimeV2Starter,
	controlWorker *investigationworkflow.RuntimeV2ControlWorker,
	returnedErr error,
) {
	defer func() {
		if recover() != nil {
			starter = nil
			controlWorker = nil
			returnedErr = investigationworkflow.ErrInvalidRuntimeV2Input
		}
	}()
	if !snapshot.Ready() || starterClient == nil || controlClient == nil {
		return nil, nil, investigationworkflow.ErrInvalidRuntimeV2Input
	}
	controlNamespace := controlClient.Namespace()
	if controlNamespace == "" {
		return nil, nil, investigationworkflow.ErrInvalidRuntimeV2Input
	}
	activities, err := snapshot.newRuntimeV2Activities(reader, repository, recovery, controlNamespace)
	if err != nil || activities == nil {
		return nil, nil, investigationworkflow.ErrInvalidRuntimeV2Input
	}
	createdStarter, createdWorker, err := investigationworkflow.NewBoundRuntimeV2TemporalRoles(
		starterClient,
		controlClient,
		activities,
		snapshot.summary.PlanManifestDigest,
		snapshot.summary.ConnectorRegistryDigest,
		snapshot.summary.BundleDigest,
	)
	if err != nil || createdStarter == nil || createdWorker == nil {
		return nil, nil, investigationworkflow.ErrInvalidRuntimeV2Input
	}
	return createdStarter, createdWorker, nil
}

// newRuntimeV2Activities constructs the control-side Temporal Activities with
// the private authority and Planner from this exact Snapshot. It remains
// package-private so callers cannot bypass NewRuntimeV2TemporalRoles and
// recombine the result with a foreign Temporal client or routing identity.
func (snapshot *Snapshot) newRuntimeV2Activities(
	reader investigation.SignalRegistrationReader,
	repository investigation.Repository,
	recovery *investigationworkflow.RecoveryActivities,
	namespace string,
) (activities *investigationworkflow.RuntimeV2Activities, returnedErr error) {
	defer func() {
		if recover() != nil {
			activities = nil
			returnedErr = investigationworkflow.ErrInvalidRuntimeV2Input
		}
	}()
	if !snapshot.Ready() {
		return nil, investigationworkflow.ErrInvalidRuntimeV2Input
	}
	preparation, err := investigationworkflow.NewActivities(reader, repository, snapshot.authority, snapshot.planner)
	if err != nil || preparation == nil {
		return nil, investigationworkflow.ErrInvalidRuntimeV2Input
	}
	created, err := investigationworkflow.NewRuntimeV2Activities(
		preparation, recovery, snapshot.summary.BundleDigest, namespace,
	)
	if err != nil || created == nil {
		return nil, investigationworkflow.ErrInvalidRuntimeV2Input
	}
	return created, nil
}

// NewReadRunnerActivities constructs the READ Activity implementation with
// this Snapshot's private Bundle. It intentionally accepts only the sealed
// mTLS client and never exposes Prepare, Execute, or the Bundle to callers.
func (snapshot *Snapshot) NewReadRunnerActivities(
	client *readrunnerclient.Client,
	credentials readexecutor.BearerSource,
	namespace string,
) (activities *readrunneractivity.Activities, returnedErr error) {
	defer func() {
		if recover() != nil {
			activities = nil
			returnedErr = readrunneractivity.ErrActivityRejected
		}
	}()
	if !snapshot.Ready() {
		return nil, readrunneractivity.ErrActivityRejected
	}
	created, err := readrunneractivity.NewActivities(
		client, snapshot.bundle, snapshot.summary.PlanManifestDigest, credentials, namespace,
	)
	if err != nil || created == nil || !created.AcceptsPlanningIdentity(
		snapshot.summary.PlanManifestDigest,
		snapshot.summary.ConnectorRegistryDigest,
		snapshot.summary.BundleDigest,
	) {
		return nil, readrunneractivity.ErrActivityRejected
	}
	return created, nil
}
