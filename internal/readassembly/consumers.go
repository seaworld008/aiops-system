package readassembly

import (
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readrunneractivity"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
)

// NewRuntimeV2Activities constructs the control-side Temporal Activities with
// the private authority and Planner from this exact Snapshot. Callers receive
// no component that can be recombined with a foreign planning graph.
func (snapshot *Snapshot) NewRuntimeV2Activities(
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
