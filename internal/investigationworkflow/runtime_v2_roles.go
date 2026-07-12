package investigationworkflow

// NewBoundRuntimeV2TemporalRoles atomically validates and constructs the two
// READ control roles while holding shared lifecycle leases on both independent
// Temporal clients. Close cannot interleave with connection comparison,
// construction, or publication of either result.
//
// Production callsites are repository-gated to readassembly.Snapshot.
func NewBoundRuntimeV2TemporalRoles(
	starterClient *RuntimeV2StarterClient,
	controlClient *RuntimeV2ControlClient,
	activities *RuntimeV2Activities,
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
) (*RuntimeV2Starter, *RuntimeV2ControlWorker, error) {
	return newBoundRuntimeV2TemporalRoles(
		starterClient,
		controlClient,
		activities,
		manifestDigest,
		registryDigest,
		bundleDigest,
		runtimeV2ProductionControlWorkerFactory,
	)
}

func newBoundRuntimeV2TemporalRoles(
	starterClient *RuntimeV2StarterClient,
	controlClient *RuntimeV2ControlClient,
	activities *RuntimeV2Activities,
	manifestDigest string,
	registryDigest string,
	bundleDigest string,
	factory runtimeV2ControlWorkerFactory,
) (
	starter *RuntimeV2Starter,
	controlWorker *RuntimeV2ControlWorker,
	returnedErr error,
) {
	defer func() {
		if recover() != nil {
			starter = nil
			controlWorker = nil
			returnedErr = ErrInvalidRuntimeV2Input
		}
	}()
	if starterClient == nil || controlClient == nil || activities == nil || factory == nil ||
		!starterClient.structurallyValid() || !controlClient.structurallyValid() {
		return nil, nil, ErrInvalidRuntimeV2Input
	}

	starterClient.lifecycle.assembly.RLock()
	defer starterClient.lifecycle.assembly.RUnlock()
	controlClient.lifecycle.assembly.RLock()
	defer controlClient.lifecycle.assembly.RUnlock()

	if !starterClient.valid() || !controlClient.valid() ||
		starterClient.connection == nil || controlClient.connection == nil ||
		starterClient.namespace != controlClient.namespace ||
		starterClient.namespace != starterClient.connection.namespace ||
		controlClient.namespace != controlClient.connection.namespace ||
		!starterClient.connection.same(controlClient.connection) {
		return nil, nil, ErrInvalidRuntimeV2Input
	}
	createdStarter, err := newRuntimeV2Starter(
		starterClient, manifestDigest, registryDigest, bundleDigest,
	)
	if err != nil || createdStarter == nil {
		return nil, nil, ErrInvalidRuntimeV2Input
	}
	createdWorker, err := newRuntimeV2ControlWorker(
		controlClient,
		activities,
		manifestDigest,
		registryDigest,
		bundleDigest,
		factory,
	)
	if err != nil || createdWorker == nil {
		return nil, nil, ErrInvalidRuntimeV2Input
	}
	return createdStarter, createdWorker, nil
}
