package readrunnerclient

import (
	"bytes"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

type leaseState struct {
	mu                    sync.Mutex
	owner                 *Client
	token                 *bearer
	descriptor            readtask.Descriptor
	taskID                string
	leaseEpoch            int64
	scopeRevision         int64
	leaseExpiresAt        time.Time
	heartbeatAfterSeconds int
	heartbeatSequence     int64
	phase                 leasePhase
	busy                  bool
}

func (state *leaseState) destroy() {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.phase = leasePhaseInvalid
	state.busy = false
	token := state.token
	state.token = nil
	state.mu.Unlock()
	if token != nil {
		token.destroy()
	}
}

func (lease *Lease) ready() bool {
	if lease == nil || lease.self != lease || lease.seal != trustedLeaseSeal || lease.state == nil {
		return false
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	return lease.state.owner != nil && lease.state.token != nil &&
		(lease.state.phase == leasePhaseClaimed || lease.state.phase == leasePhaseRunning) &&
		!lease.state.busy
}

func (capability *StartCapability) ready() bool {
	if capability == nil || capability.self != capability || capability.seal != trustedStartSeal ||
		capability.lease == nil || capability.taskID == "" || capability.leaseEpoch <= 0 ||
		capability.scopeRevision <= 0 || capability.startedAt.IsZero() {
		return false
	}
	capability.lease.mu.Lock()
	defer capability.lease.mu.Unlock()
	return capability.lease.phase == leasePhaseRunning && capability.lease.taskID == capability.taskID &&
		capability.lease.leaseEpoch == capability.leaseEpoch &&
		capability.lease.scopeRevision == capability.scopeRevision &&
		!capability.lease.leaseExpiresAt.Before(time.Now().UTC().Add(minimumLeaseRemaining))
}

func cloneDescriptor(source readtask.Descriptor) readtask.Descriptor {
	cloned := source
	cloned.Input = bytes.Clone(source.Input)
	return cloned
}
