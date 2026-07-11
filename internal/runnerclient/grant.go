package runnerclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
)

// ExecutorBinding is the complete non-secret identity of the action admitted
// through the executor READY barrier.
type ExecutorBinding struct {
	JobID               string
	PlanHash            string
	EnvironmentRevision string
	LeaseEpoch          int64
	ScopeRevision       int64
	Production          bool
	Payload             action.Envelope
}

func (binding *jobLeaseBinding) notify() {
	if binding == nil || binding.updates == nil {
		return
	}
	select {
	case binding.updates <- struct{}{}:
	default:
	}
}

func (binding *jobLeaseBinding) updateHeartbeat(directive string, expiresAt time.Time) bool {
	if binding == nil || expiresAt.IsZero() {
		return false
	}
	binding.runtimeMu.Lock()
	defer binding.runtimeMu.Unlock()
	if binding.terminationRequested {
		return directive == "TERMINATE"
	}
	if directive == "TERMINATE" {
		binding.terminationRequested = true
	} else if directive == "CONTINUE" {
		if !expiresAt.After(time.Now().UTC()) {
			return false
		}
		binding.runtimeLeaseExpiresAt = expiresAt.UTC()
	} else {
		return false
	}
	binding.notify()
	return true
}

func (binding *jobLeaseBinding) terminate() {
	if binding == nil {
		return
	}
	binding.runtimeMu.Lock()
	binding.terminationRequested = true
	binding.runtimeMu.Unlock()
	binding.notify()
}

func (binding *jobLeaseBinding) runtimeSnapshot() (time.Time, bool) {
	if binding == nil {
		return time.Time{}, true
	}
	binding.runtimeMu.Lock()
	defer binding.runtimeMu.Unlock()
	return binding.runtimeLeaseExpiresAt, binding.terminationRequested
}

func (state *credentialPreparationState) currentPhase() credentialPhase {
	if state == nil {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.phase
}

func (state *credentialPreparationState) transition(from []credentialPhase, to credentialPhase) bool {
	if state == nil || to == 0 {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, candidate := range from {
		if state.phase == candidate {
			state.phase = to
			return true
		}
	}
	return state.phase == to
}

// BindExecutor atomically verifies the READY action against the private
// Gateway lease and ACTIVE credential state, then returns a context that is
// cancelled by a sticky TERMINATE directive or by the current lease expiry.
func (grant *ExecutionGrant) BindExecutor(
	parent context.Context,
	executor ExecutorBinding,
) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil || grant == nil || grant.state == nil || grant.state.lease == nil ||
		!grant.consumeIfValid(func() bool {
			return grant.state.currentPhase() == credentialPhaseActive &&
				validExecutorGrant(grant.state, executor, time.Now().UTC())
		}) {
		return nil, nil, ErrInvalidResponse
	}
	ctx, cancel := context.WithCancel(parent)
	go monitorExecutionLease(ctx, cancel, grant.state)
	return ctx, cancel, nil
}

func (grant *ExecutionGrant) consumeIfValid(valid func() bool) bool {
	if grant == nil || valid == nil {
		return false
	}
	grant.mu.Lock()
	defer grant.mu.Unlock()
	if grant.consumed || !valid() {
		return false
	}
	grant.consumed = true
	return true
}

func validExecutorGrant(state *credentialPreparationState, executor ExecutorBinding, now time.Time) bool {
	lease := state.lease
	if lease == nil || lease.owner == nil || lease.token == nil || !lease.token.alive() ||
		executor.JobID != lease.jobID || executor.PlanHash != lease.planHash ||
		executor.LeaseEpoch != lease.leaseEpoch || executor.ScopeRevision != lease.scopeRevision || executor.Production ||
		executor.JobID != executor.Payload.ActionID || executor.PlanHash != executor.Payload.PlanHash ||
		executor.EnvironmentRevision == "" || executor.Payload.ValidateAt(now) != nil ||
		!now.Before(state.credentialExpiresAt) {
		return false
	}
	expiresAt, terminated := lease.runtimeSnapshot()
	if terminated || !expiresAt.After(now) {
		return false
	}
	descriptor := runnergateway.JobDescriptor{
		ID: executor.JobID, Kind: "WRITE_ACTION", Payload: executor.Payload, PlanHash: executor.PlanHash,
		EnvironmentRevision: executor.EnvironmentRevision, Production: false,
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return digest == lease.descriptorSHA256
}

func monitorExecutionLease(ctx context.Context, cancel context.CancelFunc, state *credentialPreparationState) {
	defer cancel()
	for {
		expiresAt, terminated := state.lease.runtimeSnapshot()
		deadline := expiresAt
		if state.credentialExpiresAt.Before(deadline) {
			deadline = state.credentialExpiresAt
		}
		if terminated || !deadline.After(time.Now().UTC()) {
			return
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-state.lease.updates:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			return
		}
	}
}
