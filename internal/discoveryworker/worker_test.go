package discoveryworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/leasefence"
)

func TestNewFailsClosedForEveryMissingDependency(t *testing.T) {
	valid := validWorkerDependencies(t)
	tests := map[string]func(*Dependencies){
		"queue":                  func(value *Dependencies) { value.Queue = nil },
		"cleanup broker":         func(value *Dependencies) { value.CleanupBroker = nil },
		"limiter":                func(value *Dependencies) { value.Limiter = nil },
		"page committer":         func(value *Dependencies) { value.PageCommitter = nil },
		"checkpoint codec":       func(value *Dependencies) { value.Checkpoints = nil },
		"claim runtime resolver": func(value *Dependencies) { value.ClaimRuntimeResolver = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if worker, err := New(candidate); worker != nil || !errors.Is(err, ErrInvalidDependencies) {
				t.Fatalf("New() = %#v,%v, want nil,ErrInvalidDependencies", worker, err)
			}
		})
	}

	var typedQueue *dependencyQueue
	var typedLimiter *dependencyLimiter
	var typedCommitter *dependencyPageCommitter
	var typedResolver *dependencyRuntimeResolver
	typedNil := map[string]func(*Dependencies){
		"queue":                  func(value *Dependencies) { value.Queue = typedQueue },
		"limiter":                func(value *Dependencies) { value.Limiter = typedLimiter },
		"page committer":         func(value *Dependencies) { value.PageCommitter = typedCommitter },
		"claim runtime resolver": func(value *Dependencies) { value.ClaimRuntimeResolver = typedResolver },
	}
	for name, mutate := range typedNil {
		t.Run("typed nil "+name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if worker, err := New(candidate); worker != nil || !errors.Is(err, ErrInvalidDependencies) {
				t.Fatalf("New() = %#v,%v, want nil,ErrInvalidDependencies", worker, err)
			}
		})
	}

	if worker, err := New(valid); err != nil || worker == nil {
		t.Fatalf("New(valid) = %#v,%v", worker, err)
	}
}

func TestProviderClaimUsesExactOpenedAttemptOrder(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(context.Background(), &fixture.claim); err != nil {
		t.Fatalf("processClaim() error = %v", err)
	}

	assertOrderedEvents(t, fixture.events.snapshot(),
		"limiter-acquire",
		"reserve-attempt",
		"open-session",
		"bind-runtime",
		"resolve-runtime",
		"heartbeat",
		"provider-validate",
		"heartbeat",
		"limiter-release",
		"propose-validation",
		"runtime-clear",
		"revoke-session",
		"record-cleanup",
		"complete",
	)
	if fixture.authority.openCalls != 1 || fixture.authority.resolveCalls != 1 ||
		fixture.provider.validateCalls != 1 || fixture.provider.discoverCalls != 0 {
		t.Fatalf("calls open=%d resolve=%d validate=%d discover=%d",
			fixture.authority.openCalls, fixture.authority.resolveCalls,
			fixture.provider.validateCalls, fixture.provider.discoverCalls)
	}
	cell := fixture.authority.cells[fixture.attempt.AttemptID]
	if cell == nil || cell.bindCalls != 1 || !cell.runtimeCleared || cell.revokeCalls != 1 {
		t.Fatalf("exact attempt runtime cell = %#v, want bind/clear/revoke once", cell)
	}
	if fixture.queue.lastProof.Attempt() != fixture.attempt ||
		fixture.queue.lastProof.Coordinates() != fixture.coordinates {
		t.Fatalf("cleanup proof drifted: attempt=%#v coordinates=%#v",
			fixture.queue.lastProof.Attempt(), fixture.queue.lastProof.Coordinates())
	}
}

func TestProviderClaimRejectsResolverRuntimeOutsideBrokerAttempt(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	fixture.authority.resolveWithForeignRuntime = true
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(
		context.Background(),
		&fixture.claim,
	); !errors.Is(err, ErrClaimRejected) {
		t.Fatalf("processClaim(foreign runtime) error = %v, want ErrClaimRejected", err)
	}
	if fixture.provider.validateCalls != 0 {
		t.Fatalf("Provider calls with foreign runtime = %d, want 0",
			fixture.provider.validateCalls)
	}
	exactCell := fixture.authority.cells[fixture.attempt.AttemptID]
	foreignCell := fixture.authority.foreignCell
	if exactCell == nil || foreignCell == nil ||
		exactCell.bindCalls != 1 || foreignCell.bindCalls != 1 ||
		!exactCell.runtimeCleared || !foreignCell.runtimeCleared ||
		exactCell.revokeCalls != 1 ||
		fixture.queue.recordCleanupCalls != 1 || fixture.queue.failCalls != 1 {
		t.Fatalf(
			"foreign runtime exact=%#v foreign=%#v cleanup=%d fail=%d",
			exactCell, foreignCell,
			fixture.queue.recordCleanupCalls, fixture.queue.failCalls,
		)
	}
	assertOrderedEvents(t, fixture.events.snapshot(),
		"open-session",
		"bind-runtime",
		"resolve-runtime",
		"bind-foreign-runtime",
		"foreign-runtime-clear",
		"runtime-clear",
		"revoke-session",
		"record-cleanup",
	)
}

func TestProviderClaimRejectsUnavailableBrokerRuntimeBeforeResolver(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*modeAttemptAuthority)
		wantBinds   int
		wantCleared bool
	}{
		{
			name: "handle has no runtime",
			configure: func(authority *modeAttemptAuthority) {
				authority.noRuntimeHandle = true
			},
		},
		{
			name: "runtime binding drift",
			configure: func(authority *modeAttemptAuthority) {
				authority.runtimeBindingDrift = true
			},
			wantBinds: 1, wantCleared: true,
		},
		{
			name: "inactive runtime",
			configure: func(authority *modeAttemptAuthority) {
				authority.inactiveRuntime = true
			},
			wantBinds: 1, wantCleared: true,
		},
		{
			name: "runtime bind failure",
			configure: func(authority *modeAttemptAuthority) {
				authority.runtimeBindErr = errors.New("runtime secret must not escape")
			},
			wantBinds: 1, wantCleared: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
			test.configure(fixture.authority)
			worker, err := New(fixture.dependencies())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			processErr := worker.processClaim(
				context.Background(),
				&fixture.claim,
			)
			if !errors.Is(processErr, ErrClaimRejected) {
				t.Fatalf("processClaim(runtime rejection) error = %v, want ErrClaimRejected", processErr)
			}
			if strings.Contains(processErr.Error(), "runtime secret") {
				t.Fatalf("processClaim(runtime rejection) leaked bind error = %v", processErr)
			}
			cell := fixture.authority.cells[fixture.attempt.AttemptID]
			if cell == nil || cell.bindCalls != test.wantBinds ||
				cell.runtimeCleared != test.wantCleared || cell.revokeCalls != 1 ||
				fixture.authority.resolveCalls != 0 ||
				fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 ||
				fixture.queue.recordCleanupCalls != 1 || fixture.queue.failCalls != 1 {
				t.Fatalf(
					"runtime rejection cell=%#v resolve=%d validate=%d discover=%d cleanup=%d fail=%d",
					cell, fixture.authority.resolveCalls,
					fixture.provider.validateCalls, fixture.provider.discoverCalls,
					fixture.queue.recordCleanupCalls, fixture.queue.failCalls,
				)
			}
		})
	}
}

func TestProviderClaimRejectsOpenAttemptDriftBeforePersistOrRevoke(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	driftedCoordinates := fixture.coordinates
	driftedCoordinates.RunID = runtimeRunID2
	driftedAttempt := fixture.attempt
	driftedAttempt.RunID = runtimeRunID2
	driftedAttempt.AttemptEpoch++
	session, err := fixture.broker.OpenAttempt(
		context.Background(),
		discoverycleanup.OpenAttemptRequest{
			Coordinates: driftedCoordinates,
			Attempt:     driftedAttempt,
		},
	)
	if err != nil {
		t.Fatalf("OpenAttempt(drift setup) error = %v", err)
	}
	session.Destroy()
	fixture.events.reset()

	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(
		context.Background(),
		&fixture.claim,
	); !errors.Is(err, ErrClaimRejected) {
		t.Fatalf("processClaim(open drift) error = %v, want ErrClaimRejected", err)
	}
	cell := fixture.authority.cells[fixture.attempt.AttemptID]
	if cell == nil || cell.revokeCalls != 0 ||
		fixture.queue.hasPendingDelay || fixture.limiter.delayCalls != 0 ||
		fixture.queue.recordCleanupCalls != 0 ||
		fixture.authority.resolveCalls != 0 ||
		fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 {
		t.Fatalf(
			"open drift cell=%#v pending-delay=%t limiter-delay=%d cleanup=%d "+
				"resolve=%d validate=%d discover=%d",
			cell, fixture.queue.hasPendingDelay, fixture.limiter.delayCalls,
			fixture.queue.recordCleanupCalls, fixture.authority.resolveCalls,
			fixture.provider.validateCalls, fixture.provider.discoverCalls,
		)
	}
}

func TestProviderClaimRejectsUnavailableOpenBeforePersistOrRevoke(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	fixture.broker.Destroy()

	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(
		context.Background(),
		&fixture.claim,
	); !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("processClaim(unavailable open) error = %v, want ErrWorkerUnavailable", err)
	}
	if fixture.queue.hasPendingDelay || fixture.limiter.delayCalls != 0 ||
		fixture.queue.recordCleanupCalls != 0 ||
		fixture.authority.openCalls != 0 || fixture.authority.resolveCalls != 0 ||
		fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 {
		t.Fatalf(
			"unavailable open pending-delay=%t limiter-delay=%d cleanup=%d "+
				"open=%d resolve=%d validate=%d discover=%d",
			fixture.queue.hasPendingDelay, fixture.limiter.delayCalls,
			fixture.queue.recordCleanupCalls, fixture.authority.openCalls,
			fixture.authority.resolveCalls, fixture.provider.validateCalls,
			fixture.provider.discoverCalls,
		)
	}
}

func TestCleanupOnlyAndTerminalClaimsNeverResolveRuntime(t *testing.T) {
	for _, mode := range []discoveryqueue.ClaimMode{
		discoveryqueue.ClaimModeCleanupOnly,
		discoveryqueue.ClaimModeTerminal,
	} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newWorkerModeFixture(t, mode)
			request := discoverycleanup.OpenAttemptRequest{
				Coordinates: fixture.coordinates, Attempt: fixture.attempt,
			}
			session, err := fixture.broker.OpenAttempt(context.Background(), request)
			if err != nil {
				t.Fatalf("OpenAttempt(setup) error = %v", err)
			}
			session.Destroy()
			if mode == discoveryqueue.ClaimModeTerminal {
				proof, err := fixture.broker.RevokeAttempt(context.Background(), fixture.attempt.AttemptID)
				if err != nil {
					t.Fatalf("RevokeAttempt(setup) error = %v", err)
				}
				proof.Destroy()
				fixture.claim.Run.CredentialCleanupStatus = assetcatalog.CredentialCleanupRevoked
			}
			fixture.events.reset()

			worker, err := New(fixture.dependencies())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if err := worker.processClaim(context.Background(), &fixture.claim); err != nil {
				t.Fatalf("processClaim() error = %v", err)
			}
			if fixture.authority.resolveCalls != 0 ||
				fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 {
				t.Fatalf("mode %s resolved/called Provider: resolve=%d validate=%d discover=%d",
					mode, fixture.authority.resolveCalls,
					fixture.provider.validateCalls, fixture.provider.discoverCalls)
			}
			if fixture.queue.heartbeatCalls != 0 || fixture.limiter.acquireCalls != 0 {
				t.Fatalf("mode %s touched Provider admission: heartbeat=%d acquire=%d",
					mode, fixture.queue.heartbeatCalls, fixture.limiter.acquireCalls)
			}
			if mode == discoveryqueue.ClaimModeCleanupOnly {
				assertOrderedEvents(t, fixture.events.snapshot(),
					"revoke-session", "record-cleanup", "delay")
			} else {
				assertOrderedEvents(t, fixture.events.snapshot(),
					"record-cleanup", "complete")
			}
			cell := fixture.authority.cells[fixture.attempt.AttemptID]
			if fixture.authority.openCalls != 1 || cell == nil || cell.revokeCalls != 1 {
				t.Fatalf("Broker replay opened/revoked again: open=%d cell=%#v",
					fixture.authority.openCalls, cell)
			}
		})
	}
}

func TestCleanupClaimsRejectOpenAttemptDriftBeforeRevoke(t *testing.T) {
	for _, mode := range []discoveryqueue.ClaimMode{
		discoveryqueue.ClaimModeCleanupOnly,
		discoveryqueue.ClaimModeTerminal,
	} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newWorkerModeFixture(t, mode)
			driftedCoordinates := fixture.coordinates
			driftedCoordinates.RunID = runtimeRunID2
			driftedAttempt := fixture.attempt
			driftedAttempt.RunID = runtimeRunID2
			driftedAttempt.AttemptEpoch++
			session, err := fixture.broker.OpenAttempt(
				context.Background(),
				discoverycleanup.OpenAttemptRequest{
					Coordinates: driftedCoordinates,
					Attempt:     driftedAttempt,
				},
			)
			if err != nil {
				t.Fatalf("OpenAttempt(drift setup) error = %v", err)
			}
			session.Destroy()
			fixture.events.reset()

			worker, err := New(fixture.dependencies())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if err := worker.processClaim(
				context.Background(),
				&fixture.claim,
			); !errors.Is(err, ErrClaimRejected) {
				t.Fatalf("processClaim(open drift) error = %v, want ErrClaimRejected", err)
			}
			cell := fixture.authority.cells[fixture.attempt.AttemptID]
			if cell == nil || cell.revokeCalls != 0 ||
				fixture.queue.recordCleanupCalls != 0 ||
				fixture.authority.resolveCalls != 0 ||
				fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 {
				t.Fatalf(
					"open drift cell=%#v cleanup=%d resolve=%d validate=%d discover=%d",
					cell, fixture.queue.recordCleanupCalls, fixture.authority.resolveCalls,
					fixture.provider.validateCalls, fixture.provider.discoverCalls,
				)
			}
		})
	}
}

func TestCleanupClaimsRecordExactOpenFailuresAsUncertain(t *testing.T) {
	tests := []struct {
		name              string
		openErr           error
		withoutHandle     bool
		wantOpenErr       error
		wantHandleRevokes int
	}{
		{
			name:              "handle plus authentication error",
			openErr:           discoverycleanup.ErrSessionAuthentication,
			wantOpenErr:       discoverycleanup.ErrSessionAuthentication,
			wantHandleRevokes: 1,
		},
		{
			name:          "nil handle plus authentication error",
			openErr:       discoverycleanup.ErrSessionAuthentication,
			withoutHandle: true,
			wantOpenErr:   discoverycleanup.ErrSessionAuthentication,
		},
		{
			name:              "handle plus generic error",
			openErr:           errors.New("ambiguous open"),
			wantOpenErr:       discoverycleanup.ErrAttemptUncertain,
			wantHandleRevokes: 1,
		},
		{
			name:          "nil handle plus generic error",
			openErr:       errors.New("open failed"),
			withoutHandle: true,
			wantOpenErr:   discoverycleanup.ErrAttemptUncertain,
		},
	}
	for _, mode := range []discoveryqueue.ClaimMode{
		discoveryqueue.ClaimModeCleanupOnly,
		discoveryqueue.ClaimModeTerminal,
	} {
		for _, test := range tests {
			t.Run(string(mode)+"/"+test.name, func(t *testing.T) {
				fixture := newWorkerModeFixture(t, mode)
				fixture.authority.openErr = test.openErr
				fixture.authority.openWithoutHandle = test.withoutHandle
				session, openErr := fixture.broker.OpenAttempt(
					context.Background(),
					discoverycleanup.OpenAttemptRequest{
						Coordinates: fixture.coordinates,
						Attempt:     fixture.attempt,
					},
				)
				if session != nil {
					session.Destroy()
				}
				if !errors.Is(openErr, test.wantOpenErr) {
					t.Fatalf("OpenAttempt(setup) error = %v, want %v", openErr, test.wantOpenErr)
				}
				fixture.events.reset()

				worker, err := New(fixture.dependencies())
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				processErr := worker.processClaim(context.Background(), &fixture.claim)
				if !errors.Is(processErr, ErrCleanupUncertain) {
					t.Fatalf(
						"processClaim(exact open failure) error = %v, want ErrCleanupUncertain",
						processErr,
					)
				}
				cell := fixture.authority.cells[fixture.attempt.AttemptID]
				if cell == nil ||
					cell.revokeCalls != test.wantHandleRevokes ||
					cell.destroyCalls != test.wantHandleRevokes ||
					fixture.authority.openCalls != 1 ||
					fixture.queue.recordCleanupCalls != 1 ||
					fixture.queue.delayCalls != 0 || fixture.queue.completeCalls != 0 ||
					fixture.queue.failCalls != 0 || !fixture.queue.sourceSuspended ||
					fixture.queue.run.Status != assetcatalog.RunStatusFailed ||
					fixture.authority.resolveCalls != 0 ||
					fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 {
					t.Fatalf(
						"exact open failure cell=%#v open=%d cleanup=%d delay=%d "+
							"complete=%d fail=%d suspended=%t status=%s "+
							"resolve=%d validate=%d discover=%d",
						cell, fixture.authority.openCalls,
						fixture.queue.recordCleanupCalls,
						fixture.queue.delayCalls, fixture.queue.completeCalls,
						fixture.queue.failCalls, fixture.queue.sourceSuspended,
						fixture.queue.run.Status, fixture.authority.resolveCalls,
						fixture.provider.validateCalls, fixture.provider.discoverCalls,
					)
				}
				if fixture.queue.lastProof.Status() != assetcatalog.CredentialCleanupUncertain ||
					fixture.queue.lastProof.Attempt() != fixture.attempt ||
					fixture.queue.lastProof.Coordinates() != fixture.coordinates ||
					fixture.broker.VerifyCleanupProof(
						context.Background(), fixture.queue.lastProof,
					) != nil {
					t.Fatalf("exact open failure produced invalid UNCERTAIN proof")
				}
			})
		}
	}
}

func TestCleanupClaimsRejectUnavailableOpenBeforeRevoke(t *testing.T) {
	for _, mode := range []discoveryqueue.ClaimMode{
		discoveryqueue.ClaimModeCleanupOnly,
		discoveryqueue.ClaimModeTerminal,
	} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newWorkerModeFixture(t, mode)
			fixture.broker.Destroy()
			worker, err := New(fixture.dependencies())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if err := worker.processClaim(
				context.Background(), &fixture.claim,
			); !errors.Is(err, ErrWorkerUnavailable) {
				t.Fatalf("processClaim(unavailable open) error = %v, want ErrWorkerUnavailable", err)
			}
			if fixture.authority.openCalls != 0 ||
				fixture.queue.recordCleanupCalls != 0 ||
				fixture.queue.delayCalls != 0 || fixture.queue.completeCalls != 0 ||
				fixture.queue.failCalls != 0 ||
				fixture.authority.resolveCalls != 0 ||
				fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 {
				t.Fatalf(
					"unavailable open=%d cleanup=%d delay=%d complete=%d fail=%d "+
						"resolve=%d validate=%d discover=%d",
					fixture.authority.openCalls, fixture.queue.recordCleanupCalls,
					fixture.queue.delayCalls, fixture.queue.completeCalls,
					fixture.queue.failCalls, fixture.authority.resolveCalls,
					fixture.provider.validateCalls, fixture.provider.discoverCalls,
				)
			}
		})
	}
}

func TestRunningPersistedDelayCleanupOnlyReplaysDelay(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeCleanupOnly)
	fixture.claim.Run.Status = assetcatalog.RunStatusRunning
	fixture.claim.Run.WorkResultKind = ""
	fixture.claim.Run.WorkResultStatus = ""
	fixture.claim.Run.WorkResultDigest = ""
	fixture.queue.run = fixture.claim.Run
	fixture.queue.hasPendingDelay = true
	session, err := fixture.broker.OpenAttempt(
		context.Background(),
		discoverycleanup.OpenAttemptRequest{
			Coordinates: fixture.coordinates, Attempt: fixture.attempt,
		},
	)
	if err != nil {
		t.Fatalf("OpenAttempt(setup) error = %v", err)
	}
	session.Destroy()
	fixture.events.reset()

	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(context.Background(), &fixture.claim); err != nil {
		t.Fatalf("processClaim(running persisted delay) error = %v", err)
	}
	if fixture.authority.openCalls != 1 || fixture.authority.resolveCalls != 0 ||
		fixture.provider.validateCalls != 0 || fixture.provider.discoverCalls != 0 ||
		fixture.queue.recordCleanupCalls != 1 || fixture.queue.delayCalls != 1 {
		t.Fatalf(
			"running delay open=%d resolve=%d validate=%d discover=%d cleanup=%d delay=%d",
			fixture.authority.openCalls, fixture.authority.resolveCalls,
			fixture.provider.validateCalls, fixture.provider.discoverCalls,
			fixture.queue.recordCleanupCalls, fixture.queue.delayCalls,
		)
	}
	assertOrderedEvents(t, fixture.events.snapshot(),
		"revoke-session", "record-cleanup", "delay",
	)
}

func TestDataClaimUsesOpenedCheckpointAndOnlyPageCommits(t *testing.T) {
	next, err := discoverysource.NewCheckpoint(
		assetcatalog.ProfileCode(runtimeProvider),
		[]byte("page-1-complete"),
	)
	if err != nil {
		t.Fatalf("NewCheckpoint(next) error = %v", err)
	}
	fixture := newWorkerDataFixture(t, discoverysource.Page{
		NextCheckpoint: next, FinalPage: true, CompleteSnapshot: true,
	})
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(context.Background(), &fixture.claim); err != nil {
		t.Fatalf("processClaim(data page) error = %v", err)
	}
	if fixture.authority.lastRequest.CheckpointCodec() != fixture.codec {
		t.Fatal("data resolver did not receive the configured checkpoint codec")
	}
	if fixture.committer.calls != 1 || fixture.queue.delayCalls != 0 ||
		fixture.provider.discoverCalls != 1 || fixture.provider.validateCalls != 0 {
		t.Fatalf("calls commit=%d delay=%d discover=%d validate=%d",
			fixture.committer.calls, fixture.queue.delayCalls,
			fixture.provider.discoverCalls, fixture.provider.validateCalls)
	}
	assertOrderedEvents(t, fixture.events.snapshot(),
		"provider-discover",
		"advance-normalizing",
		"apply-page",
		"limiter-release",
		"runtime-clear",
		"revoke-session",
		"record-cleanup",
		"heartbeat",
		"complete",
	)
}

func TestDataDelayPersistsIntentAndCleansBeforeQueueDelay(t *testing.T) {
	fixture := newWorkerDataFixture(t, discoverysource.Delay{
		Reason: discoverysource.DelayReasonProviderRetryAfter, RetryAfter: time.Second,
	})
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(context.Background(), &fixture.claim); err != nil {
		t.Fatalf("processClaim(data delay) error = %v", err)
	}
	if fixture.committer.calls != 0 || fixture.queue.delayCalls != 1 ||
		fixture.limiter.delayCalls != 1 {
		t.Fatalf("calls commit=%d queue-delay=%d limiter-delay=%d",
			fixture.committer.calls, fixture.queue.delayCalls, fixture.limiter.delayCalls)
	}
	assertOrderedEvents(t, fixture.events.snapshot(),
		"provider-discover",
		"persist-delay",
		"limiter-delay",
		"runtime-clear",
		"revoke-session",
		"record-cleanup",
		"delay",
	)
}

func TestProviderCallDriftNeverCommitsOrSucceeds(t *testing.T) {
	tests := map[string]func(*workerModeFixture){
		"fence": func(fixture *workerModeFixture) {
			fixture.queue.driftFenceAtHeartbeat = 2
		},
		"runtime binding": func(fixture *workerModeFixture) {
			fixture.provider.clearRuntimeAfterDiscover = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			next, err := discoverysource.NewCheckpoint(
				assetcatalog.ProfileCode(runtimeProvider),
				[]byte("drifted-page"),
			)
			if err != nil {
				t.Fatalf("NewCheckpoint(next) error = %v", err)
			}
			fixture := newWorkerDataFixture(t, discoverysource.Page{
				NextCheckpoint: next, FinalPage: true, CompleteSnapshot: true,
			})
			mutate(fixture)
			worker, err := New(fixture.dependencies())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if err := worker.processClaim(context.Background(), &fixture.claim); err == nil {
				t.Fatal("processClaim(drift) succeeded")
			}
			if fixture.committer.calls != 0 || fixture.queue.completeCalls != 0 {
				t.Fatalf("drift committed/succeeded: page=%d complete=%d",
					fixture.committer.calls, fixture.queue.completeCalls)
			}
			if fixture.queue.recordCleanupCalls != 1 {
				t.Fatalf("cleanup calls = %d, want 1", fixture.queue.recordCleanupCalls)
			}
		})
	}
}

func TestResponseLossReplaysExactAttemptCleanupAndTerminalReceipts(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	fixture.queue.reserveResponseLoss = true
	fixture.queue.recordCleanupResponseLoss = true
	fixture.queue.completeResponseLoss = true
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(context.Background(), &fixture.claim); err != nil {
		t.Fatalf("processClaim(response loss) error = %v", err)
	}
	if fixture.queue.reserveCalls != 2 ||
		fixture.queue.recordCleanupCalls != 2 ||
		fixture.queue.completeCalls != 2 {
		t.Fatalf("replay calls reserve=%d cleanup=%d complete=%d, want 2 each",
			fixture.queue.reserveCalls, fixture.queue.recordCleanupCalls,
			fixture.queue.completeCalls)
	}
	if fixture.authority.openCalls != 1 || fixture.provider.validateCalls != 1 {
		t.Fatalf("response loss duplicated open/provider: open=%d provider=%d",
			fixture.authority.openCalls, fixture.provider.validateCalls)
	}
	cell := fixture.authority.cells[fixture.attempt.AttemptID]
	if cell == nil || cell.bindCalls != 1 {
		t.Fatalf("response loss duplicated runtime bind: cell=%#v", cell)
	}
}

func TestChangedTerminalReceiptFailsClosed(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	fixture.queue.driftTerminalReceipt = true
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.processClaim(context.Background(), &fixture.claim); err == nil {
		t.Fatal("processClaim(changed terminal receipt) succeeded")
	}
}

func TestOpenFailureRecordsUncertainWithoutProviderOrQueueDelay(t *testing.T) {
	tests := []struct {
		name              string
		openErr           error
		withoutHandle     bool
		wantHandleRevokes int
	}{
		{
			name: "handle plus generic error", openErr: errors.New("ambiguous open"),
			wantHandleRevokes: 1,
		},
		{
			name:              "handle plus authentication error",
			openErr:           discoverycleanup.ErrSessionAuthentication,
			wantHandleRevokes: 1,
		},
		{
			name: "nil handle plus generic error", openErr: errors.New("open failed"),
			withoutHandle: true,
		},
		{
			name:    "nil handle plus authentication error",
			openErr: discoverycleanup.ErrSessionAuthentication, withoutHandle: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
			fixture.authority.openErr = test.openErr
			fixture.authority.openWithoutHandle = test.withoutHandle
			worker, err := New(fixture.dependencies())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if err := worker.processClaim(
				context.Background(), &fixture.claim,
			); !errors.Is(err, ErrCleanupUncertain) {
				t.Fatalf("processClaim(open failure) error = %v, want ErrCleanupUncertain", err)
			}
			cell := fixture.authority.cells[fixture.attempt.AttemptID]
			if fixture.provider.validateCalls != 0 || fixture.authority.resolveCalls != 0 ||
				fixture.authority.openCalls != 1 || fixture.queue.recordCleanupCalls != 1 ||
				fixture.queue.delayCalls != 0 || fixture.queue.completeCalls != 0 ||
				fixture.queue.failCalls != 0 || fixture.limiter.delayCalls != 1 ||
				!fixture.queue.sourceSuspended || fixture.queue.run.Status != assetcatalog.RunStatusFailed ||
				cell == nil || cell.revokeCalls != test.wantHandleRevokes ||
				cell.destroyCalls != test.wantHandleRevokes {
				t.Fatalf(
					"open failure provider=%d resolve=%d open=%d cleanup=%d queue-delay=%d "+
						"complete=%d fail=%d limiter-delay=%d suspended=%t status=%s cell=%#v",
					fixture.provider.validateCalls, fixture.authority.resolveCalls,
					fixture.authority.openCalls, fixture.queue.recordCleanupCalls,
					fixture.queue.delayCalls, fixture.queue.completeCalls,
					fixture.queue.failCalls, fixture.limiter.delayCalls,
					fixture.queue.sourceSuspended, fixture.queue.run.Status, cell,
				)
			}
			if fixture.queue.lastProof.Status() != assetcatalog.CredentialCleanupUncertain ||
				fixture.queue.lastProof.Attempt() != fixture.attempt ||
				fixture.queue.lastProof.Coordinates() != fixture.coordinates ||
				fixture.broker.VerifyCleanupProof(
					context.Background(), fixture.queue.lastProof,
				) != nil {
				t.Fatal("open failure produced invalid UNCERTAIN proof")
			}
			assertOrderedEvents(t, fixture.events.snapshot(),
				"reserve-attempt",
				"open-session",
				"persist-delay",
				"limiter-delay",
				"record-cleanup",
			)
		})
	}
}

func TestRunStopsAfterProviderPanicAndCleansCurrentAttempt(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	fixture.queue.claims = []discoveryqueue.ClaimResult{fixture.claim}
	fixture.provider.panicValidate = true
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := worker.Run(context.Background()); !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("Run() error = %v, want ErrWorkerUnavailable", err)
	}
	if fixture.queue.claimCalls != 1 || fixture.queue.completeCalls != 0 ||
		fixture.queue.prepareFailureCalls != 1 || fixture.queue.failCalls != 1 ||
		fixture.queue.recordCleanupCalls != 1 || fixture.limiter.releaseCalls != 1 {
		t.Fatalf("panic lifecycle claim=%d complete=%d prepare=%d fail=%d cleanup=%d release=%d",
			fixture.queue.claimCalls, fixture.queue.completeCalls,
			fixture.queue.prepareFailureCalls, fixture.queue.failCalls,
			fixture.queue.recordCleanupCalls, fixture.limiter.releaseCalls)
	}
}

func TestStopCancelsProviderAndWaitsForCurrentAttemptCleanup(t *testing.T) {
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	fixture.queue.claims = []discoveryqueue.ClaimResult{fixture.claim}
	fixture.provider.validateStarted = make(chan struct{})
	fixture.provider.blockValidationUntilCancel = true
	worker, err := New(fixture.dependencies())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	runResult := make(chan error, 1)
	go func() {
		runResult <- worker.Run(context.Background())
	}()
	select {
	case <-fixture.provider.validateStarted:
	case <-time.After(time.Second):
		t.Fatal("Provider call did not start")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if fixture.queue.claimCalls != 1 || fixture.queue.completeCalls != 0 ||
		fixture.queue.prepareFailureCalls != 1 || fixture.queue.failCalls != 1 ||
		fixture.queue.recordCleanupCalls != 1 || fixture.limiter.releaseCalls != 1 {
		t.Fatalf("cancel lifecycle claim=%d complete=%d prepare=%d fail=%d cleanup=%d release=%d",
			fixture.queue.claimCalls, fixture.queue.completeCalls,
			fixture.queue.prepareFailureCalls, fixture.queue.failCalls,
			fixture.queue.recordCleanupCalls, fixture.limiter.releaseCalls)
	}
}

func validWorkerDependencies(t *testing.T) Dependencies {
	t.Helper()
	fixture := newRuntimeFixture(t)
	return Dependencies{
		Queue:                &dependencyQueue{},
		CleanupBroker:        fixture.broker,
		Limiter:              &dependencyLimiter{},
		PageCommitter:        &dependencyPageCommitter{},
		Checkpoints:          fixture.codec,
		ClaimRuntimeResolver: &dependencyRuntimeResolver{},
		ClaimCommand: discoveryqueue.ClaimCommand{
			Owner: "task28a-test-worker", LeaseDuration: 5 * time.Second,
			ProviderKinds: []string{runtimeProvider},
		},
	}
}

type dependencyQueue struct {
	discoveryqueue.Queue
}

type dependencyLimiter struct {
	discoverylimit.Limiter
}

type dependencyPageCommitter struct {
	discoverysource.PageCommitter
}

type dependencyRuntimeResolver struct {
	ClaimRuntimeResolver
}

func (*dependencyRuntimeResolver) ResolveOpenedAttempt(
	context.Context,
	ResolveOpenedAttemptRequest,
) (ClaimRuntime, error) {
	return ClaimRuntime{}, ErrClaimRuntimeBinding
}

var (
	_ discoveryqueue.Queue          = (*dependencyQueue)(nil)
	_ discoverylimit.Limiter        = (*dependencyLimiter)(nil)
	_ discoverysource.PageCommitter = (*dependencyPageCommitter)(nil)
	_ ClaimRuntimeResolver          = (*dependencyRuntimeResolver)(nil)
	_                               = assetcatalog.RunKindDiscovery
	_                               = discoverycheckpoint.CheckpointCodec{}
	_                               = discoverycleanup.OpenAttemptRequest{}
)

type workerModeFixture struct {
	events      *eventLog
	queue       *modeQueue
	limiter     *modeLimiter
	committer   *modePageCommitter
	authority   *modeAttemptAuthority
	provider    *modeProvider
	broker      *discoverycleanup.CleanupBroker
	codec       *discoverycheckpoint.CheckpointCodec
	claim       discoveryqueue.ClaimResult
	coordinates discoveryqueue.RunCoordinates
	attempt     discoveryqueue.CleanupAttempt
}

func newWorkerModeFixture(t *testing.T, mode discoveryqueue.ClaimMode) *workerModeFixture {
	t.Helper()
	events := &eventLog{}
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: runtimeTenantID, WorkspaceID: runtimeWorkspace},
		RunID: runtimeRunID,
	}
	attempt := discoveryqueue.CleanupAttempt{
		RunID: runtimeRunID, AttemptID: runtimeAttemptID, AttemptEpoch: 11,
	}
	provider := &modeProvider{events: events}
	authority := &modeAttemptAuthority{
		events: events, provider: provider,
		cells: make(map[string]*modeSessionCell),
	}
	broker, err := discoverycleanup.NewCleanupBroker(authority, runtimeFixtureProofAuthority{})
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)
	var key [32]byte
	for index := range key {
		key[index] = byte(255 - index)
	}
	keys, err := discoverycheckpoint.NewInMemoryKeyring("worker-mode-key", map[string][32]byte{
		"worker-mode-key": key,
	})
	if err != nil {
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := discoverycheckpoint.NewCheckpointCodec(keys)
	if err != nil {
		t.Fatalf("NewCheckpointCodec() error = %v", err)
	}
	expires := time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond)
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 17)
	}
	fence, err := leasefence.FromQueueClaim(runtimeRunID, "task28a-test-worker", 11, &token)
	if err != nil {
		t.Fatalf("FromQueueClaim() error = %v", err)
	}
	run := assetcatalog.SourceRun{
		ID: runtimeRunID, SourceID: runtimeSourceID,
		Scope: coordinates.Scope, SourceRevision: 3,
		SourceRevisionDigest:    strings.Repeat("a", 64),
		Kind:                    assetcatalog.RunKindValidation,
		Status:                  assetcatalog.RunStatusRunning,
		Stage:                   assetcatalog.RunStageValidating,
		FenceEpoch:              11,
		HeartbeatSequence:       1,
		LeaseExpiresAt:          &expires,
		CheckpointVersion:       0,
		CredentialCleanupStatus: assetcatalog.CredentialCleanupNotOpened,
	}
	claim := discoveryqueue.ClaimResult{
		Run: run, ProviderKind: runtimeProvider,
		ProfileCode: assetcatalog.ProfileCode(runtimeProvider),
		Mode:        mode, Fence: fence,
	}
	if mode != discoveryqueue.ClaimModeProvider {
		claim.Run.Stage = assetcatalog.RunStageCleaningUp
		claim.Run.Status = assetcatalog.RunStatusFinalizing
		claim.Run.CredentialCleanupStatus = assetcatalog.CredentialCleanupPending
		claim.Run.WorkResultKind = assetcatalog.WorkResultValidationProof
		claim.Run.WorkResultStatus = assetcatalog.WorkResultStatusSucceeded
		claim.Run.WorkResultDigest = strings.Repeat("d", 64)
		claim.CleanupAttempt = &attempt
	}
	if mode == discoveryqueue.ClaimModeCleanupOnly {
		claim.Run.Status = assetcatalog.RunStatusRunning
		claim.Run.WorkResultKind = ""
		claim.Run.WorkResultStatus = ""
		claim.Run.WorkResultDigest = ""
		claim.Run.FailureCode = ""
		notBefore := time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
		claim.PersistedDelay = &discoveryqueue.PersistedDelay{
			Reason:    discoveryqueue.DelayReasonTransportBackoff,
			NotBefore: notBefore, DigestSHA256: strings.Repeat("e", 64),
		}
	}
	queue := &modeQueue{
		events: events, run: claim.Run, attempt: attempt,
		hasPendingDelay: mode == discoveryqueue.ClaimModeCleanupOnly,
		work: discoveryqueue.WorkResult{
			Kind:         assetcatalog.WorkResultValidationProof,
			Status:       assetcatalog.WorkResultStatusSucceeded,
			DigestSHA256: strings.Repeat("d", 64),
		},
	}
	fixture := &workerModeFixture{
		events: events, queue: queue,
		limiter:   &modeLimiter{events: events},
		authority: authority, provider: provider, broker: broker, codec: codec,
		claim: claim, coordinates: coordinates, attempt: attempt,
	}
	fixture.committer = &modePageCommitter{events: events, queue: queue}
	return fixture
}

func newWorkerDataFixture(
	t *testing.T,
	outcome discoverysource.DiscoverOutcome,
) *workerModeFixture {
	t.Helper()
	fixture := newWorkerModeFixture(t, discoveryqueue.ClaimModeProvider)
	fixture.claim.Run.Kind = assetcatalog.RunKindDiscovery
	fixture.claim.Run.Stage = assetcatalog.RunStageReading
	fixture.queue.run = fixture.claim.Run
	fixture.provider.outcome = outcome
	return fixture
}

func (fixture *workerModeFixture) dependencies() Dependencies {
	return Dependencies{
		Queue: fixture.queue, CleanupBroker: fixture.broker,
		Limiter: fixture.limiter, PageCommitter: fixture.committer,
		Checkpoints: fixture.codec, ClaimRuntimeResolver: fixture.authority,
		ClaimCommand: discoveryqueue.ClaimCommand{
			Owner: "task28a-test-worker", LeaseDuration: 5 * time.Second,
			ProviderKinds: []string{runtimeProvider},
		},
	}
}

type eventLog struct {
	mu     sync.Mutex
	values []string
}

func (events *eventLog) add(value string) {
	events.mu.Lock()
	defer events.mu.Unlock()
	events.values = append(events.values, value)
}

func (events *eventLog) snapshot() []string {
	events.mu.Lock()
	defer events.mu.Unlock()
	return slices.Clone(events.values)
}

func (events *eventLog) reset() {
	events.mu.Lock()
	defer events.mu.Unlock()
	events.values = nil
}

func assertOrderedEvents(t *testing.T, actual []string, expected ...string) {
	t.Helper()
	position := 0
	for _, event := range actual {
		if position < len(expected) && event == expected[position] {
			position++
		}
	}
	if position != len(expected) {
		t.Fatalf("events = %v, missing ordered suffix %v", actual, expected[position:])
	}
}

type modeQueue struct {
	discoveryqueue.Queue
	events                    *eventLog
	run                       assetcatalog.SourceRun
	attempt                   discoveryqueue.CleanupAttempt
	work                      discoveryqueue.WorkResult
	lastProof                 discoveryqueue.CleanupProof
	heartbeatCalls            int
	delayCalls                int
	completeCalls             int
	failCalls                 int
	prepareFailureCalls       int
	recordCleanupCalls        int
	reserveCalls              int
	driftFenceAtHeartbeat     int
	reserveResponseLoss       bool
	recordCleanupResponseLoss bool
	completeResponseLoss      bool
	driftTerminalReceipt      bool
	claims                    []discoveryqueue.ClaimResult
	claimCalls                int
	hasPendingDelay           bool
	sourceSuspended           bool
}

func (queue *modeQueue) Claim(
	context.Context,
	discoveryqueue.ClaimCommand,
) (discoveryqueue.ClaimResult, error) {
	queue.claimCalls++
	if len(queue.claims) == 0 {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrNoWork
	}
	claim := queue.claims[0]
	queue.claims = queue.claims[1:]
	return claim, nil
}

func (queue *modeQueue) Heartbeat(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	command discoveryqueue.HeartbeatCommand,
) (discoveryqueue.HeartbeatResult, error) {
	queue.events.add("heartbeat")
	queue.heartbeatCalls++
	queue.run.HeartbeatSequence = command.Sequence
	if queue.driftFenceAtHeartbeat == queue.heartbeatCalls {
		queue.run.FenceEpoch++
	}
	expires := time.Now().UTC().Add(command.Extension).Truncate(time.Microsecond)
	queue.run.LeaseExpiresAt = &expires
	return discoveryqueue.HeartbeatResult{Run: queue.run, LeaseExpiresAt: expires}, nil
}

func (queue *modeQueue) ReserveCleanupAttempt(
	context.Context,
	assetcatalog.LeaseFence,
	discoveryqueue.RunCommand,
) (discoveryqueue.CleanupAttempt, error) {
	queue.events.add("reserve-attempt")
	queue.reserveCalls++
	if queue.reserveResponseLoss && queue.reserveCalls == 1 {
		return queue.attempt, discoveryqueue.ErrUnavailable
	}
	return queue.attempt, nil
}

func (queue *modeQueue) AdvanceStage(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	command discoveryqueue.AdvanceStageCommand,
) (assetcatalog.SourceRun, error) {
	switch {
	case command.To == assetcatalog.RunStageNormalizing && command.Delay == nil:
		queue.events.add("advance-normalizing")
	case command.To == assetcatalog.RunStageCleaningUp && command.Delay != nil:
		queue.events.add("persist-delay")
		queue.hasPendingDelay = true
	default:
		return assetcatalog.SourceRun{}, discoveryqueue.ErrInvalidRequest
	}
	queue.run.Stage = command.To
	return queue.run, nil
}

func (queue *modeQueue) ProposeValidationResult(
	context.Context,
	assetcatalog.LeaseFence,
	discoveryqueue.ValidationResultCommand,
) (discoveryqueue.WorkResult, error) {
	queue.events.add("propose-validation")
	queue.run.Status = assetcatalog.RunStatusFinalizing
	queue.run.Stage = assetcatalog.RunStageCleaningUp
	queue.run.WorkResultKind = queue.work.Kind
	queue.run.WorkResultStatus = queue.work.Status
	queue.run.WorkResultDigest = queue.work.DigestSHA256
	return queue.work, nil
}

func (queue *modeQueue) PrepareFailureIntent(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	command discoveryqueue.FailureIntentCommand,
) (discoveryqueue.WorkResult, error) {
	queue.events.add("prepare-failure")
	queue.prepareFailureCalls++
	work := discoveryqueue.WorkResult{
		Kind: assetcatalog.WorkResultFailureIntent, Status: assetcatalog.WorkResultStatusFailed,
		DigestSHA256: digestText(
			command.Coordinates.RunID + ":" + command.FailureCode + ":" + command.EvidenceDigest,
		),
		FailureCode: command.FailureCode,
	}
	queue.run.Status = assetcatalog.RunStatusFinalizing
	queue.run.Stage = assetcatalog.RunStageCleaningUp
	queue.run.WorkResultKind = work.Kind
	queue.run.WorkResultStatus = work.Status
	queue.run.WorkResultDigest = work.DigestSHA256
	queue.run.FailureCode = work.FailureCode
	return work, nil
}

func (queue *modeQueue) RecordCleanup(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	proof discoveryqueue.CleanupProof,
) (discoveryqueue.CleanupResult, error) {
	queue.events.add("record-cleanup")
	queue.recordCleanupCalls++
	queue.lastProof.Destroy()
	queue.lastProof = proof.Clone()
	hasWork := queue.run.WorkResultKind.Valid() &&
		queue.run.WorkResultStatus.Valid() &&
		domain.ValidSHA256Hex(queue.run.WorkResultDigest)
	if queue.run.Stage != assetcatalog.RunStageCleaningUp ||
		hasWork == queue.hasPendingDelay {
		return discoveryqueue.CleanupResult{}, discoveryqueue.ErrStateConflict
	}
	result := discoveryqueue.CleanupResult{
		Attempt: proof.Attempt(), Status: proof.Status(),
		DigestSHA256: proof.DigestSHA256(),
	}
	if queue.recordCleanupResponseLoss && queue.recordCleanupCalls == 1 {
		return result, discoveryqueue.ErrUnavailable
	}
	queue.run.CredentialCleanupStatus = proof.Status()
	if proof.Status() == assetcatalog.CredentialCleanupUncertain {
		// The production Queue atomically owns this fail-and-suspend projection;
		// Worker must not issue Delay, Complete, or a second terminal command.
		queue.run.Status = assetcatalog.RunStatusFailed
		queue.run.Stage = assetcatalog.RunStageCompleted
		queue.run.FailureCode = "CLEANUP_UNCERTAIN"
		queue.sourceSuspended = true
	}
	result.Replayed = queue.recordCleanupCalls > 1
	return result, nil
}

func (queue *modeQueue) Delay(
	context.Context,
	assetcatalog.LeaseFence,
	discoveryqueue.DelayCommand,
) (assetcatalog.SourceRun, error) {
	queue.events.add("delay")
	queue.delayCalls++
	return queue.run, nil
}

func (queue *modeQueue) Complete(
	context.Context,
	assetcatalog.LeaseFence,
	discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, error) {
	queue.events.add("complete")
	queue.completeCalls++
	result := discoveryqueue.TerminalResult{
		RunID: runtimeRunID, Status: assetcatalog.RunStatusSucceeded,
		CommandDigest: strings.Repeat("f", 64),
		CompletedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}
	if queue.completeResponseLoss && queue.completeCalls == 1 {
		return result, discoveryqueue.ErrUnavailable
	}
	if queue.driftTerminalReceipt {
		result.RunID = runtimeRunID2
	}
	result.Replayed = queue.completeCalls > 1
	return result, nil
}

func (queue *modeQueue) Fail(
	context.Context,
	assetcatalog.LeaseFence,
	discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, error) {
	queue.events.add("fail")
	queue.failCalls++
	return discoveryqueue.TerminalResult{
		RunID: runtimeRunID, Status: assetcatalog.RunStatusFailed,
		CommandDigest: strings.Repeat("f", 64),
		CompletedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}, nil
}

type modeLimiter struct {
	discoverylimit.Limiter
	events       *eventLog
	acquireCalls int
	delayCalls   int
	releaseCalls int
}

func (limiter *modeLimiter) Acquire(
	_ context.Context,
	command discoverylimit.AcquireCommand,
) (discoverylimit.Permit, error) {
	limiter.events.add("limiter-acquire")
	limiter.acquireCalls++
	now := time.Now().UTC().Truncate(time.Microsecond)
	return discoverylimit.Permit{
		PermitID:    "70000000-0000-4000-8000-000000000007",
		Coordinates: command.Coordinates, RequestID: command.RequestID,
		CommandSHA256: strings.Repeat("1", 64), ReceiptSHA256: strings.Repeat("2", 64),
		AcquiredAt: now, ExpiresAt: now.Add(command.TTL),
	}, nil
}

func (limiter *modeLimiter) Release(
	_ context.Context,
	command discoverylimit.ReleaseCommand,
) (discoverylimit.Receipt, error) {
	limiter.events.add("limiter-release")
	limiter.releaseCalls++
	now := time.Now().UTC().Truncate(time.Microsecond)
	return discoverylimit.Receipt{
		ReceiptID: "80000000-0000-4000-8000-000000000008",
		PermitID:  command.PermitID, Kind: discoverylimit.ReceiptRelease,
		Coordinates: command.Coordinates, RequestID: command.RequestID,
		CommandSHA256: strings.Repeat("3", 64), ReceiptSHA256: strings.Repeat("4", 64),
		AcquiredAt: now, ExpiresAt: now.Add(time.Second), ReasonCode: command.ReasonCode,
	}, nil
}

func (limiter *modeLimiter) Delay(
	_ context.Context,
	command discoverylimit.DelayCommand,
) (discoverylimit.Receipt, error) {
	limiter.events.add("limiter-delay")
	limiter.delayCalls++
	now := time.Now().UTC().Truncate(time.Microsecond)
	notBefore := command.NotBefore
	return discoverylimit.Receipt{
		ReceiptID: "80000000-0000-4000-8000-000000000009",
		PermitID:  command.PermitID, Kind: discoverylimit.ReceiptDelay,
		Coordinates: command.Coordinates, RequestID: command.RequestID,
		CommandSHA256: strings.Repeat("5", 64), ReceiptSHA256: strings.Repeat("6", 64),
		AcquiredAt: now, ExpiresAt: now.Add(2 * time.Second),
		NotBefore: &notBefore, ReasonCode: command.ReasonCode,
	}, nil
}

type modePageCommitter struct {
	discoverysource.PageCommitter
	events *eventLog
	queue  *modeQueue
	calls  int
}

func (committer *modePageCommitter) ApplyPage(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
) (discoverysource.PageCommitResult, error) {
	committer.events.add("apply-page")
	committer.calls++
	committer.queue.run.Status = assetcatalog.RunStatusFinalizing
	committer.queue.run.Stage = assetcatalog.RunStageCleaningUp
	committer.queue.run.PageSequence = coordinates.PageSequence
	committer.queue.run.CheckpointVersion++
	committer.queue.run.HeartbeatSequence++
	committer.queue.run.WorkResultKind = assetcatalog.WorkResultDataProjection
	committer.queue.run.WorkResultStatus = assetcatalog.WorkResultStatusSucceeded
	committer.queue.run.WorkResultDigest = strings.Repeat("9", 64)
	return discoverysource.PageCommitResult{
		RunID: coordinates.RunID, PageSequence: coordinates.PageSequence,
		CheckpointVersion:        committer.queue.run.CheckpointVersion,
		CheckpointSHA256:         strings.Repeat("8", 64),
		PageDigestSHA256:         strings.Repeat("9", 64),
		RelationPageDigestSHA256: strings.Repeat("7", 64),
		FinalPage:                page.FinalPage, CompleteSnapshot: page.CompleteSnapshot,
	}, nil
}

type modeAttemptAuthority struct {
	mu                        sync.Mutex
	events                    *eventLog
	provider                  *modeProvider
	cells                     map[string]*modeSessionCell
	openCalls                 int
	resolveCalls              int
	lastRequest               ResolveOpenedAttemptRequest
	openErr                   error
	openWithoutHandle         bool
	noRuntimeHandle           bool
	runtimeBindingDrift       bool
	inactiveRuntime           bool
	runtimeBindErr            error
	resolveWithForeignRuntime bool
	foreignCell               *modeSessionCell
}

func (authority *modeAttemptAuthority) OpenSession(
	_ context.Context,
	request discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	authority.events.add("open-session")
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.openCalls++
	cell := &modeSessionCell{events: authority.events}
	authority.cells[request.Attempt.AttemptID] = cell
	handle := &modeSessionHandle{cell: cell}
	if authority.openWithoutHandle {
		return nil, authority.openErr
	}
	if authority.noRuntimeHandle {
		return &modeCleanupOnlySessionHandle{cell: cell}, authority.openErr
	}
	handle.bindingDrift = authority.runtimeBindingDrift
	handle.inactiveRuntime = authority.inactiveRuntime
	handle.bindErr = authority.runtimeBindErr
	return handle, authority.openErr
}

func (authority *modeAttemptAuthority) ResolveOpenedAttempt(
	_ context.Context,
	request ResolveOpenedAttemptRequest,
) (ClaimRuntime, error) {
	authority.events.add("resolve-runtime")
	authority.mu.Lock()
	authority.resolveCalls++
	authority.lastRequest = request
	cell := authority.cells[request.Attempt().AttemptID]
	if authority.resolveWithForeignRuntime {
		cell = &modeSessionCell{events: authority.events, foreign: true}
		authority.foreignCell = cell
	}
	authority.mu.Unlock()
	if cell == nil {
		return ClaimRuntime{}, ErrClaimRuntimeBinding
	}
	binding := request.RuntimeBinding()
	checkpointBytes := []byte(nil)
	if request.RunKind() != assetcatalog.RunKindValidation && request.CheckpointVersion() > 0 {
		checkpointBytes = []byte("opened-data-checkpoint")
	}
	checkpoint, err := discoverysource.NewCheckpoint(binding.ProfileCode, checkpointBytes)
	if err != nil {
		return ClaimRuntime{}, err
	}
	limits := discoverysource.Limits{
		MaxPageItems: 10, MaxPageRelations: 10, MaxPageBytes: 4096, MaxDocumentBytes: 2048,
	}
	policy := runtimeFixturePolicy()
	if authority.resolveWithForeignRuntime {
		bound, bindErr := bindModeRuntime(binding, cell)
		if bindErr != nil {
			checkpoint.Clear()
			return ClaimRuntime{}, bindErr
		}
		ownedCheckpoint := checkpoint.Clone()
		checkpoint.Clear()
		return ClaimRuntime{state: &claimRuntimeState{
			cell: request.cell, provider: authority.provider, runtime: bound,
			checkpoint: ownedCheckpoint, limits: limits, policy: policy, active: true,
		}}, nil
	}
	return request.NewClaimRuntime(authority.provider, &checkpoint, limits, policy)
}

type modeSessionCell struct {
	events         *eventLog
	foreign        bool
	bindCalls      int
	runtimeCleared bool
	revoked        bool
	revokeCalls    int
	destroyCalls   int
}

type modeRuntimeMaterial struct {
	cell *modeSessionCell
}

type modeSessionHandle struct {
	cell            *modeSessionCell
	bindingDrift    bool
	inactiveRuntime bool
	bindErr         error
}

func (handle *modeSessionHandle) BindRuntime(
	_ context.Context,
	binding discoverysource.RuntimeBinding,
) (discoverysource.BoundRuntime, error) {
	if handle.bindingDrift {
		binding.SourceRevision++
	}
	runtime, err := bindModeRuntime(binding, handle.cell)
	if err != nil {
		return discoverysource.BoundRuntime{}, err
	}
	if handle.inactiveRuntime {
		runtime.Clear()
	}
	return runtime, handle.bindErr
}

func bindModeRuntime(
	binding discoverysource.RuntimeBinding,
	cell *modeSessionCell,
) (discoverysource.BoundRuntime, error) {
	cell.bindCalls++
	bindEvent := "bind-runtime"
	clearEvent := "runtime-clear"
	if cell.foreign {
		bindEvent = "bind-foreign-runtime"
		clearEvent = "foreign-runtime-clear"
	}
	cell.events.add(bindEvent)
	material := &modeRuntimeMaterial{cell: cell}
	return discoverysource.BindRuntime(
		binding,
		material,
		func(*modeRuntimeMaterial) error { return nil },
		func(value *modeRuntimeMaterial) {
			value.cell.events.add(clearEvent)
			value.cell.runtimeCleared = true
		},
	)
}

func (handle *modeSessionHandle) Revoke(context.Context) error {
	handle.cell.events.add("revoke-session")
	handle.cell.revokeCalls++
	handle.cell.revoked = true
	return nil
}

func (handle *modeSessionHandle) Destroy() {
	handle.cell.destroyCalls++
}

type modeCleanupOnlySessionHandle struct {
	cell *modeSessionCell
}

func (handle *modeCleanupOnlySessionHandle) Revoke(context.Context) error {
	handle.cell.events.add("revoke-session")
	handle.cell.revokeCalls++
	handle.cell.revoked = true
	return nil
}

func (handle *modeCleanupOnlySessionHandle) Destroy() {
	handle.cell.destroyCalls++
}

var _ discoverycleanup.RuntimeSessionHandle = (*modeSessionHandle)(nil)
var _ discoverycleanup.SessionHandle = (*modeCleanupOnlySessionHandle)(nil)

type modeProvider struct {
	events                       *eventLog
	validateCalls, discoverCalls int
	outcome                      discoverysource.DiscoverOutcome
	clearRuntimeAfterDiscover    bool
	panicValidate                bool
	validateStarted              chan struct{}
	validateStartedOnce          sync.Once
	blockValidationUntilCancel   bool
}

func (*modeProvider) Kind() assetcatalog.SourceKind {
	return assetcatalog.SourceKindExternalCMDB
}

func (*modeProvider) ProviderKind() string { return runtimeProvider }

func (provider *modeProvider) Validate(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.ValidationRequest,
) (discoverysource.ValidationProof, error) {
	provider.events.add("provider-validate")
	provider.validateCalls++
	if provider.validateStarted != nil {
		provider.validateStartedOnce.Do(func() {
			close(provider.validateStarted)
		})
	}
	if provider.panicValidate {
		panic("provider panic canary")
	}
	if provider.blockValidationUntilCancel {
		<-ctx.Done()
		return discoverysource.ValidationProof{}, ctx.Err()
	}
	if err := discoverysource.WithRuntime[modeRuntimeMaterial](
		runtime,
		discoverysource.RuntimeBinding{
			Locator: request.Locator, SourceRevision: request.SourceRevision,
			SourceRevisionDigest: request.SourceRevisionDigest,
			RevisionStatus:       assetcatalog.SourceRevisionValidating,
			ProviderKind:         runtimeProvider, ProfileCode: assetcatalog.ProfileCode(runtimeProvider),
		},
		func(*modeRuntimeMaterial) error { return nil },
	); err != nil {
		return discoverysource.ValidationProof{}, err
	}
	return successfulValidationProof(), nil
}

func (provider *modeProvider) Discover(
	_ context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	provider.events.add("provider-discover")
	provider.discoverCalls++
	if runtime.Binding().RevisionStatus != assetcatalog.SourceRevisionPublished ||
		request.Checkpoint.ProfileCode() != assetcatalog.ProfileCode(runtimeProvider) {
		return nil, errors.New("invalid data runtime")
	}
	if provider.clearRuntimeAfterDiscover {
		runtime.Clear()
	}
	return provider.outcome, nil
}

func successfulValidationProof() discoverysource.ValidationProof {
	kinds := []discoverysource.ValidationCheckKind{
		discoverysource.ValidationCheckIdentity,
		discoverysource.ValidationCheckTrustOrSignature,
		discoverysource.ValidationCheckNetwork,
		discoverysource.ValidationCheckCredentialOpen,
		discoverysource.ValidationCheckFixedProbe,
		discoverysource.ValidationCheckSchema,
		discoverysource.ValidationCheckDLP,
		discoverysource.ValidationCheckBudget,
	}
	checks := make([]discoverysource.ValidationCheck, 0, len(kinds))
	for _, kind := range kinds {
		checks = append(checks, discoverysource.ValidationCheck{
			Kind: kind, Code: string(kind) + "_PASSED", Passed: true, Count: 1,
			DigestSHA256: digestText("validation-" + string(kind)),
		})
	}
	return discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeSucceeded,
		Code:    "VALIDATION_SUCCEEDED", Checks: checks,
	}
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

var _ assetdiscovery.FactPolicy = runtimeFixturePolicy()
