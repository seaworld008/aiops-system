// Package discoverycleanup defines the process-local security boundary for
// discovery credential/session cleanup attempts.
package discoverycleanup

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"sync"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
)

const (
	sessionRedaction = "[REDACTED_CLEANUP_SESSION]"
	brokerRedaction  = "[REDACTED_CLEANUP_BROKER]"
	proofDomain      = "asset-source-cleanup-proof.v1"
)

var (
	ErrInvalidInput           = errors.New("cleanup broker input invalid")
	ErrBrokerUnavailable      = errors.New("cleanup broker unavailable")
	ErrAttemptNotFound        = errors.New("cleanup broker attempt not found")
	ErrAttemptDrift           = errors.New("cleanup broker attempt drift")
	ErrAttemptClosed          = errors.New("cleanup broker attempt closed")
	ErrAttemptUncertain       = errors.New("cleanup broker attempt result uncertain")
	ErrSessionAuthentication  = errors.New("cleanup broker session authentication failed")
	ErrSessionDestroyed       = errors.New("cleanup broker session destroyed")
	ErrProofAuthentication    = errors.New("cleanup broker proof authentication failed")
	ErrSensitiveSerialization = errors.New(
		"cleanup broker process value is not serializable",
	)
)

// OpenAttemptRequest contains only Queue-owned safe coordinates. A concrete
// SessionOpener resolves all credential, endpoint, runtime, and transport facts
// through its own trusted binding; none of those values cross this ABI.
type OpenAttemptRequest struct {
	Coordinates discoveryqueue.RunCoordinates
	Attempt     discoveryqueue.CleanupAttempt
}

func (request OpenAttemptRequest) Validate() error {
	if !request.Coordinates.Valid() || !request.Attempt.Valid() ||
		request.Attempt.RunID != request.Coordinates.RunID {
		return ErrInvalidInput
	}
	return nil
}

// SessionOpener is the narrow trusted adapter invoked once for an exact
// attempt. Implementations must be safe for concurrent attempts, honor context
// cancellation before returning, and must not return a transport or credential
// payload. A non-nil handle returned with an error remains Broker-owned and can
// produce only an UNCERTAIN cleanup result.
type SessionOpener interface {
	OpenSession(context.Context, OpenAttemptRequest) (SessionHandle, error)
}

// SessionHandle is owned exclusively by CleanupBroker. Revoke must honor
// context cancellation and return only after it no longer accesses mutable
// handle state. The Broker then calls Destroy exactly once. The handle is never
// returned from OpenAttempt, persisted, serialized, or logged.
type SessionHandle interface {
	Revoke(context.Context) error
	Destroy()
}

// ProofAuthority signs and verifies the raw SHA-256 digest of the canonical
// cleanup proof tuple. Implementations must be concurrency-safe, honor context
// cancellation, and neither retain nor mutate digest/signature input slices.
// Key loading and production signer transport are outside this package.
type ProofAuthority interface {
	SignCleanupProof(context.Context, []byte) ([]byte, error)
	VerifyCleanupProof(context.Context, []byte, []byte) error
}

// CleanupBroker owns every live SessionHandle and coalesces concurrent or
// response-loss replays by opaque attempt ID.
type CleanupBroker struct {
	state *brokerState
}

type brokerState struct {
	mu          sync.Mutex
	opener      SessionOpener
	authority   ProofAuthority
	attempts    map[string]*attemptState
	lifetime    context.Context
	cancel      context.CancelFunc
	operations  sync.WaitGroup
	destroyDone chan struct{}
	destroyed   bool
}

type attemptState struct {
	request OpenAttemptRequest

	openDone     chan struct{}
	openComplete bool
	openErr      error
	handle       SessionHandle

	revokeDone     chan struct{}
	revokeStarted  bool
	revokeComplete bool
	revokeErr      error
	proof          discoveryqueue.CleanupProof
}

func NewCleanupBroker(opener SessionOpener, authority ProofAuthority) (*CleanupBroker, error) {
	if nilInterface(opener) || nilInterface(authority) {
		return nil, ErrInvalidInput
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &CleanupBroker{
		state: &brokerState{
			opener:      opener,
			authority:   authority,
			attempts:    make(map[string]*attemptState),
			lifetime:    lifetime,
			cancel:      cancel,
			destroyDone: make(chan struct{}),
		},
	}, nil
}

// OpenAttempt creates at most one logical session for an exact attempt. The
// returned AttemptSession is only a redacted process-local acknowledgement; it
// never contains or exposes the Broker-owned SessionHandle.
func (broker *CleanupBroker) OpenAttempt(
	ctx context.Context,
	request OpenAttemptRequest,
) (*AttemptSession, error) {
	if ctx == nil || request.Validate() != nil {
		return nil, ErrInvalidInput
	}
	if broker == nil || broker.state == nil {
		return nil, ErrBrokerUnavailable
	}
	private := broker.state

	for {
		private.mu.Lock()
		if private.destroyed {
			private.mu.Unlock()
			return nil, ErrBrokerUnavailable
		}
		state, exists := private.attempts[request.Attempt.AttemptID]
		if exists {
			if !sameRequest(state.request, request) {
				private.mu.Unlock()
				return nil, ErrAttemptDrift
			}
			if !state.openComplete {
				done := state.openDone
				private.mu.Unlock()
				if err := waitFor(ctx, private.lifetime, done); err != nil {
					return nil, err
				}
				continue
			}
			if state.revokeStarted || state.revokeComplete {
				private.mu.Unlock()
				return nil, ErrAttemptClosed
			}
			if state.openErr != nil {
				openErr := state.openErr
				private.mu.Unlock()
				return nil, openErr
			}
			if nilInterface(state.handle) {
				private.mu.Unlock()
				return nil, ErrAttemptUncertain
			}
			private.mu.Unlock()
			return newAttemptSession(request.Attempt), nil
		}

		state = &attemptState{
			request:  request,
			openDone: make(chan struct{}),
		}
		private.attempts[request.Attempt.AttemptID] = state
		private.operations.Add(1)
		private.mu.Unlock()

		operationCtx, releaseOperation := linkedContext(ctx, private.lifetime)
		handle, openErr := private.opener.OpenSession(operationCtx, request)
		releaseOperation()
		mappedErr := classifyOpenResult(handle, openErr)

		private.mu.Lock()
		if private.destroyed {
			state.openErr = ErrBrokerUnavailable
			state.openComplete = true
			close(state.openDone)
			private.mu.Unlock()
			if !nilInterface(handle) {
				handle.Destroy()
			}
			private.operations.Done()
			return nil, ErrBrokerUnavailable
		}
		state.handle = handle
		state.openErr = mappedErr
		state.openComplete = true
		close(state.openDone)
		private.mu.Unlock()
		private.operations.Done()

		if mappedErr != nil {
			return nil, mappedErr
		}
		return newAttemptSession(request.Attempt), nil
	}
}

// RevokeAttempt requires only the opaque attempt ID. The first call consumes
// the Broker-owned handle and seals one signed REVOKED or UNCERTAIN proof;
// every replay returns an exact clone of that proof without another revoke or
// signature.
func (broker *CleanupBroker) RevokeAttempt(
	ctx context.Context,
	attemptID string,
) (discoveryqueue.CleanupProof, error) {
	if ctx == nil || !validAttemptID(attemptID) {
		return discoveryqueue.CleanupProof{}, ErrInvalidInput
	}
	if broker == nil || broker.state == nil {
		return discoveryqueue.CleanupProof{}, ErrBrokerUnavailable
	}
	private := broker.state

	for {
		private.mu.Lock()
		if private.destroyed {
			private.mu.Unlock()
			return discoveryqueue.CleanupProof{}, ErrBrokerUnavailable
		}
		state, exists := private.attempts[attemptID]
		if !exists {
			private.mu.Unlock()
			return discoveryqueue.CleanupProof{}, ErrAttemptNotFound
		}
		if !state.openComplete {
			done := state.openDone
			private.mu.Unlock()
			if err := waitFor(ctx, private.lifetime, done); err != nil {
				return discoveryqueue.CleanupProof{}, err
			}
			continue
		}
		if state.revokeComplete {
			if state.revokeErr != nil {
				revokeErr := state.revokeErr
				private.mu.Unlock()
				return discoveryqueue.CleanupProof{}, revokeErr
			}
			proof := state.proof.Clone()
			private.mu.Unlock()
			return proof, nil
		}
		if state.revokeStarted {
			done := state.revokeDone
			private.mu.Unlock()
			if err := waitFor(ctx, private.lifetime, done); err != nil {
				return discoveryqueue.CleanupProof{}, err
			}
			continue
		}
		if nilInterface(state.handle) {
			openErr := state.openErr
			private.mu.Unlock()
			if openErr != nil {
				return discoveryqueue.CleanupProof{}, openErr
			}
			return discoveryqueue.CleanupProof{}, ErrAttemptUncertain
		}

		handle := state.handle
		request := state.request
		openErr := state.openErr
		state.revokeStarted = true
		state.revokeDone = make(chan struct{})
		private.operations.Add(1)
		private.mu.Unlock()

		operationCtx, releaseOperation := linkedContext(ctx, private.lifetime)
		revokeErr := handle.Revoke(operationCtx)
		releaseOperation()
		handle.Destroy()
		status := assetcatalog.CredentialCleanupRevoked
		if openErr != nil || revokeErr != nil {
			status = assetcatalog.CredentialCleanupUncertain
		}
		var proof discoveryqueue.CleanupProof
		var proofErr error
		if errors.Is(openErr, ErrSessionAuthentication) {
			proofErr = ErrSessionAuthentication
		} else {
			proof, proofErr = broker.signProof(private.lifetime, request, status)
		}
		resultProof := proof.Clone()

		private.mu.Lock()
		state.handle = nil
		state.revokeComplete = true
		if private.destroyed {
			proof.Destroy()
			resultProof.Destroy()
			state.revokeErr = ErrBrokerUnavailable
			close(state.revokeDone)
			private.mu.Unlock()
			private.operations.Done()
			return discoveryqueue.CleanupProof{}, ErrBrokerUnavailable
		}
		if proofErr != nil {
			state.revokeErr = proofErr
		} else {
			state.proof = proof
		}
		close(state.revokeDone)
		private.mu.Unlock()
		private.operations.Done()

		if proofErr != nil {
			return discoveryqueue.CleanupProof{}, proofErr
		}
		return resultProof, nil
	}
}

// VerifyCleanupProof implements discoveryqueue.CleanupProofVerifier without
// trusting any coordinate, status, digest, or authentication byte supplied by
// the proof envelope.
func (broker *CleanupBroker) VerifyCleanupProof(
	ctx context.Context,
	proof discoveryqueue.CleanupProof,
) error {
	if ctx == nil || proof.Validate() != nil {
		return ErrProofAuthentication
	}
	if broker == nil || broker.state == nil {
		return ErrBrokerUnavailable
	}
	private := broker.state
	private.mu.Lock()
	if private.destroyed {
		private.mu.Unlock()
		return ErrBrokerUnavailable
	}
	authority := private.authority
	private.operations.Add(1)
	private.mu.Unlock()
	defer private.operations.Done()

	request := OpenAttemptRequest{
		Coordinates: proof.Coordinates(),
		Attempt:     proof.Attempt(),
	}
	if request.Validate() != nil {
		return ErrProofAuthentication
	}
	digest := cleanupProofDigest(request, proof.Status())
	if subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%x", digest)), []byte(proof.DigestSHA256())) != 1 {
		return ErrProofAuthentication
	}
	signature := proof.Authentication()
	defer clear(signature)
	verificationCtx, releaseVerification := linkedContext(ctx, private.lifetime)
	defer releaseVerification()
	verificationErr := authority.VerifyCleanupProof(verificationCtx, digest[:], signature)
	private.mu.Lock()
	destroyed := private.destroyed
	private.mu.Unlock()
	if destroyed {
		return ErrBrokerUnavailable
	}
	if verificationErr != nil {
		return ErrProofAuthentication
	}
	return nil
}

func (broker *CleanupBroker) signProof(
	ctx context.Context,
	request OpenAttemptRequest,
	status assetcatalog.CredentialCleanupStatus,
) (discoveryqueue.CleanupProof, error) {
	if broker == nil || broker.state == nil {
		return discoveryqueue.CleanupProof{}, ErrBrokerUnavailable
	}
	digest := cleanupProofDigest(request, status)
	signature, err := broker.state.authority.SignCleanupProof(ctx, digest[:])
	if err != nil {
		clear(signature)
		return discoveryqueue.CleanupProof{}, ErrProofAuthentication
	}
	defer clear(signature)
	proof, err := discoveryqueue.NewCleanupProof(
		request.Coordinates,
		request.Attempt,
		status,
		fmt.Sprintf("%x", digest),
		signature,
	)
	if err != nil {
		return discoveryqueue.CleanupProof{}, ErrProofAuthentication
	}
	return proof, nil
}

// Destroy clears every Broker-owned raw handle and cached authentication
// envelope and permanently closes this process-local broker. It never claims
// that external revocation succeeded.
func (broker *CleanupBroker) Destroy() {
	if broker == nil || broker.state == nil {
		return
	}
	private := broker.state
	private.mu.Lock()
	if private.destroyed {
		done := private.destroyDone
		private.mu.Unlock()
		<-done
		return
	}
	private.destroyed = true
	private.cancel()
	private.mu.Unlock()

	private.operations.Wait()

	private.mu.Lock()
	handles := make([]SessionHandle, 0, len(private.attempts))
	for _, state := range private.attempts {
		if !nilInterface(state.handle) {
			handles = append(handles, state.handle)
			state.handle = nil
		}
		state.proof.Destroy()
	}
	private.attempts = nil
	private.mu.Unlock()

	for _, handle := range handles {
		handle.Destroy()
	}
	close(private.destroyDone)
}

// AttemptSession is a process-local acknowledgement of an opened attempt. It
// contains no credential, endpoint, runtime, transport payload, or raw handle.
type AttemptSession struct {
	state *attemptSessionState
}

type attemptSessionState struct {
	mu        sync.RWMutex
	attempt   discoveryqueue.CleanupAttempt
	destroyed bool
}

func newAttemptSession(attempt discoveryqueue.CleanupAttempt) *AttemptSession {
	return &AttemptSession{state: &attemptSessionState{attempt: attempt}}
}

func (session *AttemptSession) Attempt() (discoveryqueue.CleanupAttempt, error) {
	if session == nil || session.state == nil {
		return discoveryqueue.CleanupAttempt{}, ErrSessionDestroyed
	}
	private := session.state
	private.mu.RLock()
	defer private.mu.RUnlock()
	if private.destroyed {
		return discoveryqueue.CleanupAttempt{}, ErrSessionDestroyed
	}
	return private.attempt, nil
}

func (session *AttemptSession) Destroy() {
	if session == nil || session.state == nil {
		return
	}
	private := session.state
	private.mu.Lock()
	defer private.mu.Unlock()
	if private.destroyed {
		return
	}
	private.destroyed = true
	private.attempt = discoveryqueue.CleanupAttempt{}
}

func (AttemptSession) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (AttemptSession) UnmarshalJSON([]byte) error { return ErrSensitiveSerialization }
func (AttemptSession) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (AttemptSession) UnmarshalText([]byte) error { return ErrSensitiveSerialization }
func (AttemptSession) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (AttemptSession) UnmarshalBinary([]byte) error { return ErrSensitiveSerialization }
func (AttemptSession) String() string               { return sessionRedaction }
func (AttemptSession) GoString() string             { return sessionRedaction }
func (AttemptSession) LogValue() slog.Value         { return slog.StringValue(sessionRedaction) }
func (AttemptSession) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, sessionRedaction)
}

func (CleanupBroker) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (CleanupBroker) UnmarshalJSON([]byte) error { return ErrSensitiveSerialization }
func (CleanupBroker) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (CleanupBroker) UnmarshalText([]byte) error { return ErrSensitiveSerialization }
func (CleanupBroker) MarshalBinary() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (CleanupBroker) UnmarshalBinary([]byte) error { return ErrSensitiveSerialization }
func (CleanupBroker) String() string               { return brokerRedaction }
func (CleanupBroker) GoString() string             { return brokerRedaction }
func (CleanupBroker) LogValue() slog.Value         { return slog.StringValue(brokerRedaction) }
func (CleanupBroker) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, brokerRedaction)
}

func cleanupProofDigest(
	request OpenAttemptRequest,
	status assetcatalog.CredentialCleanupStatus,
) [sha256.Size]byte {
	return sha256.Sum256(framedTuple(
		[]byte(proofDomain),
		[]byte(request.Coordinates.Scope.TenantID),
		[]byte(request.Coordinates.Scope.WorkspaceID),
		[]byte(request.Coordinates.RunID),
		[]byte(request.Attempt.AttemptID),
		[]byte(strconv.FormatInt(request.Attempt.AttemptEpoch, 10)),
		[]byte(status),
	))
}

func framedTuple(fields ...[]byte) []byte {
	size := 0
	for _, field := range fields {
		size += 1 + 4 + len(field)
	}
	framed := make([]byte, 0, size)
	for _, field := range fields {
		framed = append(framed, 1)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed
}

func sameRequest(left, right OpenAttemptRequest) bool {
	return left.Coordinates.Scope.TenantID == right.Coordinates.Scope.TenantID &&
		left.Coordinates.Scope.WorkspaceID == right.Coordinates.Scope.WorkspaceID &&
		left.Coordinates.RunID == right.Coordinates.RunID &&
		left.Attempt == right.Attempt
}

func classifyOpenResult(handle SessionHandle, err error) error {
	if err == nil && !nilInterface(handle) {
		return nil
	}
	if errors.Is(err, ErrSessionAuthentication) {
		return ErrSessionAuthentication
	}
	return ErrAttemptUncertain
}

func linkedContext(
	parent context.Context,
	lifetime context.Context,
) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(lifetime, cancel)
	return ctx, func() {
		_ = stop()
		cancel()
	}
}

func waitFor(ctx context.Context, lifetime context.Context, done <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-lifetime.Done():
		return ErrBrokerUnavailable
	case <-done:
		return nil
	}
}

func validAttemptID(attemptID string) bool {
	return (discoveryqueue.CleanupAttempt{
		RunID:        "00000000-0000-4000-8000-000000000001",
		AttemptID:    attemptID,
		AttemptEpoch: 1,
	}).Valid()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
