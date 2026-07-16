package discoverycleanup_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
)

func TestOpenAttemptResponseLossAndConcurrentReplayCreateOneLogicalSession(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	authority := newTestProofAuthority()
	broker, err := discoverycleanup.NewCleanupBroker(opener, authority)
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)

	request := cleanupRequest(1)
	const callers = 32
	start := make(chan struct{})
	results := make(chan *discoverycleanup.AttemptSession, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			session, openErr := broker.OpenAttempt(context.Background(), request)
			results <- session
			errs <- openErr
		}()
	}
	close(start)

	for range callers {
		if openErr := <-errs; openErr != nil {
			t.Fatalf("OpenAttempt() error = %v", openErr)
		}
		session := <-results
		if got, sessionErr := session.Attempt(); sessionErr != nil || got != request.Attempt {
			t.Fatalf("Attempt() = %#v, %v; want %#v", got, sessionErr, request.Attempt)
		}
		session.Destroy()
	}
	if got := opener.openCount(request.Attempt.AttemptID); got != 1 {
		t.Fatalf("OpenSession() calls = %d, want 1", got)
	}

	// Simulate loss of every earlier response. An exact retry still returns a
	// fresh process-local wrapper without opening another logical session.
	replayed, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt(replay) error = %v", err)
	}
	replayed.Destroy()
	if got := opener.openCount(request.Attempt.AttemptID); got != 1 {
		t.Fatalf("OpenSession() calls after response loss = %d, want 1", got)
	}
}

func TestDifferentAttemptsAreIsolatedAndReopenDriftFailsClosed(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	broker := mustBroker(t, opener, newTestProofAuthority())
	firstRequest := cleanupRequest(1)
	secondRequest := cleanupRequest(2)

	first, err := broker.OpenAttempt(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("OpenAttempt(first) error = %v", err)
	}
	first.Destroy()
	second, err := broker.OpenAttempt(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("OpenAttempt(second) error = %v", err)
	}
	second.Destroy()

	firstHandle := opener.handle(firstRequest.Attempt.AttemptID)
	secondHandle := opener.handle(secondRequest.Attempt.AttemptID)
	if _, err := broker.RevokeAttempt(context.Background(), firstRequest.Attempt.AttemptID); err != nil {
		t.Fatalf("RevokeAttempt(first) error = %v", err)
	}
	if firstHandle.revokeCount() != 1 || firstHandle.destroyCount() != 1 {
		t.Fatalf("first handle revoke/destroy = %d/%d, want 1/1",
			firstHandle.revokeCount(), firstHandle.destroyCount())
	}
	if secondHandle.revokeCount() != 0 || secondHandle.destroyCount() != 0 {
		t.Fatalf("second handle changed while revoking first: revoke/destroy = %d/%d",
			secondHandle.revokeCount(), secondHandle.destroyCount())
	}

	drifted := firstRequest
	drifted.Attempt.AttemptEpoch++
	if _, err := broker.OpenAttempt(context.Background(), drifted); !errors.Is(err, discoverycleanup.ErrAttemptDrift) {
		t.Fatalf("OpenAttempt(drifted replay) error = %v, want ErrAttemptDrift", err)
	}
	if _, err := broker.RevokeAttempt(context.Background(), uuid(99)); !errors.Is(err, discoverycleanup.ErrAttemptNotFound) {
		t.Fatalf("RevokeAttempt(missing) error = %v, want ErrAttemptNotFound", err)
	}
}

func TestRevokeAttemptResponseLossReturnsSameSignedProof(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	authority := newTestProofAuthority()
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	session.Destroy()

	first, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	firstStatus := first.Status()
	firstDigest := first.DigestSHA256()
	firstAuthentication := first.Authentication()
	first.Destroy()
	replayed, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt(replay) error = %v", err)
	}
	defer replayed.Destroy()

	if firstStatus != assetcatalog.CredentialCleanupRevoked ||
		replayed.Status() != firstStatus ||
		replayed.DigestSHA256() != firstDigest ||
		!bytes.Equal(replayed.Authentication(), firstAuthentication) {
		t.Fatalf("replayed proof differs: first=%s/%s replay=%s/%s",
			firstStatus, firstDigest, replayed.Status(), replayed.DigestSHA256())
	}
	mutableAuthentication := replayed.Authentication()
	mutableAuthentication[0] ^= 0xff
	again, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt(second replay) error = %v", err)
	}
	defer again.Destroy()
	if !bytes.Equal(again.Authentication(), firstAuthentication) {
		t.Fatal("proof cache aliased a returned authentication slice")
	}
	clear(mutableAuthentication)
	clear(firstAuthentication)
	handle := opener.handle(request.Attempt.AttemptID)
	if handle.revokeCount() != 1 || handle.destroyCount() != 1 || authority.signCount() != 1 {
		t.Fatalf("revoke/destroy/sign calls = %d/%d/%d, want 1/1/1",
			handle.revokeCount(), handle.destroyCount(), authority.signCount())
	}
	if err := broker.VerifyCleanupProof(context.Background(), replayed); err != nil {
		t.Fatalf("VerifyCleanupProof(replay) error = %v", err)
	}
}

func TestRevokeUncertainIsSignedOnceAndCannotBecomeClean(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	opener.revokeErr = errors.New("sensitive upstream ambiguity: token=do-not-log")
	authority := newTestProofAuthority()
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	session.Destroy()

	first, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt(uncertain) error = %v", err)
	}
	defer first.Destroy()
	replayed, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt(uncertain replay) error = %v", err)
	}
	defer replayed.Destroy()

	if first.Status() != assetcatalog.CredentialCleanupUncertain ||
		replayed.Status() != assetcatalog.CredentialCleanupUncertain ||
		first.DigestSHA256() != replayed.DigestSHA256() ||
		!bytes.Equal(first.Authentication(), replayed.Authentication()) {
		t.Fatalf("uncertain proof was not stable: first=%s/%s replay=%s/%s",
			first.Status(), first.DigestSHA256(), replayed.Status(), replayed.DigestSHA256())
	}
	if opener.handle(request.Attempt.AttemptID).revokeCount() != 1 || authority.signCount() != 1 {
		t.Fatalf("uncertain revoke/sign calls = %d/%d, want 1/1",
			opener.handle(request.Attempt.AttemptID).revokeCount(), authority.signCount())
	}
	if err := broker.VerifyCleanupProof(context.Background(), replayed); err != nil {
		t.Fatalf("VerifyCleanupProof(uncertain) error = %v", err)
	}
}

func TestAmbiguousOpenHandleCanOnlyProduceUncertainProof(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	opener.openErr = errors.New("ambiguous open response with secret=do-not-log")
	authority := newTestProofAuthority()
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)

	if _, err := broker.OpenAttempt(context.Background(), request); !errors.Is(err, discoverycleanup.ErrAttemptUncertain) {
		t.Fatalf("OpenAttempt(ambiguous) error = %v, want ErrAttemptUncertain", err)
	}
	proof, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt(ambiguous open) error = %v", err)
	}
	defer proof.Destroy()
	if proof.Status() != assetcatalog.CredentialCleanupUncertain {
		t.Fatalf("ambiguous open cleanup status = %s, want UNCERTAIN", proof.Status())
	}
	if opener.handle(request.Attempt.AttemptID).revokeCount() != 1 || authority.signCount() != 1 {
		t.Fatalf("ambiguous open revoke/sign calls = %d/%d, want 1/1",
			opener.handle(request.Attempt.AttemptID).revokeCount(), authority.signCount())
	}
}

func TestAuthenticationFailedOpenNeverProducesCleanProof(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	opener.openErr = discoverycleanup.ErrSessionAuthentication
	authority := newTestProofAuthority()
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)

	if _, err := broker.OpenAttempt(context.Background(), request); !errors.Is(err, discoverycleanup.ErrSessionAuthentication) {
		t.Fatalf("OpenAttempt(authentication failure) error = %v, want ErrSessionAuthentication", err)
	}
	if _, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID); !errors.Is(err, discoverycleanup.ErrSessionAuthentication) {
		t.Fatalf("RevokeAttempt(authentication failure) error = %v, want ErrSessionAuthentication", err)
	}
	if _, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID); !errors.Is(err, discoverycleanup.ErrSessionAuthentication) {
		t.Fatalf("RevokeAttempt(authentication replay) error = %v, want ErrSessionAuthentication", err)
	}
	handle := opener.handle(request.Attempt.AttemptID)
	if handle.revokeCount() != 1 || handle.destroyCount() != 1 || authority.signCount() != 0 {
		t.Fatalf("authentication failure revoke/destroy/sign calls = %d/%d/%d, want 1/1/0",
			handle.revokeCount(), handle.destroyCount(), authority.signCount())
	}
}

func TestDestroyCancelsBlockedOpenAndDestroysReturnedHandle(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	opener.blockOpen = true
	broker := mustBroker(t, opener, newTestProofAuthority())
	request := cleanupRequest(1)
	openResult := make(chan error, 1)
	go func() {
		_, err := broker.OpenAttempt(context.Background(), request)
		openResult <- err
	}()
	<-opener.openStarted

	broker.Destroy()
	if err := <-openResult; !errors.Is(err, discoverycleanup.ErrBrokerUnavailable) {
		t.Fatalf("blocked OpenAttempt() error = %v, want ErrBrokerUnavailable", err)
	}
	handle := opener.handle(request.Attempt.AttemptID)
	if handle.destroyCount() != 1 {
		t.Fatalf("blocked-open handle Destroy() calls = %d, want 1", handle.destroyCount())
	}
}

func TestDestroyCancelsBlockedRevokeAndReleasesWaiters(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	opener.blockRevoke = true
	broker := mustBroker(t, opener, newTestProofAuthority())
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	session.Destroy()

	firstResult := make(chan error, 1)
	go func() {
		_, revokeErr := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
		firstResult <- revokeErr
	}()
	handle := opener.handle(request.Attempt.AttemptID)
	<-handle.revokeStarted

	waiterResult := make(chan error, 1)
	go func() {
		_, revokeErr := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
		waiterResult <- revokeErr
	}()
	broker.Destroy()

	if err := <-firstResult; !errors.Is(err, discoverycleanup.ErrBrokerUnavailable) {
		t.Fatalf("in-flight RevokeAttempt() error = %v, want ErrBrokerUnavailable", err)
	}
	if err := <-waiterResult; !errors.Is(err, discoverycleanup.ErrBrokerUnavailable) {
		t.Fatalf("waiting RevokeAttempt() error = %v, want ErrBrokerUnavailable", err)
	}
	if handle.revokeCount() != 1 || handle.destroyCount() != 1 {
		t.Fatalf("blocked-revoke handle revoke/destroy calls = %d/%d, want 1/1",
			handle.revokeCount(), handle.destroyCount())
	}
}

func TestProofSealingOutlivesCallerResponseAndStartsAfterHandleDestruction(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	authority := newTestProofAuthority()
	authority.blockSign = true
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	session.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	type revokeResult struct {
		proof discoveryqueue.CleanupProof
		err   error
	}
	result := make(chan revokeResult, 1)
	go func() {
		proof, revokeErr := broker.RevokeAttempt(ctx, request.Attempt.AttemptID)
		result <- revokeResult{proof: proof, err: revokeErr}
	}()
	<-authority.signStarted
	destroyedBeforeSignCompleted := opener.handle(request.Attempt.AttemptID).destroyCount()
	cancel() // response/caller loss must not cancel durable proof sealing
	close(authority.signRelease)

	got := <-result
	defer got.proof.Destroy()
	if got.err != nil {
		t.Fatalf("RevokeAttempt() after caller loss error = %v", got.err)
	}
	if destroyedBeforeSignCompleted != 1 {
		t.Fatalf("handle Destroy() calls at proof sealing = %d, want 1", destroyedBeforeSignCompleted)
	}
	if got.proof.Status() != assetcatalog.CredentialCleanupRevoked {
		t.Fatalf("cleanup status after caller loss = %s, want REVOKED", got.proof.Status())
	}
	replayed, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt(replay) error = %v", err)
	}
	defer replayed.Destroy()
	if replayed.DigestSHA256() != got.proof.DigestSHA256() ||
		!bytes.Equal(replayed.Authentication(), got.proof.Authentication()) {
		t.Fatal("proof changed after caller-response loss")
	}
}

func TestConcurrentDestroyWaitsForRawHandleDestruction(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	opener.blockDestroy = true
	broker := mustBroker(t, opener, newTestProofAuthority())
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	session.Destroy()
	handle := opener.handle(request.Attempt.AttemptID)

	firstDone := make(chan struct{})
	go func() {
		broker.Destroy()
		close(firstDone)
	}()
	<-handle.destroyStarted

	secondStarted := make(chan struct{})
	secondResult := make(chan bool, 1)
	go func() {
		close(secondStarted)
		broker.Destroy()
		select {
		case <-handle.destroyCompleted:
			secondResult <- true
		default:
			secondResult <- false
		}
	}()
	<-secondStarted
	runtime.Gosched()
	close(handle.destroyRelease)
	if waited := <-secondResult; !waited {
		t.Fatal("second Destroy returned before raw handle destruction completed")
	}
	<-firstDone
	if handle.destroyCount() != 1 {
		t.Fatalf("raw handle Destroy() calls = %d, want 1", handle.destroyCount())
	}
}

func TestDestroyCancelsAndJoinsBlockedProofVerification(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	authority := newTestProofAuthority()
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	session.Destroy()
	proof, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	defer proof.Destroy()

	authority.blockVerify = true
	verifyResult := make(chan error, 1)
	go func() {
		verifyResult <- broker.VerifyCleanupProof(context.Background(), proof)
	}()
	<-authority.verifyStarted
	broker.Destroy()
	close(authority.verifyRelease)
	if err := <-verifyResult; !errors.Is(err, discoverycleanup.ErrBrokerUnavailable) {
		t.Fatalf("VerifyCleanupProof() after Destroy error = %v, want ErrBrokerUnavailable", err)
	}
}

func TestCleanupProofBindsExactTupleDigestAndSignature(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	authority := newTestProofAuthority()
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	session.Destroy()
	proof, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	defer proof.Destroy()

	tuple := independentCleanupProofTuple(request, assetcatalog.CredentialCleanupRevoked)
	wantDigest := sha256.Sum256(tuple)
	if got := proof.DigestSHA256(); got != fmt.Sprintf("%x", wantDigest) {
		t.Fatalf("proof digest = %q, want %x", got, wantDigest)
	}
	if got := authority.lastSigned(); !bytes.Equal(got, wantDigest[:]) {
		t.Fatalf("signed bytes = %x, want raw digest %x", got, wantDigest)
	}
	if err := broker.VerifyCleanupProof(context.Background(), proof); err != nil {
		t.Fatalf("VerifyCleanupProof() error = %v", err)
	}

	driftedAttempt := request.Attempt
	driftedAttempt.AttemptEpoch++
	drifted, err := discoveryqueue.NewCleanupProof(
		request.Coordinates,
		driftedAttempt,
		proof.Status(),
		proof.DigestSHA256(),
		proof.Authentication(),
	)
	if err != nil {
		t.Fatalf("NewCleanupProof(drifted) error = %v", err)
	}
	defer drifted.Destroy()
	if err := broker.VerifyCleanupProof(context.Background(), drifted); !errors.Is(err, discoverycleanup.ErrProofAuthentication) {
		t.Fatalf("VerifyCleanupProof(drifted) error = %v, want ErrProofAuthentication", err)
	}

	badSignature, err := discoveryqueue.NewCleanupProof(
		request.Coordinates,
		request.Attempt,
		proof.Status(),
		proof.DigestSHA256(),
		bytes.Repeat([]byte{0xff}, 32),
	)
	if err != nil {
		t.Fatalf("NewCleanupProof(bad signature) error = %v", err)
	}
	defer badSignature.Destroy()
	if err := broker.VerifyCleanupProof(context.Background(), badSignature); !errors.Is(err, discoverycleanup.ErrProofAuthentication) {
		t.Fatalf("VerifyCleanupProof(bad signature) error = %v, want ErrProofAuthentication", err)
	}
}

func TestSessionAndBrokerRejectSerializationFormattingAndLoggingLeaks(t *testing.T) {
	t.Parallel()

	const rawHandleSecret = "raw-session-handle-secret-do-not-leak"
	opener := newTestOpener()
	opener.handleSecret = rawHandleSecret
	broker := mustBroker(t, opener, newTestProofAuthority())
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}

	assertSensitiveBoundary(t, session, request.Attempt.AttemptID, rawHandleSecret)
	assertSensitiveBoundary(t, broker, request.Attempt.AttemptID, rawHandleSecret)
	assertSensitiveBoundary(t, *session, request.Attempt.AttemptID, rawHandleSecret)
	assertSensitiveBoundary(t, *broker, request.Attempt.AttemptID, rawHandleSecret)

	session.Destroy()
	session.Destroy()
	if _, err := session.Attempt(); !errors.Is(err, discoverycleanup.ErrSessionDestroyed) {
		t.Fatalf("Attempt() after Destroy error = %v, want ErrSessionDestroyed", err)
	}

	handle := opener.handle(request.Attempt.AttemptID)
	broker.Destroy()
	broker.Destroy()
	if handle.destroyCount() != 1 {
		t.Fatalf("handle Destroy() calls = %d, want 1", handle.destroyCount())
	}
	if _, err := broker.OpenAttempt(context.Background(), cleanupRequest(2)); !errors.Is(err, discoverycleanup.ErrBrokerUnavailable) {
		t.Fatalf("OpenAttempt() after broker Destroy error = %v, want ErrBrokerUnavailable", err)
	}
	if _, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID); !errors.Is(err, discoverycleanup.ErrBrokerUnavailable) {
		t.Fatalf("RevokeAttempt() after broker Destroy error = %v, want ErrBrokerUnavailable", err)
	}
}

func mustBroker(
	t *testing.T,
	opener discoverycleanup.SessionOpener,
	authority discoverycleanup.ProofAuthority,
) *discoverycleanup.CleanupBroker {
	t.Helper()
	broker, err := discoverycleanup.NewCleanupBroker(opener, authority)
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)
	return broker
}

func cleanupRequest(sequence int) discoverycleanup.OpenAttemptRequest {
	runID := uuid(10 + sequence)
	return discoverycleanup.OpenAttemptRequest{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{
				TenantID:    uuid(1),
				WorkspaceID: uuid(2),
			},
			RunID: runID,
		},
		Attempt: discoveryqueue.CleanupAttempt{
			RunID:        runID,
			AttemptID:    uuid(20 + sequence),
			AttemptEpoch: int64(sequence),
		},
	}
}

func uuid(value int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", value)
}

type testOpener struct {
	mu           sync.Mutex
	openCalls    map[string]int
	handles      map[string]*testSessionHandle
	openErr      error
	revokeErr    error
	handleSecret string
	blockOpen    bool
	blockRevoke  bool
	blockDestroy bool
	openStarted  chan struct{}
	openOnce     sync.Once
}

func newTestOpener() *testOpener {
	return &testOpener{
		openCalls:   make(map[string]int),
		handles:     make(map[string]*testSessionHandle),
		openStarted: make(chan struct{}),
	}
}

func (opener *testOpener) OpenSession(
	ctx context.Context,
	request discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	opener.mu.Lock()
	opener.openCalls[request.Attempt.AttemptID]++
	handle := &testSessionHandle{
		revokeErr:        opener.revokeErr,
		secret:           opener.handleSecret,
		blockRevoke:      opener.blockRevoke,
		blockDestroy:     opener.blockDestroy,
		revokeStarted:    make(chan struct{}),
		destroyStarted:   make(chan struct{}),
		destroyRelease:   make(chan struct{}),
		destroyCompleted: make(chan struct{}),
	}
	opener.handles[request.Attempt.AttemptID] = handle
	openErr := opener.openErr
	blockOpen := opener.blockOpen
	opener.mu.Unlock()
	opener.openOnce.Do(func() { close(opener.openStarted) })
	if blockOpen {
		<-ctx.Done()
		return handle, ctx.Err()
	}
	return handle, openErr
}

func (opener *testOpener) openCount(attemptID string) int {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.openCalls[attemptID]
}

func (opener *testOpener) handle(attemptID string) *testSessionHandle {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.handles[attemptID]
}

type testSessionHandle struct {
	mu               sync.Mutex
	revokeCalls      int
	destroyCalls     int
	revokeErr        error
	secret           string
	blockRevoke      bool
	revokeStarted    chan struct{}
	revokeOnce       sync.Once
	blockDestroy     bool
	destroyStarted   chan struct{}
	destroyRelease   chan struct{}
	destroyCompleted chan struct{}
	destroyOnce      sync.Once
}

func (handle *testSessionHandle) Revoke(ctx context.Context) error {
	handle.mu.Lock()
	handle.revokeCalls++
	revokeErr := handle.revokeErr
	blockRevoke := handle.blockRevoke
	handle.mu.Unlock()
	handle.revokeOnce.Do(func() { close(handle.revokeStarted) })
	if blockRevoke {
		<-ctx.Done()
		return ctx.Err()
	}
	return revokeErr
}

func (handle *testSessionHandle) Destroy() {
	handle.mu.Lock()
	handle.destroyCalls++
	handle.secret = ""
	blockDestroy := handle.blockDestroy
	handle.mu.Unlock()
	handle.destroyOnce.Do(func() { close(handle.destroyStarted) })
	if blockDestroy {
		<-handle.destroyRelease
	}
	close(handle.destroyCompleted)
}

func (handle *testSessionHandle) revokeCount() int {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.revokeCalls
}

func (handle *testSessionHandle) destroyCount() int {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.destroyCalls
}

type testProofAuthority struct {
	mu            sync.Mutex
	key           []byte
	signCalls     int
	signedData    []byte
	blockSign     bool
	signStarted   chan struct{}
	signRelease   chan struct{}
	signOnce      sync.Once
	blockVerify   bool
	verifyStarted chan struct{}
	verifyRelease chan struct{}
	verifyOnce    sync.Once
}

func newTestProofAuthority() *testProofAuthority {
	return &testProofAuthority{
		key:           bytes.Repeat([]byte{0x5a}, 32),
		signStarted:   make(chan struct{}),
		signRelease:   make(chan struct{}),
		verifyStarted: make(chan struct{}),
		verifyRelease: make(chan struct{}),
	}
}

func (authority *testProofAuthority) SignCleanupProof(ctx context.Context, digest []byte) ([]byte, error) {
	authority.mu.Lock()
	authority.signCalls++
	authority.signedData = bytes.Clone(digest)
	blockSign := authority.blockSign
	authority.mu.Unlock()
	authority.signOnce.Do(func() { close(authority.signStarted) })
	if blockSign {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-authority.signRelease:
		}
	}
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (authority *testProofAuthority) VerifyCleanupProof(
	ctx context.Context,
	digest []byte,
	signature []byte,
) error {
	authority.mu.Lock()
	blockVerify := authority.blockVerify
	authority.mu.Unlock()
	authority.verifyOnce.Do(func() { close(authority.verifyStarted) })
	if blockVerify {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-authority.verifyRelease:
		}
	}
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	if subtle.ConstantTimeCompare(mac.Sum(nil), signature) != 1 {
		return errors.New("test signature rejected")
	}
	return nil
}

func (authority *testProofAuthority) signCount() int {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.signCalls
}

func (authority *testProofAuthority) lastSigned() []byte {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return bytes.Clone(authority.signedData)
}

func independentCleanupProofTuple(
	request discoverycleanup.OpenAttemptRequest,
	status assetcatalog.CredentialCleanupStatus,
) []byte {
	fields := [][]byte{
		[]byte("asset-source-cleanup-proof.v1"),
		[]byte(request.Coordinates.Scope.TenantID),
		[]byte(request.Coordinates.Scope.WorkspaceID),
		[]byte(request.Coordinates.RunID),
		[]byte(request.Attempt.AttemptID),
		[]byte(strconv.FormatInt(request.Attempt.AttemptEpoch, 10)),
		[]byte(status),
	}
	var tuple []byte
	for _, field := range fields {
		tuple = append(tuple, 1)
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		tuple = append(tuple, size[:]...)
		tuple = append(tuple, field...)
	}
	return tuple
}

type sensitiveBoundary interface {
	json.Marshaler
	json.Unmarshaler
	encoding.TextMarshaler
	encoding.TextUnmarshaler
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	fmt.Stringer
	fmt.GoStringer
	slog.LogValuer
}

func assertSensitiveBoundary(t *testing.T, value sensitiveBoundary, forbidden ...string) {
	t.Helper()
	if _, err := value.MarshalJSON(); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("MarshalJSON() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := value.UnmarshalJSON([]byte(`{}`)); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("UnmarshalJSON() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := value.MarshalText(); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("MarshalText() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := value.UnmarshalText([]byte("unsafe")); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("UnmarshalText() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := value.MarshalBinary(); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("MarshalBinary() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := value.UnmarshalBinary([]byte("unsafe")); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("UnmarshalBinary() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := json.Marshal(value); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal() error = %v, want ErrSensitiveSerialization", err)
	}

	var log bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&log, nil))
	logger.Info("boundary", "value", value)
	rendered := strings.Join([]string{
		value.String(),
		value.GoString(),
		fmt.Sprintf("%s", value),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
		log.String(),
	}, "\n")
	for _, secret := range forbidden {
		if strings.Contains(rendered, secret) {
			t.Fatalf("sensitive boundary leaked %q in %q", secret, rendered)
		}
	}
	if !strings.Contains(rendered, "[REDACTED_") {
		t.Fatalf("sensitive boundary did not use stable redaction: %q", rendered)
	}
}
