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
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
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

func TestBindAttemptRuntimeRequiresExactBrokerIssuedSessionAndHandle(t *testing.T) {
	t.Parallel()

	binding := cleanupRuntimeBinding()
	firstOpener := newRuntimeTestOpener(binding)
	firstBroker := mustBroker(t, firstOpener, newTestProofAuthority())
	request := cleanupRequest(1)
	session, err := firstBroker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	defer session.Destroy()

	foreignOpener := newRuntimeTestOpener(binding)
	foreignBroker := mustBroker(t, foreignOpener, newTestProofAuthority())
	foreignSession, err := foreignBroker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("foreign OpenAttempt() error = %v", err)
	}
	defer foreignSession.Destroy()

	if _, err := foreignBroker.BindAttemptRuntime(
		context.Background(),
		session,
		binding,
	); !errors.Is(err, discoverycleanup.ErrSessionAuthentication) {
		t.Fatalf("BindAttemptRuntime(foreign broker) error = %v, want ErrSessionAuthentication", err)
	}
	if got := foreignOpener.handle(request.Attempt.AttemptID).bindCount(); got != 0 {
		t.Fatalf("foreign handle BindRuntime() calls = %d, want 0", got)
	}

	if _, err := firstBroker.BindAttemptRuntime(
		context.Background(),
		&discoverycleanup.AttemptSession{},
		binding,
	); !errors.Is(err, discoverycleanup.ErrSessionAuthentication) {
		t.Fatalf("BindAttemptRuntime(reconstructed acknowledgement) error = %v, want ErrSessionAuthentication", err)
	}

	copied := *session
	if _, err := firstBroker.BindAttemptRuntime(
		context.Background(),
		&copied,
		binding,
	); !errors.Is(err, discoverycleanup.ErrSessionAuthentication) {
		t.Fatalf("BindAttemptRuntime(shallow copy) error = %v, want ErrSessionAuthentication", err)
	}
	if _, err := copied.Attempt(); !errors.Is(err, discoverycleanup.ErrSessionAuthentication) {
		t.Fatalf("Attempt(shallow copy) error = %v, want ErrSessionAuthentication", err)
	}
	copied.Destroy()
	if got, err := session.Attempt(); err != nil || got != request.Attempt {
		t.Fatalf("original Attempt() after copied Destroy = %#v, %v; want %#v", got, err, request.Attempt)
	}

	bound, err := firstBroker.BindAttemptRuntime(context.Background(), session, binding)
	if err != nil {
		t.Fatalf("BindAttemptRuntime(exact session) error = %v", err)
	}
	if got := bound.Binding(); got != binding {
		t.Fatalf("bound runtime binding = %#v, want %#v", got, binding)
	}
	handle := firstOpener.handle(request.Attempt.AttemptID)
	if got := handle.bindCount(); got != 1 {
		t.Fatalf("Broker-owned handle BindRuntime() calls = %d, want 1", got)
	}
	if got := firstOpener.secondHandle().bindCount(); got != 0 {
		t.Fatalf("second runtime-producing handle BindRuntime() calls = %d, want 0", got)
	}
	if err := discoverysource.WithRuntime[testRuntimeMaterial](
		bound,
		binding,
		func(material *testRuntimeMaterial) error {
			if material.SessionMarker != "broker-owned-session" {
				t.Fatalf("runtime session marker = %q, want broker-owned-session", material.SessionMarker)
			}
			return nil
		},
	); err != nil {
		t.Fatalf("WithRuntime(exact Broker-owned runtime) error = %v", err)
	}

	session.Destroy()
	if _, err := firstBroker.BindAttemptRuntime(
		context.Background(),
		session,
		binding,
	); !errors.Is(err, discoverycleanup.ErrSessionDestroyed) {
		t.Fatalf("BindAttemptRuntime(destroyed acknowledgement) error = %v, want ErrSessionDestroyed", err)
	}
}

func TestBindAttemptRuntimeCoalescesResponseLossAndRejectsBindingDrift(t *testing.T) {
	t.Parallel()

	binding := cleanupRuntimeBinding()
	opener := newRuntimeTestOpener(binding)
	broker := mustBroker(t, opener, newTestProofAuthority())
	request := cleanupRequest(1)

	const callers = 32
	sessions := make([]*discoverycleanup.AttemptSession, callers)
	for index := range sessions {
		session, err := broker.OpenAttempt(context.Background(), request)
		if err != nil {
			t.Fatalf("OpenAttempt(replay %d) error = %v", index, err)
		}
		sessions[index] = session
		defer session.Destroy()
	}

	start := make(chan struct{})
	results := make(chan discoverysource.BoundRuntime, callers)
	errs := make(chan error, callers)
	for index := range callers {
		go func(session *discoverycleanup.AttemptSession) {
			<-start
			runtimeView, bindErr := broker.BindAttemptRuntime(
				context.Background(),
				session,
				binding,
			)
			results <- runtimeView
			errs <- bindErr
		}(sessions[index])
	}
	close(start)

	runtimes := make([]discoverysource.BoundRuntime, callers)
	for index := range callers {
		if bindErr := <-errs; bindErr != nil {
			t.Fatalf("BindAttemptRuntime(concurrent replay %d) error = %v", index, bindErr)
		}
		runtimes[index] = <-results
		if got := runtimes[index].Binding(); got != binding {
			t.Fatalf("runtime replay binding = %#v, want %#v", got, binding)
		}
	}
	handle := opener.handle(request.Attempt.AttemptID)
	if got := handle.bindCount(); got != 1 {
		t.Fatalf("BindRuntime() calls after concurrent response-loss replay = %d, want 1", got)
	}
	if got := opener.openCount(); got != 1 {
		t.Fatalf("OpenSession() calls after concurrent response-loss replay = %d, want 1", got)
	}

	if err := discoverysource.WithRuntime[testRuntimeMaterial](
		runtimes[0],
		binding,
		func(material *testRuntimeMaterial) error {
			material.Uses = 41
			return nil
		},
	); err != nil {
		t.Fatalf("WithRuntime(first cached view) error = %v", err)
	}
	if err := discoverysource.WithRuntime[testRuntimeMaterial](
		runtimes[len(runtimes)-1],
		binding,
		func(material *testRuntimeMaterial) error {
			if material.Uses != 41 {
				t.Fatalf("cached runtime cell Uses = %d, want 41", material.Uses)
			}
			return nil
		},
	); err != nil {
		t.Fatalf("WithRuntime(replayed cached view) error = %v", err)
	}

	drifts := []struct {
		name   string
		mutate func(*discoverysource.RuntimeBinding)
	}{
		{"tenant", func(value *discoverysource.RuntimeBinding) {
			value.Locator.Scope.TenantID = uuid(91)
		}},
		{"workspace", func(value *discoverysource.RuntimeBinding) {
			value.Locator.Scope.WorkspaceID = uuid(92)
		}},
		{"source", func(value *discoverysource.RuntimeBinding) {
			value.Locator.SourceID = uuid(93)
		}},
		{"revision", func(value *discoverysource.RuntimeBinding) {
			value.SourceRevision++
		}},
		{"revision digest", func(value *discoverysource.RuntimeBinding) {
			value.SourceRevisionDigest = strings.Repeat("b", sha256.Size*2)
		}},
		{"revision status", func(value *discoverysource.RuntimeBinding) {
			value.RevisionStatus = assetcatalog.SourceRevisionValidating
		}},
		{"provider", func(value *discoverysource.RuntimeBinding) {
			value.ProviderKind = "OTHER_PROVIDER_V1"
		}},
		{"profile", func(value *discoverysource.RuntimeBinding) {
			value.ProfileCode = "OTHER_PROFILE_V1"
		}},
	}
	for _, drift := range drifts {
		t.Run(drift.name, func(t *testing.T) {
			changed := binding
			drift.mutate(&changed)
			if _, err := broker.BindAttemptRuntime(
				context.Background(),
				sessions[0],
				changed,
			); !errors.Is(err, discoverycleanup.ErrAttemptDrift) {
				t.Fatalf("BindAttemptRuntime(binding drift) error = %v, want ErrAttemptDrift", err)
			}
		})
	}
	if got := handle.bindCount(); got != 1 {
		t.Fatalf("BindRuntime() calls after changed-binding replays = %d, want 1", got)
	}
	if got := opener.openCount(); got != 1 {
		t.Fatalf("OpenSession() calls after changed-binding replays = %d, want 1", got)
	}
	runtimes[0].Clear()
	if got := runtimes[len(runtimes)-1].Binding(); got != (discoverysource.RuntimeBinding{}) {
		t.Fatalf("replayed runtime binding after shared-cell Clear = %#v, want inactive", got)
	}
	if _, err := broker.BindAttemptRuntime(
		context.Background(),
		sessions[0],
		binding,
	); !errors.Is(err, discoverycleanup.ErrRuntimeUnavailable) {
		t.Fatalf("BindAttemptRuntime(after cached cell Clear) error = %v, want ErrRuntimeUnavailable", err)
	}
	if got := handle.bindCount(); got != 1 {
		t.Fatalf("BindRuntime() calls after cached cell Clear = %d, want 1", got)
	}
}

func TestBindAttemptRuntimeRejectsNonRuntimeWrongInactiveAndFailedHandles(t *testing.T) {
	t.Parallel()

	binding := cleanupRuntimeBinding()
	tests := []struct {
		name      string
		configure func(*runtimeTestOpener)
		wantErr   error
		wantBinds int
	}{
		{
			name: "cleanup-only recovery handle",
			configure: func(opener *runtimeTestOpener) {
				opener.cleanupOnly = true
			},
			wantErr: discoverycleanup.ErrRuntimeUnavailable,
		},
		{
			name: "wrong-bound runtime",
			configure: func(opener *runtimeTestOpener) {
				opener.binding.SourceRevision++
			},
			wantErr:   discoverycleanup.ErrAttemptDrift,
			wantBinds: 1,
		},
		{
			name: "inactive runtime",
			configure: func(opener *runtimeTestOpener) {
				opener.returnInactive = true
			},
			wantErr:   discoverycleanup.ErrRuntimeUnavailable,
			wantBinds: 1,
		},
		{
			name: "ambiguous bind result",
			configure: func(opener *runtimeTestOpener) {
				opener.bindErr = errors.New("sensitive runtime bind error: token=do-not-log")
			},
			wantErr:   discoverycleanup.ErrRuntimeUnavailable,
			wantBinds: 1,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opener := newRuntimeTestOpener(binding)
			test.configure(opener)
			broker := mustBroker(t, opener, newTestProofAuthority())
			request := cleanupRequest(10 + index)
			session, err := broker.OpenAttempt(context.Background(), request)
			if err != nil {
				t.Fatalf("OpenAttempt() error = %v", err)
			}
			defer session.Destroy()

			_, bindErr := broker.BindAttemptRuntime(
				context.Background(),
				session,
				binding,
			)
			if !errors.Is(bindErr, test.wantErr) {
				t.Fatalf("BindAttemptRuntime() error = %v, want %v", bindErr, test.wantErr)
			}
			if strings.Contains(bindErr.Error(), "do-not-log") {
				t.Fatalf("BindAttemptRuntime() leaked upstream error = %v", bindErr)
			}
			handle := opener.handle(request.Attempt.AttemptID)
			if got := handle.bindCount(); got != test.wantBinds {
				t.Fatalf("BindRuntime() calls = %d, want %d", got, test.wantBinds)
			}
			if test.wantBinds == 1 && !handle.runtimeCleared() {
				t.Fatal("rejected runtime cell was not cleared")
			}
			if _, err := broker.BindAttemptRuntime(
				context.Background(),
				session,
				binding,
			); !errors.Is(err, test.wantErr) {
				t.Fatalf("BindAttemptRuntime(replay) error = %v, want %v", err, test.wantErr)
			}
			if got := handle.bindCount(); got != test.wantBinds {
				t.Fatalf("BindRuntime() calls after failed replay = %d, want %d", got, test.wantBinds)
			}
			proof, err := broker.RevokeAttempt(
				context.Background(),
				request.Attempt.AttemptID,
			)
			if err != nil {
				t.Fatalf("RevokeAttempt(after runtime rejection) error = %v", err)
			}
			defer proof.Destroy()
			if handle.revokeCount() != 1 || handle.destroyCount() != 1 {
				t.Fatalf("revoke/destroy calls after runtime rejection = %d/%d, want 1/1",
					handle.revokeCount(), handle.destroyCount())
			}
		})
	}
}

func TestBindAttemptRuntimeRevokeWaitsForBindAndInvalidatesRuntime(t *testing.T) {
	t.Parallel()

	binding := cleanupRuntimeBinding()
	opener := newRuntimeTestOpener(binding)
	opener.blockBind = true
	broker := mustBroker(t, opener, newTestProofAuthority())
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	defer session.Destroy()
	handle := opener.handle(request.Attempt.AttemptID)

	type bindResult struct {
		runtime discoverysource.BoundRuntime
		err     error
	}
	bindResults := make(chan bindResult, 1)
	go func() {
		runtimeView, bindErr := broker.BindAttemptRuntime(
			context.Background(),
			session,
			binding,
		)
		bindResults <- bindResult{runtime: runtimeView, err: bindErr}
	}()
	<-handle.bindStarted

	type revokeResult struct {
		proof discoveryqueue.CleanupProof
		err   error
	}
	revokeResults := make(chan revokeResult, 1)
	go func() {
		proof, revokeErr := broker.RevokeAttempt(
			context.Background(),
			request.Attempt.AttemptID,
		)
		revokeResults <- revokeResult{proof: proof, err: revokeErr}
	}()

	select {
	case result := <-revokeResults:
		result.proof.Destroy()
		t.Fatalf("RevokeAttempt() completed before BindRuntime: %v", result.err)
	case <-time.After(50 * time.Millisecond):
	}
	if got := handle.revokeCount(); got != 0 {
		t.Fatalf("Revoke() calls while bind is blocked = %d, want 0", got)
	}
	close(handle.bindRelease)

	bound := <-bindResults
	if bound.err != nil {
		t.Fatalf("BindAttemptRuntime() error = %v", bound.err)
	}
	revoked := <-revokeResults
	if revoked.err != nil {
		t.Fatalf("RevokeAttempt() error = %v", revoked.err)
	}
	defer revoked.proof.Destroy()
	if got := bound.runtime.Binding(); got != (discoverysource.RuntimeBinding{}) {
		t.Fatalf("runtime binding after revoke = %#v, want inactive", got)
	}
	if err := discoverysource.WithRuntime[testRuntimeMaterial](
		bound.runtime,
		binding,
		func(*testRuntimeMaterial) error { return nil },
	); !errors.Is(err, discoverysource.ErrRuntimeBindingMismatch) {
		t.Fatalf("WithRuntime(after revoke) error = %v, want ErrRuntimeBindingMismatch", err)
	}
	if _, err := broker.BindAttemptRuntime(
		context.Background(),
		session,
		binding,
	); !errors.Is(err, discoverycleanup.ErrAttemptClosed) {
		t.Fatalf("BindAttemptRuntime(after revoke) error = %v, want ErrAttemptClosed", err)
	}
	if handle.bindCount() != 1 || handle.revokeCount() != 1 || handle.destroyCount() != 1 {
		t.Fatalf("bind/revoke/destroy calls = %d/%d/%d, want 1/1/1",
			handle.bindCount(), handle.revokeCount(), handle.destroyCount())
	}
}

func TestBindAttemptRuntimeBrokerDestroyCancelsBindAndInvalidatesRuntime(t *testing.T) {
	t.Parallel()

	t.Run("destroy after bind", func(t *testing.T) {
		binding := cleanupRuntimeBinding()
		opener := newRuntimeTestOpener(binding)
		broker := mustBroker(t, opener, newTestProofAuthority())
		request := cleanupRequest(1)
		session, err := broker.OpenAttempt(context.Background(), request)
		if err != nil {
			t.Fatalf("OpenAttempt() error = %v", err)
		}
		defer session.Destroy()
		bound, err := broker.BindAttemptRuntime(context.Background(), session, binding)
		if err != nil {
			t.Fatalf("BindAttemptRuntime() error = %v", err)
		}

		broker.Destroy()
		if got := bound.Binding(); got != (discoverysource.RuntimeBinding{}) {
			t.Fatalf("runtime binding after Broker Destroy = %#v, want inactive", got)
		}
		if _, err := broker.BindAttemptRuntime(
			context.Background(),
			session,
			binding,
		); !errors.Is(err, discoverycleanup.ErrBrokerUnavailable) {
			t.Fatalf("BindAttemptRuntime(after Broker Destroy) error = %v, want ErrBrokerUnavailable", err)
		}
		handle := opener.handle(request.Attempt.AttemptID)
		if handle.destroyCount() != 1 || !handle.runtimeCleared() {
			t.Fatalf("handle destroy/runtime clear = %d/%t, want 1/true",
				handle.destroyCount(), handle.runtimeCleared())
		}
	})

	t.Run("destroy cancels in-flight bind", func(t *testing.T) {
		binding := cleanupRuntimeBinding()
		opener := newRuntimeTestOpener(binding)
		opener.blockBind = true
		broker := mustBroker(t, opener, newTestProofAuthority())
		request := cleanupRequest(2)
		session, err := broker.OpenAttempt(context.Background(), request)
		if err != nil {
			t.Fatalf("OpenAttempt() error = %v", err)
		}
		defer session.Destroy()
		handle := opener.handle(request.Attempt.AttemptID)

		type result struct {
			runtime discoverysource.BoundRuntime
			err     error
		}
		results := make(chan result, 1)
		go func() {
			runtimeView, bindErr := broker.BindAttemptRuntime(
				context.Background(),
				session,
				binding,
			)
			results <- result{runtime: runtimeView, err: bindErr}
		}()
		<-handle.bindStarted

		broker.Destroy()
		bound := <-results
		if !errors.Is(bound.err, discoverycleanup.ErrBrokerUnavailable) {
			t.Fatalf("BindAttemptRuntime(destroyed in flight) error = %v, want ErrBrokerUnavailable", bound.err)
		}
		if got := bound.runtime.Binding(); got != (discoverysource.RuntimeBinding{}) {
			t.Fatalf("runtime binding after cancelled bind = %#v, want inactive", got)
		}
		if handle.bindCount() != 1 || handle.destroyCount() != 1 {
			t.Fatalf("bind/destroy calls = %d/%d, want 1/1",
				handle.bindCount(), handle.destroyCount())
		}
	})
}

func TestBindAttemptRuntimeSensitiveBoundaryDoesNotLeak(t *testing.T) {
	t.Parallel()

	const (
		handleSecret  = "runtime-handle-secret-do-not-leak"
		runtimeSecret = "runtime-material-secret-do-not-leak"
	)
	binding := cleanupRuntimeBinding()
	opener := newRuntimeTestOpener(binding)
	opener.handleSecret = handleSecret
	opener.runtimeSecret = runtimeSecret
	broker := mustBroker(t, opener, newTestProofAuthority())
	request := cleanupRequest(1)
	session, err := broker.OpenAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	defer session.Destroy()
	bound, err := broker.BindAttemptRuntime(context.Background(), session, binding)
	if err != nil {
		t.Fatalf("BindAttemptRuntime() error = %v", err)
	}

	assertSensitiveBoundary(
		t,
		session,
		request.Attempt.AttemptID,
		binding.Locator.SourceID,
		binding.SourceRevisionDigest,
		binding.ProviderKind,
		string(binding.ProfileCode),
		handleSecret,
		runtimeSecret,
	)
	assertSensitiveBoundary(
		t,
		*session,
		request.Attempt.AttemptID,
		binding.Locator.SourceID,
		binding.SourceRevisionDigest,
		handleSecret,
		runtimeSecret,
	)
	assertAttemptSessionHasNoRuntimeOrHandleReference(t)
	assertRuntimeSensitiveBoundary(
		t,
		bound,
		request.Attempt.AttemptID,
		binding.Locator.SourceID,
		binding.SourceRevisionDigest,
		binding.ProviderKind,
		string(binding.ProfileCode),
		handleSecret,
		runtimeSecret,
	)
}

func assertAttemptSessionHasNoRuntimeOrHandleReference(t *testing.T) {
	t.Helper()
	sessionType := reflect.TypeOf(discoverycleanup.AttemptSession{})
	if sessionType.NumField() != 1 {
		t.Fatalf("AttemptSession fields = %d, want one opaque state pointer", sessionType.NumField())
	}
	for index := range sessionType.NumField() {
		field := sessionType.Field(index)
		if field.PkgPath == "" {
			t.Fatalf("AttemptSession exported field = %s", field.Name)
		}
	}
	stateType := sessionType.Field(0).Type.Elem()
	for index := range stateType.NumField() {
		fieldType := stateType.Field(index).Type.String()
		for _, forbidden := range []string{
			"brokerState",
			"attemptState",
			"SessionHandle",
			"RuntimeBinding",
			"BoundRuntime",
		} {
			if strings.Contains(fieldType, forbidden) {
				t.Fatalf("AttemptSession state field type %q references %s", fieldType, forbidden)
			}
		}
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
	handle := opener.handle(request.Attempt.AttemptID)
	if handle.revokeCount() != 1 || handle.destroyCount() != 1 || authority.signCount() != 1 {
		t.Fatalf("uncertain revoke/destroy/sign calls = %d/%d/%d, want 1/1/1",
			handle.revokeCount(), handle.destroyCount(), authority.signCount())
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
	handle := opener.handle(request.Attempt.AttemptID)
	if handle.revokeCount() != 1 || handle.destroyCount() != 1 || authority.signCount() != 1 {
		t.Fatalf("ambiguous open revoke/destroy/sign calls = %d/%d/%d, want 1/1/1",
			handle.revokeCount(), handle.destroyCount(), authority.signCount())
	}
}

func TestOpenFailureRevokeProducesStableUncertainProof(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		openErr         error
		nilHandle       bool
		wantOpenErr     error
		wantHandleCalls int
	}{
		{
			name:        "generic nil-handle error",
			openErr:     errors.New("sensitive upstream open failure: token=do-not-log"),
			nilHandle:   true,
			wantOpenErr: discoverycleanup.ErrAttemptUncertain,
		},
		{
			name:        "authentication nil-handle error",
			openErr:     discoverycleanup.ErrSessionAuthentication,
			nilHandle:   true,
			wantOpenErr: discoverycleanup.ErrSessionAuthentication,
		},
		{
			name:            "handle plus authentication error",
			openErr:         discoverycleanup.ErrSessionAuthentication,
			wantOpenErr:     discoverycleanup.ErrSessionAuthentication,
			wantHandleCalls: 1,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opener := newTestOpener()
			opener.openErr = test.openErr
			opener.returnNilHandle = test.nilHandle
			authority := newTestProofAuthority()
			broker := mustBroker(t, opener, authority)
			request := cleanupRequest(index + 1)

			if _, err := broker.OpenAttempt(context.Background(), request); !errors.Is(err, test.wantOpenErr) {
				t.Fatalf("OpenAttempt() error = %v, want %v", err, test.wantOpenErr)
			}

			const callers = 16
			type revokeResult struct {
				proof discoveryqueue.CleanupProof
				err   error
			}
			start := make(chan struct{})
			results := make(chan revokeResult, callers)
			for range callers {
				go func() {
					<-start
					proof, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
					results <- revokeResult{proof: proof, err: err}
				}()
			}
			close(start)

			var wantDigest string
			var wantAuthentication []byte
			defer clear(wantAuthentication)
			for range callers {
				result := <-results
				if result.err != nil {
					t.Fatalf("RevokeAttempt() error = %v", result.err)
				}
				if result.proof.Status() != assetcatalog.CredentialCleanupUncertain {
					t.Fatalf("cleanup status = %s, want UNCERTAIN", result.proof.Status())
				}
				if err := broker.VerifyCleanupProof(context.Background(), result.proof); err != nil {
					t.Fatalf("VerifyCleanupProof() error = %v", err)
				}
				authentication := result.proof.Authentication()
				if wantDigest == "" {
					wantDigest = result.proof.DigestSHA256()
					wantAuthentication = bytes.Clone(authentication)
				} else if result.proof.DigestSHA256() != wantDigest ||
					!bytes.Equal(authentication, wantAuthentication) {
					t.Fatal("concurrent revoke returned a different UNCERTAIN proof")
				}
				clear(authentication)
				result.proof.Destroy()
			}

			replayed, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
			if err != nil {
				t.Fatalf("RevokeAttempt(response-loss replay) error = %v", err)
			}
			replayedAuthentication := replayed.Authentication()
			if replayed.Status() != assetcatalog.CredentialCleanupUncertain ||
				replayed.DigestSHA256() != wantDigest ||
				!bytes.Equal(replayedAuthentication, wantAuthentication) {
				t.Fatal("response-loss replay returned a different UNCERTAIN proof")
			}
			clear(replayedAuthentication)
			replayed.Destroy()

			handle := opener.handle(request.Attempt.AttemptID)
			if handle.revokeCount() != test.wantHandleCalls ||
				handle.destroyCount() != test.wantHandleCalls ||
				authority.signCount() != 1 {
				t.Fatalf("revoke/destroy/sign calls = %d/%d/%d, want %d/%d/1",
					handle.revokeCount(), handle.destroyCount(), authority.signCount(),
					test.wantHandleCalls, test.wantHandleCalls)
			}
		})
	}
}

func TestOpenFailureSignerFailureDoesNotProduceProof(t *testing.T) {
	t.Parallel()

	opener := newTestOpener()
	opener.openErr = errors.New("sensitive upstream open failure: token=do-not-log")
	opener.returnNilHandle = true
	authority := newTestProofAuthority()
	authority.signErr = errors.New("sensitive signer failure: key=do-not-log")
	broker := mustBroker(t, opener, authority)
	request := cleanupRequest(1)

	if _, err := broker.OpenAttempt(context.Background(), request); !errors.Is(err, discoverycleanup.ErrAttemptUncertain) {
		t.Fatalf("OpenAttempt() error = %v, want ErrAttemptUncertain", err)
	}
	for range 2 {
		proof, err := broker.RevokeAttempt(context.Background(), request.Attempt.AttemptID)
		authentication := proof.Authentication()
		if !errors.Is(err, discoverycleanup.ErrProofAuthentication) ||
			proof.Status() != "" || proof.DigestSHA256() != "" || len(authentication) != 0 {
			t.Fatalf("RevokeAttempt() = %s/%q/%d, %v; want empty proof and ErrProofAuthentication",
				proof.Status(), proof.DigestSHA256(), len(authentication), err)
		}
		clear(authentication)
		proof.Destroy()
	}
	handle := opener.handle(request.Attempt.AttemptID)
	if handle.revokeCount() != 0 || handle.destroyCount() != 0 || authority.signCount() != 1 {
		t.Fatalf("revoke/destroy/sign calls = %d/%d/%d, want 0/0/1",
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

func cleanupRuntimeBinding() discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID:    uuid(1),
				WorkspaceID: uuid(2),
			},
			SourceID: uuid(40),
		},
		SourceRevision:       7,
		SourceRevisionDigest: strings.Repeat("a", sha256.Size*2),
		RevisionStatus:       assetcatalog.SourceRevisionPublished,
		ProviderKind:         "CMDB_CATALOG_V1",
		ProfileCode:          "CMDB_CATALOG_V1",
	}
}

func uuid(value int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", value)
}

type testOpener struct {
	mu              sync.Mutex
	openCalls       map[string]int
	handles         map[string]*testSessionHandle
	openErr         error
	revokeErr       error
	handleSecret    string
	blockOpen       bool
	blockRevoke     bool
	blockDestroy    bool
	returnNilHandle bool
	openStarted     chan struct{}
	openOnce        sync.Once
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
	if opener.returnNilHandle {
		return nil, openErr
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

type runtimeTestOpener struct {
	mu             sync.Mutex
	binding        discoverysource.RuntimeBinding
	cleanupOnly    bool
	returnInactive bool
	bindErr        error
	blockBind      bool
	handleSecret   string
	runtimeSecret  string
	openCalls      int
	handles        map[string]*runtimeTestSessionHandle
	second         *runtimeTestSessionHandle
}

func newRuntimeTestOpener(binding discoverysource.RuntimeBinding) *runtimeTestOpener {
	return &runtimeTestOpener{
		binding: binding,
		handles: make(map[string]*runtimeTestSessionHandle),
		second: newRuntimeTestSessionHandle(
			binding,
			"second-runtime-producing-session",
			"second-runtime-secret",
			"",
			false,
			false,
		),
	}
}

func (opener *runtimeTestOpener) OpenSession(
	_ context.Context,
	request discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	opener.openCalls++
	handle := newRuntimeTestSessionHandle(
		opener.binding,
		"broker-owned-session",
		opener.runtimeSecret,
		opener.handleSecret,
		opener.returnInactive,
		opener.blockBind,
	)
	handle.bindErr = opener.bindErr
	opener.handles[request.Attempt.AttemptID] = handle
	if opener.cleanupOnly {
		return &cleanupOnlyTestSessionHandle{handle: handle}, nil
	}
	return handle, nil
}

func (opener *runtimeTestOpener) handle(attemptID string) *runtimeTestSessionHandle {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.handles[attemptID]
}

func (opener *runtimeTestOpener) secondHandle() *runtimeTestSessionHandle {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.second
}

func (opener *runtimeTestOpener) openCount() int {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.openCalls
}

type cleanupOnlyTestSessionHandle struct {
	handle *runtimeTestSessionHandle
}

func (handle *cleanupOnlyTestSessionHandle) Revoke(ctx context.Context) error {
	return handle.handle.Revoke(ctx)
}

func (handle *cleanupOnlyTestSessionHandle) Destroy() {
	handle.handle.Destroy()
}

type testRuntimeMaterial struct {
	SessionMarker string
	Secret        string
	Uses          int
	Cleared       bool
}

type runtimeTestSessionHandle struct {
	base           *testSessionHandle
	mu             sync.Mutex
	binding        discoverysource.RuntimeBinding
	sessionMarker  string
	runtimeSecret  string
	bindCalls      int
	bindErr        error
	returnInactive bool
	blockBind      bool
	bindStarted    chan struct{}
	bindRelease    chan struct{}
	bindOnce       sync.Once
	material       *testRuntimeMaterial
	runtime        discoverysource.BoundRuntime
}

func newRuntimeTestSessionHandle(
	binding discoverysource.RuntimeBinding,
	sessionMarker string,
	runtimeSecret string,
	handleSecret string,
	returnInactive bool,
	blockBind bool,
) *runtimeTestSessionHandle {
	return &runtimeTestSessionHandle{
		base: &testSessionHandle{
			secret:           handleSecret,
			revokeStarted:    make(chan struct{}),
			destroyStarted:   make(chan struct{}),
			destroyRelease:   make(chan struct{}),
			destroyCompleted: make(chan struct{}),
		},
		binding:        binding,
		sessionMarker:  sessionMarker,
		runtimeSecret:  runtimeSecret,
		returnInactive: returnInactive,
		blockBind:      blockBind,
		bindStarted:    make(chan struct{}),
		bindRelease:    make(chan struct{}),
	}
}

func (handle *runtimeTestSessionHandle) BindRuntime(
	ctx context.Context,
	_ discoverysource.RuntimeBinding,
) (discoverysource.BoundRuntime, error) {
	handle.mu.Lock()
	handle.bindCalls++
	binding := handle.binding
	sessionMarker := handle.sessionMarker
	runtimeSecret := handle.runtimeSecret
	bindErr := handle.bindErr
	returnInactive := handle.returnInactive
	blockBind := handle.blockBind
	handle.mu.Unlock()
	handle.bindOnce.Do(func() { close(handle.bindStarted) })

	if blockBind {
		select {
		case <-ctx.Done():
			return discoverysource.BoundRuntime{}, ctx.Err()
		case <-handle.bindRelease:
		}
	}

	material := &testRuntimeMaterial{
		SessionMarker: sessionMarker,
		Secret:        runtimeSecret,
	}
	runtimeView, err := discoverysource.BindRuntime(
		binding,
		material,
		func(*testRuntimeMaterial) error { return nil },
		func(value *testRuntimeMaterial) {
			value.Secret = ""
			value.SessionMarker = ""
			value.Uses = 0
			value.Cleared = true
		},
	)
	if err != nil {
		return discoverysource.BoundRuntime{}, err
	}
	handle.mu.Lock()
	handle.material = material
	handle.runtime = runtimeView
	handle.mu.Unlock()
	if returnInactive {
		runtimeView.Clear()
	}
	if bindErr != nil {
		return runtimeView, bindErr
	}
	return runtimeView, nil
}

func (handle *runtimeTestSessionHandle) Revoke(ctx context.Context) error {
	return handle.base.Revoke(ctx)
}

func (handle *runtimeTestSessionHandle) Destroy() {
	handle.base.Destroy()
}

func (handle *runtimeTestSessionHandle) bindCount() int {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.bindCalls
}

func (handle *runtimeTestSessionHandle) runtimeCleared() bool {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.material != nil && handle.material.Cleared
}

func (handle *runtimeTestSessionHandle) revokeCount() int {
	return handle.base.revokeCount()
}

func (handle *runtimeTestSessionHandle) destroyCount() int {
	return handle.base.destroyCount()
}

var _ discoverycleanup.SessionHandle = (*cleanupOnlyTestSessionHandle)(nil)
var _ discoverycleanup.RuntimeSessionHandle = (*runtimeTestSessionHandle)(nil)

type testProofAuthority struct {
	mu            sync.Mutex
	key           []byte
	signCalls     int
	signedData    []byte
	signErr       error
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
	signErr := authority.signErr
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
	if signErr != nil {
		return nil, signErr
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

func assertRuntimeSensitiveBoundary(
	t *testing.T,
	value discoverysource.BoundRuntime,
	forbidden ...string,
) {
	t.Helper()
	if _, err := value.MarshalJSON(); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("runtime MarshalJSON() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := value.UnmarshalJSON([]byte(`{}`)); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("runtime UnmarshalJSON() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := value.MarshalText(); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("runtime MarshalText() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := value.UnmarshalText([]byte("unsafe")); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("runtime UnmarshalText() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := value.MarshalBinary(); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("runtime MarshalBinary() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := value.UnmarshalBinary([]byte("unsafe")); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("runtime UnmarshalBinary() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := json.Marshal(value); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(runtime) error = %v, want ErrSensitiveSerialization", err)
	}

	var log bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&log, nil))
	logger.Info("runtime-boundary", "value", value)
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
			t.Fatalf("runtime boundary leaked %q in %q", secret, rendered)
		}
	}
	if !strings.Contains(rendered, "[REDACTED_") {
		t.Fatalf("runtime boundary did not use stable redaction: %q", rendered)
	}
}
