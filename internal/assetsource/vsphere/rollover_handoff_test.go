package vsphere

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/leasefence"
	"github.com/vmware/govmomi/vim25/types"
)

func TestRolloverHandoffRequiresBrokerRevokeAndConsumesExactlyOnce(t *testing.T) {
	t.Parallel()

	fixture := newRolloverHandoffFixture(t)
	handoff := fixture.begin(t)
	handoff.state.mu.Lock()
	successorID := handoff.state.successorID
	handoff.state.mu.Unlock()
	oldRequest := fixture.request
	oldRequest.Checkpoint = fixture.partial.NextCheckpoint.Clone()
	methodsBeforeFreeze := fixture.predecessor.methodSnapshot()
	oldOutcome, oldErr := fixture.provider.Discover(
		context.Background(),
		fixture.runtime,
		oldRequest,
	)
	oldRequest.Checkpoint.Clear()
	if oldOutcome != nil || !errors.Is(oldErr, errInventoryContinuity) {
		t.Fatalf(
			"Discover(predecessor after handoff mint) = (%#v,%v)",
			oldOutcome,
			oldErr,
		)
	}
	if got := fixture.predecessor.methodSnapshot(); !slices.Equal(
		got,
		methodsBeforeFreeze,
	) {
		t.Fatalf("handoff mint allowed predecessor SOAP: before=%v after=%v", methodsBeforeFreeze, got)
	}
	if rebound, bindErr := fixture.opener.attempt.BindRuntime(
		context.Background(),
		fixture.binding,
	); rebound != (discoverysource.BoundRuntime{}) ||
		!errors.Is(bindErr, errInventoryContinuity) {
		t.Fatalf(
			"BindRuntime(predecessor after handoff mint) = (%#v,%v)",
			rebound,
			bindErr,
		)
	}
	prematureMaterial := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if successor, err := handoff.NewSuccessor(
		context.Background(),
		fixture.queue,
		fixture.fence,
		&prematureMaterial,
		fixture.partial.NextCheckpoint,
	); successor != nil || !errors.Is(err, errInventoryContinuity) {
		t.Fatalf("NewSuccessor(before Broker revoke) = (%#v,%v)", successor, err)
	}
	if prematureMaterial.valid() {
		t.Fatal("premature successor retained runtime material")
	}
	if err := fixture.opener.attempt.Revoke(context.Background()); err != nil {
		t.Fatalf("direct Revoke setup error = %v", err)
	}
	revokeOnlyMaterial := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if successor, err := handoff.NewSuccessor(
		context.Background(),
		fixture.queue,
		fixture.fence,
		&revokeOnlyMaterial,
		fixture.partial.NextCheckpoint,
	); successor != nil || !errors.Is(err, errInventoryContinuity) {
		t.Fatalf("NewSuccessor(after Revoke without Destroy) = (%#v,%v)", successor, err)
	}
	if revokeOnlyMaterial.valid() {
		t.Fatal("revoke-only successor retained runtime material")
	}

	proof, err := fixture.broker.RevokeAttempt(
		context.Background(),
		fixture.openRequest.Attempt.AttemptID,
	)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	if proof.Status() != assetcatalog.CredentialCleanupRevoked ||
		fixture.broker.VerifyCleanupProof(context.Background(), proof) != nil {
		proof.Destroy()
		t.Fatalf("RevokeAttempt() proof = %#v", proof)
	}
	proof.Destroy()
	fixture.predecessor.mu.Lock()
	closeCalls := fixture.predecessor.closeCalls
	fixture.predecessor.mu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("Broker Revoke+Destroy closed predecessor %d times, want 1", closeCalls)
	}
	if successor, err := fixture.opener.attempt.NewRolloverSuccessor(
		newInventoryRuntimeMaterialPointer(t, testAuthorityRoot),
		fixture.partial.NextCheckpoint,
	); successor != nil || !errors.Is(err, errInventoryContinuity) {
		if successor != nil {
			successor.Destroy()
		}
		t.Fatalf("raw predecessor successor after Broker Destroy = (%#v,%v)", successor, err)
	}

	material := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	successor, err := handoff.NewSuccessor(
		context.Background(),
		fixture.queue,
		fixture.fence,
		&material,
		fixture.partial.NextCheckpoint,
	)
	if err != nil {
		t.Fatalf("NewSuccessor() error = %v", err)
	}
	t.Cleanup(successor.Destroy)
	runtime, err := successor.BindRuntime(context.Background(), fixture.binding)
	if err != nil {
		t.Fatalf("BindRuntime(successor) error = %v", err)
	}
	request := fixture.request
	request.Checkpoint = fixture.partial.NextCheckpoint.Clone()
	page := discoverInventoryPage(t, fixture.provider, runtime, request)
	request.Checkpoint.Clear()
	if !page.FinalPage || !page.CompleteSnapshot ||
		len(page.Items) == 0 ||
		page.Items[0].Freshness.OrderSequence != 2 {
		page.NextCheckpoint.Clear()
		t.Fatalf("successor page = %#v", page)
	}
	openedFinal, empty, err := openFullInventoryCheckpoint(page.NextCheckpoint)
	if err != nil || empty || openedFinal.fullSnapshotID != successorID {
		page.NextCheckpoint.Clear()
		t.Fatalf(
			"successor checkpoint identity = (%#v,%t,%v), want %s",
			openedFinal,
			empty,
			err,
			successorID,
		)
	}
	page.NextCheckpoint.Clear()
	if got := fixture.successor.methodSnapshot(); !slices.Equal(
		got,
		[]string{"RetrievePropertiesEx"},
	) {
		t.Fatalf("handoff successor SOAP methods = %v", got)
	}
	replayMaterial := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if replay, replayErr := handoff.NewSuccessor(
		context.Background(),
		fixture.queue,
		fixture.fence,
		&replayMaterial,
		fixture.partial.NextCheckpoint,
	); replay != nil || !errors.Is(replayErr, errInventoryContinuity) {
		if replay != nil {
			replay.Destroy()
		}
		t.Fatalf("NewSuccessor(replay) = (%#v,%v)", replay, replayErr)
	}
	if replayMaterial.valid() {
		t.Fatal("replayed handoff retained runtime material")
	}
}

func TestRolloverHandoffWaitsForInFlightContinuationBeforeFreezing(t *testing.T) {
	t.Parallel()

	fixture := newRolloverHandoffFixture(t)
	fixture.predecessor.mu.Lock()
	fixture.predecessor.continuations["rollover-handoff-predecessor-token-canary"] =
		types.RetrieveResult{
			Objects: []types.ObjectContent{
				inventoryFolderContent(testAuthorityRoot.Value, "root"),
			},
		}
	fixture.predecessor.continueStarted = make(chan struct{})
	fixture.predecessor.continueRelease = make(chan struct{})
	continueStarted := fixture.predecessor.continueStarted
	continueRelease := fixture.predecessor.continueRelease
	fixture.predecessor.mu.Unlock()

	type discoverResult struct {
		outcome discoverysource.DiscoverOutcome
		err     error
	}
	discoverDone := make(chan discoverResult, 1)
	oldRequest := fixture.request
	oldRequest.Checkpoint = fixture.partial.NextCheckpoint.Clone()
	go func() {
		outcome, err := fixture.provider.Discover(
			context.Background(),
			fixture.runtime,
			oldRequest,
		)
		discoverDone <- discoverResult{outcome: outcome, err: err}
	}()
	select {
	case <-continueStarted:
	case <-time.After(2 * time.Second):
		oldRequest.Checkpoint.Clear()
		t.Fatal("continuation did not reach the in-flight SOAP barrier")
	}
	released := false
	defer func() {
		if !released {
			close(continueRelease)
		}
		oldRequest.Checkpoint.Clear()
	}()

	type beginResult struct {
		handoff *FullInventoryRolloverHandoff
		result  discoveryqueue.RolloverResult
		err     error
	}
	beginDone := make(chan beginResult, 1)
	beginStarted := make(chan struct{})
	go func() {
		close(beginStarted)
		handoff, result, err := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		beginDone <- beginResult{handoff: handoff, result: result, err: err}
	}()
	select {
	case <-beginStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("BeginHandoff goroutine did not start")
	}
	deadline := time.Now().Add(2 * time.Second)
	for fixture.authority.state.mu.TryLock() {
		fixture.authority.state.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("BeginHandoff did not acquire authority lock before continuation release")
		}
		runtime.Gosched()
	}
	select {
	case result := <-beginDone:
		if result.handoff != nil {
			result.handoff.Destroy()
		}
		t.Fatalf(
			"BeginHandoff crossed in-flight continuation = (%#v,%#v,%v)",
			result.handoff,
			result.result,
			result.err,
		)
	default:
	}
	if beginCalls, reserveCalls := fixture.queue.rolloverAdmissionCallCounts(); beginCalls != 0 || reserveCalls != 0 {
		t.Fatalf(
			"in-flight continuation reached Queue Begin/Reserve %d/%d times",
			beginCalls,
			reserveCalls,
		)
	}

	close(continueRelease)
	released = true
	var continued discoverResult
	select {
	case continued = <-discoverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight continuation did not complete")
	}
	page, ok := continued.outcome.(discoverysource.Page)
	if continued.err != nil || !ok {
		t.Fatalf(
			"Discover(in-flight continuation) = (%T,%v)",
			continued.outcome,
			continued.err,
		)
	}
	page.NextCheckpoint.Clear()

	var begun beginResult
	select {
	case begun = <-beginDone:
	case <-time.After(2 * time.Second):
		t.Fatal("BeginHandoff did not return after continuation completed")
	}
	if begun.handoff != nil {
		begun.handoff.Destroy()
	}
	if begun.handoff != nil || !errors.Is(begun.err, errInventoryContinuity) {
		t.Fatalf(
			"BeginHandoff(after checkpoint advanced) = (%#v,%#v,%v)",
			begun.handoff,
			begun.result,
			begun.err,
		)
	}
	if beginCalls, reserveCalls := fixture.queue.rolloverAdmissionCallCounts(); beginCalls != 0 || reserveCalls != 0 {
		t.Fatalf(
			"checkpoint drift reached Queue Begin/Reserve %d/%d times",
			beginCalls,
			reserveCalls,
		)
	}
	if got := fixture.predecessor.methodSnapshot(); !slices.Equal(
		got,
		[]string{"RetrievePropertiesEx", "ContinueRetrievePropertiesEx"},
	) {
		t.Fatalf("in-flight handoff SOAP methods = %v", got)
	}
}

func TestRolloverHandoffFreezesBeforeCleanupAttemptPreflight(t *testing.T) {
	t.Parallel()

	fixture := newRolloverHandoffFixture(t)
	fixture.queue.reserveObserved = make(chan struct{})
	fixture.queue.reserveRelease = make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(fixture.queue.reserveRelease)
		}
	}()

	type beginResult struct {
		handoff *FullInventoryRolloverHandoff
		result  discoveryqueue.RolloverResult
		err     error
	}
	beginDone := make(chan beginResult, 1)
	go func() {
		handoff, result, err := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		beginDone <- beginResult{handoff: handoff, result: result, err: err}
	}()
	select {
	case <-fixture.queue.reserveObserved:
	case <-time.After(2 * time.Second):
		t.Fatal("BeginHandoff did not reach the cleanup-attempt preflight barrier")
	}
	if beginCalls, reserveCalls := fixture.queue.rolloverAdmissionCallCounts(); beginCalls != 0 || reserveCalls != 1 {
		t.Fatalf(
			"blocked preflight Queue Begin/Reserve calls = %d/%d, want 0/1",
			beginCalls,
			reserveCalls,
		)
	}
	assertRolloverPredecessorFrozen(t, fixture)
	concurrentDone := make(chan beginResult, 1)
	go func() {
		handoff, result, err := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		concurrentDone <- beginResult{handoff: handoff, result: result, err: err}
	}()
	select {
	case concurrent := <-concurrentDone:
		if concurrent.handoff != nil {
			concurrent.handoff.Destroy()
		}
		if concurrent.handoff != nil ||
			!errors.Is(concurrent.err, errInventoryContinuity) {
			t.Fatalf(
				"BeginHandoff(concurrent preflight) = (%#v,%#v,%v)",
				concurrent.handoff,
				concurrent.result,
				concurrent.err,
			)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent BeginHandoff reached a second cleanup-attempt preflight")
	}
	if beginCalls, reserveCalls := fixture.queue.rolloverAdmissionCallCounts(); beginCalls != 0 || reserveCalls != 1 {
		t.Fatalf(
			"concurrent preflight Queue Begin/Reserve calls = %d/%d, want 0/1",
			beginCalls,
			reserveCalls,
		)
	}

	close(fixture.queue.reserveRelease)
	released = true
	var begun beginResult
	select {
	case begun = <-beginDone:
	case <-time.After(2 * time.Second):
		t.Fatal("BeginHandoff did not return after cleanup-attempt preflight")
	}
	if begun.err != nil || begun.handoff == nil || begun.result.Replayed {
		if begun.handoff != nil {
			begun.handoff.Destroy()
		}
		t.Fatalf(
			"BeginHandoff(after preflight) = (%#v,%#v,%v)",
			begun.handoff,
			begun.result,
			begun.err,
		)
	}
	begun.handoff.Destroy()
}

func TestRolloverHandoffPreflightFailurePermanentlyFreezesPredecessor(t *testing.T) {
	t.Parallel()

	t.Run("unavailable", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		fixture.queue.reserveError = discoveryqueue.ErrUnavailable
		handoff, _, err := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		if handoff != nil {
			handoff.Destroy()
		}
		if handoff != nil || !errors.Is(err, discoveryqueue.ErrUnavailable) {
			t.Fatalf("BeginHandoff(unavailable preflight) = (%#v,%v)", handoff, err)
		}
		assertRolloverPredecessorFrozen(t, fixture)
		assertRolloverPreflightRetryRejected(t, fixture)
	})

	t.Run("context canceled", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		fixture.queue.reserveObserved = make(chan struct{})
		fixture.queue.reserveRelease = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type beginResult struct {
			handoff *FullInventoryRolloverHandoff
			err     error
		}
		beginDone := make(chan beginResult, 1)
		go func() {
			handoff, _, err := fixture.authority.BeginHandoff(
				ctx,
				fixture.queue,
				fixture.fence,
				fixture.openRequest,
				fixture.command,
				fixture.accepted,
				fixture.partial.NextCheckpoint,
			)
			beginDone <- beginResult{handoff: handoff, err: err}
		}()
		select {
		case <-fixture.queue.reserveObserved:
		case <-time.After(2 * time.Second):
			t.Fatal("BeginHandoff did not reach the canceled preflight barrier")
		}
		assertRolloverPredecessorFrozen(t, fixture)
		cancel()
		var canceled beginResult
		select {
		case canceled = <-beginDone:
		case <-time.After(2 * time.Second):
			t.Fatal("BeginHandoff did not return after preflight context cancellation")
		}
		if canceled.handoff != nil {
			canceled.handoff.Destroy()
		}
		if canceled.handoff != nil || !errors.Is(canceled.err, context.Canceled) {
			t.Fatalf(
				"BeginHandoff(canceled preflight) = (%#v,%v)",
				canceled.handoff,
				canceled.err,
			)
		}
		assertRolloverPredecessorFrozen(t, fixture)
		assertRolloverPreflightRetryRejected(t, fixture)
	})
}

func TestRolloverHandoffRejectsCopySerializationAndConcurrentReplay(t *testing.T) {
	t.Parallel()

	fixture := newRolloverHandoffFixture(t)
	handoff := fixture.begin(t)
	handoff.state.mu.Lock()
	objectDigests := make([]string, 0, len(handoff.state.objects))
	for digest := range handoff.state.objects {
		objectDigests = append(objectDigests, digest)
	}
	relationDigests := make([]string, 0, len(handoff.state.relations))
	for digest := range handoff.state.relations {
		relationDigests = append(relationDigests, digest)
	}
	handoff.state.mu.Unlock()
	for _, digest := range append(objectDigests, relationDigests...) {
		if !lowercaseDigestPattern.MatchString(digest) ||
			strings.Contains(digest, "partial") ||
			strings.Contains(digest, "token-canary") {
			t.Fatalf("handoff retained non-digest fact payload %q", digest)
		}
	}
	proof, err := fixture.broker.RevokeAttempt(
		context.Background(),
		fixture.openRequest.Attempt.AttemptID,
	)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	proof.Destroy()

	copyValue := *handoff
	copyMaterial := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if successor, copyErr := copyValue.NewSuccessor(
		context.Background(),
		fixture.queue,
		fixture.fence,
		&copyMaterial,
		fixture.partial.NextCheckpoint,
	); successor != nil || !errors.Is(copyErr, errInventoryContinuity) {
		if successor != nil {
			successor.Destroy()
		}
		t.Fatalf("copied handoff successor = (%#v,%v)", successor, copyErr)
	}
	if copyMaterial.valid() {
		t.Fatal("copied handoff retained runtime material")
	}

	const canary = "rollover-handoff-sensitive-canary"
	for name, operation := range map[string]func() error{
		"json marshal": func() error {
			_, marshalErr := json.Marshal(handoff)
			return marshalErr
		},
		"json unmarshal": func() error {
			return json.Unmarshal([]byte(`{"canary":"`+canary+`"}`), handoff)
		},
		"text marshal": func() error {
			_, marshalErr := handoff.MarshalText()
			return marshalErr
		},
		"text unmarshal": func() error {
			return handoff.UnmarshalText([]byte(canary))
		},
		"binary marshal": func() error {
			_, marshalErr := handoff.MarshalBinary()
			return marshalErr
		},
		"binary unmarshal": func() error {
			return handoff.UnmarshalBinary([]byte(canary))
		},
	} {
		if operationErr := operation(); !errors.Is(
			operationErr,
			discoverysource.ErrSensitiveSerialization,
		) {
			t.Fatalf("%s error = %v", name, operationErr)
		}
	}
	rendered := []string{
		fmt.Sprint(handoff),
		fmt.Sprintf("%#v", handoff),
		fmt.Sprintf("%+v", handoff),
		handoff.LogValue().String(),
		slog.Any("handoff", handoff).Value.String(),
	}
	for _, value := range rendered {
		if value != fullInventoryRolloverHandoffRedact ||
			strings.Contains(value, canary) {
			t.Fatalf("handoff rendering = %q", value)
		}
	}

	const contenders = 16
	materials := make([]RuntimeMaterial, contenders)
	for index := range materials {
		materials[index] = inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
	}
	start := make(chan struct{})
	results := make(chan *FullInventoryAttempt, contenders)
	errorsSeen := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := range materials {
		wait.Add(1)
		go func(material *RuntimeMaterial) {
			defer wait.Done()
			<-start
			successor, consumeErr := handoff.NewSuccessor(
				context.Background(),
				fixture.queue,
				fixture.fence,
				material,
				fixture.partial.NextCheckpoint,
			)
			results <- successor
			errorsSeen <- consumeErr
		}(&materials[index])
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsSeen)
	successes := 0
	for successor := range results {
		if successor != nil {
			successes++
			successor.Destroy()
		}
	}
	rejections := 0
	for consumeErr := range errorsSeen {
		if consumeErr == nil {
			continue
		}
		if !errors.Is(consumeErr, errInventoryContinuity) {
			t.Fatalf("concurrent consume error = %v", consumeErr)
		}
		rejections++
	}
	if successes != 1 || rejections != contenders-1 {
		t.Fatalf("concurrent handoff successes/rejections = %d/%d", successes, rejections)
	}
	for index := range materials {
		if materials[index].valid() {
			t.Fatalf("concurrent material %d remained live", index)
		}
	}
}

func TestRolloverHandoffRejectsAdmissionAndSuccessorDriftBeforeSOAP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		wantQueueCalls int
		mutate         func(*rolloverHandoffFixture)
	}{
		{
			name: "foreign attempt",
			mutate: func(fixture *rolloverHandoffFixture) {
				fixture.openRequest.Attempt.AttemptID = "8a200000-0000-4000-8000-000000000099"
			},
		},
		{
			name: "accepted version",
			mutate: func(fixture *rolloverHandoffFixture) {
				fixture.accepted.CheckpointVersion++
			},
		},
		{
			name:           "accepted ciphertext digest",
			wantQueueCalls: 1,
			mutate: func(fixture *rolloverHandoffFixture) {
				fixture.accepted.CheckpointSHA256 = strings.Repeat("b", 64)
			},
		},
		{
			name: "accepted page sequence",
			mutate: func(fixture *rolloverHandoffFixture) {
				fixture.accepted.PageSequence = 0
			},
		},
		{
			name: "foreign run",
			mutate: func(fixture *rolloverHandoffFixture) {
				fixture.command.Coordinates.RunID = "8a200000-0000-4000-8000-000000000098"
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRolloverHandoffFixture(t)
			test.mutate(fixture)
			handoff, _, err := fixture.authority.BeginHandoff(
				context.Background(),
				fixture.queue,
				fixture.fence,
				fixture.openRequest,
				fixture.command,
				fixture.accepted,
				fixture.partial.NextCheckpoint,
			)
			if handoff != nil {
				handoff.Destroy()
			}
			if handoff != nil || err == nil {
				t.Fatalf("BeginHandoff(drift) = (%#v,%v)", handoff, err)
			}
			if got := fixture.queue.callCount(); got != test.wantQueueCalls {
				t.Fatalf(
					"admission drift Queue calls = %d, want %d",
					got,
					test.wantQueueCalls,
				)
			}
			if got := fixture.predecessor.methodSnapshot(); !slices.Equal(
				got,
				[]string{"RetrievePropertiesEx"},
			) {
				t.Fatalf("admission drift made SOAP calls: %v", got)
			}
		})
	}

	t.Run("changed checkpoint", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		changed, err := discoverysource.NewCheckpoint(profileCode, []byte(`{"changed":true}`))
		if err != nil {
			t.Fatalf("NewCheckpoint(changed) error = %v", err)
		}
		defer changed.Clear()
		handoff, _, beginErr := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			changed,
		)
		if handoff != nil {
			handoff.Destroy()
		}
		if handoff != nil || beginErr == nil || fixture.queue.callCount() != 0 {
			t.Fatalf(
				"BeginHandoff(changed checkpoint) = (%#v,%v), Queue calls %d",
				handoff,
				beginErr,
				fixture.queue.callCount(),
			)
		}
	})

	t.Run("changed fence after response loss", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		fixture.queue.dropResponse = true
		handoff, _, firstErr := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		if handoff != nil || !errors.Is(firstErr, discoveryqueue.ErrUnavailable) {
			if handoff != nil {
				handoff.Destroy()
			}
			t.Fatalf("BeginHandoff(response loss) = (%#v,%v)", handoff, firstErr)
		}
		var raw [32]byte
		for index := range raw {
			raw[index] = byte(index + 99)
		}
		foreignFence, err := leasefence.FromQueueClaim(
			fixture.openRequest.Coordinates.RunID,
			"foreign-rollover-owner",
			1,
			&raw,
		)
		if err != nil {
			t.Fatalf("FromQueueClaim(foreign) error = %v", err)
		}
		defer foreignFence.Destroy()
		handoff, _, secondErr := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			foreignFence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		if handoff != nil {
			handoff.Destroy()
		}
		if handoff != nil || secondErr == nil || fixture.queue.callCount() != 1 {
			t.Fatalf(
				"BeginHandoff(changed fence) = (%#v,%v), Queue calls %d",
				handoff,
				secondErr,
				fixture.queue.callCount(),
			)
		}
	})

	t.Run("response loss freezes predecessor and exact replay", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		fixture.queue.dropResponse = true
		handoff, _, firstErr := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		if handoff != nil || !errors.Is(firstErr, discoveryqueue.ErrUnavailable) {
			if handoff != nil {
				handoff.Destroy()
			}
			t.Fatalf("BeginHandoff(response loss) = (%#v,%v)", handoff, firstErr)
		}
		methodsBeforeFreeze := fixture.predecessor.methodSnapshot()
		oldRequest := fixture.request
		oldRequest.Checkpoint = fixture.partial.NextCheckpoint.Clone()
		oldOutcome, oldErr := fixture.provider.Discover(
			context.Background(),
			fixture.runtime,
			oldRequest,
		)
		oldRequest.Checkpoint.Clear()
		if oldOutcome != nil || !errors.Is(oldErr, errInventoryContinuity) {
			t.Fatalf(
				"Discover(predecessor after response loss) = (%#v,%v)",
				oldOutcome,
				oldErr,
			)
		}
		if got := fixture.predecessor.methodSnapshot(); !slices.Equal(
			got,
			methodsBeforeFreeze,
		) {
			t.Fatalf(
				"response-loss freeze allowed predecessor SOAP: before=%v after=%v",
				methodsBeforeFreeze,
				got,
			)
		}
		if rebound, bindErr := fixture.opener.attempt.BindRuntime(
			context.Background(),
			fixture.binding,
		); rebound != (discoverysource.BoundRuntime{}) ||
			!errors.Is(bindErr, errInventoryContinuity) {
			t.Fatalf(
				"BindRuntime(predecessor after response loss) = (%#v,%v)",
				rebound,
				bindErr,
			)
		}

		changed := fixture.accepted
		changed.PageDigestSHA256 = strings.Repeat("e", 64)
		changedHandoff, _, changedErr := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			changed,
			fixture.partial.NextCheckpoint,
		)
		if changedHandoff != nil {
			changedHandoff.Destroy()
		}
		if changedHandoff != nil ||
			!errors.Is(changedErr, errInventoryContinuity) ||
			fixture.queue.callCount() != 1 {
			t.Fatalf(
				"BeginHandoff(changed response-loss retry) = (%#v,%v), Queue calls %d",
				changedHandoff,
				changedErr,
				fixture.queue.callCount(),
			)
		}

		handoff, replayed, replayErr := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		if replayErr != nil || handoff == nil || !replayed.Replayed {
			if handoff != nil {
				handoff.Destroy()
			}
			t.Fatalf(
				"BeginHandoff(exact response-loss replay) = (%#v,%#v,%v)",
				handoff,
				replayed,
				replayErr,
			)
		}
		handoff.Destroy()
		destroyedRequest := fixture.request
		destroyedRequest.Checkpoint = fixture.partial.NextCheckpoint.Clone()
		destroyedOutcome, destroyedErr := fixture.provider.Discover(
			context.Background(),
			fixture.runtime,
			destroyedRequest,
		)
		destroyedRequest.Checkpoint.Clear()
		if destroyedOutcome != nil ||
			!errors.Is(destroyedErr, errInventoryContinuity) {
			t.Fatalf(
				"Discover(predecessor after handoff Destroy) = (%#v,%v)",
				destroyedOutcome,
				destroyedErr,
			)
		}
		if rebound, bindErr := fixture.opener.attempt.BindRuntime(
			context.Background(),
			fixture.binding,
		); rebound != (discoverysource.BoundRuntime{}) ||
			!errors.Is(bindErr, errInventoryContinuity) {
			t.Fatalf(
				"BindRuntime(predecessor after handoff Destroy) = (%#v,%v)",
				rebound,
				bindErr,
			)
		}
		if got := fixture.predecessor.methodSnapshot(); !slices.Equal(
			got,
			methodsBeforeFreeze,
		) {
			t.Fatalf("changed retry unfroze predecessor SOAP: before=%v after=%v", methodsBeforeFreeze, got)
		}
	})

	t.Run("context cancellation keeps predecessor frozen and exact replay", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		fixture.queue.beginObserved = make(chan struct{})
		fixture.queue.beginRelease = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type beginResult struct {
			handoff *FullInventoryRolloverHandoff
			result  discoveryqueue.RolloverResult
			err     error
		}
		beginDone := make(chan beginResult, 1)
		go func() {
			handoff, result, err := fixture.authority.BeginHandoff(
				ctx,
				fixture.queue,
				fixture.fence,
				fixture.openRequest,
				fixture.command,
				fixture.accepted,
				fixture.partial.NextCheckpoint,
			)
			beginDone <- beginResult{handoff: handoff, result: result, err: err}
		}()
		select {
		case <-fixture.queue.beginObserved:
		case <-time.After(2 * time.Second):
			t.Fatal("BeginHandoff did not reach the Queue cancellation barrier")
		}
		cancel()
		var canceled beginResult
		select {
		case canceled = <-beginDone:
		case <-time.After(2 * time.Second):
			t.Fatal("BeginHandoff did not return after context cancellation")
		}
		if canceled.handoff != nil {
			canceled.handoff.Destroy()
		}
		if canceled.handoff != nil || !errors.Is(canceled.err, context.Canceled) {
			t.Fatalf(
				"BeginHandoff(canceled Queue) = (%#v,%#v,%v)",
				canceled.handoff,
				canceled.result,
				canceled.err,
			)
		}
		methodsBeforeFreeze := fixture.predecessor.methodSnapshot()
		oldRequest := fixture.request
		oldRequest.Checkpoint = fixture.partial.NextCheckpoint.Clone()
		oldOutcome, oldErr := fixture.provider.Discover(
			context.Background(),
			fixture.runtime,
			oldRequest,
		)
		oldRequest.Checkpoint.Clear()
		if oldOutcome != nil || !errors.Is(oldErr, errInventoryContinuity) {
			t.Fatalf(
				"Discover(predecessor after context cancellation) = (%#v,%v)",
				oldOutcome,
				oldErr,
			)
		}
		if got := fixture.predecessor.methodSnapshot(); !slices.Equal(
			got,
			methodsBeforeFreeze,
		) {
			t.Fatalf(
				"context cancellation unfroze predecessor SOAP: before=%v after=%v",
				methodsBeforeFreeze,
				got,
			)
		}
		close(fixture.queue.beginRelease)
		handoff, replayed, replayErr := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			fixture.accepted,
			fixture.partial.NextCheckpoint,
		)
		if replayErr != nil || handoff == nil || !replayed.Replayed {
			if handoff != nil {
				handoff.Destroy()
			}
			t.Fatalf(
				"BeginHandoff(exact retry after cancellation) = (%#v,%#v,%v)",
				handoff,
				replayed,
				replayErr,
			)
		}
		handoff.Destroy()
	})

	t.Run("authority root drift", func(t *testing.T) {
		rootA := types.ManagedObjectReference{Type: "Folder", Value: "group-a"}
		rootB := types.ManagedObjectReference{Type: "Folder", Value: "group-b"}
		rootC := types.ManagedObjectReference{Type: "Folder", Value: "group-c"}
		for _, test := range []struct {
			name  string
			roots []types.ManagedObjectReference
		}{
			{name: "added root", roots: []types.ManagedObjectReference{rootA, rootB, rootC}},
			{name: "removed root", roots: []types.ManagedObjectReference{rootA}},
			{name: "same size replacement", roots: []types.ManagedObjectReference{rootC, rootA}},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture := newRolloverHandoffFixtureWithRoots(
					t,
					[]types.ManagedObjectReference{rootB, rootA},
				)
				handoff := fixture.begin(t)
				proof, err := fixture.broker.RevokeAttempt(
					context.Background(),
					fixture.openRequest.Attempt.AttemptID,
				)
				if err != nil {
					t.Fatalf("RevokeAttempt() error = %v", err)
				}
				proof.Destroy()
				openedBefore, empty, err := openFullInventoryCheckpoint(
					fixture.partial.NextCheckpoint,
				)
				if err != nil || empty {
					t.Fatalf(
						"open rollover seed = (%#v,%t,%v)",
						openedBefore,
						empty,
						err,
					)
				}
				driftMaterial := inventoryRuntimeMaterial(t, test.roots)
				successor, successorErr := handoff.NewSuccessor(
					context.Background(),
					fixture.queue,
					fixture.fence,
					&driftMaterial,
					fixture.partial.NextCheckpoint,
				)
				if successor != nil {
					successor.Destroy()
				}
				if successor != nil || !errors.Is(
					successorErr,
					errInventoryIdentityDrift,
				) {
					t.Fatalf(
						"NewSuccessor(root drift) = (%#v,%v)",
						successor,
						successorErr,
					)
				}
				if driftMaterial.valid() {
					t.Fatal("root drift retained runtime material")
				}
				openedAfter, afterEmpty, err := openFullInventoryCheckpoint(
					fixture.partial.NextCheckpoint,
				)
				if err != nil || afterEmpty || openedAfter != openedBefore {
					t.Fatalf(
						"root drift changed checkpoint = (%#v,%t,%v), before %#v",
						openedAfter,
						afterEmpty,
						err,
						openedBefore,
					)
				}
				if got := fixture.successor.methodSnapshot(); len(got) != 0 {
					t.Fatalf("root drift made successor SOAP calls: %v", got)
				}
			})
		}
	})

	t.Run("canonical root permutation", func(t *testing.T) {
		rootA := types.ManagedObjectReference{Type: "Folder", Value: "group-a"}
		rootB := types.ManagedObjectReference{Type: "Folder", Value: "group-b"}
		fixture := newRolloverHandoffFixtureWithRoots(
			t,
			[]types.ManagedObjectReference{rootB, rootA},
		)
		handoff := fixture.begin(t)
		proof, err := fixture.broker.RevokeAttempt(
			context.Background(),
			fixture.openRequest.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatalf("RevokeAttempt() error = %v", err)
		}
		proof.Destroy()
		material := inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{rootA, rootB},
		)
		successor, err := handoff.NewSuccessor(
			context.Background(),
			fixture.queue,
			fixture.fence,
			&material,
			fixture.partial.NextCheckpoint,
		)
		if err != nil {
			t.Fatalf("NewSuccessor(canonical permutation) error = %v", err)
		}
		successor.Destroy()
		if material.valid() {
			t.Fatal("canonical permutation retained runtime material")
		}
		if got := fixture.successor.methodSnapshot(); len(got) != 0 {
			t.Fatalf("canonical permutation made premature SOAP calls: %v", got)
		}
	})

	t.Run("runtime binding drift", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		handoff := fixture.begin(t)
		proof, err := fixture.broker.RevokeAttempt(
			context.Background(),
			fixture.openRequest.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatalf("RevokeAttempt() error = %v", err)
		}
		proof.Destroy()
		material := inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		successor, err := handoff.NewSuccessor(
			context.Background(),
			fixture.queue,
			fixture.fence,
			&material,
			fixture.partial.NextCheckpoint,
		)
		if err != nil {
			t.Fatalf("NewSuccessor() error = %v", err)
		}
		defer successor.Destroy()
		drifted := fixture.binding
		drifted.SourceRevision++
		runtime, bindErr := successor.BindRuntime(context.Background(), drifted)
		if runtime != (discoverysource.BoundRuntime{}) || bindErr == nil {
			t.Fatalf("BindRuntime(drift) = (%#v,%v)", runtime, bindErr)
		}
		if got := fixture.successor.methodSnapshot(); len(got) != 0 {
			t.Fatalf("binding drift made successor SOAP calls: %v", got)
		}
	})

	t.Run("successor checkpoint drift consumes capability", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		handoff := fixture.begin(t)
		proof, err := fixture.broker.RevokeAttempt(
			context.Background(),
			fixture.openRequest.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatalf("RevokeAttempt() error = %v", err)
		}
		proof.Destroy()
		changed, err := discoverysource.NewCheckpoint(profileCode, nil)
		if err != nil {
			t.Fatalf("NewCheckpoint(empty) error = %v", err)
		}
		defer changed.Clear()
		material := inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		successor, successorErr := handoff.NewSuccessor(
			context.Background(),
			fixture.queue,
			fixture.fence,
			&material,
			changed,
		)
		if successor != nil {
			successor.Destroy()
		}
		if successor != nil || !errors.Is(successorErr, errInventoryContinuity) {
			t.Fatalf("NewSuccessor(checkpoint drift) = (%#v,%v)", successor, successorErr)
		}
		if material.valid() {
			t.Fatal("checkpoint drift retained runtime material")
		}
		replayMaterial := inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		replay, replayErr := handoff.NewSuccessor(
			context.Background(),
			fixture.queue,
			fixture.fence,
			&replayMaterial,
			fixture.partial.NextCheckpoint,
		)
		if replay != nil {
			replay.Destroy()
		}
		if replay != nil || !errors.Is(replayErr, errInventoryContinuity) {
			t.Fatalf("NewSuccessor(after drift) = (%#v,%v)", replay, replayErr)
		}
	})
}

func TestRolloverHandoffRevalidatesCurrentAttemptAndFence(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(discoveryqueue.CleanupAttempt) discoveryqueue.CleanupAttempt
	}{
		{
			name: "current attempt id",
			mutate: func(attempt discoveryqueue.CleanupAttempt) discoveryqueue.CleanupAttempt {
				attempt.AttemptID = "8a200000-0000-4000-8000-000000000099"
				return attempt
			},
		},
		{
			name: "current attempt epoch",
			mutate: func(attempt discoveryqueue.CleanupAttempt) discoveryqueue.CleanupAttempt {
				attempt.AttemptEpoch++
				return attempt
			},
		},
	} {
		test := test
		t.Run("before mint/"+test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRolloverHandoffFixture(t)
			fixture.queue.mu.Lock()
			fixture.queue.currentAttempt = test.mutate(fixture.queue.currentAttempt)
			fixture.queue.mu.Unlock()

			handoff, _, err := fixture.authority.BeginHandoff(
				context.Background(),
				fixture.queue,
				fixture.fence,
				fixture.openRequest,
				fixture.command,
				fixture.accepted,
				fixture.partial.NextCheckpoint,
			)
			if handoff != nil {
				handoff.Destroy()
			}
			if handoff != nil || !errors.Is(err, errInventoryContinuity) {
				t.Fatalf("BeginHandoff(current attempt drift) = (%#v,%v)", handoff, err)
			}
			if beginCalls, reserveCalls := fixture.queue.rolloverAdmissionCallCounts(); beginCalls != 0 || reserveCalls != 1 {
				t.Fatalf(
					"current attempt drift Queue Begin/Reserve calls = %d/%d, want 0/1",
					beginCalls,
					reserveCalls,
				)
			}
			assertRolloverPredecessorFrozen(t, fixture)
			assertRolloverPreflightRetryRejected(t, fixture)
		})

		t.Run("after mint/"+test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRolloverHandoffFixture(t)
			handoff := fixture.begin(t)
			proof, err := fixture.broker.RevokeAttempt(
				context.Background(),
				fixture.openRequest.Attempt.AttemptID,
			)
			if err != nil {
				t.Fatalf("RevokeAttempt() error = %v", err)
			}
			proof.Destroy()
			fixture.queue.mu.Lock()
			fixture.queue.currentAttempt = test.mutate(fixture.queue.currentAttempt)
			fixture.queue.mu.Unlock()

			material := inventoryRuntimeMaterial(
				t,
				[]types.ManagedObjectReference{testAuthorityRoot},
			)
			successor, successorErr := handoff.NewSuccessor(
				context.Background(),
				fixture.queue,
				fixture.fence,
				&material,
				fixture.partial.NextCheckpoint,
			)
			if successor != nil {
				successor.Destroy()
			}
			if successor != nil || !errors.Is(successorErr, errInventoryContinuity) {
				t.Fatalf("NewSuccessor(current attempt drift) = (%#v,%v)", successor, successorErr)
			}
			if material.valid() {
				t.Fatal("current attempt drift retained runtime material")
			}
			if got := fixture.successor.methodSnapshot(); len(got) != 0 {
				t.Fatalf("current attempt drift made successor SOAP calls: %v", got)
			}
			fixture.queue.mu.Lock()
			fixture.queue.currentAttempt = fixture.openRequest.Attempt
			fixture.queue.mu.Unlock()
			replayMaterial := inventoryRuntimeMaterial(
				t,
				[]types.ManagedObjectReference{testAuthorityRoot},
			)
			replay, replayErr := handoff.NewSuccessor(
				context.Background(),
				fixture.queue,
				fixture.fence,
				&replayMaterial,
				fixture.partial.NextCheckpoint,
			)
			if replay != nil {
				replay.Destroy()
			}
			if replay != nil || !errors.Is(replayErr, errInventoryContinuity) {
				t.Fatalf("NewSuccessor(after attempt drift) = (%#v,%v)", replay, replayErr)
			}
		})

		t.Run("after admission/"+test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRolloverHandoffFixture(t)
			drifted := test.mutate(fixture.openRequest.Attempt)
			fixture.queue.mu.Lock()
			fixture.queue.currentAttemptAfterBegin = &drifted
			fixture.queue.mu.Unlock()
			handoff, _, err := fixture.authority.BeginHandoff(
				context.Background(),
				fixture.queue,
				fixture.fence,
				fixture.openRequest,
				fixture.command,
				fixture.accepted,
				fixture.partial.NextCheckpoint,
			)
			if handoff != nil {
				handoff.Destroy()
			}
			if handoff != nil || !errors.Is(err, errInventoryContinuity) {
				t.Fatalf("BeginHandoff(post-admission drift) = (%#v,%v)", handoff, err)
			}
			if beginCalls, reserveCalls := fixture.queue.rolloverAdmissionCallCounts(); beginCalls != 1 || reserveCalls != 2 {
				t.Fatalf(
					"post-admission drift Queue Begin/Reserve calls = %d/%d, want 1/2",
					beginCalls,
					reserveCalls,
				)
			}
			methodsBeforeFreeze := fixture.predecessor.methodSnapshot()
			oldRequest := fixture.request
			oldRequest.Checkpoint = fixture.partial.NextCheckpoint.Clone()
			oldOutcome, oldErr := fixture.provider.Discover(
				context.Background(),
				fixture.runtime,
				oldRequest,
			)
			oldRequest.Checkpoint.Clear()
			if oldOutcome != nil || !errors.Is(oldErr, errInventoryContinuity) {
				t.Fatalf(
					"Discover(predecessor after post-admission drift) = (%#v,%v)",
					oldOutcome,
					oldErr,
				)
			}
			if got := fixture.predecessor.methodSnapshot(); !slices.Equal(
				got,
				methodsBeforeFreeze,
			) {
				t.Fatalf(
					"post-admission failure unfroze predecessor SOAP: before=%v after=%v",
					methodsBeforeFreeze,
					got,
				)
			}
		})
	}

	t.Run("destroyed fence after mint", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		handoff := fixture.begin(t)
		proof, err := fixture.broker.RevokeAttempt(
			context.Background(),
			fixture.openRequest.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatalf("RevokeAttempt() error = %v", err)
		}
		proof.Destroy()
		fixture.fence.Destroy()

		material := inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		successor, successorErr := handoff.NewSuccessor(
			context.Background(),
			fixture.queue,
			fixture.fence,
			&material,
			fixture.partial.NextCheckpoint,
		)
		if successor != nil {
			successor.Destroy()
		}
		if successor != nil || !errors.Is(successorErr, errInventoryContinuity) {
			t.Fatalf("NewSuccessor(destroyed fence) = (%#v,%v)", successor, successorErr)
		}
		if material.valid() {
			t.Fatal("destroyed fence retained runtime material")
		}
		if got := fixture.successor.methodSnapshot(); len(got) != 0 {
			t.Fatalf("destroyed fence made successor SOAP calls: %v", got)
		}
	})

	t.Run("foreign fence after mint", func(t *testing.T) {
		fixture := newRolloverHandoffFixture(t)
		handoff := fixture.begin(t)
		proof, err := fixture.broker.RevokeAttempt(
			context.Background(),
			fixture.openRequest.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatalf("RevokeAttempt() error = %v", err)
		}
		proof.Destroy()
		var raw [32]byte
		for index := range raw {
			raw[index] = byte(index + 101)
		}
		foreignFence, err := leasefence.FromQueueClaim(
			fixture.openRequest.Coordinates.RunID,
			"task21a-rollover-foreign-owner",
			fixture.openRequest.Attempt.AttemptEpoch,
			&raw,
		)
		if err != nil {
			t.Fatalf("FromQueueClaim(foreign) error = %v", err)
		}
		defer foreignFence.Destroy()
		material := inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		successor, successorErr := handoff.NewSuccessor(
			context.Background(),
			fixture.queue,
			foreignFence,
			&material,
			fixture.partial.NextCheckpoint,
		)
		if successor != nil {
			successor.Destroy()
		}
		if successor != nil || !errors.Is(successorErr, errInventoryContinuity) {
			t.Fatalf("NewSuccessor(foreign fence) = (%#v,%v)", successor, successorErr)
		}
		if material.valid() {
			t.Fatal("foreign fence retained runtime material")
		}
		replayMaterial := inventoryRuntimeMaterial(
			t,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		replay, replayErr := handoff.NewSuccessor(
			context.Background(),
			fixture.queue,
			fixture.fence,
			&replayMaterial,
			fixture.partial.NextCheckpoint,
		)
		if replay != nil {
			replay.Destroy()
		}
		if replay != nil || !errors.Is(replayErr, errInventoryContinuity) {
			t.Fatalf("NewSuccessor(after foreign fence) = (%#v,%v)", replay, replayErr)
		}
	})
}

type rolloverHandoffFixture struct {
	authority   *FullInventoryRolloverAuthority
	broker      *discoverycleanup.CleanupBroker
	opener      *rolloverHandoffOpener
	queue       *rolloverAdmissionQueue
	fence       assetcatalog.LeaseFence
	openRequest discoverycleanup.OpenAttemptRequest
	command     discoveryqueue.RolloverCommand
	accepted    discoverysource.PageCommitResult
	binding     discoverysource.RuntimeBinding
	provider    discoverysource.Provider
	runtime     discoverysource.BoundRuntime
	request     discoverysource.DiscoverRequest
	partial     discoverysource.Page
	predecessor *fakeInventoryClient
	successor   *fakeInventoryClient
}

func newRolloverHandoffFixture(t *testing.T) *rolloverHandoffFixture {
	t.Helper()
	return newRolloverHandoffFixtureWithRoots(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
}

func newRolloverHandoffFixtureWithRoots(
	t *testing.T,
	roots []types.ManagedObjectReference,
) *rolloverHandoffFixture {
	t.Helper()
	canonicalRoots := slices.Clone(roots)
	slices.SortFunc(canonicalRoots, compareManagedObjectReference)
	if len(canonicalRoots) == 0 {
		t.Fatal("rollover handoff fixture requires an authority root")
	}
	primaryRoot := canonicalRoots[0]
	predecessor := newFakeInventoryClient(testInstanceUUID)
	predecessor.initial[primaryRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-partial", "partial"),
		},
		Token: "rollover-handoff-predecessor-token-canary",
	}
	successor := newFakeInventoryClient(testInstanceUUID)
	successor.initial[primaryRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-partial", "partial"),
			inventoryFolderContent(primaryRoot.Value, "root"),
		},
	}
	request := validInventoryRequest(t)
	binding := publishedInventoryBinding(request)
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	var clientMu sync.Mutex
	clients := []validationClient{predecessor, successor}
	factory.openClient = func(context.Context, resolvedRuntime) (validationClient, error) {
		clientMu.Lock()
		defer clientMu.Unlock()
		if len(clients) == 0 {
			return nil, errInventoryContinuity
		}
		client := clients[0]
		clients = clients[1:]
		return client, nil
	}
	provider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	authority := NewFullInventoryRolloverAuthority()
	t.Cleanup(authority.Destroy)
	material := inventoryRuntimeMaterial(
		t,
		roots,
	)
	openRequest := discoverycleanup.OpenAttemptRequest{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: request.Locator.Scope,
			RunID: "8a200000-0000-4000-8000-000000000001",
		},
		Attempt: discoveryqueue.CleanupAttempt{
			RunID:        "8a200000-0000-4000-8000-000000000001",
			AttemptID:    "8a200000-0000-4000-8000-000000000002",
			AttemptEpoch: 1,
		},
	}
	opener := &rolloverHandoffOpener{
		authority: authority,
		material:  &material,
	}
	proofAuthority := &rolloverHandoffProofAuthority{
		key: []byte("task21a-rollover-handoff-unit-proof-key"),
	}
	broker, err := discoverycleanup.NewCleanupBroker(opener, proofAuthority)
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)
	session, err := broker.OpenAttempt(context.Background(), openRequest)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	t.Cleanup(session.Destroy)
	runtime, err := broker.BindAttemptRuntime(context.Background(), session, binding)
	if err != nil {
		t.Fatalf("BindAttemptRuntime() error = %v", err)
	}
	partial := discoverInventoryPage(t, provider, runtime, request)
	if partial.FinalPage || partial.CompleteSnapshot {
		partial.NextCheckpoint.Clear()
		t.Fatalf("rollover fixture page closed snapshot: %#v", partial)
	}
	t.Cleanup(func() {
		partial.NextCheckpoint.Clear()
		request.Checkpoint.Clear()
	})
	accepted := discoverysource.PageCommitResult{
		RunID:                    openRequest.Coordinates.RunID,
		PageSequence:             1,
		CheckpointVersion:        1,
		CheckpointSHA256:         strings.Repeat("a", 64),
		PageDigestSHA256:         strings.Repeat("b", 64),
		RelationPageDigestSHA256: strings.Repeat("c", 64),
	}
	command := discoveryqueue.RolloverCommand{
		Coordinates:    openRequest.Coordinates,
		ReasonCode:     "PROVIDER_SESSION_LOST",
		EvidenceDigest: strings.Repeat("8", 64),
	}
	var rawFence [32]byte
	for index := range rawFence {
		rawFence[index] = byte(index + 1)
	}
	fenceTokenDigest := sha256.Sum256(rawFence[:])
	const fenceOwner = "task21a-rollover-unit-owner"
	fence, err := leasefence.FromQueueClaim(
		openRequest.Coordinates.RunID,
		fenceOwner,
		1,
		&rawFence,
	)
	if err != nil {
		t.Fatalf("FromQueueClaim() error = %v", err)
	}
	t.Cleanup(fence.Destroy)
	queue := &rolloverAdmissionQueue{
		verifier:       authority,
		fence:          fence,
		fenceOwner:     fenceOwner,
		fenceEpoch:     1,
		fenceTokenSHA:  fmt.Sprintf("%x", fenceTokenDigest[:]),
		currentAttempt: openRequest.Attempt,
		request: discoveryqueue.CheckpointLineageRolloverRequest{
			Coordinates:            openRequest.Coordinates,
			SourceID:               binding.Locator.SourceID,
			ProviderKind:           binding.ProviderKind,
			SourceRevision:         binding.SourceRevision,
			SourceRevisionDigest:   binding.SourceRevisionDigest,
			SourceDefinitionDigest: strings.Repeat("d", 64),
			ProfileCode:            binding.ProfileCode,
			CheckpointVersion:      accepted.CheckpointVersion,
			CheckpointSHA256:       accepted.CheckpointSHA256,
			ReasonCode:             command.ReasonCode,
			EvidenceDigest:         command.EvidenceDigest,
		},
		result: discoveryqueue.RolloverResult{
			ReasonCode:     command.ReasonCode,
			EvidenceDigest: command.EvidenceDigest,
			GateRevision:   7,
		},
	}
	return &rolloverHandoffFixture{
		authority: authority, broker: broker, opener: opener, queue: queue,
		fence: fence, openRequest: openRequest, command: command, accepted: accepted,
		binding: binding, provider: provider, runtime: runtime, request: request, partial: partial,
		predecessor: predecessor, successor: successor,
	}
}

func (fixture *rolloverHandoffFixture) begin(
	t *testing.T,
) *FullInventoryRolloverHandoff {
	t.Helper()
	handoff, result, err := fixture.authority.BeginHandoff(
		context.Background(),
		fixture.queue,
		fixture.fence,
		fixture.openRequest,
		fixture.command,
		fixture.accepted,
		fixture.partial.NextCheckpoint,
	)
	if err != nil || handoff == nil || result.Replayed {
		if handoff != nil {
			handoff.Destroy()
		}
		t.Fatalf("BeginHandoff() = (%#v,%#v,%v)", handoff, result, err)
	}
	t.Cleanup(handoff.Destroy)
	return handoff
}

type rolloverHandoffOpener struct {
	authority *FullInventoryRolloverAuthority
	material  *RuntimeMaterial
	attempt   *FullInventoryAttempt
}

func (opener *rolloverHandoffOpener) OpenSession(
	_ context.Context,
	request discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	if opener.authority == nil || opener.material == nil || opener.attempt != nil {
		return nil, errInventoryRejected
	}
	attempt, err := opener.authority.NewAttempt(opener.material, request)
	opener.material = nil
	if err != nil {
		return nil, err
	}
	opener.attempt = attempt
	return attempt, nil
}

type rolloverHandoffProofAuthority struct {
	key []byte
}

func (authority *rolloverHandoffProofAuthority) SignCleanupProof(
	ctx context.Context,
	digest []byte,
) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(digest) != sha256.Size {
		return nil, errInventoryRejected
	}
	mac := hmac.New(sha256.New, authority.key)
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (authority *rolloverHandoffProofAuthority) VerifyCleanupProof(
	ctx context.Context,
	digest []byte,
	signature []byte,
) error {
	expected, err := authority.SignCleanupProof(ctx, digest)
	if err != nil {
		return err
	}
	defer clear(expected)
	if !hmac.Equal(expected, signature) {
		return errInventoryRejected
	}
	return nil
}

type rolloverAdmissionQueue struct {
	discoveryqueue.Queue

	mu                       sync.Mutex
	verifier                 discoveryqueue.CheckpointLineageRolloverVerifier
	fence                    assetcatalog.LeaseFence
	fenceOwner               string
	fenceEpoch               int64
	fenceTokenSHA            string
	request                  discoveryqueue.CheckpointLineageRolloverRequest
	result                   discoveryqueue.RolloverResult
	calls                    int
	reserveCalls             int
	currentAttempt           discoveryqueue.CleanupAttempt
	currentAttemptAfterBegin *discoveryqueue.CleanupAttempt
	reserveObserved          chan struct{}
	reserveRelease           chan struct{}
	reserveError             error
	reserveOnce              sync.Once
	beginObserved            chan struct{}
	beginRelease             chan struct{}
	beginOnce                sync.Once
	dropResponse             bool
	dropped                  bool
}

func (queue *rolloverAdmissionQueue) ReserveCleanupAttempt(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.RunCommand,
) (discoveryqueue.CleanupAttempt, error) {
	queue.mu.Lock()
	queue.reserveCalls++
	observed := queue.reserveObserved
	release := queue.reserveRelease
	reserveErr := queue.reserveError
	current := queue.currentAttempt
	valid := ctx != nil && ctx.Err() == nil &&
		fence == queue.fence &&
		fence.Matches(
			queue.request.Coordinates.RunID,
			queue.fenceOwner,
			queue.fenceEpoch,
			queue.fenceTokenSHA,
		) &&
		command.Coordinates == queue.request.Coordinates
	queue.mu.Unlock()
	if observed != nil {
		queue.reserveOnce.Do(func() { close(observed) })
	}
	if !valid {
		return discoveryqueue.CleanupAttempt{}, discoveryqueue.ErrStaleFence
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return discoveryqueue.CleanupAttempt{}, ctx.Err()
		}
	}
	if reserveErr != nil {
		return discoveryqueue.CleanupAttempt{}, reserveErr
	}
	return current, nil
}

func (queue *rolloverAdmissionQueue) BeginCheckpointLineageRollover(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.RolloverCommand,
) (discoveryqueue.RolloverResult, error) {
	queue.mu.Lock()
	queue.calls++
	if fence != queue.fence ||
		!fence.Matches(
			queue.request.Coordinates.RunID,
			queue.fenceOwner,
			queue.fenceEpoch,
			queue.fenceTokenSHA,
		) ||
		command.Coordinates != queue.request.Coordinates ||
		command.ReasonCode != queue.request.ReasonCode ||
		command.EvidenceDigest != queue.request.EvidenceDigest {
		queue.mu.Unlock()
		return discoveryqueue.RolloverResult{}, discoveryqueue.ErrStaleFence
	}
	drop := queue.dropResponse && !queue.dropped
	if drop {
		queue.dropped = true
	}
	request := queue.request
	result := queue.result
	if queue.currentAttemptAfterBegin != nil {
		queue.currentAttempt = *queue.currentAttemptAfterBegin
		queue.currentAttemptAfterBegin = nil
	}
	if queue.calls > 1 {
		result.Replayed = true
	}
	beginObserved := queue.beginObserved
	beginRelease := queue.beginRelease
	queue.mu.Unlock()
	if beginObserved != nil {
		queue.beginOnce.Do(func() { close(beginObserved) })
	}
	if beginRelease != nil {
		select {
		case <-beginRelease:
		case <-ctx.Done():
			return discoveryqueue.RolloverResult{}, ctx.Err()
		}
	}
	if err := queue.verifier.VerifyCheckpointLineageRollover(ctx, request); err != nil {
		return discoveryqueue.RolloverResult{}, discoveryqueue.ErrIneligible
	}
	if drop {
		return discoveryqueue.RolloverResult{}, discoveryqueue.ErrUnavailable
	}
	return result, nil
}

func (queue *rolloverAdmissionQueue) callCount() int {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.calls
}

func (queue *rolloverAdmissionQueue) rolloverAdmissionCallCounts() (int, int) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.calls, queue.reserveCalls
}

func assertRolloverPredecessorFrozen(
	t *testing.T,
	fixture *rolloverHandoffFixture,
) {
	t.Helper()
	methodsBefore := fixture.predecessor.methodSnapshot()
	request := fixture.request
	request.Checkpoint = fixture.partial.NextCheckpoint.Clone()
	outcome, err := fixture.provider.Discover(
		context.Background(),
		fixture.runtime,
		request,
	)
	request.Checkpoint.Clear()
	if outcome != nil || !errors.Is(err, errInventoryContinuity) {
		t.Fatalf("Discover(predecessor during/after preflight) = (%#v,%v)", outcome, err)
	}
	if got := fixture.predecessor.methodSnapshot(); !slices.Equal(got, methodsBefore) {
		t.Fatalf("preflight freeze allowed predecessor SOAP: before=%v after=%v", methodsBefore, got)
	}
	if rebound, bindErr := fixture.opener.attempt.BindRuntime(
		context.Background(),
		fixture.binding,
	); rebound != (discoverysource.BoundRuntime{}) ||
		!errors.Is(bindErr, errInventoryContinuity) {
		t.Fatalf(
			"BindRuntime(predecessor during/after preflight) = (%#v,%v)",
			rebound,
			bindErr,
		)
	}
}

func assertRolloverPreflightRetryRejected(
	t *testing.T,
	fixture *rolloverHandoffFixture,
) {
	t.Helper()
	_, reserveCallsBefore := fixture.queue.rolloverAdmissionCallCounts()
	changed := fixture.accepted
	changed.PageDigestSHA256 = strings.Repeat("e", 64)
	for _, accepted := range []discoverysource.PageCommitResult{
		fixture.accepted,
		changed,
	} {
		handoff, _, err := fixture.authority.BeginHandoff(
			context.Background(),
			fixture.queue,
			fixture.fence,
			fixture.openRequest,
			fixture.command,
			accepted,
			fixture.partial.NextCheckpoint,
		)
		if handoff != nil {
			handoff.Destroy()
		}
		if handoff != nil || !errors.Is(err, errInventoryContinuity) {
			t.Fatalf("BeginHandoff(preflight retry) = (%#v,%v)", handoff, err)
		}
	}
	if _, reserveCallsAfter := fixture.queue.rolloverAdmissionCallCounts(); reserveCallsAfter != reserveCallsBefore {
		t.Fatalf(
			"closed preflight retried Queue Reserve %d times, before %d",
			reserveCallsAfter,
			reserveCallsBefore,
		)
	}
	assertRolloverPredecessorFrozen(t, fixture)
}

func newInventoryRuntimeMaterialPointer(
	t *testing.T,
	root types.ManagedObjectReference,
) *RuntimeMaterial {
	t.Helper()
	material := inventoryRuntimeMaterial(t, []types.ManagedObjectReference{root})
	return &material
}
