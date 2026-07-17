package vsphere

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/seaworld008/aiops-system/internal/discoveryworker"
	"github.com/seaworld008/aiops-system/internal/leasefence"
	"github.com/vmware/govmomi/vim25/types"
)

func TestInventoryFullSnapshotPaginatesOverFiveHundredObjectsInOneAttempt(t *testing.T) {
	t.Parallel()

	firstObjects := make([]types.ObjectContent, 0, 500)
	for index := 499; index >= 0; index-- {
		firstObjects = append(firstObjects, inventoryFolderContent(
			fmt.Sprintf("group-%04d", index),
			fmt.Sprintf("folder-%04d", index),
		))
	}
	finalObjects := []types.ObjectContent{
		inventoryFolderContent("group-0501", "folder-0501"),
		inventoryFolderContent("group-0500", "folder-0500"),
		inventoryFolderContent(testAuthorityRoot.Value, "authority-root"),
	}
	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: firstObjects,
		Token:   "raw-continuation-token-canary",
	}
	client.continuations["raw-continuation-token-canary"] = types.RetrieveResult{
		Objects: finalObjects,
	}

	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)

	first := discoverInventoryPage(t, provider, runtime, request)
	if first.FinalPage || first.CompleteSnapshot || len(first.Items) != 500 {
		t.Fatalf("first page shape = items:%d final:%t complete:%t",
			len(first.Items), first.FinalPage, first.CompleteSnapshot)
	}
	assertInventoryItemsSorted(t, first.Items)
	for _, item := range first.Items {
		if item.Freshness.OrderSequence != 1 {
			t.Fatalf("first page freshness sequence = %d, want 1", item.Freshness.OrderSequence)
		}
	}
	assertCheckpointExcludes(t, first.NextCheckpoint, "raw-continuation-token-canary")

	request.Checkpoint.Clear()
	request.Checkpoint = first.NextCheckpoint.Clone()
	first.NextCheckpoint.Clear()
	final := discoverInventoryPage(t, provider, runtime, request)
	if !final.FinalPage || !final.CompleteSnapshot || len(final.Items) != 3 {
		t.Fatalf("final page shape = items:%d final:%t complete:%t",
			len(final.Items), final.FinalPage, final.CompleteSnapshot)
	}
	assertInventoryItemsSorted(t, final.Items)
	for _, item := range final.Items {
		if item.Freshness.OrderSequence != 2 {
			t.Fatalf("final page freshness sequence = %d, want 2", item.Freshness.OrderSequence)
		}
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{
		"RetrievePropertiesEx",
		"ContinueRetrievePropertiesEx",
	}) {
		t.Fatalf("inventory methods = %v", got)
	}
	final.NextCheckpoint.Clear()
	request.Checkpoint.Clear()
}

func TestInventorySameInputCheckpointReplaysInitialNonFinalAndFinalPage(t *testing.T) {
	t.Parallel()

	child := types.ManagedObjectReference{Type: "Folder", Value: "group-child"}
	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent(child.Value, "child"),
		},
		Token: "replay-page-token-one",
	}
	client.continuations["replay-page-token-one"] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-middle", "middle"),
		},
		Token: "replay-page-token-two",
	}
	client.continuations["replay-page-token-two"] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent(
				testAuthorityRoot.Value,
				"authority-root",
				child,
			),
		},
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)

	initial := discoverInventoryPage(t, provider, runtime, request)
	if initial.FinalPage || initial.CompleteSnapshot || len(initial.Items) != 1 {
		t.Fatalf("initial page = %#v", initial)
	}
	initialEvidence := captureInventoryPageEvidence(t, initial)
	defer initialEvidence.Clear()
	initialNext := initial.NextCheckpoint.Clone()
	defer initialNext.Clear()
	mutateCallerInventoryPage(&initial)
	initialReplay := discoverInventoryPage(t, provider, runtime, request)
	assertInventoryPageEvidence(t, initialReplay, initialEvidence)
	mutateCallerInventoryPage(&initialReplay)
	initialReplayAgain := discoverInventoryPage(t, provider, runtime, request)
	assertInventoryPageEvidence(t, initialReplayAgain, initialEvidence)
	initialReplayAgain.NextCheckpoint.Clear()
	if got := client.methodSnapshot(); !slices.Equal(
		got,
		[]string{"RetrievePropertiesEx"},
	) {
		t.Fatalf("initial replay made SOAP calls: %v", got)
	}

	request.Checkpoint.Clear()
	request.Checkpoint = initialNext.Clone()
	nonFinal := discoverInventoryPage(t, provider, runtime, request)
	if nonFinal.FinalPage || nonFinal.CompleteSnapshot || len(nonFinal.Items) != 1 {
		t.Fatalf("non-final page = %#v", nonFinal)
	}
	nonFinalEvidence := captureInventoryPageEvidence(t, nonFinal)
	defer nonFinalEvidence.Clear()
	nonFinalNext := nonFinal.NextCheckpoint.Clone()
	defer nonFinalNext.Clear()
	mutateCallerInventoryPage(&nonFinal)
	nonFinalReplay := discoverInventoryPage(t, provider, runtime, request)
	assertInventoryPageEvidence(t, nonFinalReplay, nonFinalEvidence)
	nonFinalReplay.NextCheckpoint.Clear()
	if got := client.methodSnapshot(); !slices.Equal(got, []string{
		"RetrievePropertiesEx",
		"ContinueRetrievePropertiesEx",
	}) {
		t.Fatalf("non-final replay made SOAP calls: %v", got)
	}

	request.Checkpoint.Clear()
	request.Checkpoint = nonFinalNext.Clone()
	backlog := discoverInventoryPage(t, provider, runtime, request)
	if backlog.FinalPage || backlog.CompleteSnapshot || len(backlog.Items) != 1 {
		t.Fatalf("backlog item page = %#v", backlog)
	}
	backlogNext := backlog.NextCheckpoint.Clone()
	defer backlogNext.Clear()
	backlog.NextCheckpoint.Clear()

	request.Checkpoint.Clear()
	request.Checkpoint = backlogNext.Clone()
	final := discoverInventoryPage(t, provider, runtime, request)
	if !final.FinalPage || !final.CompleteSnapshot ||
		len(final.Items) != 0 || len(final.Relations) != 1 {
		t.Fatalf("final relation page = %#v", final)
	}
	finalEvidence := captureInventoryPageEvidence(t, final)
	defer finalEvidence.Clear()
	mutateCallerInventoryPage(&final)
	finalReplay := discoverInventoryPage(t, provider, runtime, request)
	assertInventoryPageEvidence(t, finalReplay, finalEvidence)
	mutateCallerInventoryPage(&finalReplay)
	finalReplayAgain := discoverInventoryPage(t, provider, runtime, request)
	assertInventoryPageEvidence(t, finalReplayAgain, finalEvidence)
	finalReplayAgain.NextCheckpoint.Clear()
	if got := client.methodSnapshot(); !slices.Equal(got, []string{
		"RetrievePropertiesEx",
		"ContinueRetrievePropertiesEx",
		"ContinueRetrievePropertiesEx",
	}) {
		t.Fatalf("final replay made SOAP calls: %v", got)
	}
	request.Checkpoint.Clear()
}

func TestInventoryReplayRejectsCheckpointBindingAuthoritySessionAndTokenDrift(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*testing.T, *FullInventoryAttempt, *fakeInventoryClient, *discoverysource.DiscoverRequest)
		wantErr error
	}{
		{
			name: "changed checkpoint",
			mutate: func(
				t *testing.T,
				_ *FullInventoryAttempt,
				_ *fakeInventoryClient,
				request *discoverysource.DiscoverRequest,
			) {
				t.Helper()
				changed, _, err := newFullInventoryCheckpoint(
					testInstanceUUID,
					1,
					"77777777-7777-4777-8777-777777777777",
					[]byte("changed-replay-token"),
				)
				if err != nil {
					t.Fatalf("newFullInventoryCheckpoint(changed) error = %v", err)
				}
				request.Checkpoint.Clear()
				request.Checkpoint = changed
			},
			wantErr: errInventoryContinuity,
		},
		{
			name: "binding",
			mutate: func(
				_ *testing.T,
				_ *FullInventoryAttempt,
				_ *fakeInventoryClient,
				request *discoverysource.DiscoverRequest,
			) {
				request.SourceRevision++
			},
			wantErr: errInventoryRejected,
		},
		{
			name: "authority",
			mutate: func(
				_ *testing.T,
				attempt *FullInventoryAttempt,
				_ *fakeInventoryClient,
				_ *discoverysource.DiscoverRequest,
			) {
				attempt.state.mu.Lock()
				attempt.state.authority.rootDigest = strings.Repeat("0", 64)
				attempt.state.mu.Unlock()
			},
			wantErr: errInventoryIdentityDrift,
		},
		{
			name: "session",
			mutate: func(
				_ *testing.T,
				_ *FullInventoryAttempt,
				client *fakeInventoryClient,
				_ *discoverysource.DiscoverRequest,
			) {
				client.mu.Lock()
				client.closed = true
				client.mu.Unlock()
			},
			wantErr: errInventoryIdentityDrift,
		},
		{
			name: "token",
			mutate: func(
				_ *testing.T,
				attempt *FullInventoryAttempt,
				_ *fakeInventoryClient,
				_ *discoverysource.DiscoverRequest,
			) {
				attempt.state.mu.Lock()
				clear(attempt.state.pageToken)
				clear(attempt.state.checkpointToken)
				attempt.state.pageToken = nil
				attempt.state.checkpointToken = nil
				attempt.state.mu.Unlock()
			},
			wantErr: errInventoryContinuity,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := newFakeInventoryClient(testInstanceUUID)
			client.initial[testAuthorityRoot] = types.RetrieveResult{
				Objects: []types.ObjectContent{
					inventoryFolderContent("group-a", "folder-a"),
				},
				Token: "replay-drift-token",
			}
			provider, attempt, runtime, request := newInventoryProviderFixture(
				t,
				client,
				[]types.ManagedObjectReference{testAuthorityRoot},
			)
			t.Cleanup(attempt.Destroy)
			first := discoverInventoryPage(t, provider, runtime, request)
			first.NextCheckpoint.Clear()
			test.mutate(t, attempt, client, &request)
			outcome, err := provider.Discover(context.Background(), runtime, request)
			if outcome != nil || !errors.Is(err, test.wantErr) {
				t.Fatalf("Discover(replay %s drift) = (%#v,%v)", test.name, outcome, err)
			}
			if got := client.methodSnapshot(); !slices.Equal(
				got,
				[]string{"RetrievePropertiesEx"},
			) {
				t.Fatalf("replay %s drift made SOAP calls: %v", test.name, got)
			}
			request.Checkpoint.Clear()
		})
	}
}

func TestInventoryMultipleRootsHaveDeterministicItemAndRelationOrdering(t *testing.T) {
	t.Parallel()

	rootA := types.ManagedObjectReference{Type: "Folder", Value: "group-a"}
	rootB := types.ManagedObjectReference{Type: "Folder", Value: "group-b"}
	childA := types.ManagedObjectReference{Type: "Folder", Value: "group-a-child"}
	childB := types.ManagedObjectReference{Type: "Folder", Value: "group-b-child"}
	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[rootA] = types.RetrieveResult{Objects: []types.ObjectContent{
		inventoryFolderContent(childA.Value, "z-child"),
		inventoryFolderContent(rootA.Value, "a-root", childA),
	}}
	client.initial[rootB] = types.RetrieveResult{Objects: []types.ObjectContent{
		inventoryFolderContent(childB.Value, "z-child"),
		inventoryFolderContent(rootB.Value, "a-root", childB),
	}}

	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{rootB, rootA},
	)
	t.Cleanup(attempt.Destroy)

	pageCount := 0
	itemCount := 0
	relationCount := 0
	for {
		page := discoverInventoryPage(t, provider, runtime, request)
		pageCount++
		itemCount += len(page.Items)
		relationCount += len(page.Relations)
		assertInventoryItemsSorted(t, page.Items)
		assertInventoryRelationsSorted(t, page.Relations)
		if !page.FinalPage {
			opened, empty, err := openFullInventoryCheckpoint(page.NextCheckpoint)
			if err != nil || empty || opened.pageTokenHash == "" {
				t.Fatalf(
					"non-final checkpoint = (%#v,%t,%v), want live attempt capability",
					opened,
					empty,
					err,
				)
			}
		}
		request.Checkpoint.Clear()
		request.Checkpoint = page.NextCheckpoint.Clone()
		final := page.FinalPage
		complete := page.CompleteSnapshot
		page.NextCheckpoint.Clear()
		if final {
			if !complete {
				t.Fatal("final multi-root page was not a complete snapshot")
			}
			break
		}
	}
	if pageCount != 4 || itemCount != 4 || relationCount != 2 {
		t.Fatalf(
			"multi-root inventory = pages:%d items:%d relations:%d",
			pageCount,
			itemCount,
			relationCount,
		)
	}
	if got := client.rootSnapshot(); !slices.Equal(got, []types.ManagedObjectReference{rootA, rootB}) {
		t.Fatalf("root call order = %v, want canonical %v", got, []types.ManagedObjectReference{rootA, rootB})
	}
	request.Checkpoint.Clear()
}

func TestInventoryRelationsFollowCommittedEndpointItemsAcrossSmallPages(t *testing.T) {
	t.Parallel()

	child := types.ManagedObjectReference{Type: "Folder", Value: "group-child"}
	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{Objects: []types.ObjectContent{
		inventoryFolderContent(child.Value, "child"),
		inventoryFolderContent(testAuthorityRoot.Value, "authority-root", child),
	}}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	request.Limits.MaxPageItems = 1

	emitted := make(map[string]struct{})
	pageCount := 0
	relationCount := 0
	for {
		page := discoverInventoryPage(t, provider, runtime, request)
		pageCount++
		current := make(map[string]struct{}, len(page.Items))
		for _, item := range page.Items {
			current[item.ExternalID] = struct{}{}
		}
		for _, relation := range page.Relations {
			relationCount++
			for _, endpoint := range []string{
				relation.FromExternalID,
				relation.ToExternalID,
			} {
				if _, alreadyCommitted := emitted[endpoint]; alreadyCommitted {
					continue
				}
				if _, inCurrentPage := current[endpoint]; !inCurrentPage {
					t.Fatalf(
						"page %d emitted relation before endpoint %q",
						pageCount,
						endpoint,
					)
				}
			}
		}
		for externalID := range current {
			emitted[externalID] = struct{}{}
		}
		request.Checkpoint.Clear()
		request.Checkpoint = page.NextCheckpoint.Clone()
		final := page.FinalPage
		page.NextCheckpoint.Clear()
		if final {
			break
		}
	}
	if pageCount != 3 || len(emitted) != 2 || relationCount != 1 {
		t.Fatalf(
			"small-page inventory = pages:%d items:%d relations:%d",
			pageCount,
			len(emitted),
			relationCount,
		)
	}
	request.Checkpoint.Clear()
}

func TestInventoryContinuationRejectsWrongOrClosedAttemptBeforeSOAP(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-a", "folder-a")},
		Token:   "attempt-bound-token-canary",
	}
	client.continuations["attempt-bound-token-canary"] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-b", "folder-b")},
	}
	provider, firstAttempt, firstRuntime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(firstAttempt.Destroy)
	first := discoverInventoryPage(t, provider, firstRuntime, request)
	request.Checkpoint.Clear()
	request.Checkpoint = first.NextCheckpoint.Clone()
	first.NextCheckpoint.Clear()

	foreignClient := newFakeInventoryClient(testInstanceUUID)
	foreignProvider, foreignAttempt, foreignRuntime, foreignRequest := newInventoryProviderFixture(
		t,
		foreignClient,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(foreignAttempt.Destroy)
	foreignRequest.Checkpoint.Clear()
	foreignRequest.Checkpoint = request.Checkpoint.Clone()
	outcome, err := foreignProvider.Discover(context.Background(), foreignRuntime, foreignRequest)
	if outcome != nil || !errors.Is(err, errInventoryContinuity) {
		t.Fatalf("foreign continuation = (%#v,%v), want continuity rejection", outcome, err)
	}
	if got := foreignClient.methodSnapshot(); len(got) != 0 {
		t.Fatalf("foreign runtime made SOAP calls: %v", got)
	}

	if err := firstAttempt.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	outcome, err = provider.Discover(context.Background(), firstRuntime, request)
	if outcome != nil || err == nil {
		t.Fatalf("closed continuation = (%#v,%v), want rejection", outcome, err)
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{"RetrievePropertiesEx"}) {
		t.Fatalf("closed attempt consumed token: %v", got)
	}
	request.Checkpoint.Clear()
	foreignRequest.Checkpoint.Clear()
}

func TestInventoryPartialRootDLPAndSchemaRejectionsNeverComplete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content types.ObjectContent
	}{
		{
			name: "missing property",
			content: types.ObjectContent{
				Obj: types.ManagedObjectReference{Type: "Folder", Value: "group-missing"},
				MissingSet: []types.MissingProperty{{
					Path: "name",
				}},
			},
		},
		{
			name:    "dlp",
			content: inventoryFolderContent("group-dlp", "bearer token-value"),
		},
		{
			name: "schema",
			content: types.ObjectContent{
				Obj: types.ManagedObjectReference{Type: "Folder", Value: "group-schema"},
				PropSet: []types.DynamicProperty{
					{Name: "name", Val: "folder-schema"},
					{Name: "annotation", Val: "not-allow-listed"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeInventoryClient(testInstanceUUID)
			client.initial[testAuthorityRoot] = types.RetrieveResult{
				Objects: []types.ObjectContent{test.content},
			}
			provider, attempt, runtime, request := newInventoryProviderFixture(
				t,
				client,
				[]types.ManagedObjectReference{testAuthorityRoot},
			)
			t.Cleanup(attempt.Destroy)
			outcome, err := provider.Discover(context.Background(), runtime, request)
			if outcome != nil || err == nil {
				t.Fatalf("Discover(partial) = (%#v,%v), want closed rejection", outcome, err)
			}
			request.Checkpoint.Clear()
		})
	}
}

func TestInventoryMissingConfiguredRootNeverCompletes(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-child-only", "child-only"),
		},
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	outcome, err := provider.Discover(context.Background(), runtime, request)
	if outcome != nil || err == nil {
		t.Fatalf("Discover(missing configured root) = (%#v,%v), want closed rejection", outcome, err)
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{"RetrievePropertiesEx"}) {
		t.Fatalf("missing-root rejection SOAP methods = %v", got)
	}
	request.Checkpoint.Clear()
}

func TestInventoryInstanceUUIDDriftStopsBeforeContinuation(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-a", "folder-a")},
		Token:   "identity-drift-token-canary",
	}
	client.continuations["identity-drift-token-canary"] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-b", "folder-b")},
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	first := discoverInventoryPage(t, provider, runtime, request)
	request.Checkpoint.Clear()
	request.Checkpoint = first.NextCheckpoint.Clone()
	first.NextCheckpoint.Clear()

	client.mu.Lock()
	client.identity.InstanceUUID = otherInstanceUUID
	client.mu.Unlock()
	outcome, err := provider.Discover(context.Background(), runtime, request)
	if outcome != nil || !errors.Is(err, errInventoryIdentityDrift) {
		t.Fatalf("Discover(identity drift) = (%#v,%v), want identity drift", outcome, err)
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{"RetrievePropertiesEx"}) {
		t.Fatalf("identity drift consumed token: %v", got)
	}
	request.Checkpoint.Clear()
}

func TestInventoryCollectorDriftStopsBeforeContinuation(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-a", "folder-a")},
		Token:   "collector-drift-token-canary",
	}
	client.continuations["collector-drift-token-canary"] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-b", "folder-b")},
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	first := discoverInventoryPage(t, provider, runtime, request)
	request.Checkpoint.Clear()
	request.Checkpoint = first.NextCheckpoint.Clone()
	first.NextCheckpoint.Clear()

	client.mu.Lock()
	client.collector.Value = "foreign-property-collector"
	client.mu.Unlock()
	outcome, err := provider.Discover(context.Background(), runtime, request)
	if outcome != nil || !errors.Is(err, errInventoryIdentityDrift) {
		t.Fatalf("Discover(collector drift) = (%#v,%v), want identity drift", outcome, err)
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{"RetrievePropertiesEx"}) {
		t.Fatalf("collector drift consumed token: %v", got)
	}
	request.Checkpoint.Clear()
}

func TestInventoryLiveTokenLossRejectsCheckpointBeforeSOAP(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-a", "folder-a")},
		Token:   "lost-live-token-canary",
	}
	client.continuations["lost-live-token-canary"] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-b", "folder-b")},
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	first := discoverInventoryPage(t, provider, runtime, request)
	request.Checkpoint.Clear()
	request.Checkpoint = first.NextCheckpoint.Clone()
	first.NextCheckpoint.Clear()

	attempt.state.mu.Lock()
	clear(attempt.state.pageToken)
	attempt.state.pageToken = nil
	attempt.state.mu.Unlock()
	outcome, err := provider.Discover(context.Background(), runtime, request)
	if outcome != nil || !errors.Is(err, errInventoryContinuity) {
		t.Fatalf("Discover(token loss) = (%#v,%v), want continuity rejection", outcome, err)
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{"RetrievePropertiesEx"}) {
		t.Fatalf("token loss made another SOAP call: %v", got)
	}
	request.Checkpoint.Clear()
}

func TestInventoryUngovernedRolloverSuccessorFailsClosedAfterRevoke(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-ungoverned", "partial-object"),
		},
		Token: "ungoverned-rollover-token-canary",
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	partial := discoverInventoryPage(t, provider, runtime, request)
	if partial.FinalPage || partial.CompleteSnapshot {
		t.Fatalf("ungoverned predecessor closed snapshot: %#v", partial)
	}
	seed := partial.NextCheckpoint.Clone()
	partial.NextCheckpoint.Clear()
	request.Checkpoint.Clear()
	if err := attempt.Revoke(context.Background()); err != nil {
		seed.Clear()
		t.Fatalf("Revoke() error = %v", err)
	}

	material := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	successor, successorErr := attempt.NewRolloverSuccessor(&material, seed)
	if successor != nil {
		successor.Destroy()
	}
	if successor != nil || !errors.Is(successorErr, errInventoryContinuity) {
		seed.Clear()
		t.Fatalf(
			"NewRolloverSuccessor(ungoverned) = (%#v,%v)",
			successor,
			successorErr,
		)
	}
	if material.valid() {
		seed.Clear()
		t.Fatal("ungoverned successor retained runtime material")
	}
	if got := client.methodSnapshot(); !slices.Equal(
		got,
		[]string{"RetrievePropertiesEx"},
	) {
		seed.Clear()
		t.Fatalf("ungoverned successor made additional SOAP calls: %v", got)
	}
	seed.Clear()
}

func TestInventoryCallerCancellationWinsOverContinuityAndStopsSOAP(t *testing.T) {
	t.Run("before first SOAP call", func(t *testing.T) {
		client := newFakeInventoryClient(testInstanceUUID)
		client.initial[testAuthorityRoot] = types.RetrieveResult{
			Objects: []types.ObjectContent{
				inventoryFolderContent(testAuthorityRoot.Value, "authority-root"),
			},
		}
		provider, attempt, runtime, request := newInventoryProviderFixture(
			t,
			client,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		t.Cleanup(attempt.Destroy)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		outcome, err := provider.Discover(ctx, runtime, request)
		if outcome != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Discover(pre-canceled) = (%#v,%v), want context cancellation", outcome, err)
		}
		if got := client.methodSnapshot(); len(got) != 0 {
			t.Fatalf("pre-canceled discovery made SOAP calls: %v", got)
		}
		request.Checkpoint.Clear()
	})

	t.Run("during continuation", func(t *testing.T) {
		client := newFakeInventoryClient(testInstanceUUID)
		client.initial[testAuthorityRoot] = types.RetrieveResult{
			Objects: []types.ObjectContent{
				inventoryFolderContent("group-a", "folder-a"),
			},
			Token: "cancel-continuation-token-canary",
		}
		client.continuations["cancel-continuation-token-canary"] = types.RetrieveResult{
			Objects: []types.ObjectContent{
				inventoryFolderContent(testAuthorityRoot.Value, "authority-root"),
			},
		}
		client.continueStarted = make(chan struct{})
		client.continueRelease = make(chan struct{})
		provider, attempt, runtime, request := newInventoryProviderFixture(
			t,
			client,
			[]types.ManagedObjectReference{testAuthorityRoot},
		)
		t.Cleanup(attempt.Destroy)
		first := discoverInventoryPage(t, provider, runtime, request)
		request.Checkpoint.Clear()
		request.Checkpoint = first.NextCheckpoint.Clone()
		first.NextCheckpoint.Clear()

		ctx, cancel := context.WithCancel(context.Background())
		type discoverResult struct {
			outcome discoverysource.DiscoverOutcome
			err     error
		}
		done := make(chan discoverResult, 1)
		go func() {
			outcome, err := provider.Discover(ctx, runtime, request)
			done <- discoverResult{outcome: outcome, err: err}
		}()
		select {
		case <-client.continueStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("continuation did not start")
		}
		cancel()
		select {
		case result := <-done:
			if result.outcome != nil || !errors.Is(result.err, context.Canceled) {
				t.Fatalf(
					"Discover(canceled continuation) = (%#v,%v), want context cancellation",
					result.outcome,
					result.err,
				)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("canceled continuation did not return")
		}
		outcome, err := provider.Discover(context.Background(), runtime, request)
		if outcome != nil || !errors.Is(err, errInventoryContinuity) {
			t.Fatalf("Discover(after canceled continuation) = (%#v,%v)", outcome, err)
		}
		if got := client.methodSnapshot(); !slices.Equal(got, []string{
			"RetrievePropertiesEx",
			"ContinueRetrievePropertiesEx",
		}) {
			t.Fatalf("canceled attempt resumed SOAP: %v", got)
		}
		request.Checkpoint.Clear()
	})
}

func TestInventoryConcurrentRuntimeClearAndDestroyCannotResume(t *testing.T) {
	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-a", "folder-a")},
		Token:   "concurrent-clear-token-canary",
	}
	client.continuations["concurrent-clear-token-canary"] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-b", "folder-b"),
			inventoryFolderContent(testAuthorityRoot.Value, "authority-root"),
		},
	}
	client.continueStarted = make(chan struct{})
	client.continueRelease = make(chan struct{})
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	first := discoverInventoryPage(t, provider, runtime, request)
	request.Checkpoint.Clear()
	request.Checkpoint = first.NextCheckpoint.Clone()
	first.NextCheckpoint.Clear()

	type discoverResult struct {
		outcome discoverysource.DiscoverOutcome
		err     error
	}
	discoverDone := make(chan discoverResult, 1)
	go func() {
		outcome, err := provider.Discover(context.Background(), runtime, request)
		discoverDone <- discoverResult{outcome: outcome, err: err}
	}()
	select {
	case <-client.continueStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("continuation did not reach the live same-attempt client")
	}

	type bindResult struct {
		runtime discoverysource.BoundRuntime
		err     error
	}
	bindDone := make(chan bindResult, 1)
	go func() {
		rebound, err := attempt.BindRuntime(
			context.Background(),
			publishedInventoryBinding(request),
		)
		bindDone <- bindResult{runtime: rebound, err: err}
	}()
	revokeContext, cancelRevoke := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRevoke()
	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- attempt.Revoke(revokeContext)
	}()
	destroyStarted := make(chan struct{})
	destroyDone := make(chan struct{})
	go func() {
		close(destroyStarted)
		attempt.Destroy()
		close(destroyDone)
	}()
	<-destroyStarted
	time.Sleep(10 * time.Millisecond)
	close(client.continueRelease)

	var completed discoverResult
	select {
	case completed = <-discoverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Discover deadlocked with runtime clear/destroy")
	}
	page, ok := completed.outcome.(discoverysource.Page)
	if completed.err != nil || !ok || !page.FinalPage || !page.CompleteSnapshot {
		t.Fatalf("in-flight Discover() = (%#v,%v), want exact final page", completed.outcome, completed.err)
	}
	page.NextCheckpoint.Clear()
	select {
	case err := <-revokeDone:
		if err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Revoke deadlocked with runtime clear/destroy")
	}
	select {
	case <-destroyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Destroy deadlocked with runtime clear/revoke")
	}
	select {
	case rebound := <-bindDone:
		if rebound.err != nil &&
			!errors.Is(rebound.err, errInventoryContinuity) &&
			!errors.Is(rebound.err, errInventoryRejected) {
			t.Fatalf("concurrent BindRuntime() error = %v", rebound.err)
		}
		rebound.runtime.Clear()
	case <-time.After(2 * time.Second):
		t.Fatal("BindRuntime deadlocked with Discover/Revoke")
	}

	outcome, err := provider.Discover(context.Background(), runtime, request)
	if outcome != nil || err == nil {
		t.Fatalf("Discover(after destroy) = (%#v,%v), want closed runtime", outcome, err)
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{
		"RetrievePropertiesEx",
		"ContinueRetrievePropertiesEx",
	}) {
		t.Fatalf("destroyed runtime resumed SOAP: %v", got)
	}
	client.mu.Lock()
	closeCalls := client.closeCalls
	client.mu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("concurrent Revoke/Destroy closed client %d times, want exactly once", closeCalls)
	}
	request.Checkpoint.Clear()
}

func TestInventoryDestroyTerminalIntentPreventsSuccessorResurrection(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-a", "folder-a"),
		},
		Token: "destroy-terminal-intent-token-canary",
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	partial := discoverInventoryPage(t, provider, runtime, request)
	seed := partial.NextCheckpoint.Clone()
	partial.NextCheckpoint.Clear()
	request.Checkpoint.Clear()
	request.Checkpoint = seed.Clone()
	binding := publishedInventoryBinding(request)

	afterRevoke := make(chan struct{})
	releaseDestroy := make(chan struct{})
	destroyDone := make(chan struct{})
	go func() {
		attempt.destroyWithBarrier(func() {
			close(afterRevoke)
			<-releaseDestroy
		})
		close(destroyDone)
	}()
	select {
	case <-afterRevoke:
	case <-time.After(2 * time.Second):
		t.Fatal("Destroy did not reach the post-revoke transition")
	}

	material := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	successor, successorErr := attempt.NewRolloverSuccessor(&material, seed)
	rebound, bindErr := attempt.BindRuntime(context.Background(), binding)
	outcome, discoverErr := provider.Discover(
		context.Background(),
		runtime,
		request,
	)
	close(releaseDestroy)
	select {
	case <-destroyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Destroy did not finish after transition release")
	}
	attempt.state.mu.Lock()
	replayActive := attempt.state.replay.active
	replayFacts := len(attempt.state.replay.page.Items) +
		len(attempt.state.replay.page.Relations)
	replayProfile := attempt.state.replay.page.NextCheckpoint.ProfileCode()
	attempt.state.mu.Unlock()
	if successor != nil {
		successor.Destroy()
	}

	if successor != nil || !errors.Is(successorErr, errInventoryContinuity) {
		t.Fatalf(
			"NewRolloverSuccessor(after terminal intent) = (%#v,%v)",
			successor,
			successorErr,
		)
	}
	if rebound != (discoverysource.BoundRuntime{}) || bindErr == nil {
		t.Fatalf("BindRuntime(after terminal intent) = (%#v,%v)", rebound, bindErr)
	}
	if outcome != nil || discoverErr == nil {
		t.Fatalf("Discover(after terminal intent) = (%#v,%v)", outcome, discoverErr)
	}
	if replayActive || replayFacts != 0 || replayProfile != "" {
		t.Fatalf(
			"Destroy retained replay cell: active:%t facts:%d profile:%q",
			replayActive,
			replayFacts,
			replayProfile,
		)
	}
	if got := client.methodSnapshot(); !slices.Equal(
		got,
		[]string{"RetrievePropertiesEx"},
	) {
		t.Fatalf("terminal Destroy resumed SOAP: %v", got)
	}
	client.mu.Lock()
	closed := client.closed
	closeCalls := client.closeCalls
	client.mu.Unlock()
	if !closed || closeCalls != 1 {
		t.Fatalf(
			"terminal Destroy client state = closed:%t close-calls:%d",
			closed,
			closeCalls,
		)
	}
	attempt.Destroy()
	client.mu.Lock()
	closeCalls = client.closeCalls
	client.mu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("Destroy response-loss replay closed client %d times", closeCalls)
	}
	request.Checkpoint.Clear()
	seed.Clear()
}

func TestInventoryTask28BRuntimeClearRevokesLiveAttemptSession(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("group-a", "folder-a"),
		},
		Token: "task28b-runtime-clear-token-canary",
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	page := discoverInventoryPage(t, provider, runtime, request)
	page.NextCheckpoint.Clear()
	request.Checkpoint.Clear()

	attempt.state.mu.Lock()
	replayActiveBefore := attempt.state.replay.active
	attempt.state.mu.Unlock()
	if !replayActiveBefore {
		t.Fatal("live attempt did not retain its last replay page")
	}
	runtime.Clear()
	client.mu.Lock()
	closed := client.closed
	closeCalls := client.closeCalls
	client.mu.Unlock()
	attempt.state.mu.Lock()
	liveTokenBytes := len(attempt.state.pageToken) + len(attempt.state.checkpointToken)
	replayActive := attempt.state.replay.active
	replayFacts := len(attempt.state.replay.page.Items) +
		len(attempt.state.replay.page.Relations)
	replayProfile := attempt.state.replay.page.NextCheckpoint.ProfileCode()
	attempt.state.mu.Unlock()
	if !closed || closeCalls != 1 || liveTokenBytes != 0 ||
		replayActive || replayFacts != 0 || replayProfile != "" {
		t.Fatalf(
			"Task28B runtime clear = closed:%t close-calls:%d live-token-bytes:%d replay:%t/%d/%q",
			closed,
			closeCalls,
			liveTokenBytes,
			replayActive,
			replayFacts,
			replayProfile,
		)
	}
	if err := attempt.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke(after Task28B runtime clear) error = %v", err)
	}
	client.mu.Lock()
	closeCalls = client.closeCalls
	client.mu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("Task28B runtime clear replay closed client %d times", closeCalls)
	}
}

func TestInventoryRevokeFailureReplayStaysSafeAndStable(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent(testAuthorityRoot.Value, "authority-root"),
		},
	}
	client.closeErr = errors.New(
		"logout failed for https://vcenter.example.invalid/sdk session-token-canary",
	)
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	page := discoverInventoryPage(t, provider, runtime, request)
	page.NextCheckpoint.Clear()
	request.Checkpoint.Clear()

	for call := 1; call <= 2; call++ {
		err := attempt.Revoke(context.Background())
		if !errors.Is(err, errInventoryRejected) ||
			err.Error() != errInventoryRejected.Error() {
			t.Fatalf("Revoke(call %d) error = %v, want stable safe rejection", call, err)
		}
		for _, forbidden := range []string{
			"vcenter.example.invalid",
			"session-token-canary",
			"https://",
		} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("Revoke(call %d) leaked %q: %v", call, forbidden, err)
			}
		}
	}
	attempt.Destroy()
}

func TestInventoryAttemptCheckpointAndTokenCloseSensitiveSurfaces(t *testing.T) {
	t.Parallel()

	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: []types.ObjectContent{inventoryFolderContent("group-a", "folder-a")},
		Token:   "serialization-token-canary",
	}
	provider, attempt, runtime, request := newInventoryProviderFixture(
		t,
		client,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	t.Cleanup(attempt.Destroy)
	page := discoverInventoryPage(t, provider, runtime, request)

	sealed, empty, err := openFullInventoryCheckpoint(page.NextCheckpoint)
	if err != nil || empty {
		t.Fatalf("openFullInventoryCheckpoint() = (%#v,%t,%v)", sealed, empty, err)
	}
	for _, value := range []any{attempt, *attempt, runtime, page.NextCheckpoint, sealed} {
		if _, err := json.Marshal(value); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
			t.Fatalf("json.Marshal(%T) error = %v", value, err)
		}
		if marshaler, ok := value.(encoding.TextMarshaler); ok {
			if _, err := marshaler.MarshalText(); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
				t.Fatalf("MarshalText(%T) error = %v", value, err)
			}
		}
		rendered := strings.Join([]string{
			fmt.Sprint(value),
			fmt.Sprintf("%v", value),
			fmt.Sprintf("%+v", value),
			fmt.Sprintf("%#v", value),
			slog.Any("value", value).Value.String(),
		}, "\n")
		for _, forbidden := range []string{
			"serialization-token-canary",
			testInstanceUUID,
			"PropertyCollector",
			"session",
		} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("%T formatting leaked %q: %s", value, forbidden, rendered)
			}
		}
	}
	assertCheckpointExcludes(t, page.NextCheckpoint, "serialization-token-canary")
	if err := discoverysource.WithCheckpointBytes(
		page.NextCheckpoint,
		profileCode,
		func(canonical []byte) error {
			var document map[string]string
			if err := json.Unmarshal(canonical, &document); err != nil {
				return err
			}
			wantKeys := []string{
				"collector_version",
				"full_snapshot_id",
				"instance_uuid",
				"mode",
				"page_token_hash",
			}
			gotKeys := make([]string, 0, len(document))
			for key := range document {
				gotKeys = append(gotKeys, key)
			}
			slices.Sort(gotKeys)
			if !slices.Equal(gotKeys, wantKeys) ||
				!lowercaseDigestPattern.MatchString(document["page_token_hash"]) {
				t.Fatalf("sealed checkpoint shape = keys:%v token-hash-valid:%t",
					gotKeys, lowercaseDigestPattern.MatchString(document["page_token_hash"]))
			}
			return nil
		},
	); err != nil {
		t.Fatalf("WithCheckpointBytes() error = %v", err)
	}
	page.NextCheckpoint.Clear()
	request.Checkpoint.Clear()
}

func TestFullInventoryCheckpointRejectsNonCanonicalOrExpandedDocuments(t *testing.T) {
	t.Parallel()

	valid := `{"instance_uuid":"55555555-5555-4555-8555-555555555555","mode":"FULL","collector_version":"1","full_snapshot_id":"77777777-7777-4777-8777-777777777777","page_token_hash":""}`
	tests := map[string]string{
		"unknown field":  strings.TrimSuffix(valid, "}") + `,"raw_token":"forbidden"}`,
		"trailing value": valid + `{}`,
		"noncanonical sequence": strings.Replace(
			valid,
			`"collector_version":"1"`,
			`"collector_version":"01"`,
			1,
		),
		"noncanonical bytes": strings.Replace(valid, `,"mode"`, `, "mode"`, 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			checkpoint, err := discoverysource.NewCheckpoint(profileCode, []byte(raw))
			if err != nil {
				t.Fatalf("NewCheckpoint() error = %v", err)
			}
			defer checkpoint.Clear()
			if _, _, err := openFullInventoryCheckpoint(checkpoint); err == nil {
				t.Fatal("openFullInventoryCheckpoint() accepted invalid document")
			}
		})
	}
}

func TestInventoryTask28AWorkerUsesOneAttemptForRetrieveAndContinuation(t *testing.T) {
	firstObjects := make([]types.ObjectContent, 0, 500)
	for index := 0; index < 500; index++ {
		firstObjects = append(firstObjects, inventoryFolderContent(
			fmt.Sprintf("worker-group-%04d", index),
			fmt.Sprintf("worker-folder-%04d", index),
		))
	}
	client := newFakeInventoryClient(testInstanceUUID)
	client.initial[testAuthorityRoot] = types.RetrieveResult{
		Objects: firstObjects,
		Token:   "task28a-worker-token-canary",
	}
	client.continuations["task28a-worker-token-canary"] = types.RetrieveResult{
		Objects: []types.ObjectContent{
			inventoryFolderContent("worker-group-0500", "worker-folder-0500"),
			inventoryFolderContent("worker-group-0501", "worker-folder-0501"),
			inventoryFolderContent(testAuthorityRoot.Value, "authority-root"),
		},
	}

	request := validInventoryRequest(t)
	binding := publishedInventoryBinding(request)
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	factory.openClient = func(context.Context, resolvedRuntime) (validationClient, error) {
		return client, nil
	}
	provider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	material := inventoryRuntimeMaterial(
		t,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	authority := &inventoryWorkerAuthority{
		material: &material,
		provider: provider,
		limits:   request.Limits,
		policy:   inventoryFactPolicy(testEnvironmentID),
		proofKey: []byte("task28a-vsphere-cleanup-proof-key"),
	}
	broker, err := discoverycleanup.NewCleanupBroker(authority, authority)
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)

	var checkpointKey [32]byte
	for index := range checkpointKey {
		checkpointKey[index] = byte(index + 1)
	}
	keyring, err := discoverycheckpoint.NewInMemoryKeyring(
		"task21a-worker-key",
		map[string][32]byte{"task21a-worker-key": checkpointKey},
	)
	if err != nil {
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	t.Cleanup(keyring.Destroy)
	codec, err := discoverycheckpoint.NewCheckpointCodec(keyring)
	if err != nil {
		t.Fatalf("NewCheckpointCodec() error = %v", err)
	}

	const (
		runID     = "8a100000-0000-4000-8000-000000000001"
		attemptID = "8a100000-0000-4000-8000-000000000002"
		owner     = "task21a-vsphere-worker"
	)
	var rawFence [32]byte
	for index := range rawFence {
		rawFence[index] = byte(index + 33)
	}
	fence, err := leasefence.FromQueueClaim(runID, owner, 1, &rawFence)
	if err != nil {
		t.Fatalf("FromQueueClaim() error = %v", err)
	}
	expires := time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond)
	run := assetcatalog.SourceRun{
		ID:                      runID,
		SourceID:                testSourceID,
		Scope:                   request.Locator.Scope,
		SourceRevision:          request.SourceRevision,
		SourceRevisionDigest:    request.SourceRevisionDigest,
		Kind:                    assetcatalog.RunKindDiscovery,
		Status:                  assetcatalog.RunStatusRunning,
		Stage:                   assetcatalog.RunStageReading,
		FenceEpoch:              1,
		HeartbeatSequence:       1,
		LeaseExpiresAt:          &expires,
		CheckpointVersion:       0,
		CredentialCleanupStatus: assetcatalog.CredentialCleanupNotOpened,
	}
	queue := &inventoryWorkerQueue{
		run: run,
		claim: &discoveryqueue.ClaimResult{
			Run:          run,
			ProviderKind: providerKind,
			ProfileCode:  profileCode,
			Mode:         discoveryqueue.ClaimModeProvider,
			Fence:        fence,
		},
		attempt: discoveryqueue.CleanupAttempt{
			RunID: runID, AttemptID: attemptID, AttemptEpoch: 1,
		},
	}
	committer := &inventoryWorkerPageCommitter{queue: queue}
	limiter := &inventoryWorkerLimiter{}
	worker, err := discoveryworker.New(discoveryworker.Dependencies{
		Queue:                queue,
		CleanupBroker:        broker,
		Limiter:              limiter,
		PageCommitter:        committer,
		Checkpoints:          codec,
		ClaimRuntimeResolver: authority,
		ClaimCommand: discoveryqueue.ClaimCommand{
			Owner:         owner,
			LeaseDuration: 5 * time.Second,
			ProviderKinds: []string{providerKind},
		},
	})
	if err != nil {
		t.Fatalf("discoveryworker.New() error = %v", err)
	}
	runContext, cancel := context.WithCancel(context.Background())
	queue.cancel = cancel
	runErr := worker.Run(runContext)
	cancel()
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Worker.Run() error = %v, want context cancellation after completion", runErr)
	}

	if authority.openCalls != 1 || authority.resolveCalls != 1 ||
		committer.calls != 2 || queue.completeCalls != 1 ||
		limiter.acquireCalls != 2 || limiter.releaseCalls != 2 {
		t.Fatalf(
			"Task28A calls open:%d resolve:%d pages:%d complete:%d acquire/release:%d/%d",
			authority.openCalls,
			authority.resolveCalls,
			committer.calls,
			queue.completeCalls,
			limiter.acquireCalls,
			limiter.releaseCalls,
		)
	}
	if got := committer.snapshot(); !slices.Equal(got, []inventoryWorkerPageShape{
		{Items: 500},
		{Items: 3, Final: true, Complete: true},
	}) {
		t.Fatalf("Task28A committed pages = %#v", got)
	}
	if got := client.methodSnapshot(); !slices.Equal(got, []string{
		"RetrievePropertiesEx",
		"ContinueRetrievePropertiesEx",
	}) {
		t.Fatalf("Task28A SOAP methods = %v", got)
	}
	client.mu.Lock()
	closed := client.closed
	client.mu.Unlock()
	if !closed {
		t.Fatal("Task28A completed without revoking the exact vSphere session")
	}
}

func discoverInventoryPage(
	t *testing.T,
	provider discoverysource.Provider,
	runtime discoverysource.BoundRuntime,
	request discoverysource.DiscoverRequest,
) discoverysource.Page {
	t.Helper()
	outcome, err := provider.Discover(context.Background(), runtime, request)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	page, ok := outcome.(discoverysource.Page)
	if !ok {
		t.Fatalf("Discover() outcome = %T, want Page", outcome)
	}
	if err := discoverysource.ValidateDiscoverResult(
		request,
		inventoryFactPolicy(testEnvironmentID),
		page,
		nil,
	); err != nil {
		t.Fatalf("Discover() page violates contract: %v", err)
	}
	return page
}

func newInventoryProviderFixture(
	t *testing.T,
	client *fakeInventoryClient,
	roots []types.ManagedObjectReference,
) (
	discoverysource.Provider,
	*FullInventoryAttempt,
	discoverysource.BoundRuntime,
	discoverysource.DiscoverRequest,
) {
	t.Helper()
	request := validInventoryRequest(t)
	binding := publishedInventoryBinding(request)
	material := inventoryRuntimeMaterial(t, roots)
	attempt, err := NewFullInventoryAttempt(&material)
	if err != nil {
		t.Fatalf("NewFullInventoryAttempt() error = %v", err)
	}
	runtime, err := attempt.BindRuntime(context.Background(), binding)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	factory.openClient = func(context.Context, resolvedRuntime) (validationClient, error) {
		return client, nil
	}
	provider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return provider, attempt, runtime, request
}

func validInventoryRequest(t *testing.T) discoverysource.DiscoverRequest {
	t.Helper()
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	return discoverysource.DiscoverRequest{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID:    testTenantID,
				WorkspaceID: testWorkspaceID,
			},
			SourceID: testSourceID,
		},
		SourceRevision:       20,
		SourceRevisionDigest: testRevisionDigest,
		Checkpoint:           checkpoint,
		Limits: discoverysource.Limits{
			MaxPageItems:     500,
			MaxPageRelations: 2_000,
			MaxPageBytes:     8 << 20,
			MaxDocumentBytes: 64 << 10,
		},
	}
}

func publishedInventoryBinding(
	request discoverysource.DiscoverRequest,
) discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator:              request.Locator,
		SourceRevision:       request.SourceRevision,
		SourceRevisionDigest: request.SourceRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionPublished,
		ProviderKind:         providerKind,
		ProfileCode:          profileCode,
	}
}

func inventoryRuntimeMaterial(
	t *testing.T,
	roots []types.ManagedObjectReference,
) RuntimeMaterial {
	t.Helper()
	endpoint, err := NewEndpointHandle("https://vcenter.example.invalid/sdk")
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle("svc-vsphere-read", []byte("test-password"))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(testTLSConfig(t), TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		testInstanceUUID,
		testEnvironmentID,
		roots,
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}
	return material
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    nonEmptyRootPool(t),
		ServerName: "vcenter.example.invalid",
	}
}

func inventoryFolderContent(
	value string,
	name string,
	children ...types.ManagedObjectReference,
) types.ObjectContent {
	properties := []types.DynamicProperty{{Name: "name", Val: name}}
	if children != nil {
		properties = append(properties, types.DynamicProperty{
			Name: "childEntity",
			Val:  slices.Clone(children),
		})
	}
	return types.ObjectContent{
		Obj:     types.ManagedObjectReference{Type: "Folder", Value: value},
		PropSet: properties,
	}
}

type inventoryPageEvidence struct {
	items            []byte
	relations        []byte
	nextCheckpoint   discoverysource.Checkpoint
	finalPage        bool
	completeSnapshot bool
}

func captureInventoryPageEvidence(
	t *testing.T,
	page discoverysource.Page,
) inventoryPageEvidence {
	t.Helper()
	items, err := json.Marshal(page.Items)
	if err != nil {
		t.Fatalf("json.Marshal(page items) error = %v", err)
	}
	relations, err := json.Marshal(page.Relations)
	if err != nil {
		clear(items)
		t.Fatalf("json.Marshal(page relations) error = %v", err)
	}
	return inventoryPageEvidence{
		items:            items,
		relations:        relations,
		nextCheckpoint:   page.NextCheckpoint.Clone(),
		finalPage:        page.FinalPage,
		completeSnapshot: page.CompleteSnapshot,
	}
}

func (evidence *inventoryPageEvidence) Clear() {
	if evidence == nil {
		return
	}
	clear(evidence.items)
	clear(evidence.relations)
	evidence.items = nil
	evidence.relations = nil
	evidence.nextCheckpoint.Clear()
	evidence.finalPage = false
	evidence.completeSnapshot = false
}

func assertInventoryPageEvidence(
	t *testing.T,
	page discoverysource.Page,
	want inventoryPageEvidence,
) {
	t.Helper()
	items, err := json.Marshal(page.Items)
	if err != nil {
		t.Fatalf("json.Marshal(replayed items) error = %v", err)
	}
	defer clear(items)
	relations, err := json.Marshal(page.Relations)
	if err != nil {
		t.Fatalf("json.Marshal(replayed relations) error = %v", err)
	}
	defer clear(relations)
	if !bytes.Equal(items, want.items) ||
		!bytes.Equal(relations, want.relations) ||
		!page.NextCheckpoint.Equal(want.nextCheckpoint) ||
		page.FinalPage != want.finalPage ||
		page.CompleteSnapshot != want.completeSnapshot {
		t.Fatalf(
			"replayed page drifted: items=%t relations=%t checkpoint=%t final=%t/%t complete=%t/%t",
			bytes.Equal(items, want.items),
			bytes.Equal(relations, want.relations),
			page.NextCheckpoint.Equal(want.nextCheckpoint),
			page.FinalPage,
			want.finalPage,
			page.CompleteSnapshot,
			want.completeSnapshot,
		)
	}
}

func mutateCallerInventoryPage(page *discoverysource.Page) {
	if page == nil {
		return
	}
	if len(page.Items) > 0 {
		page.Items[0].DisplayName = "caller-mutated"
		if len(page.Items[0].Document) > 0 {
			page.Items[0].Document[0] ^= 0xff
		}
		if len(page.Items[0].FieldProvenance) > 0 {
			page.Items[0].FieldProvenance[0].FieldCode = "CALLER_MUTATED"
		}
	}
	if len(page.Relations) > 0 {
		page.Relations[0].FromExternalID = "caller-mutated"
		page.Relations[0].Confidence = 1
	}
	page.FinalPage = !page.FinalPage
	page.CompleteSnapshot = !page.CompleteSnapshot
	page.NextCheckpoint.Clear()
}

func assertInventoryItemsSorted(
	t *testing.T,
	items []assetdiscovery.NormalizedItem,
) {
	t.Helper()
	if !slices.IsSortedFunc(items, compareNormalizedInventoryItems) {
		t.Fatalf("items are not sorted: %#v", items)
	}
}

func assertInventoryRelationsSorted(
	t *testing.T,
	relations []assetdiscovery.ObservedRelation,
) {
	t.Helper()
	if !slices.IsSortedFunc(relations, compareNormalizedInventoryRelations) {
		t.Fatalf("relations are not sorted: %#v", relations)
	}
}

func assertCheckpointExcludes(
	t *testing.T,
	checkpoint discoverysource.Checkpoint,
	forbidden string,
) {
	t.Helper()
	if err := discoverysource.WithCheckpointBytes(
		checkpoint,
		profileCode,
		func(canonical []byte) error {
			if bytes.Contains(canonical, []byte(forbidden)) {
				t.Fatalf("checkpoint leaked raw continuation token")
			}
			return nil
		},
	); err != nil {
		t.Fatalf("WithCheckpointBytes() error = %v", err)
	}
}

type fakeInventoryClient struct {
	mu            sync.Mutex
	identity      vcenterIdentity
	collector     types.ManagedObjectReference
	initial       map[types.ManagedObjectReference]types.RetrieveResult
	continuations map[string]types.RetrieveResult
	methods       []string
	roots         []types.ManagedObjectReference
	closed        bool
	closeCalls    int
	closeErr      error

	continueStarted chan struct{}
	continueRelease chan struct{}
	continueOnce    sync.Once
}

func newFakeInventoryClient(instanceUUID string) *fakeInventoryClient {
	return &fakeInventoryClient{
		identity: vcenterIdentity{
			InstanceUUID: instanceUUID,
			APIVersion:   "8.0.3",
			APIType:      "VirtualCenter",
		},
		collector: types.ManagedObjectReference{
			Type: "PropertyCollector", Value: "propertyCollector",
		},
		initial:       make(map[types.ManagedObjectReference]types.RetrieveResult),
		continuations: make(map[string]types.RetrieveResult),
	}
}

func (client *fakeInventoryClient) Identity() vcenterIdentity {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return vcenterIdentity{}
	}
	return client.identity
}

func (*fakeInventoryClient) TLSPeerDigest() string {
	return testTLSPeerDigest
}

func (*fakeInventoryClient) CurrentSession(context.Context) (sessionIdentity, error) {
	return sessionIdentity{UserName: "svc-vsphere-read"}, nil
}

func (*fakeInventoryClient) EffectivePrivileges(
	context.Context,
	[]types.ManagedObjectReference,
	string,
) ([]entityPrivilegeSnapshot, error) {
	return nil, nil
}

func (*fakeInventoryClient) ProbeRoots(
	context.Context,
	[]types.ManagedObjectReference,
) (rootProbeResult, error) {
	return rootProbeResult{}, nil
}

func (client *fakeInventoryClient) RetrieveInventoryPage(
	_ context.Context,
	root types.ManagedObjectReference,
	_ int32,
) (types.RetrieveResult, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return types.RetrieveResult{}, errors.New("closed")
	}
	client.methods = append(client.methods, "RetrievePropertiesEx")
	client.roots = append(client.roots, root)
	result, ok := client.initial[root]
	if !ok {
		return types.RetrieveResult{}, errors.New("unknown root")
	}
	return result, nil
}

func (client *fakeInventoryClient) ContinueInventoryPage(
	ctx context.Context,
	token string,
) (types.RetrieveResult, error) {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return types.RetrieveResult{}, errors.New("closed")
	}
	client.methods = append(client.methods, "ContinueRetrievePropertiesEx")
	result, ok := client.continuations[token]
	if !ok {
		client.mu.Unlock()
		return types.RetrieveResult{}, errors.New("unknown token")
	}
	delete(client.continuations, token)
	started := client.continueStarted
	release := client.continueRelease
	client.mu.Unlock()
	if started != nil {
		client.continueOnce.Do(func() { close(started) })
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return types.RetrieveResult{}, errInventoryContinuity
		}
	}
	return result, nil
}

func (client *fakeInventoryClient) CollectorReference() types.ManagedObjectReference {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.collector
}

func (client *fakeInventoryClient) Close(context.Context) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closeCalls++
	client.closed = true
	return client.closeErr
}

func (client *fakeInventoryClient) methodSnapshot() []string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return slices.Clone(client.methods)
}

func (client *fakeInventoryClient) rootSnapshot() []types.ManagedObjectReference {
	client.mu.Lock()
	defer client.mu.Unlock()
	return slices.Clone(client.roots)
}

type inventoryWorkerAuthority struct {
	mu sync.Mutex

	material *RuntimeMaterial
	provider discoverysource.Provider
	limits   discoverysource.Limits
	policy   assetdiscovery.FactPolicy
	proofKey []byte

	attempt      *FullInventoryAttempt
	openCalls    int
	resolveCalls int
}

func (authority *inventoryWorkerAuthority) OpenSession(
	ctx context.Context,
	_ discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.openCalls++
	if ctx == nil || ctx.Err() != nil || authority.material == nil ||
		authority.attempt != nil {
		return nil, errInventoryRejected
	}
	attempt, err := NewFullInventoryAttempt(authority.material)
	authority.material = nil
	if err != nil {
		return nil, err
	}
	authority.attempt = attempt
	return attempt, nil
}

func (authority *inventoryWorkerAuthority) ResolveOpenedAttempt(
	_ context.Context,
	request discoveryworker.ResolveOpenedAttemptRequest,
) (discoveryworker.ClaimRuntime, error) {
	authority.mu.Lock()
	authority.resolveCalls++
	provider := authority.provider
	limits := authority.limits
	policy := authority.policy
	authority.mu.Unlock()
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		return discoveryworker.ClaimRuntime{}, err
	}
	return request.NewClaimRuntime(provider, &checkpoint, limits, policy)
}

func (authority *inventoryWorkerAuthority) SignCleanupProof(
	ctx context.Context,
	digest []byte,
) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(digest) != sha256.Size {
		return nil, errInventoryRejected
	}
	authority.mu.Lock()
	key := bytes.Clone(authority.proofKey)
	authority.mu.Unlock()
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (authority *inventoryWorkerAuthority) VerifyCleanupProof(
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

type inventoryWorkerQueue struct {
	discoveryqueue.Queue
	mu sync.Mutex

	run           assetcatalog.SourceRun
	claim         *discoveryqueue.ClaimResult
	attempt       discoveryqueue.CleanupAttempt
	cancel        context.CancelFunc
	completeCalls int
}

func (queue *inventoryWorkerQueue) Claim(
	ctx context.Context,
	_ discoveryqueue.ClaimCommand,
) (discoveryqueue.ClaimResult, error) {
	if err := ctx.Err(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.claim == nil {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrNoWork
	}
	claim := *queue.claim
	queue.claim = nil
	return claim, nil
}

func (queue *inventoryWorkerQueue) Heartbeat(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	command discoveryqueue.HeartbeatCommand,
) (discoveryqueue.HeartbeatResult, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.run.HeartbeatSequence = command.Sequence
	expires := time.Now().UTC().Add(command.Extension).Truncate(time.Microsecond)
	queue.run.LeaseExpiresAt = &expires
	return discoveryqueue.HeartbeatResult{
		Run: queue.run.Clone(), LeaseExpiresAt: expires,
	}, nil
}

func (queue *inventoryWorkerQueue) AdvanceStage(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	command discoveryqueue.AdvanceStageCommand,
) (assetcatalog.SourceRun, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.run.Stage != command.From {
		return assetcatalog.SourceRun{}, discoveryqueue.ErrStateConflict
	}
	queue.run.Stage = command.To
	return queue.run.Clone(), nil
}

func (queue *inventoryWorkerQueue) ReserveCleanupAttempt(
	context.Context,
	assetcatalog.LeaseFence,
	discoveryqueue.RunCommand,
) (discoveryqueue.CleanupAttempt, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.run.CredentialCleanupStatus = assetcatalog.CredentialCleanupPending
	return queue.attempt, nil
}

func (queue *inventoryWorkerQueue) RecordCleanup(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	proof discoveryqueue.CleanupProof,
) (discoveryqueue.CleanupResult, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.run.CredentialCleanupStatus = proof.Status()
	return discoveryqueue.CleanupResult{
		Attempt: proof.Attempt(), Status: proof.Status(),
		DigestSHA256: proof.DigestSHA256(),
	}, nil
}

func (queue *inventoryWorkerQueue) Complete(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	command discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, error) {
	queue.mu.Lock()
	queue.completeCalls++
	queue.run.Status = command.DesiredStatus
	queue.run.Stage = assetcatalog.RunStageCompleted
	cancel := queue.cancel
	queue.mu.Unlock()
	completed := time.Now().UTC().Truncate(time.Microsecond)
	if cancel != nil {
		cancel()
	}
	return discoveryqueue.TerminalResult{
		RunID: command.Coordinates.RunID, Status: command.DesiredStatus,
		CommandDigest: strings.Repeat("f", 64), CompletedAt: completed,
	}, nil
}

type inventoryWorkerPageShape struct {
	Items    int
	Final    bool
	Complete bool
}

type inventoryWorkerPageCommitter struct {
	mu sync.Mutex

	queue *inventoryWorkerQueue
	calls int
	pages []inventoryWorkerPageShape
}

func (committer *inventoryWorkerPageCommitter) ApplyPage(
	_ context.Context,
	_ assetcatalog.LeaseFence,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
) (discoverysource.PageCommitResult, error) {
	committer.mu.Lock()
	committer.calls++
	committer.pages = append(committer.pages, inventoryWorkerPageShape{
		Items: len(page.Items), Final: page.FinalPage, Complete: page.CompleteSnapshot,
	})
	committer.mu.Unlock()

	committer.queue.mu.Lock()
	defer committer.queue.mu.Unlock()
	committer.queue.run.PageSequence = coordinates.PageSequence
	committer.queue.run.RelationPageSequence = coordinates.PageSequence
	committer.queue.run.CheckpointVersion++
	committer.queue.run.HeartbeatSequence++
	committer.queue.run.CursorAfterSHA256 = strings.Repeat("8", 64)
	if page.FinalPage {
		committer.queue.run.Status = assetcatalog.RunStatusFinalizing
		committer.queue.run.Stage = assetcatalog.RunStageCleaningUp
		committer.queue.run.WorkResultKind = assetcatalog.WorkResultDataProjection
		committer.queue.run.WorkResultStatus = assetcatalog.WorkResultStatusSucceeded
		committer.queue.run.WorkResultDigest = strings.Repeat("9", 64)
	} else {
		committer.queue.run.Stage = assetcatalog.RunStageReading
	}
	return discoverysource.PageCommitResult{
		RunID: coordinates.RunID, PageSequence: coordinates.PageSequence,
		CheckpointVersion:        committer.queue.run.CheckpointVersion,
		CheckpointSHA256:         strings.Repeat("8", 64),
		PageDigestSHA256:         strings.Repeat("9", 64),
		RelationPageDigestSHA256: strings.Repeat("7", 64),
		FinalPage:                page.FinalPage,
		CompleteSnapshot:         page.CompleteSnapshot,
	}, nil
}

func (committer *inventoryWorkerPageCommitter) snapshot() []inventoryWorkerPageShape {
	committer.mu.Lock()
	defer committer.mu.Unlock()
	return slices.Clone(committer.pages)
}

type inventoryWorkerLimiter struct {
	discoverylimit.Limiter
	mu sync.Mutex

	acquireCalls int
	releaseCalls int
}

func (limiter *inventoryWorkerLimiter) Acquire(
	_ context.Context,
	command discoverylimit.AcquireCommand,
) (discoverylimit.Permit, error) {
	limiter.mu.Lock()
	limiter.acquireCalls++
	call := limiter.acquireCalls
	limiter.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return discoverylimit.Permit{
		PermitID:    fmt.Sprintf("8a200000-0000-4000-8000-%012d", call),
		Coordinates: command.Coordinates, RequestID: command.RequestID,
		CommandSHA256: strings.Repeat("1", 64),
		ReceiptSHA256: strings.Repeat("2", 64),
		AcquiredAt:    now, ExpiresAt: now.Add(command.TTL),
	}, nil
}

func (limiter *inventoryWorkerLimiter) Release(
	_ context.Context,
	command discoverylimit.ReleaseCommand,
) (discoverylimit.Receipt, error) {
	limiter.mu.Lock()
	limiter.releaseCalls++
	call := limiter.releaseCalls
	limiter.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return discoverylimit.Receipt{
		ReceiptID: fmt.Sprintf("8a300000-0000-4000-8000-%012d", call),
		PermitID:  command.PermitID, Kind: discoverylimit.ReceiptRelease,
		Coordinates: command.Coordinates, RequestID: command.RequestID,
		CommandSHA256: strings.Repeat("3", 64),
		ReceiptSHA256: strings.Repeat("4", 64),
		AcquiredAt:    now, ExpiresAt: now.Add(time.Second),
		ReasonCode: command.ReasonCode,
	}, nil
}
