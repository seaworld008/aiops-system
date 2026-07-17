package externalcmdb

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const discoverTestEnvironmentID = "44444444-4444-4444-8444-444444444444"

func TestDiscoverResumesAssetsThenRelationsAtExactCheckpoint(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
		assetPage1:   loadExternalCMDBFixture(t, "assets-page-1.json"),
		assetPage2:   loadExternalCMDBFixture(t, "assets-page-2.json"),
		relations:    loadExternalCMDBFixture(t, "relations.json"),
	}
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.RequestURI())
		if request.Method != http.MethodGet || request.Header.Get("Accept") != catalogContentType ||
			request.Header.Get("Authorization") != "Bearer test-bearer-token" {
			http.Error(writer, "closed request contract rejected", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.RequestURI() {
		case capabilitiesPath:
			_, _ = writer.Write(fixtures.capabilities)
		case assetsPath + "?limit=500":
			_, _ = writer.Write(fixtures.assetPage1)
		case assetsPath + "?cursor=asset-cursor-0002&limit=500":
			_, _ = writer.Write(fixtures.assetPage2)
		case relationsPath + "?limit=2000":
			_, _ = writer.Write(fixtures.relations)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	contractProvider, runtimeBinding, request := newDiscoveryProviderFixture(t, server)
	first := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	if len(first.Items) != 2 || len(first.Relations) != 0 || first.FinalPage || first.CompleteSnapshot {
		t.Fatalf("first page = %#v", first)
	}

	request.Checkpoint = first.NextCheckpoint.Clone()
	second := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	if len(second.Items) != 1 || len(second.Relations) != 0 || second.FinalPage || second.CompleteSnapshot {
		t.Fatalf("second page = %#v", second)
	}

	request.Checkpoint = second.NextCheckpoint.Clone()
	third := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	if len(third.Items) != 0 || len(third.Relations) != 1 || !third.FinalPage || !third.CompleteSnapshot {
		t.Fatalf("third page = %#v", third)
	}

	wantRequests := []string{
		capabilitiesPath,
		assetsPath + "?limit=500",
		assetsPath + "?cursor=asset-cursor-0002&limit=500",
		relationsPath + "?limit=2000",
	}
	if fmt.Sprint(requests) != fmt.Sprint(wantRequests) {
		t.Fatalf("wire requests = %v, want %v", requests, wantRequests)
	}
}

func TestDiscoverCompleteCheckpointStartsNextRunAtCapabilities(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
		assetPage1:   loadExternalCMDBFixture(t, "assets-page-1.json"),
		assetPage2:   loadExternalCMDBFixture(t, "assets-page-2.json"),
		relations:    loadExternalCMDBFixture(t, "relations.json"),
	}
	const nextSnapshotEpoch = "snapshot-2026-07-17-0002"
	nextCapabilities := mutateExternalCMDBFixture(t, fixtures.capabilities, func(root map[string]any) {
		root["snapshot_epoch"] = nextSnapshotEpoch
	})
	nextAssetPage := mutateExternalCMDBFixture(t, fixtures.assetPage1, func(root map[string]any) {
		root["snapshot_epoch"] = nextSnapshotEpoch
		root["next_cursor"] = "asset-cursor-next-run-0002"
		for index, value := range root["items"].([]any) {
			value.(map[string]any)["updated_at"] = fmt.Sprintf("2026-07-17T09:00:0%dZ", index+1)
		}
	})

	var requests []string
	capabilityCalls := 0
	firstAssetCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.RequestURI())
		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.RequestURI() {
		case capabilitiesPath:
			capabilityCalls++
			if capabilityCalls == 1 {
				_, _ = writer.Write(fixtures.capabilities)
			} else {
				_, _ = writer.Write(nextCapabilities)
			}
		case assetsPath + "?limit=500":
			firstAssetCalls++
			if firstAssetCalls == 1 {
				_, _ = writer.Write(fixtures.assetPage1)
			} else {
				_, _ = writer.Write(nextAssetPage)
			}
		case assetsPath + "?cursor=asset-cursor-0002&limit=500":
			_, _ = writer.Write(fixtures.assetPage2)
		case relationsPath + "?limit=2000":
			_, _ = writer.Write(fixtures.relations)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	contractProvider, runtimeBinding, request := newDiscoveryProviderFixture(t, server)
	first := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	request.Checkpoint = first.NextCheckpoint.Clone()
	second := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	request.Checkpoint = second.NextCheckpoint.Clone()
	final := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	if !final.FinalPage || !final.CompleteSnapshot {
		t.Fatalf("final page = %#v", final)
	}
	completed, err := decodeCMDBCheckpoint(final.NextCheckpoint)
	if err != nil {
		t.Fatalf("decode complete checkpoint: %v", err)
	}
	if completed.phase != cmdbPhaseComplete || !completed.assetsComplete ||
		!completed.assetLast.present || !completed.relationLast.present {
		t.Fatalf("complete checkpoint = %#v", completed)
	}

	var persistedCanonical []byte
	if err := discoverysource.WithCheckpointBytes(final.NextCheckpoint, profileCode, func(value []byte) error {
		persistedCanonical = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatalf("read persisted checkpoint: %v", err)
	}
	persisted, err := discoverysource.NewCheckpoint(profileCode, persistedCanonical)
	if err != nil {
		t.Fatalf("restore persisted checkpoint: %v", err)
	}
	t.Cleanup(persisted.Clear)
	request.Checkpoint = persisted
	completedBeforeNextRun := request.Checkpoint.Clone()
	t.Cleanup(completedBeforeNextRun.Clear)

	next := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	if !request.Checkpoint.Equal(completedBeforeNextRun) {
		t.Fatal("next run mutated the persisted complete checkpoint")
	}
	if len(next.Items) != 2 || len(next.Relations) != 0 || next.FinalPage || next.CompleteSnapshot {
		t.Fatalf("next run first page = %#v", next)
	}
	resumed, err := decodeCMDBCheckpoint(next.NextCheckpoint)
	if err != nil {
		t.Fatalf("decode next run checkpoint: %v", err)
	}
	if resumed.phase != cmdbPhaseAssets || resumed.snapshotEpoch != nextSnapshotEpoch ||
		resumed.assetCursor != "asset-cursor-next-run-0002" ||
		resumed.assetLast.externalID != "vm-0001" ||
		resumed.relationCursor != "" || resumed.relationLast.present || resumed.assetsComplete {
		t.Fatalf("next run checkpoint leaked prior state: %#v", resumed)
	}

	wantRequests := []string{
		capabilitiesPath,
		assetsPath + "?limit=500",
		assetsPath + "?cursor=asset-cursor-0002&limit=500",
		relationsPath + "?limit=2000",
		capabilitiesPath,
		assetsPath + "?limit=500",
	}
	if fmt.Sprint(requests) != fmt.Sprint(wantRequests) {
		t.Fatalf("wire requests = %v, want %v", requests, wantRequests)
	}
}

func TestDiscoverRejectsSnapshotCursorAndOrderRegression(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
		assetPage1:   loadExternalCMDBFixture(t, "assets-page-1.json"),
		assetPage2:   loadExternalCMDBFixture(t, "assets-page-2.json"),
	}
	tests := []struct {
		name   string
		mutate func(*testing.T, []byte) []byte
	}{
		{
			name: "snapshot epoch changed",
			mutate: func(t *testing.T, payload []byte) []byte {
				return mutateExternalCMDBFixture(t, payload, func(root map[string]any) {
					root["snapshot_epoch"] = "snapshot-2026-07-17-0002"
				})
			},
		},
		{
			name: "cursor did not advance",
			mutate: func(t *testing.T, payload []byte) []byte {
				return mutateExternalCMDBFixture(t, payload, func(root map[string]any) {
					root["next_cursor"] = "asset-cursor-0002"
					root["final_page"] = false
					root["complete_snapshot"] = false
				})
			},
		},
		{
			name: "order regressed",
			mutate: func(t *testing.T, payload []byte) []byte {
				return mutateExternalCMDBFixture(t, payload, func(root map[string]any) {
					item := firstExternalCMDBFixtureItem(t, root)
					item["updated_at"] = "2026-07-17T09:29:59Z"
				})
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secondPage := test.mutate(t, fixtures.assetPage2)
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", catalogContentType)
				switch request.URL.RequestURI() {
				case capabilitiesPath:
					_, _ = writer.Write(fixtures.capabilities)
				case assetsPath + "?limit=500":
					_, _ = writer.Write(fixtures.assetPage1)
				case assetsPath + "?cursor=asset-cursor-0002&limit=500":
					_, _ = writer.Write(secondPage)
				default:
					http.NotFound(writer, request)
				}
			}))
			t.Cleanup(server.Close)

			contractProvider, runtimeBinding, request := newDiscoveryProviderFixture(t, server)
			first := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
			request.Checkpoint = first.NextCheckpoint.Clone()
			checkpointBefore := request.Checkpoint.Clone()

			outcome, err := contractProvider.Discover(context.Background(), runtimeBinding, request)
			if err == nil || outcome != nil {
				t.Fatalf("regression outcome = (%T, %v), want nil closed error", outcome, err)
			}
			if !request.Checkpoint.Equal(checkpointBefore) {
				t.Fatal("regression mutated the request checkpoint")
			}
		})
	}
}

func TestDiscoverAcceptsExactBoundaryReplayAndRejectsChangedReplay(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
		assetPage1:   loadExternalCMDBFixture(t, "assets-page-1.json"),
		assetPage2:   loadExternalCMDBFixture(t, "assets-page-2.json"),
	}
	var firstPageRoot map[string]any
	if err := json.Unmarshal(fixtures.assetPage1, &firstPageRoot); err != nil {
		t.Fatalf("decode first fixture: %v", err)
	}
	firstItems, ok := firstPageRoot["items"].([]any)
	if !ok || len(firstItems) != 2 {
		t.Fatalf("first fixture items = %#v", firstPageRoot["items"])
	}
	boundaryItem := firstItems[1]

	tests := []struct {
		name        string
		change      bool
		wantFailure bool
	}{
		{name: "exact replay", wantFailure: false},
		{name: "changed replay", change: true, wantFailure: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			replayPage := mutateExternalCMDBFixture(t, fixtures.assetPage2, func(root map[string]any) {
				replayed := cloneFixtureValue(t, boundaryItem)
				if test.change {
					replayed.(map[string]any)["display_name"] = "changed-replay"
				}
				root["items"] = []any{replayed}
			})
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", catalogContentType)
				switch request.URL.RequestURI() {
				case capabilitiesPath:
					_, _ = writer.Write(fixtures.capabilities)
				case assetsPath + "?limit=500":
					_, _ = writer.Write(fixtures.assetPage1)
				case assetsPath + "?cursor=asset-cursor-0002&limit=500":
					_, _ = writer.Write(replayPage)
				default:
					http.NotFound(writer, request)
				}
			}))
			t.Cleanup(server.Close)

			contractProvider, runtimeBinding, request := newDiscoveryProviderFixture(t, server)
			first := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
			request.Checkpoint = first.NextCheckpoint.Clone()
			outcome, err := contractProvider.Discover(context.Background(), runtimeBinding, request)
			if test.wantFailure {
				if err == nil || outcome != nil {
					t.Fatalf("changed replay = (%T, %v), want nil closed error", outcome, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("exact replay error = %v", err)
			}
			page, ok := outcome.(discoverysource.Page)
			if !ok || len(page.Items) != 1 || page.Items[0].ExternalID != "vm-0001" {
				t.Fatalf("exact replay outcome = %#v", outcome)
			}
		})
	}
}

func TestDiscoverMapsOnlyPositiveProviderRetryAfterToDelay(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
	}
	now := time.Date(2026, time.July, 17, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		statusCode int
		retryAfter string
		wantDelay  time.Duration
		wantClosed bool
	}{
		{
			name:       "429 integer",
			statusCode: http.StatusTooManyRequests,
			retryAfter: "17",
			wantDelay:  17 * time.Second,
		},
		{
			name:       "503 date",
			statusCode: http.StatusServiceUnavailable,
			retryAfter: now.Add(42 * time.Second).Format(http.TimeFormat),
			wantDelay:  42 * time.Second,
		},
		{
			name:       "zero fails closed",
			statusCode: http.StatusTooManyRequests,
			retryAfter: "0",
			wantClosed: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case capabilitiesPath:
					writer.Header().Set("Content-Type", catalogContentType)
					_, _ = writer.Write(fixtures.capabilities)
				case assetsPath:
					writer.Header().Set("Retry-After", test.retryAfter)
					writer.WriteHeader(test.statusCode)
				default:
					http.NotFound(writer, request)
				}
			}))
			t.Cleanup(server.Close)

			contractProvider, runtimeBinding, request := newDiscoveryProviderFixture(t, server)
			outcome, err := contractProvider.Discover(context.Background(), runtimeBinding, request)
			if test.wantClosed {
				if err == nil || outcome != nil {
					t.Fatalf("zero Retry-After = (%T, %v), want nil closed error", outcome, err)
				}
				if !errors.Is(err, errProviderContract) {
					t.Fatalf("zero Retry-After error = %v, want provider contract error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			delay, ok := outcome.(discoverysource.Delay)
			if !ok || delay.Reason != discoverysource.DelayReasonProviderRetryAfter ||
				delay.RetryAfter != test.wantDelay {
				t.Fatalf("delay = %#v, want %v", outcome, test.wantDelay)
			}
			if err := discoverysource.ValidateDiscoverResult(
				request,
				assetdiscoveryPolicyForTest(),
				delay,
				nil,
			); err != nil {
				t.Fatalf("Delay violates common contract: %v", err)
			}
		})
	}
}

func TestDiscoverPartialFailureReturnsNoCompletionOrCheckpoint(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
		assetPage1:   loadExternalCMDBFixture(t, "assets-page-1.json"),
	}
	assetCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.RequestURI() {
		case capabilitiesPath:
			_, _ = writer.Write(fixtures.capabilities)
		case assetsPath + "?limit=500":
			assetCalls++
			_, _ = writer.Write(fixtures.assetPage1)
		case assetsPath + "?cursor=asset-cursor-0002&limit=500":
			assetCalls++
			http.Error(writer, "upstream unavailable", http.StatusInternalServerError)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	contractProvider, runtimeBinding, request := newDiscoveryProviderFixture(t, server)
	first := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	if first.FinalPage || first.CompleteSnapshot {
		t.Fatalf("partial first page was complete: %#v", first)
	}
	request.Checkpoint = first.NextCheckpoint.Clone()
	checkpointBefore := request.Checkpoint.Clone()
	outcome, err := contractProvider.Discover(context.Background(), runtimeBinding, request)
	if err == nil || outcome != nil {
		t.Fatalf("partial failure = (%T, %v), want nil closed error", outcome, err)
	}
	if !request.Checkpoint.Equal(checkpointBefore) || assetCalls != 2 {
		t.Fatalf("partial failure advanced checkpoint or calls: equal=%t calls=%d",
			request.Checkpoint.Equal(checkpointBefore), assetCalls)
	}
}

func TestDiscoverCheckpointRejectsSerializationAndTamper(t *testing.T) {
	t.Parallel()

	fixtures := externalCMDBFixtures{
		capabilities: loadExternalCMDBFixture(t, "capabilities.json"),
		assetPage1:   loadExternalCMDBFixture(t, "assets-page-1.json"),
	}
	networkCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		networkCalls++
		writer.Header().Set("Content-Type", catalogContentType)
		switch request.URL.RequestURI() {
		case capabilitiesPath:
			_, _ = writer.Write(fixtures.capabilities)
		case assetsPath + "?limit=500":
			_, _ = writer.Write(fixtures.assetPage1)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	contractProvider, runtimeBinding, request := newDiscoveryProviderFixture(t, server)
	first := requireDiscoverPage(t, contractProvider, runtimeBinding, request)
	checkpoint := first.NextCheckpoint
	if _, err := json.Marshal(checkpoint); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(checkpoint) error = %v", err)
	}
	text, ok := any(checkpoint).(encoding.TextMarshaler)
	if !ok {
		t.Fatal("checkpoint does not implement encoding.TextMarshaler")
	}
	if _, err := text.MarshalText(); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
		t.Fatalf("MarshalText(checkpoint) error = %v", err)
	}
	if rendered := fmt.Sprintf("%v %#v", checkpoint, checkpoint); strings.Contains(rendered, "asset-cursor-0002") {
		t.Fatalf("checkpoint formatting leaked cursor: %q", rendered)
	}

	var canonical []byte
	if err := discoverysource.WithCheckpointBytes(checkpoint, profileCode, func(value []byte) error {
		canonical = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatalf("WithCheckpointBytes() error = %v", err)
	}
	if len(canonical) == 0 {
		t.Fatal("provider returned an empty resume checkpoint")
	}
	canonical[len(canonical)-1] ^= 0xff
	tampered, err := discoverysource.NewCheckpoint(profileCode, canonical)
	if err != nil {
		t.Fatalf("NewCheckpoint(tampered) error = %v", err)
	}
	request.Checkpoint = tampered
	callsBefore := networkCalls
	outcome, err := contractProvider.Discover(context.Background(), runtimeBinding, request)
	if err == nil || outcome != nil {
		t.Fatalf("tampered checkpoint = (%T, %v), want nil closed error", outcome, err)
	}
	if networkCalls != callsBefore {
		t.Fatalf("tampered checkpoint made %d network calls", networkCalls-callsBefore)
	}
}

type externalCMDBFixtures struct {
	capabilities []byte
	assetPage1   []byte
	assetPage2   []byte
	relations    []byte
}

func assetdiscoveryPolicyForTest() assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind:            providerKind,
		FreshnessKind:           assetcatalog.FreshnessObjectTimeSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{discoverTestEnvironmentID},
		TrustedPathCodes:        []string{"CMDB_V1_RELATION"},
	}
}

func mutateExternalCMDBFixture(
	t *testing.T,
	payload []byte,
	mutate func(map[string]any),
) []byte {
	t.Helper()

	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	mutate(root)
	encoded, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return encoded
}

func firstExternalCMDBFixtureItem(t *testing.T, root map[string]any) map[string]any {
	t.Helper()

	items, ok := root["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("fixture items = %#v", root["items"])
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("fixture first item = %#v", items[0])
	}
	return item
}

func cloneFixtureValue(t *testing.T, value any) any {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode fixture value: %v", err)
	}
	var clone any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatalf("decode fixture value: %v", err)
	}
	return clone
}

func newDiscoveryProviderFixture(
	t *testing.T,
	server *httptest.Server,
) (discoverysource.Provider, discoverysource.BoundRuntime, discoverysource.DiscoverRequest) {
	t.Helper()

	request := discoverysource.DiscoverRequest{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID:    "11111111-1111-4111-8111-111111111111",
				WorkspaceID: "22222222-2222-4222-8222-222222222222",
			},
			SourceID: "33333333-3333-4333-8333-333333333333",
		},
		SourceRevision:       18,
		SourceRevisionDigest: strings.Repeat("a", 64),
		Limits: discoverysource.Limits{
			MaxPageItems:     assetPageLimit,
			MaxPageRelations: relationPageLimit,
			MaxPageBytes:     maxPageBodyBytes,
			MaxDocumentBytes: 64 << 10,
		},
	}
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	request.Checkpoint = checkpoint
	t.Cleanup(request.Checkpoint.Clear)

	binding := discoverysource.RuntimeBinding{
		Locator:              request.Locator,
		SourceRevision:       request.SourceRevision,
		SourceRevisionDigest: request.SourceRevisionDigest,
		RevisionStatus:       assetcatalog.SourceRevisionPublished,
		ProviderKind:         providerKind,
		ProfileCode:          profileCode,
	}
	material := RuntimeMaterial{
		BaseURL:             server.URL,
		TLSConfig:           verifiedTLSConfigForServer(t, server),
		BearerToken:         []byte("test-bearer-token"),
		ExpectedAuthorityID: "cmdb-production-01",
		EnvironmentID:       discoverTestEnvironmentID,
	}
	boundRuntime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = boundRuntime.Close() })

	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	factory.now = func() time.Time {
		return time.Date(2026, time.July, 17, 9, 30, 0, 0, time.UTC)
	}
	contractProvider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return contractProvider, boundRuntime, request
}

func requireDiscoverPage(
	t *testing.T,
	provider discoverysource.Provider,
	runtimeBinding discoverysource.BoundRuntime,
	request discoverysource.DiscoverRequest,
) discoverysource.Page {
	t.Helper()

	outcome, err := provider.Discover(context.Background(), runtimeBinding, request)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	page, ok := outcome.(discoverysource.Page)
	if !ok {
		t.Fatalf("Discover() outcome = %T, want Page", outcome)
	}
	return page
}

func loadExternalCMDBFixture(t *testing.T, name string) []byte {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not return the test path")
	}
	path := filepath.Clean(filepath.Join(
		filepath.Dir(currentFile),
		"..", "..", "..",
		"testdata", "asset-source", "external-cmdb", name,
	))
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return payload
}
