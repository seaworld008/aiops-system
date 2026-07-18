package proxmox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

func TestProtocolIntegrationValidationAndFullInventory(t *testing.T) {
	simulator := newProxmoxSimulator(t, simulatorBehavior{})
	defer simulator.Close()

	validationProvider, validationRuntime := simulator.providerAndRuntime(
		t,
		assetcatalog.SourceRevisionValidating,
		simulator.roots,
		"example.com",
		"cluster/alpha",
	)
	defer validationRuntime.Clear()
	proof, err := validationProvider.Validate(
		context.Background(),
		validationRuntime,
		testValidationRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Outcome != assetcatalog.ValidationOutcomeSucceeded ||
		proof.Code != "VALIDATION_SUCCEEDED" ||
		len(proof.Checks) != 8 {
		t.Fatalf("proof = %#v", proof)
	}
	if err := discoverysource.ValidateValidationResult(testValidationRequest(), proof, nil); err != nil {
		t.Fatalf("validation proof contract: %v", err)
	}

	discoveryProvider, discoveryRuntime := simulator.providerAndRuntime(
		t,
		assetcatalog.SourceRevisionPublished,
		simulator.roots,
		"example.com",
		"cluster/alpha",
	)
	defer discoveryRuntime.Clear()
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Clear()
	request := testDiscoverRequest(checkpoint)
	outcome, err := discoveryProvider.Discover(context.Background(), discoveryRuntime, request)
	if err != nil {
		t.Fatal(err)
	}
	page, ok := outcome.(discoverysource.Page)
	if !ok {
		t.Fatalf("outcome = %T", outcome)
	}
	defer page.NextCheckpoint.Clear()
	if !page.FinalPage || !page.CompleteSnapshot {
		t.Fatalf("completion = final:%t complete:%t", page.FinalPage, page.CompleteSnapshot)
	}
	if len(page.Items) != 3 || len(page.Relations) != 4 {
		t.Fatalf("facts = %d items, %d relations", len(page.Items), len(page.Relations))
	}
	if err := discoverysource.ValidateDiscoverResult(
		request,
		normalizedFactPolicy(testEnvironmentID),
		page,
		nil,
	); err != nil {
		t.Fatalf("discover result contract: %v", err)
	}
	for _, item := range page.Items {
		if item.Freshness.OrderSequence != 1 {
			t.Fatalf("item %q order sequence = %d, want accepted checkpoint version 1", item.ExternalID, item.Freshness.OrderSequence)
		}
		text := string(item.Document)
		for _, forbidden := range []string{
			"10.0.0.1",
			"aa:bb:cc:dd:ee:ff",
			"reader@pve",
			"synthetic-token-secret",
			simulator.URL,
			"description",
			"cloud-init",
			"disk",
			"network",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("item %q leaked %q: %s", item.ExternalID, forbidden, text)
			}
		}
		if len(item.FieldProvenance) != 6 {
			t.Fatalf("%s provenance = %#v", item.ExternalID, item.FieldProvenance)
		}
	}
	for _, relation := range page.Relations {
		if relation.Freshness.OrderSequence != 1 {
			t.Fatalf("relation order sequence = %d, want accepted checkpoint version 1", relation.Freshness.OrderSequence)
		}
	}

	wantPaths := []string{
		"/api2/json/version",
		"/api2/json/cluster/status",
		"/api2/json/nodes",
		"/api2/json/cluster/resources?type=vm",
		"/api2/json/version",
		"/api2/json/cluster/status",
		"/api2/json/nodes",
		"/api2/json/cluster/resources?type=vm",
	}
	if got := simulator.Paths(); !slices.Equal(got, wantPaths) {
		t.Fatalf("wire paths = %#v, want %#v", got, wantPaths)
	}
	if simulator.invalidRequests.Load() != 0 {
		t.Fatalf("simulator observed %d invalid requests", simulator.invalidRequests.Load())
	}
}

func TestProtocolIntegrationTLSAuthorityAndTokenScopeFailClosed(t *testing.T) {
	t.Run("wrong CA", func(t *testing.T) {
		simulator := newProxmoxSimulator(t, simulatorBehavior{})
		defer simulator.Close()
		roots := x509.NewCertPool()
		roots.AddCert(testCertificate(t))
		value, runtime := simulator.providerAndRuntime(
			t,
			assetcatalog.SourceRevisionValidating,
			roots,
			"example.com",
			"cluster/alpha",
		)
		defer runtime.Clear()
		proof, err := value.Validate(context.Background(), runtime, testValidationRequest())
		if err != nil {
			t.Fatal(err)
		}
		assertFailedCheck(t, proof, discoverysource.ValidationCheckTrustOrSignature)
		if len(simulator.Paths()) != 0 {
			t.Fatalf("wrong CA reached application handler: %#v", simulator.Paths())
		}
	})

	t.Run("wrong SNI", func(t *testing.T) {
		simulator := newProxmoxSimulator(t, simulatorBehavior{})
		defer simulator.Close()
		value, runtime := simulator.providerAndRuntime(
			t,
			assetcatalog.SourceRevisionValidating,
			simulator.roots,
			"wrong.invalid",
			"cluster/alpha",
		)
		defer runtime.Clear()
		proof, err := value.Validate(context.Background(), runtime, testValidationRequest())
		if err != nil {
			t.Fatal(err)
		}
		assertFailedCheck(t, proof, discoverysource.ValidationCheckTrustOrSignature)
		if len(simulator.Paths()) != 0 {
			t.Fatalf("wrong SNI reached application handler: %#v", simulator.Paths())
		}
	})

	t.Run("token scope", func(t *testing.T) {
		simulator := newProxmoxSimulator(t, simulatorBehavior{rejectToken: true})
		defer simulator.Close()
		value, runtime := simulator.providerAndRuntime(
			t,
			assetcatalog.SourceRevisionValidating,
			simulator.roots,
			"example.com",
			"cluster/alpha",
		)
		defer runtime.Clear()
		proof, err := value.Validate(context.Background(), runtime, testValidationRequest())
		if err != nil {
			t.Fatal(err)
		}
		assertFailedCheck(t, proof, discoverysource.ValidationCheckCredentialOpen)
	})

	t.Run("cluster identity", func(t *testing.T) {
		simulator := newProxmoxSimulator(t, simulatorBehavior{})
		defer simulator.Close()
		value, runtime := simulator.providerAndRuntime(
			t,
			assetcatalog.SourceRevisionValidating,
			simulator.roots,
			"example.com",
			"cluster/other",
		)
		defer runtime.Clear()
		proof, err := value.Validate(context.Background(), runtime, testValidationRequest())
		if err != nil {
			t.Fatal(err)
		}
		assertFailedCheck(t, proof, discoverysource.ValidationCheckIdentity)
	})

	t.Run("quorum", func(t *testing.T) {
		simulator := newProxmoxSimulator(t, simulatorBehavior{quorate: boolPointer(false)})
		defer simulator.Close()
		value, runtime := simulator.providerAndRuntime(
			t,
			assetcatalog.SourceRevisionValidating,
			simulator.roots,
			"example.com",
			"cluster/alpha",
		)
		defer runtime.Clear()
		proof, err := value.Validate(context.Background(), runtime, testValidationRequest())
		if err != nil {
			t.Fatal(err)
		}
		assertFailedCheck(t, proof, discoverysource.ValidationCheckIdentity)
	})
}

func TestProtocolIntegrationPartialClusterCannotCompleteOrMarkMissing(t *testing.T) {
	simulator := newProxmoxSimulator(t, simulatorBehavior{
		pathStatus: map[string]int{
			"/api2/json/cluster/resources?type=vm": http.StatusInternalServerError,
		},
	})
	defer simulator.Close()
	value, runtime := simulator.providerAndRuntime(
		t,
		assetcatalog.SourceRevisionPublished,
		simulator.roots,
		"example.com",
		"cluster/alpha",
		42,
	)
	defer runtime.Clear()
	oldCanonical, err := encodeProviderCheckpoint(providerCheckpoint{
		ClusterIdentityDigest: clusterIdentityDigest(ClusterStatus{
			Identity:   "cluster/alpha",
			Name:       "alpha",
			Generation: 19,
			Quorate:    true,
			Members:    []ClusterMember{{Name: "node-a", Online: true}},
		}),
		ClusterGeneration: 18,
		ResourceDigest:    strings.Repeat("b", 64),
		CompletedAt:       "2026-07-18T09:00:00.000000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldCheckpoint, err := discoverysource.NewCheckpoint(profileCode, oldCanonical)
	clear(oldCanonical)
	if err != nil {
		t.Fatal(err)
	}
	defer oldCheckpoint.Clear()
	request := testDiscoverRequest(oldCheckpoint)
	outcome, err := value.Discover(context.Background(), runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	page, ok := outcome.(discoverysource.Page)
	if !ok {
		t.Fatalf("outcome = %T", outcome)
	}
	defer page.NextCheckpoint.Clear()
	if page.CompleteSnapshot || !page.FinalPage || len(page.Items) != 1 || len(page.Relations) != 0 {
		t.Fatalf("partial page = %#v", page)
	}
	if page.Items[0].Freshness.OrderSequence != 42 {
		t.Fatalf("partial order sequence = %d, want accepted checkpoint version 42", page.Items[0].Freshness.OrderSequence)
	}
	if !page.NextCheckpoint.Equal(request.Checkpoint) {
		t.Fatal("partial cluster advanced checkpoint")
	}
	for _, item := range page.Items {
		if item.Tombstone {
			t.Fatalf("partial response emitted tombstone: %#v", item)
		}
	}
}

func TestProtocolIntegrationRetryAfterProducesTypedDelayWithoutRetry(t *testing.T) {
	for _, status := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			simulator := newProxmoxSimulator(t, simulatorBehavior{
				pathStatus: map[string]int{"/api2/json/version": status},
				retryAfter: "7",
			})
			defer simulator.Close()
			value, runtime := simulator.providerAndRuntime(
				t,
				assetcatalog.SourceRevisionPublished,
				simulator.roots,
				"example.com",
				"cluster/alpha",
			)
			defer runtime.Clear()
			checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer checkpoint.Clear()
			request := testDiscoverRequest(checkpoint)
			outcome, err := value.Discover(context.Background(), runtime, request)
			if err != nil {
				t.Fatal(err)
			}
			delay, ok := outcome.(discoverysource.Delay)
			if !ok {
				t.Fatalf("outcome = %T", outcome)
			}
			if delay.Reason != discoverysource.DelayReasonProviderRetryAfter ||
				delay.RetryAfter != 7*time.Second {
				t.Fatalf("delay = %#v", delay)
			}
			if len(simulator.Paths()) != 1 {
				t.Fatalf("request count = %d, want no retry", len(simulator.Paths()))
			}
			if err := discoverysource.ValidateDiscoverResult(
				request,
				assetdiscovery.FactPolicy{},
				delay,
				nil,
			); err != nil {
				t.Fatalf("delay contract: %v", err)
			}
		})
	}
	for name, retryAfter := range map[string]string{
		"missing":   "",
		"zero":      "0",
		"too-large": "61",
		"malformed": "soon",
	} {
		t.Run(name, func(t *testing.T) {
			simulator := newProxmoxSimulator(t, simulatorBehavior{
				pathStatus: map[string]int{"/api2/json/version": http.StatusTooManyRequests},
				retryAfter: retryAfter,
			})
			defer simulator.Close()
			value, runtime := simulator.providerAndRuntime(
				t,
				assetcatalog.SourceRevisionPublished,
				simulator.roots,
				"example.com",
				"cluster/alpha",
			)
			defer runtime.Clear()
			checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer checkpoint.Clear()
			outcome, err := value.Discover(
				context.Background(),
				runtime,
				testDiscoverRequest(checkpoint),
			)
			if err == nil || outcome != nil {
				t.Fatalf("malformed retry result = (%#v, %v)", outcome, err)
			}
		})
	}
}

func TestProtocolIntegrationRejectsUnknownDLPDuplicateAndOversizeResponses(t *testing.T) {
	dlpCanary := strings.Join([]string{"gh", "p_", strings.Repeat("x", 24)}, "")
	cases := map[string]simulatorBehavior{
		"unknown": {
			rawBodies: map[string]string{
				"/api2/json/version": `{"data":{"version":"8.4.1","release":"1","repoid":"pve","endpoint":"https://evil.invalid"}}`,
			},
		},
		"resource-unknown": {
			rawBodies: map[string]string{
				"/api2/json/cluster/resources?type=vm": `{"data":[{"id":"qemu/101","type":"qemu","vmid":101,"name":"vm-a","node":"node-a","status":"running","maxcpu":4,"maxmem":8589934592,"template":0,"config":"ambiguous"}]}`,
			},
		},
		"dlp": {
			rawBodies: map[string]string{
				"/api2/json/cluster/resources?type=vm": `{"data":[{"id":"qemu/101","type":"qemu","vmid":101,"name":"` + dlpCanary + `","node":"node-a","status":"running","maxcpu":4,"maxmem":8589934592,"template":0}]}`,
			},
		},
		"duplicate": {
			rawBodies: map[string]string{
				"/api2/json/version": `{"data":{"version":"8.4.1","version":"8.4.1","release":"1","repoid":"pve"}}`,
			},
		},
		"oversize": {
			rawBodies: map[string]string{
				"/api2/json/version": `{"data":"` + strings.Repeat("x", (8<<20)+1) + `"}`,
			},
		},
	}
	for name, behavior := range cases {
		t.Run(name, func(t *testing.T) {
			simulator := newProxmoxSimulator(t, behavior)
			defer simulator.Close()
			value, runtime := simulator.providerAndRuntime(
				t,
				assetcatalog.SourceRevisionPublished,
				simulator.roots,
				"example.com",
				"cluster/alpha",
			)
			defer runtime.Clear()
			checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer checkpoint.Clear()
			outcome, err := value.Discover(
				context.Background(),
				runtime,
				testDiscoverRequest(checkpoint),
			)
			if err == nil || outcome != nil {
				t.Fatalf("unsafe response result = (%#v, %v)", outcome, err)
			}
			errorText := fmt.Sprint(err)
			for _, forbidden := range []string{
				"evil.invalid",
				dlpCanary,
				simulator.URL,
				"127.0.0.1",
			} {
				if strings.Contains(errorText, forbidden) {
					t.Fatalf("error leaked %q: %q", forbidden, errorText)
				}
			}
		})
	}
}

func TestProtocolIntegrationEnforcesResourceBudget(t *testing.T) {
	resources := make([]map[string]any, 5_001)
	for index := range resources {
		resources[index] = map[string]any{
			"id":       fmt.Sprintf("qemu/%d", index+100),
			"type":     "qemu",
			"vmid":     index + 100,
			"name":     fmt.Sprintf("vm-%d", index+100),
			"node":     "node-a",
			"status":   "running",
			"maxcpu":   1,
			"maxmem":   1 << 30,
			"template": 0,
		}
	}
	body, err := json.Marshal(map[string]any{"data": resources})
	if err != nil {
		t.Fatal(err)
	}
	simulator := newProxmoxSimulator(t, simulatorBehavior{
		rawBodies: map[string]string{
			"/api2/json/cluster/resources?type=vm": string(body),
		},
	})
	defer simulator.Close()
	value, runtime := simulator.providerAndRuntime(
		t,
		assetcatalog.SourceRevisionPublished,
		simulator.roots,
		"example.com",
		"cluster/alpha",
	)
	defer runtime.Clear()
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Clear()
	outcome, err := value.Discover(
		context.Background(),
		runtime,
		testDiscoverRequest(checkpoint),
	)
	if err == nil || outcome != nil {
		t.Fatalf("oversize inventory result = (%#v, %v)", outcome, err)
	}
}

func TestProtocolIntegrationPropagatesCallerCancellationAndDeadline(t *testing.T) {
	for name, contextFactory := range map[string]func() (context.Context, context.CancelFunc){
		"cancel": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		},
		"deadline": func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 20*time.Millisecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			simulator := newProxmoxSimulator(t, simulatorBehavior{
				blockPath: "/api2/json/version",
			})
			defer simulator.Close()
			value, runtime := simulator.providerAndRuntime(
				t,
				assetcatalog.SourceRevisionPublished,
				simulator.roots,
				"example.com",
				"cluster/alpha",
			)
			defer runtime.Clear()
			checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer checkpoint.Clear()
			ctx, cancel := contextFactory()
			defer cancel()
			started := time.Now()
			outcome, err := value.Discover(ctx, runtime, testDiscoverRequest(checkpoint))
			if outcome != nil || !errors.Is(err, context.Canceled) &&
				!errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("context result = (%#v, %v)", outcome, err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("caller context propagation took %s", elapsed)
			}
		})
	}
}

func TestProtocolIntegrationStripsCallerTraceBeforeAuthorizationWrite(t *testing.T) {
	simulator := newProxmoxSimulator(t, simulatorBehavior{})
	defer simulator.Close()
	value, runtime := simulator.providerAndRuntime(
		t,
		assetcatalog.SourceRevisionPublished,
		simulator.roots,
		"example.com",
		"cluster/alpha",
	)
	defer runtime.Clear()
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Clear()

	var observedAuthorization atomic.Bool
	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(key string, _ []string) {
			if strings.EqualFold(key, "Authorization") {
				observedAuthorization.Store(true)
			}
		},
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	outcome, err := value.Discover(ctx, runtime, testDiscoverRequest(checkpoint))
	if err != nil {
		t.Fatal(err)
	}
	page, ok := outcome.(discoverysource.Page)
	if !ok {
		t.Fatalf("outcome = %T", outcome)
	}
	defer page.NextCheckpoint.Clear()
	if observedAuthorization.Load() {
		t.Fatal("caller httptrace observed the Proxmox authorization header")
	}
}

type simulatorBehavior struct {
	rejectToken bool
	quorate     *bool
	pathStatus  map[string]int
	retryAfter  string
	rawBodies   map[string]string
	blockPath   string
}

type proxmoxSimulator struct {
	*httptest.Server
	roots           *x509.CertPool
	behavior        simulatorBehavior
	mu              sync.Mutex
	paths           []string
	invalidRequests atomic.Int64
}

func newProxmoxSimulator(t *testing.T, behavior simulatorBehavior) *proxmoxSimulator {
	t.Helper()
	simulator := &proxmoxSimulator{behavior: behavior}
	server := httptest.NewUnstartedServer(http.HandlerFunc(simulator.serveHTTP))
	server.EnableHTTP2 = false
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	simulator.Server = server
	simulator.roots = x509.NewCertPool()
	simulator.roots.AddCert(server.Certificate())
	return simulator
}

func (simulator *proxmoxSimulator) providerAndRuntime(
	t *testing.T,
	status assetcatalog.SourceRevisionStatus,
	roots *x509.CertPool,
	serverName string,
	expectedClusterIdentity string,
	acceptedSequence ...int64,
) (discoverysource.Provider, discoverysource.BoundRuntime) {
	t.Helper()
	sequence := int64(1)
	if len(acceptedSequence) == 1 {
		sequence = acceptedSequence[0]
	} else if len(acceptedSequence) > 1 {
		t.Fatal("at most one accepted checkpoint sequence is allowed")
	}
	binding := testRuntimeBinding(status)
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatal(err)
	}
	factory.now = func() time.Time {
		return time.Date(2026, 7, 18, 10, 11, 12, 123456000, time.UTC)
	}
	value, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	endpointURL, err := url.Parse(simulator.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpointHandle(endpointURL.String() + "/api2/json")
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustHandle(roots, serverName)
	if err != nil {
		t.Fatal(err)
	}
	token, err := NewTokenHandle(
		"reader@pve!inventory",
		[]byte("synthetic-token-secret"),
	)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthorityHandle(expectedClusterIdentity, testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewRuntimeMaterial(endpoint, trust, token, authority, sequence)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatal(err)
	}
	return value, runtime
}

func (simulator *proxmoxSimulator) Paths() []string {
	simulator.mu.Lock()
	defer simulator.mu.Unlock()
	return slices.Clone(simulator.paths)
}

func (simulator *proxmoxSimulator) serveHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	path := request.URL.EscapedPath()
	if request.URL.RawQuery != "" {
		path += "?" + request.URL.RawQuery
	}
	simulator.mu.Lock()
	simulator.paths = append(simulator.paths, path)
	simulator.mu.Unlock()

	validPaths := map[string]bool{
		"/api2/json/version":                   true,
		"/api2/json/cluster/status":            true,
		"/api2/json/nodes":                     true,
		"/api2/json/cluster/resources?type=vm": true,
	}
	if request.Method != http.MethodGet ||
		!validPaths[path] ||
		request.Body != nil && request.Body != http.NoBody ||
		request.Header.Get("Authorization") !=
			"PVEAPIToken=reader@pve!inventory=synthetic-token-secret" ||
		request.Header.Get("Accept") != "application/json" ||
		request.Header.Get("User-Agent") != "aiops-proxmox-inventory/1" {
		simulator.invalidRequests.Add(1)
		http.Error(writer, "rejected", http.StatusBadRequest)
		return
	}
	if simulator.behavior.blockPath == path {
		<-request.Context().Done()
		return
	}
	if simulator.behavior.rejectToken {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(writer, `{"data":null}`)
		return
	}
	if status := simulator.behavior.pathStatus[path]; status != 0 {
		if simulator.behavior.retryAfter != "" {
			writer.Header().Set("Retry-After", simulator.behavior.retryAfter)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, `{"data":null}`)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	if body, ok := simulator.behavior.rawBodies[path]; ok {
		_, _ = io.WriteString(writer, body)
		return
	}
	quorate := true
	if simulator.behavior.quorate != nil {
		quorate = *simulator.behavior.quorate
	}
	switch path {
	case "/api2/json/version":
		_, _ = io.WriteString(
			writer,
			`{"data":{"version":"8.4.1","release":"1","repoid":"pve"}}`,
		)
	case "/api2/json/cluster/status":
		quorateNumber := 0
		if quorate {
			quorateNumber = 1
		}
		_, _ = fmt.Fprintf(
			writer,
			`{"data":[{"type":"cluster","id":"cluster/alpha","name":"alpha","version":19,"quorate":%d,"nodes":1},{"type":"node","id":"node/node-a","name":"node-a","online":1,"level":"","nodeid":1,"ip":"10.0.0.1","local":1}]}`,
			quorateNumber,
		)
	case "/api2/json/nodes":
		_, _ = io.WriteString(
			writer,
			`{"data":[{"node":"node-a","status":"online","type":"node","maxcpu":16,"maxmem":68719476736,"id":"node/node-a","level":"","uptime":2236708,"disk":2310930432,"maxdisk":940743983104,"mem":11508809728,"cpu":0.0034,"ssl_fingerprint":"AA:BB:CC:DD:EE:FF"}]}`,
		)
	case "/api2/json/cluster/resources?type=vm":
		_, _ = io.WriteString(
			writer,
			`{"data":[{"id":"qemu/101","type":"qemu","vmid":101,"name":"vm-a","node":"node-a","status":"running","maxcpu":4,"maxmem":8589934592,"template":0,"cpu":0.02,"mem":1048576,"disk":0,"diskread":100,"diskwrite":200,"netin":300,"netout":400,"maxdisk":34359738368,"uptime":874350},{"id":"lxc/202","type":"lxc","vmid":202,"name":"ct-b","node":"node-a","status":"stopped","maxcpu":2,"maxmem":2147483648,"template":0,"cpu":0,"mem":0,"disk":0,"diskread":0,"diskwrite":0,"netin":0,"netout":0,"maxdisk":8589934592,"uptime":0}]}`,
		)
	}
}

func assertFailedCheck(
	t *testing.T,
	proof discoverysource.ValidationProof,
	kind discoverysource.ValidationCheckKind,
) {
	t.Helper()
	if proof.Outcome != assetcatalog.ValidationOutcomeFailed {
		t.Fatalf("outcome = %q", proof.Outcome)
	}
	if len(proof.Checks) == 0 {
		t.Fatal("failed proof has no checks")
	}
	last := proof.Checks[len(proof.Checks)-1]
	if last.Kind != kind || last.Passed {
		t.Fatalf("last check = %#v, want failed %s", last, kind)
	}
	if err := discoverysource.ValidateValidationResult(
		testValidationRequest(),
		proof,
		nil,
	); err != nil {
		t.Fatalf("failed proof contract: %v", err)
	}
}

func boolPointer(value bool) *bool {
	return &value
}

func testCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99001),
		Subject:               pkix.Name{CommonName: "independent-test-ca.invalid"},
		DNSNames:              []string{"independent-test-ca.invalid"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
