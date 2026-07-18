package proxmox

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	testTenantID      = "11111111-1111-4111-8111-111111111111"
	testWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	testSourceID      = "33333333-3333-4333-8333-333333333333"
	testEnvironmentID = "44444444-4444-4444-8444-444444444444"
	testRevision      = int64(7)
)

var testRevisionDigest = strings.Repeat("a", 64)

func TestProxmoxAdapterExposesOnlyInventoryReads(t *testing.T) {
	typeOfClient := reflect.TypeOf((*InventoryClient)(nil)).Elem()
	want := map[string]reflect.Type{
		"Version": reflect.TypeOf(func(context.Context) (VersionInfo, error) {
			return VersionInfo{}, nil
		}),
		"ClusterStatus": reflect.TypeOf(func(context.Context) (ClusterStatus, error) {
			return ClusterStatus{}, nil
		}),
		"ListNodes": reflect.TypeOf(func(context.Context) ([]Node, error) {
			return nil, nil
		}),
		"ListClusterResources": reflect.TypeOf(func(context.Context) ([]ClusterResource, error) {
			return nil, nil
		}),
	}
	if typeOfClient.NumMethod() != len(want) {
		t.Fatalf("inventory method count = %d, want %d", typeOfClient.NumMethod(), len(want))
	}
	for index := 0; index < typeOfClient.NumMethod(); index++ {
		method := typeOfClient.Method(index)
		signature, found := want[method.Name]
		if !found {
			t.Fatalf("unexpected inventory method %q", method.Name)
		}
		if method.Type != signature {
			t.Fatalf("%s signature = %s, want %s", method.Name, method.Type, signature)
		}
		delete(want, method.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing inventory methods: %#v", want)
	}
}

func TestProviderIdentityRemainsClosedAndUnregistered(t *testing.T) {
	binding := testRuntimeBinding(assetcatalog.SourceRevisionPublished)
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatal(err)
	}
	value, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	if got := value.Kind(); got != assetcatalog.SourceKindProxmox {
		t.Fatalf("Kind() = %q", got)
	}
	if got := value.ProviderKind(); got != "PROXMOX_VE_V1" {
		t.Fatalf("ProviderKind() = %q", got)
	}

	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"internal/sourceprofile",
		"internal/discoveryworker",
		"internal/discoveryruntime",
		"internal/discoveryqueue",
		"internal/discoverylimit",
	} {
		target := filepath.Join(root, path)
		if _, statErr := os.Stat(target); errors.Is(statErr, os.ErrNotExist) {
			continue
		} else if statErr != nil {
			t.Fatalf("stat %s: %v", path, statErr)
		}
		command := exec.Command("rg", "-n", `PROXMOX_VE_V1|proxmox`, target)
		output, commandErr := command.CombinedOutput()
		if commandErr == nil {
			t.Fatalf("Task23 must remain unregistered; %s contains:\n%s", path, output)
		}
		if exit, ok := commandErr.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			t.Fatalf("scan %s: %v\n%s", path, commandErr, output)
		}
	}
}

func TestRuntimeMaterialIsOpaqueOwnedAndClearable(t *testing.T) {
	endpoint, err := NewEndpointHandle("https://pve.test.invalid/api2/json")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(testCertificate(t))
	trust, err := NewTrustHandle(roots, "pve.test.invalid")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("synthetic-token-secret")
	token, err := NewTokenHandle("reader@pve!inventory", secret)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthorityHandle("cluster/alpha", testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewRuntimeMaterial(endpoint, trust, token, authority, 1)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)

	for name, value := range map[string]any{
		"endpoint":  endpoint,
		"trust":     trust,
		"token":     token,
		"authority": authority,
		"runtime":   material,
	} {
		if _, err := json.Marshal(value); !errors.Is(err, discoverysource.ErrSensitiveSerialization) {
			t.Fatalf("%s MarshalJSON error = %v", name, err)
		}
		formatted := fmt.Sprintf("%v %#v", value, value)
		for _, forbidden := range []string{
			"pve.test.invalid",
			"reader@pve",
			"synthetic-token-secret",
			"cluster/alpha",
			testEnvironmentID,
		} {
			if strings.Contains(formatted, forbidden) {
				t.Fatalf("%s formatting leaked %q: %q", name, forbidden, formatted)
			}
		}
		if logger, ok := value.(slog.LogValuer); ok {
			logged := logger.LogValue().String()
			if !strings.Contains(logged, "REDACTED") {
				t.Fatalf("%s LogValue = %q", name, logged)
			}
		}
	}

	snapshot, ok := material.snapshot()
	if !ok {
		t.Fatal("runtime snapshot rejected before clear")
	}
	defer snapshot.Clear()
	if string(snapshot.token.secret) != "synthetic-token-secret" {
		t.Fatal("runtime did not own an independent token copy")
	}
	material.Clear()
	if _, ok := material.snapshot(); ok {
		t.Fatal("cleared material remained active")
	}
	if string(snapshot.token.secret) != "synthetic-token-secret" {
		t.Fatal("clearing source material mutated an existing owned snapshot")
	}
}

func TestBindingDriftIsRejectedBeforeOpeningClient(t *testing.T) {
	binding := testRuntimeBinding(assetcatalog.SourceRevisionPublished)
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatal(err)
	}
	var opens atomic.Int64
	factory.openClient = func(context.Context, resolvedRuntime) (clientSession, error) {
		opens.Add(1)
		return clientSession{}, fmt.Errorf("must not open")
	}
	value, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	material := minimalRuntimeMaterial(t)
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Clear()

	checkpoint, err := discoverysource.NewCheckpoint(profileCode, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Clear()
	request := testDiscoverRequest(checkpoint)
	request.SourceRevisionDigest = strings.Repeat("b", 64)
	outcome, discoverErr := value.Discover(context.Background(), runtime, request)
	if discoverErr == nil || outcome != nil {
		t.Fatalf("drift result = (%#v, %v)", outcome, discoverErr)
	}
	if opens.Load() != 0 {
		t.Fatalf("client opened %d times before binding rejection", opens.Load())
	}
}

func TestPartialClusterCannotCompleteOrAdvanceCheckpoint(t *testing.T) {
	binding := testRuntimeBinding(assetcatalog.SourceRevisionPublished)
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatal(err)
	}
	factory.now = func() time.Time {
		return time.Date(2026, 7, 18, 10, 11, 12, 123456000, time.UTC)
	}
	client := &scriptedInventoryClient{
		version: VersionInfo{Version: "8.4.1", Release: "1", RepoID: "pve"},
		cluster: ClusterStatus{
			Identity:   "cluster/alpha",
			Name:       "alpha",
			Generation: 19,
			Quorate:    true,
			Members: []ClusterMember{
				{Name: "node-a", Online: true},
			},
		},
		nodes: []Node{
			{Name: "node-a", Status: "online", CPUCount: 16, MemoryBytes: 64 << 30},
		},
		resourceErr: clientError(clientFailureIncomplete, "PARTIAL_CLUSTER"),
	}
	factory.openClient = func(context.Context, resolvedRuntime) (clientSession, error) {
		return clientSession{
			client:     client,
			peerDigest: strings.Repeat("c", 64),
			roleDigest: strings.Repeat("d", 64),
			close:      func() {},
		}, nil
	}
	value, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	runtime := bindTestRuntime(t, binding, 42)
	defer runtime.Clear()

	oldCanonical, err := encodeProviderCheckpoint(providerCheckpoint{
		ClusterIdentityDigest: clusterIdentityDigest(client.cluster),
		ClusterGeneration:     18,
		ResourceDigest:        strings.Repeat("b", 64),
		CompletedAt:           "2026-07-18T09:00:00.000000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, oldCanonical)
	clear(oldCanonical)
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Clear()
	request := testDiscoverRequest(checkpoint)
	outcome, err := value.Discover(context.Background(), runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	page, ok := outcome.(discoverysource.Page)
	if !ok {
		t.Fatalf("outcome = %T", outcome)
	}
	defer page.NextCheckpoint.Clear()
	if page.CompleteSnapshot || !page.FinalPage {
		t.Fatalf("partial completion = final:%t complete:%t", page.FinalPage, page.CompleteSnapshot)
	}
	if len(page.Items) != 1 || len(page.Relations) != 0 {
		t.Fatalf("partial facts = %d items, %d relations", len(page.Items), len(page.Relations))
	}
	if page.Items[0].Freshness.OrderSequence != 42 {
		t.Fatalf("partial order sequence = %d, want accepted checkpoint version 42", page.Items[0].Freshness.OrderSequence)
	}
	if !page.NextCheckpoint.Equal(request.Checkpoint) {
		t.Fatal("partial response advanced or rewrote the old checkpoint")
	}
	if err := discoverysource.ValidateDiscoverResult(
		request,
		normalizedFactPolicy(testEnvironmentID),
		page,
		nil,
	); err != nil {
		t.Fatalf("partial page contract: %v", err)
	}
}

func TestNormalizationSortsAndUsesExactRawDigestFraming(t *testing.T) {
	completedAt := time.Date(2026, 7, 18, 10, 11, 12, 123456000, time.UTC)
	snapshot := inventorySnapshot{
		clusterIdentityDigest: strings.Repeat("1a", 32),
		clusterGeneration:     23,
		orderSequence:         41,
		completedAt:           completedAt,
		nodes: []Node{
			{Name: "node-b", Status: "offline", CPUCount: 8, MemoryBytes: 32 << 30},
			{Name: "node-a", Status: "online", CPUCount: 16, MemoryBytes: 64 << 30},
		},
		resources: []ClusterResource{
			{ID: "lxc/202", Type: "lxc", VMID: 202, Name: "ct-b", Node: "node-b", Status: "stopped", CPUCount: 2, MemoryBytes: 2 << 30},
			{ID: "qemu/101", Type: "qemu", VMID: 101, Name: "vm-a", Node: "node-a", Status: "running", CPUCount: 4, MemoryBytes: 8 << 30},
		},
	}
	first, checkpoint, err := normalizeInventory(testEnvironmentID, snapshot, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, secondCheckpoint, err := normalizeInventory(testEnvironmentID, snapshot, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(checkpoint, secondCheckpoint) {
		t.Fatal("identical inventory did not normalize deterministically")
	}
	gotIDs := make([]string, len(first.Items))
	for index, item := range first.Items {
		gotIDs[index] = item.ExternalID
	}
	wantIDs := []string{"lxc/202", "node/node-a", "node/node-b", "qemu/101"}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("item order = %#v, want %#v", gotIDs, wantIDs)
	}
	if len(first.Relations) != 4 {
		t.Fatalf("relations = %d, want 4", len(first.Relations))
	}
	for _, relation := range first.Relations {
		if relation.Type != assetcatalog.RelationshipContains &&
			relation.Type != assetcatalog.RelationshipRunsOn {
			t.Fatalf("unexpected relation type %q", relation.Type)
		}
		if !strings.HasPrefix(relation.ProviderPathCode, "PROXMOX_V1_") {
			t.Fatalf("relation path = %q", relation.ProviderPathCode)
		}
		if relation.Freshness.OrderSequence != snapshot.orderSequence {
			t.Fatalf("relation order = %d", relation.Freshness.OrderSequence)
		}
	}
	if err := assetdiscovery.ValidateFacts(
		first.Items,
		first.Relations,
		normalizedFactPolicy(testEnvironmentID),
	); err != nil {
		t.Fatalf("normalized facts: %v", err)
	}

	resourceDigestBytes, err := hex.DecodeString(checkpoint.ResourceDigest)
	if err != nil {
		t.Fatal(err)
	}
	identityDigestBytes, err := hex.DecodeString(snapshot.clusterIdentityDigest)
	if err != nil {
		t.Fatal(err)
	}
	wantObjectDigest := digestRawFramedTupleForTest(
		"proxmox-object-version.v1",
		identityDigestBytes,
		[]byte("23"),
		resourceDigestBytes,
		[]byte("qemu/101"),
	)
	var qemu assetdiscovery.NormalizedItem
	for _, item := range first.Items {
		if item.ExternalID == "qemu/101" {
			qemu = item
		}
	}
	if qemu.Freshness.ProviderVersionSHA256 != wantObjectDigest {
		t.Fatalf("object version = %q, want %q", qemu.Freshness.ProviderVersionSHA256, wantObjectDigest)
	}
	stableIdentity := ClusterStatus{
		Identity: "cluster/alpha",
		Name:     "alpha",
		Members:  []ClusterMember{{Name: "node-a", Online: true}},
	}
	mutableMembership := stableIdentity
	mutableMembership.Members = []ClusterMember{
		{Name: "node-a", Online: false},
		{Name: "node-b", Online: true},
	}
	if clusterIdentityDigest(stableIdentity) != clusterIdentityDigest(mutableMembership) {
		t.Fatal("mutable node membership changed the immutable cluster identity digest")
	}
}

func TestCheckpointCanonicalizationRejectsUnknownDuplicateAndSensitiveData(t *testing.T) {
	valid := providerCheckpoint{
		ClusterIdentityDigest: strings.Repeat("a", 64),
		ClusterGeneration:     9,
		ResourceDigest:        strings.Repeat("b", 64),
		CompletedAt:           "2026-07-18T10:11:12.123456Z",
	}
	canonical, err := encodeProviderCheckpoint(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeProviderCheckpointCanonical(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != valid {
		t.Fatalf("checkpoint = %#v, want %#v", decoded, valid)
	}
	for name, value := range map[string][]byte{
		"unknown":   []byte(`{"cluster_identity_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cluster_generation":9,"resource_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","completed_at":"2026-07-18T10:11:12.123456Z","token":"x"}`),
		"duplicate": []byte(`{"cluster_identity_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cluster_identity_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cluster_generation":9,"resource_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","completed_at":"2026-07-18T10:11:12.123456Z"}`),
		"trailing":  append(append([]byte{}, canonical...), []byte(` {}`)...),
	} {
		if _, err := decodeProviderCheckpointCanonical(value); err == nil {
			t.Fatalf("%s checkpoint accepted", name)
		}
	}
}

func TestProductionSourceRejectsMutationTerminalAndGenericHTTPReachability(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "internal/assetsource/proxmox")
	production := []string{"profile.go", "client.go", "validate.go", "discover.go", "normalize.go"}
	forbiddenImports := []string{
		"os/exec",
		"net/http/httputil",
		"github.com/gorilla/websocket",
		"internal/discoveryworker",
		"internal/discoveryruntime",
		"internal/discoveryqueue",
		"internal/discoverylimit",
		"internal/sourceprofile",
	}
	forbiddenSelectors := map[string]struct{}{
		"Background": {}, "WithoutCancel": {},
		"Get": {}, "Post": {}, "Put": {}, "Delete": {},
		"Upload": {}, "UploadReader": {},
		"TermProxy": {}, "TermWebSocket": {}, "VNCWebSocket": {},
		"NewVirtualMachine": {}, "NewContainer": {},
		"Start": {}, "Stop": {}, "Shutdown": {}, "Reboot": {},
		"Migrate": {}, "Resize": {},
		"InsecureSkipVerify": {}, "ProxyFromEnvironment": {},
	}
	for _, name := range production {
		path := filepath.Join(directory, name)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, spec := range file.Imports {
			value := strings.Trim(spec.Path.Value, `"`)
			for _, forbidden := range forbiddenImports {
				if value == forbidden || strings.Contains(value, forbidden) {
					t.Fatalf("%s imports forbidden package %q", name, value)
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if _, forbidden := forbiddenSelectors[selector.Sel.Name]; forbidden {
				t.Errorf("%s contains forbidden selector %s", name, selector.Sel.Name)
			}
			if name == "client.go" && selector.Sel.Name == "Clone" {
				t.Errorf("%s contains forbidden SDK mutation selector Clone", name)
			}
			return true
		})
	}
}

type scriptedInventoryClient struct {
	version       VersionInfo
	cluster       ClusterStatus
	nodes         []Node
	resources     []ClusterResource
	versionErr    error
	clusterErr    error
	nodesErr      error
	resourceErr   error
	versionCalls  atomic.Int64
	clusterCalls  atomic.Int64
	nodesCalls    atomic.Int64
	resourceCalls atomic.Int64
}

func (client *scriptedInventoryClient) Version(context.Context) (VersionInfo, error) {
	client.versionCalls.Add(1)
	return client.version, client.versionErr
}

func (client *scriptedInventoryClient) ClusterStatus(context.Context) (ClusterStatus, error) {
	client.clusterCalls.Add(1)
	return client.cluster, client.clusterErr
}

func (client *scriptedInventoryClient) ListNodes(context.Context) ([]Node, error) {
	client.nodesCalls.Add(1)
	return slices.Clone(client.nodes), client.nodesErr
}

func (client *scriptedInventoryClient) ListClusterResources(context.Context) ([]ClusterResource, error) {
	client.resourceCalls.Add(1)
	return slices.Clone(client.resources), client.resourceErr
}

func testRuntimeBinding(status assetcatalog.SourceRevisionStatus) discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID:    testTenantID,
				WorkspaceID: testWorkspaceID,
			},
			SourceID: testSourceID,
		},
		SourceRevision:       testRevision,
		SourceRevisionDigest: testRevisionDigest,
		RevisionStatus:       status,
		ProviderKind:         "PROXMOX_VE_V1",
		ProfileCode:          assetcatalog.ProfileCode("PROXMOX_VE_V1"),
	}
}

func testDiscoverRequest(checkpoint discoverysource.Checkpoint) discoverysource.DiscoverRequest {
	binding := testRuntimeBinding(assetcatalog.SourceRevisionPublished)
	return discoverysource.DiscoverRequest{
		Locator:              binding.Locator,
		SourceRevision:       binding.SourceRevision,
		SourceRevisionDigest: binding.SourceRevisionDigest,
		Checkpoint:           checkpoint,
		Limits:               testLimits(),
	}
}

func testValidationRequest() discoverysource.ValidationRequest {
	binding := testRuntimeBinding(assetcatalog.SourceRevisionValidating)
	return discoverysource.ValidationRequest{
		Locator:              binding.Locator,
		SourceRevision:       binding.SourceRevision,
		SourceRevisionDigest: binding.SourceRevisionDigest,
		Limits:               testLimits(),
	}
}

func testLimits() discoverysource.Limits {
	return discoverysource.Limits{
		MaxPageItems:     10_000,
		MaxPageRelations: 20_000,
		MaxPageBytes:     16 << 20,
		MaxDocumentBytes: 64 << 10,
	}
}

func minimalRuntimeMaterial(t *testing.T, acceptedSequence ...int64) RuntimeMaterial {
	t.Helper()
	sequence := int64(1)
	if len(acceptedSequence) == 1 {
		sequence = acceptedSequence[0]
	} else if len(acceptedSequence) > 1 {
		t.Fatal("at most one accepted checkpoint sequence is allowed")
	}
	endpoint, err := NewEndpointHandle("https://pve.test.invalid/api2/json")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(testCertificate(t))
	trust, err := NewTrustHandle(roots, "pve.test.invalid")
	if err != nil {
		t.Fatal(err)
	}
	token, err := NewTokenHandle("reader@pve!inventory", []byte("synthetic-token-secret"))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthorityHandle("cluster/alpha", testEnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewRuntimeMaterial(endpoint, trust, token, authority, sequence)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func bindTestRuntime(
	t *testing.T,
	binding discoverysource.RuntimeBinding,
	acceptedSequence ...int64,
) discoverysource.BoundRuntime {
	t.Helper()
	material := minimalRuntimeMaterial(t, acceptedSequence...)
	runtime, err := discoverysource.BindRuntime(
		binding,
		&material,
		func(*RuntimeMaterial) error { return nil },
		func(value *RuntimeMaterial) { value.Clear() },
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("repository root not found")
		}
		directory = parent
	}
}

func digestRawFramedTupleForTest(domain string, fields ...[]byte) string {
	hasher := sha256.New()
	for _, value := range append([][]byte{[]byte(domain)}, fields...) {
		_, _ = hasher.Write([]byte{1})
		length := []byte{
			byte(len(value) >> 24),
			byte(len(value) >> 16),
			byte(len(value) >> 8),
			byte(len(value)),
		}
		_, _ = hasher.Write(length)
		_, _ = hasher.Write(value)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
