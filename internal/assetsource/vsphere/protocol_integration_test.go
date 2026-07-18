package vsphere

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/leasefence"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/types"
)

func TestProtocolIntegrationFullInventoryUsesTLSRetrieveAndSameSessionContinue(t *testing.T) {
	model := simulator.VPX()
	model.ClusterHost = 1
	model.Host = 0
	model.Machine = 501
	if err := model.Create(); err != nil {
		t.Fatalf("create simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpointURL := *server.URL
	user := endpointURL.User
	endpointURL.User = nil
	if user == nil {
		t.Fatal("simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok || password == "" {
		t.Fatal("simulator URL has no password")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	endpoint, err := NewEndpointHandle(endpointURL.String())
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle(user.Username(), []byte(password))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: endpointURL.Hostname(),
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		model.ServiceContent.About.InstanceUuid,
		testEnvironmentID,
		[]types.ManagedObjectReference{model.RootFolder.Reference()},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}

	request := validInventoryRequest(t)
	binding := publishedInventoryBinding(request)
	attempt, err := NewFullInventoryAttempt(&material)
	if err != nil {
		t.Fatalf("NewFullInventoryAttempt() error = %v", err)
	}
	t.Cleanup(attempt.Destroy)
	runtime, err := attempt.BindRuntime(context.Background(), binding)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	var methodMu sync.Mutex
	var methods []string
	factory.observeMethod = func(method string) {
		methodMu.Lock()
		methods = append(methods, method)
		methodMu.Unlock()
	}
	provider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var (
		pageCount int
		itemCount int
	)
	for {
		outcome, discoverErr := provider.Discover(context.Background(), runtime, request)
		if discoverErr != nil {
			methodMu.Lock()
			calledMethods := slices.Clone(methods)
			methodMu.Unlock()
			t.Fatalf(
				"Discover(page %d) error = %v; SOAP methods = %v",
				pageCount+1,
				discoverErr,
				calledMethods,
			)
		}
		page, ok := outcome.(discoverysource.Page)
		if !ok {
			t.Fatalf("Discover(page %d) outcome = %T, want Page", pageCount+1, outcome)
		}
		if err := discoverysource.ValidateDiscoverResult(
			request,
			inventoryFactPolicy(testEnvironmentID),
			page,
			nil,
		); err != nil {
			t.Fatalf("Discover(page %d) violates contract: %v", pageCount+1, err)
		}
		pageCount++
		itemCount += len(page.Items)
		request.Checkpoint.Clear()
		request.Checkpoint = page.NextCheckpoint.Clone()
		final := page.FinalPage
		page.NextCheckpoint.Clear()
		if final {
			break
		}
	}
	request.Checkpoint.Clear()
	if pageCount < 2 || itemCount <= 500 {
		t.Fatalf("full inventory pages/items = %d/%d, want paged inventory >500", pageCount, itemCount)
	}
	if err := attempt.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	methodMu.Lock()
	gotMethods := slices.Clone(methods)
	methodMu.Unlock()
	if len(gotMethods) < 5 ||
		gotMethods[0] != "RetrieveServiceContent" ||
		gotMethods[1] != "Login" ||
		!slices.Contains(gotMethods, "RetrievePropertiesEx") ||
		!slices.Contains(gotMethods, "ContinueRetrievePropertiesEx") ||
		gotMethods[len(gotMethods)-1] != "Logout" {
		t.Fatalf("SOAP methods = %v", gotMethods)
	}
	for _, forbidden := range []string{
		"PowerOnVM_Task",
		"PowerOffVM_Task",
		"ReconfigVM_Task",
		"WaitForUpdatesEx",
	} {
		if slices.Contains(gotMethods, forbidden) {
			t.Fatalf("Task 21A invoked forbidden SOAP method %s: %v", forbidden, gotMethods)
		}
	}
}

func TestProtocolIntegrationCompleteSnapshotIsSingleEnvironment(t *testing.T) {
	request := validInventoryRequest(t)
	policy := inventoryFactPolicy(testEnvironmentID)
	if policy.EnvironmentMapping != assetcatalog.EnvironmentMappingSingle ||
		!slices.Equal(policy.AuthorityEnvironmentIDs, []string{testEnvironmentID}) {
		t.Fatalf("inventory policy = %#v", policy)
	}
	request.Checkpoint.Clear()
}

func TestProtocolIntegrationStandaloneComputeResourceAndDistributedNetworking(
	t *testing.T,
) {
	model := simulator.VPX()
	model.Machine = 1
	provider, attempt, runtime, request := newTLSProtocolInventoryFixture(t, model)
	t.Cleanup(attempt.Destroy)

	var items []assetdiscovery.NormalizedItem
	var relations []assetdiscovery.ObservedRelation
	for {
		outcome, err := provider.Discover(context.Background(), runtime, request)
		if err != nil {
			t.Fatalf("Discover() error = %v", err)
		}
		page, ok := outcome.(discoverysource.Page)
		if !ok {
			t.Fatalf("Discover() outcome = %T, want Page", outcome)
		}
		items = append(items, page.Items...)
		relations = append(relations, page.Relations...)
		request.Checkpoint.Clear()
		request.Checkpoint = page.NextCheckpoint.Clone()
		final := page.FinalPage
		page.NextCheckpoint.Clear()
		if final {
			break
		}
	}
	request.Checkpoint.Clear()

	var (
		clusterItem        bool
		folderHost         bool
		folderResourcePool bool
		datacenterVM       bool
	)
	for _, item := range items {
		if strings.Contains(item.ExternalID, ":ComputeResource:") &&
			!strings.Contains(item.ExternalID, ":ClusterComputeResource:") {
			t.Fatalf("plain ComputeResource projected as item %#v", item)
		}
		if strings.Contains(item.ExternalID, ":DistributedVirtual") {
			t.Fatalf("distributed networking projected as item %#v", item)
		}
		clusterItem = clusterItem ||
			strings.Contains(item.ExternalID, ":ClusterComputeResource:")
	}
	for _, relation := range relations {
		for _, endpoint := range []string{relation.FromExternalID, relation.ToExternalID} {
			if strings.Contains(endpoint, ":ComputeResource:") &&
				!strings.Contains(endpoint, ":ClusterComputeResource:") {
				t.Fatalf("plain ComputeResource persisted as relation endpoint %#v", relation)
			}
			if strings.Contains(endpoint, ":DistributedVirtual") {
				t.Fatalf("distributed networking persisted as relation endpoint %#v", relation)
			}
		}
		folderHost = folderHost ||
			strings.Contains(relation.FromExternalID, ":Folder:") &&
				strings.Contains(relation.ToExternalID, ":HostSystem:")
		folderResourcePool = folderResourcePool ||
			strings.Contains(relation.FromExternalID, ":Folder:") &&
				strings.Contains(relation.ToExternalID, ":ResourcePool:")
		datacenterVM = datacenterVM ||
			strings.Contains(relation.FromExternalID, ":Datacenter:") &&
				strings.Contains(relation.ToExternalID, ":VirtualMachine:")
	}
	if !clusterItem || !folderHost || !folderResourcePool || !datacenterVM {
		t.Fatalf(
			"simulator topology = cluster:%t folder-host:%t folder-pool:%t datacenter-vm:%t",
			clusterItem,
			folderHost,
			folderResourcePool,
			datacenterVM,
		)
	}
}

func TestProtocolIntegrationRolloverHandoffLogsOutAndStartsFreshRetrieve(t *testing.T) {
	model := simulator.VPX()
	model.ClusterHost = 1
	model.Host = 0
	model.Machine = 1
	if err := model.Create(); err != nil {
		t.Fatalf("create simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpointURL := *server.URL
	user := endpointURL.User
	endpointURL.User = nil
	if user == nil {
		t.Fatal("simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok || password == "" {
		t.Fatal("simulator URL has no password")
	}
	newMaterial := func() RuntimeMaterial {
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		endpoint, err := NewEndpointHandle(endpointURL.String())
		if err != nil {
			t.Fatalf("NewEndpointHandle() error = %v", err)
		}
		credential, err := NewCredentialHandle(user.Username(), []byte(password))
		if err != nil {
			t.Fatalf("NewCredentialHandle() error = %v", err)
		}
		trust, err := NewTrustHandle(&tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
			ServerName: endpointURL.Hostname(),
		}, TLSCompatibilityStrict)
		if err != nil {
			t.Fatalf("NewTrustHandle() error = %v", err)
		}
		authority, err := NewAuthorityHandle(
			model.ServiceContent.About.InstanceUuid,
			testEnvironmentID,
			[]types.ManagedObjectReference{model.RootFolder.Reference()},
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

	request := validInventoryRequest(t)
	request.Limits.MaxPageItems = 1
	binding := publishedInventoryBinding(request)
	factory, err := NewClientFactory(binding)
	if err != nil {
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	var methodMu sync.Mutex
	var methods []string
	factory.observeMethod = func(method string) {
		methodMu.Lock()
		methods = append(methods, method)
		methodMu.Unlock()
	}
	provider, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rolloverAuthority := NewFullInventoryRolloverAuthority()
	t.Cleanup(rolloverAuthority.Destroy)
	material := newMaterial()
	openRequest := discoverycleanup.OpenAttemptRequest{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: request.Locator.Scope,
			RunID: "8a300000-0000-4000-8000-000000000001",
		},
		Attempt: discoveryqueue.CleanupAttempt{
			RunID:        "8a300000-0000-4000-8000-000000000001",
			AttemptID:    "8a300000-0000-4000-8000-000000000002",
			AttemptEpoch: 1,
		},
	}
	opener := &rolloverHandoffOpener{
		authority: rolloverAuthority,
		material:  &material,
	}
	proofAuthority := &rolloverHandoffProofAuthority{
		key: []byte("task21a-protocol-rollover-proof-key"),
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
		t.Fatalf("protocol rollover predecessor closed snapshot: %#v", partial)
	}
	defer partial.NextCheckpoint.Clear()
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
	const fenceOwner = "task21a-protocol-rollover-owner"
	fence, err := leasefence.FromQueueClaim(
		openRequest.Coordinates.RunID,
		fenceOwner,
		1,
		&rawFence,
	)
	if err != nil {
		t.Fatalf("FromQueueClaim() error = %v", err)
	}
	defer fence.Destroy()
	queue := &rolloverAdmissionQueue{
		verifier:       rolloverAuthority,
		fence:          fence,
		fenceOwner:     fenceOwner,
		fenceEpoch:     1,
		fenceTokenSHA:  hex.EncodeToString(fenceTokenDigest[:]),
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
			GateRevision:   9,
		},
	}
	handoff, _, err := rolloverAuthority.BeginHandoff(
		context.Background(),
		queue,
		fence,
		openRequest,
		command,
		accepted,
		partial.NextCheckpoint,
	)
	if err != nil {
		t.Fatalf("BeginHandoff() error = %v", err)
	}
	defer handoff.Destroy()
	methodMu.Lock()
	methodsBeforeFreeze := slices.Clone(methods)
	methodMu.Unlock()
	frozenRequest := request
	frozenRequest.Checkpoint = partial.NextCheckpoint.Clone()
	if outcome, discoverErr := provider.Discover(
		context.Background(),
		runtime,
		frozenRequest,
	); outcome != nil || !errors.Is(discoverErr, errInventoryContinuity) {
		frozenRequest.Checkpoint.Clear()
		t.Fatalf(
			"Discover(predecessor after handoff mint) = (%#v,%v)",
			outcome,
			discoverErr,
		)
	}
	frozenRequest.Checkpoint.Clear()
	if rebound, bindErr := opener.attempt.BindRuntime(
		context.Background(),
		binding,
	); rebound != (discoverysource.BoundRuntime{}) ||
		!errors.Is(bindErr, errInventoryContinuity) {
		t.Fatalf(
			"BindRuntime(predecessor after handoff mint) = (%#v,%v)",
			rebound,
			bindErr,
		)
	}
	methodMu.Lock()
	methodsAfterFreeze := slices.Clone(methods)
	methodMu.Unlock()
	if !slices.Equal(methodsAfterFreeze, methodsBeforeFreeze) {
		t.Fatalf(
			"handoff mint allowed predecessor SOAP: before=%v after=%v",
			methodsBeforeFreeze,
			methodsAfterFreeze,
		)
	}
	proof, err := broker.RevokeAttempt(
		context.Background(),
		openRequest.Attempt.AttemptID,
	)
	if err != nil {
		t.Fatalf("RevokeAttempt() error = %v", err)
	}
	proof.Destroy()
	oldRequest := request
	oldRequest.Checkpoint = partial.NextCheckpoint.Clone()
	if outcome, discoverErr := provider.Discover(
		context.Background(),
		runtime,
		oldRequest,
	); outcome != nil || discoverErr == nil {
		oldRequest.Checkpoint.Clear()
		t.Fatalf("Discover(old runtime) = (%#v,%v)", outcome, discoverErr)
	}
	oldRequest.Checkpoint.Clear()

	successorMaterial := newMaterial()
	successor, err := handoff.NewSuccessor(
		context.Background(),
		queue,
		fence,
		&successorMaterial,
		partial.NextCheckpoint,
	)
	if err != nil {
		t.Fatalf("NewSuccessor() error = %v", err)
	}
	successorRuntime, err := successor.BindRuntime(context.Background(), binding)
	if err != nil {
		successor.Destroy()
		t.Fatalf("BindRuntime(successor) error = %v", err)
	}
	successorRequest := request
	successorRequest.Checkpoint = partial.NextCheckpoint.Clone()
	successorPage := discoverInventoryPage(
		t,
		provider,
		successorRuntime,
		successorRequest,
	)
	successorRequest.Checkpoint.Clear()
	successorPage.NextCheckpoint.Clear()
	successor.Destroy()

	methodMu.Lock()
	gotMethods := slices.Clone(methods)
	methodMu.Unlock()
	if countProtocolMethod(gotMethods, "Login") != 2 ||
		countProtocolMethod(gotMethods, "Logout") != 2 {
		t.Fatalf("rollover Login/Logout methods = %v", gotMethods)
	}
	secondLogin := nthProtocolMethod(gotMethods, "Login", 2)
	firstLogout := nthProtocolMethod(gotMethods, "Logout", 1)
	if secondLogin < 0 || firstLogout < 0 || firstLogout > secondLogin {
		t.Fatalf("rollover session order = %v", gotMethods)
	}
	firstSuccessorDataMethod := ""
	for _, method := range gotMethods[secondLogin+1:] {
		if method == "RetrievePropertiesEx" ||
			method == "ContinueRetrievePropertiesEx" {
			firstSuccessorDataMethod = method
			break
		}
	}
	if firstSuccessorDataMethod != "RetrievePropertiesEx" {
		t.Fatalf(
			"successor first data SOAP method = %q, methods %v",
			firstSuccessorDataMethod,
			gotMethods,
		)
	}
}

func newTLSProtocolInventoryFixture(
	t *testing.T,
	model *simulator.Model,
) (
	discoverysource.Provider,
	*FullInventoryAttempt,
	discoverysource.BoundRuntime,
	discoverysource.DiscoverRequest,
) {
	t.Helper()
	if err := model.Create(); err != nil {
		t.Fatalf("create simulator model: %v", err)
	}
	t.Cleanup(model.Remove)
	model.Service.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server := model.Service.NewServer()
	t.Cleanup(server.Close)

	endpointURL := *server.URL
	user := endpointURL.User
	endpointURL.User = nil
	if user == nil {
		t.Fatal("simulator URL has no credential")
	}
	password, ok := user.Password()
	if !ok || password == "" {
		t.Fatal("simulator URL has no password")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	endpoint, err := NewEndpointHandle(endpointURL.String())
	if err != nil {
		t.Fatalf("NewEndpointHandle() error = %v", err)
	}
	credential, err := NewCredentialHandle(user.Username(), []byte(password))
	if err != nil {
		t.Fatalf("NewCredentialHandle() error = %v", err)
	}
	trust, err := NewTrustHandle(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: endpointURL.Hostname(),
	}, TLSCompatibilityStrict)
	if err != nil {
		t.Fatalf("NewTrustHandle() error = %v", err)
	}
	authority, err := NewAuthorityHandle(
		model.ServiceContent.About.InstanceUuid,
		testEnvironmentID,
		[]types.ManagedObjectReference{model.RootFolder.Reference()},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	material, err := NewRuntimeMaterial(endpoint, credential, trust, authority)
	if err != nil {
		t.Fatalf("NewRuntimeMaterial() error = %v", err)
	}
	request := validInventoryRequest(t)
	binding := publishedInventoryBinding(request)
	attempt, err := NewFullInventoryAttempt(&material)
	if err != nil {
		t.Fatalf("NewFullInventoryAttempt() error = %v", err)
	}
	runtime, err := attempt.BindRuntime(context.Background(), binding)
	if err != nil {
		attempt.Destroy()
		t.Fatalf("BindRuntime() error = %v", err)
	}
	factory, err := NewClientFactory(binding)
	if err != nil {
		attempt.Destroy()
		t.Fatalf("NewClientFactory() error = %v", err)
	}
	provider, err := New(factory)
	if err != nil {
		attempt.Destroy()
		t.Fatalf("New() error = %v", err)
	}
	return provider, attempt, runtime, request
}

func countProtocolMethod(methods []string, target string) int {
	count := 0
	for _, method := range methods {
		if method == target {
			count++
		}
	}
	return count
}

func nthProtocolMethod(methods []string, target string, ordinal int) int {
	seen := 0
	for index, method := range methods {
		if method != target {
			continue
		}
		seen++
		if seen == ordinal {
			return index
		}
	}
	return -1
}
