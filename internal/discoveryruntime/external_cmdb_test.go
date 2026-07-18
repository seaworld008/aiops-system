package discoveryruntime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/discoveryworker"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const (
	runtimeTenantID      = "61000000-0000-4000-8000-000000000001"
	runtimeWorkspaceID   = "62000000-0000-4000-8000-000000000002"
	runtimeSourceID      = "63000000-0000-4000-8000-000000000003"
	runtimeRunID         = "64000000-0000-4000-8000-000000000004"
	runtimeAttemptID     = "65000000-0000-4000-8000-000000000005"
	runtimeEnvironmentID = "66000000-0000-4000-8000-000000000006"
	runtimeIntegrationID = "67000000-0000-4000-8000-000000000007"
	runtimeRevisionSHA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runtimeDefinitionSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	runtimeCredentialReference = "external-cmdb-runtime-credential"
	runtimeTrustReference      = "external-cmdb-runtime-trust"
	runtimeNetworkReference    = "external-cmdb-runtime-network"

	runtimeSecretEndpoint = "https://runtime-secret.invalid"
	runtimeSecretToken    = "runtime-secret-token"
	runtimeSecretCA       = "runtime-secret-ca"
)

func TestExternalCMDBAuthorityResolvesMaterialOnceAndClaimUsesOpenedCellOnly(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	references := &recordingReferenceResolver{snapshot: snapshot}
	materials := &recordingMaterialResolver{want: snapshot}
	authority, err := newExternalCMDBAuthority(references, materials)
	if err != nil {
		t.Fatalf("newExternalCMDBAuthority() error = %v", err)
	}
	t.Cleanup(authority.Destroy)

	open := runtimeOpenAttemptRequest()
	first, err := authority.ResolveRuntimeBinding(t.Context(), open)
	if err != nil || first != snapshot.binding {
		t.Fatalf("ResolveRuntimeBinding(first) = %#v,%v", first, err)
	}
	replay, err := authority.ResolveRuntimeBinding(t.Context(), open)
	if err != nil || replay != first {
		t.Fatalf("ResolveRuntimeBinding(replay) = %#v,%v", replay, err)
	}
	if references.calls != 2 || materials.calls != 0 {
		t.Fatalf("resolver calls before materialization = refs:%d material:%d", references.calls, materials.calls)
	}

	key, err := newExternalCMDBAttemptKey(open)
	if err != nil {
		t.Fatalf("newExternalCMDBAttemptKey() error = %v", err)
	}
	bound, lifecycle, err := authority.materialize(t.Context(), key, first)
	if err != nil || bound.Binding() != first || lifecycle == nil {
		t.Fatalf("materialize() = %#v,%#v,%v", bound, lifecycle, err)
	}
	if materials.calls != 1 {
		t.Fatalf("material resolver calls = %d, want 1", materials.calls)
	}
	if err := discoverysource.WithRuntime[externalcmdb.RuntimeMaterial](
		bound,
		first,
		func(material *externalcmdb.RuntimeMaterial) error {
			if material.BaseURL != runtimeSecretEndpoint ||
				string(material.BearerToken) != runtimeSecretToken ||
				material.EnvironmentID != runtimeEnvironmentID {
				return errors.New("resolved material drift")
			}
			return nil
		},
	); err != nil {
		t.Fatalf("WithRuntime() error = %v", err)
	}
	if second, secondLifecycle, secondErr := authority.materialize(
		t.Context(), key, first,
	); second.Binding() != (discoverysource.RuntimeBinding{}) ||
		secondLifecycle != nil ||
		!errors.Is(secondErr, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("second materialize = %#v,%#v,%v", second, secondLifecycle, secondErr)
	}
	if materials.calls != 1 {
		t.Fatalf("second materialize called resolver %d times", materials.calls)
	}
	responseReplay, err := authority.ResolveRuntimeBinding(t.Context(), open)
	if err != nil || responseReplay != first || materials.calls != 1 {
		t.Fatalf(
			"response-loss binding replay = %#v,%v material calls=%d",
			responseReplay,
			err,
			materials.calls,
		)
	}

	provider, checkpoint, limits, policy, err := authority.claimComponents(
		t.Context(),
		key,
		first,
		assetcatalog.RunKindValidation,
		0,
		"",
		nil,
	)
	if err != nil || provider == nil || checkpoint == nil ||
		provider.ProviderKind() != snapshot.binding.ProviderKind ||
		!checkpoint.IsEmpty() ||
		limits != snapshot.limits ||
		policy.ProviderKind != snapshot.binding.ProviderKind {
		if checkpoint != nil {
			checkpoint.Clear()
		}
		t.Fatalf(
			"claimComponents() = provider:%#v checkpoint:%#v limits:%#v policy:%#v err:%v",
			provider,
			checkpoint,
			limits,
			policy,
			err,
		)
	}
	checkpoint.Clear()
	if references.calls != 5 || materials.calls != 1 {
		t.Fatalf("claim path reopened resolver = refs:%d material:%d", references.calls, materials.calls)
	}

	bound.Clear()
	if err := lifecycle.Revoke(t.Context()); err != nil {
		t.Fatalf("runtime lifecycle Revoke() error = %v", err)
	}
	lifecycle.Destroy()
	if materials.revokeCalls != 1 || materials.destroyCalls != 1 ||
		!materials.ownedMaterialCleared() {
		t.Fatalf(
			"material lifecycle revoke/destroy/clear = %d/%d/%t",
			materials.revokeCalls,
			materials.destroyCalls,
			materials.ownedMaterialCleared(),
		)
	}
	if replay, replayErr := authority.ResolveRuntimeBinding(
		t.Context(),
		open,
	); replay != (discoverysource.RuntimeBinding{}) ||
		!errors.Is(replayErr, ErrExternalCMDBRuntimeAuthority) ||
		materials.calls != 1 {
		t.Fatalf(
			"destroyed attempt replay = %#v,%v material calls=%d",
			replay,
			replayErr,
			materials.calls,
		)
	}
}

func TestExternalCMDBAuthorityOpensPersistedDiscoveryCheckpointFromCell(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	snapshot.runKind = assetcatalog.RunKindDiscovery
	snapshot.binding.RevisionStatus = assetcatalog.SourceRevisionPublished
	var master [32]byte
	for index := range master {
		master[index] = byte(index + 1)
	}
	keyring, err := discoverycheckpoint.NewInMemoryKeyring(
		"external-cmdb-runtime-checkpoint-v1",
		map[string][32]byte{
			"external-cmdb-runtime-checkpoint-v1": master,
		},
	)
	if err != nil {
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	t.Cleanup(keyring.Destroy)
	codec, err := discoverycheckpoint.NewCheckpointCodec(keyring)
	if err != nil {
		t.Fatalf("NewCheckpointCodec() error = %v", err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(
		snapshot.binding.ProfileCode,
		[]byte(`{"cursor":"opaque-provider-cursor"}`),
	)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	sealed, err := codec.Seal(
		t.Context(),
		discoverycheckpoint.CheckpointAAD{
			TenantID:                snapshot.binding.Locator.Scope.TenantID,
			WorkspaceID:             snapshot.binding.Locator.Scope.WorkspaceID,
			SourceID:                snapshot.binding.Locator.SourceID,
			ProviderKind:            snapshot.binding.ProviderKind,
			CheckpointRevision:      snapshot.binding.SourceRevision,
			CanonicalRevisionDigest: snapshot.binding.SourceRevisionDigest,
			SourceDefinitionDigest:  snapshot.sourceDefinitionSHA256,
			CheckpointKeyID:         "external-cmdb-runtime-checkpoint-v1",
			CheckpointVersion:       1,
		},
		checkpoint,
	)
	checkpoint.Clear()
	if err != nil {
		t.Fatalf("CheckpointCodec.Seal() error = %v", err)
	}
	defer clear(sealed.Envelope)
	snapshot.sealedCheckpoint = sealed.Clone()
	snapshot.checkpointVersion = 1
	snapshot.checkpointSHA256 = sealed.CheckpointSHA256

	references := &recordingReferenceResolver{snapshot: snapshot}
	materials := &recordingMaterialResolver{want: snapshot}
	authority, err := newExternalCMDBAuthority(references, materials)
	if err != nil {
		t.Fatalf("newExternalCMDBAuthority() error = %v", err)
	}
	t.Cleanup(authority.Destroy)
	binding, err := authority.ResolveRuntimeBinding(
		t.Context(),
		runtimeOpenAttemptRequest(),
	)
	if err != nil {
		t.Fatalf("ResolveRuntimeBinding() error = %v", err)
	}
	key, _ := newExternalCMDBAttemptKey(runtimeOpenAttemptRequest())
	bound, lifecycle, err := authority.materialize(t.Context(), key, binding)
	if err != nil {
		t.Fatalf("materialize() error = %v", err)
	}
	provider, opened, limits, policy, err := authority.claimComponents(
		t.Context(),
		key,
		binding,
		assetcatalog.RunKindDiscovery,
		1,
		sealed.CheckpointSHA256,
		codec,
	)
	if err != nil || provider == nil || opened == nil || opened.IsEmpty() ||
		limits != snapshot.limits ||
		policy.ProviderKind != snapshot.binding.ProviderKind ||
		references.calls != 3 || materials.calls != 1 {
		if opened != nil {
			opened.Clear()
		}
		t.Fatalf(
			"persisted claim = provider:%#v checkpoint:%#v refs:%d material:%d err:%v",
			provider,
			opened,
			references.calls,
			materials.calls,
			err,
		)
	}
	opened.Clear()
	bound.Clear()
	if err := lifecycle.Revoke(t.Context()); err != nil {
		t.Fatalf("lifecycle.Revoke() error = %v", err)
	}
	lifecycle.Destroy()
}

func TestExternalCMDBAuthorityRejectsTupleReferenceAndBindingDriftBeforeMaterial(t *testing.T) {
	base := validExternalCMDBAttemptSnapshot(t)
	tests := map[string]func(*externalCMDBAttemptSnapshot, *discoverycleanup.OpenAttemptRequest){
		"scope": func(_ *externalCMDBAttemptSnapshot, request *discoverycleanup.OpenAttemptRequest) {
			request.Coordinates.Scope.WorkspaceID = "68000000-0000-4000-8000-000000000008"
		},
		"run": func(_ *externalCMDBAttemptSnapshot, request *discoverycleanup.OpenAttemptRequest) {
			request.Coordinates.RunID = "69000000-0000-4000-8000-000000000009"
			request.Attempt.RunID = request.Coordinates.RunID
		},
		"attempt": func(_ *externalCMDBAttemptSnapshot, request *discoverycleanup.OpenAttemptRequest) {
			request.Attempt.AttemptID = "6a000000-0000-4000-8000-00000000000a"
		},
		"epoch": func(_ *externalCMDBAttemptSnapshot, request *discoverycleanup.OpenAttemptRequest) {
			request.Attempt.AttemptEpoch++
		},
		"integration reference": func(snapshot *externalCMDBAttemptSnapshot, _ *discoverycleanup.OpenAttemptRequest) {
			snapshot.references.integrationID = "6b000000-0000-4000-8000-00000000000b"
		},
		"credential reference": func(snapshot *externalCMDBAttemptSnapshot, _ *discoverycleanup.OpenAttemptRequest) {
			snapshot.references.credentialReferenceID = "drifted-credential-reference"
		},
		"trust reference": func(snapshot *externalCMDBAttemptSnapshot, _ *discoverycleanup.OpenAttemptRequest) {
			snapshot.references.trustReferenceID = "drifted-trust-reference"
		},
		"network reference": func(snapshot *externalCMDBAttemptSnapshot, _ *discoverycleanup.OpenAttemptRequest) {
			snapshot.references.networkPolicyReferenceID = "drifted-network-reference"
		},
		"binding": func(snapshot *externalCMDBAttemptSnapshot, _ *discoverycleanup.OpenAttemptRequest) {
			snapshot.binding.SourceRevisionDigest = strings.Repeat("c", 64)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			initial := base.clone()
			references := &recordingReferenceResolver{snapshot: initial}
			materials := &recordingMaterialResolver{want: initial}
			authority, err := newExternalCMDBAuthority(references, materials)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(authority.Destroy)
			open := runtimeOpenAttemptRequest()
			binding, err := authority.ResolveRuntimeBinding(t.Context(), open)
			if err != nil {
				t.Fatalf("initial ResolveRuntimeBinding() error = %v", err)
			}

			drifted := initial.clone()
			driftedOpen := open
			mutate(&drifted, &driftedOpen)
			references.snapshot = drifted
			if resolved, resolveErr := authority.ResolveRuntimeBinding(
				t.Context(), driftedOpen,
			); resolved != (discoverysource.RuntimeBinding{}) ||
				!errors.Is(resolveErr, ErrExternalCMDBRuntimeAuthority) {
				t.Fatalf("drifted ResolveRuntimeBinding() = %#v,%v", resolved, resolveErr)
			}
			key, _ := newExternalCMDBAttemptKey(open)
			if bound, lifecycle, materialErr := authority.materialize(
				t.Context(), key, binding,
			); materialErr == nil {
				bound.Clear()
				if lifecycle != nil {
					lifecycle.Destroy()
				}
				t.Fatal("drifted snapshot remained materializable")
			}
			if materials.calls != 0 {
				t.Fatalf("drift reached material resolver: %d calls", materials.calls)
			}
		})
	}
}

func TestExternalCMDBAuthorityAllowsClosedRecoveryBindingButNeverMaterializes(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	snapshot.initialAllowed = false
	references := &recordingReferenceResolver{snapshot: snapshot}
	materials := &recordingMaterialResolver{want: snapshot}
	authority, err := newExternalCMDBAuthority(references, materials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.Destroy)
	binding, err := authority.ResolveRuntimeBinding(
		t.Context(),
		runtimeOpenAttemptRequest(),
	)
	if err != nil || binding != snapshot.binding {
		t.Fatalf("closed recovery binding = %#v,%v", binding, err)
	}
	key, _ := newExternalCMDBAttemptKey(runtimeOpenAttemptRequest())
	runtime, lifecycle, err := authority.materialize(t.Context(), key, binding)
	runtime.Clear()
	if lifecycle != nil {
		lifecycle.Destroy()
	}
	if !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("closed recovery materialize() error = %v", err)
	}
	if materials.calls != 0 {
		t.Fatalf(
			"closed recovery reached material resolver: %d calls",
			materials.calls,
		)
	}
}

func TestExternalCMDBAuthorityRejectRelatedReadsCellSnapshotUnderLock(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	const relatedAttemptID = "6d000000-0000-4000-8000-00000000000d"
	snapshot.key.attempt.AttemptID = relatedAttemptID
	cell := &externalCMDBAttemptCell{snapshot: snapshot}
	private := &externalCMDBAuthorityState{
		attempts: map[string]*externalCMDBAttemptCell{
			relatedAttemptID: cell,
		},
	}
	key, _ := newExternalCMDBAttemptKey(runtimeOpenAttemptRequest())
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		for range 10_000 {
			private.rejectRelated(key)
		}
	}()
	go func() {
		defer wait.Done()
		<-start
		for index := range 10_000 {
			cell.mu.Lock()
			if index%2 == 0 {
				cell.snapshot = externalCMDBAttemptSnapshot{}
			} else {
				cell.snapshot = snapshot
			}
			cell.mu.Unlock()
		}
	}()
	close(start)
	wait.Wait()

	cell.mu.Lock()
	cell.snapshot = snapshot
	cell.rejected = false
	cell.mu.Unlock()
	private.rejectRelated(key)
	cell.mu.Lock()
	rejected := cell.rejected
	cell.mu.Unlock()
	if !rejected {
		t.Fatal("related Run cell was not rejected")
	}
}

func TestExternalCMDBAuthorityBoundsMaterialResolutionByAdmissionLifetime(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	snapshot.materialDeadline = time.Now().Add(25 * time.Millisecond)
	references := &recordingReferenceResolver{snapshot: snapshot}
	materials := &recordingMaterialResolver{
		want:           snapshot,
		resolveStarted: make(chan struct{}),
	}
	authority, err := newExternalCMDBAuthority(references, materials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.Destroy)
	binding, err := authority.ResolveRuntimeBinding(
		t.Context(),
		runtimeOpenAttemptRequest(),
	)
	if err != nil {
		t.Fatalf("ResolveRuntimeBinding() error = %v", err)
	}
	key, _ := newExternalCMDBAttemptKey(runtimeOpenAttemptRequest())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	started := time.Now()
	runtime, lifecycle, err := authority.materialize(ctx, key, binding)
	elapsed := time.Since(started)
	runtime.Clear()
	if lifecycle != nil {
		lifecycle.Destroy()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("materialize() error = %v, want admission deadline", err)
	}
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("material resolution elapsed = %v, want lease-bounded cancellation", elapsed)
	}
	if materials.calls != 1 {
		t.Fatalf("material resolver calls = %d, want 1", materials.calls)
	}
}

func TestExternalCMDBAuthorityRevokesCandidateAfterAdmissionContextExpires(
	t *testing.T,
) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	snapshot.materialDeadline = time.Now().Add(25 * time.Millisecond)
	references := &recordingReferenceResolver{snapshot: snapshot}
	materials := &recordingMaterialResolver{
		want:                      snapshot,
		resolveErrorAfterMaterial: true,
	}
	authority, err := newExternalCMDBAuthority(references, materials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.Destroy)
	binding, err := authority.ResolveRuntimeBinding(
		t.Context(),
		runtimeOpenAttemptRequest(),
	)
	if err != nil {
		t.Fatalf("ResolveRuntimeBinding() error = %v", err)
	}
	key, _ := newExternalCMDBAttemptKey(runtimeOpenAttemptRequest())
	runtime, lifecycle, err := authority.materialize(
		t.Context(),
		key,
		binding,
	)
	runtime.Clear()
	if lifecycle != nil {
		lifecycle.Destroy()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired candidate materialize() error = %v", err)
	}
	if materials.calls != 1 || materials.revokeCalls != 1 ||
		materials.destroyCalls != 1 ||
		!materials.revokeContextBounded ||
		!materials.revokeContextActive ||
		!materials.ownedMaterialCleared() {
		t.Fatalf(
			"expired candidate cleanup calls=%d/%d/%d bounded=%t active=%t cleared=%t",
			materials.calls,
			materials.revokeCalls,
			materials.destroyCalls,
			materials.revokeContextBounded,
			materials.revokeContextActive,
			materials.ownedMaterialCleared(),
		)
	}
}

func TestExternalCMDBAuthorityNeverCallsResolverAfterAdmissionLifetimeElapsed(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	snapshot.materialDeadline = time.Now().Add(25 * time.Millisecond)
	references := &recordingReferenceResolver{
		snapshot:       snapshot,
		admissionDelay: 50 * time.Millisecond,
	}
	materials := &recordingMaterialResolver{want: snapshot}
	authority, err := newExternalCMDBAuthority(references, materials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.Destroy)
	binding, err := authority.ResolveRuntimeBinding(
		t.Context(),
		runtimeOpenAttemptRequest(),
	)
	if err != nil {
		t.Fatalf("ResolveRuntimeBinding() error = %v", err)
	}
	key, _ := newExternalCMDBAttemptKey(runtimeOpenAttemptRequest())
	runtime, lifecycle, err := authority.materialize(
		t.Context(),
		key,
		binding,
	)
	runtime.Clear()
	if lifecycle != nil {
		lifecycle.Destroy()
	}
	if !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("elapsed admission materialize() error = %v", err)
	}
	if materials.calls != 0 {
		t.Fatalf(
			"elapsed admission reached material resolver: %d calls",
			materials.calls,
		)
	}
}

func TestExternalCMDBAuthorityDestroysMaterialWhenPostResolveFactsDrift(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	drifted := snapshot.clone()
	drifted.references.credentialReferenceID = "post-resolve-drift"
	references := &recordingReferenceResolver{
		snapshot:            snapshot,
		postResolveSnapshot: &drifted,
	}
	materials := &recordingMaterialResolver{
		want:                 snapshot,
		revokeWaitForContext: true,
	}
	authority, err := newExternalCMDBAuthority(references, materials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.Destroy)
	binding, err := authority.ResolveRuntimeBinding(
		t.Context(),
		runtimeOpenAttemptRequest(),
	)
	if err != nil {
		t.Fatalf("ResolveRuntimeBinding() error = %v", err)
	}
	key, _ := newExternalCMDBAttemptKey(runtimeOpenAttemptRequest())
	materializeContext, cancelMaterialize := context.WithTimeout(
		t.Context(),
		75*time.Millisecond,
	)
	defer cancelMaterialize()
	runtime, lifecycle, err := authority.materialize(
		materializeContext,
		key,
		binding,
	)
	runtime.Clear()
	if lifecycle != nil {
		lifecycle.Destroy()
	}
	if !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("post-resolve drift materialize() error = %v", err)
	}
	if materials.calls != 1 || materials.revokeCalls != 1 ||
		materials.destroyCalls != 1 || !materials.revokeContextBounded ||
		!materials.ownedMaterialCleared() {
		t.Fatalf(
			"post-resolve cleanup calls=%d/%d/%d bounded=%t cleared=%t",
			materials.calls,
			materials.revokeCalls,
			materials.destroyCalls,
			materials.revokeContextBounded,
			materials.ownedMaterialCleared(),
		)
	}
	if provider, checkpoint, _, _, claimErr := authority.claimComponents(
		t.Context(),
		key,
		binding,
		assetcatalog.RunKindValidation,
		0,
		"",
		nil,
	); provider != nil || checkpoint != nil ||
		!errors.Is(claimErr, ErrExternalCMDBRuntimeAuthority) {
		if checkpoint != nil {
			checkpoint.Clear()
		}
		t.Fatalf(
			"post-resolve drift published claim provider=%#v checkpoint=%#v error=%v",
			provider,
			checkpoint,
			claimErr,
		)
	}
}

func TestExternalCMDBBoundRuntimeCloseUsesBoundedRevokeAndDestroys(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	materials := &recordingMaterialResolver{want: snapshot}
	request := newExternalCMDBMaterialRequest(snapshot)
	resolved, err := materials.ResolveExternalCMDB(t.Context(), request)
	request.destroy()
	if err != nil {
		t.Fatalf("ResolveExternalCMDB() error = %v", err)
	}
	bound, err := resolved.bind(snapshot.binding, snapshot)
	if err != nil {
		resolved.Destroy()
		t.Fatalf("bind() error = %v", err)
	}
	if err := bound.Close(); err != nil {
		resolved.Destroy()
		t.Fatalf("BoundRuntime.Close() error = %v", err)
	}
	resolved.Destroy()
	if materials.revokeCalls != 1 || materials.destroyCalls != 1 ||
		!materials.revokeContextBounded ||
		!materials.ownedMaterialCleared() {
		t.Fatalf(
			"BoundRuntime.Close cleanup=%d/%d bounded=%t cleared=%t",
			materials.revokeCalls,
			materials.destroyCalls,
			materials.revokeContextBounded,
			materials.ownedMaterialCleared(),
		)
	}
}

func TestExternalCMDBRuntimeMaterialSeversResolverAliases(t *testing.T) {
	tokenAlias := []byte(runtimeSecretToken)
	nextProtosAlias := []string{"h2"}
	tlsAlias := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    x509.NewCertPool(),
		ServerName: "cmdb.runtime.example",
		NextProtos: nextProtosAlias,
	}
	input := &externalcmdb.RuntimeMaterial{
		BaseURL:             runtimeSecretEndpoint,
		TLSConfig:           tlsAlias,
		BearerToken:         tokenAlias,
		ExpectedAuthorityID: "runtime-authority",
		EnvironmentID:       runtimeEnvironmentID,
	}
	destroyCalls := 0
	resolved, err := NewExternalCMDBRuntimeMaterial(
		input,
		func(context.Context) error { return nil },
		func() { destroyCalls++ },
	)
	if err != nil {
		t.Fatalf("NewExternalCMDBRuntimeMaterial() error = %v", err)
	}
	owned := resolved.state.material
	ownedTokenAlias := owned.BearerToken
	if input.BaseURL != "" || input.TLSConfig != nil ||
		input.BearerToken != nil || input.ExpectedAuthorityID != "" ||
		input.EnvironmentID != "" || !allZero(tokenAlias) {
		resolved.Destroy()
		t.Fatal("resolver input retained runtime material after transfer")
	}
	if owned.TLSConfig == tlsAlias ||
		owned.TLSConfig.RootCAs == tlsAlias.RootCAs ||
		&owned.BearerToken[0] == &tokenAlias[0] {
		resolved.Destroy()
		t.Fatal("owned runtime material retained a resolver alias")
	}

	tokenAlias[0] = 'X'
	tlsAlias.ServerName = "attacker.invalid"
	tlsAlias.MinVersion = tls.VersionTLS12
	nextProtosAlias[0] = "attacker"
	callerRoot, err := testpki.NewAuthority(
		"external-cmdb-resolver-alias-root",
		time.Now(),
	)
	if err != nil {
		resolved.Destroy()
		t.Fatal(err)
	}
	tlsAlias.RootCAs.AddCert(callerRoot.Certificate)
	if string(owned.BearerToken) != runtimeSecretToken ||
		owned.TLSConfig.ServerName != "cmdb.runtime.example" ||
		owned.TLSConfig.MinVersion != tls.VersionTLS13 ||
		len(owned.TLSConfig.NextProtos) != 1 ||
		owned.TLSConfig.NextProtos[0] != "h2" ||
		len(owned.TLSConfig.RootCAs.Subjects()) != 0 {
		resolved.Destroy()
		t.Fatal("resolver alias mutation changed owned runtime material")
	}

	snapshot := validExternalCMDBAttemptSnapshot(t)
	bound, err := resolved.bind(snapshot.binding, snapshot)
	if err != nil {
		resolved.Destroy()
		t.Fatalf("bind(alias-isolated material) error = %v", err)
	}
	if err := discoverysource.WithRuntime[externalcmdb.RuntimeMaterial](
		bound,
		snapshot.binding,
		func(material *externalcmdb.RuntimeMaterial) error {
			if string(material.BearerToken) != runtimeSecretToken ||
				material.TLSConfig.ServerName != "cmdb.runtime.example" ||
				material.TLSConfig.MinVersion != tls.VersionTLS13 ||
				len(material.TLSConfig.RootCAs.Subjects()) != 0 {
				return errors.New("provider runtime changed through caller alias")
			}
			return nil
		},
	); err != nil {
		bound.Clear()
		resolved.Destroy()
		t.Fatalf("WithRuntime(alias-isolated material) error = %v", err)
	}
	bound.Clear()
	resolved.Destroy()
	if destroyCalls != 1 || !allZero(ownedTokenAlias) ||
		tokenAlias[0] != 'X' ||
		owned.BaseURL != "" || owned.TLSConfig != nil ||
		len(owned.BearerToken) != 0 ||
		owned.ExpectedAuthorityID != "" || owned.EnvironmentID != "" {
		t.Fatalf(
			"owned runtime cleanup calls=%d cleared=%t",
			destroyCalls,
			allZero(ownedTokenAlias),
		)
	}
}

func TestExternalCMDBRuntimeMaterialInvalidInputPreservesCallerOwnership(t *testing.T) {
	token := []byte("invalid token\n")
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    x509.NewCertPool(),
	}
	input := &externalcmdb.RuntimeMaterial{
		BaseURL:             runtimeSecretEndpoint,
		TLSConfig:           config,
		BearerToken:         token,
		ExpectedAuthorityID: "runtime-authority",
		EnvironmentID:       runtimeEnvironmentID,
	}
	destroyCalls := 0
	resolved, err := NewExternalCMDBRuntimeMaterial(
		input,
		func(context.Context) error { return nil },
		func() { destroyCalls++ },
	)
	if resolved != nil || !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		if resolved != nil {
			resolved.Destroy()
		}
		t.Fatalf("invalid material constructor = %#v,%v", resolved, err)
	}
	if input.BaseURL != runtimeSecretEndpoint ||
		input.TLSConfig != config ||
		&input.BearerToken[0] != &token[0] ||
		string(input.BearerToken) != "invalid token\n" ||
		input.ExpectedAuthorityID != "runtime-authority" ||
		input.EnvironmentID != runtimeEnvironmentID ||
		destroyCalls != 0 {
		t.Fatal("invalid constructor call changed caller-owned material")
	}
}

func TestExternalCMDBRuntimeMaterialRejectsUnsafeTLSAliases(t *testing.T) {
	tests := map[string]func(*tls.Config){
		"key log writer": func(config *tls.Config) {
			config.KeyLogWriter = &bytes.Buffer{}
		},
		"dynamic client certificate": func(config *tls.Config) {
			config.GetClientCertificate = func(
				*tls.CertificateRequestInfo,
			) (*tls.Certificate, error) {
				return nil, nil
			}
		},
		"custom verification": func(config *tls.Config) {
			config.VerifyConnection = func(tls.ConnectionState) error {
				return nil
			}
		},
		"uncloneable private key": func(config *tls.Config) {
			config.Certificates = []tls.Certificate{{
				Certificate: [][]byte{{1, 2, 3}},
				PrivateKey:  uncloneableRuntimeSigner{},
			}}
		},
		"typed nil RSA private key": func(config *tls.Config) {
			config.Certificates = []tls.Certificate{{
				Certificate: [][]byte{{1, 2, 3}},
				PrivateKey:  (*rsa.PrivateKey)(nil),
			}}
		},
		"typed nil ECDSA private key": func(config *tls.Config) {
			config.Certificates = []tls.Certificate{{
				Certificate: [][]byte{{1, 2, 3}},
				PrivateKey:  (*ecdsa.PrivateKey)(nil),
			}}
		},
		"empty Ed25519 private key": func(config *tls.Config) {
			config.Certificates = []tls.Certificate{{
				Certificate: [][]byte{{1, 2, 3}},
				PrivateKey:  ed25519.PrivateKey{},
			}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			token := []byte(runtimeSecretToken)
			config := &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    x509.NewCertPool(),
			}
			mutate(config)
			input := &externalcmdb.RuntimeMaterial{
				BaseURL:             runtimeSecretEndpoint,
				TLSConfig:           config,
				BearerToken:         token,
				ExpectedAuthorityID: "runtime-authority",
				EnvironmentID:       runtimeEnvironmentID,
			}
			destroyCalls := 0
			var (
				resolved *ExternalCMDBRuntimeMaterial
				err      error
				panicked any
			)
			func() {
				defer func() {
					panicked = recover()
				}()
				resolved, err = NewExternalCMDBRuntimeMaterial(
					input,
					func(context.Context) error { return nil },
					func() { destroyCalls++ },
				)
			}()
			if panicked != nil {
				t.Fatalf("unsafe TLS constructor panicked: %v", panicked)
			}
			if resolved != nil ||
				!errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
				if resolved != nil {
					resolved.Destroy()
				}
				t.Fatalf("unsafe TLS constructor = %#v,%v", resolved, err)
			}
			if input.TLSConfig != config ||
				string(input.BearerToken) != runtimeSecretToken ||
				!strings.HasPrefix(input.BaseURL, "https://") ||
				destroyCalls != 0 {
				t.Fatal("unsafe TLS rejection changed caller ownership")
			}
		})
	}
}

func TestExternalCMDBRuntimeMaterialCloneFailurePreservesRSAKeys(t *testing.T) {
	first, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	first.Precomputed = rsa.PrecomputedValues{}
	second, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	second.Precomputed = rsa.PrecomputedValues{}
	second.PublicKey.E = 2
	firstD := bytes.Clone(first.D.Bytes())
	firstPrimes := cloneBigIntBytes(first.Primes)
	secondD := bytes.Clone(second.D.Bytes())
	secondPrimes := cloneBigIntBytes(second.Primes)
	token := []byte(runtimeSecretToken)
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    x509.NewCertPool(),
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{{1, 2, 3}},
				PrivateKey:  first,
			},
			{
				Certificate: [][]byte{{4, 5, 6}},
				PrivateKey:  second,
			},
		},
	}
	input := &externalcmdb.RuntimeMaterial{
		BaseURL:             runtimeSecretEndpoint,
		TLSConfig:           config,
		BearerToken:         token,
		ExpectedAuthorityID: "runtime-authority",
		EnvironmentID:       runtimeEnvironmentID,
	}
	resolved, err := NewExternalCMDBRuntimeMaterial(
		input,
		func(context.Context) error { return nil },
		func() {},
	)
	if resolved != nil || !errors.Is(err, ErrExternalCMDBRuntimeAuthority) {
		if resolved != nil {
			resolved.Destroy()
		}
		t.Fatalf("partial RSA clone = %#v,%v", resolved, err)
	}
	if input.TLSConfig != config ||
		string(input.BearerToken) != runtimeSecretToken ||
		config.Certificates[0].PrivateKey != first ||
		config.Certificates[1].PrivateKey != second ||
		!rsaPrivateKeyUnchanged(first, firstD, firstPrimes) ||
		!rsaPrivateKeyUnchanged(second, secondD, secondPrimes) {
		t.Fatal("failed RSA clone changed caller-owned material")
	}
}

func TestExternalCMDBRuntimeMaterialClonesAndClearsStaticClientKey(t *testing.T) {
	now := time.Now()
	authority, err := testpki.NewAuthority(
		"external-cmdb-runtime-client-root",
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	client, err := authority.IssueClient(testpki.ClientOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	sourceKey, ok := client.TLS.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || sourceKey.D == nil {
		t.Fatal("test client key is not ECDSA")
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      x509.NewCertPool(),
		Certificates: []tls.Certificate{client.TLS},
	}
	input := &externalcmdb.RuntimeMaterial{
		BaseURL:             runtimeSecretEndpoint,
		TLSConfig:           config,
		ExpectedAuthorityID: "runtime-authority",
		EnvironmentID:       runtimeEnvironmentID,
	}
	destroyCalls := 0
	resolved, err := NewExternalCMDBRuntimeMaterial(
		input,
		func(context.Context) error { return nil },
		func() { destroyCalls++ },
	)
	if err != nil {
		t.Fatalf("static client key constructor error = %v", err)
	}
	ownedKey, ok := resolved.state.material.
		TLSConfig.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	if !ok || ownedKey == sourceKey || ownedKey.D == nil ||
		sourceKey.D != nil || len(config.Certificates) != 0 {
		resolved.Destroy()
		t.Fatal("static client key ownership was not transferred")
	}
	digest := sha256.Sum256([]byte("external-cmdb-owned-key-probe"))
	if _, err := ownedKey.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		resolved.Destroy()
		t.Fatalf("owned static client key Sign() error = %v", err)
	}
	snapshot := validExternalCMDBAttemptSnapshot(t)
	bound, err := resolved.bind(snapshot.binding, snapshot)
	if err != nil {
		resolved.Destroy()
		t.Fatalf("bind static client key error = %v", err)
	}
	bound.Clear()
	if ownedKey.D != nil {
		resolved.Destroy()
		t.Fatal("BoundRuntime.Clear() did not zero owned static client key")
	}
	resolved.Destroy()
	if destroyCalls != 1 || ownedKey.D != nil {
		t.Fatalf(
			"owned static client key cleanup calls=%d cleared=%t",
			destroyCalls,
			ownedKey.D == nil,
		)
	}
}

func TestExternalCMDBRuntimeMaterialDestroyWaitsForBoundRuntimeUse(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	materials := &recordingMaterialResolver{want: snapshot}
	request := newExternalCMDBMaterialRequest(snapshot)
	resolved, err := materials.ResolveExternalCMDB(t.Context(), request)
	request.destroy()
	if err != nil {
		t.Fatalf("ResolveExternalCMDB() error = %v", err)
	}
	bound, err := resolved.bind(snapshot.binding, snapshot)
	if err != nil {
		resolved.Destroy()
		t.Fatalf("bind() error = %v", err)
	}
	using := make(chan struct{})
	releaseUse := make(chan struct{})
	useDone := make(chan error, 1)
	go func() {
		useDone <- discoverysource.WithRuntime[externalcmdb.RuntimeMaterial](
			bound,
			snapshot.binding,
			func(material *externalcmdb.RuntimeMaterial) error {
				close(using)
				<-releaseUse
				if material.BaseURL == "" || len(material.BearerToken) == 0 {
					return errors.New("runtime cleared during active use")
				}
				return nil
			},
		)
	}()
	<-using
	destroyed := make(chan struct{})
	go func() {
		resolved.Destroy()
		close(destroyed)
	}()
	destroyedBeforeRelease := false
	select {
	case <-destroyed:
		destroyedBeforeRelease = true
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseUse)
	if err := <-useDone; err != nil {
		t.Fatalf("WithRuntime() error = %v", err)
	}
	<-destroyed
	bound.Clear()
	if destroyedBeforeRelease {
		t.Fatal("Destroy() bypassed active BoundRuntime use")
	}
	if materials.destroyCalls != 1 || !materials.ownedMaterialCleared() {
		t.Fatalf(
			"Destroy cleanup=%d cleared=%t",
			materials.destroyCalls,
			materials.ownedMaterialCleared(),
		)
	}
}

func TestExternalCMDBRuntimeMaterialConcurrentDestroyWaitsForFinalizer(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	materials := &recordingMaterialResolver{
		want:           snapshot,
		destroyStarted: make(chan struct{}),
		destroyRelease: make(chan struct{}),
	}
	request := newExternalCMDBMaterialRequest(snapshot)
	resolved, err := materials.ResolveExternalCMDB(t.Context(), request)
	request.destroy()
	if err != nil {
		t.Fatalf("ResolveExternalCMDB() error = %v", err)
	}

	firstDone := make(chan struct{})
	go func() {
		resolved.Destroy()
		close(firstDone)
	}()
	<-materials.destroyStarted

	secondDone := make(chan struct{})
	go func() {
		resolved.Destroy()
		close(secondDone)
	}()
	secondReturnedBeforeFinalizer := false
	select {
	case <-secondDone:
		secondReturnedBeforeFinalizer = true
	case <-time.After(25 * time.Millisecond):
	}

	close(materials.destroyRelease)
	<-firstDone
	<-secondDone
	if secondReturnedBeforeFinalizer {
		t.Fatal("concurrent Destroy() returned before finalizer completed")
	}
	if materials.destroyCalls != 1 || !materials.ownedMaterialCleared() {
		t.Fatalf(
			"Destroy cleanup=%d cleared=%t",
			materials.destroyCalls,
			materials.ownedMaterialCleared(),
		)
	}
}

func TestExternalCMDBRuntimeMaterialLifecycleAndSensitiveSurfaces(t *testing.T) {
	snapshot := validExternalCMDBAttemptSnapshot(t)
	materials := &recordingMaterialResolver{want: snapshot}
	request := newExternalCMDBMaterialRequest(snapshot)
	resolved, err := materials.ResolveExternalCMDB(t.Context(), request)
	if err != nil {
		t.Fatalf("ResolveExternalCMDB() error = %v", err)
	}
	copiedRequest := *request
	reconstructedRequest := &ExternalCMDBMaterialRequest{}
	if copiedRequest.Coordinates().Valid() ||
		copiedRequest.Attempt().Valid() ||
		copiedRequest.RuntimeBinding() != (discoverysource.RuntimeBinding{}) ||
		reconstructedRequest.Coordinates().Valid() ||
		reconstructedRequest.Attempt().Valid() ||
		reconstructedRequest.RuntimeBinding() !=
			(discoverysource.RuntimeBinding{}) {
		t.Fatal("copied or reconstructed material request remained usable")
	}
	copiedMaterial := *resolved
	reconstructedMaterial := &ExternalCMDBRuntimeMaterial{}
	if !errors.Is(
		copiedMaterial.Revoke(t.Context()),
		ErrExternalCMDBRuntimeAuthority,
	) || !errors.Is(
		reconstructedMaterial.Revoke(t.Context()),
		ErrExternalCMDBRuntimeAuthority,
	) {
		t.Fatal("copied or reconstructed runtime material remained usable")
	}

	for name, value := range map[string]any{
		"request":                request,
		"copied request":         copiedRequest,
		"reconstructed request":  reconstructedRequest,
		"material":               resolved,
		"copied material":        copiedMaterial,
		"reconstructed material": reconstructedMaterial,
	} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		rendered := fmt.Sprintf("%v %#v", value, value)
		for _, forbidden := range []string{
			runtimeSecretEndpoint,
			runtimeSecretToken,
			runtimeSecretCA,
			runtimeCredentialReference,
			runtimeTrustReference,
			runtimeNetworkReference,
		} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("%s formatting leaked %q: %q", name, forbidden, rendered)
			}
		}
	}

	start := make(chan struct{})
	release := make(chan struct{})
	materials.revokeStarted = start
	materials.revokeRelease = release
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		_ = resolved.Revoke(context.Background())
	}()
	<-start
	go func() {
		defer wait.Done()
		_ = resolved.Revoke(context.Background())
	}()
	go func() {
		defer wait.Done()
		resolved.Destroy()
	}()
	close(release)
	wait.Wait()
	resolved.Destroy()
	if materials.revokeCalls != 1 || materials.destroyCalls != 1 ||
		!materials.revokeContextBounded ||
		!materials.ownedMaterialCleared() {
		t.Fatalf(
			"concurrent lifecycle revoke/destroy/clear = %d/%d/%t/%t",
			materials.revokeCalls,
			materials.destroyCalls,
			materials.revokeContextBounded,
			materials.ownedMaterialCleared(),
		)
	}
	request.destroy()
	if request.Coordinates().Valid() || request.Attempt().Valid() ||
		request.RuntimeBinding() != (discoverysource.RuntimeBinding{}) {
		t.Fatal("destroyed material request remained usable")
	}
}

func validExternalCMDBAttemptSnapshot(t *testing.T) externalCMDBAttemptSnapshot {
	t.Helper()
	descriptor, err := externalcmdb.NewReconciliationDescriptor(sourceprofile.ExternalCMDBV1())
	if err != nil {
		t.Fatal(err)
	}
	open := runtimeOpenAttemptRequest()
	return externalCMDBAttemptSnapshot{
		key: externalCMDBAttemptKey{
			coordinates: open.Coordinates,
			attempt:     open.Attempt,
		},
		binding: runtimeBinding(),
		runKind: assetcatalog.RunKindValidation,
		references: externalCMDBReferences{
			integrationID:            runtimeIntegrationID,
			credentialReferenceID:    runtimeCredentialReference,
			trustReferenceID:         runtimeTrustReference,
			networkPolicyReferenceID: runtimeNetworkReference,
		},
		environmentID:          runtimeEnvironmentID,
		sourceDefinitionSHA256: runtimeDefinitionSHA,
		descriptorSHA256:       descriptor.DescriptorDigestSHA256(),
		limits:                 descriptor.Limits(),
		initialAllowed:         true,
		materialDeadline:       time.Now().Add(time.Minute),
	}
}

func runtimeOpenAttemptRequest() discoverycleanup.OpenAttemptRequest {
	return discoverycleanup.OpenAttemptRequest{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{
				TenantID: runtimeTenantID, WorkspaceID: runtimeWorkspaceID,
			},
			RunID: runtimeRunID,
		},
		Attempt: discoveryqueue.CleanupAttempt{
			RunID: runtimeRunID, AttemptID: runtimeAttemptID, AttemptEpoch: 7,
		},
	}
}

func runtimeBinding() discoverysource.RuntimeBinding {
	return discoverysource.RuntimeBinding{
		Locator: assetcatalog.SourceLocator{
			Scope: assetcatalog.SourceScope{
				TenantID: runtimeTenantID, WorkspaceID: runtimeWorkspaceID,
			},
			SourceID: runtimeSourceID,
		},
		SourceRevision:       1,
		SourceRevisionDigest: runtimeRevisionSHA,
		RevisionStatus:       assetcatalog.SourceRevisionValidating,
		ProviderKind:         "CMDB_CATALOG_V1",
		ProfileCode:          "CMDB_CATALOG_V1",
	}
}

type recordingReferenceResolver struct {
	snapshot            externalCMDBAttemptSnapshot
	postResolveSnapshot *externalCMDBAttemptSnapshot
	admissionDelay      time.Duration
	calls               int
}

func (resolver *recordingReferenceResolver) resolveExternalCMDBAttempt(
	_ context.Context,
	key externalCMDBAttemptKey,
) (externalCMDBAttemptSnapshot, error) {
	resolver.calls++
	if key != resolver.snapshot.key {
		return externalCMDBAttemptSnapshot{}, ErrExternalCMDBRuntimeAuthority
	}
	return resolver.snapshot.clone(), nil
}

func (resolver *recordingReferenceResolver) admitExternalCMDBMaterial(
	ctx context.Context,
	key externalCMDBAttemptKey,
	expected externalCMDBAttemptSnapshot,
	use func(context.Context, externalCMDBAttemptSnapshot) error,
) error {
	if ctx == nil || use == nil {
		return ErrExternalCMDBRuntimeAuthority
	}
	confirmed, err := resolver.resolveExternalCMDBAttempt(ctx, key)
	if err != nil || !expected.same(confirmed) ||
		confirmed.materialDeadline.IsZero() {
		clear(confirmed.sealedCheckpoint.Envelope)
		return boundedRuntimeAuthorityError(err)
	}
	if resolver.admissionDelay > 0 {
		time.Sleep(resolver.admissionDelay)
	}
	if !time.Now().Before(confirmed.materialDeadline) {
		clear(confirmed.sealedCheckpoint.Envelope)
		return ErrExternalCMDBRuntimeAuthority
	}
	admissionContext, cancel := context.WithDeadline(
		ctx,
		confirmed.materialDeadline,
	)
	defer cancel()
	callbackSnapshot := confirmed.clone()
	err = use(admissionContext, callbackSnapshot)
	clear(callbackSnapshot.sealedCheckpoint.Envelope)
	if err != nil {
		clear(confirmed.sealedCheckpoint.Envelope)
		return boundedRuntimeAuthorityError(err)
	}
	if err := admissionContext.Err(); err != nil {
		clear(confirmed.sealedCheckpoint.Envelope)
		return err
	}
	if resolver.postResolveSnapshot != nil {
		resolver.snapshot = resolver.postResolveSnapshot.clone()
		resolver.postResolveSnapshot = nil
	}
	rechecked, err := resolver.resolveExternalCMDBAttempt(
		admissionContext,
		key,
	)
	if err != nil || !confirmed.same(rechecked) {
		clear(confirmed.sealedCheckpoint.Envelope)
		clear(rechecked.sealedCheckpoint.Envelope)
		return boundedRuntimeAuthorityError(err)
	}
	clear(confirmed.sealedCheckpoint.Envelope)
	clear(rechecked.sealedCheckpoint.Envelope)
	return nil
}

type recordingMaterialResolver struct {
	want                      externalCMDBAttemptSnapshot
	calls                     int
	revokeCalls               int
	destroyCalls              int
	owned                     *externalcmdb.RuntimeMaterial
	tokenAlias                []byte
	revokeStarted             chan struct{}
	revokeRelease             chan struct{}
	resolveStarted            chan struct{}
	resolveRelease            chan struct{}
	destroyStarted            chan struct{}
	destroyRelease            chan struct{}
	revokeWaitForContext      bool
	revokeContextBounded      bool
	revokeContextActive       bool
	resolveErrorAfterMaterial bool
}

func (resolver *recordingMaterialResolver) ResolveExternalCMDB(
	ctx context.Context,
	request *ExternalCMDBMaterialRequest,
) (*ExternalCMDBRuntimeMaterial, error) {
	resolver.calls++
	if request == nil ||
		request.Coordinates() != resolver.want.key.coordinates ||
		request.Attempt() != resolver.want.key.attempt ||
		request.RuntimeBinding() != resolver.want.binding ||
		request.IntegrationID() != resolver.want.references.integrationID ||
		request.CredentialReferenceID() != resolver.want.references.credentialReferenceID ||
		request.TrustReferenceID() != resolver.want.references.trustReferenceID ||
		request.NetworkPolicyReferenceID() != resolver.want.references.networkPolicyReferenceID ||
		request.EnvironmentID() != resolver.want.environmentID {
		return nil, ErrExternalCMDBRuntimeAuthority
	}
	if resolver.resolveStarted != nil {
		close(resolver.resolveStarted)
	}
	if resolver.resolveRelease != nil {
		select {
		case <-resolver.resolveRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	} else if resolver.resolveStarted != nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	material := &externalcmdb.RuntimeMaterial{
		BaseURL: runtimeSecretEndpoint,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    x509.NewCertPool(),
		},
		BearerToken:         []byte(runtimeSecretToken),
		ExpectedAuthorityID: "runtime-authority",
		EnvironmentID:       resolver.want.environmentID,
	}
	resolver.tokenAlias = material.BearerToken
	resolved, err := NewExternalCMDBRuntimeMaterial(
		material,
		func(ctx context.Context) error {
			if resolver.revokeStarted != nil {
				close(resolver.revokeStarted)
			}
			if resolver.revokeRelease != nil {
				<-resolver.revokeRelease
			}
			_, resolver.revokeContextBounded = ctx.Deadline()
			resolver.revokeContextActive = ctx.Err() == nil
			if resolver.revokeWaitForContext &&
				resolver.revokeContextBounded {
				<-ctx.Done()
			}
			resolver.revokeCalls++
			return ctx.Err()
		},
		func() {
			if resolver.destroyStarted != nil {
				close(resolver.destroyStarted)
			}
			if resolver.destroyRelease != nil {
				<-resolver.destroyRelease
			}
			resolver.destroyCalls++
		},
	)
	if err != nil {
		return nil, err
	}
	resolver.owned = resolved.state.material
	if resolver.resolveErrorAfterMaterial {
		<-ctx.Done()
		return resolved, ctx.Err()
	}
	return resolved, nil
}

func (resolver *recordingMaterialResolver) ownedMaterialCleared() bool {
	return resolver.owned != nil &&
		resolver.owned.BaseURL == "" &&
		resolver.owned.TLSConfig == nil &&
		len(resolver.owned.BearerToken) == 0 &&
		allZero(resolver.tokenAlias) &&
		resolver.owned.ExpectedAuthorityID == "" &&
		resolver.owned.EnvironmentID == ""
}

func allZero(value []byte) bool {
	for _, character := range value {
		if character != 0 {
			return false
		}
	}
	return true
}

func cloneBigIntBytes(values []*big.Int) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		if values[index] != nil {
			cloned[index] = bytes.Clone(values[index].Bytes())
		}
	}
	return cloned
}

func rsaPrivateKeyUnchanged(
	key *rsa.PrivateKey,
	wantD []byte,
	wantPrimes [][]byte,
) bool {
	if key == nil || key.D == nil || !bytes.Equal(key.D.Bytes(), wantD) ||
		len(key.Primes) != len(wantPrimes) ||
		key.Precomputed.Dp != nil ||
		key.Precomputed.Dq != nil ||
		key.Precomputed.Qinv != nil ||
		len(key.Precomputed.CRTValues) != 0 {
		return false
	}
	for index := range key.Primes {
		if key.Primes[index] == nil ||
			!bytes.Equal(key.Primes[index].Bytes(), wantPrimes[index]) {
			return false
		}
	}
	return true
}

type uncloneableRuntimeSigner struct{}

func (uncloneableRuntimeSigner) Public() crypto.PublicKey {
	return nil
}

func (uncloneableRuntimeSigner) Sign(
	io.Reader,
	[]byte,
	crypto.SignerOpts,
) ([]byte, error) {
	return nil, errors.New("uncloneable runtime signer")
}

var (
	_ discoveryworker.AttemptRuntimeFactory = (*ExternalCMDBAuthority)(nil)
	_ ExternalCMDBMaterialResolver          = (*recordingMaterialResolver)(nil)
)
