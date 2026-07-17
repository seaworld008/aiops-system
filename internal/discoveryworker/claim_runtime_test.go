package discoveryworker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

func TestResolveOpenedAttemptRequestAndClaimRuntimeBindExactAttempt(t *testing.T) {
	fixture := newRuntimeFixture(t)
	material := &runtimeFixtureMaterial{canary: "runtime-secret-canary"}
	bound, err := discoverysource.BindRuntime(
		fixture.binding,
		material,
		func(value *runtimeFixtureMaterial) error {
			value.closed = true
			return nil
		},
		func(value *runtimeFixtureMaterial) {
			value.cleared = true
			value.canary = ""
		},
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	request, err := newResolveOpenedAttemptRequest(
		fixture.session,
		fixture.coordinates,
		fixture.attempt,
		fixture.binding,
		bound,
		assetcatalog.RunKindDiscovery,
		0,
		"",
		fixture.codec,
	)
	if err != nil {
		t.Fatalf("newResolveOpenedAttemptRequest() error = %v", err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(fixture.binding.ProfileCode, nil)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	runtime, err := newClaimRuntime(
		request,
		runtimeFixtureProvider{},
		&checkpoint,
		discoverysource.Limits{
			MaxPageItems: 10, MaxPageRelations: 10, MaxPageBytes: 4096, MaxDocumentBytes: 2048,
		},
		runtimeFixturePolicy(),
	)
	if err != nil {
		t.Fatalf("newClaimRuntime() error = %v", err)
	}
	defer runtime.destroy()

	if err := runtime.validate(request); err != nil {
		t.Fatalf("ClaimRuntime.validate() error = %v", err)
	}
	if checkpoint.ProfileCode() != "" {
		t.Fatal("newClaimRuntime did not consume the caller checkpoint")
	}

	drifted := request
	drifted.cell = &openedAttemptCell{
		session: fixture.session, coordinates: fixture.coordinates,
		attempt: discoveryqueue.CleanupAttempt{
			RunID: fixture.attempt.RunID, AttemptID: fixture.attempt.AttemptID,
			AttemptEpoch: fixture.attempt.AttemptEpoch + 1,
		},
		binding: fixture.binding, runtime: bound, runKind: assetcatalog.RunKindDiscovery,
		checkpoints: fixture.codec,
	}
	if err := runtime.validate(drifted); !errors.Is(err, ErrClaimRuntimeBinding) {
		t.Fatalf("ClaimRuntime.validate(drift) error = %v, want ErrClaimRuntimeBinding", err)
	}

	runtime.destroy()
	if !material.cleared || material.canary != "" || bound.Binding() != (discoverysource.RuntimeBinding{}) {
		t.Fatalf("runtime material not cleared: %#v binding=%#v", material, bound.Binding())
	}
}

func TestClaimRuntimeRejectsAttemptAndRuntimeCellSplice(t *testing.T) {
	fixture := newRuntimeFixture(t)
	limits := discoverysource.Limits{
		MaxPageItems: 10, MaxPageRelations: 10,
		MaxPageBytes: 4096, MaxDocumentBytes: 2048,
	}
	firstMaterial := &runtimeFixtureMaterial{canary: "attempt-a-runtime"}
	firstBound, err := discoverysource.BindRuntime(
		fixture.binding,
		firstMaterial,
		func(*runtimeFixtureMaterial) error { return nil },
		func(value *runtimeFixtureMaterial) { value.canary = "" },
	)
	if err != nil {
		t.Fatalf("BindRuntime(attempt A) error = %v", err)
	}
	firstRequest, err := newResolveOpenedAttemptRequest(
		fixture.session, fixture.coordinates, fixture.attempt, fixture.binding,
		firstBound, assetcatalog.RunKindDiscovery, 0, "", fixture.codec,
	)
	if err != nil {
		t.Fatalf("newResolveOpenedAttemptRequest(attempt A) error = %v", err)
	}
	firstCheckpoint, err := discoverysource.NewCheckpoint(fixture.binding.ProfileCode, nil)
	if err != nil {
		t.Fatalf("NewCheckpoint(attempt A) error = %v", err)
	}
	firstRuntime, err := newClaimRuntime(
		firstRequest, runtimeFixtureProvider{}, &firstCheckpoint,
		limits, runtimeFixturePolicy(),
	)
	if err != nil {
		t.Fatalf("newClaimRuntime(attempt A) error = %v", err)
	}
	defer firstRuntime.destroy()

	secondAttempt := fixture.attempt
	secondAttempt.AttemptID = runtimeAttemptID2
	secondAttempt.AttemptEpoch++
	secondSession, err := fixture.broker.OpenAttempt(
		context.Background(),
		discoverycleanup.OpenAttemptRequest{
			Coordinates: fixture.coordinates,
			Attempt:     secondAttempt,
		},
	)
	if err != nil {
		t.Fatalf("OpenAttempt(attempt B) error = %v", err)
	}
	defer secondSession.Destroy()
	secondMaterial := &runtimeFixtureMaterial{canary: "attempt-b-runtime"}
	secondBound, err := discoverysource.BindRuntime(
		fixture.binding,
		secondMaterial,
		func(*runtimeFixtureMaterial) error { return nil },
		func(value *runtimeFixtureMaterial) { value.canary = "" },
	)
	if err != nil {
		t.Fatalf("BindRuntime(attempt B) error = %v", err)
	}
	secondRequest, err := newResolveOpenedAttemptRequest(
		secondSession, fixture.coordinates, secondAttempt, fixture.binding,
		secondBound, assetcatalog.RunKindDiscovery, 0, "", fixture.codec,
	)
	if err != nil {
		t.Fatalf("newResolveOpenedAttemptRequest(attempt B) error = %v", err)
	}
	if err := firstRuntime.validate(secondRequest); !errors.Is(err, ErrClaimRuntimeBinding) {
		t.Fatalf("ClaimRuntime.validate(attempt A runtime + attempt B request) error = %v", err)
	}

	secondCheckpoint, err := discoverysource.NewCheckpoint(fixture.binding.ProfileCode, nil)
	if err != nil {
		t.Fatalf("NewCheckpoint(attempt B) error = %v", err)
	}
	forged := ClaimRuntime{state: &claimRuntimeState{
		cell: firstRequest.cell, provider: runtimeFixtureProvider{},
		runtime: secondBound, checkpoint: secondCheckpoint,
		limits: limits, policy: runtimeFixturePolicy(), active: true,
	}}
	if err := forged.validate(firstRequest); !errors.Is(err, ErrClaimRuntimeBinding) {
		t.Fatalf("ClaimRuntime.validate(attempt A request + attempt B runtime) error = %v", err)
	}
	forged.destroy()
	if firstMaterial.canary == "" || secondMaterial.canary != "" {
		t.Fatalf("splice cleanup first=%q second=%q", firstMaterial.canary, secondMaterial.canary)
	}
}

func TestClaimRuntimeRejectsNonemptyInitialDataCheckpoint(t *testing.T) {
	fixture := newRuntimeFixture(t)
	material := &runtimeFixtureMaterial{canary: "stale-cursor-runtime"}
	bound, err := discoverysource.BindRuntime(
		fixture.binding,
		material,
		func(*runtimeFixtureMaterial) error { return nil },
		func(value *runtimeFixtureMaterial) { value.canary = "" },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	request, err := newResolveOpenedAttemptRequest(
		fixture.session,
		fixture.coordinates,
		fixture.attempt,
		fixture.binding,
		bound,
		assetcatalog.RunKindDiscovery,
		0,
		"",
		fixture.codec,
	)
	if err != nil {
		t.Fatalf("newResolveOpenedAttemptRequest() error = %v", err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(
		fixture.binding.ProfileCode,
		[]byte("unpersisted-stale-cursor"),
	)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	if runtime, err := newClaimRuntime(
		request,
		runtimeFixtureProvider{},
		&checkpoint,
		discoverysource.Limits{
			MaxPageItems: 10, MaxPageRelations: 10,
			MaxPageBytes: 4096, MaxDocumentBytes: 2048,
		},
		runtimeFixturePolicy(),
	); !errors.Is(err, ErrClaimRuntimeBinding) || runtime.state != nil {
		t.Fatalf("newClaimRuntime(stale v0 checkpoint) = %#v,%v", runtime, err)
	}
	if material.canary != "" || checkpoint.ProfileCode() != "" {
		t.Fatal("rejected initial checkpoint/runtime were not cleared")
	}
}

func TestResolveOpenedAttemptRequestRejectsSessionAttemptAndBindingDrift(t *testing.T) {
	fixture := newRuntimeFixture(t)
	material := &runtimeFixtureMaterial{canary: "drift-runtime"}
	bound, err := discoverysource.BindRuntime(
		fixture.binding,
		material,
		func(*runtimeFixtureMaterial) error { return nil },
		func(value *runtimeFixtureMaterial) { value.canary = "" },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	defer bound.Clear()
	tests := map[string]func() (*discoverycleanup.AttemptSession, discoveryqueue.RunCoordinates, discoveryqueue.CleanupAttempt, discoverysource.RuntimeBinding){
		"coordinates": func() (*discoverycleanup.AttemptSession, discoveryqueue.RunCoordinates, discoveryqueue.CleanupAttempt, discoverysource.RuntimeBinding) {
			coordinates := fixture.coordinates
			coordinates.RunID = runtimeRunID2
			return fixture.session, coordinates, fixture.attempt, fixture.binding
		},
		"attempt id": func() (*discoverycleanup.AttemptSession, discoveryqueue.RunCoordinates, discoveryqueue.CleanupAttempt, discoverysource.RuntimeBinding) {
			attempt := fixture.attempt
			attempt.AttemptID = runtimeAttemptID2
			return fixture.session, fixture.coordinates, attempt, fixture.binding
		},
		"attempt epoch": func() (*discoverycleanup.AttemptSession, discoveryqueue.RunCoordinates, discoveryqueue.CleanupAttempt, discoverysource.RuntimeBinding) {
			attempt := fixture.attempt
			attempt.AttemptEpoch++
			return fixture.session, fixture.coordinates, attempt, fixture.binding
		},
		"invalid source revision": func() (*discoverycleanup.AttemptSession, discoveryqueue.RunCoordinates, discoveryqueue.CleanupAttempt, discoverysource.RuntimeBinding) {
			binding := fixture.binding
			binding.SourceRevision = 0
			return fixture.session, fixture.coordinates, fixture.attempt, binding
		},
		"invalid binding digest": func() (*discoverycleanup.AttemptSession, discoveryqueue.RunCoordinates, discoveryqueue.CleanupAttempt, discoverysource.RuntimeBinding) {
			binding := fixture.binding
			binding.SourceRevisionDigest = "not-a-digest"
			return fixture.session, fixture.coordinates, fixture.attempt, binding
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			session, coordinates, attempt, binding := mutate()
			if _, err := newResolveOpenedAttemptRequest(
				session, coordinates, attempt, binding, bound,
				assetcatalog.RunKindDiscovery, 0, "", fixture.codec,
			); !errors.Is(err, ErrClaimRuntimeBinding) {
				t.Fatalf("newResolveOpenedAttemptRequest() error = %v, want ErrClaimRuntimeBinding", err)
			}
		})
	}
}

func TestClaimRuntimeAndResolverRequestCloseSensitiveSurfaces(t *testing.T) {
	fixture := newRuntimeFixture(t)
	validationBinding := fixture.binding
	validationBinding.RevisionStatus = assetcatalog.SourceRevisionValidating
	material := &runtimeFixtureMaterial{canary: "runtime-secret-canary"}
	bound, err := discoverysource.BindRuntime(
		validationBinding,
		material,
		func(*runtimeFixtureMaterial) error { return nil },
		func(value *runtimeFixtureMaterial) { value.canary = "" },
	)
	if err != nil {
		t.Fatalf("BindRuntime() error = %v", err)
	}
	request, err := newResolveOpenedAttemptRequest(
		fixture.session,
		fixture.coordinates,
		fixture.attempt,
		validationBinding,
		bound,
		assetcatalog.RunKindValidation,
		0,
		"",
		nil,
	)
	if err != nil {
		t.Fatalf("newResolveOpenedAttemptRequest(validation) error = %v", err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(fixture.binding.ProfileCode, nil)
	if err != nil {
		t.Fatalf("NewCheckpoint(empty) error = %v", err)
	}
	runtime, err := newClaimRuntime(
		request,
		runtimeFixtureProvider{},
		&checkpoint,
		discoverysource.Limits{
			MaxPageItems: 10, MaxPageRelations: 10, MaxPageBytes: 4096, MaxDocumentBytes: 2048,
		},
		runtimeFixturePolicy(),
	)
	if err != nil {
		t.Fatalf("newClaimRuntime() error = %v", err)
	}
	defer runtime.destroy()

	assertOpaqueRuntimeValue(t, "request", request, &request, resolveRequestRedaction)
	assertOpaqueRuntimeValue(t, "runtime", runtime, &runtime, claimRuntimeRedaction)
	for _, value := range []any{request, runtime} {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			if typ.Field(index).IsExported() {
				t.Fatalf("%s exposes field %s", typ, typ.Field(index).Name)
			}
		}
	}
}

func assertOpaqueRuntimeValue(
	t *testing.T,
	name string,
	value any,
	pointer any,
	redaction string,
) {
	t.Helper()
	canary := "runtime-secret-canary"
	if encoded, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) || encoded != nil {
		t.Fatalf("%s json = %q,%v", name, encoded, err)
	}
	for _, candidate := range []any{value, pointer} {
		if marshaler, ok := candidate.(encoding.TextMarshaler); ok {
			if encoded, err := marshaler.MarshalText(); !errors.Is(err, ErrSensitiveSerialization) || encoded != nil {
				t.Fatalf("%s text = %q,%v", name, encoded, err)
			}
		}
		if marshaler, ok := candidate.(encoding.BinaryMarshaler); ok {
			if encoded, err := marshaler.MarshalBinary(); !errors.Is(err, ErrSensitiveSerialization) || encoded != nil {
				t.Fatalf("%s binary = %q,%v", name, encoded, err)
			}
		}
	}
	for _, formatted := range []string{
		fmt.Sprint(value),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
		slog.Any("value", value).Value.String(),
	} {
		if formatted != redaction || strings.Contains(formatted, canary) {
			t.Fatalf("%s formatted = %q, want %q", name, formatted, redaction)
		}
	}
}

const (
	runtimeTenantID   = "10000000-0000-4000-8000-000000000001"
	runtimeWorkspace  = "20000000-0000-4000-8000-000000000002"
	runtimeSourceID   = "30000000-0000-4000-8000-000000000003"
	runtimeRunID      = "40000000-0000-4000-8000-000000000004"
	runtimeRunID2     = "40000000-0000-4000-8000-000000000005"
	runtimeAttemptID  = "50000000-0000-4000-8000-000000000005"
	runtimeAttemptID2 = "50000000-0000-4000-8000-000000000006"
	runtimeProvider   = "CMDB_CATALOG_V1"
)

type runtimeFixture struct {
	broker      *discoverycleanup.CleanupBroker
	session     *discoverycleanup.AttemptSession
	coordinates discoveryqueue.RunCoordinates
	attempt     discoveryqueue.CleanupAttempt
	binding     discoverysource.RuntimeBinding
	codec       *discoverycheckpoint.CheckpointCodec
}

func newRuntimeFixture(t *testing.T) runtimeFixture {
	t.Helper()
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{TenantID: runtimeTenantID, WorkspaceID: runtimeWorkspace},
		RunID: runtimeRunID,
	}
	attempt := discoveryqueue.CleanupAttempt{
		RunID: runtimeRunID, AttemptID: runtimeAttemptID, AttemptEpoch: 7,
	}
	opener := &runtimeFixtureOpener{}
	broker, err := discoverycleanup.NewCleanupBroker(opener, runtimeFixtureProofAuthority{})
	if err != nil {
		t.Fatalf("NewCleanupBroker() error = %v", err)
	}
	t.Cleanup(broker.Destroy)
	session, err := broker.OpenAttempt(context.Background(), discoverycleanup.OpenAttemptRequest{
		Coordinates: coordinates, Attempt: attempt,
	})
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	t.Cleanup(session.Destroy)

	var key [32]byte
	for index := range key {
		key[index] = byte(index + 1)
	}
	keys, err := discoverycheckpoint.NewInMemoryKeyring("runtime-test-key", map[string][32]byte{
		"runtime-test-key": key,
	})
	if err != nil {
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := discoverycheckpoint.NewCheckpointCodec(keys)
	if err != nil {
		t.Fatalf("NewCheckpointCodec() error = %v", err)
	}
	return runtimeFixture{
		broker: broker, session: session, coordinates: coordinates, attempt: attempt,
		binding: discoverysource.RuntimeBinding{
			Locator: assetcatalog.SourceLocator{
				Scope: coordinates.Scope, SourceID: runtimeSourceID,
			},
			SourceRevision: 3, SourceRevisionDigest: strings.Repeat("a", 64),
			RevisionStatus: assetcatalog.SourceRevisionPublished,
			ProviderKind:   runtimeProvider,
			ProfileCode:    assetcatalog.ProfileCode(runtimeProvider),
		},
		codec: codec,
	}
}

type runtimeFixtureMaterial struct {
	canary          string
	closed, cleared bool
}

type runtimeFixtureProvider struct{}

func (runtimeFixtureProvider) Kind() assetcatalog.SourceKind {
	return assetcatalog.SourceKindExternalCMDB
}

func (runtimeFixtureProvider) ProviderKind() string { return runtimeProvider }

func (runtimeFixtureProvider) Validate(
	context.Context,
	discoverysource.BoundRuntime,
	discoverysource.ValidationRequest,
) (discoverysource.ValidationProof, error) {
	return discoverysource.ValidationProof{}, nil
}

func (runtimeFixtureProvider) Discover(
	context.Context,
	discoverysource.BoundRuntime,
	discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	return nil, nil
}

func runtimeFixturePolicy() assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind:            runtimeProvider,
		FreshnessKind:           assetcatalog.FreshnessCatalogSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{"60000000-0000-4000-8000-000000000006"},
		TrustedPathCodes:        []string{"cmdb.catalog"},
		RelationshipTypes:       []assetcatalog.RelationshipType{},
		AllowedDocumentFields:   map[assetcatalog.Kind][]string{},
	}
}

type runtimeFixtureOpener struct{}

func (*runtimeFixtureOpener) OpenSession(
	context.Context,
	discoverycleanup.OpenAttemptRequest,
) (discoverycleanup.SessionHandle, error) {
	return &runtimeFixtureHandle{}, nil
}

type runtimeFixtureHandle struct{}

func (*runtimeFixtureHandle) Revoke(context.Context) error { return nil }
func (*runtimeFixtureHandle) Destroy()                     {}

type runtimeFixtureProofAuthority struct{}

func (runtimeFixtureProofAuthority) SignCleanupProof(_ context.Context, digest []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte("runtime-fixture-proof-key"))
	_, _ = mac.Write(digest)
	return mac.Sum(nil), nil
}

func (runtimeFixtureProofAuthority) VerifyCleanupProof(
	_ context.Context,
	digest []byte,
	signature []byte,
) error {
	expected, _ := runtimeFixtureProofAuthority{}.SignCleanupProof(context.Background(), digest)
	if !hmac.Equal(expected, signature) {
		return errors.New("invalid fixture proof")
	}
	return nil
}
