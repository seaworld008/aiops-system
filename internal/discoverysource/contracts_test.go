package discoverysource

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

const (
	testTenantID      = "11111111-1111-4111-8111-111111111111"
	testWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	testSourceID      = "33333333-3333-4333-8333-333333333333"
	testEnvironmentID = "44444444-4444-4444-8444-444444444444"
	testProviderKind  = "CMDB_CATALOG_V1"
	testProfileCode   = assetcatalog.ProfileCode("CMDB_PROFILE_V1")
)

type wrappedPage Page

func (wrappedPage) isDiscoverOutcome() {}

type unknownOutcome struct{}

func (unknownOutcome) isDiscoverOutcome() {}

type runtimeMaterial struct {
	Secret string
}

type contractProvider struct{}

func (contractProvider) Kind() assetcatalog.SourceKind { return assetcatalog.SourceKindExternalCMDB }
func (contractProvider) ProviderKind() string          { return testProviderKind }
func (contractProvider) Validate(context.Context, BoundRuntime, ValidationRequest) (ValidationProof, error) {
	return ValidationProof{}, nil
}
func (contractProvider) Discover(context.Context, BoundRuntime, DiscoverRequest) (DiscoverOutcome, error) {
	return Page{}, nil
}

var _ Provider = contractProvider{}

func TestLimitsValidateRejectsEveryInvalidDimension(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Limits)
	}{
		{"items zero", func(value *Limits) { value.MaxPageItems = 0 }},
		{"relations negative", func(value *Limits) { value.MaxPageRelations = -1 }},
		{"page bytes zero", func(value *Limits) { value.MaxPageBytes = 0 }},
		{"document bytes zero", func(value *Limits) { value.MaxDocumentBytes = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := validLimits()
			test.mutate(&limits)
			assertErrorIs(t, limits.Validate(), ErrProviderContractViolation)
		})
	}
	if err := validLimits().Validate(); err != nil {
		t.Fatalf("Limits.Validate() error = %v", err)
	}
}

func TestValidationRequestValidateRejectsDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ValidationRequest)
	}{
		{"tenant", func(value *ValidationRequest) { value.Locator.Scope.TenantID = "invalid" }},
		{"workspace", func(value *ValidationRequest) { value.Locator.Scope.WorkspaceID = "invalid" }},
		{"source", func(value *ValidationRequest) { value.Locator.SourceID = "invalid" }},
		{"revision", func(value *ValidationRequest) { value.SourceRevision = 0 }},
		{"digest", func(value *ValidationRequest) { value.SourceRevisionDigest = strings.Repeat("A", 64) }},
		{"limits", func(value *ValidationRequest) { value.Limits.MaxPageItems = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validValidationRequest()
			test.mutate(&request)
			assertErrorIs(t, request.Validate(), ErrProviderContractViolation)
		})
	}
	if err := validValidationRequest().Validate(); err != nil {
		t.Fatalf("ValidationRequest.Validate() error = %v", err)
	}
}

func TestValidationProofAcceptsExactSuccessAndControlledFailure(t *testing.T) {
	request := validValidationRequest()
	success := validSuccessProof()
	if err := ValidateValidationResult(request, success, nil); err != nil {
		t.Fatalf("ValidateValidationResult(success) error = %v", err)
	}

	failure := ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeFailed,
		Code:    "SCHEMA_REJECTED",
		Checks: []ValidationCheck{
			{Kind: ValidationCheckIdentity, Code: "IDENTITY_VERIFIED", Passed: true, Count: 1},
			{Kind: ValidationCheckSchema, Code: "SCHEMA_REJECTED", Passed: false, Count: 2},
		},
	}
	if err := ValidateValidationResult(request, failure, nil); err != nil {
		t.Fatalf("ValidateValidationResult(failure) error = %v", err)
	}
}

func TestValidationProofDigestIsStableAndBindsRequestAndProof(t *testing.T) {
	request := validValidationRequest()
	proof := validSuccessProof()
	first, err := proof.Digest(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := proof.Digest(request)
	if err != nil || second != first {
		t.Fatalf("Digest() = %q, %v; want %q", second, err, first)
	}
	if len(first) != sha256.Size*2 || first != strings.ToLower(first) {
		t.Fatalf("Digest() = %q, want lowercase SHA-256", first)
	}

	mutatedRequest := request
	mutatedRequest.SourceRevision++
	mutatedDigest, err := proof.Digest(mutatedRequest)
	if err != nil || mutatedDigest == first {
		t.Fatalf("request mutation digest = %q, %v", mutatedDigest, err)
	}
	mutatedProof := proof
	mutatedProof.Checks = append([]ValidationCheck(nil), proof.Checks...)
	mutatedProof.Checks[0].Count++
	mutatedDigest, err = mutatedProof.Digest(request)
	if err != nil || mutatedDigest == first {
		t.Fatalf("proof mutation digest = %q, %v", mutatedDigest, err)
	}
}

func TestValidateValidationResultRejectsEveryInvalidTupleAndProof(t *testing.T) {
	request := validValidationRequest()
	providerErr := errors.New("provider transport canary")
	if got := ValidateValidationResult(request, ValidationProof{}, providerErr); got != providerErr {
		t.Fatalf("provider error = %v, want original instance", got)
	}

	tests := []struct {
		name  string
		proof ValidationProof
		err   error
	}{
		{"zero proof nil error", ValidationProof{}, nil},
		{"proof and error", validSuccessProof(), providerErr},
		{"unknown outcome", func() ValidationProof { value := validSuccessProof(); value.Outcome = "UNKNOWN"; return value }(), nil},
		{"bad proof code", func() ValidationProof { value := validSuccessProof(); value.Code = "bad-code"; return value }(), nil},
		{"success missing check", func() ValidationProof { value := validSuccessProof(); value.Checks = value.Checks[:7]; return value }(), nil},
		{"success reordered checks", func() ValidationProof {
			value := validSuccessProof()
			value.Checks[0], value.Checks[1] = value.Checks[1], value.Checks[0]
			return value
		}(), nil},
		{"success failed check", func() ValidationProof { value := validSuccessProof(); value.Checks[3].Passed = false; return value }(), nil},
		{"success contradictory check code", func() ValidationProof {
			value := validSuccessProof()
			value.Checks[0].Code = "IDENTITY_FAILED"
			return value
		}(), nil},
		{"success wrong code", func() ValidationProof { value := validSuccessProof(); value.Code = "VALIDATION_PASSED"; return value }(), nil},
		{"check code", func() ValidationProof { value := validSuccessProof(); value.Checks[0].Code = "bad-code"; return value }(), nil},
		{"negative count", func() ValidationProof { value := validSuccessProof(); value.Checks[0].Count = -1; return value }(), nil},
		{"uppercase digest", func() ValidationProof {
			value := validSuccessProof()
			value.Checks[0].DigestSHA256 = strings.Repeat("A", 64)
			return value
		}(), nil},
		{"unknown check", ValidationProof{Outcome: assetcatalog.ValidationOutcomeFailed, Code: "VALIDATION_FAILED", Checks: []ValidationCheck{{Kind: "UNKNOWN", Code: "IDENTITY_FAILED", Passed: false}}}, nil},
		{"duplicate check", ValidationProof{Outcome: assetcatalog.ValidationOutcomeFailed, Code: "VALIDATION_FAILED", Checks: []ValidationCheck{{Kind: ValidationCheckIdentity, Code: "IDENTITY_VERIFIED", Passed: true}, {Kind: ValidationCheckIdentity, Code: "IDENTITY_FAILED", Passed: false}}}, nil},
		{"failure checks out of order", ValidationProof{Outcome: assetcatalog.ValidationOutcomeFailed, Code: "VALIDATION_FAILED", Checks: []ValidationCheck{{Kind: ValidationCheckSchema, Code: "SCHEMA_VERIFIED", Passed: true}, {Kind: ValidationCheckIdentity, Code: "IDENTITY_FAILED", Passed: false}}}, nil},
		{"failure success code", ValidationProof{Outcome: assetcatalog.ValidationOutcomeFailed, Code: "VALIDATION_SUCCEEDED", Checks: []ValidationCheck{{Kind: ValidationCheckIdentity, Code: "IDENTITY_FAILED", Passed: false}}}, nil},
		{"failure has no failed check", ValidationProof{Outcome: assetcatalog.ValidationOutcomeFailed, Code: "VALIDATION_FAILED", Checks: []ValidationCheck{{Kind: ValidationCheckIdentity, Code: "IDENTITY_VERIFIED", Passed: true}}}, nil},
		{"failure contradictory check code", ValidationProof{Outcome: assetcatalog.ValidationOutcomeFailed, Code: "VALIDATION_FAILED", Checks: []ValidationCheck{{Kind: ValidationCheckIdentity, Code: "IDENTITY_VERIFIED", Passed: false}}}, nil},
		{"failure has no checks", ValidationProof{Outcome: assetcatalog.ValidationOutcomeFailed, Code: "VALIDATION_FAILED"}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertErrorIs(t, ValidateValidationResult(request, test.proof, test.err), ErrProviderContractViolation)
		})
	}
}

func TestValidationProofRejectsBrokerCleanupAttemptAndAvailabilityClaims(t *testing.T) {
	request := validValidationRequest()
	reservedCodes := []string{
		"CLEANUP_SUCCEEDED",
		"ATTEMPT_CLEANED",
		"AVAILABLE",
		"CREDENTIAL_CLEANUP_SUCCEEDED",
		"REVOCATION_SUCCEEDED",
		"ATTEMPT_RECEIPT_RECORDED",
		"BROKER_CLEANUP_SUCCEEDED",
		"GATE_AVAILABLE",
	}
	for _, code := range reservedCodes {
		t.Run("proof code "+code, func(t *testing.T) {
			proof := ValidationProof{
				Outcome: assetcatalog.ValidationOutcomeFailed,
				Code:    code,
				Checks:  []ValidationCheck{{Kind: ValidationCheckIdentity, Code: "IDENTITY_FAILED", Passed: false}},
			}
			assertErrorIs(t, ValidateValidationResult(request, proof, nil), ErrProviderContractViolation)
		})
		t.Run("check code "+code, func(t *testing.T) {
			proof := ValidationProof{
				Outcome: assetcatalog.ValidationOutcomeFailed,
				Code:    "VALIDATION_FAILED",
				Checks:  []ValidationCheck{{Kind: ValidationCheckIdentity, Code: code, Passed: false}},
			}
			assertErrorIs(t, ValidateValidationResult(request, proof, nil), ErrProviderContractViolation)
		})
	}
	if err := ValidateValidationResult(request, validSuccessProof(), nil); err != nil {
		t.Fatalf("legal eight-check validation proof error = %v", err)
	}
}

func TestBoundRuntimeBindsExactTypeAndCompleteSafeCoordinates(t *testing.T) {
	binding := validRuntimeBinding(assetcatalog.SourceRevisionValidating)
	material := runtimeMaterial{Secret: "runtime-secret-canary"}
	runtime, err := BindRuntime(binding, &material, func(*runtimeMaterial) error { return nil }, func(value *runtimeMaterial) { value.Secret = "" })
	if err != nil {
		t.Fatal(err)
	}
	copyOfRuntime := runtime
	if got := copyOfRuntime.Binding(); got != binding || got.ProviderKind != testProviderKind || got.ProfileCode != testProfileCode {
		t.Fatalf("Binding() = %#v", got)
	}
	if copyOfRuntime.ProviderKind() != testProviderKind || copyOfRuntime.ProfileCode() != testProfileCode {
		t.Fatal("safe binding accessors drifted")
	}
	if err := WithRuntime[runtimeMaterial](copyOfRuntime, binding, func(value *runtimeMaterial) error {
		if value != &material || value.Secret != "runtime-secret-canary" {
			t.Fatalf("callback material = %#v", value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertErrorIs(t, WithRuntime[int](copyOfRuntime, binding, func(*int) error { return nil }), ErrRuntimeBindingMismatch)

	drifts := []func(*RuntimeBinding){
		func(value *RuntimeBinding) { value.Locator.Scope.TenantID = testWorkspaceID },
		func(value *RuntimeBinding) { value.Locator.Scope.WorkspaceID = testTenantID },
		func(value *RuntimeBinding) { value.Locator.SourceID = testWorkspaceID },
		func(value *RuntimeBinding) { value.SourceRevision++ },
		func(value *RuntimeBinding) { value.SourceRevisionDigest = strings.Repeat("b", 64) },
		func(value *RuntimeBinding) { value.RevisionStatus = assetcatalog.SourceRevisionPublished },
		func(value *RuntimeBinding) { value.ProviderKind = "OTHER_PROVIDER_V1" },
		func(value *RuntimeBinding) { value.ProfileCode = "OTHER_PROFILE_V1" },
	}
	for index, drift := range drifts {
		expected := binding
		drift(&expected)
		if err := WithRuntime[runtimeMaterial](copyOfRuntime, expected, func(*runtimeMaterial) error { return nil }); !errors.Is(err, ErrRuntimeBindingMismatch) {
			t.Errorf("binding drift %d error = %v", index, err)
		}
	}
	runtime.Clear()
	assertErrorIs(t, WithRuntime[runtimeMaterial](copyOfRuntime, binding, func(*runtimeMaterial) error { return nil }), ErrRuntimeBindingMismatch)
}

func TestBoundRuntimeCloseIsSharedIdempotentAndAlwaysClears(t *testing.T) {
	binding := validRuntimeBinding(assetcatalog.SourceRevisionPublished)
	material := runtimeMaterial{Secret: "runtime-secret-canary"}
	closeErr := errors.New("close failure")
	var closeCount, clearCount int
	runtime, err := BindRuntime(binding, &material, func(*runtimeMaterial) error {
		closeCount++
		return closeErr
	}, func(value *runtimeMaterial) {
		clearCount++
		value.Secret = ""
	})
	if err != nil {
		t.Fatal(err)
	}
	copyOfRuntime := runtime
	if got := copyOfRuntime.Close(); got != closeErr {
		t.Fatalf("Close() = %v, want original error", got)
	}
	if got := runtime.Close(); got != closeErr {
		t.Fatalf("second Close() = %v, want cached original error", got)
	}
	if closeCount != 1 || clearCount != 1 || material.Secret != "" {
		t.Fatalf("callbacks = close:%d clear:%d material:%#v", closeCount, clearCount, material)
	}
	assertErrorIs(t, WithRuntime[runtimeMaterial](runtime, binding, func(*runtimeMaterial) error { return nil }), ErrRuntimeBindingMismatch)
	runtime.Clear()
	if clearCount != 1 {
		t.Fatalf("Clear after Close invoked callback %d times", clearCount)
	}
}

func TestBindRuntimeRejectsInvalidBindingTypedNilAndCallbacks(t *testing.T) {
	binding := validRuntimeBinding(assetcatalog.SourceRevisionValidating)
	material := runtimeMaterial{}
	closeFn := func(*runtimeMaterial) error { return nil }
	clearFn := func(*runtimeMaterial) {}

	invalid := binding
	invalid.RevisionStatus = assetcatalog.SourceRevisionDraft
	_, err := BindRuntime(invalid, &material, closeFn, clearFn)
	assertErrorIs(t, err, ErrRuntimeBindingMismatch)
	var nilMaterial *runtimeMaterial
	_, err = BindRuntime(binding, nilMaterial, closeFn, clearFn)
	assertErrorIs(t, err, ErrRuntimeBindingMismatch)
	var nestedTypedNil *runtimeMaterial
	_, err = BindRuntime(binding, &nestedTypedNil, func(**runtimeMaterial) error { return nil }, func(**runtimeMaterial) {})
	assertErrorIs(t, err, ErrRuntimeBindingMismatch)
	_, err = BindRuntime(binding, &material, nil, clearFn)
	assertErrorIs(t, err, ErrRuntimeBindingMismatch)
	_, err = BindRuntime(binding, &material, closeFn, nil)
	assertErrorIs(t, err, ErrRuntimeBindingMismatch)
}

func TestCheckpointClonesOwnsClearsAndComparesWithoutDigest(t *testing.T) {
	raw := []byte("checkpoint-secret-canary")
	checkpoint, err := NewCheckpoint(testProfileCode, raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'X'
	var retained []byte
	if err := WithCheckpointBytes(checkpoint, testProfileCode, func(value []byte) error {
		retained = value
		if string(value) != "checkpoint-secret-canary" {
			t.Fatalf("checkpoint bytes = %q", value)
		}
		value[0] = 'Y'
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range retained {
		if value != 0 {
			t.Fatal("temporary checkpoint clone was not cleared")
		}
	}
	if checkpoint.ProfileCode() != testProfileCode || checkpoint.IsEmpty() {
		t.Fatal("checkpoint safe metadata drifted")
	}
	clone := checkpoint.Clone()
	if !checkpoint.Equal(clone) {
		t.Fatal("deep clone is not equal")
	}
	other, err := NewCheckpoint(testProfileCode, []byte("different"))
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Equal(other) {
		t.Fatal("different plaintext checkpoints compared equal")
	}
	checkpoint.Clear()
	if checkpoint.Equal(clone) || checkpoint.ProfileCode() != "" || checkpoint.IsEmpty() {
		t.Fatal("cleared checkpoint remained active")
	}
	if err := WithCheckpointBytes(clone, testProfileCode, func(value []byte) error {
		if string(value) != "checkpoint-secret-canary" {
			t.Fatalf("clone bytes = %q", value)
		}
		return nil
	}); err != nil {
		t.Fatalf("deep clone invalidated with original: %v", err)
	}
}

func TestCheckpointAcceptsExplicitEmptyAndRejectsInvalidShapes(t *testing.T) {
	empty, err := NewCheckpoint(testProfileCode, nil)
	if err != nil || !empty.IsEmpty() {
		t.Fatalf("NewCheckpoint(empty) = %#v, %v", empty, err)
	}
	if err := WithCheckpointBytes(empty, testProfileCode, func(value []byte) error {
		if value == nil || len(value) != 0 {
			t.Fatalf("explicit empty callback = %#v", value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if (Checkpoint{}).IsEmpty() {
		t.Fatal("zero checkpoint reported explicit empty")
	}
	assertErrorIs(t, WithCheckpointBytes(Checkpoint{}, testProfileCode, func([]byte) error { return nil }), ErrCheckpointContract)
	assertErrorIs(t, WithCheckpointBytes(empty, "OTHER_PROFILE_V1", func([]byte) error { return nil }), ErrCheckpointContract)
	assertErrorIs(t, WithCheckpointBytes(empty, testProfileCode, nil), ErrCheckpointContract)
	_, err = NewCheckpoint("", nil)
	assertErrorIs(t, err, ErrCheckpointContract)
	_, err = NewCheckpoint(testProfileCode, make([]byte, MaxCheckpointCanonicalBytes+1))
	assertErrorIs(t, err, ErrCheckpointContract)
}

func TestSensitiveProcessValuesRejectSerializationAndRedactFormatting(t *testing.T) {
	material := runtimeMaterial{Secret: "runtime-secret-canary"}
	runtime, err := BindRuntime(validRuntimeBinding(assetcatalog.SourceRevisionValidating), &material, func(*runtimeMaterial) error { return nil }, func(value *runtimeMaterial) { value.Secret = "" })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Clear)
	checkpoint, err := NewCheckpoint(testProfileCode, []byte("checkpoint-secret-canary"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)

	assertSensitiveValue(t, "runtime", runtime, &runtime, boundRuntimeRedaction, "runtime-secret-canary")
	assertSensitiveValue(t, "checkpoint", checkpoint, &checkpoint, checkpointRedaction, "checkpoint-secret-canary")
}

func TestDiscoverRequestValidateRequiresExactCheckpoint(t *testing.T) {
	request := validDiscoverRequest(t)
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*DiscoverRequest)
	}{
		{"locator", func(value *DiscoverRequest) { value.Locator.SourceID = "invalid" }},
		{"revision", func(value *DiscoverRequest) { value.SourceRevision = 0 }},
		{"digest", func(value *DiscoverRequest) { value.SourceRevisionDigest = strings.Repeat("A", 64) }},
		{"checkpoint", func(value *DiscoverRequest) { value.Checkpoint.Clear() }},
		{"limits", func(value *DiscoverRequest) { value.Limits.MaxPageBytes = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validDiscoverRequest(t)
			test.mutate(&candidate)
			assertErrorIs(t, candidate.Validate(), ErrProviderContractViolation)
		})
	}
}

func TestValidateDiscoverResultAcceptsClosedPageAndDelayOutcomes(t *testing.T) {
	request := validDiscoverRequest(t)
	policy := validFactPolicy()
	page := validFinalPage(t)
	if err := ValidateDiscoverResult(request, policy, page, nil); err != nil {
		t.Fatalf("final page error = %v", err)
	}
	type PageAlias = Page
	alias := PageAlias(validFinalPage(t))
	if err := ValidateDiscoverResult(request, policy, alias, nil); err != nil {
		t.Fatalf("true alias error = %v", err)
	}
	if err := ValidateDiscoverResult(request, policy, Delay{Reason: DelayReasonProviderRetryAfter, RetryAfter: time.Second}, nil); err != nil {
		t.Fatalf("delay error = %v", err)
	}

	relationOnly := Page{
		Relations:      []assetdiscovery.ObservedRelation{validRelation()},
		NextCheckpoint: newCheckpoint(t, "next-relation"),
	}
	if err := ValidateDiscoverResult(request, policy, relationOnly, nil); err != nil {
		t.Fatalf("relation-only page error = %v", err)
	}
	itemPage := Page{Items: []assetdiscovery.NormalizedItem{validItem()}, NextCheckpoint: newCheckpoint(t, "next-item")}
	if err := ValidateDiscoverResult(request, policy, itemPage, nil); err != nil {
		t.Fatalf("non-final item page error = %v", err)
	}
	itemPage.FinalPage = true
	if err := ValidateDiscoverResult(request, policy, itemPage, nil); err != nil {
		t.Fatalf("final incremental page error = %v", err)
	}
}

func TestValidateDiscoverResultPreservesProviderErrorAndRejectsInvalidXOR(t *testing.T) {
	request := validDiscoverRequest(t)
	policy := validFactPolicy()
	providerErr := errors.New("provider transport canary")
	if got := ValidateDiscoverResult(request, policy, nil, providerErr); got != providerErr {
		t.Fatalf("provider error = %v, want original instance", got)
	}

	page := validFinalPage(t)
	pagePointer := &page
	var typedNilPage *Page
	var typedNilDelay *Delay
	tests := []struct {
		name    string
		outcome DiscoverOutcome
		err     error
	}{
		{"nil nil", nil, nil},
		{"page and error", page, providerErr},
		{"pointer page", pagePointer, nil},
		{"typed nil page", typedNilPage, nil},
		{"typed nil delay", typedNilDelay, nil},
		{"pointer delay", &Delay{Reason: DelayReasonProviderRetryAfter, RetryAfter: time.Second}, nil},
		{"defined wrapper", wrappedPage(page), nil},
		{"unknown outcome", unknownOutcome{}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertErrorIs(t, ValidateDiscoverResult(request, policy, test.outcome, test.err), ErrProviderContractViolation)
		})
	}
}

func TestValidateDiscoverResultRejectsInvalidPageAndDelayGates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DiscoverRequest, *assetdiscovery.FactPolicy, *Page) DiscoverOutcome
	}{
		{"complete non-final", func(_ *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			page.FinalPage = false
			return *page
		}},
		{"empty final incremental", func(_ *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			page.CompleteSnapshot = false
			return *page
		}},
		{"empty non-final", func(_ *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			page.FinalPage = false
			page.CompleteSnapshot = false
			return *page
		}},
		{"item limit", func(request *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			request.Limits.MaxPageItems = 1
			first := validItem()
			second := validItem()
			second.ExternalID = "vm-2"
			page.Items = []assetdiscovery.NormalizedItem{first, second}
			return *page
		}},
		{"relation limit", func(request *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			request.Limits.MaxPageRelations = 0
			page.Relations = []assetdiscovery.ObservedRelation{validRelation()}
			return *page
		}},
		{"document limit", func(request *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			request.Limits.MaxDocumentBytes = 1
			page.Items = []assetdiscovery.NormalizedItem{validItem()}
			return *page
		}},
		{"page byte limit", func(request *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			request.Limits.MaxPageBytes = 1
			page.Items = []assetdiscovery.NormalizedItem{validItem()}
			return *page
		}},
		{"fact contract", func(_ *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			item := validItem()
			item.ProviderKind = "OTHER_PROVIDER_V1"
			page.Items = []assetdiscovery.NormalizedItem{item}
			return *page
		}},
		{"zero next checkpoint", func(_ *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			page.NextCheckpoint = Checkpoint{}
			return *page
		}},
		{"wrong next profile", func(_ *DiscoverRequest, _ *assetdiscovery.FactPolicy, page *Page) DiscoverOutcome {
			checkpoint, _ := NewCheckpoint("OTHER_PROFILE_V1", nil)
			page.NextCheckpoint = checkpoint
			return *page
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validDiscoverRequest(t)
			policy := validFactPolicy()
			page := validFinalPage(t)
			outcome := test.mutate(&request, &policy, &page)
			assertErrorIs(t, ValidateDiscoverResult(request, policy, outcome, nil), ErrProviderContractViolation)
		})
	}

	for name, delay := range map[string]Delay{
		"unknown reason": {Reason: "TRANSPORT_BACKOFF", RetryAfter: time.Second},
		"zero duration":  {Reason: DelayReasonProviderRetryAfter},
		"negative":       {Reason: DelayReasonProviderRetryAfter, RetryAfter: -time.Second},
		"above maximum":  {Reason: DelayReasonProviderRetryAfter, RetryAfter: 60*time.Second + time.Nanosecond},
	} {
		t.Run("delay "+name, func(t *testing.T) {
			assertErrorIs(t, ValidateDiscoverResult(validDiscoverRequest(t), validFactPolicy(), delay, nil), ErrProviderContractViolation)
		})
	}
}

func TestCheckpointAccessAndClearAreRaceSafe(t *testing.T) {
	checkpoint := newCheckpoint(t, "race-checkpoint")
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		copyOfCheckpoint := checkpoint
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 500; iteration++ {
				_ = WithCheckpointBytes(copyOfCheckpoint, testProfileCode, func([]byte) error { return nil })
				_ = copyOfCheckpoint.Equal(checkpoint)
				_ = copyOfCheckpoint.String()
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		checkpoint.Clear()
	}()
	close(start)
	wait.Wait()
	assertErrorIs(t, WithCheckpointBytes(checkpoint, testProfileCode, func([]byte) error { return nil }), ErrCheckpointContract)
}

func TestBoundRuntimeAccessAndCloseAreRaceSafe(t *testing.T) {
	binding := validRuntimeBinding(assetcatalog.SourceRevisionPublished)
	material := struct{ Uses int }{}
	runtime, err := BindRuntime(binding, &material, func(*struct{ Uses int }) error { return nil }, func(value *struct{ Uses int }) { value.Uses = 0 })
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		copyOfRuntime := runtime
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 500; iteration++ {
				_ = WithRuntime(copyOfRuntime, binding, func(value *struct{ Uses int }) error {
					value.Uses++
					return nil
				})
				_ = copyOfRuntime.Binding()
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		_ = runtime.Close()
	}()
	close(start)
	wait.Wait()
	assertErrorIs(t, WithRuntime(runtime, binding, func(*struct{ Uses int }) error { return nil }), ErrRuntimeBindingMismatch)
}

func assertSensitiveValue(t *testing.T, name string, value any, pointer any, redaction, canary string) {
	t.Helper()
	if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("%s json.Marshal error = %v", name, err)
	}
	if err := json.Unmarshal([]byte(`{}`), pointer); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("%s json.Unmarshal error = %v", name, err)
	}
	textMarshaler, ok := value.(encoding.TextMarshaler)
	if !ok {
		t.Fatalf("%s does not implement encoding.TextMarshaler", name)
	}
	if _, err := textMarshaler.MarshalText(); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("%s MarshalText error = %v", name, err)
	}
	textUnmarshaler, ok := pointer.(encoding.TextUnmarshaler)
	if !ok {
		t.Fatalf("%s does not implement encoding.TextUnmarshaler", name)
	}
	if err := textUnmarshaler.UnmarshalText([]byte(canary)); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("%s UnmarshalText error = %v", name, err)
	}
	binaryMarshaler, ok := value.(encoding.BinaryMarshaler)
	if !ok {
		t.Fatalf("%s does not implement encoding.BinaryMarshaler", name)
	}
	if _, err := binaryMarshaler.MarshalBinary(); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("%s MarshalBinary error = %v", name, err)
	}
	binaryUnmarshaler, ok := pointer.(encoding.BinaryUnmarshaler)
	if !ok {
		t.Fatalf("%s does not implement encoding.BinaryUnmarshaler", name)
	}
	if err := binaryUnmarshaler.UnmarshalBinary([]byte(canary)); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("%s UnmarshalBinary error = %v", name, err)
	}

	stringer, ok := value.(fmt.Stringer)
	if !ok || stringer.String() != redaction {
		t.Fatalf("%s String() = %q", name, stringer.String())
	}
	goStringer, ok := value.(fmt.GoStringer)
	if !ok || goStringer.GoString() != redaction {
		t.Fatalf("%s GoString() = %q", name, goStringer.GoString())
	}
	logValuer, ok := value.(slog.LogValuer)
	if !ok || logValuer.LogValue().String() != redaction {
		t.Fatalf("%s LogValue() = %#v", name, logValuer.LogValue())
	}
	for format, rendered := range map[string]string{
		"%v": fmt.Sprintf("%v", value), "%+v": fmt.Sprintf("%+v", value), "%#v": fmt.Sprintf("%#v", value),
		"%s": fmt.Sprintf("%s", value), "%q": fmt.Sprintf("%q", value), "%x": fmt.Sprintf("%x", value),
		"pointer": fmt.Sprintf("%+v", pointer),
	} {
		if rendered != redaction || strings.Contains(rendered, canary) {
			t.Errorf("%s %s formatting = %q", name, format, rendered)
		}
	}
}

func assertErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(%v)", err, target)
	}
	for _, canary := range []string{"runtime-secret-canary", "checkpoint-secret-canary", "provider transport canary"} {
		if strings.Contains(fmt.Sprint(err), canary) {
			t.Fatalf("error exposed canary %q: %v", canary, err)
		}
	}
}

func validLimits() Limits {
	return Limits{MaxPageItems: 100, MaxPageRelations: 100, MaxPageBytes: 1 << 20, MaxDocumentBytes: 64 << 10}
}

func validLocator() assetcatalog.SourceLocator {
	return assetcatalog.SourceLocator{
		Scope:    assetcatalog.SourceScope{TenantID: testTenantID, WorkspaceID: testWorkspaceID},
		SourceID: testSourceID,
	}
}

func validValidationRequest() ValidationRequest {
	return ValidationRequest{
		Locator: validLocator(), SourceRevision: 7, SourceRevisionDigest: strings.Repeat("a", 64), Limits: validLimits(),
	}
}

func validRuntimeBinding(status assetcatalog.SourceRevisionStatus) RuntimeBinding {
	request := validValidationRequest()
	return RuntimeBinding{
		Locator: request.Locator, SourceRevision: request.SourceRevision, SourceRevisionDigest: request.SourceRevisionDigest,
		RevisionStatus: status, ProviderKind: testProviderKind, ProfileCode: testProfileCode,
	}
}

func validSuccessProof() ValidationProof {
	kinds := []ValidationCheckKind{
		ValidationCheckIdentity, ValidationCheckTrustOrSignature, ValidationCheckNetwork, ValidationCheckCredentialOpen,
		ValidationCheckFixedProbe, ValidationCheckSchema, ValidationCheckDLP, ValidationCheckBudget,
	}
	codes := []string{
		"IDENTITY_VERIFIED", "TRUST_OR_SIGNATURE_VERIFIED", "NETWORK_VERIFIED", "CREDENTIAL_OPEN_VERIFIED",
		"FIXED_PROBE_VERIFIED", "SCHEMA_VERIFIED", "DLP_VERIFIED", "BUDGET_VERIFIED",
	}
	checks := make([]ValidationCheck, len(kinds))
	for index, kind := range kinds {
		checks[index] = ValidationCheck{Kind: kind, Code: codes[index], Passed: true, Count: int64(index + 1)}
	}
	checks[0].DigestSHA256 = strings.Repeat("b", 64)
	return ValidationProof{Outcome: assetcatalog.ValidationOutcomeSucceeded, Code: "VALIDATION_SUCCEEDED", Checks: checks}
}

func validDiscoverRequest(t *testing.T) DiscoverRequest {
	t.Helper()
	return DiscoverRequest{
		Locator: validLocator(), SourceRevision: 7, SourceRevisionDigest: strings.Repeat("a", 64),
		Checkpoint: newCheckpoint(t, "current-checkpoint"), Limits: validLimits(),
	}
}

func newCheckpoint(t *testing.T, value string) Checkpoint {
	t.Helper()
	checkpoint, err := NewCheckpoint(testProfileCode, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func validFinalPage(t *testing.T) Page {
	t.Helper()
	return Page{NextCheckpoint: newCheckpoint(t, "next-checkpoint"), FinalPage: true, CompleteSnapshot: true}
}

func validFactPolicy() assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind: testProviderKind, FreshnessKind: assetcatalog.FreshnessObjectSequence,
		EnvironmentMapping: assetcatalog.EnvironmentMappingSingle, AuthorityEnvironmentIDs: []string{testEnvironmentID},
		TrustedPathCodes:      []string{"CMDB_V1_DISPLAY_NAME", "CMDB_V1_KIND"},
		RelationshipTypes:     []assetcatalog.RelationshipType{assetcatalog.RelationshipContains},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{assetcatalog.KindLinuxVM: {"cpu_count", "name"}},
	}
}

func validItem() assetdiscovery.NormalizedItem {
	document := []byte(`{"cpu_count":4,"name":"vm-1"}`)
	digest := sha256.Sum256(document)
	fields := []string{"display_name", "environment_id", "external_id", "kind", "provider_kind", "type_details"}
	provenance := make([]assetdiscovery.FieldProvenance, len(fields))
	for index, field := range fields {
		provenance[index] = assetdiscovery.FieldProvenance{
			FieldCode: field, ProviderPathCode: "CMDB_V1_DISPLAY_NAME", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100,
		}
	}
	return assetdiscovery.NormalizedItem{
		EnvironmentID: testEnvironmentID, ProviderKind: testProviderKind, ExternalID: "vm-1", Kind: assetcatalog.KindLinuxVM,
		DisplayName: "vm-1", SchemaVersion: "CMDB_V1_KIND", Document: document, DocumentSHA256: hex.EncodeToString(digest[:]),
		Freshness:       assetdiscovery.FreshnessCandidate{Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 1, ProviderVersionSHA256: strings.Repeat("c", 64)},
		FieldProvenance: provenance, Fingerprints: map[string]string{"machine_id": "vm-1"},
	}
}

func validRelation() assetdiscovery.ObservedRelation {
	return assetdiscovery.ObservedRelation{
		SourceEnvironmentID: testEnvironmentID, TargetEnvironmentID: testEnvironmentID,
		FromExternalID: "cluster-1", ToExternalID: "vm-1", Type: assetcatalog.RelationshipContains,
		ProviderPathCode: "CMDB_V1_KIND", Confidence: 100,
		Freshness: assetdiscovery.FreshnessCandidate{Kind: assetcatalog.FreshnessObjectSequence, OrderSequence: 1, ProviderVersionSHA256: strings.Repeat("d", 64)},
	}
}
