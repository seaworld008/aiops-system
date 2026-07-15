package discoverysource

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

const (
	MaxCheckpointCanonicalBytes = 65507
	boundRuntimeRedaction       = "[REDACTED_BOUND_RUNTIME]"
	checkpointRedaction         = "[REDACTED_CHECKPOINT]"
)

var (
	ErrProviderContractViolation = errors.New("source provider contract violation")
	ErrRuntimeBindingMismatch    = errors.New("source runtime binding mismatch")
	ErrCheckpointContract        = errors.New("source checkpoint contract violation")
	ErrSensitiveSerialization    = errors.New("sensitive process value is not serializable")

	canonicalUUIDPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	lowercaseDigestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	providerKindPattern        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	validationCodePattern      = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	orderedValidationCheckKind = []ValidationCheckKind{
		ValidationCheckIdentity,
		ValidationCheckTrustOrSignature,
		ValidationCheckNetwork,
		ValidationCheckCredentialOpen,
		ValidationCheckFixedProbe,
		ValidationCheckSchema,
		ValidationCheckDLP,
		ValidationCheckBudget,
	}
)

type DelayReason string

const DelayReasonProviderRetryAfter DelayReason = "PROVIDER_RETRY_AFTER"

type ValidationCheckKind string

const (
	ValidationCheckIdentity         ValidationCheckKind = "IDENTITY"
	ValidationCheckTrustOrSignature ValidationCheckKind = "TRUST_OR_SIGNATURE"
	ValidationCheckNetwork          ValidationCheckKind = "NETWORK"
	ValidationCheckCredentialOpen   ValidationCheckKind = "CREDENTIAL_OPEN"
	ValidationCheckFixedProbe       ValidationCheckKind = "FIXED_PROBE"
	ValidationCheckSchema           ValidationCheckKind = "SCHEMA"
	ValidationCheckDLP              ValidationCheckKind = "DLP"
	ValidationCheckBudget           ValidationCheckKind = "BUDGET"
)

type Limits struct {
	MaxPageItems     int64
	MaxPageRelations int64
	MaxPageBytes     int64
	MaxDocumentBytes int64
}

type ValidationRequest struct {
	Locator              assetcatalog.SourceLocator
	SourceRevision       int64
	SourceRevisionDigest string
	Limits               Limits
}

type ValidationCheck struct {
	Kind         ValidationCheckKind
	Code         string
	Passed       bool
	Count        int64
	DigestSHA256 string
}

type ValidationProof struct {
	Outcome assetcatalog.ValidationOutcome
	Code    string
	Checks  []ValidationCheck
}

type DiscoverRequest struct {
	Locator              assetcatalog.SourceLocator
	SourceRevision       int64
	SourceRevisionDigest string
	Checkpoint           Checkpoint
	Limits               Limits
}

type RuntimeBinding struct {
	Locator              assetcatalog.SourceLocator
	SourceRevision       int64
	SourceRevisionDigest string
	RevisionStatus       assetcatalog.SourceRevisionStatus
	ProviderKind         string
	ProfileCode          assetcatalog.ProfileCode
}

type BoundRuntime struct {
	cell *runtimeCell
}

type runtimeCell struct {
	mu         sync.Mutex
	binding    RuntimeBinding
	material   any
	close      func(any) error
	clear      func(any)
	active     bool
	finalized  bool
	finalError error
}

func BindRuntime[T any](binding RuntimeBinding, material *T, closeFn func(*T) error, clearFn func(*T)) (BoundRuntime, error) {
	if !runtimeBindingValid(binding) || !runtimeMaterialValid(material) || closeFn == nil || clearFn == nil {
		return BoundRuntime{}, runtimeBindingError("INVALID_BINDING")
	}
	cell := &runtimeCell{
		binding:  binding,
		material: material,
		close: func(value any) error {
			typed, ok := value.(*T)
			if !ok || typed == nil {
				return runtimeBindingError("MATERIAL_TYPE_MISMATCH")
			}
			return closeFn(typed)
		},
		clear: func(value any) {
			if typed, ok := value.(*T); ok && typed != nil {
				clearFn(typed)
			}
		},
		active: true,
	}
	return BoundRuntime{cell: cell}, nil
}

func WithRuntime[T any](runtime BoundRuntime, expected RuntimeBinding, use func(*T) error) error {
	if runtime.cell == nil || !runtimeBindingValid(expected) || use == nil {
		return runtimeBindingError("ACCESS_REJECTED")
	}
	runtime.cell.mu.Lock()
	defer runtime.cell.mu.Unlock()
	material, ok := runtime.cell.material.(*T)
	if !runtime.cell.active || runtime.cell.binding != expected || !ok || material == nil {
		return runtimeBindingError("ACCESS_REJECTED")
	}
	return use(material)
}

func (runtime BoundRuntime) Binding() RuntimeBinding {
	if runtime.cell == nil {
		return RuntimeBinding{}
	}
	runtime.cell.mu.Lock()
	defer runtime.cell.mu.Unlock()
	if !runtime.cell.active {
		return RuntimeBinding{}
	}
	return runtime.cell.binding
}

func (runtime BoundRuntime) ProviderKind() string { return runtime.Binding().ProviderKind }

func (runtime BoundRuntime) ProfileCode() assetcatalog.ProfileCode {
	return runtime.Binding().ProfileCode
}

func (runtime BoundRuntime) Close() error {
	if runtime.cell == nil {
		return runtimeBindingError("INACTIVE_RUNTIME")
	}
	runtime.cell.mu.Lock()
	defer runtime.cell.mu.Unlock()
	if runtime.cell.finalized {
		return runtime.cell.finalError
	}
	if !runtime.cell.active {
		return runtimeBindingError("INACTIVE_RUNTIME")
	}
	runtime.cell.active = false
	runtime.cell.finalized = true
	func() {
		defer runtime.cell.clear(runtime.cell.material)
		runtime.cell.finalError = runtime.cell.close(runtime.cell.material)
	}()
	runtime.cell.binding = RuntimeBinding{}
	runtime.cell.material = nil
	runtime.cell.close = nil
	runtime.cell.clear = nil
	return runtime.cell.finalError
}

func (runtime BoundRuntime) Clear() {
	if runtime.cell == nil {
		return
	}
	runtime.cell.mu.Lock()
	defer runtime.cell.mu.Unlock()
	if !runtime.cell.active {
		return
	}
	runtime.cell.active = false
	runtime.cell.finalized = true
	runtime.cell.clear(runtime.cell.material)
	runtime.cell.binding = RuntimeBinding{}
	runtime.cell.material = nil
	runtime.cell.close = nil
	runtime.cell.clear = nil
}

func (BoundRuntime) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*BoundRuntime) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (BoundRuntime) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*BoundRuntime) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (BoundRuntime) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*BoundRuntime) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (BoundRuntime) String() string                 { return boundRuntimeRedaction }
func (BoundRuntime) GoString() string               { return boundRuntimeRedaction }
func (BoundRuntime) LogValue() slog.Value           { return slog.StringValue(boundRuntimeRedaction) }
func (BoundRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, boundRuntimeRedaction)
}

type Checkpoint struct {
	cell *checkpointCell
}

type checkpointCell struct {
	mu        sync.Mutex
	profile   assetcatalog.ProfileCode
	canonical []byte
	active    bool
}

func NewCheckpoint(profileCode assetcatalog.ProfileCode, canonical []byte) (Checkpoint, error) {
	if !profileCode.Valid() || len(canonical) > MaxCheckpointCanonicalBytes {
		return Checkpoint{}, checkpointError("INVALID_CHECKPOINT")
	}
	owned := append([]byte{}, canonical...)
	return Checkpoint{cell: &checkpointCell{profile: profileCode, canonical: owned, active: true}}, nil
}

func (checkpoint Checkpoint) Clone() Checkpoint {
	profile, canonical, active := checkpoint.snapshot()
	if !active {
		return Checkpoint{}
	}
	return Checkpoint{cell: &checkpointCell{profile: profile, canonical: canonical, active: true}}
}

func (checkpoint Checkpoint) ProfileCode() assetcatalog.ProfileCode {
	if checkpoint.cell == nil {
		return ""
	}
	checkpoint.cell.mu.Lock()
	defer checkpoint.cell.mu.Unlock()
	if !checkpoint.cell.active {
		return ""
	}
	return checkpoint.cell.profile
}

func (checkpoint Checkpoint) IsEmpty() bool {
	if checkpoint.cell == nil {
		return false
	}
	checkpoint.cell.mu.Lock()
	defer checkpoint.cell.mu.Unlock()
	return checkpoint.cell.active && len(checkpoint.cell.canonical) == 0
}

func WithCheckpointBytes(checkpoint Checkpoint, expected assetcatalog.ProfileCode, use func([]byte) error) error {
	if !expected.Valid() || use == nil {
		return checkpointError("ACCESS_REJECTED")
	}
	profile, temporary, active := checkpoint.snapshot()
	if !active || profile != expected {
		clear(temporary)
		return checkpointError("ACCESS_REJECTED")
	}
	defer clear(temporary)
	return use(temporary)
}

func (checkpoint Checkpoint) Equal(other Checkpoint) bool {
	leftProfile, left, leftActive := checkpoint.snapshot()
	rightProfile, right, rightActive := other.snapshot()
	defer clear(left)
	defer clear(right)
	if !leftActive || !rightActive {
		return false
	}
	return constantTimeBytesEqual([]byte(leftProfile), []byte(rightProfile)) == 1 &&
		constantTimeBytesEqual(left, right) == 1
}

func (checkpoint *Checkpoint) Clear() {
	if checkpoint == nil || checkpoint.cell == nil {
		return
	}
	checkpoint.cell.mu.Lock()
	defer checkpoint.cell.mu.Unlock()
	clear(checkpoint.cell.canonical)
	checkpoint.cell.canonical = nil
	checkpoint.cell.profile = ""
	checkpoint.cell.active = false
}

func (checkpoint Checkpoint) snapshot() (assetcatalog.ProfileCode, []byte, bool) {
	if checkpoint.cell == nil {
		return "", nil, false
	}
	checkpoint.cell.mu.Lock()
	defer checkpoint.cell.mu.Unlock()
	if !checkpoint.cell.active {
		return "", nil, false
	}
	return checkpoint.cell.profile, append([]byte{}, checkpoint.cell.canonical...), true
}

func (Checkpoint) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*Checkpoint) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (Checkpoint) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*Checkpoint) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (Checkpoint) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*Checkpoint) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (Checkpoint) String() string                 { return checkpointRedaction }
func (Checkpoint) GoString() string               { return checkpointRedaction }
func (Checkpoint) LogValue() slog.Value           { return slog.StringValue(checkpointRedaction) }
func (Checkpoint) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, checkpointRedaction) }

func (limits Limits) Validate() error {
	if limits.MaxPageItems <= 0 || limits.MaxPageRelations < 0 || limits.MaxPageBytes <= 0 || limits.MaxDocumentBytes <= 0 {
		return providerContractError("INVALID_LIMITS")
	}
	return nil
}

func (request ValidationRequest) Validate() error {
	if !validSourceLocator(request.Locator) || request.SourceRevision <= 0 ||
		!lowercaseDigestPattern.MatchString(request.SourceRevisionDigest) {
		return providerContractError("INVALID_VALIDATION_REQUEST")
	}
	return request.Limits.Validate()
}

func ValidateValidationResult(request ValidationRequest, proof ValidationProof, providerError error) error {
	if err := request.Validate(); err != nil {
		return err
	}
	zeroProof := proof.Outcome == "" && proof.Code == "" && len(proof.Checks) == 0
	if providerError != nil {
		if !zeroProof {
			return providerContractError("INVALID_VALIDATION_RESULT_TUPLE")
		}
		return providerError
	}
	if zeroProof || !validValidationProof(proof) {
		return providerContractError("INVALID_VALIDATION_PROOF")
	}
	return nil
}

func (proof ValidationProof) Digest(request ValidationRequest) (string, error) {
	if err := ValidateValidationResult(request, proof, nil); err != nil {
		return "", err
	}
	hasher := sha256.New()
	writeDigestFrame(hasher, []byte("source-validation-proof.v1"))
	writeDigestFrame(hasher, []byte(request.Locator.Scope.TenantID))
	writeDigestFrame(hasher, []byte(request.Locator.Scope.WorkspaceID))
	writeDigestFrame(hasher, []byte(request.Locator.SourceID))
	writeDigestInt64(hasher, request.SourceRevision)
	writeDigestSHA256(hasher, request.SourceRevisionDigest)
	writeDigestInt64(hasher, request.Limits.MaxPageItems)
	writeDigestInt64(hasher, request.Limits.MaxPageRelations)
	writeDigestInt64(hasher, request.Limits.MaxPageBytes)
	writeDigestInt64(hasher, request.Limits.MaxDocumentBytes)
	writeDigestFrame(hasher, []byte(proof.Outcome))
	writeDigestFrame(hasher, []byte(proof.Code))
	writeDigestInt64(hasher, int64(len(proof.Checks)))
	for _, check := range proof.Checks {
		writeDigestFrame(hasher, []byte(check.Kind))
		writeDigestFrame(hasher, []byte(check.Code))
		if check.Passed {
			writeDigestInt64(hasher, 1)
		} else {
			writeDigestInt64(hasher, 0)
		}
		writeDigestInt64(hasher, check.Count)
		if check.DigestSHA256 == "" {
			writeDigestNull(hasher)
		} else {
			writeDigestSHA256(hasher, check.DigestSHA256)
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (request DiscoverRequest) Validate() error {
	if !validSourceLocator(request.Locator) || request.SourceRevision <= 0 ||
		!lowercaseDigestPattern.MatchString(request.SourceRevisionDigest) {
		return providerContractError("INVALID_DISCOVER_REQUEST")
	}
	if err := request.Limits.Validate(); err != nil {
		return err
	}
	if request.Checkpoint.ProfileCode() == "" {
		return providerContractError("INVALID_DISCOVER_CHECKPOINT")
	}
	return nil
}

type Provider interface {
	Kind() assetcatalog.SourceKind
	ProviderKind() string
	Validate(context.Context, BoundRuntime, ValidationRequest) (ValidationProof, error)
	Discover(context.Context, BoundRuntime, DiscoverRequest) (DiscoverOutcome, error)
}

type Page struct {
	Items            []assetdiscovery.NormalizedItem
	Relations        []assetdiscovery.ObservedRelation
	NextCheckpoint   Checkpoint
	FinalPage        bool
	CompleteSnapshot bool
}

type Delay struct {
	Reason     DelayReason
	RetryAfter time.Duration
}

type DiscoverOutcome interface {
	isDiscoverOutcome()
}

func (Page) isDiscoverOutcome()  {}
func (Delay) isDiscoverOutcome() {}

func ValidateDiscoverResult(request DiscoverRequest, policy assetdiscovery.FactPolicy, outcome DiscoverOutcome, providerError error) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if providerError != nil {
		if outcome != nil {
			return providerContractError("INVALID_DISCOVER_RESULT_TUPLE")
		}
		return providerError
	}
	if outcome == nil {
		return providerContractError("INVALID_DISCOVER_RESULT_TUPLE")
	}
	switch value := outcome.(type) {
	case Page:
		return validatePage(request, policy, value)
	case Delay:
		return validateDelay(value)
	default:
		return providerContractError("INVALID_DISCOVER_OUTCOME_TYPE")
	}
}

func validValidationProof(proof ValidationProof) bool {
	if !proof.Outcome.Valid() || !validationCodePattern.MatchString(proof.Code) ||
		len(proof.Checks) == 0 || len(proof.Checks) > len(orderedValidationCheckKind) {
		return false
	}
	lastOrder := -1
	failed := false
	for _, check := range proof.Checks {
		order := validationCheckOrder(check.Kind)
		if order <= lastOrder || !validValidationCheckCode(check) || check.Count < 0 ||
			check.DigestSHA256 != "" && !lowercaseDigestPattern.MatchString(check.DigestSHA256) {
			return false
		}
		lastOrder = order
		failed = failed || !check.Passed
	}
	if proof.Outcome == assetcatalog.ValidationOutcomeSucceeded {
		if proof.Code != "VALIDATION_SUCCEEDED" || len(proof.Checks) != len(orderedValidationCheckKind) {
			return false
		}
		for index, check := range proof.Checks {
			if check.Kind != orderedValidationCheckKind[index] || !check.Passed {
				return false
			}
		}
		return true
	}
	return proof.Outcome == assetcatalog.ValidationOutcomeFailed && validValidationFailureCode(proof.Code) && failed
}

func validValidationCheckCode(check ValidationCheck) bool {
	if !validationCodePattern.MatchString(check.Code) || reservedProviderProofCode(check.Code) {
		return false
	}
	if check.Code == "VALIDATION_SUCCEEDED" {
		return check.Passed
	}
	prefix := string(check.Kind) + "_"
	if !strings.HasPrefix(check.Code, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(check.Code, prefix)
	if check.Passed {
		switch suffix {
		case "PASSED", "SUCCEEDED", "VERIFIED":
			return true
		}
		return false
	}
	switch suffix {
	case "FAILED", "INCOMPATIBLE", "REJECTED", "UNSUPPORTED":
		return true
	}
	return false
}

func validValidationFailureCode(code string) bool {
	if !validationCodePattern.MatchString(code) || reservedProviderProofCode(code) {
		return false
	}
	for _, suffix := range []string{"FAILED", "INCOMPATIBLE", "REJECTED", "UNSUPPORTED"} {
		if code == "VALIDATION_"+suffix || code == "PROVIDER_"+suffix || code == "AUTHORITY_"+suffix {
			return true
		}
		for _, kind := range orderedValidationCheckKind {
			if code == string(kind)+"_"+suffix {
				return true
			}
		}
	}
	return false
}

func reservedProviderProofCode(code string) bool {
	for _, token := range strings.Split(code, "_") {
		switch token {
		case "ATTEMPT", "AVAILABLE", "AVAILABILITY", "BROKER", "CLEANED", "CLEANUP", "CLEAR", "CLEARED",
			"DEGRADED", "GATE", "RECEIPT", "REVOCATION", "REVOKE", "REVOKED", "SUSPENDED", "UNAVAILABLE":
			return true
		}
	}
	return false
}

func validationCheckOrder(kind ValidationCheckKind) int {
	for index, candidate := range orderedValidationCheckKind {
		if candidate == kind {
			return index
		}
	}
	return -1
}

func validatePage(request DiscoverRequest, policy assetdiscovery.FactPolicy, page Page) error {
	if int64(len(page.Items)) > request.Limits.MaxPageItems || int64(len(page.Relations)) > request.Limits.MaxPageRelations {
		return providerContractError("PAGE_LIMIT_EXCEEDED")
	}
	for _, item := range page.Items {
		if int64(len(item.Document)) > request.Limits.MaxDocumentBytes {
			return providerContractError("DOCUMENT_LIMIT_EXCEEDED")
		}
	}
	if page.CompleteSnapshot && !page.FinalPage || len(page.Items) == 0 && len(page.Relations) == 0 &&
		(!page.FinalPage || !page.CompleteSnapshot) {
		return providerContractError("INVALID_PAGE_COMPLETION")
	}
	if page.NextCheckpoint.ProfileCode() == "" || page.NextCheckpoint.ProfileCode() != request.Checkpoint.ProfileCode() {
		return providerContractError("INVALID_NEXT_CHECKPOINT")
	}
	if err := assetdiscovery.ValidateFacts(page.Items, page.Relations, policy); err != nil {
		return providerContractError("INVALID_PAGE_FACTS")
	}
	size, ok := pageSemanticBytes(page)
	if !ok || size > request.Limits.MaxPageBytes {
		return providerContractError("PAGE_BYTE_LIMIT_EXCEEDED")
	}
	return nil
}

func validateDelay(delay Delay) error {
	if delay.Reason != DelayReasonProviderRetryAfter || delay.RetryAfter <= 0 || delay.RetryAfter > 60*time.Second {
		return providerContractError("INVALID_PROVIDER_DELAY")
	}
	return nil
}

func pageSemanticBytes(page Page) (int64, bool) {
	total := int64(32)
	add := func(length int) bool {
		if length < 0 || int64(length) > math.MaxInt64-total {
			return false
		}
		total += int64(length)
		return true
	}
	addFramed := func(length int) bool {
		if length > math.MaxInt-5 {
			return false
		}
		return add(length + 5)
	}
	for _, item := range page.Items {
		for _, value := range []string{
			item.EnvironmentID, item.ProviderKind, item.ExternalID, string(item.Kind), item.DisplayName,
			item.SchemaVersion, item.DocumentSHA256, string(item.Freshness.Kind), item.Freshness.ProviderVersionSHA256,
			item.TombstoneReason,
		} {
			if !addFramed(len(value)) {
				return 0, false
			}
		}
		if !addFramed(len(item.Document)) || !add(64) {
			return 0, false
		}
		for _, provenance := range item.FieldProvenance {
			if !addFramed(len(provenance.FieldCode)) || !addFramed(len(provenance.ProviderPathCode)) ||
				!addFramed(len(provenance.Ownership)) || !add(8) {
				return 0, false
			}
		}
		for key, value := range item.Fingerprints {
			if !addFramed(len(key)) || !addFramed(len(value)) {
				return 0, false
			}
		}
	}
	for _, relation := range page.Relations {
		for _, value := range []string{
			relation.SourceEnvironmentID, relation.TargetEnvironmentID, relation.FromExternalID, relation.ToExternalID,
			string(relation.Type), relation.ProviderPathCode, string(relation.Freshness.Kind), relation.Freshness.ProviderVersionSHA256,
		} {
			if !addFramed(len(value)) {
				return 0, false
			}
		}
		if !add(32) {
			return 0, false
		}
	}
	_, checkpointBytes, active := page.NextCheckpoint.snapshot()
	defer clear(checkpointBytes)
	if !active || !addFramed(len(checkpointBytes)) {
		return 0, false
	}
	return total, true
}

func runtimeBindingValid(binding RuntimeBinding) bool {
	return validSourceLocator(binding.Locator) && binding.SourceRevision > 0 &&
		lowercaseDigestPattern.MatchString(binding.SourceRevisionDigest) &&
		(binding.RevisionStatus == assetcatalog.SourceRevisionValidating || binding.RevisionStatus == assetcatalog.SourceRevisionPublished) &&
		providerKindPattern.MatchString(binding.ProviderKind) && binding.ProfileCode.Valid()
}

func runtimeMaterialValid[T any](material *T) bool {
	if material == nil {
		return false
	}
	value := reflect.ValueOf(any(*material))
	if !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

func validSourceLocator(locator assetcatalog.SourceLocator) bool {
	return canonicalUUIDPattern.MatchString(locator.Scope.TenantID) &&
		canonicalUUIDPattern.MatchString(locator.Scope.WorkspaceID) &&
		canonicalUUIDPattern.MatchString(locator.SourceID)
}

func constantTimeBytesEqual(left, right []byte) int {
	length := max(len(left), len(right))
	leftPadded := make([]byte, length)
	rightPadded := make([]byte, length)
	copy(leftPadded, left)
	copy(rightPadded, right)
	equalLength := subtle.ConstantTimeEq(int32(len(left)), int32(len(right)))
	equalContent := subtle.ConstantTimeCompare(leftPadded, rightPadded)
	clear(leftPadded)
	clear(rightPadded)
	return equalLength & equalContent
}

func writeDigestFrame(writer io.Writer, value []byte) {
	_, _ = writer.Write([]byte{1})
	var length [4]byte
	length[0] = byte(uint32(len(value)) >> 24)
	length[1] = byte(uint32(len(value)) >> 16)
	length[2] = byte(uint32(len(value)) >> 8)
	length[3] = byte(uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func writeDigestInt64(writer io.Writer, value int64) {
	writeDigestFrame(writer, []byte(strconv.FormatInt(value, 10)))
}

func writeDigestSHA256(writer io.Writer, value string) {
	decoded, _ := hex.DecodeString(value)
	writeDigestFrame(writer, decoded)
	clear(decoded)
}

func writeDigestNull(writer io.Writer) {
	_, _ = writer.Write([]byte{0})
}

func providerContractError(code string) error {
	return fmt.Errorf("%w: %s", ErrProviderContractViolation, code)
}

func runtimeBindingError(code string) error {
	return fmt.Errorf("%w: %s", ErrRuntimeBindingMismatch, code)
}

func checkpointError(code string) error {
	return fmt.Errorf("%w: %s", ErrCheckpointContract, code)
}
