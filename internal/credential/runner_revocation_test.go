package credential

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestBuildRunnerRevocationReceiptV1UsesJCSAndStringBigints(t *testing.T) {
	t.Parallel()

	claim := runnerRevocationTestClaim()
	const epoch = int64(1<<53 + 1)
	claim.Revocation.ClaimEpoch = epoch
	claim.HeartbeatSequence = epoch + 2
	now := time.Date(2026, 7, 11, 13, 14, 15, 123456000, time.FixedZone("offset", 8*60*60))
	receipt, err := BuildRunnerRevocationReceiptV1(claim, RunnerRevocationCompletion{
		ClaimEpoch: epoch, Outcome: RunnerRevocationFailed, FailureCode: FailureTimeout,
	}, now)
	if err != nil {
		t.Fatalf("BuildRunnerRevocationReceiptV1() error = %v", err)
	}
	detail, err := CanonicalRunnerFailureDetail(FailureTimeout)
	if err != nil {
		t.Fatalf("CanonicalRunnerFailureDetail() error = %v", err)
	}
	expectedJSON, err := json.Marshal(struct {
		SchemaVersion       string                  `json:"schema_version"`
		RevocationID        string                  `json:"revocation_id"`
		TenantID            string                  `json:"tenant_id"`
		WorkspaceID         string                  `json:"workspace_id"`
		EnvironmentID       string                  `json:"environment_id"`
		ActionID            string                  `json:"action_id"`
		Issuer              string                  `json:"issuer"`
		IssuerRevision      string                  `json:"issuer_revision"`
		RunnerID            string                  `json:"runner_id"`
		ScopeRevision       string                  `json:"scope_revision"`
		CertificateSHA256   string                  `json:"certificate_sha256"`
		ClaimEpoch          string                  `json:"claim_epoch"`
		HeartbeatSequence   string                  `json:"heartbeat_seq"`
		ClaimTokenSHA256    string                  `json:"claim_token_sha256"`
		Outcome             RunnerRevocationOutcome `json:"outcome"`
		FailureCount        int                     `json:"failure_count"`
		FailureCode         FailureCode             `json:"failure_code"`
		FailureDetailSHA256 string                  `json:"failure_detail_sha256"`
	}{
		SchemaVersion: runnerRevocationReceiptSchemaV1,
		RevocationID:  claim.Revocation.ID, TenantID: claim.Revocation.TenantID,
		WorkspaceID: claim.Revocation.WorkspaceID, EnvironmentID: claim.Revocation.EnvironmentID,
		ActionID: claim.Revocation.ActionID, Issuer: claim.Revocation.Issuer,
		IssuerRevision: claim.Revocation.IssuerRevision, RunnerID: claim.RunnerID,
		ScopeRevision:     strconv.FormatInt(claim.ScopeRevision, 10),
		CertificateSHA256: claim.CertificateSHA256, ClaimEpoch: strconv.FormatInt(epoch, 10),
		HeartbeatSequence: strconv.FormatInt(epoch+2, 10), ClaimTokenSHA256: claim.ClaimTokenSHA256,
		Outcome: RunnerRevocationFailed, FailureCount: claim.Revocation.FailureCount + 1,
		FailureCode: FailureTimeout, FailureDetailSHA256: SHA256Hex(detail),
	})
	if err != nil {
		t.Fatalf("json.Marshal(expected) error = %v", err)
	}
	canonical, err := jsoncanonicalizer.Transform(expectedJSON)
	if err != nil {
		t.Fatalf("JCS expected error = %v", err)
	}
	wantDigest := sha256.Sum256(append([]byte(runnerRevocationReceiptSchemaV1+"\x00"), canonical...))
	if want := hex.EncodeToString(wantDigest[:]); receipt.ReceiptHash != want {
		t.Fatalf("ReceiptHash = %s, want %s", receipt.ReceiptHash, want)
	}
	if receipt.ClaimEpoch != epoch || receipt.HeartbeatSequence != epoch+2 ||
		receipt.FailureCount != claim.Revocation.FailureCount+1 || receipt.FailureCode != FailureTimeout ||
		receipt.FailureDetailSHA256 != SHA256Hex(detail) || !receipt.ReceivedAt.Equal(now) ||
		receipt.ReceivedAt.Location() != time.UTC {
		t.Fatalf("receipt = %#v", receipt)
	}
	serialized, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("json.Marshal(receipt) error = %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(serialized, &wire); err != nil {
		t.Fatalf("json.Unmarshal(receipt) error = %v", err)
	}
	for field, want := range map[string]string{
		"scope_revision": strconv.FormatInt(claim.ScopeRevision, 10),
		"claim_epoch":    strconv.FormatInt(epoch, 10),
		"heartbeat_seq":  strconv.FormatInt(epoch+2, 10),
	} {
		var got string
		if err := json.Unmarshal(wire[field], &got); err != nil || got != want {
			t.Errorf("receipt JSON %s = %s (%q, %v), want decimal string %q", field, wire[field], got, err, want)
		}
	}

	adjacent := claim
	adjacent.HeartbeatSequence++
	second, err := BuildRunnerRevocationReceiptV1(adjacent, RunnerRevocationCompletion{
		ClaimEpoch: epoch, Outcome: RunnerRevocationFailed, FailureCode: FailureTimeout,
	}, now)
	if err != nil || second.ReceiptHash == receipt.ReceiptHash {
		t.Fatalf("adjacent bigint receipt = %#v, %v", second, err)
	}
}

func TestBuildRunnerRevocationReceiptV1BindsEveryTrustedFieldButNotReceivedAt(t *testing.T) {
	t.Parallel()

	base := runnerRevocationTestClaim()
	completion := RunnerRevocationCompletion{
		ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: RunnerRevocationFailed, FailureCode: FailureTimeout,
	}
	first, err := BuildRunnerRevocationReceiptV1(base, completion, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("BuildRunnerRevocationReceiptV1(base) error = %v", err)
	}

	mutations := map[string]func(*RunnerRevocationClaim){
		"revocation": func(value *RunnerRevocationClaim) { value.Revocation.ID = "30000000-0000-4000-8000-000000000021" },
		"tenant":     func(value *RunnerRevocationClaim) { value.Revocation.TenantID = "10000000-0000-4000-8000-000000000011" },
		"workspace": func(value *RunnerRevocationClaim) {
			value.Revocation.WorkspaceID = "10000000-0000-4000-8000-000000000012"
		},
		"environment": func(value *RunnerRevocationClaim) {
			value.Revocation.EnvironmentID = "10000000-0000-4000-8000-000000000013"
		},
		"action":          func(value *RunnerRevocationClaim) { value.Revocation.ActionID = "action-2" },
		"issuer":          func(value *RunnerRevocationClaim) { value.Revocation.Issuer = "vault-secondary" },
		"issuer revision": func(value *RunnerRevocationClaim) { value.Revocation.IssuerRevision = "rev-2" },
		"runner": func(value *RunnerRevocationClaim) {
			value.RunnerID = "runner-revoker-2"
			value.Revocation.ClaimedBy = value.RunnerID
		},
		"scope revision": func(value *RunnerRevocationClaim) { value.ScopeRevision++ },
		"certificate":    func(value *RunnerRevocationClaim) { value.CertificateSHA256 = strings.Repeat("b", 64) },
		"claim epoch": func(value *RunnerRevocationClaim) {
			value.Revocation.ClaimEpoch++
		},
		"heartbeat":          func(value *RunnerRevocationClaim) { value.HeartbeatSequence++ },
		"claim token digest": func(value *RunnerRevocationClaim) { value.ClaimTokenSHA256 = strings.Repeat("d", 64) },
		"failure count":      func(value *RunnerRevocationClaim) { value.Revocation.FailureCount++ },
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			changed := base
			mutate(&changed)
			changedCompletion := completion
			changedCompletion.ClaimEpoch = changed.Revocation.ClaimEpoch
			receipt, buildErr := BuildRunnerRevocationReceiptV1(changed, changedCompletion, time.Unix(1, 0))
			if buildErr != nil {
				t.Fatalf("BuildRunnerRevocationReceiptV1() error = %v", buildErr)
			}
			if receipt.ReceiptHash == first.ReceiptHash {
				t.Fatalf("%s was not bound into receipt hash %s", name, receipt.ReceiptHash)
			}
		})
	}

	differentCode, err := BuildRunnerRevocationReceiptV1(base, RunnerRevocationCompletion{
		ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: RunnerRevocationFailed, FailureCode: FailureRateLimited,
	}, time.Unix(1, 0))
	if err != nil || differentCode.ReceiptHash == first.ReceiptHash {
		t.Fatalf("failure code/detail binding = %#v, %v", differentCode, err)
	}
	revoked, err := BuildRunnerRevocationReceiptV1(base, RunnerRevocationCompletion{
		ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: RunnerRevocationRevoked,
	}, time.Unix(1, 0))
	if err != nil || revoked.ReceiptHash == first.ReceiptHash || revoked.FailureCount != 0 ||
		revoked.FailureCode != "" || revoked.FailureDetailSHA256 != "" {
		t.Fatalf("REVOKED receipt = %#v, %v", revoked, err)
	}
	later, err := BuildRunnerRevocationReceiptV1(base, completion, time.Unix(999, 0))
	if err != nil || later.ReceiptHash != first.ReceiptHash || later.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatalf("received_at affected proof = %#v, %v", later, err)
	}
}

func TestBuildRunnerRevocationReceiptV1RejectsInvalidClaimsAndCompletions(t *testing.T) {
	t.Parallel()

	base := runnerRevocationTestClaim()
	validCompletion := RunnerRevocationCompletion{
		ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: RunnerRevocationFailed, FailureCode: FailureUnknown,
	}
	invalidClaims := map[string]func(*RunnerRevocationClaim){
		"revocation":      func(value *RunnerRevocationClaim) { value.Revocation.ID = "not-a-uuid" },
		"tenant":          func(value *RunnerRevocationClaim) { value.Revocation.TenantID = "tenant" },
		"workspace":       func(value *RunnerRevocationClaim) { value.Revocation.WorkspaceID = "workspace" },
		"environment":     func(value *RunnerRevocationClaim) { value.Revocation.EnvironmentID = "environment" },
		"action":          func(value *RunnerRevocationClaim) { value.Revocation.ActionID = "" },
		"issuer":          func(value *RunnerRevocationClaim) { value.Revocation.Issuer = " vault" },
		"issuer revision": func(value *RunnerRevocationClaim) { value.Revocation.IssuerRevision = "revision space" },
		"status":          func(value *RunnerRevocationClaim) { value.Revocation.Status = StatusRevocationPending },
		"epoch":           func(value *RunnerRevocationClaim) { value.Revocation.ClaimEpoch = 0 },
		"failure count":   func(value *RunnerRevocationClaim) { value.Revocation.FailureCount = -1 },
		"runner":          func(value *RunnerRevocationClaim) { value.RunnerID = "" },
		"claimed by":      func(value *RunnerRevocationClaim) { value.Revocation.ClaimedBy = "other-runner" },
		"scope revision":  func(value *RunnerRevocationClaim) { value.ScopeRevision = 0 },
		"certificate":     func(value *RunnerRevocationClaim) { value.CertificateSHA256 = strings.Repeat("A", 64) },
		"claim digest":    func(value *RunnerRevocationClaim) { value.ClaimTokenSHA256 = strings.Repeat("z", 64) },
		"heartbeat":       func(value *RunnerRevocationClaim) { value.HeartbeatSequence = -1 },
	}
	for name, mutate := range invalidClaims {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claim := base
			mutate(&claim)
			completion := validCompletion
			completion.ClaimEpoch = claim.Revocation.ClaimEpoch
			if _, err := BuildRunnerRevocationReceiptV1(claim, completion, time.Time{}); !errors.Is(err, ErrInvalidRevocationRequest) {
				t.Fatalf("error = %v, want ErrInvalidRevocationRequest", err)
			}
		})
	}

	invalidCompletions := map[string]RunnerRevocationCompletion{
		"stale epoch":         {ClaimEpoch: base.Revocation.ClaimEpoch + 1, Outcome: RunnerRevocationRevoked},
		"unknown outcome":     {ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: "SUCCESS"},
		"revoked failure":     {ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: RunnerRevocationRevoked, FailureCode: FailureTimeout},
		"failed empty code":   {ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: RunnerRevocationFailed},
		"failed unknown code": {ClaimEpoch: base.Revocation.ClaimEpoch, Outcome: RunnerRevocationFailed, FailureCode: "SECRET_BODY"},
	}
	for name, completion := range invalidCompletions {
		if _, err := BuildRunnerRevocationReceiptV1(base, completion, time.Time{}); !errors.Is(err, ErrInvalidRevocationRequest) {
			t.Errorf("%s error = %v, want ErrInvalidRevocationRequest", name, err)
		}
	}
	overflow := base
	overflow.Revocation.FailureCount = math.MaxInt
	if _, err := BuildRunnerRevocationReceiptV1(overflow, validCompletion, time.Time{}); !errors.Is(err, ErrInvalidRevocationRequest) {
		t.Fatalf("failure count overflow error = %v", err)
	}
}

func TestCanonicalRunnerFailureDetailIsFixedDetachedAndComplete(t *testing.T) {
	t.Parallel()

	codes := []FailureCode{
		FailureIssuerUnavailable, FailureRateLimited, FailureTimeout, FailureAuthentication,
		FailurePermissionDenied, FailureReferenceMissing, FailureInvalidReference, FailureUnknown,
	}
	seen := make(map[string]FailureCode, len(codes))
	for _, code := range codes {
		first, err := CanonicalRunnerFailureDetail(code)
		if err != nil || len(first) == 0 || bytes.Contains(first, []byte("secret")) {
			t.Fatalf("CanonicalRunnerFailureDetail(%q) = %q, %v", code, first, err)
		}
		original := string(first)
		first[0] ^= 0xff
		second, err := CanonicalRunnerFailureDetail(code)
		if err != nil || string(second) != original {
			t.Fatalf("failure detail is shared/mutable for %q: %q, %v", code, second, err)
		}
		if prior, duplicate := seen[string(second)]; duplicate {
			t.Fatalf("failure codes %q and %q share detail %q", prior, code, second)
		}
		seen[string(second)] = code
	}
	if detail, err := CanonicalRunnerFailureDetail("NOT_ALLOWLISTED"); detail != nil || !errors.Is(err, ErrInvalidRevocationRequest) {
		t.Fatalf("invalid failure detail = %q, %v", detail, err)
	}
}

func TestFullJitterRevocationRetryDelayBoundariesAndEntropyFailure(t *testing.T) {
	t.Parallel()

	for _, attempt := range []int{math.MinInt, -1, 0, 1} {
		if got := FullJitterRevocationRetryDelay(attempt, errReader{}); got != MinRevocationRetryDelay {
			t.Errorf("attempt %d delay = %s, want %s", attempt, got, MinRevocationRetryDelay)
		}
	}
	if got := FullJitterRevocationRetryDelay(2, nil); got != MinRevocationRetryDelay {
		t.Fatalf("nil entropy delay = %s", got)
	}
	if got := FullJitterRevocationRetryDelay(2, errReader{}); got != MinRevocationRetryDelay {
		t.Fatalf("failed entropy delay = %s", got)
	}

	for _, test := range []struct {
		attempt int
		upper   time.Duration
	}{
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{8, 10*time.Minute + 40*time.Second},
		{9, MaxRevocationRetryDelay},
		{math.MaxInt, MaxRevocationRetryDelay},
	} {
		if got := revocationRetryUpperBound(test.attempt); got != test.upper {
			t.Errorf("upper(%d) = %s, want %s", test.attempt, got, test.upper)
		}
		span := int64(test.upper-MinRevocationRetryDelay) + 1
		maximumOffset := new(big.Int).Sub(big.NewInt(span), big.NewInt(1))
		encoded := maximumOffset.Bytes()
		got := FullJitterRevocationRetryDelay(test.attempt, bytes.NewReader(encoded))
		if got != test.upper {
			t.Errorf("maximum jitter(%d) = %s, want %s", test.attempt, got, test.upper)
		}
		if minimum := FullJitterRevocationRetryDelay(test.attempt, zeroReader{}); minimum != MinRevocationRetryDelay {
			t.Errorf("minimum jitter(%d) = %s", test.attempt, minimum)
		}
	}
}

func TestRunnerRevocationDomainTypesCannotCarryOrRenderRawSecrets(t *testing.T) {
	t.Parallel()

	for _, value := range []any{
		RunnerRevocationClaim{}, RunnerRevocationHeartbeat{}, RunnerRevocationCompletion{}, RunnerRevocationReceipt{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			name := strings.ToLower(typeOf.Field(index).Name)
			if (strings.Contains(name, "token") && !strings.Contains(name, "sha256")) || strings.Contains(name, "accessor") {
				t.Fatalf("%s contains secret-capable field %s", typeOf, typeOf.Field(index).Name)
			}
		}
	}
	claim := runnerRevocationTestClaim()
	receipt, err := BuildRunnerRevocationReceiptV1(claim, RunnerRevocationCompletion{
		ClaimEpoch: claim.Revocation.ClaimEpoch, Outcome: RunnerRevocationFailed, FailureCode: FailureAuthentication,
	}, time.Now())
	if err != nil {
		t.Fatalf("BuildRunnerRevocationReceiptV1() error = %v", err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("json.Marshal(receipt) error = %v", err)
	}
	for _, forbidden := range []string{"raw-token-canary", "revoke-accessor-canary", "failure-body-canary", "accessor"} {
		if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
			t.Fatalf("receipt JSON leaks %q: %s", forbidden, encoded)
		}
	}
}

func TestRunnerRevocationReceiptMarshalJSONRejectsInvalidBigintFences(t *testing.T) {
	t.Parallel()

	claim := runnerRevocationTestClaim()
	receipt, err := BuildRunnerRevocationReceiptV1(claim, RunnerRevocationCompletion{
		ClaimEpoch: claim.Revocation.ClaimEpoch, Outcome: RunnerRevocationRevoked,
	}, time.Time{})
	if err != nil {
		t.Fatalf("BuildRunnerRevocationReceiptV1() error = %v", err)
	}
	for name, mutate := range map[string]func(*RunnerRevocationReceipt){
		"scope":     func(value *RunnerRevocationReceipt) { value.ScopeRevision = 0 },
		"epoch":     func(value *RunnerRevocationReceipt) { value.ClaimEpoch = 0 },
		"heartbeat": func(value *RunnerRevocationReceipt) { value.HeartbeatSequence = -1 },
	} {
		invalid := receipt
		mutate(&invalid)
		if _, err := json.Marshal(invalid); !errors.Is(err, ErrInvalidRevocationRequest) {
			t.Errorf("%s json.Marshal error = %v, want ErrInvalidRevocationRequest", name, err)
		}
	}
}

func runnerRevocationTestClaim() RunnerRevocationClaim {
	return RunnerRevocationClaim{
		Revocation: Revocation{
			ID:            "30000000-0000-4000-8000-000000000020",
			TenantID:      "10000000-0000-4000-8000-000000000001",
			WorkspaceID:   "10000000-0000-4000-8000-000000000002",
			EnvironmentID: "10000000-0000-4000-8000-000000000003",
			ActionID:      "action-1", Issuer: "vault-production", IssuerRevision: "rev-1",
			Status: StatusRevoking, ClaimEpoch: 7, ClaimedBy: "runner-revoker", FailureCount: 3,
		},
		RunnerID: "runner-revoker", ScopeRevision: 11,
		CertificateSHA256: strings.Repeat("a", 64), ClaimTokenSHA256: strings.Repeat("c", 64),
		HeartbeatSequence: 5,
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type zeroReader struct{}

func (zeroReader) Read(value []byte) (int, error) {
	clear(value)
	return len(value), nil
}
