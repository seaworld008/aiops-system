package credential

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAESGCMProtectorRoundTripBindsContextAndUsesKeyedHMAC(t *testing.T) {
	t.Parallel()

	protector := testProtector(t, "key-2026-07", map[string]ProtectionKey{
		"key-2026-07": {
			EncryptionKey: bytes.Repeat([]byte{0x11}, 32),
			HMACKey:       bytes.Repeat([]byte{0x22}, 32),
		},
	})
	context := ReferenceContext{
		RevocationID:   "10000000-0000-4000-8000-000000000001",
		ActionID:       "20000000-0000-4000-8000-000000000001",
		ActionEpoch:    7,
		Issuer:         "vault-production",
		IssuerRevision: "rev-17",
	}
	plaintext := []byte("lease/accessor with spaces and unicode-租约")
	reference, err := NewSensitiveReference(plaintext)
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	protected, err := protector.Protect(context, reference)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if protected.KeyID != "key-2026-07" || len(protected.AccessorHMAC) != 32 {
		t.Fatalf("protected shape = key %q hmac length %d", protected.KeyID, len(protected.AccessorHMAC))
	}
	if bytes.Contains(protected.Ciphertext, plaintext) || bytes.Equal(protected.AccessorHMAC, plaintext) {
		t.Fatal("protected form contains the plaintext accessor")
	}

	opened, err := protector.Unprotect(context, protected)
	if err != nil {
		t.Fatalf("Unprotect() error = %v", err)
	}
	if got := opened.Bytes(); !bytes.Equal(got, plaintext) {
		t.Fatalf("opened reference = %q", got)
	}

	wrongContext := context
	wrongContext.ActionEpoch++
	if _, err := protector.Unprotect(wrongContext, protected); !errors.Is(err, ErrReferenceProtection) {
		t.Fatalf("Unprotect(wrong AAD) error = %v, want ErrReferenceProtection", err)
	}
	wrongRevision := context
	wrongRevision.IssuerRevision = "rev-18"
	if _, err := protector.Unprotect(wrongRevision, protected); !errors.Is(err, ErrReferenceProtection) {
		t.Fatalf("Unprotect(wrong issuer revision AAD) error = %v, want ErrReferenceProtection", err)
	}

	otherProtector := testProtector(t, "key-2026-07", map[string]ProtectionKey{
		"key-2026-07": {
			EncryptionKey: bytes.Repeat([]byte{0x11}, 32),
			HMACKey:       bytes.Repeat([]byte{0x33}, 32),
		},
	})
	if _, err := otherProtector.Unprotect(context, protected); !errors.Is(err, ErrReferenceProtection) {
		t.Fatalf("Unprotect(wrong HMAC key) error = %v, want ErrReferenceProtection", err)
	}
}

func TestAESGCMProtectorSupportsKeyRotationWithoutMutatingCallerKeys(t *testing.T) {
	t.Parallel()

	oldEncryptionKey := bytes.Repeat([]byte{0x41}, 32)
	oldHMACKey := bytes.Repeat([]byte{0x42}, 32)
	oldProtector := testProtector(t, "old-key", map[string]ProtectionKey{
		"old-key": {EncryptionKey: oldEncryptionKey, HMACKey: oldHMACKey},
	})
	context := ReferenceContext{
		RevocationID: "10000000-0000-4000-8000-000000000002",
		ActionID:     "20000000-0000-4000-8000-000000000002",
		ActionEpoch:  3,
		Issuer:       "vault-production", IssuerRevision: "rev-1",
	}
	secret, err := NewSensitiveReference([]byte("old-accessor"))
	if err != nil {
		t.Fatal(err)
	}
	oldProtected, err := oldProtector.Protect(context, secret)
	if err != nil {
		t.Fatal(err)
	}

	rotated := testProtector(t, "new-key", map[string]ProtectionKey{
		"old-key": {EncryptionKey: oldEncryptionKey, HMACKey: oldHMACKey},
		"new-key": {
			EncryptionKey: bytes.Repeat([]byte{0x51}, 32),
			HMACKey:       bytes.Repeat([]byte{0x52}, 32),
		},
	})
	clear(oldEncryptionKey)
	clear(oldHMACKey)
	matched, err := rotated.Matches(context, oldProtected, secret)
	if err != nil || !matched {
		t.Fatalf("rotated Matches(old key ID) = %v, %v", matched, err)
	}
	different, _ := NewSensitiveReference([]byte("different-accessor"))
	matched, err = rotated.Matches(context, oldProtected, different)
	if err != nil || matched {
		t.Fatalf("rotated Matches(different accessor) = %v, %v", matched, err)
	}

	opened, err := rotated.Unprotect(context, oldProtected)
	if err != nil || string(opened.Bytes()) != "old-accessor" {
		t.Fatalf("rotated Unprotect(old) = %q, %v", opened.Bytes(), err)
	}
	newReference, _ := NewSensitiveReference([]byte("new-accessor"))
	newProtected, err := rotated.Protect(context, newReference)
	if err != nil {
		t.Fatal(err)
	}
	if newProtected.KeyID != "new-key" {
		t.Fatalf("new protected key id = %q", newProtected.KeyID)
	}
}

func TestSensitiveAndProtectedReferencesNeverRenderSecretMaterial(t *testing.T) {
	t.Parallel()

	plaintext := []byte("do-not-render-accessor")
	reference, err := NewSensitiveReference(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	protected := ProtectedReference{
		Ciphertext:   []byte("do-not-render-ciphertext"),
		AccessorHMAC: bytes.Repeat([]byte{0x77}, 32),
		KeyID:        "key-safe-to-identify",
	}

	for name, value := range map[string]any{
		"sensitive JSON": reference,
		"protected JSON": protected,
	} {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("marshal %s: %v", name, marshalErr)
		}
		if bytes.Contains(encoded, plaintext) || bytes.Contains(encoded, protected.Ciphertext) {
			t.Fatalf("%s leaked material: %s", name, encoded)
		}
	}
	for _, rendered := range []string{fmt.Sprint(reference), fmt.Sprintf("%+v", reference), fmt.Sprint(protected), fmt.Sprintf("%+v", protected)} {
		if strings.Contains(rendered, string(plaintext)) || strings.Contains(rendered, string(protected.Ciphertext)) {
			t.Fatalf("formatted reference leaked material: %s", rendered)
		}
	}
	referenceValue := *reference
	for _, rendered := range []string{fmt.Sprint(referenceValue), fmt.Sprintf("%+v", referenceValue), fmt.Sprintf("%#v", referenceValue)} {
		if strings.Contains(rendered, string(plaintext)) || strings.Contains(rendered, fmt.Sprint(plaintext)) {
			t.Fatalf("copied sensitive reference leaked material: %s", rendered)
		}
	}

	copyBeforeDestroy := reference.Bytes()
	reference.Destroy()
	if got := reference.Bytes(); len(got) != 0 {
		t.Fatalf("Destroy() retained %d bytes", len(got))
	}
	if string(copyBeforeDestroy) != string(plaintext) {
		t.Fatal("Bytes() did not return an independent copy")
	}
}

func TestFailureRequestsNeverRenderUpstreamDetail(t *testing.T) {
	t.Parallel()
	detail := []byte("upstream secret-shaped response body")
	fence := ClaimFence{
		RevocationID: "10000000-0000-4000-8000-000000000098", WorkerID: "revoker-1", Token: "claim-token", Epoch: 1,
	}
	values := []any{
		RetryRevocationRequest{Fence: fence, Delay: time.Second, FailureCode: FailureIssuerUnavailable, FailureDetail: detail},
		RequireManualRequest{Fence: fence, FailureCode: FailurePermissionDenied, FailureDetail: detail},
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		rendered := fmt.Sprintf("%+v %#v", value, value)
		if strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(detail)) || strings.Contains(rendered, fmt.Sprint(detail)) {
			t.Fatalf("failure request leaked upstream detail: json=%s format=%s", encoded, rendered)
		}
	}
}

func TestFencesAndKeyMaterialNeverRenderBearerOrKeys(t *testing.T) {
	t.Parallel()
	actionToken := "action-bearer-must-not-render"
	claimToken := "claim-bearer-must-not-render"
	actionFence := ActionFence{ActionID: "action-1", RunnerID: "runner-1", Token: actionToken, Epoch: 2}
	claimFence := ClaimFence{
		RevocationID: "10000000-0000-4000-8000-000000000099", WorkerID: "revoker-1", Token: claimToken, Epoch: 3,
	}
	key := ProtectionKey{
		EncryptionKey: bytes.Repeat([]byte{0x73}, 32),
		HMACKey:       bytes.Repeat([]byte{0x74}, 32),
	}
	keyRender := fmt.Sprint(key.EncryptionKey)
	protector := testProtector(t, "key-1", map[string]ProtectionKey{"key-1": key})

	for name, value := range map[string]any{
		"action fence": actionFence,
		"claim fence":  claimFence,
		"key":          key,
		"ring":         KeyRing{ActiveKeyID: "key-1", Keys: map[string]ProtectionKey{"key-1": key}},
		"protector":    protector,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		rendered := fmt.Sprintf("%+v %#v", value, value)
		if strings.Contains(string(encoded), actionToken) || strings.Contains(string(encoded), claimToken) ||
			strings.Contains(rendered, actionToken) || strings.Contains(rendered, claimToken) || strings.Contains(rendered, keyRender) {
			t.Fatalf("%s rendered bearer or key material: json=%s format=%s", name, encoded, rendered)
		}
	}
}

func TestAESGCMProtectorRejectsMalformedKeysAndProtectedShape(t *testing.T) {
	t.Parallel()

	invalidRings := []KeyRing{
		{},
		{ActiveKeyID: "missing", Keys: map[string]ProtectionKey{}},
		{ActiveKeyID: "short", Keys: map[string]ProtectionKey{
			"short": {EncryptionKey: bytes.Repeat([]byte{1}, 16), HMACKey: bytes.Repeat([]byte{2}, 32)},
		}},
		{ActiveKeyID: "short-hmac", Keys: map[string]ProtectionKey{
			"short-hmac": {EncryptionKey: bytes.Repeat([]byte{1}, 32), HMACKey: bytes.Repeat([]byte{2}, 16)},
		}},
		{ActiveKeyID: "same-key", Keys: map[string]ProtectionKey{
			"same-key": {EncryptionKey: bytes.Repeat([]byte{3}, 32), HMACKey: bytes.Repeat([]byte{3}, 32)},
		}},
	}
	for index, ring := range invalidRings {
		if _, err := NewAESGCMProtector(ring); !errors.Is(err, ErrReferenceProtection) {
			t.Errorf("NewAESGCMProtector(invalid[%d]) error = %v", index, err)
		}
	}

	protector := testProtector(t, "key", map[string]ProtectionKey{
		"key": {EncryptionKey: bytes.Repeat([]byte{1}, 32), HMACKey: bytes.Repeat([]byte{2}, 32)},
	})
	context := ReferenceContext{
		RevocationID:   "10000000-0000-4000-8000-000000000003",
		ActionID:       "20000000-0000-4000-8000-000000000003",
		ActionEpoch:    1,
		Issuer:         "vault",
		IssuerRevision: "rev-1",
	}
	if _, err := protector.Unprotect(context, ProtectedReference{KeyID: "key"}); !errors.Is(err, ErrReferenceProtection) {
		t.Fatalf("Unprotect(malformed) error = %v", err)
	}
}

func TestAESGCMProtectorDestroyIsConcurrentIdempotentAndFailsClosed(t *testing.T) {
	t.Parallel()
	protector := testProtector(t, "destroy-key", map[string]ProtectionKey{
		"destroy-key": {
			EncryptionKey: bytes.Repeat([]byte{0x81}, 32),
			HMACKey:       bytes.Repeat([]byte{0x82}, 32),
		},
	})
	context := ReferenceContext{
		RevocationID: "10000000-0000-4000-8000-000000000097",
		ActionID:     "20000000-0000-4000-8000-000000000097",
		ActionEpoch:  2,
		Issuer:       "vault-production", IssuerRevision: "rev-1",
	}
	reference, _ := NewSensitiveReference([]byte("destroy-race-accessor"))
	protected, err := protector.Protect(context, reference)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errorsByWorker := make(chan error, 32)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for range 8 {
				sealed, protectErr := protector.Protect(context, reference)
				if protectErr != nil {
					if !errors.Is(protectErr, ErrReferenceProtection) {
						errorsByWorker <- protectErr
					}
					return
				}
				opened, openErr := protector.Unprotect(context, sealed)
				if openErr != nil {
					if !errors.Is(openErr, ErrReferenceProtection) {
						errorsByWorker <- openErr
					}
					return
				}
				opened.Destroy()
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		protector.Destroy()
		protector.Destroy()
	}()
	close(start)
	wait.Wait()
	close(errorsByWorker)
	for workerErr := range errorsByWorker {
		t.Errorf("concurrent protector operation error = %v", workerErr)
	}
	if _, err := protector.Protect(context, reference); !errors.Is(err, ErrReferenceProtection) {
		t.Fatalf("Protect(after Destroy) error = %v", err)
	}
	if _, err := protector.Unprotect(context, protected); !errors.Is(err, ErrReferenceProtection) {
		t.Fatalf("Unprotect(after Destroy) error = %v", err)
	}
	if _, err := protector.Matches(context, protected, reference); !errors.Is(err, ErrReferenceProtection) {
		t.Fatalf("Matches(after Destroy) error = %v", err)
	}
	if err := protector.Close(); err != nil {
		t.Fatalf("Close(after Destroy) error = %v", err)
	}
}

func testProtector(t *testing.T, active string, keys map[string]ProtectionKey) *AESGCMProtector {
	t.Helper()
	protector, err := NewAESGCMProtector(KeyRing{ActiveKeyID: active, Keys: keys})
	if err != nil {
		t.Fatalf("NewAESGCMProtector() error = %v", err)
	}
	t.Cleanup(protector.Destroy)
	return protector
}
