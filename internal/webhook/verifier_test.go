package webhook_test

import (
	"net/http"
	"testing"

	"github.com/aiops-system/control-plane/internal/webhook"
)

func TestHMACVerifierAcceptsValidSignatureAndRejectsTampering(t *testing.T) {
	verifier := webhook.NewHMACVerifier(func(integrationID, provider string) ([]byte, error) {
		return []byte("secret"), nil
	})
	body := []byte(`{"event":"firing"}`)
	headers := http.Header{}
	headers.Set(webhook.SignatureHeader, webhook.Sign("secret", body))

	if err := verifier.Verify("integration-1", "alertmanager", headers, body); err != nil {
		t.Fatalf("Verify(valid) error = %v", err)
	}
	if err := verifier.Verify("integration-1", "alertmanager", headers, []byte(`{"event":"resolved"}`)); err == nil {
		t.Fatal("Verify(tampered) error = nil, want rejection")
	}
}

