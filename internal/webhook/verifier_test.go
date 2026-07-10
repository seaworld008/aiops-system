package webhook_test

import (
	"net/http"
	"testing"

	"github.com/seaworld008/aiops-system/internal/webhook"
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

func TestHMACVerifierResolvesSecretByIntegrationAndProvider(t *testing.T) {
	verifier := webhook.NewHMACVerifier(func(integrationID, provider string) ([]byte, error) {
		return []byte(integrationID + "/" + provider), nil
	})
	body := []byte(`{"event":"firing"}`)
	headers := http.Header{}
	headers.Set(webhook.SignatureHeader, webhook.Sign("integration-1/alertmanager", body))
	if err := verifier.Verify("integration-1", "alertmanager", headers, body); err != nil {
		t.Fatalf("Verify(scoped) error = %v", err)
	}
	if err := verifier.Verify("integration-2", "alertmanager", headers, body); err == nil {
		t.Fatal("Verify(other integration) error = nil, want rejection")
	}
}
