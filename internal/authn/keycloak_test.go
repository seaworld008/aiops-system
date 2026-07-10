package authn

import (
	"context"
	"testing"
)

func TestNewKeycloakVerifierRejectsUnsafeDiscoveryConfiguration(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		issuer   string
		clientID string
	}{
		{"", "aiops-control-plane"},
		{"http://keycloak.example.com/realms/aiops", "aiops-control-plane"},
		{"https://user@keycloak.example.com/realms/aiops", "aiops-control-plane"},
		{"https://keycloak.example.com/realms/aiops?secret=x", "aiops-control-plane"},
		{"https://keycloak.example.com/realms/aiops", ""},
	} {
		if _, err := NewKeycloakVerifier(context.Background(), test.issuer, test.clientID); err == nil {
			t.Fatalf("NewKeycloakVerifier(%q, %q) error = nil", test.issuer, test.clientID)
		}
	}
}
