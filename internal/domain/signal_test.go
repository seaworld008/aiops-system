package domain_test

import (
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

func TestSignalValidateRequiresProviderIdentityAndPayloadHash(t *testing.T) {
	signal := domain.Signal{
		ID:              "signal-1",
		WorkspaceID:     "workspace-1",
		IntegrationID:   "integration-1",
		Provider:        "alertmanager",
		ProviderEventID: "",
		PayloadHash:     "",
		ObservedAt:      time.Now(),
	}

	if err := signal.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want required field error")
	}
}

func TestSignalValidateRejectsOversizedIndexedFields(t *testing.T) {
	item := domain.Signal{
		ID: "signal-1", WorkspaceID: "workspace-1", IntegrationID: "integration-1",
		Provider: "nightingale", ProviderEventID: string(make([]byte, 513)),
		PayloadHash: "hash", Fingerprint: "fingerprint", Status: "firing", ObservedAt: time.Now(),
	}
	if err := item.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want indexed-field size rejection")
	}
}
