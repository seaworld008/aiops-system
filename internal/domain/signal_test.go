package domain_test

import (
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
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
