package domain_test

import (
	"strings"
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

func TestSignalValidateRejectsUnsafeIndexedMetadataWithoutEcho(t *testing.T) {
	const canary = "signal-index-canary"
	valid := domain.Signal{
		ID: "signal-1", WorkspaceID: "workspace-1", IntegrationID: "integration-1",
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: strings.Repeat("a", 64),
		Fingerprint: "fingerprint-1", Status: "firing", ObservedAt: time.Now(),
	}
	for name, mutate := range map[string]func(*domain.Signal){
		"noncanonical provider":  func(signal *domain.Signal) { signal.Provider = "Alert Manager" },
		"invalid UTF-8 provider": func(signal *domain.Signal) { signal.Provider = string([]byte{0xff}) },
		"sensitive provider event": func(signal *domain.Signal) {
			signal.ProviderEventID = "authorization=" + canary
		},
		"format character fingerprint": func(signal *domain.Signal) {
			signal.Fingerprint = "fingerprint-1​"
		},
	} {
		t.Run(name, func(t *testing.T) {
			item := valid
			if mutate != nil {
				mutate(&item)
			}
			err := item.Validate()
			if err == nil {
				t.Fatal("Signal.Validate() error = nil, want unsafe metadata rejection")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Signal.Validate() echoed metadata: %v", err)
			}
		})
	}
}
