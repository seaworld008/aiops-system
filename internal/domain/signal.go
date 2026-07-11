package domain

import (
	"fmt"
	"time"
)

type Signal struct {
	ID              string
	WorkspaceID     string
	IntegrationID   string
	Provider        string
	ProviderEventID string
	PayloadHash     string
	Fingerprint     string
	Status          string
	Labels          map[string]string
	ObservedAt      time.Time
}

func (signal Signal) Validate() error {
	fields := map[string]string{
		"id":                signal.ID,
		"workspace_id":      signal.WorkspaceID,
		"integration_id":    signal.IntegrationID,
		"provider":          signal.Provider,
		"provider_event_id": signal.ProviderEventID,
		"payload_hash":      signal.PayloadHash,
		"fingerprint":       signal.Fingerprint,
		"status":            signal.Status,
	}
	for name, value := range fields {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if signal.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at is required")
	}
	if len(signal.Provider) > 64 || len(signal.ProviderEventID) > 512 || len(signal.Fingerprint) > 512 || len(signal.PayloadHash) > 128 {
		return fmt.Errorf("signal indexed fields exceed byte limits")
	}
	if !lowCardinalityPattern.MatchString(signal.Provider) || !ValidSafeText(signal.Provider) ||
		!ValidSafeText(signal.ProviderEventID) || !ValidSafeText(signal.Fingerprint) {
		return fmt.Errorf("signal indexed metadata is unsafe")
	}
	if signal.Status != "firing" && signal.Status != "resolved" {
		return fmt.Errorf("signal status must be firing or resolved")
	}
	return nil
}
