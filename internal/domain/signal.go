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
	}
	for name, value := range fields {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if signal.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at is required")
	}
	return nil
}
