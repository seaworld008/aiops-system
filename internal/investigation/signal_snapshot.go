package investigation

import (
	"time"
)

const registeredSignalSnapshotSemanticsV1 = "investigation.registered-signal-snapshot.v1"

// RegisteredSignalSnapshotHash binds trusted Tenant/Workspace identity and
// every normalized Signal fact at the read boundary. It is an internal
// repository fence and is never part of Workflow input, receipt, or History.
func RegisteredSignalSnapshotHash(registered RegisteredSignal) (string, error) {
	if registered.Validate() != nil {
		return "", ErrInvalidRequest
	}
	normalized, err := NormalizeSignalForReplay(registered.Signal)
	if err != nil {
		return "", ErrInvalidRequest
	}
	return semanticRequestHash(registeredSignalSnapshotSemanticsV1, struct {
		TenantID        string            `json:"tenant_id"`
		ID              string            `json:"id"`
		WorkspaceID     string            `json:"workspace_id"`
		IntegrationID   string            `json:"integration_id"`
		Provider        string            `json:"provider"`
		ProviderEventID string            `json:"provider_event_id"`
		PayloadHash     string            `json:"payload_hash"`
		Fingerprint     string            `json:"fingerprint"`
		Status          string            `json:"status"`
		Labels          map[string]string `json:"labels"`
		ObservedAt      time.Time         `json:"observed_at"`
	}{
		TenantID: registered.TenantID,
		ID:       normalized.ID, WorkspaceID: registered.WorkspaceID, IntegrationID: normalized.IntegrationID,
		Provider: normalized.Provider, ProviderEventID: normalized.ProviderEventID, PayloadHash: normalized.PayloadHash,
		Fingerprint: normalized.Fingerprint, Status: normalized.Status, Labels: normalized.Labels, ObservedAt: normalized.ObservedAt,
	})
}
