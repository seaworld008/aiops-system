package investigation_test

import (
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestNormalizeSignalStripsMonotonicTimeAndDetachesLabels(t *testing.T) {
	observedAt := time.Now()
	signal := domain.Signal{
		ID: "signal-1", WorkspaceID: "workspace-1", IntegrationID: "integration-1",
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: testSHA256Hex([]byte("payload")),
		Fingerprint: "fingerprint-1", Status: "firing", Labels: map[string]string{"service": "payments"},
		ObservedAt: observedAt,
	}
	normalized, err := investigation.NormalizeSignal(signal, observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("NormalizeSignal() error = %v", err)
	}
	wantObservedAt := time.Unix(0, observedAt.UnixNano()).UTC()
	if normalized.ObservedAt != wantObservedAt {
		t.Fatalf("ObservedAt = %#v, want UTC time without monotonic component %#v", normalized.ObservedAt, wantObservedAt)
	}
	signal.Labels["service"] = "mutated"
	if normalized.Labels["service"] != "payments" {
		t.Fatalf("normalized Labels alias caller: %v", normalized.Labels)
	}
}

func TestNormalizeSignalForReplayCanonicalizesEmptyLabels(t *testing.T) {
	now := time.Date(2026, 7, 13, 6, 10, 0, 0, time.UTC)
	signal := domain.Signal{
		ID: "signal-empty-labels", WorkspaceID: "workspace-1", IntegrationID: "integration-1",
		Provider: "alertmanager", ProviderEventID: "event-empty-labels", PayloadHash: testSHA256Hex([]byte("payload")),
		Fingerprint: "fingerprint-empty-labels", Status: "firing", ObservedAt: now,
	}
	nilLabels, err := investigation.NormalizeSignalForReplay(signal)
	if err != nil {
		t.Fatalf("NormalizeSignalForReplay(nil labels) error = %v", err)
	}
	signal.Labels = map[string]string{}
	emptyLabels, err := investigation.NormalizeSignalForReplay(signal)
	if err != nil {
		t.Fatalf("NormalizeSignalForReplay(empty labels) error = %v", err)
	}
	if nilLabels.Labels == nil || emptyLabels.Labels == nil || len(nilLabels.Labels) != 0 || len(emptyLabels.Labels) != 0 {
		t.Fatalf("normalized labels = %#v/%#v, want canonical non-nil empty maps", nilLabels.Labels, emptyLabels.Labels)
	}
}
