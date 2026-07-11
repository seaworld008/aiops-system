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
