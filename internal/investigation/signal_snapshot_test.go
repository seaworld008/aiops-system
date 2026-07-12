package investigation_test

import (
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestRegisteredSignalSnapshotHashBindsTrustedTenantAndEveryNormalizedSignalFact(t *testing.T) {
	base := investigation.RegisteredSignal{
		TenantID:    "99999999-9999-4999-8999-999999999999",
		WorkspaceID: "22222222-2222-4222-8222-222222222222",
		Signal: domain.Signal{
			ID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222",
			IntegrationID: "33333333-3333-4333-8333-333333333333", Provider: "alertmanager",
			ProviderEventID: "event-1", PayloadHash: strings.Repeat("a", 64), Fingerprint: "payments",
			Status: "firing", Labels: map[string]string{"service": "payments"},
			ObservedAt: time.Date(2026, 7, 12, 6, 0, 0, 123456000, time.UTC),
		},
	}
	want, err := investigation.RegisteredSignalSnapshotHash(base)
	if err != nil || !domain.ValidSHA256Hex(want) {
		t.Fatalf("RegisteredSignalSnapshotHash() = %q, %v", want, err)
	}
	mutations := map[string]func(*investigation.RegisteredSignal){
		"tenant": func(registered *investigation.RegisteredSignal) {
			registered.TenantID = "88888888-8888-4888-8888-888888888888"
		},
		"id": func(registered *investigation.RegisteredSignal) {
			registered.Signal.ID = "44444444-4444-4444-8444-444444444444"
		},
		"workspace": func(registered *investigation.RegisteredSignal) {
			registered.WorkspaceID = "44444444-4444-4444-8444-444444444444"
			registered.Signal.WorkspaceID = registered.WorkspaceID
		},
		"integration": func(registered *investigation.RegisteredSignal) {
			registered.Signal.IntegrationID = "44444444-4444-4444-8444-444444444444"
		},
		"provider":       func(registered *investigation.RegisteredSignal) { registered.Signal.Provider = "nightingale" },
		"provider event": func(registered *investigation.RegisteredSignal) { registered.Signal.ProviderEventID = "event-2" },
		"payload hash": func(registered *investigation.RegisteredSignal) {
			registered.Signal.PayloadHash = strings.Repeat("b", 64)
		},
		"fingerprint": func(registered *investigation.RegisteredSignal) { registered.Signal.Fingerprint = "checkout" },
		"status":      func(registered *investigation.RegisteredSignal) { registered.Signal.Status = "resolved" },
		"labels":      func(registered *investigation.RegisteredSignal) { registered.Signal.Labels["service"] = "checkout" },
		"observed at": func(registered *investigation.RegisteredSignal) {
			registered.Signal.ObservedAt = registered.Signal.ObservedAt.Add(time.Microsecond)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.Signal.Labels = map[string]string{"service": "payments"}
			mutate(&changed)
			got, err := investigation.RegisteredSignalSnapshotHash(changed)
			if err != nil || got == want {
				t.Fatalf("RegisteredSignalSnapshotHash(mutated %s) = %q, %v; want distinct", name, got, err)
			}
		})
	}
	ordered := base
	ordered.Signal.Labels = map[string]string{"zone": "a", "service": "payments"}
	reordered := base
	reordered.Signal.Labels = map[string]string{"service": "payments", "zone": "a"}
	left, _ := investigation.RegisteredSignalSnapshotHash(ordered)
	right, _ := investigation.RegisteredSignalSnapshotHash(reordered)
	if left != right {
		t.Fatalf("label insertion order changed hash: %s / %s", left, right)
	}
}
