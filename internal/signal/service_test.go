package signal_test

import (
	"context"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/signal"
	"github.com/aiops-system/control-plane/internal/store/memory"
)

func TestIngestAlertmanagerCreatesOneSignalPerAlert(t *testing.T) {
	repository := memory.New()
	service := signal.NewService(repository, func() time.Time {
		return time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	})
	payload := []byte(`{
      "status":"firing",
      "groupKey":"{}:{alertname=\"HighErrorRate\"}",
      "alerts":[
        {"fingerprint":"abc", "startsAt":"2026-07-10T09:59:00Z", "labels":{"alertname":"HighErrorRate"}},
        {"fingerprint":"def", "startsAt":"2026-07-10T09:58:00Z", "labels":{"alertname":"PodRestarting"}}
      ]
    }`)

	result, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "alertmanager", payload)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if result.Accepted != 2 || result.Duplicates != 0 {
		t.Fatalf("result = %#v, want 2 accepted and 0 duplicates", result)
	}
}

func TestIngestNightingaleUsesEventIDForIdempotency(t *testing.T) {
	repository := memory.New()
	service := signal.NewService(repository, time.Now)
	payload := []byte(`{"event_id":"evt-1","hash":"host-1/cpu","trigger_time":1783650000}`)

	first, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "nightingale", payload)
	if err != nil {
		t.Fatalf("first Ingest() error = %v", err)
	}
	second, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "nightingale", payload)
	if err != nil {
		t.Fatalf("second Ingest() error = %v", err)
	}
	if first.Accepted != 1 || second.Duplicates != 1 {
		t.Fatalf("first=%#v second=%#v, want accepted then duplicate", first, second)
	}
}

func TestIngestRejectsUnsupportedProvider(t *testing.T) {
	service := signal.NewService(memory.New(), time.Now)
	_, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "unknown", []byte(`{}`))
	if err == nil {
		t.Fatal("Ingest() error = nil, want unsupported provider")
	}
}
