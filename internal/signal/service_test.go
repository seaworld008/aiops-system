package signal_test

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
	"github.com/aiops-system/control-plane/internal/signal"
	"github.com/aiops-system/control-plane/internal/store/memory"
)

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

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

func TestIngestGeneratesPostgresCompatibleUUID(t *testing.T) {
	repository := &capturingRepository{}
	service := signal.NewService(repository, time.Now)
	payload := []byte(`{"event_id":"evt-1","hash":"host-1/cpu","trigger_time":1783650000}`)

	if _, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "nightingale", payload); err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if len(repository.signals) != 1 || !uuidV4Pattern.MatchString(repository.signals[0].ID) {
		t.Fatalf("generated signal ID = %q, want UUIDv4", repository.signals[0].ID)
	}
}

type capturingRepository struct {
	signals []domain.Signal
}

func (repository *capturingRepository) CreateSignal(_ context.Context, item domain.Signal) (bool, error) {
	repository.signals = append(repository.signals, item)
	return true, nil
}
