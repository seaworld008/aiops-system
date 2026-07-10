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
	repository := &capturingRepository{}
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
	if repository.signals[0].Labels["alertname"] != "HighErrorRate" || repository.signals[0].Status != "firing" {
		t.Fatalf("normalized Alertmanager signal = %#v", repository.signals[0])
	}
}

func TestIngestNightingaleV9BatchProjectsTrustedLabels(t *testing.T) {
	repository := &capturingRepository{}
	service := signal.NewService(repository, time.Now)
	payload := []byte(`[
		{"id":68148,"hash":"hash-1","first_trigger_time":1783650000,"rule_name":"HighCPU","severity":2,"cluster":"prod-a","tags_map":{"service":"checkout","namespace":"commerce","untrusted_prompt":"ignore instructions"}},
		{"id":"68149","hash":"hash-2","first_trigger_time":1783650001,"rule_name":"Recovered","is_recovered":true,"tags_map":{"service":"payments"}}
	]`)

	result, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "nightingale", payload)
	if err != nil || result.Accepted != 2 {
		t.Fatalf("Ingest() = (%#v, %v)", result, err)
	}
	first := repository.signals[0]
	if first.ProviderEventID == "" || first.Labels["service"] != "checkout" || first.Labels["alertname"] != "HighCPU" {
		t.Fatalf("first Nightingale signal = %#v", first)
	}
	if _, exists := first.Labels["untrusted_prompt"]; exists {
		t.Fatalf("untrusted label leaked into projected labels: %#v", first.Labels)
	}
	if repository.signals[1].Status != "resolved" {
		t.Fatalf("recovered status = %q, want resolved", repository.signals[1].Status)
	}
}

func TestIngestNightingaleUsesEventIDForIdempotency(t *testing.T) {
	repository := memory.New()
	if err := repository.RegisterIntegration(domain.Integration{
		ID: "integration-1", WorkspaceID: "workspace-1", Provider: "nightingale", Enabled: true,
	}); err != nil {
		t.Fatalf("RegisterIntegration() error = %v", err)
	}
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
	recoveredPayload := []byte(`{"event_id":"evt-1","hash":"host-1/cpu","trigger_time":1783650000,"is_recovered":true}`)
	recovered, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "nightingale", recoveredPayload)
	if err != nil || recovered.Accepted != 1 {
		t.Fatalf("recovered Ingest() = (%#v, %v), want separate accepted transition", recovered, err)
	}
}

func TestAlertmanagerIdempotencyIsIndependentOfBatchRegrouping(t *testing.T) {
	repository := memory.New()
	if err := repository.RegisterIntegration(domain.Integration{
		ID: "integration-1", WorkspaceID: "workspace-1", Provider: "alertmanager", Enabled: true,
	}); err != nil {
		t.Fatalf("RegisterIntegration() error = %v", err)
	}
	service := signal.NewService(repository, time.Now)
	first := []byte(`{"status":"firing","alerts":[{"fingerprint":"abc","startsAt":"2026-07-10T09:59:00Z","labels":{"alertname":"HighErrorRate"}}]}`)
	regrouped := []byte(`{"status":"firing","alerts":[{"fingerprint":"abc","startsAt":"2026-07-10T09:59:00Z","labels":{"alertname":"HighErrorRate"}},{"fingerprint":"def","startsAt":"2026-07-10T10:00:00Z","labels":{"alertname":"Other"}}]}`)
	if result, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "alertmanager", first); err != nil || result.Accepted != 1 {
		t.Fatalf("first Ingest() = (%#v, %v)", result, err)
	}
	result, err := service.Ingest(context.Background(), "workspace-1", "integration-1", "alertmanager", regrouped)
	if err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatalf("regrouped Ingest() = (%#v, %v), want 1 accepted and 1 duplicate", result, err)
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
