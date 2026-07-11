package memory_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
)

func newRepository(t *testing.T, now time.Time) *memory.Repository {
	t.Helper()
	var mu sync.Mutex
	next := 0
	repository, err := memory.New(memory.Options{
		Clock:          func() time.Time { return now },
		TenantResolver: testTenantResolver,
		IDFactory: func() string {
			mu.Lock()
			defer mu.Unlock()
			next++
			return fmt.Sprintf("generated-%d", next)
		},
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	return repository
}

func testTenantResolver(workspaceID string) (string, error) {
	return "tenant-" + workspaceID, nil
}

func testSignal(workspaceID, signalID, status string, observedAt time.Time) domain.Signal {
	return domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: "integration-1", Provider: "alertmanager",
		ProviderEventID: signalID, PayloadHash: sha256Hex([]byte("payload-" + signalID)), Fingerprint: "fingerprint-1",
		Status: status, Labels: map[string]string{"service": "payments"}, ObservedAt: observedAt,
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func createIncident(t *testing.T, repository *memory.Repository, workspaceID, signalID string, now time.Time) domain.Incident {
	t.Helper()
	signal := testSignal(workspaceID, signalID, "firing", now)
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal() error = %v", err)
	}
	result, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: workspaceID, SignalID: signalID, CorrelationKey: "payments:prod:" + signalID,
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	})
	if err != nil {
		t.Fatalf("CorrelateSignal() error = %v", err)
	}
	return result.Incident
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func startModel(t *testing.T, repository *memory.Repository, investigationID, idempotencyKey string) {
	t.Helper()
	if _, err := repository.StartModel(context.Background(), investigation.StartModelRequest{
		WorkspaceID: "workspace-1", InvestigationID: investigationID, IdempotencyKey: idempotencyKey,
	}); err != nil {
		t.Fatalf("StartModel() error = %v", err)
	}
}
