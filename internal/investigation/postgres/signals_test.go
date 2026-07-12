package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestSignalOutboxIDCollisionIsNotMisclassifiedAsIdempotency(t *testing.T) {
	err := mapSignalOutboxError(&pgconn.PgError{
		Code: "23505", ConstraintName: "outbox_events_pkey", Message: "sensitive detail",
	})
	if !errors.Is(err, investigation.ErrInvalidRequest) || errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("mapSignalOutboxError() = %v", err)
	}
}

const (
	coreTenantID      = "10000000-0000-4000-8000-000000000001"
	coreWorkspaceID   = "20000000-0000-4000-8000-000000000002"
	coreIntegrationID = "30000000-0000-4000-8000-000000000003"
	coreSignalID      = "40000000-0000-4000-8000-000000000004"
	coreOutboxID      = "50000000-0000-4000-8000-000000000005"
)

func TestRegisterSignalPersistsFactAndOutboxAtomically(t *testing.T) {
	database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
	now := time.Date(2026, 7, 12, 9, 0, 0, 123456000, time.UTC)
	signal := coreSignal(now)

	database.ExpectBegin()
	expectCoreWorkspaceLock(database)
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(coreTenantID, coreWorkspaceID, coreSignalID).
		WillReturnRows(emptyCoreSignalRows())
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(coreTenantID, coreWorkspaceID, coreIntegrationID, signal.ProviderEventID).
		WillReturnRows(emptyCoreSignalRows())
	database.ExpectQuery("FROM integrations AS integration").
		WithArgs(coreTenantID, coreWorkspaceID, coreIntegrationID).
		WillReturnRows(pgxmock.NewRows([]string{"provider", "enabled", "now"}).AddRow(signal.Provider, true, now))
	database.ExpectExec("INSERT INTO signals").
		WithArgs(
			coreSignalID, coreTenantID, coreWorkspaceID, coreIntegrationID,
			signal.Provider, signal.ProviderEventID, signal.PayloadHash, signal.Fingerprint,
			signal.Status, now, `{"status":"firing","labels":{"severity":"warning"}}`,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(coreOutboxID, coreTenantID, coreWorkspaceID, coreSignalID, `{"signal_id":"40000000-0000-4000-8000-000000000004"}`).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	created, err := repository.RegisterSignal(context.Background(), signal)
	if err != nil || !created {
		t.Fatalf("RegisterSignal() = %v, %v; want true, nil", created, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestRegisterSignalExactReplaySkipsMutableAdmissionAndIDFactory(t *testing.T) {
	factoryCalls := 0
	database, repository := newCoreMockRepository(t, func() string {
		factoryCalls++
		return "invalid generated identifier"
	})
	now := time.Date(2026, 7, 12, 10, 0, 0, 654321000, time.UTC)
	signal := coreSignal(now)

	database.ExpectBegin()
	expectCoreWorkspaceLock(database)
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(coreTenantID, coreWorkspaceID, coreSignalID).
		WillReturnRows(coreSignalRows(signal))
	database.ExpectCommit()

	created, err := repository.RegisterSignal(context.Background(), signal)
	if err != nil || created || factoryCalls != 0 {
		t.Fatalf("RegisterSignal(replay) = %v, %v, factory calls %d; want false, nil, 0", created, err, factoryCalls)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestRegisterSignalChangedReplayConflictsOnCompleteFacts(t *testing.T) {
	database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })
	now := time.Date(2026, 7, 12, 11, 0, 0, 0, time.UTC)
	incoming := coreSignal(now)
	existing := incoming
	existing.Labels = map[string]string{"severity": "critical"}

	database.ExpectBegin()
	expectCoreWorkspaceLock(database)
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(coreTenantID, coreWorkspaceID, coreSignalID).
		WillReturnRows(coreSignalRows(existing))
	database.ExpectRollback()

	created, err := repository.RegisterSignal(context.Background(), incoming)
	if created || !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("RegisterSignal(changed replay) = %v, %v; want conflict", created, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestRegisterSignalChecksDBClockOnlyForNewFact(t *testing.T) {
	factoryCalls := 0
	database, repository := newCoreMockRepository(t, func() string {
		factoryCalls++
		return coreOutboxID
	})
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	signal := coreSignal(now.Add(investigation.MaxSignalFutureSkew + time.Microsecond))

	database.ExpectBegin()
	expectCoreWorkspaceLock(database)
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(coreTenantID, coreWorkspaceID, coreSignalID).
		WillReturnRows(emptyCoreSignalRows())
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(coreTenantID, coreWorkspaceID, coreIntegrationID, signal.ProviderEventID).
		WillReturnRows(emptyCoreSignalRows())
	database.ExpectQuery("FROM integrations AS integration").
		WithArgs(coreTenantID, coreWorkspaceID, coreIntegrationID).
		WillReturnRows(pgxmock.NewRows([]string{"provider", "enabled", "now"}).AddRow(signal.Provider, true, now))
	database.ExpectRollback()

	created, err := repository.RegisterSignal(context.Background(), signal)
	if created || !errors.Is(err, investigation.ErrInvalidRequest) || factoryCalls != 0 {
		t.Fatalf("RegisterSignal(future) = %v, %v, factory calls %d; want admission rejection before generation", created, err, factoryCalls)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestGetSignalReturnsNotFoundAcrossWorkspaceScope(t *testing.T) {
	database, repository := newCoreMockRepository(t, func() string { return coreOutboxID })

	database.ExpectBegin()
	expectCoreWorkspaceLock(database)
	database.ExpectQuery("FROM signals AS signal").
		WithArgs(coreTenantID, coreWorkspaceID, coreSignalID).
		WillReturnRows(emptyCoreSignalRows())
	database.ExpectRollback()

	_, err := repository.GetSignal(context.Background(), coreWorkspaceID, coreSignalID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSignal(cross workspace) error = %v, want ErrNotFound", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func newCoreMockRepository(t *testing.T, idFactory func() string) (pgxmock.PgxPoolIface, *Repository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	t.Cleanup(database.Close)
	repository, err := New(database, Options{
		TaskRuntimeBinder:  testTaskRuntimeBinder,
		IDFactory:          idFactory,
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return database, repository
}

func expectCoreWorkspaceLock(database pgxmock.PgxPoolIface) {
	database.ExpectQuery("SELECT tenant_id::text").
		WithArgs(coreWorkspaceID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id"}).AddRow(coreTenantID))
}

func coreSignal(observedAt time.Time) domain.Signal {
	return domain.Signal{
		ID:              coreSignalID,
		WorkspaceID:     coreWorkspaceID,
		IntegrationID:   coreIntegrationID,
		Provider:        "alertmanager",
		ProviderEventID: "event-42",
		PayloadHash:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Fingerprint:     "payments:latency",
		Status:          "firing",
		Labels:          map[string]string{"severity": "warning"},
		ObservedAt:      observedAt,
	}
}

func emptyCoreSignalRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "integration_id", "provider",
		"provider_event_id", "payload_hash", "fingerprint", "status", "labels", "observed_at",
	})
}

func coreSignalRows(signal domain.Signal) *pgxmock.Rows {
	labels := `{"severity":"warning"}`
	if signal.Labels["severity"] == "critical" {
		labels = `{"severity":"critical"}`
	}
	return emptyCoreSignalRows().AddRow(
		signal.ID,
		coreTenantID,
		signal.WorkspaceID,
		signal.IntegrationID,
		signal.Provider,
		signal.ProviderEventID,
		signal.PayloadHash,
		signal.Fingerprint,
		signal.Status,
		[]byte(labels),
		signal.ObservedAt,
	)
}
