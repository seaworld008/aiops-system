package postgres

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestGetRegisteredSignalReadsGlobalPrimaryKeyAndTrustedCompositeScope(t *testing.T) {
	database, repository := newRegisteredSignalMockRepository(t)
	now := time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC)
	database.ExpectBegin()
	database.ExpectQuery(`(?s)JOIN workspaces AS workspace.*workspace\.id = signal\.workspace_id.*workspace\.tenant_id = signal\.tenant_id.*JOIN integrations AS integration.*integration\.id = signal\.integration_id.*integration\.tenant_id = signal\.tenant_id.*integration\.workspace_id = signal\.workspace_id.*integration\.provider = signal\.provider.*WHERE signal\.id = \$1.*FOR SHARE OF signal, workspace, integration`).
		WithArgs(writeMockSignalID).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "tenant_id", "workspace_id", "integration_id", "provider", "provider_event_id",
			"payload_hash", "fingerprint", "status", "labels", "observed_at",
		}).AddRow(
			writeMockSignalID, writeMockTenantID, writeMockWorkspaceID, writeMockServiceID,
			"alertmanager", "event-1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "payments", "firing", []byte(`{"service":"payments"}`), now,
		))
	database.ExpectCommit()

	registered, err := repository.GetRegisteredSignal(context.Background(), writeMockSignalID)
	if err != nil || registered.TenantID != writeMockTenantID || registered.WorkspaceID != writeMockWorkspaceID ||
		registered.Signal.ID != writeMockSignalID {
		t.Fatalf("GetRegisteredSignal() = %#v, %v", registered, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestGetRegisteredSignalMapsMissingAndRejectsInvalidIDBeforeTransaction(t *testing.T) {
	database, repository := newRegisteredSignalMockRepository(t)
	if _, err := repository.GetRegisteredSignal(context.Background(), "invalid"); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("GetRegisteredSignal(invalid) error = %v", err)
	}
	database.ExpectBegin()
	database.ExpectQuery(regexp.QuoteMeta("WHERE signal.id = $1")).WithArgs(writeMockSignalID).
		WillReturnError(errors.New("driver secret must not escape"))
	database.ExpectRollback()
	if _, err := repository.GetRegisteredSignal(context.Background(), writeMockSignalID); err == nil ||
		errors.Is(err, store.ErrNotFound) || regexp.MustCompile("driver secret").MatchString(err.Error()) {
		t.Fatalf("GetRegisteredSignal(database failure) error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func newRegisteredSignalMockRepository(t *testing.T) (pgxmock.PgxPoolIface, *Repository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	t.Cleanup(database.Close)
	repository, err := New(database, Options{
		TaskRuntimeBinder:  testTaskRuntimeBinder,
		IDFactory:          func() string { return writeMockInvestigationID },
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return database, repository
}
