package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/credential"
)

const cleanupInspectorQueryPattern = `SELECT status FROM credential_revocations WHERE action_id = \$1 AND action_lease_epoch = \$2`

func TestCleanupInspectorReportsMissingActionEpoch(t *testing.T) {
	t.Parallel()

	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectQuery(cleanupInspectorQueryPattern).
		WithArgs(postgresTestActionID, int64(7)).
		WillReturnRows(pgxmock.NewRows([]string{"status"}))

	present, terminal, err := repository.InspectCleanup(context.Background(), postgresTestActionID, 7)
	if err != nil || present || terminal {
		t.Fatalf("InspectCleanup() = (%t, %t, %v), want (false, false, nil)", present, terminal, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestCleanupInspectorClassifiesOnlyCleanupTerminalStatesAsTerminal(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		status   credential.RevocationStatus
		terminal bool
	}{
		{status: credential.StatusPrepared},
		{status: credential.StatusAnchored},
		{status: credential.StatusActive},
		{status: credential.StatusRevocationPending},
		{status: credential.StatusRevoking},
		{status: credential.StatusManualRequired},
		{status: credential.StatusRevoked, terminal: true},
		{status: credential.StatusNoCredential, terminal: true},
	} {
		t.Run(string(test.status), func(t *testing.T) {
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("pgxmock.NewPool() error = %v", err)
			}
			defer database.Close()
			repository, err := New(database, repositoryTestProtector(t), Options{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			database.ExpectQuery(cleanupInspectorQueryPattern).
				WithArgs(postgresTestActionID, int64(8)).
				WillReturnRows(pgxmock.NewRows([]string{"status"}).AddRow(string(test.status)))

			present, terminal, err := repository.InspectCleanup(context.Background(), postgresTestActionID, 8)
			if err != nil || !present || terminal != test.terminal {
				t.Fatalf("InspectCleanup(%s) = (%t, %t, %v), want (true, %t, nil)",
					test.status, present, terminal, err, test.terminal)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestCleanupInspectorValidatesActionEpochWithoutQuery(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		actionID string
		epoch    int64
	}{
		{name: "empty action", actionID: "", epoch: 1},
		{name: "invalid action", actionID: " action", epoch: 1},
		{name: "zero epoch", actionID: postgresTestActionID, epoch: 0},
		{name: "negative epoch", actionID: postgresTestActionID, epoch: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("pgxmock.NewPool() error = %v", err)
			}
			defer database.Close()
			repository, err := New(database, repositoryTestProtector(t), Options{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			present, terminal, err := repository.InspectCleanup(context.Background(), test.actionID, test.epoch)
			if !errors.Is(err, credential.ErrInvalidRevocationRequest) || present || terminal {
				t.Fatalf("InspectCleanup() = (%t, %t, %v), want invalid request", present, terminal, err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unexpected database query: %v", err)
			}
		})
	}
}

func TestCleanupInspectorPreservesContextErrors(t *testing.T) {
	t.Parallel()

	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	present, terminal, err := repository.InspectCleanup(ctx, postgresTestActionID, 9)
	if err != context.Canceled || present || terminal {
		t.Fatalf("InspectCleanup(canceled) = (%t, %t, %v), want context.Canceled", present, terminal, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected database query: %v", err)
	}

	database.ExpectQuery(cleanupInspectorQueryPattern).
		WithArgs(postgresTestActionID, int64(9)).
		WillReturnError(context.DeadlineExceeded)
	present, terminal, err = repository.InspectCleanup(context.Background(), postgresTestActionID, 9)
	if err != context.DeadlineExceeded || present || terminal {
		t.Fatalf("InspectCleanup(database deadline) = (%t, %t, %v), want context.DeadlineExceeded", present, terminal, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestCleanupInspectorWrapsStorageErrorsWithoutLeakingDriverDetails(t *testing.T) {
	t.Parallel()

	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	const secretDriverDetail = "plaintext-accessor-driver-detail"
	database.ExpectQuery(cleanupInspectorQueryPattern).
		WithArgs(postgresTestActionID, int64(10)).
		WillReturnError(errors.New(secretDriverDetail))

	present, terminal, err := repository.InspectCleanup(context.Background(), postgresTestActionID, 10)
	if !errors.Is(err, credential.ErrRevocationPersistence) || present || terminal {
		t.Fatalf("InspectCleanup(storage error) = (%t, %t, %v), want safe persistence error", present, terminal, err)
	}
	if strings.Contains(err.Error(), secretDriverDetail) {
		t.Fatalf("InspectCleanup(storage error) leaked driver detail: %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}
