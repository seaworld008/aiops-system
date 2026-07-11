package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestValidUUIDRequiresCanonicalRFC4122VersionsOneThroughFive(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"11111111-1111-1111-8111-111111111111",
		"11111111-1111-2111-9111-111111111111",
		"11111111-1111-3111-a111-111111111111",
		"11111111-1111-4111-b111-111111111111",
		"11111111-1111-5111-8111-111111111111",
	} {
		if !validUUID(value) {
			t.Fatalf("validUUID(%q) = false", value)
		}
	}
	for _, value := range []string{
		"",
		"11111111-1111-0111-8111-111111111111",
		"11111111-1111-6111-8111-111111111111",
		"11111111-1111-4111-7111-111111111111",
		"11111111-1111-4111-c111-111111111111",
		"11111111-1111-4111-8111-11111111111Z",
		"11111111-1111-4111-8111-11111111111",
		"11111111-1111-4111-8111-111111111111 ",
	} {
		if validUUID(value) {
			t.Fatalf("validUUID(%q) = true", value)
		}
	}
}

func TestNewFailsClosedWithoutEveryTrustedDependency(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	authorizer := func(context.Context, string, investigation.TaskSpec) error { return nil }
	factory := func() string { return "11111111-1111-4111-8111-111111111111" }
	for name, operation := range map[string]func() (*Repository, error){
		"database": func() (*Repository, error) {
			return New(nil, Options{IDFactory: factory, TaskSpecAuthorizer: authorizer})
		},
		"ID factory": func() (*Repository, error) {
			return New(database, Options{TaskSpecAuthorizer: authorizer})
		},
		"task authorizer": func() (*Repository, error) {
			return New(database, Options{IDFactory: factory})
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, newErr := operation()
			if got != nil || !errors.Is(newErr, investigation.ErrInvalidRequest) {
				t.Fatalf("New(%s missing) = %#v, %v; want nil ErrInvalidRequest", name, got, newErr)
			}
		})
	}
}

func TestDatabaseErrorDoesNotExposePostgreSQLDiagnostics(t *testing.T) {
	t.Parallel()
	const secret = "postgres://admin:secret@example.internal/database"
	err := databaseError("read investigation", &pgconn.PgError{
		Code: "XX000", Message: secret, Detail: secret, Hint: secret,
	})
	if err == nil || strings.Contains(err.Error(), secret) || !errors.Is(err, errDatabaseOperation) {
		t.Fatalf("databaseError() = %v; want redacted sentinel", err)
	}
}

func TestDatabaseErrorDoesNotGuessDomainSemanticsFromSQLState(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"23505", "23503", "23514", "22P02"} {
		err := databaseError("persist investigation", &pgconn.PgError{
			Code: code, ConstraintName: "unknown_internal_constraint", Message: "sensitive diagnostic",
		})
		if !errors.Is(err, errDatabaseOperation) || errors.Is(err, store.ErrIdempotencyConflict) ||
			errors.Is(err, store.ErrNotFound) || errors.Is(err, investigation.ErrInvalidRequest) {
			t.Fatalf("databaseError(SQLSTATE %s) = %v; want only redacted persistence sentinel", code, err)
		}
	}
}

func TestInvalidPersistentReadIDsAreRejectedBeforeBegin(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := New(database, Options{
		IDFactory:          func() string { return "11111111-1111-4111-8111-111111111111" },
		TaskSpecAuthorizer: func(context.Context, string, investigation.TaskSpec) error { return nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()
	operations := map[string]func() error{
		"signal": func() error {
			_, operationErr := repository.GetSignal(ctx, "not-a-uuid", "11111111-1111-4111-8111-111111111111")
			return operationErr
		},
		"incident": func() error {
			_, operationErr := repository.GetIncident(ctx, "11111111-1111-4111-8111-111111111111", "UPPERCASE")
			return operationErr
		},
		"investigation list": func() error {
			_, operationErr := repository.ListInvestigations(ctx, investigation.ListInvestigationsRequest{
				WorkspaceID: "11111111-1111-4111-8111-111111111111",
				IncidentID:  "11111111-1111-6111-8111-111111111111",
			})
			return operationErr
		},
		"task": func() error {
			_, operationErr := repository.GetTask(ctx, "11111111-1111-4111-8111-111111111111", "")
			return operationErr
		},
		"evidence list": func() error {
			_, operationErr := repository.ListEvidence(ctx, investigation.ListEvidenceRequest{
				WorkspaceID:     "11111111-1111-4111-8111-111111111111",
				InvestigationID: "11111111-1111-4111-8111-111111111111",
				TaskID:          "11111111-1111-4111-7111-111111111111",
			})
			return operationErr
		},
		"hypothesis": func() error {
			_, operationErr := repository.GetHypothesis(ctx, "11111111-1111-4111-8111-111111111111", "11111111-1111-4111-C111-111111111111")
			return operationErr
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if operationErr := operation(); !errors.Is(operationErr, investigation.ErrInvalidRequest) {
				t.Fatalf("operation error = %v, want ErrInvalidRequest", operationErr)
			}
		})
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("invalid input reached database: %v", err)
	}
}
