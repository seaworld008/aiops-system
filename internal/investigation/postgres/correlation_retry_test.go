package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestRetryableCorrelationErrorClassifiesOnlyTransientAndActiveCorrelationConflicts(t *testing.T) {
	t.Parallel()
	ordinary := errors.New("ordinary failure")
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "serialization failure", err: &pgconn.PgError{Code: "40001"}, want: true},
		{name: "deadlock", err: &pgconn.PgError{Code: "40P01"}, want: true},
		{
			name: "active correlation winner",
			err:  &pgconn.PgError{Code: "23505", ConstraintName: "incidents_active_correlation_uk"},
			want: true,
		},
		{
			name: "other unique constraint",
			err:  &pgconn.PgError{Code: "23505", ConstraintName: "incidents_pkey"},
			want: false,
		},
		{name: "ordinary error", err: ordinary, want: false},
		{
			name: "wrapped serialization failure",
			err:  databaseError("commit correlation", &pgconn.PgError{Code: "40001"}),
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := retryableCorrelationError(test.err); got != test.want {
				t.Fatalf("retryableCorrelationError(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

func TestMapCorrelationWriteErrorClassifiesPersistentIDCollisionsWithoutDiagnostics(t *testing.T) {
	t.Parallel()
	const canary = "postgres://admin:secret@internal.example/aiops"
	for _, constraint := range []string{"incidents_pkey", "outbox_events_pkey"} {
		t.Run(constraint, func(t *testing.T) {
			t.Parallel()
			postgresError := &pgconn.PgError{
				Code: "23505", ConstraintName: constraint,
				Message: canary, Detail: canary, Hint: canary,
			}
			mapped := mapCorrelationWriteError("persist correlation", postgresError)
			if !errors.Is(mapped, investigation.ErrInvalidRequest) {
				t.Fatalf("mapCorrelationWriteError(%s) = %v, want ErrInvalidRequest", constraint, mapped)
			}
			if strings.Contains(mapped.Error(), canary) {
				t.Fatalf("mapCorrelationWriteError(%s) leaked PostgreSQL diagnostics: %v", constraint, mapped)
			}
			var retained *pgconn.PgError
			if errors.As(mapped, &retained) {
				t.Fatalf("mapCorrelationWriteError(%s) retained diagnostic-bearing PgError", constraint)
			}
		})
	}
}
