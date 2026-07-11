package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestStaleLeaseTransitionRecognizesOnlyTheNamedPostgreSQLGuard(t *testing.T) {
	t.Parallel()
	if !staleLeaseTransition(&pgconn.PgError{
		Code: "55000", ConstraintName: "investigation_task_attempts_lease_current_guard",
	}) {
		t.Fatal("staleLeaseTransition() rejected the named lease-current guard")
	}
	for _, failure := range []*pgconn.PgError{
		{Code: "55000", ConstraintName: "investigation_task_attempts_state_guard"},
		{Code: "23514", ConstraintName: "investigation_task_attempts_lease_current_guard"},
	} {
		if staleLeaseTransition(failure) {
			t.Fatalf("staleLeaseTransition() accepted unrelated PostgreSQL error: %#v", failure)
		}
	}
}

func TestEncodeLeaseTokenRequiresExactly256BitsAndCanonicalBase64URL(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 24, 31, 33, 64} {
		raw := make([]byte, size)
		if encoded, err := encodeLeaseToken(raw); err == nil || encoded != nil {
			t.Fatalf("encodeLeaseToken(%d bytes) = %q, %v; want rejection", size, encoded, err)
		}
	}
	raw := bytes.Repeat([]byte{0xff}, 32)
	encoded, err := encodeLeaseToken(raw)
	if err != nil || len(encoded) != 43 || bytes.ContainsRune(encoded, '=') {
		t.Fatalf("encodeLeaseToken(32 bytes) = %q (len=%d), %v", encoded, len(encoded), err)
	}
}

func TestNewRequiresPostgreSQLAndValidTrustedSources(t *testing.T) {
	t.Parallel()

	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	t.Cleanup(database.Close)

	validTokenSource := func() ([]byte, error) {
		return make([]byte, 32), nil
	}
	validIDSource := func() string { return "10000000-0000-4000-8000-000000000001" }
	var typedNil *nilDatabase
	tests := []struct {
		name     string
		database DB
		options  Options
	}{
		{name: "missing database", options: Options{TokenSource: validTokenSource, IDSource: validIDSource}},
		{name: "typed nil database", database: typedNil, options: Options{TokenSource: validTokenSource, IDSource: validIDSource}},
		{name: "missing token source", database: database, options: Options{IDSource: validIDSource}},
		{name: "missing ID source", database: database, options: Options{TokenSource: validTokenSource}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository, newErr := New(test.database, test.options)
			if repository != nil || !errors.Is(newErr, readtask.ErrInvalidRequest) {
				t.Fatalf("New() = %#v, %v; want ErrInvalidRequest", repository, newErr)
			}
		})
	}

	repository, err := New(database, Options{TokenSource: validTokenSource, IDSource: validIDSource})
	if err != nil || repository == nil {
		t.Fatalf("New(valid) = %#v, %v", repository, err)
	}
}

type nilDatabase struct{}

func (*nilDatabase) Begin(context.Context) (pgx.Tx, error) { return nil, errors.New("not called") }
