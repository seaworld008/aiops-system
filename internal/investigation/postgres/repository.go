package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

// DB is the minimum pgx pool contract used by the investigation repository.
// Transactions remain the tenant-resolution and consistency boundary even for
// reads; the direct methods are retained so a pool or an already scoped test
// double can satisfy the same dependency contract.
type DB interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Options struct {
	IDFactory          func() string
	TaskSpecAuthorizer investigation.TaskSpecAuthorizer
}

type Repository struct {
	database           DB
	idFactory          func() string
	taskSpecAuthorizer investigation.TaskSpecAuthorizer
}

var _ investigation.Repository = (*Repository)(nil)

var errDatabaseOperation = errors.New("investigation database operation failed")

func New(database DB, options Options) (*Repository, error) {
	if nilInterface(database) || options.IDFactory == nil || options.TaskSpecAuthorizer == nil {
		return nil, fmt.Errorf("%w: trusted PostgreSQL repository dependencies are required", investigation.ErrInvalidRequest)
	}
	return &Repository{
		database:           database,
		idFactory:          options.IDFactory,
		taskSpecAuthorizer: options.TaskSpecAuthorizer,
	}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) &&
		reflect.ValueOf(value).IsNil()
}

func (repository *Repository) newUUID() (string, error) {
	id := repository.idFactory()
	if !validUUID(id) {
		return "", fmt.Errorf("%w: ID factory returned an invalid persistent resource ID", investigation.ErrInvalidRequest)
	}
	return id, nil
}

func databaseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	// SQLSTATE alone is not an application error contract. A 23505 can be an
	// ID-factory collision, a uniqueness invariant, or a true idempotency
	// conflict; a deferred 23514 usually means our transaction violated a
	// persistence invariant. Callers that intentionally map a named constraint
	// do so at that operation boundary. Everything else remains a redacted,
	// retry-classifiable persistence failure.
	return databaseOperationError{operation: operation, cause: err}
}

// databaseOperationError preserves the underlying error for trusted internal
// classification without copying PostgreSQL messages, hints, identities or
// connection details into its user-facing string.
type databaseOperationError struct {
	operation string
	cause     error
}

func (failure databaseOperationError) Error() string {
	return failure.operation + ": " + errDatabaseOperation.Error()
}

func (failure databaseOperationError) Unwrap() []error {
	return []error{errDatabaseOperation, failure.cause}
}
