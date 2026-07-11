package postgres

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

const runtimeSchemaVersion = "investigation-runtime.v1"

var lowercaseRFC4122UUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func validUUID(value string) bool {
	return lowercaseRFC4122UUID.MatchString(value)
}

func validUUIDs(values ...string) bool {
	for _, value := range values {
		if !validUUID(value) {
			return false
		}
	}
	return true
}

func validOptionalUUID(value string) bool {
	return value == "" || validUUID(value)
}

func optionalUUID(value *string) (string, error) {
	if value == nil {
		return "", nil
	}
	if !validUUID(*value) {
		return "", fmt.Errorf("invalid persisted UUID")
	}
	return *value, nil
}

func optionalUUIDText(value pgtype.Text) (string, error) {
	if !value.Valid {
		return "", nil
	}
	if !validUUID(value.String) {
		return "", fmt.Errorf("invalid persisted UUID")
	}
	return value.String, nil
}

// lockWorkspace derives tenant scope from the trusted workspace row. No caller
// supplied tenant identifier is accepted by this package.
func lockWorkspace(ctx context.Context, tx pgx.Tx, workspaceID string) (string, error) {
	var tenantID string
	err := tx.QueryRow(ctx, `
		SELECT tenant_id::text
		FROM workspaces
		WHERE id = $1
		FOR SHARE
	`, workspaceID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", databaseError("resolve workspace scope", err)
	}
	if !validUUID(tenantID) {
		return "", fmt.Errorf("resolve workspace scope: %w", errDatabaseOperation)
	}
	return tenantID, nil
}

func beginWorkspace(ctx context.Context, repository *Repository, workspaceID string) (pgx.Tx, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if !validUUID(workspaceID) {
		return nil, "", fmt.Errorf("%w: invalid workspace ID", investigation.ErrInvalidRequest)
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return nil, "", databaseError("begin workspace transaction", err)
	}
	tenantID, err := lockWorkspace(ctx, tx, workspaceID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, "", err
	}
	return tx, tenantID, nil
}

func commit(ctx context.Context, tx pgx.Tx, operation string) error {
	if err := tx.Commit(ctx); err != nil {
		return databaseError(operation, err)
	}
	return nil
}

func scopedDatabaseNow(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID string,
) (time.Time, error) {
	var now time.Time
	err := tx.QueryRow(ctx, `
		SELECT clock_timestamp()
		FROM workspaces AS workspace
		WHERE workspace.tenant_id = $1 AND workspace.id = $2
	`, tenantID, workspaceID).Scan(&now)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, store.ErrNotFound
	}
	if err != nil {
		return time.Time{}, databaseError("read scoped database time", err)
	}
	return databaseTime(now), nil
}
