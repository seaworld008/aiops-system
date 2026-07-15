package postgres

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

var canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const resolveScopeSQL = `
SELECT w.tenant_id::text, w.id::text, e.id::text
FROM workspaces AS w
JOIN environments AS e
  ON e.tenant_id = w.tenant_id
 AND e.workspace_id = w.id
WHERE w.id = $1::uuid
  AND e.id = $2::uuid
`

const lockMutationScopeSQL = `
SELECT w.tenant_id::text, w.id::text, e.id::text
FROM workspaces AS w
JOIN environments AS e
  ON e.tenant_id = w.tenant_id
 AND e.workspace_id = w.id
WHERE w.tenant_id = $1::uuid
  AND w.id = $2::uuid
  AND e.id = $3::uuid
`

const lockIdempotencySQL = `
SELECT pg_advisory_xact_lock(
    hashtextextended('asset-management-idempotency.v1:' || $1::text || ':' || $2::text || ':' || $3::text, 0)
)
`

func (repository *Repository) ResolveScope(
	ctx context.Context,
	workspaceID string,
	environmentID string,
) (assetcatalog.Scope, error) {
	if !validUUID(workspaceID) || !validUUID(environmentID) {
		return assetcatalog.Scope{}, assetcatalog.ErrInvalidRequest
	}
	var scope assetcatalog.Scope
	err := repository.pool.QueryRow(ctx, resolveScopeSQL, workspaceID, environmentID).Scan(
		&scope.TenantID,
		&scope.WorkspaceID,
		&scope.EnvironmentID,
	)
	if err != nil {
		return assetcatalog.Scope{}, mapPGError(err)
	}
	if !scope.Valid() {
		return assetcatalog.Scope{}, assetcatalog.ErrStateConflict
	}
	return scope, nil
}

func validUUID(value string) bool { return canonicalUUIDPattern.MatchString(value) }

func lockMutationScope(ctx context.Context, tx pgx.Tx, scope assetcatalog.Scope) error {
	if !scope.Valid() {
		return assetcatalog.ErrInvalidRequest
	}
	var persisted assetcatalog.Scope
	err := tx.QueryRow(
		ctx,
		lockMutationScopeSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
	).Scan(&persisted.TenantID, &persisted.WorkspaceID, &persisted.EnvironmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return assetcatalog.ErrScopeViolation
	}
	if err != nil {
		return err
	}
	if persisted != scope {
		return assetcatalog.ErrScopeViolation
	}
	return nil
}

func lockIdempotency(ctx context.Context, tx pgx.Tx, scope assetcatalog.Scope, key string) error {
	_, err := tx.Exec(ctx, lockIdempotencySQL, scope.TenantID, scope.WorkspaceID, key)
	return err
}
