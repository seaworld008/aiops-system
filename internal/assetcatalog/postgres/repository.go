package postgres

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const serializableAttempts = 3

type Repository struct {
	pool  *pgxpool.Pool
	clock func() time.Time
	newID func() string
}

func New(pool *pgxpool.Pool, clock func() time.Time, newID func() string) (*Repository, error) {
	if pool == nil || newID == nil {
		return nil, errors.New("asset catalog pool and id generator are required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Repository{pool: pool, clock: clock, newID: newID}, nil
}

func (repository *Repository) withSerializable(
	ctx context.Context,
	operation func(pgx.Tx) (assetcatalog.AssetMutationResult, error),
) (assetcatalog.AssetMutationResult, error) {
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return assetcatalog.AssetMutationResult{}, mapPGError(err)
		}
		result, operationErr := operation(tx)
		if operationErr != nil {
			_ = tx.Rollback(ctx)
			if isRetryablePGError(operationErr) && attempt+1 < serializableAttempts {
				if err := waitForRetry(ctx, attempt); err != nil {
					return assetcatalog.AssetMutationResult{}, err
				}
				continue
			}
			return assetcatalog.AssetMutationResult{}, mapPGError(operationErr)
		}
		if err := tx.Commit(ctx); err != nil {
			if isRetryablePGError(err) && attempt+1 < serializableAttempts {
				if waitErr := waitForRetry(ctx, attempt); waitErr != nil {
					return assetcatalog.AssetMutationResult{}, waitErr
				}
				continue
			}
			return assetcatalog.AssetMutationResult{}, mapPGError(err)
		}
		return result.Clone(), nil
	}
	return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
}

func waitForRetry(ctx context.Context, attempt int) error {
	var random [1]byte
	_, _ = cryptorand.Read(random[:])
	delay := time.Duration(attempt+1)*time.Millisecond + time.Duration(random[0]%3)*time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isRetryablePGError(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		(postgresError.Code == "40001" || postgresError.Code == "40P01")
}

func mapPGError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return assetcatalog.ErrNotFound
	}
	for _, stable := range []error{
		assetcatalog.ErrInvalidRequest,
		assetcatalog.ErrNotFound,
		assetcatalog.ErrScopeViolation,
		assetcatalog.ErrVersionConflict,
		assetcatalog.ErrStateConflict,
		assetcatalog.ErrIdempotency,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return assetcatalog.ErrStateConflict
	}
	switch postgresError.Code {
	case "23503":
		return assetcatalog.ErrScopeViolation
	case "23505":
		return assetcatalog.ErrIdempotency
	case "23514", "22P02", "22001", "22023":
		return assetcatalog.ErrInvalidRequest
	case "40001", "40P01":
		return assetcatalog.ErrStateConflict
	default:
		return assetcatalog.ErrStateConflict
	}
}

var (
	_ assetcatalog.Reader              = (*Repository)(nil)
	_ assetcatalog.AssetReadRepository = (*Repository)(nil)
	_ assetcatalog.ScopeResolver       = (*Repository)(nil)
	_ assetcatalog.Repository          = (*Repository)(nil)
)
