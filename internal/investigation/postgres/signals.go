package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) RegisterSignal(ctx context.Context, incoming domain.Signal) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	signal, err := investigation.NormalizeSignalForReplay(incoming)
	if err != nil {
		return false, err
	}
	if !validUUIDs(signal.ID, signal.WorkspaceID, signal.IntegrationID) {
		return false, fmt.Errorf("%w: invalid signal persistent resource ID", investigation.ErrInvalidRequest)
	}
	// PostgreSQL timestamptz is microsecond precision. Canonicalizing before
	// persistence makes an otherwise identical replay independent of the
	// caller's nanosecond representation.
	signal.ObservedAt = signal.ObservedAt.Round(time.Microsecond).UTC()

	tx, tenantID, err := beginWorkspace(ctx, repository, signal.WorkspaceID)
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	existing, found, err := findSignalByID(ctx, tx, tenantID, signal.WorkspaceID, signal.ID)
	if err != nil {
		return false, err
	}
	if found {
		if !equalSignalFacts(existing, signal) {
			return false, store.ErrIdempotencyConflict
		}
		if err := commit(ctx, tx, "commit signal replay"); err != nil {
			return false, err
		}
		committed = true
		return false, nil
	}

	existing, found, err = findSignalByProviderEvent(
		ctx,
		tx,
		tenantID,
		signal.WorkspaceID,
		signal.IntegrationID,
		signal.ProviderEventID,
	)
	if err != nil {
		return false, err
	}
	if found {
		if !equalSignalFacts(existing, signal) {
			return false, store.ErrIdempotencyConflict
		}
		if err := commit(ctx, tx, "commit signal replay"); err != nil {
			return false, err
		}
		committed = true
		return false, nil
	}

	var (
		integrationProvider string
		integrationEnabled  bool
		databaseNow         time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT integration.provider, integration.enabled, clock_timestamp()
		FROM integrations AS integration
		WHERE integration.tenant_id = $1
		  AND integration.workspace_id = $2
		  AND integration.id = $3
		FOR SHARE OF integration
	`, tenantID, signal.WorkspaceID, signal.IntegrationID).Scan(
		&integrationProvider,
		&integrationEnabled,
		&databaseNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, store.ErrNotFound
	}
	if err != nil {
		return false, databaseError("resolve signal integration", err)
	}
	if !integrationEnabled {
		return false, store.ErrNotFound
	}
	if integrationProvider != signal.Provider {
		return false, store.ErrScopeViolation
	}
	if err := investigation.ValidateNewSignalTime(signal, databaseTime(databaseNow)); err != nil {
		return false, err
	}

	payloadSummary, err := json.Marshal(struct {
		Status string            `json:"status"`
		Labels map[string]string `json:"labels"`
	}{Status: signal.Status, Labels: signal.Labels})
	if err != nil {
		return false, fmt.Errorf("%w: invalid normalized signal labels", investigation.ErrInvalidRequest)
	}
	// Generate only after both replay lookups and new-fact admission. Exact
	// replay therefore does not depend on a currently healthy ID generator,
	// while an invalid candidate is still rejected before either business row
	// is inserted.
	outboxID, err := repository.newUUID()
	if err != nil {
		return false, err
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO signals (
			id, tenant_id, workspace_id, integration_id, provider,
			provider_event_id, payload_hash, fingerprint, status,
			observed_at, payload_summary
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11::jsonb
		)
		ON CONFLICT DO NOTHING
	`,
		signal.ID,
		tenantID,
		signal.WorkspaceID,
		signal.IntegrationID,
		signal.Provider,
		signal.ProviderEventID,
		signal.PayloadHash,
		signal.Fingerprint,
		signal.Status,
		signal.ObservedAt,
		string(payloadSummary),
	)
	if err != nil {
		return false, databaseError("insert signal", err)
	}
	if result.RowsAffected() == 0 {
		exactReplay, replayErr := repository.concurrentSignalReplay(ctx, tx, tenantID, signal)
		if replayErr != nil {
			return false, replayErr
		}
		if !exactReplay {
			return false, store.ErrIdempotencyConflict
		}
		if err := commit(ctx, tx, "commit concurrent signal replay"); err != nil {
			return false, err
		}
		committed = true
		return false, nil
	}

	outboxPayload, err := json.Marshal(struct {
		SignalID string `json:"signal_id"`
	}{SignalID: signal.ID})
	if err != nil {
		return false, fmt.Errorf("%w: invalid signal outbox payload", investigation.ErrInvalidRequest)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, workspace_id, aggregate_type, aggregate_id,
			aggregate_version, event_type, payload, created_at, available_at
		) VALUES (
			$1, $2, $3, 'SIGNAL', $4,
			1, 'signal.ingested.v1', $5::jsonb, statement_timestamp(), statement_timestamp()
		)
	`, outboxID, tenantID, signal.WorkspaceID, signal.ID, string(outboxPayload)); err != nil {
		return false, mapSignalOutboxError(err)
	}
	if err := commit(ctx, tx, "commit signal registration"); err != nil {
		return false, err
	}
	committed = true
	return true, nil
}

func mapSignalOutboxError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" &&
		postgresError.ConstraintName == "outbox_events_pkey" {
		return fmt.Errorf("%w: ID factory returned a duplicate signal outbox ID", investigation.ErrInvalidRequest)
	}
	return databaseError("insert signal outbox event", err)
}

func (repository *Repository) concurrentSignalReplay(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	signal domain.Signal,
) (bool, error) {
	existing, found, err := findSignalByID(ctx, tx, tenantID, signal.WorkspaceID, signal.ID)
	if err != nil {
		return false, err
	}
	if !found {
		existing, found, err = findSignalByProviderEvent(
			ctx,
			tx,
			tenantID,
			signal.WorkspaceID,
			signal.IntegrationID,
			signal.ProviderEventID,
		)
		if err != nil {
			return false, err
		}
	}
	return found && equalSignalFacts(existing, signal), nil
}

func (repository *Repository) GetSignal(ctx context.Context, workspaceID, signalID string) (domain.Signal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Signal{}, err
	}
	if !validUUIDs(workspaceID, signalID) {
		return domain.Signal{}, fmt.Errorf("%w: invalid signal scope", investigation.ErrInvalidRequest)
	}
	tx, tenantID, err := beginWorkspace(ctx, repository, workspaceID)
	if err != nil {
		return domain.Signal{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	signal, found, err := findSignalByID(ctx, tx, tenantID, workspaceID, signalID)
	if err != nil {
		return domain.Signal{}, err
	}
	if !found {
		return domain.Signal{}, store.ErrNotFound
	}
	if err := commit(ctx, tx, "commit signal read"); err != nil {
		return domain.Signal{}, err
	}
	committed = true
	return signal, nil
}

func (repository *Repository) GetRegisteredSignal(ctx context.Context, signalID string) (investigation.RegisteredSignal, error) {
	if ctx == nil {
		return investigation.RegisteredSignal{}, fmt.Errorf("%w: context is required", investigation.ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return investigation.RegisteredSignal{}, err
	}
	if !validUUID(signalID) {
		return investigation.RegisteredSignal{}, fmt.Errorf("%w: invalid global signal ID", investigation.ErrInvalidRequest)
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return investigation.RegisteredSignal{}, databaseError("begin registered signal read", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	registered, err := scanRegisteredSignal(tx.QueryRow(ctx, `
		SELECT `+signalProjection+`
		FROM signals AS signal
		JOIN workspaces AS workspace
		  ON workspace.id = signal.workspace_id
		 AND workspace.tenant_id = signal.tenant_id
		JOIN integrations AS integration
		  ON integration.id = signal.integration_id
		 AND integration.tenant_id = signal.tenant_id
		 AND integration.workspace_id = signal.workspace_id
		WHERE signal.id = $1
		FOR SHARE OF signal, workspace, integration
	`, signalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return investigation.RegisteredSignal{}, store.ErrNotFound
	}
	if err != nil {
		return investigation.RegisteredSignal{}, databaseError("read registered signal", err)
	}
	if err := commit(ctx, tx, "commit registered signal read"); err != nil {
		return investigation.RegisteredSignal{}, err
	}
	committed = true
	return registered, nil
}

func findSignalByID(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	workspaceID string,
	signalID string,
) (domain.Signal, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT `+signalProjection+`
		FROM signals AS signal
		WHERE signal.tenant_id = $1
		  AND signal.workspace_id = $2
		  AND signal.id = $3
		FOR SHARE OF signal
	`, tenantID, workspaceID, signalID)
	signal, err := scanSignal(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Signal{}, false, nil
	}
	if err != nil {
		return domain.Signal{}, false, databaseError("read signal", err)
	}
	return signal, true, nil
}

func findSignalByProviderEvent(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	workspaceID string,
	integrationID string,
	providerEventID string,
) (domain.Signal, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT `+signalProjection+`
		FROM signals AS signal
		WHERE signal.tenant_id = $1
		  AND signal.workspace_id = $2
		  AND signal.integration_id = $3
		  AND signal.provider_event_id = $4
		FOR SHARE OF signal
	`, tenantID, workspaceID, integrationID, providerEventID)
	signal, err := scanSignal(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Signal{}, false, nil
	}
	if err != nil {
		return domain.Signal{}, false, databaseError("read signal provider event", err)
	}
	return signal, true, nil
}

func equalSignalFacts(left, right domain.Signal) bool {
	return left.ID == right.ID &&
		left.WorkspaceID == right.WorkspaceID &&
		left.IntegrationID == right.IntegrationID &&
		left.Provider == right.Provider &&
		left.ProviderEventID == right.ProviderEventID &&
		left.PayloadHash == right.PayloadHash &&
		left.Fingerprint == right.Fingerprint &&
		left.Status == right.Status &&
		left.ObservedAt.Equal(right.ObservedAt) &&
		maps.Equal(left.Labels, right.Labels)
}
