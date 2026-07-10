package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
	"github.com/aiops-system/control-plane/internal/ids"
	"github.com/aiops-system/control-plane/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const maxOutboxBatch = 100

type DB interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Store struct {
	database DB
}

func New(database DB) *Store {
	return &Store{database: database}
}

func (repository *Store) CreateSignal(ctx context.Context, item domain.Signal) (bool, error) {
	if err := item.Validate(); err != nil {
		return false, err
	}
	if item.Fingerprint == "" {
		return false, fmt.Errorf("signal fingerprint is required")
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin signal transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	var tenantID, integrationWorkspaceID, provider string
	err = tx.QueryRow(ctx, `
		SELECT tenant_id::text, workspace_id::text, provider
		FROM integrations
		WHERE id = $1 AND enabled = true
	`, item.IntegrationID).Scan(&tenantID, &integrationWorkspaceID, &provider)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, store.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("resolve signal integration: %w", err)
	}
	if integrationWorkspaceID != item.WorkspaceID || provider != item.Provider {
		return false, store.ErrScopeViolation
	}

	result, err := tx.Exec(ctx, `
		INSERT INTO signals (
			id, tenant_id, workspace_id, integration_id, provider,
			provider_event_id, payload_hash, fingerprint, observed_at, payload_summary
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, '{}'::jsonb)
		ON CONFLICT (integration_id, provider_event_id) DO NOTHING
	`, item.ID, tenantID, item.WorkspaceID, item.IntegrationID, item.Provider,
		item.ProviderEventID, item.PayloadHash, item.Fingerprint, item.ObservedAt.UTC())
	if err != nil {
		return false, fmt.Errorf("insert signal: %w", err)
	}
	if result.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit signal: %w", err)
		}
		committed = true
		return true, nil
	}

	var existingID, existingTenantID, existingWorkspaceID, existingProvider, existingHash string
	err = tx.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, workspace_id::text, provider, payload_hash
		FROM signals
		WHERE integration_id = $1 AND provider_event_id = $2
		FOR SHARE
	`, item.IntegrationID, item.ProviderEventID).Scan(
		&existingID, &existingTenantID, &existingWorkspaceID, &existingProvider, &existingHash,
	)
	if err != nil {
		return false, fmt.Errorf("read existing signal: %w", err)
	}
	conflict := existingTenantID != tenantID || existingWorkspaceID != item.WorkspaceID ||
		existingProvider != item.Provider || existingHash != item.PayloadHash
	if conflict {
		if err := insertSignalConflictAudit(ctx, tx, signalConflictAudit{
			TenantID: existingTenantID, WorkspaceID: existingWorkspaceID,
			IntegrationID: item.IntegrationID, SignalID: existingID,
			ProviderEventID: item.ProviderEventID, ExistingHash: existingHash,
			IncomingHash: item.PayloadHash, IncomingWorkspaceID: item.WorkspaceID,
			IncomingProvider: item.Provider,
		}); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit duplicate signal outcome: %w", err)
	}
	committed = true
	if conflict {
		return false, store.ErrIdempotencyConflict
	}
	return false, nil
}

type signalConflictAudit struct {
	TenantID            string
	WorkspaceID         string
	IntegrationID       string
	SignalID            string
	ProviderEventID     string
	ExistingHash        string
	IncomingHash        string
	IncomingWorkspaceID string
	IncomingProvider    string
}

func insertSignalConflictAudit(ctx context.Context, tx pgx.Tx, conflict signalConflictAudit) error {
	details, err := json.Marshal(map[string]string{
		"provider_event_id":     conflict.ProviderEventID,
		"existing_payload_hash": conflict.ExistingHash,
		"incoming_payload_hash": conflict.IncomingHash,
		"incoming_workspace_id": conflict.IncomingWorkspaceID,
		"incoming_provider":     conflict.IncomingProvider,
	})
	if err != nil {
		return fmt.Errorf("encode signal conflict audit: %w", err)
	}
	sum := sha256.Sum256(details)
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_records (
			id, tenant_id, workspace_id, actor_type, actor_id, action,
			resource_type, resource_id, request_id, payload_hash, details
		) VALUES ($1, $2, $3, 'INTEGRATION', $4, 'signal.idempotency_conflict',
			'SIGNAL', $5, $6, $7, $8)
	`, ids.NewUUID(), conflict.TenantID, conflict.WorkspaceID, conflict.IntegrationID,
		conflict.SignalID, ids.NewUUID(), hex.EncodeToString(sum[:]), details)
	if err != nil {
		return fmt.Errorf("insert signal conflict audit: %w", err)
	}
	return nil
}

func (repository *Store) CreateIncident(ctx context.Context, incident domain.Incident) error {
	if err := incident.ValidateForCreate(); err != nil {
		return err
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin incident transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	var tenantID string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM workspaces WHERE id = $1`, incident.WorkspaceID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("resolve incident workspace: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO incidents (
			id, tenant_id, workspace_id, service_id, environment_id,
			status, severity, title, opened_at, updated_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, incident.ID, tenantID, incident.WorkspaceID, nullableUUID(incident.ServiceID), nullableUUID(incident.EnvironmentID),
		incident.Status, incident.Severity, incident.Title, incident.OpenedAt.UTC(), incident.UpdatedAt.UTC(), incident.Version)
	if err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	payload, err := json.Marshal(map[string]string{"incident_id": incident.ID})
	if err != nil {
		return fmt.Errorf("encode incident outbox payload: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version,
			event_type, payload, created_at, available_at
		) VALUES ($1, $2, $3, 'INCIDENT', $4, $5, 'incident.created.v1', $6,
			statement_timestamp(), statement_timestamp())
	`, ids.NewUUID(), tenantID, incident.WorkspaceID, incident.ID, incident.Version, payload)
	if err != nil {
		return fmt.Errorf("insert incident outbox event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit incident transaction: %w", err)
	}
	committed = true
	return nil
}

func (repository *Store) ClaimOutbox(ctx context.Context, consumerID string, limit int, lease time.Duration) ([]domain.OutboxEvent, error) {
	if consumerID == "" || limit <= 0 || limit > maxOutboxBatch || lease <= 0 || lease > 15*time.Minute {
		return nil, fmt.Errorf("invalid outbox claim parameters")
	}
	claimToken := ids.NewUUID()
	rows, err := repository.database.Query(ctx, `
		WITH candidates AS (
			SELECT id
			FROM outbox_events
			WHERE delivered_at IS NULL
			  AND available_at <= statement_timestamp()
			  AND (claim_expires_at IS NULL OR claim_expires_at <= statement_timestamp())
			ORDER BY available_at, created_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		UPDATE outbox_events AS event
		SET claimed_at = statement_timestamp(), claimed_by = $2, claim_token = $3,
			claim_expires_at = statement_timestamp() + make_interval(secs => $4::double precision),
			attempts = event.attempts + 1
		FROM candidates
		WHERE event.id = candidates.id
		RETURNING event.id::text, event.tenant_id::text, event.workspace_id::text,
			event.aggregate_type, event.aggregate_id::text, event.aggregate_version,
			event.event_type, event.payload, event.created_at, event.available_at,
			event.claimed_at, event.claimed_by, event.claim_token::text,
			event.claim_expires_at, event.attempts, COALESCE(event.last_error_code, '')
	`, limit, consumerID, claimToken, lease.Seconds())
	if err != nil {
		return nil, fmt.Errorf("claim outbox events: %w", err)
	}
	defer rows.Close()

	events := make([]domain.OutboxEvent, 0, limit)
	for rows.Next() {
		var event domain.OutboxEvent
		if err := rows.Scan(
			&event.ID, &event.TenantID, &event.WorkspaceID, &event.AggregateType,
			&event.AggregateID, &event.AggregateVersion, &event.Type, &event.Payload,
			&event.CreatedAt, &event.AvailableAt, &event.ClaimedAt, &event.ClaimedBy,
			&event.ClaimToken, &event.ClaimExpiresAt, &event.Attempts, &event.LastErrorCode,
		); err != nil {
			return nil, fmt.Errorf("scan claimed outbox event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read claimed outbox events: %w", err)
	}
	return events, nil
}

func (repository *Store) AckOutbox(ctx context.Context, id, claimToken string) error {
	result, err := repository.database.Exec(ctx, `
		UPDATE outbox_events
		SET delivered_at = statement_timestamp(), claimed_at = NULL, claimed_by = NULL,
			claim_token = NULL, claim_expires_at = NULL, last_error_code = NULL
		WHERE id = $1 AND claim_token = $2 AND delivered_at IS NULL
	`, id, claimToken)
	if err != nil {
		return fmt.Errorf("ack outbox event: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var delivered bool
	err = repository.database.QueryRow(ctx, `
		SELECT delivered_at IS NOT NULL FROM outbox_events WHERE id = $1
	`, id).Scan(&delivered)
	if err == nil && delivered {
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check outbox delivery state: %w", err)
	}
	return store.ErrStaleClaim
}

func (repository *Store) RetryOutbox(ctx context.Context, id, claimToken string, availableAt time.Time, failureCode string) error {
	if availableAt.IsZero() || !store.ValidFailureCode(failureCode) {
		return fmt.Errorf("invalid outbox retry parameters")
	}
	result, err := repository.database.Exec(ctx, `
		UPDATE outbox_events
		SET available_at = $3, claimed_at = NULL, claimed_by = NULL,
			claim_token = NULL, claim_expires_at = NULL, last_error_code = $4
		WHERE id = $1 AND claim_token = $2 AND delivered_at IS NULL
	`, id, claimToken, availableAt.UTC(), failureCode)
	if err != nil {
		return fmt.Errorf("retry outbox event: %w", err)
	}
	if result.RowsAffected() != 1 {
		return store.ErrStaleClaim
	}
	return nil
}

func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}
