package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
	"github.com/aiops-system/control-plane/internal/store"
	postgresstore "github.com/aiops-system/control-plane/internal/store/postgres"
	"github.com/pashagolub/pgxmock/v4"
)

const (
	tenantID      = "11111111-1111-4111-8111-111111111111"
	workspaceID   = "22222222-2222-4222-8222-222222222222"
	integrationID = "33333333-3333-4333-8333-333333333333"
	signalID      = "44444444-4444-4444-8444-444444444444"
	incidentID    = "55555555-5555-4555-8555-555555555555"
)

func TestCreateSignalCommitsConflictAuditBeforeReturningDomainError(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, workspace_id::text, provider").
		WithArgs(integrationID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "workspace_id", "provider"}).AddRow(tenantID, workspaceID, "alertmanager"))
	database.ExpectExec("INSERT INTO signals").
		WithArgs(signalID, tenantID, workspaceID, integrationID, "alertmanager", "event-1", "incoming-hash", "fingerprint-1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 0))
	database.ExpectQuery("SELECT id::text, tenant_id::text, workspace_id::text, provider, payload_hash").
		WithArgs(integrationID, "event-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "payload_hash"}).
			AddRow(signalID, tenantID, workspaceID, "alertmanager", "existing-hash"))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), tenantID, workspaceID, integrationID, signalID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	repository := postgresstore.New(database)
	created, err := repository.CreateSignal(context.Background(), domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: integrationID,
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: "incoming-hash",
		Fingerprint: "fingerprint-1", ObservedAt: time.Now().UTC(),
	})
	if created || !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CreateSignal() = (%v, %v), want conflict", created, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestCreateSignalReturnsDuplicateWithoutAuditForSamePayload(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, workspace_id::text, provider").
		WithArgs(integrationID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "workspace_id", "provider"}).AddRow(tenantID, workspaceID, "alertmanager"))
	database.ExpectExec("INSERT INTO signals").
		WithArgs(signalID, tenantID, workspaceID, integrationID, "alertmanager", "event-1", "same-hash", "fingerprint-1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 0))
	database.ExpectQuery("SELECT id::text, tenant_id::text, workspace_id::text, provider, payload_hash").
		WithArgs(integrationID, "event-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "payload_hash"}).
			AddRow(signalID, tenantID, workspaceID, "alertmanager", "same-hash"))
	database.ExpectCommit()

	created, err := postgresstore.New(database).CreateSignal(context.Background(), domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: integrationID,
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: "same-hash",
		Fingerprint: "fingerprint-1", ObservedAt: time.Now().UTC(),
	})
	if err != nil || created {
		t.Fatalf("CreateSignal() = (%v, %v), want duplicate", created, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestCreateSignalRejectsIntegrationWorkspaceMismatch(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, workspace_id::text, provider").
		WithArgs(integrationID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id", "workspace_id", "provider"}).AddRow(tenantID, workspaceID, "alertmanager"))
	database.ExpectRollback()

	created, err := postgresstore.New(database).CreateSignal(context.Background(), domain.Signal{
		ID: signalID, WorkspaceID: "99999999-9999-4999-8999-999999999999", IntegrationID: integrationID,
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: "hash",
		Fingerprint: "fingerprint-1", ObservedAt: time.Now().UTC(),
	})
	if created || !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CreateSignal() = (%v, %v), want scope violation", created, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestCreateIncidentAndOutboxAreCommittedAtomically(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text FROM workspaces").
		WithArgs(workspaceID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	database.ExpectExec("INSERT INTO incidents").
		WithArgs(incidentID, tenantID, workspaceID, nil, nil, domain.IncidentOpen, "UNKNOWN", "Unclassified operational incident", pgxmock.AnyArg(), pgxmock.AnyArg(), int64(1)).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), tenantID, workspaceID, incidentID, int64(1), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	incident := domain.NewIncident(incidentID, workspaceID, time.Now().UTC())
	if err := postgresstore.New(database).CreateIncident(context.Background(), incident); err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestCreateIncidentRollsBackWhenOutboxInsertFails(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text FROM workspaces").
		WithArgs(workspaceID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	database.ExpectExec("INSERT INTO incidents").
		WithArgs(incidentID, tenantID, workspaceID, nil, nil, domain.IncidentOpen, "UNKNOWN", "Unclassified operational incident", pgxmock.AnyArg(), pgxmock.AnyArg(), int64(1)).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), tenantID, workspaceID, incidentID, int64(1), pgxmock.AnyArg()).
		WillReturnError(errors.New("outbox unavailable"))
	database.ExpectRollback()

	incident := domain.NewIncident(incidentID, workspaceID, time.Now().UTC())
	if err := postgresstore.New(database).CreateIncident(context.Background(), incident); err == nil {
		t.Fatal("CreateIncident() error = nil, want rollback")
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestOutboxClaimReturnsFencingTokenAndAckUsesIt(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	payload, _ := json.Marshal(map[string]string{"incident_id": incidentID})
	database.ExpectQuery("WITH candidates").
		WithArgs(1, "dispatcher-1", pgxmock.AnyArg(), float64(60)).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "tenant_id", "workspace_id", "aggregate_type", "aggregate_id", "aggregate_version",
			"event_type", "payload", "created_at", "available_at", "claimed_at", "claimed_by",
			"claim_token", "claim_expires_at", "attempts", "last_error_code",
		}).AddRow(
			"66666666-6666-4666-8666-666666666666", tenantID, workspaceID, "INCIDENT", incidentID, int64(1),
			"incident.created.v1", payload, now, now, now, "dispatcher-1",
			"77777777-7777-4777-8777-777777777777", now.Add(time.Minute), 1, "",
		))
	database.ExpectExec("UPDATE outbox_events").
		WithArgs("66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	repository := postgresstore.New(database)
	events, err := repository.ClaimOutbox(context.Background(), "dispatcher-1", 1, time.Minute)
	if err != nil || len(events) != 1 || events[0].ClaimToken == "" || events[0].ClaimedBy != "dispatcher-1" {
		t.Fatalf("ClaimOutbox() = (%#v, %v)", events, err)
	}
	if err := repository.AckOutbox(context.Background(), events[0].ID, events[0].ClaimToken); err != nil {
		t.Fatalf("AckOutbox() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestOutboxRetryRejectsStaleToken(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	database.ExpectExec("UPDATE outbox_events").
		WithArgs(
			"66666666-6666-4666-8666-666666666666",
			"77777777-7777-4777-8777-777777777777",
			pgxmock.AnyArg(),
			"temporal_unavailable",
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err = postgresstore.New(database).RetryOutbox(
		context.Background(),
		"66666666-6666-4666-8666-666666666666",
		"77777777-7777-4777-8777-777777777777",
		time.Now().Add(time.Minute),
		"temporal_unavailable",
	)
	if !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("RetryOutbox() error = %v, want ErrStaleClaim", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestOutboxAckIsIdempotentAfterUncertainResponse(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	id := "66666666-6666-4666-8666-666666666666"
	token := "77777777-7777-4777-8777-777777777777"
	database.ExpectExec("UPDATE outbox_events").WithArgs(id, token).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery("SELECT delivered_at IS NOT NULL FROM outbox_events").
		WithArgs(id).
		WillReturnRows(pgxmock.NewRows([]string{"delivered"}).AddRow(true))

	if err := postgresstore.New(database).AckOutbox(context.Background(), id, token); err != nil {
		t.Fatalf("AckOutbox() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}
