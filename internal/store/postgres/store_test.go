package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/store"
	postgresstore "github.com/seaworld008/aiops-system/internal/store/postgres"
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
		WithArgs(signalID, tenantID, workspaceID, integrationID, "alertmanager", "event-1", "incoming-hash", "fingerprint-1", "firing", pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 0))
	database.ExpectQuery("SELECT id::text, tenant_id::text, workspace_id::text, provider, payload_hash").
		WithArgs(integrationID, "event-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "payload_hash"}).
			AddRow(signalID, tenantID, workspaceID, "alertmanager", "existing-hash"))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), tenantID, workspaceID, integrationID, signalID, pgxmock.AnyArg(), nil, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	repository := postgresstore.New(database)
	created, err := repository.CreateSignal(context.Background(), domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: integrationID,
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: "incoming-hash",
		Fingerprint: "fingerprint-1", Status: "firing", ObservedAt: time.Now().UTC(),
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
		WithArgs(signalID, tenantID, workspaceID, integrationID, "alertmanager", "event-1", "same-hash", "fingerprint-1", "firing", pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 0))
	database.ExpectQuery("SELECT id::text, tenant_id::text, workspace_id::text, provider, payload_hash").
		WithArgs(integrationID, "event-1").
		WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "payload_hash"}).
			AddRow(signalID, tenantID, workspaceID, "alertmanager", "same-hash"))
	database.ExpectCommit()

	created, err := postgresstore.New(database).CreateSignal(context.Background(), domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: integrationID,
		Provider: "alertmanager", ProviderEventID: "event-1", PayloadHash: "same-hash",
		Fingerprint: "fingerprint-1", Status: "firing", ObservedAt: time.Now().UTC(),
	})
	if err != nil || created {
		t.Fatalf("CreateSignal() = (%v, %v), want duplicate", created, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestCreateSignalAndOutboxAreCommittedAtomically(t *testing.T) {
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
		WithArgs(signalID, tenantID, workspaceID, integrationID, "alertmanager", "event-new", "hash", "fingerprint-1", "firing", pgxmock.AnyArg(), `{"labels":null,"status":"firing"}`).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), tenantID, workspaceID, signalID, `{"signal_id":"44444444-4444-4444-8444-444444444444"}`).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	created, err := postgresstore.New(database).CreateSignal(context.Background(), domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: integrationID,
		Provider: "alertmanager", ProviderEventID: "event-new", PayloadHash: "hash",
		Fingerprint: "fingerprint-1", Status: "firing", ObservedAt: time.Now().UTC(),
	})
	if err != nil || !created {
		t.Fatalf("CreateSignal() = (%v, %v), want created", created, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestCreateSignalRollsBackWhenOutboxInsertFails(t *testing.T) {
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
		WithArgs(signalID, tenantID, workspaceID, integrationID, "alertmanager", "event-new", "hash", "fingerprint-1", "firing", pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), tenantID, workspaceID, signalID, pgxmock.AnyArg()).
		WillReturnError(errors.New("outbox unavailable"))
	database.ExpectRollback()

	created, err := postgresstore.New(database).CreateSignal(context.Background(), domain.Signal{
		ID: signalID, WorkspaceID: workspaceID, IntegrationID: integrationID,
		Provider: "alertmanager", ProviderEventID: "event-new", PayloadHash: "hash",
		Fingerprint: "fingerprint-1", Status: "firing", ObservedAt: time.Now().UTC(),
	})
	if err == nil || created {
		t.Fatalf("CreateSignal() = (%v, %v), want rollback error", created, err)
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
		Fingerprint: "fingerprint-1", Status: "firing", ObservedAt: time.Now().UTC(),
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
	database.ExpectQuery(`(?s)WITH candidates AS \(.*WHERE event_type = \$1.*ORDER BY available_at, created_at, id.*FOR UPDATE SKIP LOCKED.*LIMIT \$2`).
		WithArgs("incident.created.v1", 1, "dispatcher-1", pgxmock.AnyArg(), float64(60)).
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
		WithArgs("66666666-6666-4666-8666-666666666666", "incident.created.v1", "77777777-7777-4777-8777-777777777777").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	repository := postgresstore.New(database)
	events, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "incident.created.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	})
	if err != nil || len(events) != 1 || events[0].ClaimToken == "" || events[0].ClaimedBy != "dispatcher-1" {
		t.Fatalf("ClaimOutbox() = (%#v, %v)", events, err)
	}
	if err := repository.AckOutbox(context.Background(), events[0].ID, "incident.created.v1", events[0].ClaimToken); err != nil {
		t.Fatalf("AckOutbox() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestOutboxClaimRejectsInvalidExactTypeAndBoundsBeforeSQL(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	repository := postgresstore.New(database)
	tests := []struct {
		name, eventType, consumerID string
		limit                       int
		lease                       time.Duration
	}{
		{name: "empty type", eventType: "", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "wildcard", eventType: "signal.*", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "prefix", eventType: "signal.ingested", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "oversized type", eventType: strings.Repeat("a", 126) + ".v1", consumerID: "worker-1", limit: 1, lease: time.Minute},
		{name: "empty consumer", eventType: "signal.ingested.v1", consumerID: "", limit: 1, lease: time.Minute},
		{name: "oversized consumer", eventType: "signal.ingested.v1", consumerID: strings.Repeat("w", 129), limit: 1, lease: time.Minute},
		{name: "zero limit", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 0, lease: time.Minute},
		{name: "oversized limit", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 101, lease: time.Minute},
		{name: "subsecond lease", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 1, lease: time.Second - 1},
		{name: "oversized lease", eventType: "signal.ingested.v1", consumerID: "worker-1", limit: 1, lease: 15*time.Minute + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := repository.ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
				EventType: test.eventType, ConsumerID: test.consumerID, Limit: test.limit, Lease: test.lease,
			}); err == nil {
				t.Fatal("ClaimOutbox() error = nil, want validation failure")
			}
		})
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("invalid requests reached PostgreSQL: %v", err)
	}
}

func TestOutboxClaimFailsClosedWhenReturnedTypeDoesNotMatch(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	const canary = "payload-token-canary"
	database.ExpectQuery("WITH candidates").
		WithArgs("signal.ingested.v1", 1, "dispatcher-1", pgxmock.AnyArg(), float64(60)).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "tenant_id", "workspace_id", "aggregate_type", "aggregate_id", "aggregate_version",
			"event_type", "payload", "created_at", "available_at", "claimed_at", "claimed_by",
			"claim_token", "claim_expires_at", "attempts", "last_error_code",
		}).AddRow(
			"66666666-6666-4666-8666-666666666666", tenantID, workspaceID, "INCIDENT", incidentID, int64(1),
			"incident.created.v1", []byte(`{"value":"`+canary+`"}`), now, now, now, "dispatcher-1",
			canary, now.Add(time.Minute), 1, "",
		))

	events, err := postgresstore.New(database).ClaimOutbox(context.Background(), store.ClaimOutboxRequest{
		EventType: "signal.ingested.v1", ConsumerID: "dispatcher-1", Limit: 1, Lease: time.Minute,
	})
	if err == nil || len(events) != 0 {
		t.Fatalf("ClaimOutbox(mismatched scan) = (%#v, %v), want fail closed", events, err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("ClaimOutbox() error leaked scanned payload/token: %v", err)
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
			"incident.created.v1",
			"77777777-7777-4777-8777-777777777777",
			pgxmock.AnyArg(),
			"temporal_unavailable",
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err = postgresstore.New(database).RetryOutbox(
		context.Background(),
		"66666666-6666-4666-8666-666666666666",
		"incident.created.v1",
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

func TestOutboxAckAndRetryPredicatesBindExpectedEventType(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer database.Close()
	const (
		id    = "66666666-6666-4666-8666-666666666666"
		token = "77777777-7777-4777-8777-777777777777"
	)
	database.ExpectExec(`(?s)UPDATE outbox_events.*WHERE id = \$1 AND event_type = \$2 AND claim_token = \$3`).
		WithArgs(id, "signal.ingested.v1", token).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery(`(?s)SELECT delivered_at IS NOT NULL AND delivered_claim_token = \$3.*WHERE id = \$1 AND event_type = \$2`).
		WithArgs(id, "signal.ingested.v1", token).
		WillReturnRows(pgxmock.NewRows([]string{"delivered"}))
	repository := postgresstore.New(database)
	if err := repository.AckOutbox(context.Background(), id, "signal.ingested.v1", token); !errors.Is(err, store.ErrStaleClaim) {
		t.Fatalf("AckOutbox() error = %v, want ErrStaleClaim", err)
	}

	database.ExpectExec(`(?s)UPDATE outbox_events.*WHERE id = \$1 AND event_type = \$2 AND claim_token = \$3`).
		WithArgs(id, "signal.ingested.v1", token, pgxmock.AnyArg(), "workflow_start_failed").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	if err := repository.RetryOutbox(
		context.Background(), id, "signal.ingested.v1", token, time.Now().Add(time.Minute), "workflow_start_failed",
	); !errors.Is(err, store.ErrStaleClaim) {
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
	database.ExpectExec("UPDATE outbox_events").WithArgs(id, "incident.created.v1", token).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	database.ExpectQuery("SELECT delivered_at IS NOT NULL AND delivered_claim_token").
		WithArgs(id, "incident.created.v1", token).
		WillReturnRows(pgxmock.NewRows([]string{"delivered"}).AddRow(true))

	if err := postgresstore.New(database).AckOutbox(context.Background(), id, "incident.created.v1", token); err != nil {
		t.Fatalf("AckOutbox() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}
