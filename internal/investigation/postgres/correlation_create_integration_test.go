package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	investigationpostgres "github.com/seaworld008/aiops-system/internal/investigation/postgres"
	"github.com/seaworld008/aiops-system/internal/store"
)

const (
	repositorySignalID       = "41000000-0000-4000-8000-000000000001"
	repositorySecondSignalID = "41000000-0000-4000-8000-000000000002"
)

func TestPostgresInvestigationWritesRejectInvalidUUIDsBeforeSQL(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("create pgx mock: %v", err)
	}
	defer database.Close()
	authorizerCalls := 0
	repository, err := investigationpostgres.New(database, investigationpostgres.Options{
		TaskRuntimeBinder: testTaskRuntimeBinder,
		IDFactory:         func() string { return "90000000-0000-4000-8000-000000000001" },
		TaskSpecAuthorizer: func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error {
			authorizerCalls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("postgres.New() error = %v", err)
	}
	if _, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: "not-a-uuid", SignalID: repositorySignalID,
		CorrelationKey: "payments:staging:invalid", MappingStatus: domain.MappingUnresolved,
	}); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CorrelateSignal(invalid UUID) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: testWorkspaceID, IncidentID: "not-a-uuid", IdempotencyKey: "investigate:invalid",
		Tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Operation: "range_query",
			Input: []byte(`{"lookback_minutes":15}`),
		}},
	})); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CreateOrGetInvestigation(invalid UUID) error = %v, want ErrInvalidRequest", err)
	}
	if authorizerCalls != 0 {
		t.Fatalf("authorizer calls = %d, want 0 before persistent identity validation", authorizerCalls)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected SQL before UUID validation: %v", err)
	}
}

func TestPostgresCorrelateSignalCreatesDurableReplayAndOutbox(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	signal := fixture.registerSignal(t, repositorySignalID, "firing", fixture.base, "event-create")
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: testWorkspaceID, SignalID: signal.ID,
		CorrelationKey: "payments:staging:latency-create",
		ServiceID:      testServiceID, EnvironmentID: testEnvironmentID, MappingStatus: domain.MappingExact,
	}
	first, err := fixture.repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(first) error = %v", err)
	}
	replay, err := fixture.repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(replay) error = %v", err)
	}
	if !first.Created || !first.Associated || !first.Counted || replay.Created || !replay.Associated || replay.Counted ||
		replay.Incident.ID != first.Incident.ID || first.Incident.SignalCount != 1 {
		t.Fatalf("create/replay = %#v / %#v, want one counted incident and an uncounted replay", first, replay)
	}
	changed := request
	changed.MappingStatus = domain.MappingUnresolved
	if _, err := fixture.repository.CorrelateSignal(context.Background(), changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CorrelateSignal(changed replay) error = %v, want ErrIdempotencyConflict", err)
	}

	var incidents, associations, correlations, createdEvents int
	if err := fixture.harness.db.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM incidents WHERE id = $1),
			(SELECT count(*) FROM incident_signals WHERE incident_id = $1 AND signal_id = $2),
			(SELECT count(*) FROM investigation_signal_correlations WHERE incident_id = $1 AND signal_id = $2),
			(SELECT count(*) FROM outbox_events WHERE aggregate_id = $1 AND event_type = 'incident.created.v1')
	`, first.Incident.ID, signal.ID).Scan(&incidents, &associations, &correlations, &createdEvents); err != nil {
		t.Fatalf("read committed correlation facts: %v", err)
	}
	if incidents != 1 || associations != 1 || correlations != 1 || createdEvents != 1 {
		t.Fatalf("committed counts = incident:%d association:%d correlation:%d outbox:%d, want all 1",
			incidents, associations, correlations, createdEvents)
	}
}

func TestPostgresCorrelateSignalPreservesResolvedNoopTombstone(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	resolved := fixture.registerSignal(t, repositorySignalID, "resolved", fixture.base, "event-resolved")
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: testWorkspaceID, SignalID: resolved.ID,
		CorrelationKey: "payments:staging:resolved-noop", MappingStatus: domain.MappingUnresolved,
	}
	first, err := fixture.repository.CorrelateSignal(context.Background(), request)
	if err != nil || first != (investigation.CorrelateSignalResult{}) {
		t.Fatalf("CorrelateSignal(resolved first) = %#v, %v; want durable no-op", first, err)
	}

	firing := fixture.registerSignal(t, repositorySecondSignalID, "firing", fixture.base.Add(time.Second), "event-after-resolved")
	created, err := fixture.repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: testWorkspaceID, SignalID: firing.ID,
		CorrelationKey: request.CorrelationKey, MappingStatus: domain.MappingUnresolved,
	})
	if err != nil || !created.Created {
		t.Fatalf("CorrelateSignal(firing after no-op) = %#v, %v; want new incident", created, err)
	}
	replay, err := fixture.repository.CorrelateSignal(context.Background(), request)
	if err != nil || replay != (investigation.CorrelateSignalResult{}) {
		t.Fatalf("CorrelateSignal(resolved replay) = %#v, %v; want stable no-op", replay, err)
	}
	var tombstoneIncident pgtype.Text
	if err := fixture.harness.db.QueryRow(context.Background(), `
		SELECT incident_id::text FROM investigation_signal_correlations
		WHERE tenant_id = $1 AND workspace_id = $2 AND signal_id = $3
	`, testTenantID, testWorkspaceID, resolved.ID).Scan(&tombstoneIncident); err != nil {
		t.Fatalf("read resolved tombstone: %v", err)
	}
	if tombstoneIncident.Valid {
		t.Fatalf("resolved tombstone incident = %v, want NULL", tombstoneIncident)
	}
}

func TestPostgresCorrelateSignalConcurrentlyMergesOneActiveIncident(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	const signalCount = 16
	signals := make([]domain.Signal, signalCount)
	for index := range signals {
		signalID := fmt.Sprintf("41000000-0000-4000-8000-%012x", index+100)
		signals[index] = fixture.registerSignal(
			t, signalID, "firing", fixture.base.Add(time.Duration(index)*time.Millisecond), fmt.Sprintf("event-concurrent-%d", index),
		)
	}
	start := make(chan struct{})
	results := make(chan investigation.CorrelateSignalResult, signalCount)
	errorsCh := make(chan error, signalCount)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var group sync.WaitGroup
	for _, signal := range signals {
		group.Add(1)
		go func(signalID string) {
			defer group.Done()
			<-start
			result, err := fixture.repository.CorrelateSignal(ctx, investigation.CorrelateSignalRequest{
				WorkspaceID: testWorkspaceID, SignalID: signalID,
				CorrelationKey: "payments:staging:concurrent-merge",
				ServiceID:      testServiceID, EnvironmentID: testEnvironmentID, MappingStatus: domain.MappingExact,
			})
			results <- result
			errorsCh <- err
		}(signal.ID)
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("CorrelateSignal(concurrent) error = %v", err)
		}
	}
	created := 0
	incidentID := ""
	for result := range results {
		if result.Created {
			created++
		}
		if incidentID == "" {
			incidentID = result.Incident.ID
		} else if result.Incident.ID != incidentID {
			t.Fatalf("concurrent incident ID = %q, want %q", result.Incident.ID, incidentID)
		}
	}
	var persistedCount, associationCount, correlationCount, outboxCount int
	var persistedVersion int64
	var openedAt, lastSignalAt time.Time
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT incident.signal_count, incident.version, incident.opened_at, incident.last_signal_at,
		       (SELECT count(*) FROM incident_signals AS association
		        WHERE association.tenant_id = incident.tenant_id
		          AND association.workspace_id = incident.workspace_id
		          AND association.incident_id = incident.id),
		       (SELECT count(*) FROM investigation_signal_correlations AS correlation
		        WHERE correlation.tenant_id = incident.tenant_id
		          AND correlation.workspace_id = incident.workspace_id
		          AND correlation.incident_id = incident.id),
		       (SELECT count(*) FROM outbox_events AS event
		        WHERE event.tenant_id = incident.tenant_id
		          AND event.workspace_id = incident.workspace_id
		          AND event.aggregate_id = incident.id
		          AND event.event_type = 'incident.created.v1')
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
	`, testTenantID, testWorkspaceID, incidentID).Scan(
		&persistedCount, &persistedVersion, &openedAt, &lastSignalAt,
		&associationCount, &correlationCount, &outboxCount,
	); err != nil {
		t.Fatalf("read concurrent incident aggregate: %v", err)
	}
	wantOpenedAt := signals[0].ObservedAt.UTC()
	wantLastSignalAt := signals[len(signals)-1].ObservedAt.UTC()
	if created != 1 || persistedCount != signalCount || persistedVersion != signalCount ||
		associationCount != signalCount || correlationCount != signalCount || outboxCount != 1 ||
		!openedAt.Equal(wantOpenedAt) || !lastSignalAt.Equal(wantLastSignalAt) {
		t.Fatalf(
			"concurrent aggregate = created:%d count:%d version:%d associations:%d correlations:%d outbox:%d window:%s..%s; want 1/%d/%d/%d/%d/1/%s..%s",
			created, persistedCount, persistedVersion, associationCount, correlationCount, outboxCount,
			openedAt, lastSignalAt, signalCount, signalCount, signalCount, signalCount, wantOpenedAt, wantLastSignalAt,
		)
	}
}

func TestPostgresCorrelateSameSignalConcurrentlyCountsAndAssociatesOnce(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	signal := fixture.registerSignal(t, repositorySignalID, "firing", fixture.base, "event-same-signal-concurrent")
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: testWorkspaceID, SignalID: signal.ID,
		CorrelationKey: "payments:staging:same-signal-concurrent",
		ServiceID:      testServiceID, EnvironmentID: testEnvironmentID, MappingStatus: domain.MappingExact,
	}
	const goroutines = 16
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan investigation.CorrelateSignalResult, goroutines)
	errorsCh := make(chan error, goroutines)
	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := fixture.repository.CorrelateSignal(ctx, request)
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("CorrelateSignal(same signal concurrent) error = %v", err)
		}
	}
	created, counted, associated := 0, 0, 0
	incidentID := ""
	for result := range results {
		if result.Created {
			created++
		}
		if result.Counted {
			counted++
		}
		if result.Associated {
			associated++
		}
		if incidentID == "" {
			incidentID = result.Incident.ID
		} else if result.Incident.ID != incidentID {
			t.Fatalf("same-signal incident ID = %q, want %q", result.Incident.ID, incidentID)
		}
	}
	var signalCount, associationCount, correlationCount, outboxCount int
	var version int64
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT incident.signal_count, incident.version,
		       (SELECT count(*) FROM incident_signals AS association
		        WHERE association.tenant_id = incident.tenant_id
		          AND association.workspace_id = incident.workspace_id
		          AND association.incident_id = incident.id
		          AND association.signal_id = $4),
		       (SELECT count(*) FROM investigation_signal_correlations AS correlation
		        WHERE correlation.tenant_id = incident.tenant_id
		          AND correlation.workspace_id = incident.workspace_id
		          AND correlation.incident_id = incident.id
		          AND correlation.signal_id = $4),
		       (SELECT count(*) FROM outbox_events AS event
		        WHERE event.tenant_id = incident.tenant_id
		          AND event.workspace_id = incident.workspace_id
		          AND event.aggregate_id = incident.id
		          AND event.event_type = 'incident.created.v1')
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
	`, testTenantID, testWorkspaceID, incidentID, signal.ID).Scan(
		&signalCount, &version, &associationCount, &correlationCount, &outboxCount,
	); err != nil {
		t.Fatalf("read same-signal concurrent facts: %v", err)
	}
	if created != 1 || counted != 1 || associated != goroutines || signalCount != 1 || version != 1 ||
		associationCount != 1 || correlationCount != 1 || outboxCount != 1 {
		t.Fatalf(
			"same-signal results = created:%d counted:%d associated:%d persisted-count:%d version:%d associations:%d correlations:%d outbox:%d",
			created, counted, associated, signalCount, version, associationCount, correlationCount, outboxCount,
		)
	}
}

func TestPostgresCreateInvestigationReplaysBeforeAuthorizationAndBindsActiveHash(t *testing.T) {
	var authorized atomic.Bool
	var authorizerCalls atomic.Int64
	authorized.Store(true)
	fixture := newRepositoryWriteFixture(t, func(_ context.Context, scope investigation.TaskSpecScope, _ investigation.TaskSpec) error {
		authorizerCalls.Add(1)
		if scope != (investigation.TaskSpecScope{
			TenantID: testTenantID, WorkspaceID: testWorkspaceID,
			EnvironmentID: testEnvironmentID, ServiceID: testServiceID,
			MappingStatus: domain.MappingExact,
		}) {
			return errors.New("wrong-task-scope-canary")
		}
		if !authorized.Load() {
			return errors.New("revoked-task-authorizer-canary")
		}
		return nil
	})
	incident := fixture.createIncident(t, repositorySignalID, "payments:staging:create-investigation")
	request := investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: testWorkspaceID, IncidentID: incident.ID, IdempotencyKey: "investigate:postgres-create",
		Tasks: []investigation.TaskSpec{
			{Key: "metrics", ConnectorID: "prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
			{Key: "logs", ConnectorID: "victorialogs-staging-v1-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
		},
	}
	first, err := fixture.repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, request))
	if err != nil {
		t.Fatalf("CreateOrGetInvestigation(first) error = %v", err)
	}
	if !first.Created || len(first.Tasks) != 2 || first.Tasks[0].Key != "logs" || first.Tasks[0].Position != 1 ||
		first.Tasks[1].Key != "metrics" || first.Tasks[1].Position != 2 {
		t.Fatalf("CreateOrGetInvestigation(first) = %#v, want stable task order", first)
	}
	if authorizerCalls.Load() != 2 {
		t.Fatalf("authorizer calls after create = %d, want 2", authorizerCalls.Load())
	}

	authorized.Store(false)
	replay, err := fixture.repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, request))
	if err != nil || replay.Created || replay.Investigation.ID != first.Investigation.ID {
		t.Fatalf("CreateOrGetInvestigation(replay after revocation) = %#v, %v", replay, err)
	}
	if authorizerCalls.Load() != 2 {
		t.Fatalf("authorizer calls after exact replay = %d, want 2", authorizerCalls.Load())
	}
	conflict := request
	conflict.Tasks = []investigation.TaskSpec{{
		Key: "metrics", ConnectorID: "prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Operation: "range_query", Input: []byte(`{"lookback_minutes":16}`),
	}}
	if _, err := fixture.repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, conflict)); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CreateOrGetInvestigation(conflicting replay) error = %v, want ErrIdempotencyConflict", err)
	}
	newKey := request
	newKey.IdempotencyKey = "investigate:postgres-create:binding"
	if _, err := fixture.repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, newKey)); !errors.Is(err, investigation.ErrInvalidRequest) ||
		strings.Contains(fmt.Sprint(err), "revoked-task-authorizer-canary") {
		t.Fatalf("CreateOrGetInvestigation(unauthorized binding) error = %v", err)
	}
	if authorizerCalls.Load() != 3 {
		t.Fatalf("authorizer calls after rejected active binding = %d, want 3", authorizerCalls.Load())
	}
	authorized.Store(true)
	bound, err := fixture.repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, newKey))
	if err != nil || bound.Created || bound.Investigation.ID != first.Investigation.ID {
		t.Fatalf("CreateOrGetInvestigation(active binding) = %#v, %v", bound, err)
	}
	if authorizerCalls.Load() != 5 {
		t.Fatalf("authorizer calls after authorized active binding = %d, want 5", authorizerCalls.Load())
	}

	var status, schemaVersion string
	var version int64
	var windowStart, windowEnd time.Time
	var ledgerCount int
	if err := fixture.harness.db.QueryRow(context.Background(), `
		SELECT incident.status, incident.version,
		       investigation.window_start, investigation.window_end, investigation.tool_schema_version,
		       (SELECT count(*) FROM investigation_idempotency_records
		        WHERE workspace_id = $1 AND resource_id = investigation.id)
		FROM incidents AS incident
		JOIN investigations AS investigation
		  ON investigation.tenant_id = incident.tenant_id
		 AND investigation.workspace_id = incident.workspace_id
		 AND investigation.incident_id = incident.id
		WHERE incident.workspace_id = $1 AND incident.id = $2 AND investigation.id = $3
	`, testWorkspaceID, incident.ID, first.Investigation.ID).Scan(
		&status, &version, &windowStart, &windowEnd, &schemaVersion, &ledgerCount,
	); err != nil {
		t.Fatalf("read investigation admission snapshot: %v", err)
	}
	if status != string(domain.IncidentInvestigating) || version != 2 || schemaVersion != "investigation-task.v1" ||
		!windowStart.Equal(incident.OpenedAt) || !windowEnd.Equal(incident.LastSignalAt) || ledgerCount != 2 {
		t.Fatalf("admission snapshot = status:%s version:%d window:%s..%s schema:%s ledgers:%d",
			status, version, windowStart, windowEnd, schemaVersion, ledgerCount)
	}
}

func TestPostgresCreateInvestigationRejectsUntrustedIncidentScopeWithoutPartialWrite(t *testing.T) {
	const wrongEnvironmentID = "26000000-0000-4000-8000-000000000001"
	for name, configure := range map[string]func(*testing.T, repositoryWriteFixture) investigation.CorrelateSignalRequest{
		"wrong environment": func(t *testing.T, fixture repositoryWriteFixture) investigation.CorrelateSignalRequest {
			execSQL(t, fixture.harness.db, `
				INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
				VALUES ($1, $2, $3, 'other-staging', 'STAGING')
			`, wrongEnvironmentID, testTenantID, testWorkspaceID)
			return investigation.CorrelateSignalRequest{
				CorrelationKey: "payments:other-staging:scope", ServiceID: testServiceID,
				EnvironmentID: wrongEnvironmentID, MappingStatus: domain.MappingExact,
			}
		},
		"unresolved mapping": func(_ *testing.T, _ repositoryWriteFixture) investigation.CorrelateSignalRequest {
			return investigation.CorrelateSignalRequest{
				CorrelationKey: "payments:unknown:scope", MappingStatus: domain.MappingUnresolved,
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var authorizerCalls atomic.Int64
			fixture := newRepositoryWriteFixture(t, func(_ context.Context, scope investigation.TaskSpecScope, _ investigation.TaskSpec) error {
				authorizerCalls.Add(1)
				if scope.TenantID != testTenantID || scope.WorkspaceID != testWorkspaceID ||
					scope.ServiceID != testServiceID || scope.EnvironmentID != testEnvironmentID ||
					scope.MappingStatus != domain.MappingExact {
					return errors.New("scope-authorizer-canary")
				}
				return nil
			})
			correlation := configure(t, fixture)
			signal := fixture.registerSignal(
				t, repositorySignalID, "firing", fixture.base,
				"event-scope-"+strings.ReplaceAll(name, " ", "-"),
			)
			correlation.WorkspaceID = testWorkspaceID
			correlation.SignalID = signal.ID
			correlated, err := fixture.repository.CorrelateSignal(context.Background(), correlation)
			if err != nil {
				t.Fatalf("CorrelateSignal() error = %v", err)
			}
			idempotencyKey := "investigate:postgres-scope:" + strings.ReplaceAll(name, " ", "-")
			_, err = fixture.repository.CreateOrGetInvestigation(context.Background(), boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
				WorkspaceID: testWorkspaceID, IncidentID: correlated.Incident.ID, IdempotencyKey: idempotencyKey,
				Tasks: []investigation.TaskSpec{{
					Key: "metrics", ConnectorID: "prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Operation: "range_query",
					Input: []byte(`{"lookback_minutes":15}`),
				}},
			}))

			if !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("CreateOrGetInvestigation() error = %v, want ErrInvalidRequest", err)
			}
			if strings.Contains(fmt.Sprint(err), "scope-authorizer-canary") {
				t.Fatalf("CreateOrGetInvestigation() leaked scope authorizer detail: %v", err)
			}
			wantCalls := int64(1)
			if correlation.MappingStatus != domain.MappingExact {
				wantCalls = 0
			}
			if authorizerCalls.Load() != wantCalls {
				t.Fatalf("authorizer calls = %d, want %d", authorizerCalls.Load(), wantCalls)
			}

			var status string
			var version int64
			var investigations, tasks, ledgers int
			if err := fixture.harness.db.QueryRow(context.Background(), `
				SELECT incident.status, incident.version,
				       (SELECT count(*) FROM investigations WHERE tenant_id = incident.tenant_id AND workspace_id = incident.workspace_id AND incident_id = incident.id),
				       (SELECT count(*) FROM tool_invocations WHERE tenant_id = incident.tenant_id AND workspace_id = incident.workspace_id AND incident_id = incident.id),
				       (SELECT count(*) FROM investigation_idempotency_records WHERE tenant_id = incident.tenant_id AND workspace_id = incident.workspace_id AND idempotency_key = $4)
				FROM incidents AS incident
				WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
			`, testTenantID, testWorkspaceID, correlated.Incident.ID, idempotencyKey).Scan(
				&status, &version, &investigations, &tasks, &ledgers,
			); err != nil {
				t.Fatalf("read rejected scope facts: %v", err)
			}
			if status != string(domain.IncidentOpen) || version != 1 || investigations != 0 || tasks != 0 || ledgers != 0 {
				t.Fatalf("rejected scope facts = status:%s version:%d investigations:%d tasks:%d ledgers:%d",
					status, version, investigations, tasks, ledgers)
			}
		})
	}
}

func TestPostgresCreateInvestigationSameKeyConcurrentlyCommitsOneFixedResult(t *testing.T) {
	fixture := newRepositoryWriteFixture(t, nil)
	incident := fixture.createIncident(t, repositorySignalID, "payments:staging:create-concurrent")
	request := investigation.CreateOrGetInvestigationRequest{
		WorkspaceID: testWorkspaceID, IncidentID: incident.ID, IdempotencyKey: "investigate:postgres-concurrent",
		Tasks: []investigation.TaskSpec{
			{Key: "metrics", ConnectorID: "prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`)},
			{Key: "logs", ConnectorID: "victorialogs-staging-v1-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Operation: "search", Input: []byte(`{"lookback_minutes":30}`)},
		},
	}
	const goroutines = 16
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan investigation.CreateOrGetInvestigationResult, goroutines)
	errorsCh := make(chan error, goroutines)
	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := fixture.repository.CreateOrGetInvestigation(ctx, boundCreateRequest(t, request))
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("CreateOrGetInvestigation(concurrent same key) error = %v", err)
		}
	}
	created := 0
	investigationID := ""
	taskIDs := [2]string{}
	for result := range results {
		if result.Created {
			created++
		}
		if len(result.Tasks) != 2 || result.Tasks[0].Key != "logs" || result.Tasks[0].Position != 1 ||
			result.Tasks[1].Key != "metrics" || result.Tasks[1].Position != 2 {
			t.Fatalf("concurrent fixed tasks = %#v", result.Tasks)
		}
		if investigationID == "" {
			investigationID = result.Investigation.ID
			taskIDs = [2]string{result.Tasks[0].ID, result.Tasks[1].ID}
		} else if result.Investigation.ID != investigationID || result.Tasks[0].ID != taskIDs[0] ||
			result.Tasks[1].ID != taskIDs[1] {
			t.Fatalf(
				"concurrent result IDs = investigation:%q tasks:%q/%q; want %q %q/%q",
				result.Investigation.ID, result.Tasks[0].ID, result.Tasks[1].ID,
				investigationID, taskIDs[0], taskIDs[1],
			)
		}
	}
	var status, taskSignature string
	var incidentVersion int64
	var investigationCount, taskCount, ledgerCount int
	if err := fixture.harness.db.QueryRow(ctx, `
		SELECT incident.status, incident.version,
		       (SELECT count(*) FROM investigations AS investigation
		        WHERE investigation.tenant_id = incident.tenant_id
		          AND investigation.workspace_id = incident.workspace_id
		          AND investigation.incident_id = incident.id
		          AND investigation.runtime_schema_version = 'investigation-runtime.v1'),
		       (SELECT count(*) FROM tool_invocations AS task
		        WHERE task.tenant_id = incident.tenant_id
		          AND task.workspace_id = incident.workspace_id
		          AND task.investigation_id = $4
		          AND task.runtime_schema_version = 'investigation-runtime.v1'),
		       (SELECT string_agg(task.task_key || ':' || task.position::text, ',' ORDER BY task.position)
		        FROM tool_invocations AS task
		        WHERE task.tenant_id = incident.tenant_id
		          AND task.workspace_id = incident.workspace_id
		          AND task.investigation_id = $4
		          AND task.runtime_schema_version = 'investigation-runtime.v1'),
		       (SELECT count(*) FROM investigation_idempotency_records AS ledger
		        WHERE ledger.tenant_id = incident.tenant_id
		          AND ledger.workspace_id = incident.workspace_id
		          AND ledger.idempotency_key = $5
		          AND ledger.resource_id = $4)
		FROM incidents AS incident
		WHERE incident.tenant_id = $1 AND incident.workspace_id = $2 AND incident.id = $3
	`, testTenantID, testWorkspaceID, incident.ID, investigationID, request.IdempotencyKey).Scan(
		&status, &incidentVersion, &investigationCount, &taskCount, &taskSignature, &ledgerCount,
	); err != nil {
		t.Fatalf("read concurrent investigation facts: %v", err)
	}
	if created != 1 || status != string(domain.IncidentInvestigating) || incidentVersion != 2 ||
		investigationCount != 1 || taskCount != 2 || taskSignature != "logs:1,metrics:2" || ledgerCount != 1 {
		t.Fatalf(
			"concurrent investigation = created:%d status:%s version:%d investigations:%d tasks:%d signature:%q ledger:%d",
			created, status, incidentVersion, investigationCount, taskCount, taskSignature, ledgerCount,
		)
	}
}

type repositoryWriteFixture struct {
	harness    *postgresHarness
	repository *investigationpostgres.Repository
	base       time.Time
}

func newRepositoryWriteFixture(
	t *testing.T,
	authorizer investigation.TaskSpecAuthorizer,
) repositoryWriteFixture {
	t.Helper()
	var next atomic.Uint64
	return newRepositoryWriteFixtureWithIDFactory(t, authorizer, func() string {
		return fmt.Sprintf("90000000-0000-4000-8000-%012x", next.Add(1))
	})
}

func newRepositoryWriteFixtureWithIDFactory(
	t *testing.T,
	authorizer investigation.TaskSpecAuthorizer,
	idFactory func() string,
) repositoryWriteFixture {
	t.Helper()
	if idFactory == nil {
		t.Fatal("repository write fixture requires an ID factory")
	}
	harness := newPostgresHarness(t)
	harness.applyThroughLatestInvestigationSchema(t)
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	execSQL(t, harness.db, `INSERT INTO tenants (id, name) VALUES ($1, 'tenant')`, testTenantID)
	execSQL(t, harness.db, `INSERT INTO workspaces (id, tenant_id, name) VALUES ($1, $2, 'workspace')`, testWorkspaceID, testTenantID)
	execSQL(t, harness.db, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1, $2, $3, 'staging', 'STAGING')
	`, testEnvironmentID, testTenantID, testWorkspaceID)
	execSQL(t, harness.db, `
		INSERT INTO services (id, tenant_id, workspace_id, name, owner_group)
		VALUES ($1, $2, $3, 'payments', 'payments-sre')
	`, testServiceID, testTenantID, testWorkspaceID)
	execSQL(t, harness.db, `
		INSERT INTO integrations (id, tenant_id, workspace_id, provider, name, secret_ref)
		VALUES ($1, $2, $3, 'alertmanager', 'alerts', 'vault://alerts')
	`, testIntegrationID, testTenantID, testWorkspaceID)
	if authorizer == nil {
		authorizer = func(context.Context, investigation.TaskSpecScope, investigation.TaskSpec) error { return nil }
	}
	repository, err := investigationpostgres.New(harness.extendedPool(t), investigationpostgres.Options{
		TaskRuntimeBinder:  testTaskRuntimeBinder,
		IDFactory:          idFactory,
		TaskSpecAuthorizer: authorizer,
	})
	if err != nil {
		t.Fatalf("postgres.New() error = %v", err)
	}
	return repositoryWriteFixture{harness: harness, repository: repository, base: base}
}

func (fixture repositoryWriteFixture) registerSignal(
	t *testing.T,
	signalID, status string,
	observedAt time.Time,
	providerEventID string,
) domain.Signal {
	t.Helper()
	signal := domain.Signal{
		ID: signalID, WorkspaceID: testWorkspaceID, IntegrationID: testIntegrationID,
		Provider: "alertmanager", ProviderEventID: providerEventID,
		PayloadHash: sha256Hex([]byte("payload-" + signalID)), Fingerprint: "payments:staging:latency",
		Status: status, Labels: map[string]string{"service": "payments"}, ObservedAt: observedAt,
	}
	created, err := fixture.repository.RegisterSignal(context.Background(), signal)
	if err != nil || !created {
		t.Fatalf("RegisterSignal(%s) = %v, %v; want created", signalID, created, err)
	}
	return signal
}

func (fixture repositoryWriteFixture) createIncident(t *testing.T, signalID, correlationKey string) domain.Incident {
	t.Helper()
	signal := fixture.registerSignal(t, signalID, "firing", fixture.base, "event-"+signalID)
	result, err := fixture.repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: testWorkspaceID, SignalID: signal.ID, CorrelationKey: correlationKey,
		ServiceID: testServiceID, EnvironmentID: testEnvironmentID, MappingStatus: domain.MappingExact,
	})
	if err != nil || !result.Created {
		t.Fatalf("CorrelateSignal(create incident) = %#v, %v", result, err)
	}
	return result.Incident
}
