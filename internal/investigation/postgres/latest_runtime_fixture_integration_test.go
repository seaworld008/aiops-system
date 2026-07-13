package postgres_test

import (
	"testing"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

// newLatestRuntimeFixture is intentionally separate from newRuntimeFixture.
// The latter remains a pre-cutover 000010 fixture for migration compatibility
// tests, while repository lifecycle tests exercise the latest investigation-owned
// schema through 000014 and bound v2 facts produced through the real write path.
func newLatestRuntimeFixture(t *testing.T) runtimeFixture {
	t.Helper()
	ids := []string{
		"91000000-0000-4000-8000-000000000001", // signal-ingested outbox
		testIncidentID,
		"91000000-0000-4000-8000-000000000002", // incident-created outbox
		testInvestigationID,
		testTaskID,
	}
	nextID := 0
	writeFixture := newRepositoryWriteFixtureWithIDFactory(t, nil, func() string {
		if nextID >= len(ids) {
			t.Fatalf("unexpected latest runtime fixture ID request %d", nextID+1)
		}
		id := ids[nextID]
		nextID++
		return id
	})
	incident := writeFixture.createIncident(t, testSignalID, "payments:staging:latency")
	if incident.ID != testIncidentID {
		t.Fatalf("latest runtime fixture incident ID = %s, want %s", incident.ID, testIncidentID)
	}
	created, err := writeFixture.repository.CreateOrGetInvestigation(
		t.Context(),
		boundCreateRequest(t, investigation.CreateOrGetInvestigationRequest{
			WorkspaceID: testWorkspaceID, IncidentID: testIncidentID,
			IdempotencyKey: "investigate:runtime",
			Tasks: []investigation.TaskSpec{{
				Key:         "metrics",
				ConnectorID: "prometheus-staging-v1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				Operation:   "range_query",
				Input:       []byte(`{"lookback_minutes":15}`),
			}},
		}),
	)
	if err != nil || !created.Created || created.Investigation.ID != testInvestigationID ||
		created.Investigation.RequestHashVersion != domain.InvestigationCreateRequestVersionV2 ||
		created.Investigation.PlanBinding.IsZero() || len(created.Tasks) != 1 ||
		created.Tasks[0].ID != testTaskID || created.Tasks[0].RuntimeBinding.IsZero() || nextID != len(ids) {
		t.Fatalf("create latest bound runtime fixture = %#v, ids=%d, err=%v", created, nextID, err)
	}
	return runtimeFixture{harness: writeFixture.harness, base: created.Investigation.CreatedAt}
}
