package postgres

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/overview"
)

const (
	repositoryTestTenantID      = "11111111-1111-4111-8111-111111111111"
	repositoryTestWorkspaceID   = "22222222-2222-4222-8222-222222222222"
	repositoryTestEnvironmentID = "33333333-3333-4333-8333-333333333333"
)

var repositoryTestNow = time.Date(2026, time.July, 18, 10, 0, 0, 0, time.UTC)

func TestRepositoryResolveScopeUsesWorkspaceEnvironmentRelationship(t *testing.T) {
	t.Parallel()
	database, repository := newMockRepository(t)
	defer database.Close()
	expectReadOnlyQuery(
		database,
		`SELECT w\.tenant_id::text, w\.id::text, e\.id::text`,
		[]any{repositoryTestWorkspaceID, repositoryTestEnvironmentID},
		pgxmock.NewRows([]string{"tenant_id", "workspace_id", "environment_id"}).
			AddRow(repositoryTestTenantID, repositoryTestWorkspaceID, repositoryTestEnvironmentID),
	)

	scope, err := repository.ResolveScope(
		context.Background(),
		repositoryTestWorkspaceID,
		repositoryTestEnvironmentID,
	)
	if err != nil {
		t.Fatalf("ResolveScope() error = %v", err)
	}
	if scope != repositoryTestScope() {
		t.Fatalf("ResolveScope() = %#v, want %#v", scope, repositoryTestScope())
	}
	assertMockExpectations(t, database)
}

func TestRepositoryReadinessDistinguishesMissingPartialAndAvailableModules(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		feature overview.Feature
		present []bool
		want    overview.ImplementationState
	}{
		"assets missing": {
			feature: overview.FeatureAssets,
			present: []bool{false, false},
			want:    overview.StateNotStarted,
		},
		"assets partial": {
			feature: overview.FeatureAssets,
			present: []bool{true, false},
			want:    overview.StateUnavailable,
		},
		"assets available": {
			feature: overview.FeatureAssets,
			present: []bool{true, true},
			want:    overview.StateAvailable,
		},
		"sources missing": {
			feature: overview.FeatureSources,
			present: []bool{false, false, false, false, false},
			want:    overview.StateNotStarted,
		},
		"sources partial": {
			feature: overview.FeatureSources,
			present: []bool{true, true, true, true, false},
			want:    overview.StateUnavailable,
		},
		"sources available": {
			feature: overview.FeatureSources,
			present: []bool{true, true, true, true, true},
			want:    overview.StateAvailable,
		},
	} {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			database, repository := newMockRepository(t)
			defer database.Close()
			relations := testRelations(test.feature)
			rows := pgxmock.NewRows([]string{"relation_name", "present"})
			for index, present := range test.present {
				rows = rows.AddRow(relations[index], present)
			}
			expectReadOnlyQuery(
				database,
				`SELECT relation_name, to_regclass`,
				[]any{relations},
				rows,
			)
			state, err := repository.State(context.Background(), repositoryTestScope(), test.feature)
			if err != nil {
				t.Fatalf("State() error = %v", err)
			}
			if state != test.want {
				t.Fatalf("State() = %s, want %s", state, test.want)
			}
			assertMockExpectations(t, database)
		})
	}
}

func TestRepositoryLaterFeaturesAreNotStartedWithoutDatabaseGuessing(t *testing.T) {
	t.Parallel()
	database, repository := newMockRepository(t)
	defer database.Close()
	for _, feature := range []overview.Feature{
		overview.FeatureConnections,
		overview.FeatureInvestigations,
		overview.FeatureActions,
		overview.FeatureReleases,
	} {
		state, err := repository.State(context.Background(), repositoryTestScope(), feature)
		if err != nil || state != overview.StateNotStarted {
			t.Errorf("State(%s) = (%s, %v), want NOT_STARTED", feature, state, err)
		}
	}
	assertMockExpectations(t, database)
}

func TestRepositoryAssetFactsUseExactCompositeScopeAndBoundedReadOnlyQuery(t *testing.T) {
	t.Parallel()
	database, repository := newMockRepository(t)
	defer database.Close()
	oldest := repositoryTestNow.Add(-time.Hour)
	expectReadOnlyQuery(
		database,
		`(?s)FROM asset_conflicts AS conflict.*conflict\.tenant_id = \$1::uuid.*conflict\.workspace_id = \$2::uuid.*conflict\.environment_id = \$3::uuid.*FROM assets AS asset.*asset\.tenant_id = \$1::uuid.*asset\.workspace_id = \$2::uuid.*asset\.environment_id = \$3::uuid`,
		[]any{repositoryTestTenantID, repositoryTestWorkspaceID, repositoryTestEnvironmentID},
		pgxmock.NewRows([]string{
			"observed_at", "total", "discovered", "active", "stale", "quarantined", "retired",
			"exact", "ambiguous", "unresolved", "oldest_stale_at", "open_conflicts",
		}).AddRow(
			repositoryTestNow, int64(6), int64(1), int64(2), int64(1), int64(1), int64(1),
			int64(2), int64(2), int64(2), oldest, int64(2),
		),
	)

	facts, err := repository.ReadAssetFacts(context.Background(), repositoryTestScope())
	if err != nil {
		t.Fatalf("ReadAssetFacts() error = %v; expectations = %v", err, database.ExpectationsWereMet())
	}
	if facts.Total != 6 || facts.StaleCount != 1 || facts.OpenConflictCount != 2 ||
		facts.OldestStaleAt == nil || !facts.OldestStaleAt.Equal(oldest) {
		t.Fatalf("ReadAssetFacts() = %#v", facts)
	}
	if len(facts.Lifecycles) != 5 || len(facts.MappingStatuses) != 3 {
		t.Fatalf("asset fact dimensions = lifecycle:%#v mapping:%#v", facts.Lifecycles, facts.MappingStatuses)
	}
	assertMockExpectations(t, database)
}

func TestRepositorySourceFactsAggregateOnlyEnvironmentAuthorizedSafeGateSummaries(t *testing.T) {
	t.Parallel()
	database, repository := newMockRepository(t)
	defer database.Close()
	providerJSON := []byte(`[
		{"provider_kind":"MANUAL_V1","gate_status":"AVAILABLE","source_count":1,"evidence_at":"2026-07-18T10:00:00Z"},
		{"provider_kind":"VSPHERE_V1","gate_status":"UNAVAILABLE","source_count":2,"evidence_at":null}
	]`)
	expectReadOnlyQuery(
		database,
		`(?s)asset_source_revision_authorities.*authority\.environment_id = \$3::uuid.*asset_source_limit_buckets.*jsonb_agg`,
		[]any{repositoryTestTenantID, repositoryTestWorkspaceID, repositoryTestEnvironmentID},
		sourceFactRows(providerJSON),
	)

	facts, err := repository.ReadSourceFacts(context.Background(), repositoryTestScope())
	if err != nil {
		t.Fatalf("ReadSourceFacts() error = %v", err)
	}
	if facts.Total != 3 || facts.BackpressuredCount != 2 ||
		len(facts.Statuses) != 4 || len(facts.RevisionStatuses) != 6 ||
		len(facts.GateStatuses) != 5 || len(facts.RunStatuses) != 8 ||
		len(facts.ProviderGates) != 2 {
		t.Fatalf("ReadSourceFacts() = %#v", facts)
	}
	if got := facts.ProviderGates[0]; got.ProviderKind != "MANUAL_V1" ||
		got.GateStatus != assetcatalog.SourceGateAvailable || got.SourceCount != 1 ||
		got.EvidenceAt == nil || !got.EvidenceAt.Equal(repositoryTestNow) {
		t.Fatalf("first provider gate = %#v", got)
	}
	assertMockExpectations(t, database)
}

func TestRepositoryRollsBackAndReturnsClosedErrorOnQueryFailure(t *testing.T) {
	t.Parallel()
	database, repository := newMockRepository(t)
	defer database.Close()
	canary := errors.New("endpoint=https://private credential=secret")
	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	database.ExpectExec(regexp.QuoteMeta("SET LOCAL statement_timeout = '500ms'")).
		WillReturnResult(pgxmock.NewResult("SET", 0))
	database.ExpectQuery("FROM assets AS asset").
		WithArgs(repositoryTestTenantID, repositoryTestWorkspaceID, repositoryTestEnvironmentID).
		WillReturnError(canary)
	database.ExpectRollback()

	_, err := repository.ReadAssetFacts(context.Background(), repositoryTestScope())
	if !errors.Is(err, overview.ErrUnavailable) || errors.Is(err, canary) {
		t.Fatalf("ReadAssetFacts() error = %v, want closed ErrUnavailable", err)
	}
	assertMockExpectations(t, database)
}

func newMockRepository(t *testing.T) (pgxmock.PgxPoolIface, *Repository) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	return database, newRepository(database)
}

func repositoryTestScope() assetcatalog.Scope {
	return assetcatalog.Scope{
		TenantID:      repositoryTestTenantID,
		WorkspaceID:   repositoryTestWorkspaceID,
		EnvironmentID: repositoryTestEnvironmentID,
	}
}

func expectReadOnlyQuery(
	database pgxmock.PgxPoolIface,
	query string,
	args []any,
	rows *pgxmock.Rows,
) {
	database.ExpectBeginTx(pgx.TxOptions{AccessMode: pgx.ReadOnly})
	database.ExpectExec(regexp.QuoteMeta("SET LOCAL statement_timeout = '500ms'")).
		WillReturnResult(pgxmock.NewResult("SET", 0))
	expectation := database.ExpectQuery(query)
	if args != nil {
		expectation.WithArgs(args...)
	}
	expectation.WillReturnRows(rows)
	database.ExpectCommit()
}

func sourceFactRows(providerJSON []byte) *pgxmock.Rows {
	columns := []string{
		"observed_at", "total",
		"active", "paused", "degraded", "disabled",
		"revision_draft", "revision_validating", "revision_validated", "revision_rejected",
		"revision_published", "revision_superseded",
		"gate_unavailable", "gate_validating", "gate_available", "gate_degraded", "gate_suspended",
		"run_queued", "run_delayed", "run_running", "run_finalizing",
		"run_succeeded", "run_partial", "run_failed", "run_cancelled",
		"backpressured", "provider_gates",
	}
	values := []any{
		repositoryTestNow, int64(3),
		int64(1), int64(1), int64(1), int64(0),
		int64(1), int64(0), int64(0), int64(0), int64(2), int64(0),
		int64(2), int64(0), int64(1), int64(0), int64(0),
		int64(0), int64(0), int64(1), int64(0), int64(1), int64(0), int64(1), int64(0),
		int64(2), providerJSON,
	}
	return pgxmock.NewRows(columns).AddRow(values...)
}

func testRelations(feature overview.Feature) []string {
	switch feature {
	case overview.FeatureAssets:
		return []string{"assets", "asset_conflicts"}
	case overview.FeatureSources:
		return []string{
			"asset_sources",
			"asset_source_revisions",
			"asset_source_revision_authorities",
			"asset_source_runs",
			"asset_source_limit_buckets",
		}
	default:
		return nil
	}
}

func assertMockExpectations(t *testing.T, database pgxmock.PgxPoolIface) {
	t.Helper()
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}
