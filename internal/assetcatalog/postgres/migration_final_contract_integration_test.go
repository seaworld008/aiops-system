package postgres_test

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAssetCatalogMigrationFinalOperationalContract(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	t.Run("run state and cleanup proof", func(t *testing.T) {
		finalRequireColumns(t, harness.db, "asset_source_runs", []string{
			"source_revision", "source_revision_digest", "run_kind", "status",
			"stage_code", "stage_changed_at", "trigger_type", "gate_revision",
			"cursor_before_sha256", "cursor_after_sha256", "page_sequence", "page_digest",
			"relation_page_sequence", "relation_page_digest", "final_page", "complete_snapshot",
			"effective_complete_snapshot", "checkpoint_version", "lease_owner",
			"lease_expires_at", "fence_epoch", "fence_token_hash", "heartbeat_sequence",
			"not_before", "pending_transition", "pending_transition_reason",
			"pending_transition_not_before", "pending_transition_digest",
			"observed_count", "created_count", "changed_count", "unchanged_count",
			"conflict_count", "missing_count", "stale_count", "restored_count",
			"tombstoned_count", "rejected_count", "work_result_kind",
			"work_result_status", "work_result_digest", "work_result_recorded_at",
			"validation_outcome", "validation_digest", "validation_proof_digest",
			"lineage_rollover_reason", "lineage_rollover_evidence_digest",
			"cleanup_attempt_id", "cleanup_attempt_epoch", "cleanup_status", "cleanup_digest",
			"terminal_failure_override", "terminal_failure_override_digest",
			"terminal_command_sha256",
			"failure_code", "trace_id", "started_at", "heartbeat_at", "completed_at",
		})
		finalForbidColumns(t, harness.db, "asset_source_runs", []string{"definition_revision"})

		finalRequireExactVocabulary(t, harness.db, "asset_source_runs", "run_kind", []string{
			"VALIDATION", "DISCOVERY", "CSV_IMPORT", "API_INGESTION", "MANUAL_MUTATION",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_source_runs", "status", []string{
			"QUEUED", "DELAYED", "RUNNING", "FINALIZING",
			"SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_source_runs", "stage_code", []string{
			"WAITING", "DELAYED", "VALIDATING", "READING", "NORMALIZING",
			"APPLYING", "CLEANING_UP", "COMPLETED",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_source_runs", "cleanup_status", []string{
			"NOT_OPENED", "PENDING", "REVOKED", "NO_CREDENTIAL", "UNCERTAIN",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_source_runs", "work_result_kind", []string{
			"DATA_PROJECTION", "VALIDATION_PROOF", "FAILURE_INTENT",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_source_runs", "work_result_status", []string{
			"SUCCEEDED", "PARTIAL", "FAILED",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_source_runs", "terminal_failure_override", []string{
			"CLEANUP_UNCERTAIN",
		})

		finalRequireConstraintTokens(t, harness.db, "asset_source_runs_state_ck", []string{
			"QUEUED", "DELAYED", "RUNNING", "FINALIZING", "SUCCEEDED", "PARTIAL",
			"FAILED", "CANCELLED", "WAITING", "CLEANING_UP", "COMPLETED",
			"work_result_kind", "cleanup_status", "completed_at",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_source_runs_work_result_ck", []string{
			"DATA_PROJECTION", "VALIDATION_PROOF", "FAILURE_INTENT",
			"work_result_digest", "work_result_recorded_at", "validation_proof_digest",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_source_runs_cleanup_ck", []string{
			"cleanup_attempt_id", "cleanup_attempt_epoch", "cleanup_digest",
			"NOT_OPENED", "PENDING", "REVOKED", "NO_CREDENTIAL", "UNCERTAIN",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_source_runs_pending_transition_ck", []string{
			"DELAY", "PROVIDER_RETRY_AFTER", "TRANSPORT_BACKOFF",
			"pending_transition_not_before", "pending_transition_digest",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_source_runs_terminal_override_ck", []string{
			"CLEANUP_UNCERTAIN", "terminal_failure_override_digest", "UNCERTAIN",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_source_runs_snapshot_ck", []string{
			"final_page", "complete_snapshot", "effective_complete_snapshot", "rejected_count",
		})
	})

	t.Run("observation freshness tombstone and previous chain", func(t *testing.T) {
		finalRequireColumns(t, harness.db, "asset_observations", []string{
			"environment_id", "source_id", "run_id", "provider_kind", "external_id",
			"source_revision", "canonical_revision_digest", "source_definition_digest",
			"observed_at", "freshness_kind", "freshness_order_time",
			"freshness_order_sequence", "provider_version_sha256", "provider_fact_sha256",
			"fingerprint_sha256", "provider_provenance_sha256", "previous_observation_id",
			"previous_chain_sha256", "observation_chain_sha256",
			"accepted_checkpoint_version", "run_fence_epoch", "run_page_sequence",
			"schema_version", "normalized_document", "document_sha256", "field_provenance",
			"field_provenance_sha256", "tombstone", "tombstone_reason_code",
		})
		finalRequireNullable(t, harness.db, "asset_observations", "normalized_document")
		finalRequireNullable(t, harness.db, "asset_observations", "document_sha256")

		finalRequireExactVocabulary(t, harness.db, "asset_observations", "freshness_kind", []string{
			"CATALOG_SEQUENCE", "OBJECT_SEQUENCE", "OBJECT_TIME_SEQUENCE", "CHECKPOINT_SEQUENCE",
		})
		finalRequireConstraintColumns(t, harness.db, "asset_observations_same_run_object_uk", []string{
			"tenant_id", "workspace_id", "source_id", "run_id", "provider_kind", "external_id",
		})
		finalRequireConstraintColumns(t, harness.db, "asset_observations_previous_exact_fk", []string{
			"tenant_id", "workspace_id", "environment_id", "source_id", "provider_kind",
			"external_id", "previous_observation_id", "previous_chain_sha256",
		})
		finalRequireForeignKey(t, harness.db, "asset_observations_previous_exact_fk",
			"asset_observations", []string{
				"tenant_id", "workspace_id", "environment_id", "source_id", "provider_kind",
				"external_id", "id", "observation_chain_sha256",
			})
		finalRequireForeignKey(t, harness.db, "asset_observations_run_revision_fk",
			"asset_source_runs", []string{
				"tenant_id", "workspace_id", "source_id", "id",
				"source_revision", "source_revision_digest",
			})
		finalRequireConstraintTokens(t, harness.db, "asset_observations_previous_exact_fk", []string{
			"previous_observation_id", "previous_chain_sha256",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_observations_previous_pair_ck", []string{
			"previous_observation_id", "previous_chain_sha256", "IS NULL", "IS NOT NULL",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_observations_freshness_ck", []string{
			"CATALOG_SEQUENCE", "OBJECT_SEQUENCE", "OBJECT_TIME_SEQUENCE",
			"CHECKPOINT_SEQUENCE", "freshness_order_time",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_observations_checkpoint_freshness_ck", []string{
			"CHECKPOINT_SEQUENCE", "freshness_order_sequence", "accepted_checkpoint_version",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_observations_document_ck", []string{
			"tombstone", "normalized_document", "document_sha256", "tombstone_reason_code",
			"IS NULL", "IS NOT NULL",
		})
		finalRequireTableCheckTokens(t, harness.db, "asset_observations", []string{
			"freshness_order_sequence", "provider_version_sha256", "provider_fact_sha256",
			"fingerprint_sha256", "provider_provenance_sha256", "observation_chain_sha256",
			"accepted_checkpoint_version", "run_fence_epoch", "run_page_sequence",
		})
	})

	t.Run("relationship is an independent freshness fact", func(t *testing.T) {
		finalRequireColumns(t, harness.db, "asset_relationships", []string{
			"source_id", "source_revision", "canonical_revision_digest", "last_run_id",
			"last_page_sequence", "relation_page_sha256", "accepted_checkpoint_version",
			"run_fence_epoch", "source_environment_id",
			"target_environment_id", "source_asset_id", "target_asset_id",
			"from_external_id", "to_external_id", "relationship_type", "provider_path_code",
			"confidence", "freshness_kind", "freshness_order_time",
			"freshness_order_sequence", "provider_version_sha256", "relation_fact_sha256",
		})
		finalForbidColumns(t, harness.db, "asset_relationships", []string{
			"observation_id", "source_observation_id",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_relationships", "freshness_kind", []string{
			"CATALOG_SEQUENCE", "OBJECT_SEQUENCE", "OBJECT_TIME_SEQUENCE", "CHECKPOINT_SEQUENCE",
		})
		finalRequireExactVocabulary(t, harness.db, "asset_relationships", "relationship_type", []string{
			"RUNS_ON", "CONTAINS", "DEPENDS_ON", "MONITORED_BY", "LOGS_TO", "TRACES_TO",
			"DELIVERED_BY", "MANAGED_BY", "PRIMARY_RUNTIME_FOR",
		})
		finalRequireConstraintColumns(t, harness.db, "asset_relationships_last_run_fk", []string{
			"tenant_id", "workspace_id", "source_id", "last_run_id",
			"source_revision", "canonical_revision_digest",
		})
		finalRequireForeignKey(t, harness.db, "asset_relationships_last_run_fk",
			"asset_source_runs", []string{
				"tenant_id", "workspace_id", "source_id", "id",
				"source_revision", "source_revision_digest",
			})
		finalRequireTableCheckTokens(t, harness.db, "asset_relationships", []string{
			"last_page_sequence", "relation_page_sha256", "freshness_order_sequence",
			"provider_version_sha256", "relation_fact_sha256", "freshness_order_time",
			"accepted_checkpoint_version", "run_fence_epoch",
		})
	})

	t.Run("success pointers bind exact completed runs", func(t *testing.T) {
		finalRequireColumns(t, harness.db, "asset_sources", []string{
			"last_success_run_id", "last_success_at",
			"last_complete_snapshot_run_id", "last_complete_snapshot_at",
		})
		finalForbidColumns(t, harness.db, "asset_sources", []string{"last_successful_run_id"})
		finalRequireConstraintColumns(t, harness.db, "asset_sources_last_success_run_fk", []string{
			"tenant_id", "workspace_id", "id", "last_success_run_id",
		})
		finalRequireForeignKey(t, harness.db, "asset_sources_last_success_run_fk",
			"asset_source_runs", []string{"tenant_id", "workspace_id", "source_id", "id"})
		finalRequireConstraintColumns(t, harness.db, "asset_sources_last_complete_snapshot_run_fk", []string{
			"tenant_id", "workspace_id", "id", "last_complete_snapshot_run_id",
		})
		finalRequireForeignKey(t, harness.db, "asset_sources_last_complete_snapshot_run_fk",
			"asset_source_runs", []string{"tenant_id", "workspace_id", "source_id", "id"})
		finalRequireConstraintTokens(t, harness.db, "asset_sources_last_success_ck", []string{
			"last_success_run_id", "last_success_at", "IS NULL", "IS NOT NULL",
		})
		finalRequireConstraintTokens(t, harness.db, "asset_sources_last_complete_snapshot_ck", []string{
			"last_complete_snapshot_run_id", "last_complete_snapshot_at", "IS NULL", "IS NOT NULL",
		})

		triggerBody := finalTableTriggerBody(t, harness.db, "asset_sources")
		finalRequirePattern(t, triggerBody, `(?i)status\s*=\s*'SUCCEEDED'`,
			"success pointer guard must accept only SUCCEEDED runs")
		finalRequirePattern(t, triggerBody, `(?i)run_kind\s*(?:<>|!=)\s*'VALIDATION'`,
			"success pointer guard must reject Validation runs")
		for _, token := range []string{
			"last_success_run_id", "last_success_at", "last_complete_snapshot_run_id",
			"last_complete_snapshot_at", "effective_complete_snapshot", "completed_at",
		} {
			if !strings.Contains(strings.ToLower(triggerBody), strings.ToLower(token)) {
				t.Errorf("asset_sources trigger contract omits %q", token)
			}
		}
		finalRequirePattern(t, triggerBody,
			`(?i)new\.last_success_at\s*(?:<|<=)\s*old\.last_success_at`,
			"success pointer guard must reject completion-time regression")
	})

	t.Run("page and terminal closures are deferred and fail closed", func(t *testing.T) {
		for _, trigger := range []struct {
			name  string
			table string
		}{
			{name: "asset_source_runs_page_closure_guard", table: "asset_source_runs"},
			{name: "asset_source_runs_terminal_closure_guard", table: "asset_source_runs"},
			{name: "asset_observations_page_closure_guard", table: "asset_observations"},
			{name: "asset_relationships_page_closure_guard", table: "asset_relationships"},
			{name: "asset_sources_deferred_state_guard", table: "asset_sources"},
			{name: "asset_source_revisions_deferred_state_guard", table: "asset_source_revisions"},
		} {
			var deferrable, initiallyDeferred, enabled bool
			if err := harness.db.QueryRow(context.Background(), `
				SELECT trigger_record.tgdeferrable,trigger_record.tginitdeferred,
					trigger_record.tgenabled='O'
				FROM pg_catalog.pg_trigger AS trigger_record
				JOIN pg_catalog.pg_class AS relation ON relation.oid=trigger_record.tgrelid
				JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
				WHERE namespace.nspname='public' AND relation.relname=$1
				  AND trigger_record.tgname=$2 AND trigger_record.tgconstraint<>0
			`, trigger.table, trigger.name).Scan(&deferrable, &initiallyDeferred, &enabled); err != nil {
				t.Fatalf("read deferred trigger %s: %v", trigger.name, err)
			}
			if !deferrable || !initiallyDeferred || !enabled {
				t.Errorf("trigger %s deferred/enabled=(%v,%v,%v), want all true",
					trigger.name, deferrable, initiallyDeferred, enabled)
			}
		}
	})
}

func finalRequireColumns(t *testing.T, database *pgxpool.Pool, table string, expected []string) {
	t.Helper()
	actual := finalTableColumns(t, database, table)
	for _, column := range expected {
		if !slices.Contains(actual, column) {
			t.Errorf("%s is missing final-contract column %s", table, column)
		}
	}
}

func finalForbidColumns(t *testing.T, database *pgxpool.Pool, table string, forbidden []string) {
	t.Helper()
	actual := finalTableColumns(t, database, table)
	for _, column := range forbidden {
		if slices.Contains(actual, column) {
			t.Errorf("%s retains forbidden legacy column %s", table, column)
		}
	}
}

func finalTableColumns(t *testing.T, database *pgxpool.Pool, table string) []string {
	t.Helper()
	rows, err := database.Query(context.Background(), `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema='public' AND table_name=$1
		ORDER BY ordinal_position
	`, table)
	if err != nil {
		t.Fatalf("read columns for %s: %v", table, err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan column for %s: %v", table, err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns for %s: %v", table, err)
	}
	if len(columns) == 0 {
		t.Fatalf("table public.%s does not exist", table)
	}
	return columns
}

func finalRequireNullable(t *testing.T, database *pgxpool.Pool, table, column string) {
	t.Helper()
	var nullable string
	if err := database.QueryRow(context.Background(), `
		SELECT is_nullable
		FROM information_schema.columns
		WHERE table_schema='public' AND table_name=$1 AND column_name=$2
	`, table, column).Scan(&nullable); err != nil {
		t.Fatalf("read nullability for %s.%s: %v", table, column, err)
	}
	if nullable != "YES" {
		t.Errorf("%s.%s must be nullable for tombstones, got is_nullable=%s", table, column, nullable)
	}
}

var finalQuotedCode = regexp.MustCompile(`'([A-Z][A-Z0-9_]*)'`)

func finalRequireExactVocabulary(
	t *testing.T,
	database *pgxpool.Pool,
	table string,
	column string,
	expected []string,
) {
	t.Helper()
	var definition string
	if err := database.QueryRow(context.Background(), `
		SELECT COALESCE(string_agg(pg_get_constraintdef(c.oid, true), E'\n' ORDER BY c.conname), '')
		FROM pg_constraint c
		JOIN pg_class r ON r.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		JOIN pg_attribute a ON a.attrelid=r.oid AND a.attname=$2 AND NOT a.attisdropped
		WHERE n.nspname='public' AND r.relname=$1 AND c.contype='c'
		  AND c.conkey=ARRAY[a.attnum]::smallint[]
	`, table, column).Scan(&definition); err != nil {
		t.Fatalf("read vocabulary constraint for %s.%s: %v", table, column, err)
	}
	if definition == "" {
		t.Fatalf("%s.%s has no dedicated closed-vocabulary CHECK", table, column)
	}

	actualSet := make(map[string]struct{})
	for _, match := range finalQuotedCode.FindAllStringSubmatch(definition, -1) {
		actualSet[match[1]] = struct{}{}
	}
	actual := make([]string, 0, len(actualSet))
	for value := range actualSet {
		actual = append(actual, value)
	}
	sort.Strings(actual)
	want := slices.Clone(expected)
	sort.Strings(want)
	if !slices.Equal(actual, want) {
		t.Errorf("%s.%s vocabulary=%v, want exactly %v; definition=%s", table, column, actual, want, definition)
	}
}

func finalRequireConstraintColumns(
	t *testing.T,
	database *pgxpool.Pool,
	constraint string,
	expected []string,
) {
	t.Helper()
	rows, err := database.Query(context.Background(), `
		SELECT a.attname
		FROM pg_constraint c
		JOIN pg_class r ON r.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, position)
		JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum=k.attnum
		WHERE n.nspname='public' AND c.conname=$1
		ORDER BY k.position
	`, constraint)
	if err != nil {
		t.Fatalf("read columns for constraint %s: %v", constraint, err)
	}
	defer rows.Close()

	var actual []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan columns for constraint %s: %v", constraint, err)
		}
		actual = append(actual, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns for constraint %s: %v", constraint, err)
	}
	if !slices.Equal(actual, expected) {
		t.Errorf("constraint %s columns=%v, want exactly %v", constraint, actual, expected)
	}
}

func finalRequireForeignKey(
	t *testing.T,
	database *pgxpool.Pool,
	constraint string,
	expectedTable string,
	expectedColumns []string,
) {
	t.Helper()
	rows, err := database.Query(context.Background(), `
		SELECT referenced.relname, referenced_column.attname
		FROM pg_constraint c
		JOIN pg_class referencing ON referencing.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=referencing.relnamespace
		JOIN pg_class referenced ON referenced.oid=c.confrelid
		CROSS JOIN LATERAL unnest(c.confkey) WITH ORDINALITY AS k(attnum, position)
		JOIN pg_attribute referenced_column
		  ON referenced_column.attrelid=referenced.oid AND referenced_column.attnum=k.attnum
		WHERE n.nspname='public' AND c.conname=$1 AND c.contype='f'
		ORDER BY k.position
	`, constraint)
	if err != nil {
		t.Fatalf("read referenced columns for %s: %v", constraint, err)
	}
	defer rows.Close()

	var table string
	var actual []string
	for rows.Next() {
		var rowTable, column string
		if err := rows.Scan(&rowTable, &column); err != nil {
			t.Fatalf("scan referenced columns for %s: %v", constraint, err)
		}
		if table == "" {
			table = rowTable
		} else if table != rowTable {
			t.Fatalf("foreign key %s unexpectedly references multiple tables", constraint)
		}
		actual = append(actual, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate referenced columns for %s: %v", constraint, err)
	}
	if table != expectedTable || !slices.Equal(actual, expectedColumns) {
		t.Errorf("foreign key %s references %s%v, want %s%v",
			constraint, table, actual, expectedTable, expectedColumns)
	}
}

func finalRequireConstraintTokens(
	t *testing.T,
	database *pgxpool.Pool,
	constraint string,
	tokens []string,
) {
	t.Helper()
	var definition string
	if err := database.QueryRow(context.Background(), `
		SELECT pg_get_constraintdef(c.oid, true)
		FROM pg_constraint c
		JOIN pg_namespace n ON n.oid=c.connamespace
		WHERE n.nspname='public' AND c.conname=$1
	`, constraint).Scan(&definition); err != nil {
		t.Fatalf("read constraint %s: %v", constraint, err)
	}
	lower := strings.ToLower(definition)
	for _, token := range tokens {
		if !strings.Contains(lower, strings.ToLower(token)) {
			t.Errorf("constraint %s omits %q: %s", constraint, token, definition)
		}
	}
}

func finalRequireTableCheckTokens(
	t *testing.T,
	database *pgxpool.Pool,
	table string,
	tokens []string,
) {
	t.Helper()
	var definitions string
	if err := database.QueryRow(context.Background(), `
		SELECT COALESCE(string_agg(pg_get_constraintdef(c.oid, true), E'\n' ORDER BY c.conname), '')
		FROM pg_constraint c
		JOIN pg_class r ON r.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		WHERE n.nspname='public' AND r.relname=$1 AND c.contype='c'
	`, table).Scan(&definitions); err != nil {
		t.Fatalf("read CHECK constraints for %s: %v", table, err)
	}
	lower := strings.ToLower(definitions)
	for _, token := range tokens {
		if !strings.Contains(lower, strings.ToLower(token)) {
			t.Errorf("%s CHECK contract omits %q", table, token)
		}
	}
}

func finalTableTriggerBody(t *testing.T, database *pgxpool.Pool, table string) string {
	t.Helper()
	var body string
	if err := database.QueryRow(context.Background(), `
		SELECT COALESCE(string_agg(pg_get_functiondef(p.oid), E'\n' ORDER BY t.tgname), '')
		FROM pg_trigger t
		JOIN pg_class r ON r.oid=t.tgrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		JOIN pg_proc p ON p.oid=t.tgfoid
		WHERE n.nspname='public' AND r.relname=$1 AND NOT t.tgisinternal AND t.tgenabled='O'
	`, table).Scan(&body); err != nil {
		t.Fatalf("read trigger functions for %s: %v", table, err)
	}
	if body == "" {
		t.Fatalf("%s has no enabled user trigger contract", table)
	}
	return body
}

func finalRequirePattern(t *testing.T, value, pattern, message string) {
	t.Helper()
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		t.Fatalf("compile final-contract pattern %q: %v", pattern, err)
	}
	if !matched {
		t.Errorf("%s; pattern=%s", message, pattern)
	}
}
