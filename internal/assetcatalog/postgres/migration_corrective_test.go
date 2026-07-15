package postgres_test

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const correctiveManualProfileManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":1,"compatibility_class":"MANUAL_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CATALOG_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":65536,"max_page_items":1,"max_page_relations":0,"network_mode":"NONE","parser_code":"MANUAL_ASSET_V1","profile_code":"MANUAL_V1","provider_kind":"MANUAL_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":[],"schedule_mode":"NONE","source_kind":"MANUAL","sync_mode":"MANUAL","trust_mode":"NONE","trusted_path_codes":["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`

const correctiveManualProviderSchemaV1 = `{"additionalProperties":false,"properties":{},"type":"object"}`

func TestAssetCatalogCorrectiveOwnsExact35RoutineSignaturesAndFutureHook(t *testing.T) {
	up := readMigration(t, "000015_assets_catalog.up.sql")
	correctiveAssertTopLevelParserSemantics(t)

	assertExactSQLObjectSet(t, "000015 owned routines", correctiveRoutineIdentities(up), correctiveExpectedRoutineIdentities())
	assertExactSQLObjectSet(t, "000015 reviewed trigger manifest", correctiveTriggerIdentities(t, up), correctiveExpectedTriggerIdentities())

	hook := correctiveRequireFunction(t, up, "public.asset_catalog_future_source_gate_admitted")
	correctiveAssertFunctionAttributes(t, "future Source hook", hook,
		"language plpgsql", "stable", "security invoker", "set search_path = pg_catalog, public, pg_temp")
	body := correctiveNormalizeSQL(hook.body)
	if body != "begin return false; end;" {
		t.Errorf("default future Source hook body = %q, want exact fail-closed RETURN false body", body)
	}
}

func TestAssetCatalogCorrectiveRejectsNoncanonicalProfileManifestAndDefinitionV2Drift(t *testing.T) {
	up := readMigration(t, "000015_assets_catalog.up.sql")
	revisionTable := correctiveRequireTable(t, up, "public.asset_source_revisions")
	correctiveRequireTokens(t, "Source Revision profile columns", correctiveNormalizeSQL(revisionTable),
		"canonical_profile_manifest bytea not null",
		"profile_manifest_sha256 text not null",
	)
	if strings.Contains(correctiveNormalizeSQL(revisionTable), "canonical_profile_manifest_sha256") {
		t.Error("profile manifest SHA column must be profile_manifest_sha256, not a parallel canonical_profile_manifest_sha256 name")
	}

	closure := correctiveRequireFunction(t, up, "public.validate_asset_source_revision_deferred_state")
	body := correctiveStripSQLComments(closure.body)
	normalizedBody := correctiveNormalizeSQL(body)
	correctiveRequireTokens(t, "deferred Profile closure", normalizedBody,
		"canonical_profile_manifest",
		"profile_manifest_sha256",
		"asset-source-profile-manifest.v1",
		"asset-source-definition.v2",
		"json_each",
		"convert_from",
		"::json",
		"convert_to",
	)
	for _, key := range correctiveProfileManifestV1Keys() {
		if !strings.Contains(normalizedBody, "'"+key+"'") {
			t.Errorf("deferred Profile closure does not enumerate closed manifest key %q", key)
		}
	}
	if !regexp.MustCompile(`(?is)count\s*\(\s*\*\s*\)`).MatchString(body) {
		t.Error("deferred Profile closure does not count all manifest rows")
	}
	if !regexp.MustCompile(`(?is)count\s*\(\s*distinct\s+[^)]+\)`).MatchString(body) {
		t.Error("deferred Profile closure does not count distinct manifest keys")
	}
	if comparisons := regexp.MustCompile(`(?is)(?:=|<>|!=|is\s+(?:not\s+)?distinct\s+from)\s*26\b`).FindAllString(body, -1); len(comparisons) < 2 {
		t.Errorf("deferred Profile closure has %d comparisons to the exact 26/26 cardinality, want at least two", len(comparisons))
	}
	if !regexp.MustCompile(`(?is)convert_to\s*\([^;]+?'utf8'\s*\)`).MatchString(body) ||
		!regexp.MustCompile(`(?is)(?:canonical_profile_manifest[^;]*(?:=|<>|!=|is\s+(?:not\s+)?distinct\s+from)|(?:=|<>|!=|is\s+(?:not\s+)?distinct\s+from)[^;]*canonical_profile_manifest)`).MatchString(body) {
		t.Error("deferred Profile closure does not byte-compare reconstructed UTF-8 with canonical_profile_manifest")
	}
	if regexp.MustCompile(`(?i)canonical_profile_manifest[^;\n]*jsonb|jsonb[^;\n]*canonical_profile_manifest|jsonb_each`).MatchString(body) {
		t.Error("deferred Profile closure must parse raw manifest as json and must not collapse duplicate keys through jsonb")
	}
}

func TestAssetCatalogCorrectiveRecomputesAuthorityDefinitionAndBindingDigestsInSQL(t *testing.T) {
	correctiveAssertDigestDataflowForms(t)
	up := readMigration(t, "000015_assets_catalog.up.sql")
	closure := correctiveRequireFunction(t, up, "public.validate_asset_source_revision_deferred_state")
	closureBody := correctiveNormalizeSQL(closure.body)
	correctiveRequireTokens(t, "deferred SQL digest closure", closureBody,
		"asset-source-authority-scope.v1",
		"asset-source-definition.v2",
		"public.asset_source_revision_authorities",
		"profile_manifest_sha256",
		"canonical_provider_schema_sha256",
		"public.asset_catalog_source_revision_binding_digest(",
		"collate \"c\"",
	)
	for label, expression := range map[string]string{
		"profile hash decoded to raw bytes":  `(?is)decode\s*\(\s*[a-z_][a-z0-9_]*\.profile_manifest_sha256\s*,\s*'hex'\s*\)`,
		"provider hash decoded to raw bytes": `(?is)decode\s*\(\s*[a-z_][a-z0-9_]*\.canonical_provider_schema_sha256\s*,\s*'hex'\s*\)`,
		"authority canonical UUID ordering":  `(?is)order\s+by\s+[a-z_][a-z0-9_]*\.environment_id\s*::\s*text\s+collate\s+"c"`,
	} {
		if !regexp.MustCompile(expression).MatchString(closure.body) {
			t.Errorf("deferred SQL digest closure missing %s", label)
		}
	}
	authorityFrames := correctiveDigestFramesByDomain(closure.body, "asset-source-authority-scope.v1")
	correctiveAssertExactFrames(t, "authority N+2 digest", authorityFrames, []string{
		`(?is)^(?:pg_catalog\.)?convert_to\(\s*'asset-source-authority-scope\.v1'\s*,\s*'utf8'\s*\)$`,
		`(?is)^(?:pg_catalog\.)?convert_to\(\s*(?:[a-z_][a-z0-9_]*|count\s*\(\s*\*\s*\))\s*::\s*text\s*,\s*'utf8'\s*\)$`,
		`(?is)^(?:pg_catalog\.)?convert_to\(\s*[a-z_][a-z0-9_]*\.environment_id\s*::\s*text\s*,\s*'utf8'\s*\)$`,
	})
	definitionFrames := correctiveDigestFramesByDomain(closure.body, "asset-source-definition.v2")
	correctiveAssertExactFrames(t, "SourceDefinitionDigest six-frame formula", definitionFrames, []string{
		`(?is)^(?:pg_catalog\.)?convert_to\(\s*'asset-source-definition\.v2'\s*,\s*'utf8'\s*\)$`,
		correctiveGenericFrameConversionPattern("source_kind"),
		correctiveGenericFrameConversionPattern("provider_kind"),
		correctiveGenericFrameConversionPattern("profile_code"),
		correctiveGenericFrameDecodePattern("profile_manifest_sha256"),
		correctiveGenericFrameDecodePattern("canonical_provider_schema_sha256"),
	})

	binding := correctiveRequireFunction(t, up, "public.asset_catalog_source_revision_binding_digest")
	correctiveAssertFunctionAttributes(t, "Source Revision binding digest", binding,
		"language plpgsql", "immutable", "parallel safe", "security invoker", "set search_path = pg_catalog, public, pg_temp")
	frames := correctiveDigestFramesByDomain(binding.body, "asset-source-revision-binding.v1")
	framePatterns := []string{
		`(?is)^(?:pg_catalog\.)?convert_to\(\s*'asset-source-revision-binding\.v1'\s*,\s*'utf8'\s*\)$`,
		correctiveFrameConversionPattern("candidate.tenant_id", false),
		correctiveFrameConversionPattern("candidate.workspace_id", false),
		correctiveFrameConversionPattern("candidate.source_id", false),
		correctiveFrameConversionPattern("candidate.revision", false),
		correctiveFrameDecodePattern("candidate.source_definition_digest", false),
		correctiveFrameConversionPattern("candidate.integration_id", true),
		correctiveFrameConversionPattern("candidate.sync_mode", false),
		correctiveFrameConversionPattern("candidate.credential_reference_id", true),
		correctiveFrameConversionPattern("candidate.trust_reference_id", true),
		correctiveFrameConversionPattern("candidate.network_policy_reference_id", true),
		correctiveFrameDecodePattern("candidate.authority_scope_digest", false),
		correctiveFrameConversionPattern("candidate.rate_limit_requests", false),
		correctiveFrameConversionPattern("candidate.rate_limit_window_seconds", false),
		correctiveFrameConversionPattern("candidate.backpressure_base_seconds", false),
		correctiveFrameConversionPattern("candidate.backpressure_max_seconds", false),
		correctiveFrameConversionPattern("candidate.profile_code", false),
		correctiveFrameConversionPattern("candidate.schedule_expression", true),
		correctiveFrameConversionPattern("candidate.typed_extension_code", true),
		correctiveFrameDecodePattern("candidate.prepared_extension_digest", true),
	}
	if len(frames) != len(framePatterns) {
		t.Errorf("binding digest frame count = %d, want exact %d including both terminal NULL frames", len(frames), len(framePatterns))
	} else {
		for index, expression := range framePatterns {
			if !regexp.MustCompile(expression).MatchString(frames[index]) {
				t.Errorf("BindingDigest frame %d has noncanonical expression %q", index+1, frames[index])
			}
		}
	}

	framer := correctiveRequireFunction(t, up, "public.asset_catalog_framed_value_v1")
	correctiveAssertFunctionAttributes(t, "SQL frame encoder", framer,
		"language plpgsql", "immutable", "parallel safe", "security invoker", "set search_path = pg_catalog, public, pg_temp")
	correctiveRequireTokens(t, "SQL frame encoder", correctiveNormalizeSQL(framer.body),
		"decode('00', 'hex')",
		"decode('01', 'hex')",
		"pg_catalog.int4send(pg_catalog.octet_length(candidate))",
	)
}

func TestAssetCatalogCorrectiveRejectsOpaqueReferenceAndTypedPairDrift(t *testing.T) {
	up := readMigration(t, "000015_assets_catalog.up.sql")
	opaque := correctiveRequireFunction(t, up, "public.asset_catalog_opaque_reference_valid")
	correctiveAssertFunctionAttributes(t, "opaque-reference validator", opaque,
		"language plpgsql", "immutable", "parallel safe", "security invoker", "set search_path = pg_catalog, public, pg_temp")
	if !strings.Contains(opaque.body, `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`) {
		t.Error("opaque-reference validator does not enforce the exact no-scheme/no-path grammar")
	}

	revisionTable := correctiveNormalizeSQL(correctiveRequireTable(t, up, "public.asset_source_revisions"))
	correctiveRequireTokens(t, "typed-extension nullable pair", revisionTable,
		"typed_extension_code text",
		"prepared_extension_digest text",
		"public.asset_catalog_sha256_valid(prepared_extension_digest)",
	)
	if !regexp.MustCompile(`(?is)\(\s*typed_extension_code\s+is\s+null\s*\)\s*=\s*\(\s*prepared_extension_digest\s+is\s+null\s*\)`).MatchString(revisionTable) {
		t.Error("typed_extension_code and prepared_extension_digest are not one exact nullable pair")
	}
	for _, reference := range []string{"credential_reference_id", "trust_reference_id", "network_policy_reference_id"} {
		if !strings.Contains(revisionTable, "public.asset_catalog_opaque_reference_valid("+reference+")") {
			t.Errorf("Source Revision %s does not use the dedicated opaque-reference validator", reference)
		}
	}
	relationshipTable := correctiveNormalizeSQL(correctiveRequireTable(t, up, "public.asset_relationships"))
	if !strings.Contains(relationshipTable, "public.asset_catalog_opaque_reference_valid(cross_environment_policy_reference_id)") {
		t.Error("cross_environment_policy_reference_id does not use the dedicated opaque-reference validator")
	}

	closure := correctiveNormalizeSQL(correctiveRequireFunction(t, up, "public.validate_asset_source_revision_deferred_state").body)
	correctiveRequireTokens(t, "typed-extension SourceKind matrix", closure,
		"'kubernetes_operator'",
		"typed_extension_code",
		"prepared_extension_digest",
		"profile_code",
	)
	if !regexp.MustCompile(`(?is)source_kind\s*=\s*'kubernetes_operator'.*?typed_extension_code\s*(?:=|<>|!=|is\s+(?:not\s+)?distinct\s+from)\s*[a-z_][a-z0-9_]*\.profile_code`).MatchString(closure) {
		t.Error("KUBERNETES_OPERATOR does not require the present typed-extension code to equal profile_code")
	}
	if !regexp.MustCompile(`(?is)source_kind\s*(?:<>|!=)\s*'kubernetes_operator'.*?typed_extension_code\s+is\s+not\s+null.{0,600}prepared_extension_digest\s+is\s+not\s+null`).MatchString(closure) {
		t.Error("non-KUBERNETES_OPERATOR kinds, including MANUAL and AWX, do not have an explicit NULL-pair rejection branch")
	}
}

func TestAssetCatalogCorrectiveFutureSourceInsertAndLiveStagesFailClosed(t *testing.T) {
	up := readMigration(t, "000015_assets_catalog.up.sql")
	hook := correctiveRequireFunction(t, up, "public.asset_catalog_future_source_gate_admitted")
	correctiveAssertFunctionAttributes(t, "future Source hook", hook,
		"language plpgsql", "stable", "security invoker", "set search_path = pg_catalog, public, pg_temp")
	if correctiveNormalizeSQL(hook.body) != "begin return false; end;" {
		t.Error("000015 future Source hook is not an exact default-false implementation")
	}

	mutation := correctiveNormalizeSQL(correctiveRequireFunction(t, up, "public.enforce_asset_sources_mutation").body)
	if got := strings.Count(mutation, "public.asset_catalog_future_source_gate_admitted(new)"); got != 1 {
		t.Errorf("live future Source hook call count = %d, want exactly one call on final NEW", got)
	}
	correctiveRequireTokens(t, "future Source live-stage branch", mutation,
		"new.source_kind in ('kubernetes_operator', 'awx_inventory')",
		"new.gate_status in ('validating', 'available', 'degraded')",
		"public.asset_catalog_future_source_gate_admitted(new) is not true",
		"current_setting('transaction_isolation')",
		"'serializable'",
	)
	hookCall := strings.Index(mutation, "public.asset_catalog_future_source_gate_admitted(new)")
	lastNormalization := strings.LastIndex(mutation, "new.validated_binding_digest := null")
	if hookCall < 0 || lastNormalization < 0 || hookCall <= lastNormalization {
		t.Error("future live-stage hook must run only after generic fail-close normalization has produced final NEW")
	}
	if hookCall >= 0 && regexp.MustCompile(`(?is)\bnew\.[a-z_][a-z0-9_]*\s*:=`).MatchString(mutation[hookCall:]) {
		t.Error("future live-stage hook must observe final NEW; no NEW assignment may follow the hook call")
	}
	if regexp.MustCompile(`(?is)gate_status\s+in\s*\([^)]*'unavailable'[^)]*\).{0,600}asset_catalog_future_source_gate_admitted`).MatchString(mutation) ||
		regexp.MustCompile(`(?is)gate_status\s+in\s*\([^)]*'suspended'[^)]*\).{0,600}asset_catalog_future_source_gate_admitted`).MatchString(mutation) {
		t.Error("UNAVAILABLE/SUSPENDED fail-close destinations must not depend on the successor hook")
	}

	deferred := correctiveNormalizeSQL(correctiveRequireFunction(t, up, "public.validate_asset_source_deferred_state").body)
	if got := strings.Count(deferred, "public.asset_catalog_future_source_gate_admitted(current_source)"); got != 1 {
		t.Errorf("deferred INSERT future Source hook call count = %d, want one call on reloaded current_source", got)
	}
	if strings.Contains(deferred, "asset_catalog_future_source_gate_admitted(new)") {
		t.Error("deferred INSERT closure must never call the hook with stale trigger NEW")
	}
	correctiveRequireTokens(t, "future Source initial INSERT closure", deferred,
		"tg_op = 'insert'",
		"from public.asset_sources",
		"current_source.version <> 2",
		"current_source.gate_status <> 'unavailable'",
		"current_source.gate_revision <> 0",
		"current_source.checkpoint_revision <> 0",
		"current_source.checkpoint_version <> 0",
		"current_source.published_revision is not null",
		"current_source.validated_run_id is not null",
		"current_source.checkpoint_ciphertext is not null",
		"revision = 1",
		"state = 'draft'",
		"expected_source_version = 1",
		"current_setting('transaction_isolation')",
		"'serializable'",
		"public.asset_catalog_future_source_gate_admitted(current_source) is not true",
	)
}

func TestAssetCatalogCorrectiveDownUsesOneShotNowaitAndDropsEveryDependency(t *testing.T) {
	downRaw := readMigration(t, "000015_assets_catalog.down.sql")
	down := correctiveNormalizeSQL(downRaw)
	down = strings.ReplaceAll(down, "timestamptz", "timestamp with time zone")
	locks := correctiveDownLockStatements(downRaw)
	if len(locks) != 1 {
		t.Errorf("down LOCK TABLE statement count = %d, want exactly one", len(locks))
	} else {
		want := "lock table public.tenants, public.workspaces, public.environments, public.integrations, public.services, public.service_bindings, public.audit_records, public.outbox_events, public.asset_sources, public.asset_source_revisions, public.asset_source_revision_authorities, public.asset_source_runs, public.asset_observations, public.assets, public.asset_type_details, public.asset_conflicts, public.asset_relationships, public.service_asset_bindings in access exclusive mode nowait;"
		if locks[0] != want {
			t.Errorf("down one-shot lock = %q, want exact 18-relation NOWAIT lock", locks[0])
		}
	}
	if strings.Contains(down, " cascade") {
		t.Error("down migration must not use CASCADE")
	}

	assertExactSQLObjectSet(t, "down dropped trigger manifest", correctiveDroppedTriggerIdentities(downRaw), correctiveExpectedDroppedTriggerIdentities())
	assertExactSQLObjectSet(t, "down dropped routine manifest", correctiveDroppedRoutineIdentities(downRaw), correctiveExpectedRoutineIdentities())
	correctiveAssertOrdered(t, "cycle-breaking foreign keys", down, []string{
		"drop constraint asset_sources_published_revision_fk",
		"drop constraint asset_sources_validated_run_fk",
		"drop constraint asset_sources_last_success_run_fk",
		"drop constraint asset_sources_last_complete_snapshot_run_fk",
		"drop constraint asset_source_revisions_validation_run_fk",
	})
	correctiveAssertBefore(t,
		"drop constraint asset_source_revisions_validation_run_fk",
		"drop function public.asset_catalog_source_run_terminal_digest(public.asset_source_runs, text, text)",
		down,
	)
	for _, dependency := range []struct {
		function string
		table    string
	}{
		{"drop function public.asset_catalog_source_run_terminal_digest(public.asset_source_runs, text, text)", "drop table public.asset_source_runs"},
		{"drop function public.asset_catalog_source_run_failure_override_digest(public.asset_source_runs, text)", "drop table public.asset_source_runs"},
		{"drop function public.asset_catalog_source_run_delay_intent_digest(public.asset_source_runs, text, timestamp with time zone)", "drop table public.asset_source_runs"},
		{"drop function public.asset_catalog_source_run_no_credential_digest(public.asset_source_runs)", "drop table public.asset_source_runs"},
		{"drop function public.asset_catalog_source_revision_binding_digest(public.asset_source_revisions)", "drop table public.asset_source_revisions"},
		{"drop function public.asset_catalog_future_source_gate_admitted(public.asset_sources)", "drop table public.asset_sources"},
	} {
		correctiveAssertBefore(t, dependency.function, dependency.table, down)
	}
	correctiveAssertOrdered(t, "child-first ten-table drop order", down, []string{
		"drop table public.service_asset_bindings",
		"drop table public.asset_relationships",
		"drop table public.asset_conflicts",
		"drop table public.asset_type_details",
		"drop table public.assets",
		"drop table public.asset_observations",
		"drop table public.asset_source_runs",
		"drop table public.asset_source_revision_authorities",
		"drop table public.asset_source_revisions",
		"drop table public.asset_sources",
	})
	correctiveAssertBefore(t, "drop table public.asset_sources", "drop function public.asset_catalog_opaque_reference_valid(text)", down)
}

func TestAssetCatalogCorrectiveManualProfileLiteralAndSQLParity(t *testing.T) {
	correctiveAssertLiteralDigest(t, "MANUAL Profile manifest", correctiveManualProfileManifestV1, 794,
		"57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96")
	correctiveAssertLiteralDigest(t, "MANUAL Provider schema", correctiveManualProviderSchemaV1, 62,
		"99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa")

	up := readMigration(t, "000015_assets_catalog.up.sql")
	closure := correctiveRequireFunction(t, up, "public.validate_asset_source_revision_deferred_state")
	body := correctiveStripSQLComments(closure.body)
	if strings.Count(body, correctiveManualProfileManifestV1) != 1 {
		t.Error("deferred MANUAL closure must embed the exact 794-byte Profile manifest once as executable SQL")
	}
	if strings.Count(body, correctiveManualProviderSchemaV1) != 1 {
		t.Error("deferred MANUAL closure must embed the exact 62-byte Provider schema once as executable SQL")
	}
	normalizedBody := correctiveNormalizeSQL(body)
	correctiveRequireTokens(t, "MANUAL SQL parity closure", normalizedBody,
		"57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96",
		"99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa",
		"7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c",
		"asset-source-definition.v2",
		"profile_manifest_sha256",
		"canonical_provider_schema_sha256",
		"source_kind",
		"provider_kind",
		"profile_code",
		"sync_mode",
		"rate_limit_requests",
		"rate_limit_window_seconds",
		"backpressure_base_seconds",
		"backpressure_max_seconds",
		"integration_id is not null",
		"credential_reference_id is not null",
		"trust_reference_id is not null",
		"network_policy_reference_id is not null",
		"schedule_expression is not null",
		"typed_extension_code is not null",
		"prepared_extension_digest is not null",
	)
	for field, literal := range map[string]string{
		"source_kind":   "manual",
		"provider_kind": "manual_v1",
		"profile_code":  "manual_v1",
		"sync_mode":     "manual",
	} {
		expression := `(?is)\b` + regexp.QuoteMeta(field) + `\b\s*(?:=|<>|!=|is\s+(?:not\s+)?distinct\s+from)\s*'` + regexp.QuoteMeta(literal) + `'`
		if !regexp.MustCompile(expression).MatchString(normalizedBody) {
			t.Errorf("MANUAL SQL parity closure does not compare %s with exact %q", field, strings.ToUpper(literal))
		}
	}
	for _, field := range []string{
		"rate_limit_requests", "rate_limit_window_seconds", "backpressure_base_seconds", "backpressure_max_seconds",
	} {
		expression := `(?is)\b` + regexp.QuoteMeta(field) + `\b\s*(?:=|<>|!=|is\s+(?:not\s+)?distinct\s+from)\s*1\b`
		if !regexp.MustCompile(expression).MatchString(normalizedBody) {
			t.Errorf("MANUAL SQL parity closure does not compare %s with exact 1", field)
		}
	}
	if !regexp.MustCompile(`(?is)\bauthority[a-z0-9_]*\b\s*(?:=|<>|!=|is\s+(?:not\s+)?distinct\s+from)\s*1\b`).MatchString(normalizedBody) {
		t.Error("MANUAL SQL parity closure does not require exactly one authority row")
	}
	for label, literal := range map[string]string{
		"Profile manifest literal": correctiveManualProfileManifestV1,
		"Provider schema literal":  correctiveManualProviderSchemaV1,
		"Profile manifest SHA":     "57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96",
		"Provider schema SHA":      "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa",
		"definition digest":        "7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c",
	} {
		if !correctiveLiteralComparedInStatement(body, literal) {
			t.Errorf("MANUAL SQL parity closure embeds %s but never compares it", label)
		}
	}
	if !regexp.MustCompile(`(?is)octet_length\s*\(\s*[a-z_][a-z0-9_]*\.canonical_profile_manifest\s*\)\s*(?:<>|!=)\s*794`).MatchString(body) {
		t.Error("MANUAL SQL parity closure does not byte-check the 794-byte Profile manifest")
	}
	if !regexp.MustCompile(`(?is)octet_length\s*\(\s*[a-z_][a-z0-9_]*\.canonical_provider_schema\s*\)\s*(?:<>|!=)\s*62`).MatchString(body) {
		t.Error("MANUAL SQL parity closure does not byte-check the 62-byte Provider schema")
	}
}

func TestAssetCatalogCorrectiveEnforcesDatabaseRoleSeparation(t *testing.T) {
	up := correctiveNormalizeSQL(readMigration(t, "000015_assets_catalog.up.sql"))
	for _, role := range correctiveBaseDatabaseRoles() {
		if !strings.Contains(up, role) {
			t.Errorf("up migration does not preflight or grant the reviewed base role %q", role)
		}
	}
	correctiveRequireTokens(t, "migration role boundary", up,
		"set local role aiops_schema_owner",
		"reset role",
		"to aiops_control_plane_runtime",
	)
	if !regexp.MustCompile(`(?is)revoke\s+(?:all|execute)\s+on\s+function\b.+?\s+from\s+public`).MatchString(up) {
		t.Error("migration does not revoke PUBLIC function execution with one reviewed REVOKE form")
	}
	if !regexp.MustCompile(`(?is)grant\s+execute\s+on\s+function\b.+?\s+to\s+aiops_control_plane_runtime`).MatchString(up) {
		t.Error("migration does not grant the reviewed pure-function surface to the runtime role")
	}

	production := correctiveReadSubstantiveArtifact(t, "internal/store/postgres/database_role_admission.go", 1024)
	correctiveAssertDatabaseRoleAdmissionAPI(t, "internal/store/postgres/database_role_admission.go", production)
	productionNormalized := correctiveNormalizeSource(production)
	correctiveRequireTokens(t, "database role admission production interface", productionNormalized,
		"trustedschema",
		"session_user",
		"current_user",
		"pg_catalog.aclexplode",
		"pg_catalog.acldefault",
		"pg_auth_members",
		"rolsuper",
		"rolcreatedb",
		"rolcreaterole",
		"rolreplication",
		"rolbypassrls",
		"rolcanlogin",
		"rolinherit",
	)
	for _, role := range correctiveBaseDatabaseRoles() {
		if !strings.Contains(productionNormalized, role) {
			t.Errorf("database role admission production interface omits exact role %q", role)
		}
	}

	roleTests := correctiveReadSubstantiveArtifact(t, "internal/store/postgres/database_role_admission_test.go", 512)
	correctiveAssertDatabaseRoleAdmissionTests(t, "internal/store/postgres/database_role_admission_test.go", roleTests)
	roleTestsNormalized := correctiveNormalizeSource(roleTests)
	correctiveRequireTokens(t, "database role admission negative suite", roleTestsNormalized,
		"migration",
		"application",
		"distinct",
	)
	for _, role := range correctiveBaseDatabaseRoles() {
		if !strings.Contains(roleTestsNormalized, role) {
			t.Errorf("database role admission tests do not independently pin role %q", role)
		}
	}

	runbook := correctiveReadSubstantiveArtifact(t, "docs/operations/database-role-bootstrap.md", 512)
	runbookNormalized := correctiveNormalizeSource(runbook)
	correctiveRequireTokens(t, "database role bootstrap runbook", runbookNormalized,
		"migration", "application", "dsn", "noinherit", "nologin", "connect", "temp", "create")
	for _, role := range correctiveBaseDatabaseRoles() {
		if !strings.Contains(runbookNormalized, role) {
			t.Errorf("database role bootstrap runbook omits role %q", role)
		}
	}

	ci := correctiveReadSubstantiveArtifact(t, ".github/workflows/ci.yml", 512)
	ciNormalized := correctiveNormalizeSource(ci)
	for _, role := range correctiveBaseDatabaseRoles() {
		if !strings.Contains(ciNormalized, role) {
			t.Errorf("CI role fixture omits role %q", role)
		}
	}
	makefile := correctiveReadSubstantiveArtifact(t, "Makefile", 256)
	makefileNormalized := correctiveNormalizeSource(makefile)
	correctiveRequireTokens(t, "integration target", makefileNormalized,
		"test-integration:", "./internal/store/postgres", "./internal/assetcatalog/postgres")
}

func correctiveAssertDatabaseRoleAdmissionAPI(t *testing.T, filename, source string) {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		t.Errorf("parse database role admission production interface: %v", err)
		return
	}

	typeFound := false
	constructorFound := false
	checkFound := false
	for _, declaration := range parsed.Decls {
		switch candidate := declaration.(type) {
		case *ast.GenDecl:
			for _, specification := range candidate.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != "DatabaseRoleAdmission" {
					continue
				}
				_, typeFound = typeSpec.Type.(*ast.StructType)
			}
		case *ast.FuncDecl:
			switch candidate.Name.Name {
			case "NewDatabaseRoleAdmission":
				constructorFound = candidate.Recv == nil &&
					correctiveFieldCount(candidate.Type.Params) == 2 &&
					correctiveLastParameterIsString(candidate.Type.Params) &&
					correctiveSinglePointerResult(candidate.Type.Results, "DatabaseRoleAdmission")
			case "Check":
				checkFound = correctivePointerReceiver(candidate.Recv, "DatabaseRoleAdmission") &&
					correctiveSingleSelectorParameter(candidate.Type.Params, "context", "Context", false) &&
					correctiveSingleIdentResult(candidate.Type.Results, "error")
			}
		}
	}
	if !typeFound {
		t.Error("database role admission must expose type DatabaseRoleAdmission struct")
	}
	if !constructorFound {
		t.Error("database role admission must expose NewDatabaseRoleAdmission(database, trustedSchema string) *DatabaseRoleAdmission")
	}
	if !checkFound {
		t.Error("database role admission must expose (*DatabaseRoleAdmission).Check(context.Context) error")
	}
}

func correctiveAssertDatabaseRoleAdmissionTests(t *testing.T, filename, source string) {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		t.Errorf("parse database role admission tests: %v", err)
		return
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "TestDatabaseRoleAdmission") {
			continue
		}
		if correctiveSingleSelectorParameter(function.Type.Params, "testing", "T", true) &&
			correctiveFieldCount(function.Type.Results) == 0 {
			return
		}
	}
	t.Error("database role admission suite must expose at least one TestDatabaseRoleAdmission*(t *testing.T) test")
}

func correctiveFieldCount(fields *ast.FieldList) int {
	if fields == nil {
		return 0
	}
	count := 0
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			count++
			continue
		}
		count += len(field.Names)
	}
	return count
}

func correctiveLastParameterIsString(fields *ast.FieldList) bool {
	if fields == nil || len(fields.List) == 0 {
		return false
	}
	identifier, ok := fields.List[len(fields.List)-1].Type.(*ast.Ident)
	return ok && identifier.Name == "string"
}

func correctiveSinglePointerResult(fields *ast.FieldList, typeName string) bool {
	if correctiveFieldCount(fields) != 1 || fields == nil || len(fields.List) != 1 {
		return false
	}
	pointer, ok := fields.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	identifier, ok := pointer.X.(*ast.Ident)
	return ok && identifier.Name == typeName
}

func correctiveSingleIdentResult(fields *ast.FieldList, typeName string) bool {
	if correctiveFieldCount(fields) != 1 || fields == nil || len(fields.List) != 1 {
		return false
	}
	identifier, ok := fields.List[0].Type.(*ast.Ident)
	return ok && identifier.Name == typeName
}

func correctivePointerReceiver(fields *ast.FieldList, typeName string) bool {
	if correctiveFieldCount(fields) != 1 || fields == nil || len(fields.List) != 1 {
		return false
	}
	pointer, ok := fields.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	identifier, ok := pointer.X.(*ast.Ident)
	return ok && identifier.Name == typeName
}

func correctiveSingleSelectorParameter(fields *ast.FieldList, packageName, typeName string, pointerRequired bool) bool {
	if correctiveFieldCount(fields) != 1 || fields == nil || len(fields.List) != 1 {
		return false
	}
	expression := fields.List[0].Type
	if pointerRequired {
		pointer, ok := expression.(*ast.StarExpr)
		if !ok {
			return false
		}
		expression = pointer.X
	} else if _, isPointer := expression.(*ast.StarExpr); isPointer {
		return false
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != typeName {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Name == packageName
}

type correctiveFunction struct {
	full       string
	body       string
	attributes string
}

const correctiveSQLIdentifierPattern = `(?:"(?:""|[^"])+"|[a-z_][a-z0-9_$]*)`

func correctiveQualifiedSQLIdentifierPattern() string {
	return correctiveSQLIdentifierPattern + `(?:\s*\.\s*` + correctiveSQLIdentifierPattern + `)?`
}

func correctiveCanonicalSQLIdentifier(raw string) string {
	parts := make([]string, 0, 2)
	start := 0
	inQuotes := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			if inQuotes && index+1 < len(raw) && raw[index+1] == '"' {
				index++
				continue
			}
			inQuotes = !inQuotes
		case '.':
			if !inQuotes {
				parts = append(parts, raw[start:index])
				start = index + 1
			}
		}
	}
	parts = append(parts, raw[start:])
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) >= 2 && part[0] == '"' && part[len(part)-1] == '"' {
			value := strings.ReplaceAll(part[1:len(part)-1], `""`, `"`)
			if regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`).MatchString(value) {
				parts[index] = value
			} else {
				parts[index] = `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
			}
			continue
		}
		parts[index] = strings.ToLower(part)
	}
	return strings.Join(parts, ".")
}

func correctiveTopLevelSQLStatements(sql string) []string {
	statements := make([]string, 0, 64)
	var statement strings.Builder
	statement.Grow(1024)
	inSingleQuote := false
	singleQuoteBackslashEscapes := false
	inDoubleQuote := false
	lineComment := false
	blockCommentDepth := 0
	dollarTag := ""
	for index := 0; index < len(sql); index++ {
		character := sql[index]
		if lineComment {
			if character == '\n' {
				lineComment = false
				statement.WriteByte('\n')
			} else {
				statement.WriteByte(' ')
			}
			continue
		}
		if blockCommentDepth > 0 {
			switch {
			case character == '/' && index+1 < len(sql) && sql[index+1] == '*':
				blockCommentDepth++
				statement.WriteString("  ")
				index++
			case character == '*' && index+1 < len(sql) && sql[index+1] == '/':
				blockCommentDepth--
				statement.WriteString("  ")
				index++
			case character == '\n':
				statement.WriteByte('\n')
			default:
				statement.WriteByte(' ')
			}
			continue
		}
		if dollarTag != "" {
			if strings.HasPrefix(sql[index:], dollarTag) {
				statement.WriteString(dollarTag)
				index += len(dollarTag) - 1
				dollarTag = ""
			} else {
				statement.WriteByte(character)
			}
			continue
		}
		if inSingleQuote {
			statement.WriteByte(character)
			if singleQuoteBackslashEscapes && character == '\\' && index+1 < len(sql) {
				statement.WriteByte(sql[index+1])
				index++
			} else if character == '\'' && index+1 < len(sql) && sql[index+1] == '\'' {
				statement.WriteByte(sql[index+1])
				index++
			} else if character == '\'' {
				inSingleQuote = false
				singleQuoteBackslashEscapes = false
			}
			continue
		}
		if inDoubleQuote {
			statement.WriteByte(character)
			if character == '"' && index+1 < len(sql) && sql[index+1] == '"' {
				statement.WriteByte(sql[index+1])
				index++
			} else if character == '"' {
				inDoubleQuote = false
			}
			continue
		}
		switch {
		case character == '-' && index+1 < len(sql) && sql[index+1] == '-':
			lineComment = true
			statement.WriteString("  ")
			index++
		case character == '/' && index+1 < len(sql) && sql[index+1] == '*':
			blockCommentDepth = 1
			statement.WriteString("  ")
			index++
		case character == '\'':
			inSingleQuote = true
			singleQuoteBackslashEscapes = correctiveEscapeStringPrefix(sql, index)
			statement.WriteByte(character)
		case character == '"':
			inDoubleQuote = true
			statement.WriteByte(character)
		case character == '$':
			tag := correctiveDollarQuoteTag(sql[index:])
			if tag == "" {
				statement.WriteByte(character)
				continue
			}
			dollarTag = tag
			statement.WriteString(tag)
			index += len(tag) - 1
		case character == ';':
			statement.WriteByte(character)
			if text := strings.TrimSpace(statement.String()); text != "" {
				statements = append(statements, text)
			}
			statement.Reset()
		default:
			statement.WriteByte(character)
		}
	}
	if text := strings.TrimSpace(statement.String()); text != "" {
		statements = append(statements, text)
	}
	return statements
}

func correctiveDollarQuoteTag(value string) string {
	if strings.HasPrefix(value, "$$") {
		return "$$"
	}
	if len(value) < 3 || value[0] != '$' || !((value[1] >= 'A' && value[1] <= 'Z') ||
		(value[1] >= 'a' && value[1] <= 'z') || value[1] == '_') {
		return ""
	}
	for index := 2; index < len(value); index++ {
		character := value[index]
		if character == '$' {
			return value[:index+1]
		}
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_') {
			return ""
		}
	}
	return ""
}

func correctiveEscapeStringPrefix(sql string, quote int) bool {
	if quote < 1 || (sql[quote-1] != 'e' && sql[quote-1] != 'E') {
		return false
	}
	if quote == 1 {
		return true
	}
	previous := sql[quote-2]
	return !((previous >= 'A' && previous <= 'Z') || (previous >= 'a' && previous <= 'z') ||
		(previous >= '0' && previous <= '9') || previous == '_' || previous == '$')
}

func correctiveAssertTopLevelParserSemantics(t *testing.T) {
	t.Helper()
	fixture := `
CREATE FUNCTION public.real() RETURNS boolean AS $body$
BEGIN
    PERFORM 'CREATE FUNCTION public.string_fake() RETURNS boolean';
    PERFORM 'CREATE TABLE public.body_fake(id integer)';
    RETURN false;
END;
$body$ LANGUAGE plpgsql;
SELECT 'CREATE FUNCTION public.top_string_fake() RETURNS boolean';
SELECT '\';
CREATE FUNCTION public.after_backslash() RETURNS boolean AS $$ BEGIN RETURN false; END; $$ LANGUAGE plpgsql;
CREATE FUNCTION public."QuotedExtra"() RETURNS boolean AS $$ BEGIN RETURN false; END; $$ LANGUAGE plpgsql;
CREATE TABLE public."QuotedTable" (id integer);
CREATE TRIGGER "QuotedTrigger" AFTER INSERT ON public."QuotedTable"
FOR EACH ROW EXECUTE PROCEDURE public.real();
CREATE OR REPLACE TRIGGER "QuotedTrigger2" AFTER UPDATE ON public."QuotedTable"
FOR EACH ROW EXECUTE FUNCTION public.real();`
	assertExactSQLObjectSet(t, "top-level routine lexer fixture", correctiveRoutineIdentities(fixture), []string{
		"public.real()", "public.after_backslash()", `public."QuotedExtra"()`,
	})
	assertExactSQLObjectSet(t, "top-level table lexer fixture", createdTableIdentities(fixture), []string{`public."QuotedTable"`})
	assertExactSQLObjectSet(t, "EXECUTE PROCEDURE trigger lexer fixture", correctiveTriggerIdentities(t, fixture), []string{
		correctiveTriggerIdentity(`public."QuotedTable"`, `"QuotedTrigger"`, false, "after", []string{"insert"}, "row", false, "procedure:public.real"),
		correctiveTriggerIdentity(`public."QuotedTable"`, `"QuotedTrigger2"`, false, "after", []string{"update"}, "row", false, "public.real"),
	})
}

func correctiveRequireFunction(t *testing.T, sql, qualifiedName string) correctiveFunction {
	t.Helper()
	definition, ok := correctiveFunctionDefinition(sql, qualifiedName)
	if !ok {
		t.Errorf("migration does not define function %s", qualifiedName)
	}
	return definition
}

func correctiveFunctionDefinition(sql, qualifiedName string) (correctiveFunction, bool) {
	pattern := regexp.MustCompile(`(?is)^\s*create\s+(?:or\s+replace\s+)?function\s+(` +
		correctiveQualifiedSQLIdentifierPattern() + `)\s*\(`)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		location := pattern.FindStringSubmatchIndex(statement)
		if location == nil || correctiveCanonicalSQLIdentifier(statement[location[2]:location[3]]) != strings.ToLower(qualifiedName) {
			continue
		}
		open := location[1] - 1
		close := correctiveMatchingParen(statement, open)
		if close < 0 {
			return correctiveFunction{}, false
		}
		tail := statement[close+1:]
		dollarPattern := regexp.MustCompile(`(?is)\bas\s+(\$[a-z_][a-z0-9_]*\$|\$\$)`)
		dollarLocation := dollarPattern.FindStringSubmatchIndex(strings.ToLower(tail))
		if dollarLocation == nil {
			return correctiveFunction{}, false
		}
		tag := tail[dollarLocation[2]:dollarLocation[3]]
		bodyStart := close + 1 + dollarLocation[1]
		bodyEndRelative := strings.Index(statement[bodyStart:], tag)
		if bodyEndRelative < 0 {
			return correctiveFunction{}, false
		}
		bodyEnd := bodyStart + bodyEndRelative
		attributeStart := bodyEnd + len(tag)
		return correctiveFunction{
			full:       statement,
			body:       correctiveStripSQLComments(statement[bodyStart:bodyEnd]),
			attributes: statement[attributeStart:],
		}, true
	}
	return correctiveFunction{}, false
}

func correctiveAssertFunctionAttributes(t *testing.T, label string, function correctiveFunction, required ...string) {
	t.Helper()
	attributes := correctiveNormalizeSQL(function.attributes)
	correctiveRequireTokens(t, label+" attributes", attributes, required...)
	if strings.Contains(attributes, "security definer") {
		t.Errorf("%s must not be SECURITY DEFINER", label)
	}
}

func correctiveRoutineIdentities(sql string) []string {
	pattern := regexp.MustCompile(`(?is)^\s*create\s+(?:or\s+replace\s+)?function\s+(` +
		correctiveQualifiedSQLIdentifierPattern() + `)\s*\(`)
	return correctiveRoutineIdentitiesFromStatements(sql, pattern)
}

func correctiveDroppedRoutineIdentities(sql string) []string {
	pattern := regexp.MustCompile(`(?is)^\s*drop\s+function\s+(` + correctiveQualifiedSQLIdentifierPattern() + `)\s*\(`)
	return correctiveRoutineIdentitiesFromStatements(sql, pattern)
}

func correctiveRoutineIdentitiesFromStatements(sql string, pattern *regexp.Regexp) []string {
	identities := make([]string, 0, 35)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		match := pattern.FindStringSubmatchIndex(statement)
		if match == nil {
			continue
		}
		open := match[1] - 1
		close := correctiveMatchingParen(statement, open)
		name := correctiveCanonicalSQLIdentifier(statement[match[2]:match[3]])
		if close < 0 {
			identities = append(identities, name+"(<unclosed>)")
			continue
		}
		arguments := correctiveSplitSQLArguments(statement[open+1 : close])
		types := make([]string, 0, len(arguments))
		for _, argument := range arguments {
			if strings.TrimSpace(argument) != "" {
				types = append(types, correctiveCanonicalArgumentType(argument))
			}
		}
		identities = append(identities, name+"("+strings.Join(types, ",")+")")
	}
	return identities
}

func correctiveExpectedRoutineIdentities() []string {
	return []string{
		"public.asset_catalog_text_valid(text,integer)",
		"public.asset_catalog_code_valid(text,integer)",
		"public.asset_catalog_sha256_valid(text)",
		"public.asset_catalog_provider_kind_valid(text)",
		"public.asset_catalog_idempotency_key_valid(text)",
		"public.asset_catalog_json_object_valid(bytea,integer,integer)",
		"public.asset_catalog_labels_valid(jsonb)",
		"public.asset_catalog_checkpoint_envelope_valid(bytea)",
		"public.asset_catalog_field_provenance_valid(bytea)",
		"public.asset_catalog_framed_value_v1(bytea)",
		"public.asset_catalog_source_run_no_credential_digest(public.asset_source_runs)",
		"public.asset_catalog_source_run_delay_intent_digest(public.asset_source_runs,text,timestamp with time zone)",
		"public.asset_catalog_source_run_failure_override_digest(public.asset_source_runs,text)",
		"public.asset_catalog_source_run_terminal_digest(public.asset_source_runs,text,text)",
		"public.asset_catalog_opaque_reference_valid(text)",
		"public.asset_catalog_future_source_gate_admitted(public.asset_sources)",
		"public.asset_catalog_source_revision_binding_digest(public.asset_source_revisions)",
		"public.validate_asset_management_audit_insert()",
		"public.reject_asset_catalog_immutable()",
		"public.reject_asset_catalog_delete()",
		"public.reject_asset_catalog_truncate()",
		"public.enforce_assets_transition()",
		"public.enforce_asset_conflict_transition()",
		"public.enforce_asset_catalog_edge_mutation()",
		"public.enforce_asset_relationship_mutation()",
		"public.validate_asset_relationship_page_closure()",
		"public.enforce_asset_sources_mutation()",
		"public.validate_asset_source_deferred_state()",
		"public.enforce_asset_source_revision_transition()",
		"public.validate_asset_source_revision_deferred_state()",
		"public.enforce_asset_source_run_mutation()",
		"public.validate_asset_source_run_page_closure()",
		"public.validate_asset_source_run_terminal_closure()",
		"public.enforce_asset_observation_admission()",
		"public.validate_asset_observation_page_closure()",
	}
}

func correctiveCanonicalArgumentType(argument string) string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(argument)))
	if len(fields) == 0 {
		return ""
	}
	for index, field := range fields {
		if field == "default" || field == "=" {
			fields = fields[:index]
			break
		}
	}
	if len(fields) == 0 {
		return ""
	}
	if fields[0] == "in" || fields[0] == "out" || fields[0] == "inout" || fields[0] == "variadic" {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return ""
	}
	if len(fields) > 1 && !correctiveStartsWithType(fields[0]) {
		fields = fields[1:]
	}
	typeName := strings.Join(fields, " ")
	switch typeName {
	case "timestamptz", "pg_catalog.timestamptz", "pg_catalog.timestamp with time zone":
		return "timestamp with time zone"
	case "int4", "pg_catalog.int4", "pg_catalog.integer":
		return "integer"
	case "pg_catalog.text":
		return "text"
	case "pg_catalog.bytea":
		return "bytea"
	case "pg_catalog.jsonb":
		return "jsonb"
	default:
		return typeName
	}
}

func correctiveStartsWithType(token string) bool {
	if strings.HasPrefix(token, "public.") || strings.HasPrefix(token, "pg_catalog.") {
		return true
	}
	switch token {
	case "text", "integer", "int4", "bytea", "jsonb", "timestamptz", "timestamp":
		return true
	default:
		return false
	}
}

func correctiveSplitSQLArguments(arguments string) []string {
	if strings.TrimSpace(arguments) == "" {
		return nil
	}
	parts := make([]string, 0, 4)
	start, depth := 0, 0
	inSingleQuote, inDoubleQuote := false, false
	for index := 0; index < len(arguments); index++ {
		character := arguments[index]
		if inSingleQuote {
			if character == '\'' && index+1 < len(arguments) && arguments[index+1] == '\'' {
				index++
			} else if character == '\'' {
				inSingleQuote = false
			}
			continue
		}
		if inDoubleQuote {
			if character == '"' {
				inDoubleQuote = false
			}
			continue
		}
		switch character {
		case '\'':
			inSingleQuote = true
		case '"':
			inDoubleQuote = true
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, arguments[start:index])
				start = index + 1
			}
		}
	}
	parts = append(parts, arguments[start:])
	return parts
}

func correctiveFramedArguments(sql string) []string {
	const call = "public.asset_catalog_framed_value_v1("
	arguments := make([]string, 0, 20)
	for offset := 0; offset < len(sql); {
		relative := strings.Index(sql[offset:], call)
		if relative < 0 {
			break
		}
		open := offset + relative + len(call) - 1
		close := correctiveMatchingParen(sql, open)
		if close < 0 {
			arguments = append(arguments, "<unclosed>")
			break
		}
		arguments = append(arguments, strings.TrimSpace(sql[open+1:close]))
		offset = close + 1
	}
	return arguments
}

func correctiveDigestFramesByDomain(body, domain string) []string {
	for _, frames := range correctiveDigestFrameCandidates(correctiveNormalizeSQL(body)) {
		if len(frames) > 0 && strings.Contains(frames[0], "'"+strings.ToLower(domain)+"'") {
			return frames
		}
	}
	return nil
}

func correctiveAssertDigestDataflowForms(t *testing.T) {
	t.Helper()
	qualifiedFixture := `
DECLARE
    frame_a bytea := public.asset_catalog_framed_value_v1(pg_catalog.convert_to('dataflow.v1','UTF8'));
    frame_b bytea;
    frame_c bytea;
    digest_input bytea := frame_a;
BEGIN
    SELECT public.asset_catalog_framed_value_v1(pg_catalog.convert_to('select-into','UTF8')) INTO frame_b;
    frame_c = public.asset_catalog_framed_value_v1(pg_catalog.convert_to('equals-assignment','UTF8'));
    digest_input := digest_input || frame_b;
    digest_input = digest_input || frame_c;
    RETURN pg_catalog.encode(pg_catalog.sha256(digest_input),'hex');
END;`
	correctiveAssertExactFrames(t, "qualified core sha256 dataflow lexer fixture",
		correctiveDigestFramesByDomain(qualifiedFixture, "dataflow.v1"), []string{
			`(?is)^(?:pg_catalog\.)?convert_to\(\s*'dataflow\.v1'\s*,\s*'utf8'\s*\)$`,
			`(?is)^(?:pg_catalog\.)?convert_to\(\s*'select-into'\s*,\s*'utf8'\s*\)$`,
			`(?is)^(?:pg_catalog\.)?convert_to\(\s*'equals-assignment'\s*,\s*'utf8'\s*\)$`,
		})

	unqualifiedFixture := `
BEGIN
    RETURN pg_catalog.encode(sha256(
        public.asset_catalog_framed_value_v1(pg_catalog.convert_to('direct-dataflow.v1','UTF8')) ||
        public.asset_catalog_framed_value_v1(pg_catalog.convert_to('direct-frame','UTF8'))
    ),'hex');
END;`
	correctiveAssertExactFrames(t, "unqualified core sha256 direct-expression lexer fixture",
		correctiveDigestFramesByDomain(unqualifiedFixture, "direct-dataflow.v1"), []string{
			`(?is)^(?:pg_catalog\.)?convert_to\(\s*'direct-dataflow\.v1'\s*,\s*'utf8'\s*\)$`,
			`(?is)^(?:pg_catalog\.)?convert_to\(\s*'direct-frame'\s*,\s*'utf8'\s*\)$`,
		})

	pgcryptoFixture := `
BEGIN
    RETURN pg_catalog.encode(public.digest(
        public.asset_catalog_framed_value_v1(pg_catalog.convert_to('pgcrypto-must-not-match.v1','UTF8')),
        'sha256'
    ),'hex');
END;`
	if got := correctiveDigestFramesByDomain(pgcryptoFixture, "pgcrypto-must-not-match.v1"); len(got) != 0 {
		t.Fatalf("digest dataflow lexer accepted pgcrypto digest instead of PostgreSQL 18 core sha256: %v", got)
	}

	nonCodeFixtures := map[string]string{
		"ordinary string":      `'pg_catalog.sha256(public.asset_catalog_framed_value_v1(candidate))'`,
		"escape string":        `E'pg_catalog.sha256(public.asset_catalog_framed_value_v1(candidate))'`,
		"dollar string":        `$fake$pg_catalog.sha256(public.asset_catalog_framed_value_v1(candidate))$fake$`,
		"quoted identifier":    `"sha256"(public.asset_catalog_framed_value_v1(candidate))`,
		"line comment":         "-- pg_catalog.sha256(public.asset_catalog_framed_value_v1(candidate))\nRETURN NULL",
		"nested block comment": `/* outer /* pg_catalog.sha256(public.asset_catalog_framed_value_v1(candidate)) */ outer */ RETURN NULL`,
	}
	for label, fixture := range nonCodeFixtures {
		if got := correctiveDigestInputs(fixture); len(got) != 0 {
			t.Errorf("digest dataflow lexer accepted sha256 call from %s: %v", label, got)
		}
	}
}

func correctiveDigestFrameCandidates(body string) [][]string {
	environment := make(map[string]string)
	candidates := make([][]string, 0, 3)
	for _, statement := range correctiveTopLevelSQLStatements(body) {
		statement = strings.TrimSuffix(strings.TrimSpace(statement), ";")
		target, expression, assigned := correctivePLpgSQLAssignment(statement)
		if assigned {
			expression = correctiveExpandReviewedVariables(expression, environment)
		} else {
			expression = correctiveExpandReviewedVariables(statement, environment)
		}
		for _, input := range correctiveDigestInputs(expression) {
			frames, ok := correctiveResolveFrameSequence(input, environment, 0)
			if !ok {
				continue
			}
			for index := range frames {
				frames[index] = correctiveExpandReviewedVariables(frames[index], environment)
			}
			candidates = append(candidates, frames)
		}
		if assigned {
			environment[target] = expression
		}
	}
	return candidates
}

func correctivePLpgSQLAssignment(statement string) (string, string, bool) {
	selectInto := regexp.MustCompile(`(?is)\bselect\s+(.+?)\s+into\s+(?:strict\s+)?([a-z_][a-z0-9_]*)\b(?:\s+from\b.*)?$`)
	if match := selectInto.FindStringSubmatch(statement); match != nil {
		return strings.ToLower(match[2]), strings.TrimSpace(match[1]), true
	}
	operator := strings.LastIndex(statement, ":=")
	operatorWidth := 2
	if operator < 0 {
		operator = correctiveLastBareEquals(statement)
		operatorWidth = 1
	}
	if operator < 0 {
		return "", "", false
	}
	left := statement[:operator]
	right := strings.TrimSpace(statement[operator+operatorWidth:])
	if operatorWidth == 1 && strings.Contains(strings.ToLower(right), " then ") {
		return "", "", false
	}
	declaration := regexp.MustCompile(`(?is)([a-z_][a-z0-9_]*)\s+(?:constant\s+)?(?:bytea|text|bigint|integer|int|boolean|uuid|jsonb?|timestamptz|timestamp(?:\s+with\s+time\s+zone)?)\s*$`)
	if match := declaration.FindStringSubmatch(left); match != nil {
		return strings.ToLower(match[1]), right, true
	}
	nameAtEnd := regexp.MustCompile(`(?is)([a-z_][a-z0-9_]*)\s*$`)
	location := nameAtEnd.FindStringSubmatchIndex(left)
	if location == nil {
		return "", "", false
	}
	prefix := strings.TrimSpace(left[:location[2]])
	if strings.HasSuffix(prefix, ".") {
		return "", "", false
	}
	return strings.ToLower(left[location[2]:location[3]]), right, true
}

func correctiveLastBareEquals(statement string) int {
	for index := len(statement) - 1; index >= 0; index-- {
		if statement[index] != '=' {
			continue
		}
		if index > 0 && strings.ContainsRune(":<>!=", rune(statement[index-1])) {
			continue
		}
		if index+1 < len(statement) && (statement[index+1] == '=' || statement[index+1] == '>') {
			continue
		}
		return index
	}
	return -1
}

func correctiveDigestInputs(body string) []string {
	pattern := regexp.MustCompile(`(?is)\b(?:pg_catalog\.)?sha256\s*\(`)
	locations := pattern.FindAllStringIndex(correctiveMaskNonCodeSQL(body), -1)
	inputs := make([]string, 0, len(locations))
	for _, location := range locations {
		open := location[1] - 1
		close := correctiveMatchingParen(body, open)
		if close < 0 {
			continue
		}
		arguments := correctiveSplitSQLArguments(body[open+1 : close])
		if len(arguments) == 1 {
			inputs = append(inputs, strings.TrimSpace(arguments[0]))
		}
	}
	return inputs
}

func correctiveMaskNonCodeSQL(value string) string {
	masked := []byte(value)
	lineComment := false
	blockCommentDepth := 0
	inSingleQuote := false
	singleQuoteBackslashEscapes := false
	inDoubleQuote := false
	dollarTag := ""
	for index := 0; index < len(value); index++ {
		character := value[index]
		if lineComment {
			masked[index] = ' '
			if character == '\n' {
				lineComment = false
			}
			continue
		}
		if blockCommentDepth > 0 {
			masked[index] = ' '
			if character == '/' && index+1 < len(value) && value[index+1] == '*' {
				masked[index+1] = ' '
				blockCommentDepth++
				index++
			} else if character == '*' && index+1 < len(value) && value[index+1] == '/' {
				masked[index+1] = ' '
				blockCommentDepth--
				index++
			}
			continue
		}
		if dollarTag != "" {
			masked[index] = ' '
			if strings.HasPrefix(value[index:], dollarTag) {
				for offset := 1; offset < len(dollarTag); offset++ {
					masked[index+offset] = ' '
				}
				index += len(dollarTag) - 1
				dollarTag = ""
			}
			continue
		}
		if inSingleQuote {
			masked[index] = ' '
			if singleQuoteBackslashEscapes && character == '\\' && index+1 < len(value) {
				masked[index+1] = ' '
				index++
			} else if character == '\'' && index+1 < len(value) && value[index+1] == '\'' {
				masked[index+1] = ' '
				index++
			} else if character == '\'' {
				inSingleQuote = false
				singleQuoteBackslashEscapes = false
			}
			continue
		}
		if inDoubleQuote {
			masked[index] = ' '
			if character == '"' && index+1 < len(value) && value[index+1] == '"' {
				masked[index+1] = ' '
				index++
			} else if character == '"' {
				inDoubleQuote = false
			}
			continue
		}
		switch {
		case character == '-' && index+1 < len(value) && value[index+1] == '-':
			masked[index], masked[index+1] = ' ', ' '
			lineComment = true
			index++
		case character == '/' && index+1 < len(value) && value[index+1] == '*':
			masked[index], masked[index+1] = ' ', ' '
			blockCommentDepth = 1
			index++
		case character == '\'':
			masked[index] = ' '
			inSingleQuote = true
			singleQuoteBackslashEscapes = correctiveEscapeStringPrefix(value, index)
		case character == '"':
			masked[index] = ' '
			inDoubleQuote = true
		case character == '$':
			tag := correctiveDollarQuoteTag(value[index:])
			if tag != "" {
				for offset := 0; offset < len(tag); offset++ {
					masked[index+offset] = ' '
				}
				index += len(tag) - 1
				dollarTag = tag
			}
		}
	}
	return string(masked)
}

func correctiveResolveFrameSequence(expression string, assignments map[string]string, depth int) ([]string, bool) {
	if depth > 64 {
		return nil, false
	}
	expression = correctiveTrimOuterParentheses(strings.TrimSpace(expression))
	if regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(expression) {
		assigned, ok := assignments[expression]
		if !ok || assigned == "<ambiguous>" {
			return nil, false
		}
		return correctiveResolveFrameSequence(assigned, assignments, depth+1)
	}
	operands := correctiveSplitTopLevelConcat(expression)
	if len(operands) > 1 {
		frames := make([]string, 0, len(operands))
		for _, operand := range operands {
			resolved, ok := correctiveResolveFrameSequence(operand, assignments, depth+1)
			if !ok {
				return nil, false
			}
			frames = append(frames, resolved...)
		}
		return frames, true
	}
	frames := correctiveFramedArguments(expression)
	if len(frames) != 1 {
		return nil, false
	}
	const call = "public.asset_catalog_framed_value_v1("
	callStart := strings.Index(expression, call)
	if callStart == 0 {
		open := len(call) - 1
		if correctiveMatchingParen(expression, open) == len(expression)-1 {
			return frames, true
		}
	}
	if strings.Contains(expression, "string_agg(") && strings.Contains(expression, "order by") {
		return frames, true
	}
	return nil, false
}

func correctiveSplitTopLevelConcat(expression string) []string {
	parts := make([]string, 0, 20)
	start := 0
	depth := 0
	inSingleQuote := false
	inDoubleQuote := false
	for index := 0; index < len(expression); index++ {
		character := expression[index]
		if inSingleQuote {
			if character == '\'' && index+1 < len(expression) && expression[index+1] == '\'' {
				index++
			} else if character == '\'' {
				inSingleQuote = false
			}
			continue
		}
		if inDoubleQuote {
			if character == '"' && index+1 < len(expression) && expression[index+1] == '"' {
				index++
			} else if character == '"' {
				inDoubleQuote = false
			}
			continue
		}
		switch character {
		case '\'':
			inSingleQuote = true
		case '"':
			inDoubleQuote = true
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 && index+1 < len(expression) && expression[index+1] == '|' {
				parts = append(parts, strings.TrimSpace(expression[start:index]))
				index++
				start = index + 1
			}
		}
	}
	if len(parts) == 0 {
		return []string{strings.TrimSpace(expression)}
	}
	parts = append(parts, strings.TrimSpace(expression[start:]))
	return parts
}

func correctiveTrimOuterParentheses(expression string) string {
	for len(expression) >= 2 && expression[0] == '(' && correctiveMatchingParen(expression, 0) == len(expression)-1 {
		expression = strings.TrimSpace(expression[1 : len(expression)-1])
	}
	return expression
}

func correctiveExpandReviewedVariables(expression string, assignments map[string]string) string {
	for iteration := 0; iteration < 32; iteration++ {
		expanded, changed := correctiveExpandReviewedVariablesOnce(expression, assignments)
		expression = expanded
		if !changed {
			break
		}
	}
	return correctiveNormalizeSQL(expression)
}

func correctiveExpandReviewedVariablesOnce(expression string, assignments map[string]string) (string, bool) {
	var expanded strings.Builder
	expanded.Grow(len(expression))
	changed := false
	inSingleQuote := false
	inDoubleQuote := false
	for index := 0; index < len(expression); {
		character := expression[index]
		if inSingleQuote {
			expanded.WriteByte(character)
			index++
			if character == '\'' && index < len(expression) && expression[index] == '\'' {
				expanded.WriteByte(expression[index])
				index++
			} else if character == '\'' {
				inSingleQuote = false
			}
			continue
		}
		if inDoubleQuote {
			expanded.WriteByte(character)
			index++
			if character == '"' && index < len(expression) && expression[index] == '"' {
				expanded.WriteByte(expression[index])
				index++
			} else if character == '"' {
				inDoubleQuote = false
			}
			continue
		}
		if character == '\'' {
			inSingleQuote = true
			expanded.WriteByte(character)
			index++
			continue
		}
		if character == '"' {
			inDoubleQuote = true
			expanded.WriteByte(character)
			index++
			continue
		}
		if (character >= 'a' && character <= 'z') || character == '_' {
			end := index + 1
			for end < len(expression) && ((expression[end] >= 'a' && expression[end] <= 'z') ||
				(expression[end] >= '0' && expression[end] <= '9') || expression[end] == '_') {
				end++
			}
			name := expression[index:end]
			previous := index - 1
			for previous >= 0 && (expression[previous] == ' ' || expression[previous] == '\t') {
				previous--
			}
			next := end
			for next < len(expression) && (expression[next] == ' ' || expression[next] == '\t') {
				next++
			}
			assigned, ok := assignments[name]
			if ok && assigned != "<ambiguous>" && assigned != name &&
				(previous < 0 || expression[previous] != '.') && (next >= len(expression) || expression[next] != '.') {
				expanded.WriteString(assigned)
				changed = true
			} else {
				expanded.WriteString(name)
			}
			index = end
			continue
		}
		expanded.WriteByte(character)
		index++
	}
	return expanded.String(), changed
}

func correctiveFrameConversionPattern(field string, optional bool) string {
	quoted := regexp.QuoteMeta(field)
	core := `(?:pg_catalog\.)?convert_to\(\s*` + quoted + `(?:\s*::\s*text)?\s*,\s*'utf8'\s*\)`
	if !optional {
		return `(?is)^` + core + `$`
	}
	return `(?is)^(?:` + core + `|case\s+when\s+` + quoted + `\s+is\s+null\s+then\s+null\s+else\s+` + core + `\s+end)$`
}

func correctiveFrameDecodePattern(field string, optional bool) string {
	quoted := regexp.QuoteMeta(field)
	core := `(?:pg_catalog\.)?decode\(\s*` + quoted + `\s*,\s*'hex'\s*\)`
	if !optional {
		return `(?is)^` + core + `$`
	}
	return `(?is)^(?:` + core + `|case\s+when\s+` + quoted + `\s+is\s+null\s+then\s+null\s+else\s+` + core + `\s+end)$`
}

func correctiveGenericFrameConversionPattern(field string) string {
	return `(?is)^(?:pg_catalog\.)?convert_to\(\s*[a-z_][a-z0-9_]*\.` + regexp.QuoteMeta(field) +
		`(?:\s*::\s*text)?\s*,\s*'utf8'\s*\)$`
}

func correctiveGenericFrameDecodePattern(field string) string {
	return `(?is)^(?:pg_catalog\.)?decode\(\s*[a-z_][a-z0-9_]*\.` + regexp.QuoteMeta(field) +
		`\s*,\s*'hex'\s*\)$`
}

func correctiveAssertExactFrames(t *testing.T, label string, frames, patterns []string) {
	t.Helper()
	if len(frames) != len(patterns) {
		t.Errorf("%s frame count = %d, want exact %d", label, len(frames), len(patterns))
		return
	}
	for index, expression := range patterns {
		if !regexp.MustCompile(expression).MatchString(frames[index]) {
			t.Errorf("%s frame %d has noncanonical expression %q", label, index+1, frames[index])
		}
	}
}

func correctiveTriggerIdentities(t *testing.T, sql string) []string {
	t.Helper()
	pattern := regexp.MustCompile(`(?is)^\s*create\s+(?:or\s+replace\s+)?(constraint\s+)?trigger\s+(` + correctiveSQLIdentifierPattern +
		`)\s+(before|after|instead\s+of)\s+(.+?)\s+on\s+(` + correctiveQualifiedSQLIdentifierPattern() +
		`)\s+(.+?)\bexecute\s+(function|procedure)\s+(` + correctiveQualifiedSQLIdentifierPattern() + `)\s*\(\s*\)\s*;\s*$`)
	identities := make([]string, 0, 39)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		match := pattern.FindStringSubmatch(statement)
		if match == nil {
			continue
		}
		events := strings.Split(correctiveNormalizeSQL(match[4]), " or ")
		sort.Strings(events)
		modifiers := correctiveNormalizeSQL(match[6])
		constraint := match[1] != ""
		level := "row"
		deferred := false
		switch {
		case constraint && modifiers == "deferrable initially deferred for each row":
			deferred = true
		case !constraint && modifiers == "for each row":
		case !constraint && modifiers == "for each statement":
			level = "statement"
		default:
			t.Errorf("trigger %s has unreviewed modifiers %q (WHEN/REFERENCING/additional clauses are forbidden)", correctiveCanonicalSQLIdentifier(match[2]), modifiers)
		}
		caller := correctiveCanonicalSQLIdentifier(match[8])
		if !strings.EqualFold(match[7], "function") {
			caller = "procedure:" + caller
		}
		identities = append(identities, correctiveTriggerIdentity(
			correctiveCanonicalSQLIdentifier(match[5]),
			correctiveCanonicalSQLIdentifier(match[2]),
			constraint,
			correctiveNormalizeSQL(match[3]),
			events,
			level,
			deferred,
			caller,
		))
	}
	return identities
}

func correctiveTriggerIdentity(relation, name string, constraint bool, timing string, events []string, level string, deferred bool, caller string) string {
	eventCopy := append([]string(nil), events...)
	sort.Strings(eventCopy)
	return relation + "/" + name + "|constraint=" + correctiveBoolText(constraint) + "|" + timing + "|" +
		strings.Join(eventCopy, ",") + "|" + level + "|deferred=" + correctiveBoolText(deferred) + "|" + caller + "()"
}

func correctiveExpectedTriggerIdentities() []string {
	row := func(relation, name, timing string, events []string, caller string) string {
		return correctiveTriggerIdentity("public."+relation, name, false, timing, events, "row", false, "public."+caller)
	}
	statement := func(relation, name, caller string) string {
		return correctiveTriggerIdentity("public."+relation, name, false, "before", []string{"truncate"}, "statement", false, "public."+caller)
	}
	deferred := func(relation, name string, events []string, caller string) string {
		return correctiveTriggerIdentity("public."+relation, name, true, "after", events, "row", true, "public."+caller)
	}
	return []string{
		row("audit_records", "asset_management_audit_insert_guard", "before", []string{"insert"}, "validate_asset_management_audit_insert"),
		row("asset_observations", "asset_observations_immutable", "before", []string{"update"}, "reject_asset_catalog_immutable"),
		row("asset_type_details", "asset_type_details_immutable", "before", []string{"update"}, "reject_asset_catalog_immutable"),
		row("asset_source_revision_authorities", "asset_source_revision_authorities_immutable", "before", []string{"update"}, "reject_asset_catalog_immutable"),
		row("asset_sources", "asset_sources_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_revisions", "asset_source_revisions_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_revision_authorities", "asset_source_revision_authorities_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_runs", "asset_source_runs_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_observations", "asset_observations_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("assets", "assets_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_type_details", "asset_type_details_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_conflicts", "asset_conflicts_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_relationships", "asset_relationships_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("service_asset_bindings", "service_asset_bindings_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		statement("asset_sources", "asset_sources_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_source_revisions", "asset_source_revisions_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_source_revision_authorities", "asset_source_revision_authorities_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_source_runs", "asset_source_runs_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_observations", "asset_observations_truncate_guard", "reject_asset_catalog_truncate"),
		statement("assets", "assets_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_type_details", "asset_type_details_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_conflicts", "asset_conflicts_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_relationships", "asset_relationships_truncate_guard", "reject_asset_catalog_truncate"),
		statement("service_asset_bindings", "service_asset_bindings_truncate_guard", "reject_asset_catalog_truncate"),
		row("assets", "assets_transition_guard", "before", []string{"insert", "update"}, "enforce_assets_transition"),
		row("asset_conflicts", "asset_conflicts_transition_guard", "before", []string{"insert", "update"}, "enforce_asset_conflict_transition"),
		row("asset_relationships", "asset_relationships_mutation_guard", "before", []string{"insert", "update"}, "enforce_asset_relationship_mutation"),
		deferred("asset_relationships", "asset_relationships_page_closure_guard", []string{"insert", "update"}, "validate_asset_relationship_page_closure"),
		row("service_asset_bindings", "service_asset_bindings_mutation_guard", "before", []string{"insert", "update"}, "enforce_asset_catalog_edge_mutation"),
		row("asset_sources", "asset_sources_mutation_guard", "before", []string{"insert", "update"}, "enforce_asset_sources_mutation"),
		deferred("asset_sources", "asset_sources_deferred_state_guard", []string{"insert", "update"}, "validate_asset_source_deferred_state"),
		row("asset_source_revisions", "asset_source_revisions_transition_guard", "before", []string{"insert", "update"}, "enforce_asset_source_revision_transition"),
		deferred("asset_source_revisions", "asset_source_revisions_deferred_state_guard", []string{"insert", "update"}, "validate_asset_source_revision_deferred_state"),
		deferred("asset_source_revision_authorities", "asset_source_revision_authorities_deferred_state_guard", []string{"insert"}, "validate_asset_source_revision_deferred_state"),
		row("asset_source_runs", "asset_source_runs_mutation_guard", "before", []string{"insert", "update"}, "enforce_asset_source_run_mutation"),
		deferred("asset_source_runs", "asset_source_runs_page_closure_guard", []string{"update"}, "validate_asset_source_run_page_closure"),
		deferred("asset_source_runs", "asset_source_runs_terminal_closure_guard", []string{"insert", "update"}, "validate_asset_source_run_terminal_closure"),
		row("asset_observations", "asset_observations_admission_guard", "before", []string{"insert"}, "enforce_asset_observation_admission"),
		deferred("asset_observations", "asset_observations_page_closure_guard", []string{"insert"}, "validate_asset_observation_page_closure"),
	}
}

func correctiveDroppedTriggerIdentities(sql string) []string {
	pattern := regexp.MustCompile(`(?is)^\s*drop\s+trigger\s+(` + correctiveSQLIdentifierPattern + `)\s+on\s+(` +
		correctiveQualifiedSQLIdentifierPattern() + `)\s*;\s*$`)
	identities := make([]string, 0, 39)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		match := pattern.FindStringSubmatch(statement)
		if match == nil {
			continue
		}
		identities = append(identities, correctiveCanonicalSQLIdentifier(match[2])+"/"+correctiveCanonicalSQLIdentifier(match[1]))
	}
	return identities
}

func correctiveExpectedDroppedTriggerIdentities() []string {
	expected := correctiveExpectedTriggerIdentities()
	dropped := make([]string, 0, len(expected))
	for _, identity := range expected {
		dropped = append(dropped, strings.SplitN(identity, "|", 2)[0])
	}
	return dropped
}

func createdTableIdentities(sql string) []string {
	return correctiveSQLObjectIdentities(sql, `(?is)^\s*create\s+table\s+(`+correctiveQualifiedSQLIdentifierPattern()+`)\s*\(`)
}

func droppedTableIdentities(sql string) []string {
	return correctiveSQLObjectIdentities(sql, `(?is)^\s*drop\s+table\s+(`+correctiveQualifiedSQLIdentifierPattern()+`)\s*;\s*$`)
}

func correctiveSQLObjectIdentities(sql, expression string) []string {
	pattern := regexp.MustCompile(expression)
	identities := make([]string, 0, 10)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		match := pattern.FindStringSubmatch(statement)
		if match != nil {
			identities = append(identities, correctiveCanonicalSQLIdentifier(match[1]))
		}
	}
	return identities
}

func assertExactSQLObjectSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	gotCopy := append([]string(nil), got...)
	wantCopy := append([]string(nil), want...)
	sort.Strings(gotCopy)
	sort.Strings(wantCopy)
	if !reflect.DeepEqual(gotCopy, wantCopy) {
		t.Errorf("%s = %v, want exact set %v", label, gotCopy, wantCopy)
	}
}

func correctiveRequireTable(t *testing.T, sql, qualifiedName string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?is)^\s*create\s+table\s+(` + correctiveQualifiedSQLIdentifierPattern() + `)\s*\(`)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		location := pattern.FindStringSubmatchIndex(statement)
		if location == nil || correctiveCanonicalSQLIdentifier(statement[location[2]:location[3]]) != strings.ToLower(qualifiedName) {
			continue
		}
		open := location[1] - 1
		close := correctiveMatchingParen(statement, open)
		if close < 0 {
			t.Errorf("table %s has an unclosed definition", qualifiedName)
			return ""
		}
		return statement[location[0] : close+1]
	}
	t.Errorf("migration does not define table %s with an explicit schema", qualifiedName)
	return ""
}

func correctiveMatchingParen(value string, open int) int {
	depth := 0
	inSingleQuote, inDoubleQuote := false, false
	for index := open; index < len(value); index++ {
		character := value[index]
		if inSingleQuote {
			if character == '\'' && index+1 < len(value) && value[index+1] == '\'' {
				index++
			} else if character == '\'' {
				inSingleQuote = false
			}
			continue
		}
		if inDoubleQuote {
			if character == '"' {
				inDoubleQuote = false
			}
			continue
		}
		switch character {
		case '\'':
			inSingleQuote = true
		case '"':
			inDoubleQuote = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func correctiveProfileManifestV1Keys() []string {
	return []string{
		"version", "source_kind", "provider_kind", "profile_code", "sync_mode", "freshness_kind",
		"environment_mapping_mode", "integration_mode", "credential_purpose", "trust_mode", "network_mode",
		"rate_limit_requests", "rate_limit_window_seconds", "backpressure_base_seconds", "backpressure_max_seconds",
		"schedule_mode", "max_page_items", "max_page_relations", "max_page_bytes", "max_document_bytes",
		"parser_code", "compatibility_class", "dlp_policy_code", "trusted_path_codes", "relationship_types",
		"typed_extension_code",
	}
}

func correctiveDownLockStatements(sql string) []string {
	pattern := regexp.MustCompile(`(?is)^\s*lock\s+table\s+.+;\s*$`)
	matches := make([]string, 0, 1)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		if pattern.MatchString(statement) {
			matches = append(matches, correctiveNormalizeSQL(statement))
		}
	}
	return matches
}

func correctiveAssertOrdered(t *testing.T, label, text string, ordered []string) {
	t.Helper()
	previous := -1
	for _, token := range ordered {
		position := strings.Index(text, token)
		if position < 0 {
			t.Errorf("%s missing %q", label, token)
			continue
		}
		if position <= previous {
			t.Errorf("%s places %q out of required order", label, token)
		}
		previous = position
	}
}

func correctiveAssertBefore(t *testing.T, first, second, text string) {
	t.Helper()
	firstPosition := strings.Index(text, first)
	secondPosition := strings.Index(text, second)
	if firstPosition < 0 {
		t.Errorf("dependency order missing %q", first)
	}
	if secondPosition < 0 {
		t.Errorf("dependency order missing %q", second)
	}
	if firstPosition >= 0 && secondPosition >= 0 && firstPosition >= secondPosition {
		t.Errorf("dependency %q must be dropped before %q", first, second)
	}
}

func correctiveAssertLiteralDigest(t *testing.T, label, literal string, wantBytes int, wantDigest string) {
	t.Helper()
	if len([]byte(literal)) != wantBytes {
		t.Fatalf("test fixture %s length = %d, want %d", label, len([]byte(literal)), wantBytes)
	}
	digest := sha256.Sum256([]byte(literal))
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("test fixture %s SHA-256 = %s, want %s", label, got, wantDigest)
	}
}

func correctiveLiteralComparedInStatement(body, literal string) bool {
	statement := correctiveStatementContainingLiteral(body, literal)
	if statement == "" {
		return false
	}
	return regexp.MustCompile(`(?is)(?:<>|!=|is\s+(?:not\s+)?distinct\s+from|(?:^|[^:])=)`).MatchString(statement)
}

func correctiveStatementContainingLiteral(body, literal string) string {
	location := strings.Index(body, literal)
	if location < 0 {
		return ""
	}
	start := strings.LastIndex(body[:location], ";") + 1
	endRelative := strings.Index(body[location+len(literal):], ";")
	end := len(body)
	if endRelative >= 0 {
		end = location + len(literal) + endRelative + 1
	}
	return body[start:end]
}

func correctiveReadSubstantiveArtifact(t *testing.T, relative string, minimumBytes int) string {
	t.Helper()
	raw, err := os.ReadFile(correctiveRepositoryPath(t, relative))
	if err != nil {
		t.Errorf("read required artifact %s: %v", relative, err)
		return ""
	}
	trimmed := strings.TrimSpace(string(raw))
	if len([]byte(trimmed)) < minimumBytes {
		t.Errorf("required artifact %s has %d substantive bytes, want at least %d", relative, len([]byte(trimmed)), minimumBytes)
	}
	if regexp.MustCompile(`(?i)\b(?:todo|tbd|fixme|implement later)\b`).MatchString(trimmed) {
		t.Errorf("required artifact %s contains an incomplete marker", relative)
	}
	return string(raw)
}

func correctiveRepositoryPath(t *testing.T, relative string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../..", relative))
}

func correctiveBaseDatabaseRoles() []string {
	return []string{
		"aiops_migrator",
		"aiops_schema_owner",
		"aiops_control_plane_runtime",
		"aiops_control_plane_workload",
	}
}

func correctiveRequireTokens(t *testing.T, label, text string, required ...string) {
	t.Helper()
	for _, token := range required {
		if !strings.Contains(text, strings.ToLower(token)) {
			t.Errorf("%s missing %q", label, token)
		}
	}
}

func correctiveNormalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(correctiveStripSQLComments(value))), " ")
}

func correctiveNormalizeSource(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), " ")
}

func correctiveStripSQLComments(value string) string {
	var result strings.Builder
	result.Grow(len(value))
	inSingleQuote, inDoubleQuote := false, false
	lineComment, blockComment := false, false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if lineComment {
			if character == '\n' {
				lineComment = false
				result.WriteByte('\n')
			} else {
				result.WriteByte(' ')
			}
			continue
		}
		if blockComment {
			if character == '*' && index+1 < len(value) && value[index+1] == '/' {
				blockComment = false
				result.WriteString("  ")
				index++
			} else if character == '\n' {
				result.WriteByte('\n')
			} else {
				result.WriteByte(' ')
			}
			continue
		}
		if inSingleQuote {
			result.WriteByte(character)
			if character == '\'' && index+1 < len(value) && value[index+1] == '\'' {
				result.WriteByte(value[index+1])
				index++
			} else if character == '\'' {
				inSingleQuote = false
			}
			continue
		}
		if inDoubleQuote {
			result.WriteByte(character)
			if character == '"' {
				inDoubleQuote = false
			}
			continue
		}
		if character == '-' && index+1 < len(value) && value[index+1] == '-' {
			lineComment = true
			result.WriteString("  ")
			index++
			continue
		}
		if character == '/' && index+1 < len(value) && value[index+1] == '*' {
			blockComment = true
			result.WriteString("  ")
			index++
			continue
		}
		result.WriteByte(character)
		if character == '\'' {
			inSingleQuote = true
		} else if character == '"' {
			inDoubleQuote = true
		}
	}
	return result.String()
}

func correctiveBoolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
