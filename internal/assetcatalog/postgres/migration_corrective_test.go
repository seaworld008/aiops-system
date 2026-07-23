package postgres_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const correctiveManualProfileManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":1,"compatibility_class":"MANUAL_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CATALOG_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":65536,"max_page_items":1,"max_page_relations":0,"network_mode":"NONE","parser_code":"MANUAL_ASSET_V1","profile_code":"MANUAL_V1","provider_kind":"MANUAL_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":[],"schedule_mode":"NONE","source_kind":"MANUAL","sync_mode":"MANUAL","trust_mode":"NONE","trusted_path_codes":["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`

const correctiveManualProviderSchemaV1 = `{"additionalProperties":false,"properties":{},"type":"object"}`

const correctiveCanonicalEmptyRelationPageSHA256 = "b89ad607e709ef2ea85f7fc6eb0f80e32ae3ecf234220907a0fe718825f7c151"

func TestAssetCatalogCorrectiveOwnsVersionMatchedRoutineSignaturesAndRuntimeLock(t *testing.T) {
	up := readMigration(t, "000015_assets_catalog.up.sql")
	correctiveAssertTopLevelParserSemantics(t)

	assertExactSQLObjectSet(
		t,
		"000015 owned routines",
		correctiveRoutineIdentities(up),
		correctiveExpectedRoutineIdentitiesForMigration(t, up),
	)
	assertExactSQLObjectSet(t, "000015 reviewed trigger manifest",
		correctiveTriggerIdentities(t, up),
		correctiveExpectedTriggerIdentitiesForMigration(t, up),
	)

	hook := correctiveRequireFunction(t, up, "public.asset_catalog_future_source_gate_admitted")
	correctiveAssertFunctionAttributes(t, "future Source hook", hook,
		"language plpgsql", "stable", "security invoker", "set search_path = pg_catalog, public, pg_temp")
	body := correctiveNormalizeSQL(hook.body)
	if body != "begin return false; end;" {
		t.Errorf("default future Source hook body = %q, want exact fail-closed RETURN false body", body)
	}

	lock := correctiveRequireFunction(t, up, "public.asset_catalog_lock_exact_service_binding")
	lockAttributes := correctiveNormalizeSQL(lock.attributes)
	correctiveRequireTokens(t, "runtime exact Service Binding lock attributes", lockAttributes,
		"language plpgsql",
		"volatile",
		"strict",
		"parallel unsafe",
		"security definer",
		"set search_path = pg_catalog, public, pg_temp",
	)
	correctiveRequireTokens(t, "runtime exact Service Binding lock result",
		correctiveNormalizeSQL(lock.full), ") returns boolean as")
	lockBody := correctiveNormalizeSQL(lock.body)
	correctiveRequireTokens(t, "runtime exact Service Binding lock body", lockBody,
		"current_setting('transaction_isolation')",
		"'serializable'",
		"current_setting('transaction_read_only')",
		"'off'",
		"from public.services",
		"for key share",
		"from public.service_bindings",
		"for share",
		"mapping_status <> 'exact'",
		"asset_catalog_exact_service_binding_isolation_guard",
		"asset_catalog_exact_service_binding_service_scope_guard",
		"asset_catalog_exact_service_binding_environment_guard",
		"asset_catalog_exact_service_binding_mapping_guard",
	)
	correctiveAssertOrdered(t, "runtime exact Service Binding lock order", lockBody, []string{
		"from public.services",
		"for key share",
		"from public.service_bindings",
		"for share",
	})
}

func TestAssetCatalogCorrectiveSourceGateSuccessorRoutineManifest(t *testing.T) {
	currentUp := readMigration(t, "000015_assets_catalog.up.sql")
	currentDown := readMigration(t, "000015_assets_catalog.down.sql")
	successorUp, successorDown, err := correctiveSourceGateSuccessorRoutineBoundary(
		currentUp,
		currentDown,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := correctiveExpectedSourceGateSuccessorRoutineIdentities()

	assertExactSQLObjectSet(
		t,
		"Source Gate successor routines",
		correctiveRoutineIdentities(successorUp),
		want,
	)
	assertExactSQLObjectSet(
		t,
		"Source Gate successor down routines",
		correctiveDroppedRoutineIdentities(successorDown),
		want,
	)

	for _, contract := range []struct {
		name        string
		sessionUser string
		otherUser   string
	}{
		{
			name:        "public.asset_catalog_seal_qualification_receipt",
			sessionUser: "aiops_source_gate_sealer",
			otherUser:   "aiops_source_gate_admitter",
		},
		{
			name:        "public.asset_catalog_admit_source_gate",
			sessionUser: "aiops_source_gate_admitter",
			otherUser:   "aiops_source_gate_sealer",
		},
	} {
		function := correctiveRequireFunction(t, successorUp, contract.name)
		attributes := correctiveNormalizeSQL(function.attributes)
		correctiveRequireTokens(t, contract.name+" attributes", attributes,
			"language plpgsql",
			"volatile",
			"strict",
			"parallel unsafe",
			"security definer",
			"set search_path = pg_catalog, public, pg_temp",
		)
		correctiveRequireTokens(t, contract.name+" result",
			correctiveNormalizeSQL(function.full), ") returns boolean as")
		body := correctiveNormalizeSQL(function.body)
		correctiveAssertSourceGateSessionGuard(t, contract.name, body, contract.sessionUser)
		if strings.Contains(body, contract.otherUser) {
			t.Errorf("%s body accepts or names cross-capability identity %s", contract.name, contract.otherUser)
		}
	}
}

func TestAssetCatalogCorrectiveSourceGateSuccessorRoutineDualStateBoundary(t *testing.T) {
	currentUp := readMigration(t, "000015_assets_catalog.up.sql")
	currentDown := readMigration(t, "000015_assets_catalog.down.sql")
	currentState, err := correctiveSourceGateRoutineManifestState(currentUp)
	if err != nil {
		t.Fatal(err)
	}
	exact36Up := currentUp
	exact36Down := currentDown
	exact38Up := currentUp
	exact38Down := currentDown
	if currentState == "exact-36" {
		exact38Up += correctiveSourceGateSuccessorRoutineFixture()
		exact38Down = correctiveSourceGateSuccessorRoutineDownFixture() + exact38Down
	} else {
		exact36Up = correctiveWithoutSourceGateSuccessorRoutineStatements(exact36Up, false)
		exact36Down = correctiveWithoutSourceGateSuccessorRoutineStatements(exact36Down, true)
	}

	overload := `
CREATE FUNCTION public.asset_catalog_admit_source_gate(uuid)
RETURNS boolean LANGUAGE sql AS 'SELECT false';
`
	for _, test := range []struct {
		name      string
		up        string
		down      string
		wantError bool
	}{
		{name: "exact-36 attaches successor fixture", up: exact36Up, down: exact36Down},
		{name: "synthetic exact-38 validates migration itself", up: exact38Up, down: exact38Down},
		{name: "duplicate successor routines fail closed", up: exact38Up + correctiveSourceGateSuccessorRoutineFixture(), down: exact38Down, wantError: true},
		{name: "successor overload fails closed", up: exact38Up + overload, down: exact38Down, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			up, down, err := correctiveSourceGateSuccessorRoutineBoundary(test.up, test.down)
			if test.wantError {
				if err == nil {
					t.Fatal("routine boundary accepted duplicate or overload manifest")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertExactSQLObjectSet(t, "dual-state successor routines", correctiveRoutineIdentities(up), correctiveExpectedSourceGateSuccessorRoutineIdentities())
			assertExactSQLObjectSet(t, "dual-state successor down routines", correctiveDroppedRoutineIdentities(down), correctiveExpectedSourceGateSuccessorRoutineIdentities())
		})
	}
}

func TestAssetCatalogCorrectiveSourceGateSessionGuardDirection(t *testing.T) {
	fixture := correctiveSourceGateSuccessorRoutineFixture()
	sealer := correctiveRequireFunction(t, fixture, "public.asset_catalog_seal_qualification_receipt")
	if err := correctiveSourceGateSessionGuardError(sealer.body, "aiops_source_gate_sealer"); err != nil {
		t.Fatalf("correct sealer session guard rejected: %v", err)
	}
	reversed := strings.Replace(sealer.body, "<>", "=", 1)
	if err := correctiveSourceGateSessionGuardError(reversed, "aiops_source_gate_sealer"); err == nil {
		t.Fatal("reversed sealer session guard accepted; only the wrong session identity may enter 42501")
	}
}

func TestAssetCatalogCorrectiveSourceGateSuccessorTriggerManifest(t *testing.T) {
	currentUp := readMigration(t, "000015_assets_catalog.up.sql")
	currentDown := readMigration(t, "000015_assets_catalog.down.sql")
	columnList := func(runID, digest, expires string) string {
		return fmt.Sprintf(`
    gate_evidence_run_id %s,
    gate_evidence_digest %s,
    gate_evidence_expires_at %s`, runID, digest, expires)
	}
	alterList := func(runID, digest, expires string) string {
		return fmt.Sprintf(`
ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_run_id %s;
ALTER TABLE public.asset_sources ADD gate_evidence_digest %s NULL;
ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_expires_at %s;
`, runID, digest, expires)
	}
	mixedAlterList := func(digest, expires string) string {
		return fmt.Sprintf(`
ALTER TABLE public.asset_sources ADD gate_evidence_digest %s;
ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_expires_at %s NULL;
`, digest, expires)
	}
	dynamicDO := func(body string) string {
		return "\nDO $$\nBEGIN\n" + body + "\nEND;\n$$;\n"
	}
	singleQuotedDO := func(body string) string {
		return "\nDO '" + strings.ReplaceAll(body, "'", "''") + "' LANGUAGE plpgsql;\n"
	}
	escapeQuotedDO := func(body string) string {
		escaped := strings.NewReplacer(
			`\`, `\\`,
			`'`, `\'`,
			"\n", `\n`,
			"\r", `\r`,
			"\t", `\t`,
		).Replace(body)
		return "\nDO E'" + escaped + "' LANGUAGE plpgsql;\n"
	}
	successorColumns := columnList("uuid", "text", "timestamptz")
	exactTrigger := `
CREATE CONSTRAINT TRIGGER asset_sources_gate_evidence_closure_guard
AFTER INSERT OR UPDATE ON public.asset_sources
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state();
	`
	exactDrop := "\nDROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources;\n"
	dropAnchor := "DROP TRIGGER asset_sources_deferred_state_guard ON public.asset_sources;"
	successorUp, successorDown, err := correctiveSourceGateSuccessorTriggerFixture(
		t, currentUp, currentDown, successorColumns, exactTrigger, dropAnchor, exactDrop,
	)
	if err != nil {
		t.Fatalf("construct successor source-gate fixture: %v", err)
	}
	assertRejectedDO := func(name, statement string) {
		t.Helper()
		t.Run("discriminator rejects "+name, func(t *testing.T) {
			if required, err := correctiveSourceGateTriggerRequired(currentUp + statement); err == nil {
				t.Fatalf("gate-column discriminator = %t, nil; want %s error", required, name)
			}
		})
		t.Run("up rejects "+name, func(t *testing.T) {
			if _, diagnostics := correctiveParsedTriggerIdentities(successorUp + statement); len(diagnostics) == 0 {
				t.Fatalf("successor up manifest accepted %s", name)
			}
		})
		t.Run("down rejects "+name, func(t *testing.T) {
			got := correctiveDroppedTriggerIdentities(successorDown + statement)
			want := correctiveExpectedDroppedTriggerIdentitiesForMigration(t, successorUp)
			if correctiveSQLObjectSetsEqual(got, want) {
				t.Fatalf("successor down manifest accepted %s", name)
			}
		})
	}
	assertSafeDO := func(name, statement string) {
		t.Helper()
		t.Run("safe "+name+" preserves manifests", func(t *testing.T) {
			up := strings.Replace(successorUp, "RESET ROLE;", statement+"RESET ROLE;", 1)
			required, err := correctiveSourceGateTriggerRequired(up)
			if err != nil || !required {
				t.Fatalf("safe %s discriminator = %t, %v; want true, nil", name, required, err)
			}
			gotUp, diagnostics := correctiveParsedTriggerIdentities(up)
			if len(diagnostics) != 0 || !correctiveSQLObjectSetsEqual(gotUp, correctiveExpectedTriggerIdentitiesForMigration(t, up)) {
				t.Fatalf("safe %s changed up manifest: diagnostics=%v", name, diagnostics)
			}
			down := strings.Replace(successorDown, dropAnchor, statement+dropAnchor, 1)
			if got := correctiveDroppedTriggerIdentities(down); !correctiveSQLObjectSetsEqual(got, correctiveExpectedDroppedTriggerIdentitiesForMigration(t, up)) {
				t.Fatalf("safe %s changed down manifest", name)
			}
		})
	}
	assertSafeDOPaths := func(name, statement string) {
		t.Helper()
		up := strings.Replace(successorUp, "RESET ROLE;", statement+"RESET ROLE;", 1)
		t.Run("discriminator accepts safe "+name, func(t *testing.T) {
			required, err := correctiveSourceGateTriggerRequired(up)
			if err != nil || !required {
				t.Fatalf("safe %s discriminator = %t, %v; want true, nil", name, required, err)
			}
		})
		t.Run("up accepts safe "+name, func(t *testing.T) {
			got, diagnostics := correctiveParsedTriggerIdentities(up)
			if len(diagnostics) != 0 || !correctiveSQLObjectSetsEqual(got, correctiveExpectedTriggerIdentitiesForMigration(t, up)) {
				t.Fatalf("safe %s changed up manifest: diagnostics=%v", name, diagnostics)
			}
		})
		t.Run("down accepts safe "+name, func(t *testing.T) {
			down := strings.Replace(successorDown, dropAnchor, statement+dropAnchor, 1)
			if got := correctiveDroppedTriggerIdentities(down); !correctiveSQLObjectSetsEqual(got, correctiveExpectedDroppedTriggerIdentitiesForMigration(t, up)) {
				t.Fatalf("safe %s changed down manifest", name)
			}
		})
	}

	typeVariants := []struct{ name, runID, digest, expires string }{
		{"bare", "uuid", "text", "timestamptz"},
		{"quoted bare", `"uuid"`, `"text"`, `"timestamptz"`},
		{"qualified", "pg_catalog.uuid", "pg_catalog.text", "pg_catalog.timestamptz"},
		{"quoted schema", `"pg_catalog".uuid`, `"pg_catalog".text`, `"pg_catalog".timestamptz`},
		{"quoted type", `pg_catalog."uuid"`, `pg_catalog."text"`, `pg_catalog."timestamptz"`},
		{"quoted both", `"pg_catalog"."uuid"`, `"pg_catalog"."text"`, `"pg_catalog"."timestamptz"`},
		{"timestamp phrase", "uuid", "text", "timestamp with time zone"},
		{"qualified timestamp phrase", "pg_catalog.uuid", "pg_catalog.text", "pg_catalog.timestamp with time zone"},
	}
	successors := make([]struct{ name, up string }, 0, len(typeVariants)*3)
	for _, types := range typeVariants {
		columns := columnList(types.runID, types.digest, types.expires)
		mixed := correctiveSourceGateColumnsFixture(t, currentUp, "gate_evidence_run_id "+types.runID) +
			mixedAlterList(types.digest, types.expires)
		successors = append(successors,
			struct{ name, up string }{types.name + " inline", correctiveSourceGateColumnsFixture(t, currentUp, columns)},
			struct{ name, up string }{types.name + " all alter", currentUp + alterList(types.runID, types.digest, types.expires)},
			struct{ name, up string }{types.name + " mixed", mixed},
		)
	}
	alterColumns := alterList("uuid", "text", "timestamptz")
	for _, test := range successors {
		t.Run(test.name+" exact3 requires guard", func(t *testing.T) {
			required, err := correctiveSourceGateTriggerRequired(test.up)
			if err != nil || !required {
				t.Fatalf("gate-column discriminator = %t, %v; want true, nil before trigger creation", required, err)
			}
			up := test.up + exactTrigger
			assertExactSQLObjectSet(t, "successor routine manifest", correctiveRoutineIdentities(up), correctiveExpectedRoutineIdentitiesForMigration(t, currentUp))
			assertExactSQLObjectSet(t, "successor trigger manifest", correctiveTriggerIdentities(t, up), correctiveExpectedTriggerIdentitiesForMigration(t, up))
			assertExactSQLObjectSet(t, "successor down trigger manifest", correctiveDroppedTriggerIdentities(successorDown), correctiveExpectedDroppedTriggerIdentitiesForMigration(t, up))
		})
	}
	normalizedSuccessorDown := correctiveNormalizeSQL(successorDown)
	firstTableDrop := strings.Index(normalizedSuccessorDown, "drop table ")
	lastTriggerDrop := strings.LastIndex(normalizedSuccessorDown, "drop trigger ")
	if strings.Count(successorDown, strings.TrimSpace(exactDrop)) != 1 ||
		firstTableDrop < 0 || lastTriggerDrop < 0 || lastTriggerDrop >= firstTableDrop {
		t.Fatal("successor down must drop every trigger exactly once before the first table drop")
	}

	replaceTrigger := func(old, replacement string) string {
		return strings.Replace(exactTrigger, old, replacement, 1)
	}
	upNegatives := []struct{ name, trigger string }{
		{"missing trigger", ""},
		{"wrong name", replaceTrigger("asset_sources_gate_evidence_closure_guard", "asset_sources_gate_evidence_closure_guard_wrong")},
		{"or replace", replaceTrigger("CREATE CONSTRAINT TRIGGER", "CREATE OR REPLACE CONSTRAINT TRIGGER")},
		{"non constraint", replaceTrigger("CREATE CONSTRAINT TRIGGER", "CREATE TRIGGER")},
		{"non deferred", replaceTrigger("DEFERRABLE INITIALLY DEFERRED", "NOT DEFERRABLE INITIALLY IMMEDIATE")},
		{"wrong events", replaceTrigger("AFTER INSERT OR UPDATE", "AFTER INSERT")},
		{"wrong caller", replaceTrigger("public.validate_asset_source_deferred_state()", "public.validate_asset_source_revision_deferred_state()")},
		{"wrong relation", replaceTrigger("ON public.asset_sources", "ON public.asset_source_runs")},
		{"statement level", replaceTrigger("FOR EACH ROW", "FOR EACH STATEMENT")},
		{"duplicate named trigger", exactTrigger + exactTrigger},
		{"dropped after create", exactTrigger + "\nDROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources;\n"},
		{"disabled after create", exactTrigger + "\nALTER TABLE public.asset_sources DISABLE TRIGGER asset_sources_gate_evidence_closure_guard;\n"},
		{"extra trigger", exactTrigger + `
CREATE TRIGGER asset_sources_gate_evidence_extra_guard
AFTER UPDATE ON public.asset_sources
FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state();
`},
		{"extra trigger with arguments", exactTrigger + `
CREATE TRIGGER asset_sources_gate_evidence_extra_guard
AFTER UPDATE ON public.asset_sources
FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state('unreviewed');
`},
	}
	for _, test := range upNegatives {
		t.Run("up rejects "+test.name, func(t *testing.T) {
			fixture := correctiveSourceGateColumnsFixture(t, currentUp, successorColumns) + test.trigger
			got, diagnostics := correctiveParsedTriggerIdentities(fixture)
			want := correctiveExpectedTriggerIdentitiesForMigration(t, fixture)
			if len(diagnostics) == 0 && correctiveSQLObjectSetsEqual(got, want) {
				t.Fatalf("successor up manifest accepted %s", test.name)
			}
		})
	}

	downNegatives := []struct{ name, down string }{
		{"missing drop", currentDown},
		{"wrong relation", currentDown + strings.Replace(exactDrop, "ON public.asset_sources", "ON public.asset_source_runs", 1)},
		{"extra drop", successorDown + "\nDROP TRIGGER asset_sources_gate_evidence_extra_guard ON public.asset_sources;\n"},
		{"extra drop with if exists", successorDown + "\nDROP TRIGGER IF EXISTS asset_sources_gate_evidence_extra_guard ON public.asset_sources;\n"},
		{"postposed drop", currentDown + exactDrop},
		{"drop after first table", strings.Replace(currentDown, "DROP TABLE public.service_asset_bindings;", "DROP TABLE public.service_asset_bindings;"+exactDrop, 1)},
		{"duplicate successor drop", strings.Replace(successorDown, strings.TrimSpace(exactDrop), strings.TrimSpace(exactDrop)+exactDrop, 1)},
		{"create after drops", successorDown + exactTrigger},
		{"create with arguments after drops", successorDown + `
CREATE TRIGGER asset_sources_gate_evidence_extra_guard
AFTER UPDATE ON public.asset_sources
FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state('unreviewed');
`},
		{"alter trigger after drops", successorDown + "\nALTER TRIGGER asset_sources_deferred_state_guard ON public.asset_sources RENAME TO asset_sources_deferred_state_guard_wrong;\n"},
		{"disable trigger after drops", successorDown + "\nALTER TABLE public.asset_sources DISABLE TRIGGER asset_sources_deferred_state_guard;\n"},
		{"enable trigger after drops", successorDown + "\nALTER TABLE public.asset_sources ENABLE ALWAYS TRIGGER asset_sources_deferred_state_guard;\n"},
	}
	for _, test := range downNegatives {
		t.Run("down rejects "+test.name, func(t *testing.T) {
			got := correctiveDroppedTriggerIdentities(test.down)
			want := correctiveExpectedDroppedTriggerIdentitiesForMigration(t, successorUp)
			if correctiveSQLObjectSetsEqual(got, want) {
				t.Fatalf("successor down manifest accepted %s", test.name)
			}
		})
	}
	dynamicTriggers := []struct{ name, body string }{
		{"create", `EXECUTE 'CREATE TRIGGER dynamic_guard AFTER UPDATE ON public.asset_sources FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state()';`},
		{"drop", `EXECUTE 'DROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources';`},
		{"alter", `EXECUTE 'ALTER TRIGGER asset_sources_deferred_state_guard ON public.asset_sources RENAME TO dynamic_guard';`},
		{"enable format", `EXECUTE format('ALTER TABLE public.asset_sources ENABLE TRIGGER %I', 'asset_sources_deferred_state_guard');`},
		{"disable concat", `EXECUTE 'ALTER TABLE public.asset_sources DISABLE ' || 'TRIGGER asset_sources_deferred_state_guard';`},
	}
	for _, test := range dynamicTriggers {
		t.Run("up rejects dynamic "+test.name, func(t *testing.T) {
			if _, diagnostics := correctiveParsedTriggerIdentities(successorUp + dynamicDO(test.body)); len(diagnostics) == 0 {
				t.Fatalf("successor up manifest accepted dynamic %s trigger lifecycle", test.name)
			}
		})
		t.Run("down rejects dynamic "+test.name, func(t *testing.T) {
			got := correctiveDroppedTriggerIdentities(successorDown + dynamicDO(test.body))
			want := correctiveExpectedDroppedTriggerIdentitiesForMigration(t, successorUp)
			if correctiveSQLObjectSetsEqual(got, want) {
				t.Fatalf("successor down manifest accepted dynamic %s trigger lifecycle", test.name)
			}
		})
	}
	ordinaryBackslashDynamicSQL := []struct{ name, body string }{
		{"octal add", `BEGIN \105XECUTE 'ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_status text'; END;`},
		{"hex drop", `BEGIN \x45XECUTE 'DROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources'; END;`},
		{"unicode disable", `BEGIN \u0045XECUTE 'ALTER TABLE public.asset_sources DISABLE TRIGGER asset_sources_deferred_state_guard'; END;`},
	}
	for _, test := range ordinaryBackslashDynamicSQL {
		assertRejectedDO("ordinary backslash "+test.name, singleQuotedDO(test.body))
	}
	nonCanonicalLanguageDOs := []struct{ name, statement string }{
		{
			"prefix non plpgsql do language",
			"\nDO LANGUAGE plperl 'spi_exec_query(''ALTER TABLE public.asset_sources DISABLE TRIGGER asset_sources_deferred_state_guard'');';\n",
		},
		{
			"tail non plpgsql do language",
			strings.Replace(
				singleQuotedDO(`spi_exec_query('ALTER TABLE public.asset_sources DISABLE TRIGGER asset_sources_deferred_state_guard');`),
				"LANGUAGE plpgsql",
				"LANGUAGE plperl",
				1,
			),
		},
		{
			"quoted prefix do language alias",
			"\nDO LANGUAGE \"plpgsql\" 'BEGIN PERFORM 1; END;';\n",
		},
		{
			"quoted tail do language alias",
			strings.Replace(singleQuotedDO("BEGIN PERFORM 1; END;"), "LANGUAGE plpgsql", `LANGUAGE "plpgsql"`, 1),
		},
		{
			"duplicate prefix and tail do language",
			"\nDO LANGUAGE plpgsql 'BEGIN PERFORM 1; END;' LANGUAGE plpgsql;\n",
		},
	}
	for _, test := range nonCanonicalLanguageDOs {
		assertRejectedDO(test.name, test.statement)
	}
	singleQuotedDynamicSQL := []struct{ name, body string }{
		{"add", `BEGIN EXECUTE 'ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_status text'; END;`},
		{"create", `BEGIN EXECUTE 'CREATE TRIGGER dynamic_guard AFTER UPDATE ON public.asset_sources FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state()'; END;`},
		{"drop", `BEGIN EXECUTE 'DROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources'; END;`},
		{"alter", `BEGIN EXECUTE 'ALTER TRIGGER asset_sources_deferred_state_guard ON public.asset_sources RENAME TO dynamic_guard'; END;`},
		{"enable", `BEGIN EXECUTE format('ALTER TABLE public.asset_sources ENABLE TRIGGER %I', 'asset_sources_deferred_state_guard'); END;`},
		{"disable", `BEGIN EXECUTE 'ALTER TABLE public.asset_sources DISABLE ' || 'TRIGGER asset_sources_deferred_state_guard'; END;`},
	}
	singleQuotedDynamicForms := []struct {
		name string
		do   func(string) string
	}{
		{"single quoted", singleQuotedDO},
		{"escape quoted", escapeQuotedDO},
	}
	for _, form := range singleQuotedDynamicForms {
		for _, test := range singleQuotedDynamicSQL {
			t.Run("discriminator rejects "+form.name+" dynamic "+test.name, func(t *testing.T) {
				if required, err := correctiveSourceGateTriggerRequired(currentUp + form.do(test.body)); err == nil {
					t.Fatalf("gate-column discriminator = %t, nil; want dynamic %s error", required, test.name)
				}
			})
			t.Run("up rejects "+form.name+" dynamic "+test.name, func(t *testing.T) {
				if _, diagnostics := correctiveParsedTriggerIdentities(successorUp + form.do(test.body)); len(diagnostics) == 0 {
					t.Fatalf("successor up manifest accepted %s dynamic %s", form.name, test.name)
				}
			})
			t.Run("down rejects "+form.name+" dynamic "+test.name, func(t *testing.T) {
				got := correctiveDroppedTriggerIdentities(successorDown + form.do(test.body))
				want := correctiveExpectedDroppedTriggerIdentitiesForMigration(t, successorUp)
				if correctiveSQLObjectSetsEqual(got, want) {
					t.Fatalf("successor down manifest accepted %s dynamic %s", form.name, test.name)
				}
			})
		}
	}
	directSQLDOForms := []struct {
		name string
		do   func(string) string
	}{
		{"dollar quoted", dynamicDO},
		{"single quoted", func(statement string) string {
			return singleQuotedDO("BEGIN\n" + statement + "\nEND;")
		}},
		{"escape quoted", func(statement string) string {
			return escapeQuotedDO("BEGIN\n" + statement + "\nEND;")
		}},
	}
	directSQLStatements := []struct{ name, statement string }{
		{"add", "ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_status text;"},
		{"create table", "CREATE TABLE public.asset_source_review_probe (id integer);"},
		{"drop table", "DROP TABLE public.asset_source_review_probe;"},
		{"create", "CREATE TRIGGER dynamic_guard AFTER UPDATE ON public.asset_sources FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state();"},
		{"drop", "DROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources;"},
		{"alter", "ALTER TRIGGER asset_sources_deferred_state_guard ON public.asset_sources RENAME TO dynamic_guard;"},
		{"enable", "ALTER TABLE public.asset_sources ENABLE TRIGGER asset_sources_deferred_state_guard;"},
		{"disable", "ALTER TABLE public.asset_sources DISABLE TRIGGER asset_sources_deferred_state_guard;"},
		{"reviewer temp view", "CREATE TEMP VIEW codex_review_unknown_ddl_e7c AS SELECT 1;"},
		{"index", "CREATE INDEX codex_review_unknown_ddl_index ON public.asset_sources (id);"},
		{"type", "CREATE TYPE public.codex_review_unknown_ddl_type AS ENUM ('review');"},
		{"sequence", "CREATE SEQUENCE public.codex_review_unknown_ddl_sequence;"},
		{"function", "ALTER FUNCTION public.asset_catalog_text_valid(text, integer) STABLE;"},
		{"grant", "GRANT SELECT ON public.asset_sources TO aiops_control_plane_runtime;"},
		{"revoke", "REVOKE SELECT ON public.asset_sources FROM aiops_control_plane_runtime;"},
		{"comment", "COMMENT ON TABLE public.asset_sources IS 'review';"},
		{"lock", "LOCK TABLE public.asset_sources IN ACCESS SHARE MODE;"},
		{"truncate", "TRUNCATE TABLE public.asset_sources;"},
		{"set local", "SET LOCAL application_name = 'codex_review';"},
	}
	for _, form := range directSQLDOForms {
		for _, sql := range directSQLStatements {
			assertRejectedDO("direct "+form.name+" "+sql.name, form.do(sql.statement))
		}
	}
	codeBodyDOForms := []struct {
		name string
		do   func(string) string
	}{
		{"dollar quoted", func(body string) string {
			return "\nDO $$\n" + body + "\n$$ LANGUAGE plpgsql;\n"
		}},
		{"single quoted", singleQuotedDO},
		{"escape quoted", escapeQuotedDO},
	}
	safeCodeBodies := []struct{ name, body string }{
		{
			"empty declare",
			`DECLARE
BEGIN
    PERFORM 1;
END;`,
		},
		{
			"declare identifier",
			`DECLARE
    comment text := 'safe';
BEGIN
    RAISE NOTICE '%', comment;
END;`,
		},
		{
			"assignment identifier",
			`DECLARE
    comment text;
BEGIN
    comment := 'safe';
    PERFORM length(comment);
END;`,
		},
		{
			"quoted assignment identifier",
			`DECLARE
    "target" text;
    comment text := 'safe';
BEGIN
    "target" := comment;
    PERFORM length("target");
END;`,
		},
		{
			"update set",
			`BEGIN
    UPDATE public.asset_sources
    SET updated_at = updated_at
    WHERE false;
END;`,
		},
		{
			"select alias",
			`DECLARE
    selected integer;
BEGIN
    SELECT 1 AS comment INTO selected;
    PERFORM selected;
END;`,
		},
		{
			"select execute alias",
			`DECLARE
    selected integer;
BEGIN
    SELECT 1 AS execute INTO selected;
    PERFORM selected;
END;`,
		},
		{
			"unicode identifier",
			`DECLARE
    λcomment integer := 0;
BEGIN
    λcomment := 1;
END;`,
		},
		{
			"high-bit identifier",
			`DECLARE
    😀comment integer := 0;
BEGIN
    😀comment := 1;
END;`,
		},
		{
			"option dump directive",
			`#option dump BEGIN
    PERFORM 1;
END;`,
		},
		{
			"same-line variable conflict directive",
			`#variable_conflict use_variable BEGIN
    PERFORM 1;
END;`,
		},
		{
			"same-line print strict params directive",
			`#print_strict_params on BEGIN
    PERFORM 1;
END;`,
		},
		{
			"quoted print strict params on directive",
			`#print_strict_params "on" BEGIN
    PERFORM 1;
END;`,
		},
		{
			"quoted print strict params off directive",
			`#print_strict_params "off" BEGIN
    PERFORM 1;
END;`,
		},
		{
			"adjacent quoted print strict params directive",
			`#print_strict_params "on"BEGIN
    PERFORM 1;
END;`,
		},
	}
	for _, form := range codeBodyDOForms {
		for _, body := range safeCodeBodies {
			assertSafeDOPaths(form.name+" "+body.name, form.do(body.body))
		}
	}
	controlBoundaryDDL := []struct{ name, body string }{
		{
			"if then",
			`BEGIN
    IF true THEN
        CREATE TEMP VIEW codex_review_if_ddl AS SELECT 1;
    END IF;
END;`,
		},
		{
			"else",
			`BEGIN
    IF false THEN
        NULL;
    ELSE
        GRANT SELECT ON public.asset_sources TO aiops_control_plane_runtime;
    END IF;
END;`,
		},
		{
			"elseif",
			`BEGIN
    IF false THEN
        NULL;
    ELSEIF true THEN
        CREATE TEMP VIEW codex_review_elseif_bypass AS SELECT 1;
    END IF;
END;`,
		},
		{
			"high-bit then identifier",
			`DECLARE
    😀then integer := 1;
BEGIN
    IF 😀then = 1 THEN
        CREATE TEMP VIEW codex_review_high_bit_then_bypass AS SELECT 1;
    END IF;
END;`,
		},
		{
			"dollar tag inside identifier",
			`BEGIN
    PERFORM 1 AS safe$mask$alias;
    CREATE TEMP VIEW codex_review_dollar_identifier_bypass AS SELECT 1;
END;`,
		},
		{
			"variable conflict directive",
			`#variable_conflict use_variable
BEGIN
    CREATE TEMP VIEW codex_review_variable_conflict_bypass AS SELECT 1;
END;`,
		},
		{
			"print strict params directive",
			`#print_strict_params on
BEGIN
    CREATE TEMP VIEW codex_review_print_strict_params_bypass AS SELECT 1;
END;`,
		},
		{
			"same-line option dump directive",
			`#option dump BEGIN
    CREATE TEMP VIEW codex_review_option_dump_bypass AS SELECT 1;
END;`,
		},
		{
			"quoted print strict params directive",
			`#print_strict_params "on" BEGIN
    CREATE TEMP VIEW codex_review_quoted_print_strict_params_bypass AS SELECT 1;
END;`,
		},
		{
			"adjacent quoted print strict params directive",
			`#print_strict_params "on"BEGIN
    CREATE TEMP VIEW codex_review_adjacent_quoted_print_strict_params_bypass AS SELECT 1;
END;`,
		},
		{
			"loop",
			`BEGIN
    LOOP
        DROP VIEW codex_review_loop_ddl;
        EXIT;
    END LOOP;
END;`,
		},
		{
			"exception",
			`BEGIN
    BEGIN
        PERFORM 1;
    EXCEPTION WHEN OTHERS THEN
        ALTER FUNCTION public.asset_catalog_text_valid(text, integer) STABLE;
    END;
END;`,
		},
		{
			"empty declare",
			`DECLARE
BEGIN
    CREATE TEMP VIEW codex_review_empty_declare_bypass AS SELECT 1;
    BEGIN
        PERFORM 1;
    END;
END;`,
		},
		{
			"for dynamic execute",
			`DECLARE
    selected record;
BEGIN
    FOR selected IN EXECUTE 'SELECT 1' LOOP
        EXIT;
    END LOOP;
END;`,
		},
	}
	for _, form := range codeBodyDOForms {
		for _, boundary := range controlBoundaryDDL {
			assertRejectedDO("direct "+form.name+" control "+boundary.name, form.do(boundary.body))
		}
	}
	escapeEncodedExecuteForms := []struct{ name, execute string }{
		{"octal", `\105XECUTE`},
		{"hex", `\x45XECUTE`},
		{"short unicode", `\u0045XECUTE`},
		{"long unicode", `\U00000045XECUTE`},
		{"other character", `\EXECUTE`},
	}
	escapeEncodedDDL := []struct{ name, sql string }{
		{"add", "ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_status text"},
		{"create", "CREATE TRIGGER dynamic_guard AFTER UPDATE ON public.asset_sources FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state()"},
		{"drop", "DROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources"},
		{"alter", "ALTER TRIGGER asset_sources_deferred_state_guard ON public.asset_sources RENAME TO dynamic_guard"},
		{"enable", "ALTER TABLE public.asset_sources ENABLE TRIGGER asset_sources_deferred_state_guard"},
		{"disable", "ALTER TABLE public.asset_sources DISABLE TRIGGER asset_sources_deferred_state_guard"},
	}
	for _, form := range escapeEncodedExecuteForms {
		for _, ddl := range escapeEncodedDDL {
			statement := "\nDO E'BEGIN " + form.execute + " \\'" + ddl.sql + "\\'; END;' LANGUAGE plpgsql;\n"
			assertRejectedDO("escape "+form.name+" dynamic "+ddl.name, statement)
		}
	}
	invalidEscapeDOs := []struct{ name, statement string }{
		{"trailing escape backslash", "\nDO E'BEGIN PERFORM 1; END;\\"},
		{"escape hex without digit", "\nDO E'BEGIN PERFORM \\x; END;' LANGUAGE plpgsql;\n"},
		{"truncated short unicode escape", "\nDO E'BEGIN PERFORM \\u123; END;' LANGUAGE plpgsql;\n"},
		{"truncated long unicode escape", "\nDO E'BEGIN PERFORM \\U0001234; END;' LANGUAGE plpgsql;\n"},
		{"unicode escape above maximum", "\nDO E'BEGIN PERFORM \\U00110000; END;' LANGUAGE plpgsql;\n"},
		{"unicode NUL escape", "\nDO E'BEGIN PERFORM \\u0000; END;' LANGUAGE plpgsql;\n"},
		{"unpaired unicode surrogate escape", "\nDO E'BEGIN PERFORM \\uD800; END;' LANGUAGE plpgsql;\n"},
		{"unpaired long unicode surrogate escape", "\nDO E'BEGIN PERFORM \\U0000DC00; END;' LANGUAGE plpgsql;\n"},
		{"octal low byte NUL escape", "\nDO E'BEGIN PERFORM \\400; END;' LANGUAGE plpgsql;\n"},
		{"invalid UTF-8 escape byte", "\nDO E'BEGIN PERFORM \\377; END;' LANGUAGE plpgsql;\n"},
		{"invalid UTF-8 low escape byte", "\nDO E'BEGIN PERFORM \\777; END;' LANGUAGE plpgsql;\n"},
	}
	for _, test := range invalidEscapeDOs {
		assertRejectedDO(test.name, test.statement)
	}
	safeDOBodies := []struct{ name, body string }{
		{"ordinary", "    PERFORM 1;"},
		{"single quote", "    RAISE NOTICE 'EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET';"},
		{"escape string", `    RAISE NOTICE E'EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET';`},
		{"line comment", "    -- EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET\n    PERFORM 1;"},
		{"block comment", "    /* EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET */\n    PERFORM 1;"},
		{"nested dollar quote", "    PERFORM $inner$EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET$inner$;"},
	}
	for _, test := range safeDOBodies {
		t.Run("safe do "+test.name+" preserves manifests", func(t *testing.T) {
			safeDO := dynamicDO(test.body)
			up := strings.Replace(successorUp, "RESET ROLE;", safeDO+"RESET ROLE;", 1)
			required, err := correctiveSourceGateTriggerRequired(up)
			if err != nil || !required {
				t.Fatalf("safe DO discriminator = %t, %v; want true, nil", required, err)
			}
			gotUp, diagnostics := correctiveParsedTriggerIdentities(up)
			if len(diagnostics) != 0 || !correctiveSQLObjectSetsEqual(gotUp, correctiveExpectedTriggerIdentitiesForMigration(t, up)) {
				t.Fatalf("safe DO changed up manifest: diagnostics=%v", diagnostics)
			}
			down := strings.Replace(successorDown, dropAnchor, safeDO+dropAnchor, 1)
			if got := correctiveDroppedTriggerIdentities(down); !correctiveSQLObjectSetsEqual(got, correctiveExpectedDroppedTriggerIdentitiesForMigration(t, up)) {
				t.Fatal("safe DO changed down manifest")
			}
		})
	}
	safeSingleQuotedDOs := []struct{ name, statement string }{
		{"default language", "\nDO 'BEGIN PERFORM 1; END;';\n"},
		{"prefix language", "\nDO LANGUAGE plpgsql 'BEGIN PERFORM 1; END;';\n"},
		{"tail language", singleQuotedDO("BEGIN PERFORM 1; END;")},
		{"doubled quote", singleQuotedDO("BEGIN RAISE NOTICE 'it''s EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET'; PERFORM 1; END;")},
		{"escape string", escapeQuotedDO("BEGIN\nRAISE NOTICE E'EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET\\n';\nPERFORM 1;\nEND;")},
		{"escape octal", `DO E'BEGIN PERFORM \061; END;' LANGUAGE plpgsql;`},
		{"escape octal low byte", `DO E'BEGIN PERFORM \501; END;' LANGUAGE plpgsql;`},
		{"escape hex", `DO E'BEGIN PERFORM \x31; END;' LANGUAGE plpgsql;`},
		{"escape unicode", `DO E'BEGIN RAISE NOTICE \'\u03bb\'; PERFORM 1; END;' LANGUAGE plpgsql;`},
		{"escape long unicode", `DO E'BEGIN RAISE NOTICE \'\U0001F642\'; PERFORM 1; END;' LANGUAGE plpgsql;`},
		{"escape mixed long short surrogate", `DO E'BEGIN RAISE NOTICE \'\U0000D83D\uDE42\'; PERFORM 1; END;' LANGUAGE plpgsql;`},
		{"escape mixed short long surrogate", `DO E'BEGIN RAISE NOTICE \'\uD83D\U0000DE42\'; PERFORM 1; END;' LANGUAGE plpgsql;`},
		{"escape long surrogate pair", `DO E'BEGIN RAISE NOTICE \'\U0000D83D\U0000DE42\'; PERFORM 1; END;' LANGUAGE plpgsql;`},
		{"escape outer line comment", escapeQuotedDO("BEGIN\n-- EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET\nPERFORM 1;\nEND;")},
		{"escape outer block comment", escapeQuotedDO("BEGIN\n/* EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET */\nPERFORM 1;\nEND;")},
		{"escape outer nested dollar quote", escapeQuotedDO("BEGIN PERFORM $inner$EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET$inner$; END;")},
		{"line comment", singleQuotedDO("BEGIN\n-- EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET\nPERFORM 1;\nEND;")},
		{"block comment", singleQuotedDO("BEGIN\n/* EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET */\nPERFORM 1;\nEND;")},
		{"nested dollar quote", singleQuotedDO("BEGIN PERFORM $inner$EXECUTE CREATE ALTER DROP GRANT REVOKE COMMENT LOCK SET$inner$; END;")},
	}
	for _, test := range safeSingleQuotedDOs {
		assertSafeDO("single quoted do "+test.name, test.statement)
	}
	assertSafeDO("procedural statements", `
DO $$
DECLARE
    safe_counter integer := 0;
BEGIN
    safe_counter := safe_counter + 1;
    IF safe_counter = 1 THEN
        PERFORM 1;
    ELSE
        NULL;
    END IF;
    FOR safe_counter IN 1..2 LOOP
        CONTINUE WHEN safe_counter = 1;
        EXIT WHEN safe_counter = 2;
    END LOOP;
    ASSERT safe_counter = 2;
END;
$$ LANGUAGE plpgsql;
`)
	validEscapeStrings := []struct {
		name, input, want string
	}{
		{"controls quote and backslash", `E'\b\f\n\r\t\'\\'`, "\b\f\n\r\t'\\"},
		{"one to three digit octal", `E'\1\12\101'`, "\x01\nA"},
		{"three digit octal low byte", `E'\501'`, "A"},
		{"three digit octal low byte UTF-8", `E'\703\651'`, "é"},
		{"octal maximum width boundary", `E'\1234'`, "S4"},
		{"one to two digit hex", `E'\x4\x41'`, "\x04A"},
		{"hex maximum width boundary", `E'\x414'`, "A4"},
		{"octal UTF-8 bytes", `E'\303\251'`, "é"},
		{"hex UTF-8 bytes", `E'\xC3\xA9'`, "é"},
		{"four digit unicode", `E'\u03bb'`, "λ"},
		{"eight digit unicode", `E'\U0001F642'`, "🙂"},
		{"unicode surrogate pair", `E'\uD83D\uDE42'`, "🙂"},
		{"long short unicode surrogate pair", `E'\U0000D83D\uDE42'`, "🙂"},
		{"short long unicode surrogate pair", `E'\uD83D\U0000DE42'`, "🙂"},
		{"long unicode surrogate pair", `E'\U0000D83D\U0000DE42'`, "🙂"},
		{"other escaped character", `E'\q'`, "q"},
		{"newline continuation", "E'one\\\ntwo'", "onetwo"},
		{"CRLF continuation", "E'one\\\r\ntwo'", "onetwo"},
	}
	for _, test := range validEscapeStrings {
		t.Run("escape string decoder accepts "+test.name, func(t *testing.T) {
			got, end, ok := correctiveSingleQuotedSQLLiteral(test.input, 1)
			if !ok || end != len(test.input) || got != test.want {
				t.Fatalf("correctiveSingleQuotedSQLLiteral(%q) = %q, %d, %t; want %q, %d, true",
					test.input, got, end, ok, test.want, len(test.input))
			}
		})
	}
	invalidEscapeStrings := []struct{ name, input string }{
		{"trailing backslash", `E'abc\`},
		{"hex without digit", `E'\x'`},
		{"truncated short unicode", `E'\u123'`},
		{"truncated long unicode", `E'\U0001234'`},
		{"unicode above maximum", `E'\U00110000'`},
		{"unicode NUL", `E'\u0000'`},
		{"unpaired high surrogate", `E'\uD800'`},
		{"unpaired low surrogate", `E'\uDC00'`},
		{"unpaired long high surrogate", `E'\U0000D800'`},
		{"unpaired long low surrogate", `E'\U0000DC00'`},
		{"invalid surrogate pair", `E'\uD800\u0041'`},
		{"octal low byte NUL", `E'\400'`},
		{"octal NUL", `E'\000'`},
		{"invalid UTF-8 byte", `E'\377'`},
		{"invalid UTF-8 low byte", `E'\777'`},
	}
	for _, test := range invalidEscapeStrings {
		t.Run("escape string decoder rejects "+test.name, func(t *testing.T) {
			if got, end, ok := correctiveSingleQuotedSQLLiteral(test.input, 1); ok {
				t.Fatalf("correctiveSingleQuotedSQLLiteral(%q) = %q, %d, true; want rejection", test.input, got, end)
			}
		})
	}
	if correctiveSQLObjectSetsEqual(
		correctiveDroppedTriggerIdentities(successorDown),
		correctiveExpectedDroppedTriggerIdentitiesForMigration(t, currentUp),
	) {
		t.Fatal("baseline down manifest accepted premature successor trigger drop")
	}

	quotedAliases := strings.NewReplacer(
		"gate_evidence_run_id", `"Gate_Evidence_Run_ID"`,
		"gate_evidence_digest", `"Gate_Evidence_Digest"`,
		"gate_evidence_expires_at", `"Gate_Evidence_Expires_At"`,
	).Replace(successorColumns)
	invalidColumns := []struct{ name, columns string }{
		{"partial tuple", "gate_evidence_run_id uuid"},
		{"wrong type", strings.Replace(successorColumns, "run_id uuid", "run_id text", 1)},
		{"non nullable", strings.Replace(successorColumns, "run_id uuid", "run_id uuid NOT NULL", 1)},
		{"fourth alias", successorColumns + ",\n    gate_evidence_status text"},
		{"quoted case aliases", quotedAliases},
		{"quoted uppercase schema", columnList(`"PG_CATALOG".uuid`, "text", "timestamptz")},
		{"quoted uppercase type", columnList(`pg_catalog."UUID"`, "text", "timestamptz")},
		{"other schema", columnList("unreviewed.uuid", "text", "timestamptz")},
		{"array type", columnList("uuid[]", "text", "timestamptz")},
		{"type modifier", columnList("uuid", "text", "timestamptz(6)")},
	}
	for _, test := range invalidColumns {
		t.Run("discriminator rejects "+test.name, func(t *testing.T) {
			fixture := correctiveSourceGateColumnsFixture(t, currentUp, test.columns)
			if required, err := correctiveSourceGateTriggerRequired(fixture); err == nil {
				t.Fatalf("gate-column discriminator = %t, nil; want invalid %s error", required, test.name)
			}
		})
	}

	invalidAlters := []struct{ name, up string }{
		{"partial alter", currentUp + "\nALTER TABLE public.asset_sources ADD COLUMN gate_evidence_run_id uuid;\n"},
		{"wrong alter type", currentUp + strings.Replace(alterColumns, "run_id uuid", "run_id text", 1)},
		{"duplicate mixed column", correctiveSourceGateColumnsFixture(t, currentUp, successorColumns) + "\nALTER TABLE public.asset_sources ADD COLUMN gate_evidence_run_id uuid;\n"},
		{"unknown alter column", currentUp + alterColumns + "\nALTER TABLE public.asset_sources ADD COLUMN gate_evidence_status text;\n"},
		{"unreviewed alter column", correctiveSourceGateColumnsFixture(t, currentUp, successorColumns) + "\nALTER TABLE public.asset_sources ALTER COLUMN gate_evidence_run_id TYPE text;\n"},
		{"dynamic exact3 alter", currentUp + dynamicDO(`
    EXECUTE 'ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_run_id uuid';
    EXECUTE format('ALTER TABLE public.asset_sources ADD COLUMN %I text', 'gate_evidence_digest');
    EXECUTE 'ALTER TABLE public.asset_sources ADD COLUMN gate_evidence_' || 'expires_at timestamptz';`)},
	}
	for _, test := range invalidAlters {
		t.Run("discriminator rejects "+test.name, func(t *testing.T) {
			if required, err := correctiveSourceGateTriggerRequired(test.up); err == nil {
				t.Fatalf("gate-column discriminator = %t, nil; want invalid %s error", required, test.name)
			}
		})
	}
}

func TestAssetCatalogCorrectiveSourceGateSuccessorFixtureReusesFormalState(t *testing.T) {
	currentUp := readMigration(t, "000015_assets_catalog.up.sql")
	currentDown := readMigration(t, "000015_assets_catalog.down.sql")
	columns := `
    gate_evidence_run_id uuid,
    gate_evidence_digest text,
    gate_evidence_expires_at timestamptz`
	trigger := `
CREATE CONSTRAINT TRIGGER asset_sources_gate_evidence_closure_guard
AFTER INSERT OR UPDATE ON public.asset_sources
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state();
	`
	dropAnchor := "DROP TRIGGER asset_sources_deferred_state_guard ON public.asset_sources;"
	drop := "\nDROP TRIGGER asset_sources_gate_evidence_closure_guard ON public.asset_sources;\n"

	formalUp, formalDown, err := correctiveSourceGateSuccessorTriggerFixture(
		t, currentUp, currentDown, columns, trigger, dropAnchor, drop,
	)
	if err != nil {
		t.Fatalf("construct formal successor fixture from baseline: %v", err)
	}
	gotUp, gotDown, err := correctiveSourceGateSuccessorTriggerFixture(
		t, formalUp, formalDown, columns, trigger, dropAnchor, drop,
	)
	if err != nil {
		t.Fatalf("reuse formal successor fixture: %v", err)
	}
	if gotUp != formalUp || gotDown != formalDown {
		t.Fatalf(
			"formal successor fixture was reconstructed: run-id=%d digest=%d expires=%d trigger=%d drop=%d; want byte-for-byte reuse",
			strings.Count(gotUp, "gate_evidence_run_id"),
			strings.Count(gotUp, "gate_evidence_digest"),
			strings.Count(gotUp, "gate_evidence_expires_at"),
			strings.Count(gotUp, "CREATE CONSTRAINT TRIGGER asset_sources_gate_evidence_closure_guard"),
			strings.Count(gotDown, "DROP TRIGGER asset_sources_gate_evidence_closure_guard"),
		)
	}

	partialUp := correctiveSourceGateColumnsFixture(t, currentUp, "gate_evidence_run_id uuid")
	duplicateColumnsUp := correctiveSourceGateColumnsFixture(t, formalUp, columns)
	extraTrigger := `
CREATE TRIGGER asset_sources_gate_evidence_extra_guard
AFTER UPDATE ON public.asset_sources
FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state();
`
	dynamicTrigger := `
DO $$
BEGIN
    EXECUTE 'CREATE TRIGGER dynamic_guard AFTER UPDATE ON public.asset_sources FOR EACH ROW EXECUTE FUNCTION public.validate_asset_source_deferred_state()';
END;
$$;
`
	replaceFormalTrigger := func(old, replacement string) string {
		return strings.Replace(formalUp, trigger, strings.Replace(trigger, old, replacement, 1), 1)
	}
	rejected := []struct {
		name string
		up   string
		down string
	}{
		{"partial columns", partialUp, currentDown},
		{"duplicate columns", duplicateColumnsUp, formalDown},
		{"aliased column", strings.Replace(formalUp, "gate_evidence_run_id uuid", "gate_evidence_run_alias uuid", 1), formalDown},
		{"wrong column type", strings.Replace(formalUp, "gate_evidence_run_id uuid", "gate_evidence_run_id text", 1), formalDown},
		{"renamed trigger", strings.Replace(formalUp, "asset_sources_gate_evidence_closure_guard", "asset_sources_gate_evidence_closure_guard_wrong", 1), formalDown},
		{"wrong trigger relation", replaceFormalTrigger("ON public.asset_sources", "ON public.asset_source_runs"), formalDown},
		{"wrong trigger caller", replaceFormalTrigger("public.validate_asset_source_deferred_state()", "public.validate_asset_source_revision_deferred_state()"), formalDown},
		{"wrong trigger lifecycle", replaceFormalTrigger("DEFERRABLE INITIALLY DEFERRED", "NOT DEFERRABLE INITIALLY IMMEDIATE"), formalDown},
		{"duplicate trigger", formalUp + trigger, formalDown},
		{"extra trigger object", formalUp + extraTrigger, formalDown},
		{"dynamic trigger DDL", formalUp + dynamicTrigger, formalDown},
		{"formal up with baseline down", formalUp, currentDown},
		{"baseline up with formal down", currentUp, formalDown},
		{"wrong down relation", formalUp, strings.Replace(formalDown, drop, strings.Replace(drop, "ON public.asset_sources", "ON public.asset_source_runs", 1), 1)},
		{"duplicate down drop", formalUp, strings.Replace(formalDown, dropAnchor, dropAnchor+drop, 1)},
		{"dynamic down DDL", formalUp, formalDown + dynamicTrigger},
	}
	for _, test := range rejected {
		t.Run("rejects "+test.name, func(t *testing.T) {
			if _, _, err := correctiveSourceGateSuccessorTriggerFixture(
				t, test.up, test.down, columns, trigger, dropAnchor, drop,
			); err == nil {
				t.Fatalf("successor fixture construction accepted %s state", test.name)
			}
		})
	}
}

func TestAssetCatalogCorrectiveOwnsNormalizedLimiterBucketAndPermitTruth(t *testing.T) {
	up := readMigration(t, "000015_assets_catalog.up.sql")
	buckets := correctiveNormalizeSQL(correctiveRequireTable(t, up, "public.asset_source_limit_buckets"))
	permits := correctiveNormalizeSQL(correctiveRequireTable(t, up, "public.asset_source_limit_permits"))

	correctiveRequireTokens(t, "Limiter bucket truth", buckets,
		"bucket_kind text not null",
		"bucket_key text not null",
		"source_id uuid",
		"provider_kind text",
		"next_token_at timestamptz not null",
		"last_receipt_id uuid",
		"version bigint not null default 1",
		"unique (tenant_id, workspace_id, bucket_kind, bucket_key)",
		"asset_source_limit_buckets_scope_key_ck",
		"asset_source_limit_buckets_time_ck",
	)
	correctiveRequireTokens(t, "Limiter permit/receipt truth", permits,
		"permit_id uuid not null",
		"record_kind text not null",
		"'acquire'",
		"'release'",
		"'delay'",
		"'expire'",
		"source_bucket_id uuid not null",
		"workspace_bucket_id uuid not null",
		"provider_bucket_id uuid not null",
		"request_id text not null",
		"command_sha256 text not null",
		"receipt_sha256 text not null",
		"acquired_at timestamptz not null",
		"expires_at timestamptz not null",
		"not_before timestamptz",
		"terminal_reason_code text",
		"asset_source_limit_permits_acquire_exact_fk",
		"asset_source_limit_permits_record_shape_ck",
		"asset_source_limit_permits_time_ck",
	)
	correctiveRequireTokens(t, "Limiter terminal uniqueness", correctiveNormalizeSQL(up),
		"create unique index asset_source_limit_permits_one_terminal_uk",
		"where record_kind in ('release', 'delay', 'expire')",
		"add constraint asset_source_limit_buckets_last_receipt_fk",
		"foreign key (tenant_id, workspace_id, last_receipt_id)",
		"references public.asset_source_limit_permits (tenant_id, workspace_id, id)",
		"on delete restrict",
		"deferrable initially immediate",
	)

	edge := correctiveNormalizeSQL(
		correctiveRequireFunction(t, up, "public.enforce_asset_catalog_edge_mutation").body,
	)
	correctiveRequireTokens(t, "Limiter bucket CAS guard", edge,
		"tg_table_name = 'asset_source_limit_buckets'",
		"new.last_receipt_id",
		"public.asset_source_limit_permits",
		"new.next_token_at < old.next_token_at",
		"new.version <> old.version + 1",
		"asset_source_limit_buckets_identity_guard",
		"asset_source_limit_buckets_receipt_guard",
		"asset_source_limit_buckets_version_guard",
		"asset_source_limit_buckets_token_monotonic_guard",
	)
}

func TestAssetCatalogCorrectiveAllowsOnlyCanonicalEmptyRepeatedRelationPageDigest(t *testing.T) {
	if got := assetCatalogCorrectiveFramedDigest(
		[]byte("asset-relation-page.v1"), []byte("0"),
	); got != correctiveCanonicalEmptyRelationPageSHA256 {
		t.Fatalf("canonical empty relation-page digest = %q, want %q", got, correctiveCanonicalEmptyRelationPageSHA256)
	}

	up := readMigration(t, "000015_assets_catalog.up.sql")
	body := correctiveStripSQLComments(
		correctiveRequireFunction(t, up, "public.enforce_asset_source_run_mutation").body,
	)
	equalityPattern := regexp.MustCompile(
		`(?is)new\s*\.\s*relation_page_digest\s+is\s+not\s+distinct\s+from\s+old\s*\.\s*relation_page_digest`,
	)
	guardedPattern := regexp.MustCompile(
		`(?is)new\s*\.\s*relation_page_digest\s+is\s+not\s+distinct\s+from\s+old\s*\.\s*relation_page_digest\s+and\s+new\s*\.\s*relation_page_digest\s+is\s+distinct\s+from\s+'` +
			correctiveCanonicalEmptyRelationPageSHA256 + `'`,
	)
	equalityCount := len(equalityPattern.FindAllString(body, -1))
	guardedCount := len(guardedPattern.FindAllString(body, -1))
	if equalityCount != 2 {
		t.Errorf("relation-page equality rejection count = %d, want exact snapshot and page-advance predicates", equalityCount)
	}
	if guardedCount != 2 {
		t.Errorf("canonical-empty guarded equality count = %d, want 2; %d equality rejections remain unconditional",
			guardedCount, equalityCount-guardedCount)
	}
	if literalCount := strings.Count(body, correctiveCanonicalEmptyRelationPageSHA256); literalCount != 2 {
		t.Errorf("canonical empty relation-page literal count = %d, want exact two guarded predicates", literalCount)
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
	up := readMigration(t, "000015_assets_catalog.up.sql")
	downRaw := readMigration(t, "000015_assets_catalog.down.sql")
	down := correctiveNormalizeSQL(downRaw)
	down = strings.ReplaceAll(down, "timestamptz", "timestamp with time zone")
	locks := correctiveDownLockStatements(downRaw)
	if len(locks) != 1 {
		t.Errorf("down LOCK TABLE statement count = %d, want exactly one", len(locks))
	} else {
		want := "lock table public.tenants, public.workspaces, public.environments, public.integrations, public.services, public.service_bindings, public.audit_records, public.outbox_events, public.asset_sources, public.asset_source_revisions, public.asset_source_revision_authorities, public.asset_source_runs, public.asset_source_limit_buckets, public.asset_source_limit_permits, public.asset_observations, public.assets, public.asset_type_details, public.asset_conflicts, public.asset_relationships, public.service_asset_bindings in access exclusive mode nowait;"
		if locks[0] != want {
			t.Errorf("down one-shot lock = %q, want exact 20-relation NOWAIT lock", locks[0])
		}
	}
	if strings.Contains(down, " cascade") {
		t.Error("down migration must not use CASCADE")
	}

	assertExactSQLObjectSet(t, "down dropped trigger manifest",
		correctiveDroppedTriggerIdentities(downRaw),
		correctiveExpectedDroppedTriggerIdentitiesForMigration(t, up),
	)
	assertExactSQLObjectSet(
		t,
		"down dropped routine manifest",
		correctiveDroppedRoutineIdentities(downRaw),
		correctiveExpectedRoutineIdentitiesForMigration(t, up),
	)
	correctiveAssertOrdered(t, "cycle-breaking foreign keys", down, []string{
		"drop constraint asset_source_limit_buckets_last_receipt_fk",
		"drop constraint asset_sources_published_revision_fk",
		"drop constraint asset_sources_validated_run_fk",
		"drop constraint asset_sources_last_success_run_fk",
		"drop constraint asset_sources_last_complete_snapshot_run_fk",
		"drop constraint asset_source_revisions_validation_run_fk",
	})
	correctiveAssertBefore(t,
		"drop constraint asset_source_limit_buckets_last_receipt_fk",
		"drop table public.asset_source_limit_permits",
		down,
	)
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
	correctiveAssertOrdered(t, "child-first twelve-table drop order", down, []string{
		"drop table public.service_asset_bindings",
		"drop table public.asset_relationships",
		"drop table public.asset_conflicts",
		"drop table public.asset_type_details",
		"drop table public.assets",
		"drop table public.asset_observations",
		"drop table public.asset_source_limit_permits",
		"drop table public.asset_source_limit_buckets",
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
		"grant update (next_token_at, last_receipt_id, version, updated_at) on public.asset_source_limit_buckets to aiops_control_plane_runtime",
		"public.asset_catalog_lock_exact_service_binding(uuid, uuid, uuid, uuid)",
	)
	if strings.Contains(up, "grant update on table public.asset_source_limit_buckets") ||
		strings.Contains(up, "grant update on table public.asset_source_limit_permits") ||
		strings.Contains(up, "grant update on table public.services") ||
		strings.Contains(up, "grant update on table public.service_bindings") {
		t.Error("runtime ACL grants an unreviewed broad UPDATE surface")
	}
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
const correctivePLpgSQLUnquotedIdentifierPattern = `(?:[A-Za-z_]|[^\x00-\x7F])(?:[A-Za-z0-9_$]|[^\x00-\x7F])*`
const correctivePLpgSQLIdentifierPattern = `(?:"(?:""|[^"])+"|` + correctivePLpgSQLUnquotedIdentifierPattern + `)`
const correctiveTriggerLifecycleStatementPattern = `(?is)^\s*(?:create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\b|` +
	`drop\s+trigger\b|alter\s+trigger\b|alter\s+table\b.+?\b(?:enable|disable)\s+(?:(?:always|replica)\s+)?trigger\b)`

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
			tag := correctiveDollarQuoteAt(sql, index)
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

func correctiveDOExecutesDynamicSQL(statement string) bool {
	doPrefix := regexp.MustCompile(`(?is)^\s*do\b`).FindStringIndex(statement)
	if doPrefix == nil {
		return false
	}
	body, ok := correctiveDOCodeBody(statement[doPrefix[1]:])
	if !ok {
		return true
	}
	code := correctiveMaskNonCodePLpgSQL(body)
	declaration := false
	for _, sql := range correctiveTopLevelSQLStatements(code) {
		if correctiveDOStatementExecutesUnreviewedSQL(sql, &declaration) {
			return true
		}
	}
	return declaration
}

func correctiveDOStatementExecutesUnreviewedSQL(statement string, declaration *bool) bool {
	statement = correctiveTrimPLpgSQLLabels(statement)
	for len(statement) > 0 {
		if strings.HasPrefix(statement, "#") {
			var ok bool
			statement, ok = correctiveTrimPLpgSQLDirective(statement)
			if !ok {
				return true
			}
			statement = correctiveTrimPLpgSQLLabels(statement)
			continue
		}
		words := correctivePLpgSQLWords(statement)
		if len(words) == 0 {
			return false
		}
		lead := strings.ToLower(statement[words[0][0]:words[0][1]])
		if *declaration {
			if lead != "begin" {
				return false
			}
			*declaration = false
			statement = correctiveTrimPLpgSQLLabels(statement[words[0][1]:])
			continue
		}
		if regexp.MustCompile(
			`(?is)^` + correctivePLpgSQLIdentifierPattern +
				`(?:\s*(?:\.\s*` + correctivePLpgSQLIdentifierPattern + `|\[[^\]]+\]))*\s*(?::=|=)`,
		).MatchString(statement) {
			return false
		}
		switch lead {
		case "declare":
			*declaration = true
			statement = correctiveTrimPLpgSQLLabels(statement[words[0][1]:])
			continue
		case "begin", "else", "loop":
			statement = correctiveTrimPLpgSQLLabels(statement[words[0][1]:])
			continue
		case "if", "elsif", "elseif", "case", "when", "exception":
			var ok bool
			statement, ok = correctivePLpgSQLControlRemainder(statement, "then")
			if !ok {
				return true
			}
			statement = correctiveTrimPLpgSQLLabels(statement)
			continue
		case "while", "for", "foreach":
			if lead == "for" && correctiveDOHasWordSequence(statement, words, "in", "execute") {
				return true
			}
			var ok bool
			statement, ok = correctivePLpgSQLControlRemainder(statement, "loop")
			if !ok {
				return true
			}
			statement = correctiveTrimPLpgSQLLabels(statement)
			continue
		case "end":
			return false
		case "open":
			return correctiveDOHasWordSequence(statement, words, "for", "execute")
		case "return":
			return correctiveDOHasWordSequence(statement, words, "query", "execute")
		default:
			return correctiveUnsafeDOCommandLead(statement, words)
		}
	}
	return false
}

func correctiveTrimPLpgSQLDirective(statement string) (string, bool) {
	if len(statement) == 0 || statement[0] != '#' {
		return "", false
	}
	words := correctivePLpgSQLWords(statement)
	if len(words) < 2 ||
		!correctivePLpgSQLDirectiveWhitespace(statement[1:words[0][0]]) ||
		words[1][0] == words[0][1] ||
		!correctivePLpgSQLDirectiveWhitespace(statement[words[0][1]:words[1][0]]) {
		return "", false
	}
	option, quotedOption := correctivePLpgSQLIdentifierValue(statement[words[0][0]:words[0][1]])
	value, quotedValue := correctivePLpgSQLIdentifierValue(statement[words[1][0]:words[1][1]])
	valid := !quotedOption && !quotedValue && option == "option" && value == "dump" ||
		!quotedOption && !quotedValue && option == "variable_conflict" &&
			(value == "error" || value == "use_variable" || value == "use_column") ||
		!quotedOption && option == "print_strict_params" && (value == "on" || value == "off")
	if !valid || !quotedValue && words[1][1] < len(statement) &&
		!correctivePLpgSQLDirectiveWhitespace(statement[words[1][1]:words[1][1]+1]) {
		return "", false
	}
	return strings.TrimSpace(statement[words[1][1]:]), true
}

func correctivePLpgSQLIdentifierValue(value string) (string, bool) {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return strings.ReplaceAll(value[1:len(value)-1], `""`, `"`), true
	}
	return strings.ToLower(value), false
}

func correctivePLpgSQLDirectiveWhitespace(value string) bool {
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
		default:
			return false
		}
	}
	return true
}

func correctiveTrimPLpgSQLLabels(statement string) string {
	statement = strings.TrimSpace(statement)
	for strings.HasPrefix(statement, "<<") {
		end := strings.Index(statement[2:], ">>")
		if end < 0 {
			return statement
		}
		statement = strings.TrimSpace(statement[end+4:])
	}
	return statement
}

func correctivePLpgSQLControlRemainder(statement, boundary string) (string, bool) {
	words := correctivePLpgSQLWords(statement)
	caseDepth := 0
	for index := 1; index < len(words); index++ {
		word := strings.ToLower(statement[words[index][0]:words[index][1]])
		if word == "case" {
			caseDepth++
			continue
		}
		if word == "end" && caseDepth > 0 {
			caseDepth--
			continue
		}
		if word == boundary && caseDepth == 0 {
			return statement[words[index][1]:], true
		}
	}
	return "", false
}

func correctivePLpgSQLWords(statement string) [][]int {
	return regexp.MustCompile(correctivePLpgSQLIdentifierPattern).FindAllStringIndex(statement, -1)
}

func correctiveUnsafeDOCommandLead(statement string, words [][]int) bool {
	lead := strings.ToLower(statement[words[0][0]:words[0][1]])
	switch lead {
	case "security":
		return len(words) > 1 && strings.EqualFold(statement[words[1][0]:words[1][1]], "label")
	case "start":
		return len(words) > 1 && strings.EqualFold(statement[words[1][0]:words[1][1]], "transaction")
	case "abort", "alter", "analyze", "call", "checkpoint", "cluster", "comment", "commit", "copy",
		"create", "deallocate", "discard", "do", "drop", "execute", "explain", "grant", "import", "listen",
		"load", "lock", "notify", "prepare", "reassign", "refresh", "reindex", "release", "reset",
		"revoke", "rollback", "savepoint", "set", "show", "truncate", "unlisten", "vacuum":
		return true
	default:
		return false
	}
}

func correctiveDOHasWordSequence(statement string, words [][]int, first, second string) bool {
	for index := 0; index+1 < len(words); index++ {
		if strings.EqualFold(statement[words[index][0]:words[index][1]], first) &&
			strings.EqualFold(statement[words[index+1][0]:words[index+1][1]], second) {
			return true
		}
	}
	return false
}

func correctiveDOCodeBody(suffix string) (string, bool) {
	suffix = strings.TrimSpace(suffix)
	prefixLanguage := false
	languagePrefix := regexp.MustCompile(`(?is)^language\s+(` + correctiveSQLIdentifierPattern + `)\s+`)
	if match := languagePrefix.FindStringSubmatchIndex(suffix); match != nil {
		if !correctiveCanonicalDOLanguage(suffix[match[2]:match[3]]) {
			return "", false
		}
		prefixLanguage = true
		suffix = strings.TrimSpace(suffix[match[1]:])
	}
	if len(suffix) == 0 {
		return "", false
	}

	bodyEnd := 0
	body := ""
	switch {
	case suffix[0] == '$':
		tag := correctiveDollarQuoteTag(suffix)
		if tag == "" {
			return "", false
		}
		bodyStart := len(tag)
		bodyEndRelative := strings.Index(suffix[bodyStart:], tag)
		if bodyEndRelative < 0 {
			return "", false
		}
		bodyEnd = bodyStart + bodyEndRelative + len(tag)
		body = suffix[bodyStart : bodyStart+bodyEndRelative]
	case suffix[0] == '\'':
		var ok bool
		body, bodyEnd, ok = correctiveSingleQuotedSQLLiteral(suffix, 0)
		if !ok {
			return "", false
		}
	case len(suffix) >= 2 && (suffix[0] == 'e' || suffix[0] == 'E') && suffix[1] == '\'':
		var ok bool
		body, bodyEnd, ok = correctiveSingleQuotedSQLLiteral(suffix, 1)
		if !ok {
			return "", false
		}
	default:
		return "", false
	}

	tail := strings.TrimSpace(suffix[bodyEnd:])
	if tail == ";" {
		return body, true
	}
	languageTail := regexp.MustCompile(`(?is)^language\s+(` + correctiveSQLIdentifierPattern + `)\s*;\s*$`)
	match := languageTail.FindStringSubmatch(tail)
	if prefixLanguage || match == nil || !correctiveCanonicalDOLanguage(match[1]) {
		return "", false
	}
	return body, true
}

func correctiveCanonicalDOLanguage(value string) bool {
	return len(value) > 0 && value[0] != '"' && strings.EqualFold(value, "plpgsql")
}

func correctiveSingleQuotedSQLLiteral(value string, quote int) (string, int, bool) {
	if quote < 0 || quote >= len(value) || value[quote] != '\'' {
		return "", 0, false
	}
	backslashEscapes := correctiveEscapeStringPrefix(value, quote)
	var body strings.Builder
	for index := quote + 1; index < len(value); index++ {
		character := value[index]
		switch {
		case character == '\'' && index+1 < len(value) && value[index+1] == '\'':
			body.WriteByte('\'')
			index++
		case character == '\'':
			decoded := body.String()
			if strings.IndexByte(decoded, 0) >= 0 || !utf8.ValidString(decoded) {
				return "", 0, false
			}
			return decoded, index + 1, true
		case character == '\\' && !backslashEscapes:
			return "", 0, false
		case backslashEscapes && character == '\\':
			decoded, next, ok := correctiveDecodeEscapeString(value, index)
			if !ok {
				return "", 0, false
			}
			body.WriteString(decoded)
			index = next - 1
		default:
			body.WriteByte(character)
		}
	}
	return "", 0, false
}

func correctiveDecodeEscapeString(value string, backslash int) (string, int, bool) {
	if backslash < 0 || backslash+1 >= len(value) || value[backslash] != '\\' {
		return "", 0, false
	}
	escaped := value[backslash+1]
	switch escaped {
	case '\n':
		return "", backslash + 2, true
	case '\r':
		next := backslash + 2
		if next < len(value) && value[next] == '\n' {
			next++
		}
		return "", next, true
	case 'b':
		return "\b", backslash + 2, true
	case 'f':
		return "\f", backslash + 2, true
	case 'n':
		return "\n", backslash + 2, true
	case 'r':
		return "\r", backslash + 2, true
	case 't':
		return "\t", backslash + 2, true
	case '\\', '\'':
		return string(escaped), backslash + 2, true
	case 'x':
		start := backslash + 2
		end := start
		for end < len(value) && end < start+2 && correctiveHexDigit(value[end]) {
			end++
		}
		if end == start {
			return "", 0, false
		}
		decoded, err := strconv.ParseUint(value[start:end], 16, 8)
		if err != nil || decoded == 0 {
			return "", 0, false
		}
		return string([]byte{byte(decoded)}), end, true
	case 'u', 'U':
		digits := 4
		if escaped == 'U' {
			digits = 8
		}
		codePoint, next, ok := correctiveUnicodeEscape(value, backslash+2, digits)
		if !ok || codePoint == 0 || codePoint > utf8.MaxRune {
			return "", 0, false
		}
		if codePoint >= 0xdc00 && codePoint <= 0xdfff {
			return "", 0, false
		}
		if codePoint >= 0xd800 && codePoint <= 0xdbff {
			if next+2 > len(value) || value[next] != '\\' || (value[next+1] != 'u' && value[next+1] != 'U') {
				return "", 0, false
			}
			lowDigits := 4
			if value[next+1] == 'U' {
				lowDigits = 8
			}
			low, lowNext, lowOK := correctiveUnicodeEscape(value, next+2, lowDigits)
			if !lowOK || low < 0xdc00 || low > 0xdfff {
				return "", 0, false
			}
			codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00)
			next = lowNext
		}
		return string(rune(codePoint)), next, true
	}
	if escaped >= '0' && escaped <= '7' {
		end := backslash + 1
		for end < len(value) && end < backslash+4 && value[end] >= '0' && value[end] <= '7' {
			end++
		}
		decoded, err := strconv.ParseUint(value[backslash+1:end], 8, 16)
		decodedByte := byte(decoded)
		if err != nil || decodedByte == 0 {
			return "", 0, false
		}
		return string([]byte{decodedByte}), end, true
	}
	return string(escaped), backslash + 2, true
}

func correctiveUnicodeEscape(value string, start, digits int) (uint64, int, bool) {
	end := start + digits
	if start < 0 || digits < 1 || end > len(value) {
		return 0, 0, false
	}
	for index := start; index < end; index++ {
		if !correctiveHexDigit(value[index]) {
			return 0, 0, false
		}
	}
	decoded, err := strconv.ParseUint(value[start:end], 16, 32)
	if err != nil {
		return 0, 0, false
	}
	return decoded, end, true
}

func correctiveHexDigit(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
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
CREATE TRIGGER "QuotedTrigger2" AFTER UPDATE ON public."QuotedTable"
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

func correctiveSourceGateSuccessorRoutineFixture() string {
	return `
CREATE FUNCTION public.asset_catalog_seal_qualification_receipt(
    uuid, uuid, uuid, uuid, bigint, bigint,
    text, timestamp with time zone, timestamp with time zone, text
)
RETURNS boolean AS $$
BEGIN
    IF session_user <> 'aiops_source_gate_sealer' THEN
        RAISE EXCEPTION 'source gate sealer identity required' USING ERRCODE = '42501';
    END IF;
    RETURN false;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp;

CREATE FUNCTION public.asset_catalog_admit_source_gate(
    uuid, uuid, uuid, uuid, bigint, bigint
)
RETURNS boolean AS $$
BEGIN
    IF session_user <> 'aiops_source_gate_admitter' THEN
        RAISE EXCEPTION 'source gate admitter identity required' USING ERRCODE = '42501';
    END IF;
    RETURN false;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp;
`
}

func correctiveSourceGateSuccessorRoutineDownFixture() string {
	return `
DROP FUNCTION public.asset_catalog_seal_qualification_receipt(
    uuid, uuid, uuid, uuid, bigint, bigint,
    text, timestamp with time zone, timestamp with time zone, text
);
DROP FUNCTION public.asset_catalog_admit_source_gate(
    uuid, uuid, uuid, uuid, bigint, bigint
);
`
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
	identities := make([]string, 0, 36)
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
		"public.asset_catalog_lock_exact_service_binding(uuid,uuid,uuid,uuid)",
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

func correctiveExpectedSourceGateSuccessorRoutineIdentities() []string {
	identities := append([]string(nil), correctiveExpectedRoutineIdentities()...)
	return append(
		identities,
		"public.asset_catalog_seal_qualification_receipt(uuid,uuid,uuid,uuid,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text)",
		"public.asset_catalog_admit_source_gate(uuid,uuid,uuid,uuid,bigint,bigint)",
	)
}

func correctiveSourceGateRoutineManifestState(up string) (string, error) {
	got := correctiveRoutineIdentities(up)
	switch {
	case correctiveSQLObjectSetsEqual(got, correctiveExpectedRoutineIdentities()):
		return "exact-36", nil
	case correctiveSQLObjectSetsEqual(got, correctiveExpectedSourceGateSuccessorRoutineIdentities()):
		return "exact-38", nil
	default:
		sorted := append([]string(nil), got...)
		sort.Strings(sorted)
		return "", fmt.Errorf(
			"000015 routine manifest is neither current exact-36 nor future exact-38: %v",
			sorted,
		)
	}
}

func correctiveExpectedRoutineIdentitiesForMigration(t *testing.T, up string) []string {
	t.Helper()
	state, err := correctiveSourceGateRoutineManifestState(up)
	if err != nil {
		t.Fatal(err)
	}
	if state == "exact-38" {
		return correctiveExpectedSourceGateSuccessorRoutineIdentities()
	}
	return correctiveExpectedRoutineIdentities()
}

func correctiveSourceGateSuccessorRoutineBoundary(up, down string) (string, string, error) {
	state, err := correctiveSourceGateRoutineManifestState(up)
	if err != nil {
		return "", "", err
	}
	if state == "exact-36" {
		return up + correctiveSourceGateSuccessorRoutineFixture(),
			correctiveSourceGateSuccessorRoutineDownFixture() + down,
			nil
	}
	return up, down, nil
}

func correctiveWithoutSourceGateSuccessorRoutineStatements(sql string, dropped bool) string {
	successors := correctiveExpectedSourceGateSuccessorRoutineIdentities()
	successorIdentities := map[string]struct{}{
		successors[len(successors)-2]: {},
		successors[len(successors)-1]: {},
	}
	statements := correctiveTopLevelSQLStatements(sql)
	filtered := make([]string, 0, len(statements))
	for _, statement := range statements {
		identities := correctiveRoutineIdentities(statement)
		if dropped {
			identities = correctiveDroppedRoutineIdentities(statement)
		}
		if len(identities) == 1 {
			if _, remove := successorIdentities[identities[0]]; remove {
				continue
			}
		}
		filtered = append(filtered, statement)
	}
	return strings.Join(filtered, "\n")
}

func correctiveAssertSourceGateSessionGuard(
	t *testing.T,
	label, body, identity string,
) {
	t.Helper()
	if err := correctiveSourceGateSessionGuardError(body, identity); err != nil {
		t.Errorf("%s session identity guard: %v", label, err)
	}
}

func correctiveSourceGateSessionGuardError(body, identity string) error {
	normalized := correctiveNormalizeSQL(body)
	if strings.Count(normalized, "session_user") != 1 {
		return fmt.Errorf(
			"normalized body names session_user %d times, want exactly once",
			strings.Count(normalized, "session_user"),
		)
	}
	guard := regexp.MustCompile(
		`\bif session_user <> '` + regexp.QuoteMeta(identity) +
			`' then raise exception [^;]+ using errcode = '42501'; end if;`,
	)
	if matches := guard.FindAllStringIndex(normalized, -1); len(matches) != 1 {
		return fmt.Errorf(
			"normalized body must contain exactly one wrong-identity 42501 branch for %q",
			identity,
		)
	}
	return nil
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
	return correctiveMaskNonCodeSQLMode(value, false)
}

func correctiveMaskNonCodePLpgSQL(value string) string {
	return correctiveMaskNonCodeSQLMode(value, true)
}

func correctiveMaskNonCodeSQLMode(value string, preserveQuotedIdentifiers bool) string {
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
			if !preserveQuotedIdentifiers {
				masked[index] = ' '
			}
			if character == '"' && index+1 < len(value) && value[index+1] == '"' {
				if !preserveQuotedIdentifiers {
					masked[index+1] = ' '
				}
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
			if !preserveQuotedIdentifiers {
				masked[index] = ' '
			}
			inDoubleQuote = true
		case character == '$':
			tag := correctiveDollarQuoteAt(value, index)
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

func correctiveDollarQuoteAt(value string, index int) string {
	if index < 0 || index >= len(value) || value[index] != '$' {
		return ""
	}
	if index > 0 && correctiveUnquotedIdentifierContinuation(value[index-1]) {
		return ""
	}
	return correctiveDollarQuoteTag(value[index:])
}

func correctiveUnquotedIdentifierContinuation(character byte) bool {
	return character >= 0x80 ||
		(character >= 'A' && character <= 'Z') ||
		(character >= 'a' && character <= 'z') ||
		(character >= '0' && character <= '9') ||
		character == '_' || character == '$'
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
	identities, diagnostics := correctiveParsedTriggerIdentities(sql)
	for _, diagnostic := range diagnostics {
		t.Error(diagnostic)
	}
	return identities
}

func correctiveParsedTriggerIdentities(sql string) ([]string, []string) {
	pattern := regexp.MustCompile(`(?is)^\s*create\s+(constraint\s+)?trigger\s+(` + correctiveSQLIdentifierPattern +
		`)\s+(before|after|instead\s+of)\s+(.+?)\s+on\s+(` + correctiveQualifiedSQLIdentifierPattern() +
		`)\s+(.+?)\bexecute\s+(function|procedure)\s+(` + correctiveQualifiedSQLIdentifierPattern() + `)\s*\(\s*\)\s*;\s*$`)
	unreviewed := regexp.MustCompile(correctiveTriggerLifecycleStatementPattern)
	identities := make([]string, 0, 45)
	diagnostics := make([]string, 0)
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		if correctiveDOExecutesDynamicSQL(statement) {
			diagnostics = append(diagnostics, "unreviewed dynamic SQL in DO statement")
			continue
		}
		match := pattern.FindStringSubmatch(statement)
		if match == nil {
			if unreviewed.MatchString(correctiveMaskNonCodeSQL(statement)) {
				diagnostics = append(diagnostics, "unreviewed top-level trigger statement: "+correctiveNormalizeSQL(statement))
			}
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
			diagnostics = append(diagnostics, fmt.Sprintf(
				"trigger %s has unreviewed modifiers %q (WHEN/REFERENCING/additional clauses are forbidden)",
				correctiveCanonicalSQLIdentifier(match[2]),
				modifiers,
			))
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
	return identities, diagnostics
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
		row("asset_source_limit_permits", "asset_source_limit_permits_immutable", "before", []string{"update"}, "reject_asset_catalog_immutable"),
		row("asset_sources", "asset_sources_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_revisions", "asset_source_revisions_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_revision_authorities", "asset_source_revision_authorities_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_runs", "asset_source_runs_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_limit_buckets", "asset_source_limit_buckets_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
		row("asset_source_limit_permits", "asset_source_limit_permits_delete_guard", "before", []string{"delete"}, "reject_asset_catalog_delete"),
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
		statement("asset_source_limit_buckets", "asset_source_limit_buckets_truncate_guard", "reject_asset_catalog_truncate"),
		statement("asset_source_limit_permits", "asset_source_limit_permits_truncate_guard", "reject_asset_catalog_truncate"),
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
		row("asset_source_limit_buckets", "asset_source_limit_buckets_mutation_guard", "before", []string{"insert", "update"}, "enforce_asset_catalog_edge_mutation"),
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

func correctiveExpectedTriggerIdentitiesForMigration(t *testing.T, up string) []string {
	t.Helper()
	expected := correctiveExpectedTriggerIdentities()
	required, err := correctiveSourceGateTriggerRequired(up)
	if err != nil {
		t.Errorf("asset_sources gate-evidence column discriminator: %v", err)
		return expected
	}
	if !required {
		return expected
	}
	return append(expected, correctiveTriggerIdentity(
		"public.asset_sources",
		"asset_sources_gate_evidence_closure_guard",
		true,
		"after",
		[]string{"insert", "update"},
		"row",
		true,
		"public.validate_asset_source_deferred_state",
	))
}

func correctiveSourceGateTriggerRequired(up string) (bool, error) {
	alterTable := regexp.MustCompile(`(?is)^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(` +
		correctiveQualifiedSQLIdentifierPattern() + `)\s+`)
	addColumn := regexp.MustCompile(`(?is)^\s*alter\s+table\s+(` + correctiveQualifiedSQLIdentifierPattern() +
		`)\s+add\s+(?:column\s+)?(` + correctiveSQLIdentifierPattern + `)\s+(.+?)\s*;\s*$`)
	triggerLifecycle := regexp.MustCompile(correctiveTriggerLifecycleStatementPattern)
	manifest := make([]string, 0, 3)
	tableSeen := false
	for _, statement := range correctiveTopLevelSQLStatements(up) {
		if correctiveDOExecutesDynamicSQL(statement) {
			return false, fmt.Errorf("unreviewed dynamic SQL in DO statement")
		}
		table, found, err := correctiveTableDefinitionInStatement(statement, "public.asset_sources")
		if err != nil {
			return false, err
		}
		if found {
			if tableSeen {
				return false, fmt.Errorf("duplicate public.asset_sources definition")
			}
			tableSeen = true
			open := strings.Index(table, "(")
			if open < 0 {
				return false, fmt.Errorf("public.asset_sources definition has no column list")
			}
			for _, element := range correctiveSplitSQLArguments(table[open+1 : len(table)-1]) {
				name, definition, ok := correctiveColumnDefinition(element)
				if ok && correctiveGateEvidenceColumnLike(name) {
					manifest = append(manifest, correctiveGateEvidenceColumnIdentity(name, definition))
				}
			}
			continue
		}
		if triggerLifecycle.MatchString(correctiveMaskNonCodeSQL(statement)) {
			continue
		}

		alterMatch := alterTable.FindStringSubmatch(statement)
		if alterMatch == nil || correctiveCanonicalSQLIdentifier(alterMatch[1]) != "public.asset_sources" ||
			!strings.Contains(strings.ToLower(statement), "gate_evidence_") {
			continue
		}
		if !tableSeen {
			return false, fmt.Errorf("gate-evidence ALTER precedes public.asset_sources definition")
		}
		addMatch := addColumn.FindStringSubmatch(statement)
		if addMatch == nil || correctiveCanonicalSQLIdentifier(addMatch[1]) != "public.asset_sources" {
			return false, fmt.Errorf("unreviewed gate-evidence ALTER: %s", correctiveNormalizeSQL(statement))
		}
		name := correctiveCanonicalSQLIdentifier(addMatch[2])
		if !correctiveGateEvidenceColumnLike(name) {
			return false, fmt.Errorf("unreviewed gate-evidence ALTER: %s", correctiveNormalizeSQL(statement))
		}
		manifest = append(manifest, correctiveGateEvidenceColumnIdentity(name, addMatch[3]))
	}
	if !tableSeen {
		return false, fmt.Errorf("migration does not define table public.asset_sources with an explicit schema")
	}
	if len(manifest) == 0 {
		return false, nil
	}
	sort.Strings(manifest)
	expected := []string{
		"gate_evidence_digest text",
		"gate_evidence_expires_at timestamp with time zone",
		"gate_evidence_run_id uuid",
	}
	if !reflect.DeepEqual(manifest, expected) {
		return false, fmt.Errorf("gate-evidence column manifest = %v, want exact %v", manifest, expected)
	}
	return true, nil
}

func correctiveGateEvidenceColumnIdentity(name, definition string) string {
	return name + " " + correctiveCanonicalGateEvidenceType(definition)
}

func correctiveCanonicalGateEvidenceType(definition string) string {
	definition = strings.TrimSpace(correctiveStripSQLComments(definition))
	definition = regexp.MustCompile(`(?i)\s+null\s*$`).ReplaceAllString(definition, "")
	if match := regexp.MustCompile(`(?is)^(.+?)\s+with\s+time\s+zone$`).FindStringSubmatch(definition); match != nil {
		switch correctiveCanonicalSQLIdentifier(match[1]) {
		case "timestamp", "pg_catalog.timestamp":
			return "timestamp with time zone"
		default:
			return definition
		}
	}
	canonical := correctiveCanonicalSQLIdentifier(definition)
	switch canonical {
	case "uuid", "pg_catalog.uuid":
		return "uuid"
	case "text", "pg_catalog.text":
		return "text"
	case "timestamptz", "pg_catalog.timestamptz":
		return "timestamp with time zone"
	default:
		return definition
	}
}

func correctiveGateEvidenceColumnLike(name string) bool {
	if len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"' {
		name = strings.ReplaceAll(name[1:len(name)-1], `""`, `"`)
	}
	return strings.HasPrefix(strings.ToLower(name), "gate_evidence_")
}

func correctiveColumnDefinition(element string) (string, string, bool) {
	pattern := regexp.MustCompile(`(?is)^\s*(` + correctiveSQLIdentifierPattern + `)\s+(.+?)\s*$`)
	match := pattern.FindStringSubmatch(element)
	if match == nil {
		return "", "", false
	}
	name := correctiveCanonicalSQLIdentifier(match[1])
	switch strings.ToLower(name) {
	case "constraint", "primary", "unique", "check", "foreign", "exclude", "like":
		return "", "", false
	default:
		return name, match[2], true
	}
}

func correctiveSourceGateColumnsFixture(t *testing.T, up, columns string) string {
	t.Helper()
	table := correctiveRequireTable(t, up, "public.asset_sources")
	if table == "" {
		return up
	}
	if strings.Count(up, table) != 1 {
		t.Fatalf("public.asset_sources fixture definition occurs %d times, want exact one", strings.Count(up, table))
	}
	successorTable := strings.TrimSuffix(table, ")") + ",\n    " + strings.TrimSpace(columns) + "\n)"
	return strings.Replace(up, table, successorTable, 1)
}

func correctiveSourceGateSuccessorTriggerFixture(
	t *testing.T,
	up, down, columns, trigger, dropAnchor, drop string,
) (string, string, error) {
	t.Helper()
	formal, err := correctiveSourceGateSuccessorTriggerFixtureState(up, down)
	if err != nil {
		return "", "", err
	}
	if formal {
		return up, down, nil
	}

	table, err := correctiveTableDefinition(up, "public.asset_sources")
	if err != nil {
		return "", "", err
	}
	if occurrences := strings.Count(up, table); occurrences != 1 {
		return "", "", fmt.Errorf("public.asset_sources fixture definition occurs %d times, want exact one", occurrences)
	}
	if occurrences := strings.Count(down, dropAnchor); occurrences != 1 {
		return "", "", fmt.Errorf("successor trigger drop anchor occurs %d times, want exact one", occurrences)
	}
	successorTable := strings.TrimSuffix(table, ")") + ",\n    " + strings.TrimSpace(columns) + "\n)"
	successorUp := strings.Replace(up, table, successorTable, 1) + trigger
	successorDown := strings.Replace(down, dropAnchor, dropAnchor+drop, 1)
	formal, err = correctiveSourceGateSuccessorTriggerFixtureState(successorUp, successorDown)
	if err != nil {
		return "", "", fmt.Errorf("constructed successor source-gate fixture: %w", err)
	}
	if !formal {
		return "", "", fmt.Errorf("constructed successor source-gate fixture remains baseline")
	}
	return successorUp, successorDown, nil
}

func correctiveSourceGateSuccessorTriggerFixtureState(up, down string) (bool, error) {
	required, err := correctiveSourceGateTriggerRequired(up)
	if err != nil {
		return false, fmt.Errorf("source-gate columns: %w", err)
	}

	expectedUp := correctiveExpectedTriggerIdentities()
	if required {
		expectedUp = append(expectedUp, correctiveTriggerIdentity(
			"public.asset_sources",
			"asset_sources_gate_evidence_closure_guard",
			true,
			"after",
			[]string{"insert", "update"},
			"row",
			true,
			"public.validate_asset_source_deferred_state",
		))
	}
	gotUp, diagnostics := correctiveParsedTriggerIdentities(up)
	if len(diagnostics) != 0 {
		return false, fmt.Errorf("source-gate up trigger manifest diagnostics: %v", diagnostics)
	}
	if !correctiveSQLObjectSetsEqual(gotUp, expectedUp) {
		return false, fmt.Errorf("source-gate up trigger manifest does not match %s state", correctiveSourceGateFixtureStateName(required))
	}

	expectedDown := make([]string, 0, len(expectedUp))
	for _, identity := range expectedUp {
		expectedDown = append(expectedDown, strings.SplitN(identity, "|", 2)[0])
	}
	if gotDown := correctiveDroppedTriggerIdentities(down); !correctiveSQLObjectSetsEqual(gotDown, expectedDown) {
		return false, fmt.Errorf("source-gate down trigger manifest does not match %s state", correctiveSourceGateFixtureStateName(required))
	}
	return required, nil
}

func correctiveSourceGateFixtureStateName(formal bool) string {
	if formal {
		return "formal"
	}
	return "baseline"
}

func correctiveDroppedTriggerIdentities(sql string) []string {
	pattern := regexp.MustCompile(`(?is)^\s*drop\s+trigger\s+(` + correctiveSQLIdentifierPattern + `)\s+on\s+(` +
		correctiveQualifiedSQLIdentifierPattern() + `)\s*;\s*$`)
	unreviewed := regexp.MustCompile(correctiveTriggerLifecycleStatementPattern)
	dropTable := regexp.MustCompile(`(?is)^\s*drop\s+table\b`)
	identities := make([]string, 0, 45)
	tableDropSeen := false
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		masked := correctiveMaskNonCodeSQL(statement)
		if dropTable.MatchString(masked) {
			tableDropSeen = true
		}
		if correctiveDOExecutesDynamicSQL(statement) {
			identities = append(identities, "<unreviewed-dynamic-sql-in-do>")
			continue
		}
		match := pattern.FindStringSubmatch(statement)
		if match == nil {
			if unreviewed.MatchString(masked) {
				identities = append(identities, "<unreviewed-trigger-statement>:"+correctiveNormalizeSQL(statement))
			}
			continue
		}
		if tableDropSeen {
			identities = append(identities, "<trigger-drop-after-table>:"+correctiveNormalizeSQL(statement))
			continue
		}
		identities = append(identities, correctiveCanonicalSQLIdentifier(match[2])+"/"+correctiveCanonicalSQLIdentifier(match[1]))
	}
	return identities
}

func correctiveExpectedDroppedTriggerIdentitiesForMigration(t *testing.T, up string) []string {
	t.Helper()
	expected := correctiveExpectedTriggerIdentitiesForMigration(t, up)
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
	identities := make([]string, 0, 12)
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
	if !correctiveSQLObjectSetsEqual(got, want) {
		gotCopy := append([]string(nil), got...)
		wantCopy := append([]string(nil), want...)
		sort.Strings(gotCopy)
		sort.Strings(wantCopy)
		t.Errorf("%s = %v, want exact set %v", label, gotCopy, wantCopy)
	}
}

func correctiveSQLObjectSetsEqual(got, want []string) bool {
	gotCopy := append([]string(nil), got...)
	wantCopy := append([]string(nil), want...)
	sort.Strings(gotCopy)
	sort.Strings(wantCopy)
	return reflect.DeepEqual(gotCopy, wantCopy)
}

func correctiveRequireTable(t *testing.T, sql, qualifiedName string) string {
	t.Helper()
	statement, err := correctiveTableDefinition(sql, qualifiedName)
	if err != nil {
		t.Error(err)
		return ""
	}
	return statement
}

func correctiveTableDefinition(sql, qualifiedName string) (string, error) {
	for _, statement := range correctiveTopLevelSQLStatements(sql) {
		table, found, err := correctiveTableDefinitionInStatement(statement, qualifiedName)
		if err != nil {
			return "", err
		}
		if found {
			return table, nil
		}
	}
	return "", fmt.Errorf("migration does not define table %s with an explicit schema", qualifiedName)
}

func correctiveTableDefinitionInStatement(statement, qualifiedName string) (string, bool, error) {
	pattern := regexp.MustCompile(`(?is)^\s*create\s+table\s+(` + correctiveQualifiedSQLIdentifierPattern() + `)\s*\(`)
	location := pattern.FindStringSubmatchIndex(statement)
	if location == nil || correctiveCanonicalSQLIdentifier(statement[location[2]:location[3]]) != strings.ToLower(qualifiedName) {
		return "", false, nil
	}
	open := location[1] - 1
	close := correctiveMatchingParen(statement, open)
	if close < 0 {
		return "", true, fmt.Errorf("table %s has an unclosed definition", qualifiedName)
	}
	return statement[location[0] : close+1], true, nil
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
