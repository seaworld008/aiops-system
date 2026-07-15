package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type schemaAdmissionQueryStub struct {
	row           schemaAdmissionRowStub
	beginErr      error
	execErr       error
	execErrAt     int
	rollbackErr   error
	beginCalls    int
	execCalls     int
	calls         int
	rollbackCalls int
	lastOptions   pgx.TxOptions
	execSQLs      []string
	lastSQL       string
	lastArgs      []any
	callOrder     []string
}

func (stub *schemaAdmissionQueryStub) BeginTx(
	_ context.Context,
	options pgx.TxOptions,
) (schemaAdmissionTransaction, error) {
	stub.beginCalls++
	stub.lastOptions = options
	stub.callOrder = append(stub.callOrder, "begin")
	if stub.beginErr != nil {
		return nil, stub.beginErr
	}
	return stub, nil
}

func (stub *schemaAdmissionQueryStub) Exec(_ context.Context, sql string, _ ...any) error {
	stub.execCalls++
	stub.execSQLs = append(stub.execSQLs, sql)
	if stub.execCalls == 1 {
		stub.callOrder = append(stub.callOrder, "set-search-path")
	} else {
		stub.callOrder = append(stub.callOrder, "set-quote-identifiers")
	}
	if stub.execErr != nil && (stub.execErrAt == 0 || stub.execErrAt == stub.execCalls) {
		return stub.execErr
	}
	return nil
}

func (stub *schemaAdmissionQueryStub) QueryRow(_ context.Context, sql string, args ...any) schemaAdmissionRow {
	stub.calls++
	stub.lastSQL = sql
	stub.lastArgs = append([]any(nil), args...)
	stub.callOrder = append(stub.callOrder, "manifest")
	return stub.row
}

func (stub *schemaAdmissionQueryStub) Rollback(context.Context) error {
	stub.rollbackCalls++
	stub.callOrder = append(stub.callOrder, "rollback")
	return stub.rollbackErr
}

type schemaAdmissionRowStub struct {
	manifest []byte
	err      error
}

func (stub schemaAdmissionRowStub) Scan(destinations ...any) error {
	if stub.err != nil {
		return stub.err
	}
	destination, ok := destinations[0].(*[]byte)
	if !ok {
		panic("unexpected schema admission destination")
	}
	*destination = append((*destination)[:0], stub.manifest...)
	return nil
}

func newReviewedSchemaAdmission(
	database schemaAdmissionDatabase,
	trustedSchema string,
	reviewedManifest []byte,
) *SchemaAdmission {
	digest := sha256.Sum256(reviewedManifest)
	return newSchemaAdmission(database, trustedSchema, hex.EncodeToString(digest[:]))
}

func TestSchemaAdmissionFailsClosedWithoutDatabase(t *testing.T) {
	probe := NewSchemaAdmission(nil, "public")

	err := probe.Check(context.Background())
	if !errors.Is(err, ErrAssetCatalogUnavailable) {
		t.Fatalf("Check() error = %v, want %q", err, ErrAssetCatalogUnavailable)
	}
	if got, want := err.Error(), AssetCatalogUnavailableCode; got != want {
		t.Fatalf("Check() error text = %q, want %q", got, want)
	}
}

func TestSchemaAdmissionRejectsMissingTrustedSchemaWithoutQuery(t *testing.T) {
	manifest := []byte("reviewed manifest")
	query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{manifest: manifest}}
	probe := newReviewedSchemaAdmission(query, "", manifest)

	err := probe.Check(context.Background())
	if !errors.Is(err, ErrAssetCatalogUnavailable) {
		t.Fatalf("Check() error = %v, want %q", err, ErrAssetCatalogUnavailable)
	}
	if query.calls != 0 {
		t.Fatalf("Check() query calls = %d, want 0", query.calls)
	}
}

func TestSchemaAdmissionRejectsNonCanonicalTrustedSchemaWithoutQuery(t *testing.T) {
	manifest := []byte("reviewed manifest")
	for _, trustedSchema := range []string{
		" public",
		"public ",
		"public\x00shadow",
		"public\nshadow",
		strings.Repeat("s", 64),
	} {
		t.Run(strings.ReplaceAll(trustedSchema, "\x00", "NUL"), func(t *testing.T) {
			query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{manifest: manifest}}
			probe := newReviewedSchemaAdmission(query, trustedSchema, manifest)

			err := probe.Check(context.Background())
			if !errors.Is(err, ErrAssetCatalogUnavailable) {
				t.Fatalf("Check() error = %v, want %q", err, ErrAssetCatalogUnavailable)
			}
			if query.calls != 0 {
				t.Fatalf("Check() query calls = %d, want 0", query.calls)
			}
		})
	}
}

func TestSchemaAdmissionHidesDatabaseFailure(t *testing.T) {
	manifest := []byte("reviewed manifest")
	query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{
		err: errors.New("postgres dial failed for secret connection text"),
	}}
	probe := newReviewedSchemaAdmission(query, "public", manifest)

	err := probe.Check(context.Background())
	if !errors.Is(err, ErrAssetCatalogUnavailable) {
		t.Fatalf("Check() error = %v, want %q", err, ErrAssetCatalogUnavailable)
	}
	if strings.Contains(err.Error(), "postgres") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Check() leaked database error text: %q", err)
	}
	if query.calls != 1 {
		t.Fatalf("Check() query calls = %d, want 1", query.calls)
	}
	if query.rollbackCalls != 1 {
		t.Fatalf("Check() rollback calls = %d, want 1", query.rollbackCalls)
	}
}

func TestSchemaAdmissionFailsClosedAcrossTransactionBoundary(t *testing.T) {
	manifest := []byte("reviewed manifest")
	tests := []struct {
		name          string
		configure     func(*schemaAdmissionQueryStub)
		wantExecs     int
		wantQueries   int
		wantRollbacks int
	}{
		{
			name: "begin",
			configure: func(stub *schemaAdmissionQueryStub) {
				stub.beginErr = errors.New("secret begin failure")
			},
			wantExecs:     0,
			wantQueries:   0,
			wantRollbacks: 0,
		},
		{
			name: "set local search path",
			configure: func(stub *schemaAdmissionQueryStub) {
				stub.execErrAt = 1
				stub.execErr = errors.New("secret set-local failure")
			},
			wantExecs:     1,
			wantQueries:   0,
			wantRollbacks: 1,
		},
		{
			name: "set local quote identifiers",
			configure: func(stub *schemaAdmissionQueryStub) {
				stub.execErrAt = 2
				stub.execErr = errors.New("secret set-local failure")
			},
			wantExecs:     2,
			wantQueries:   0,
			wantRollbacks: 1,
		},
		{
			name: "manifest",
			configure: func(stub *schemaAdmissionQueryStub) {
				stub.row.err = errors.New("secret manifest failure")
			},
			wantExecs:     2,
			wantQueries:   1,
			wantRollbacks: 1,
		},
		{
			name: "rollback",
			configure: func(stub *schemaAdmissionQueryStub) {
				stub.rollbackErr = errors.New("secret rollback failure")
			},
			wantExecs:     2,
			wantQueries:   1,
			wantRollbacks: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{manifest: manifest}}
			test.configure(query)
			probe := newReviewedSchemaAdmission(query, "public", manifest)

			err := probe.Check(context.Background())
			if !errors.Is(err, ErrAssetCatalogUnavailable) {
				t.Fatalf("Check() error = %v, want %q", err, ErrAssetCatalogUnavailable)
			}
			if got := err.Error(); strings.Contains(got, "secret") {
				t.Fatalf("Check() leaked transaction error text: %q", got)
			}
			if query.execCalls != test.wantExecs {
				t.Fatalf("Check() exec calls = %d, want %d", query.execCalls, test.wantExecs)
			}
			if query.calls != test.wantQueries {
				t.Fatalf("Check() query calls = %d, want %d", query.calls, test.wantQueries)
			}
			if query.rollbackCalls != test.wantRollbacks {
				t.Fatalf("Check() rollback calls = %d, want %d", query.rollbackCalls, test.wantRollbacks)
			}
		})
	}
}

func TestSchemaAdmissionRejectsInvalidReviewedHashWithoutQuery(t *testing.T) {
	for _, reviewedHash := range []string{
		"",
		"not-a-sha256",
		strings.Repeat("A", sha256.Size*2),
	} {
		query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{manifest: []byte("manifest")}}
		probe := newSchemaAdmission(query, "public", reviewedHash)

		err := probe.Check(context.Background())
		if !errors.Is(err, ErrAssetCatalogUnavailable) {
			t.Fatalf("Check() error = %v, want %q", err, ErrAssetCatalogUnavailable)
		}
		if query.calls != 0 {
			t.Fatalf("Check() query calls = %d, want 0", query.calls)
		}
	}
}

func TestSchemaAdmissionRejectsManifestMismatch(t *testing.T) {
	reviewed := []byte("reviewed manifest")
	query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{manifest: []byte("drifted manifest")}}
	probe := newReviewedSchemaAdmission(query, "public", reviewed)

	err := probe.Check(context.Background())
	if !errors.Is(err, ErrAssetCatalogUnavailable) {
		t.Fatalf("Check() error = %v, want %q", err, ErrAssetCatalogUnavailable)
	}
	if query.calls != 1 {
		t.Fatalf("Check() query calls = %d, want 1", query.calls)
	}
}

func TestSchemaAdmissionAcceptsCompleteCatalog(t *testing.T) {
	manifest := []byte("reviewed PostgreSQL 18.4 catalog manifest")
	query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{manifest: manifest}}
	probe := newReviewedSchemaAdmission(query, "public", manifest)

	if err := probe.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if query.calls != 1 {
		t.Fatalf("Check() query calls = %d, want 1", query.calls)
	}
}

func TestSchemaAdmissionUsesOnlyExplicitTrustedSchema(t *testing.T) {
	manifest := []byte("reviewed manifest")
	query := &schemaAdmissionQueryStub{row: schemaAdmissionRowStub{manifest: manifest}}
	probe := newReviewedSchemaAdmission(query, "control_plane", manifest)

	if err := probe.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if got, want := len(query.lastArgs), 1; got != want {
		t.Fatalf("Check() query argument count = %d, want %d", got, want)
	}
	if got, want := query.lastArgs[0], any("control_plane"); got != want {
		t.Fatalf("Check() trusted schema argument = %v, want %v", got, want)
	}
	if got, want := strings.Join(query.callOrder, ","), "begin,set-search-path,set-quote-identifiers,manifest,rollback"; got != want {
		t.Fatalf("Check() call order = %q, want %q", got, want)
	}
	if query.lastOptions.IsoLevel != pgx.RepeatableRead {
		t.Fatalf("Check() transaction isolation = %q, want %q", query.lastOptions.IsoLevel, pgx.RepeatableRead)
	}
	if query.lastOptions.AccessMode != pgx.ReadOnly {
		t.Fatalf("Check() transaction access mode = %q, want %q", query.lastOptions.AccessMode, pgx.ReadOnly)
	}
	if got, want := query.execSQLs, []string{
		schemaAdmissionSetLocalSearchPathSQL,
		schemaAdmissionSetLocalQuoteIdentifiersSQL,
	}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Check() SET LOCAL SQL = %q, want %q", got, want)
	}
	if got, want := strings.ToLower(schemaAdmissionSetLocalSearchPathSQL),
		"set local search_path = pg_catalog, pg_temp"; got != want {
		t.Fatalf("schema admission SET LOCAL SQL = %q, want %q", got, want)
	}
	if got, want := strings.ToLower(schemaAdmissionSetLocalQuoteIdentifiersSQL),
		"set local quote_all_identifiers = off"; got != want {
		t.Fatalf("schema admission quote identifiers SQL = %q, want %q", got, want)
	}
	lowerSQL := strings.ToLower(query.lastSQL)
	for _, forbidden := range []string{
		"current_schema",
		"current_schemas",
		"search_path_guard",
		"set_config",
		"'search_path'",
	} {
		if strings.Contains(lowerSQL, forbidden) {
			t.Errorf("schema admission SQL uses forbidden %q resolution", forbidden)
		}
	}
	if !strings.Contains(lowerSQL, "namespace.nspname = $1") {
		t.Error("schema admission SQL does not bind the explicit trusted schema")
	}
}

func TestSchemaAdmissionManifestCoversExactCatalogSurface(t *testing.T) {
	lowerSQL := strings.ToLower(schemaAdmissionSQL)
	for _, required := range []string{
		"asset_sources",
		"asset_source_revisions",
		"asset_source_revision_authorities",
		"asset_source_runs",
		"asset_observations",
		"assets",
		"asset_type_details",
		"asset_conflicts",
		"asset_relationships",
		"service_asset_bindings",
		"audit_records",
		"outbox_events",
		"server_version_num",
		"pg_catalog.pg_attribute",
		"pg_catalog.pg_constraint",
		"pg_catalog.pg_index",
		"pg_catalog.pg_trigger",
		"pg_catalog.pg_depend",
		"pg_catalog.pg_proc",
		"pg_catalog.pg_description",
		"pg_catalog.pg_roles",
		"pg_catalog.aclexplode",
		"pg_catalog.acldefault",
		"pg_catalog.format_type",
		"pg_catalog.pg_get_expr",
		"pg_catalog.pg_get_constraintdef",
		"pg_catalog.pg_get_indexdef",
		"pg_catalog.pg_get_triggerdef",
		"pg_catalog.pg_get_functiondef",
		"relpersistence",
		"relrowsecurity",
		"relforcerowsecurity",
		"relispartition",
		"relhassubclass",
		"attidentity",
		"attgenerated",
		"attisdropped",
		"atthasmissing",
		"attislocal",
		"attinhcount",
		"convalidated",
		"tgenabled",
		"tgdeferrable",
		"tginitdeferred",
		"direct_function_dependency_count",
		"direct_function_dependencies",
		"dependency.deptype",
		"trigger_record.tgisinternal then null",
		"constraint_surface",
		"provolatile",
		"proisstrict",
		"prosecdef",
		"proconfig",
		"authorization-owner",
		"authorization-acl",
		"owner_oid",
		"grantee",
		"grantor",
		"privilege_type",
		"is_grantable",
		"multiplicity",
		"int8send",
		"int4send",
		"record_kind collate \"c\"",
		"sort_key collate \"c\"",
	} {
		if !strings.Contains(lowerSQL, required) {
			t.Errorf("schema admission manifest is missing %q", required)
		}
	}
	if strings.Contains(lowerSQL, "and not trigger_record.tgisinternal") {
		t.Error("schema admission excludes internal constraint triggers")
	}
	columnRecordsStart := strings.Index(lowerSQL, "column_records as (")
	constraintRecordsStart := strings.Index(lowerSQL, "constraint_records as (")
	if columnRecordsStart < 0 || constraintRecordsStart <= columnRecordsStart {
		t.Fatal("schema admission structural column record region is missing")
	}
	if strings.Contains(lowerSQL[columnRecordsStart:constraintRecordsStart], "and not attribute.attisdropped") {
		t.Error("schema admission excludes dropped-column drift")
	}
}
