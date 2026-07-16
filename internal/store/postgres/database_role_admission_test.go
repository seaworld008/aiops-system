package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type databaseRoleAdmissionDatabaseStub struct {
	snapshot      databaseRoleAdmissionSnapshot
	rawSnapshot   []byte
	beginErr      error
	execErr       error
	rowErr        error
	rollbackErr   error
	beginCalls    int
	execCalls     int
	queryCalls    int
	rollbackCalls int
	lastOptions   pgx.TxOptions
	lastExecSQL   string
	lastSQL       string
	lastArgs      []any
	callOrder     []string
}

func (stub *databaseRoleAdmissionDatabaseStub) BeginTx(
	_ context.Context,
	options pgx.TxOptions,
) (databaseRoleAdmissionTransaction, error) {
	stub.beginCalls++
	stub.lastOptions = options
	stub.callOrder = append(stub.callOrder, "begin")
	if stub.beginErr != nil {
		return nil, stub.beginErr
	}
	return stub, nil
}

func (stub *databaseRoleAdmissionDatabaseStub) Exec(
	_ context.Context,
	sql string,
	_ ...any,
) error {
	stub.execCalls++
	stub.lastExecSQL = sql
	stub.callOrder = append(stub.callOrder, "set-local")
	return stub.execErr
}

func (stub *databaseRoleAdmissionDatabaseStub) QueryRow(
	_ context.Context,
	sql string,
	args ...any,
) databaseRoleAdmissionRow {
	stub.queryCalls++
	stub.lastSQL = sql
	stub.lastArgs = append([]any(nil), args...)
	stub.callOrder = append(stub.callOrder, "snapshot")
	raw := stub.rawSnapshot
	if raw == nil {
		var err error
		raw, err = json.Marshal(stub.snapshot)
		if err != nil {
			panic(err)
		}
	}
	return databaseRoleAdmissionRowStub{raw: raw, err: stub.rowErr}
}

func (stub *databaseRoleAdmissionDatabaseStub) Rollback(context.Context) error {
	stub.rollbackCalls++
	stub.callOrder = append(stub.callOrder, "rollback")
	return stub.rollbackErr
}

type databaseRoleAdmissionRowStub struct {
	raw []byte
	err error
}

func (stub databaseRoleAdmissionRowStub) Scan(destinations ...any) error {
	if stub.err != nil {
		return stub.err
	}
	destination, ok := destinations[0].(*[]byte)
	if !ok {
		panic("unexpected database role admission destination")
	}
	*destination = append((*destination)[:0], stub.raw...)
	return nil
}

func TestDatabaseRoleAdmissionAcceptsExactApplicationWorkloadContract(t *testing.T) {
	stub := &databaseRoleAdmissionDatabaseStub{
		snapshot: validDatabaseRoleAdmissionSnapshot("public"),
	}
	probe := newDatabaseRoleAdmission(stub, "public")

	if err := probe.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if got, want := strings.Join(stub.callOrder, ","), "begin,set-local,snapshot,rollback"; got != want {
		t.Fatalf("Check() call order = %q, want %q", got, want)
	}
	if got, want := stub.lastOptions.AccessMode, pgx.ReadOnly; got != want {
		t.Fatalf("Check() transaction access mode = %q, want %q", got, want)
	}
	if got, want := stub.lastOptions.IsoLevel, pgx.RepeatableRead; got != want {
		t.Fatalf("Check() transaction isolation = %q, want %q", got, want)
	}
	if got, want := stub.lastExecSQL, databaseRoleAdmissionSetLocalSearchPathSQL; got != want {
		t.Fatalf("Check() SET LOCAL SQL = %q, want %q", got, want)
	}
	if got, want := len(stub.lastArgs), 1; got != want {
		t.Fatalf("Check() query argument count = %d, want %d", got, want)
	}
	if got, want := stub.lastArgs[0], any("public"); got != want {
		t.Fatalf("Check() trusted schema argument = %v, want %v", got, want)
	}
}

func TestDatabaseRoleAdmissionRequiresDistinctApplicationIdentityFromMigration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*databaseRoleAdmissionSnapshot)
	}{
		{
			name: "migration session user",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.SessionUser = "aiops_migrator"
			},
		},
		{
			name: "set role current user",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.CurrentUser = "aiops_control_plane_runtime"
			},
		},
		{
			name: "owner identity",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.SessionUser = "aiops_schema_owner"
				snapshot.CurrentUser = "aiops_schema_owner"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneDatabaseRoleAdmissionSnapshot(t, validDatabaseRoleAdmissionSnapshot("public"))
			test.mutate(&snapshot)
			assertDatabaseRoleAdmissionRejected(t, snapshot)
		})
	}
}

func TestDatabaseRoleAdmissionRejectsRoleDatabaseSchemaAndACLDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*databaseRoleAdmissionSnapshot)
	}{
		{
			name: "missing role",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Roles = snapshot.Roles[1:]
			},
		},
		{
			name: "unknown extra role",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Roles = append(snapshot.Roles, databaseRoleAdmissionRole{Label: "UNKNOWN:999", Name: "shadow"})
			},
		},
		{
			name: "migrator inherits",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "MIGRATOR").Inherit = true
			},
		},
		{
			name: "schema owner login",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "SCHEMA_OWNER").Login = true
			},
		},
		{
			name: "runtime bypass rls",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "RUNTIME").BypassRLS = true
			},
		},
		{
			name: "workload no inherit",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "WORKLOAD").Inherit = false
			},
		},
		{
			name: "workload createdb",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "WORKLOAD").CreateDB = true
			},
		},
		{
			name: "workload createrole",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "WORKLOAD").CreateRole = true
			},
		},
		{
			name: "workload replication",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "WORKLOAD").Replication = true
			},
		},
		{
			name: "workload superuser",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				roleByLabel(t, snapshot, "WORKLOAD").Superuser = true
			},
		},
		{
			name: "missing migrator membership",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Memberships = snapshot.Memberships[1:]
			},
		},
		{
			name: "migrator membership inherit",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				membership(t, snapshot, "MIGRATOR", "SCHEMA_OWNER").Inherit = true
			},
		},
		{
			name: "migrator membership cannot set",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				membership(t, snapshot, "MIGRATOR", "SCHEMA_OWNER").Set = false
			},
		},
		{
			name: "migrator membership admin",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				membership(t, snapshot, "MIGRATOR", "SCHEMA_OWNER").Admin = true
			},
		},
		{
			name: "workload membership cannot inherit",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				membership(t, snapshot, "WORKLOAD", "RUNTIME").Inherit = false
			},
		},
		{
			name: "workload membership can set role",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				membership(t, snapshot, "WORKLOAD", "RUNTIME").Set = true
			},
		},
		{
			name: "workload membership admin",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				membership(t, snapshot, "WORKLOAD", "RUNTIME").Admin = true
			},
		},
		{
			name: "unexpected membership",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Memberships = append(snapshot.Memberships, databaseRoleAdmissionMembership{
					Role: "SCHEMA_OWNER", Member: "WORKLOAD", Inherit: false, Set: true, Admin: false,
				})
			},
		},
		{
			name: "workload effective set role runtime",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				capability(t, snapshot, "WORKLOAD", "RUNTIME", "SET").Allowed = true
			},
		},
		{
			name: "workload missing inherited runtime",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				capability(t, snapshot, "WORKLOAD", "RUNTIME", "USAGE").Allowed = false
			},
		},
		{
			name: "migrator cannot set owner",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				capability(t, snapshot, "MIGRATOR", "SCHEMA_OWNER", "SET").Allowed = false
			},
		},
		{
			name: "migrator inherits owner",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				capability(t, snapshot, "MIGRATOR", "SCHEMA_OWNER", "USAGE").Allowed = true
			},
		},
		{
			name: "database wrong owner",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Database.Owner = "MIGRATOR"
			},
		},
		{
			name: "database public connect",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Database.ACL = append(snapshot.Database.ACL, testACL("PUBLIC", "CONNECT"))
			},
		},
		{
			name: "database runtime connect",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Database.ACL = append(snapshot.Database.ACL, testACL("RUNTIME", "CONNECT"))
			},
		},
		{
			name: "database missing workload connect",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Database.ACL = removeACL(snapshot.Database.ACL, "WORKLOAD", "CONNECT")
			},
		},
		{
			name: "database grant option",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				aclByKey(t, snapshot.Database.ACL, "MIGRATOR", "CONNECT").Grantable = true
			},
		},
		{
			name: "schema wrong owner",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.Owner = "WORKLOAD"
			},
		},
		{
			name: "schema default public usage",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.ACL = append(snapshot.Schema.ACL, testACL("PUBLIC", "USAGE"))
			},
		},
		{
			name: "schema migrator direct usage",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.ACL = append(snapshot.Schema.ACL, testACL("MIGRATOR", "USAGE"))
			},
		},
		{
			name: "schema workload direct usage",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.ACL = append(snapshot.Schema.ACL, testACL("WORKLOAD", "USAGE"))
			},
		},
		{
			name: "schema runtime create",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.ACL = append(snapshot.Schema.ACL, testACL("RUNTIME", "CREATE"))
			},
		},
		{
			name: "schema missing runtime usage",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.ACL = removeACL(snapshot.Schema.ACL, "RUNTIME", "USAGE")
			},
		},
		{
			name: "schema unknown grantee",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.ACL = append(snapshot.Schema.ACL, testACL("UNKNOWN:901", "USAGE"))
			},
		},
		{
			name: "schema unknown grantor",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				aclByKey(t, snapshot.Schema.ACL, "RUNTIME", "USAGE").Grantor = "UNKNOWN:902"
			},
		},
		{
			name: "schema duplicate semantic acl",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				aclByKey(t, snapshot.Schema.ACL, "RUNTIME", "USAGE").Multiplicity = 2
			},
		},
		{
			name: "schema unexpected name",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Schema.Name = "shadow"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneDatabaseRoleAdmissionSnapshot(t, validDatabaseRoleAdmissionSnapshot("public"))
			test.mutate(&snapshot)
			assertDatabaseRoleAdmissionRejected(t, snapshot)
		})
	}
}

func TestDatabaseRoleAdmissionRejectsReviewedRelationAndColumnACLDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*databaseRoleAdmissionSnapshot)
	}{
		{
			name: "missing relation",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Relations = snapshot.Relations[1:]
			},
		},
		{
			name: "wrong relation owner",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relationByName(t, snapshot, "assets").Owner = "MIGRATOR"
			},
		},
		{
			name: "wrong relation kind",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relationByName(t, snapshot, "assets").Kind = "v"
			},
		},
		{
			name: "missing runtime select",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "assets")
				relation.ACL = removeACL(relation.ACL, "RUNTIME", "SELECT")
			},
		},
		{
			name: "unexpected runtime update",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "asset_type_details")
				relation.ACL = append(relation.ACL, testACL("RUNTIME", "UPDATE"))
			},
		},
		{
			name: "broad limiter bucket update",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "asset_source_limit_buckets")
				relation.ACL = append(relation.ACL, testACL("RUNTIME", "UPDATE"))
			},
		},
		{
			name: "limiter permit update",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "asset_source_limit_permits")
				relation.ACL = append(relation.ACL, testACL("RUNTIME", "UPDATE"))
			},
		},
		{
			name: "service parent update",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "services")
				relation.ACL = append(relation.ACL, testACL("RUNTIME", "UPDATE"))
			},
		},
		{
			name: "runtime delete",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "asset_sources")
				relation.ACL = append(relation.ACL, testACL("RUNTIME", "DELETE"))
			},
		},
		{
			name: "workload direct select",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "assets")
				relation.ACL = append(relation.ACL, testACL("WORKLOAD", "SELECT"))
			},
		},
		{
			name: "unknown relation grantee",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				relation := relationByName(t, snapshot, "assets")
				relation.ACL = append(relation.ACL, testACL("UNKNOWN:903", "SELECT"))
			},
		},
		{
			name: "relation wrong grantor",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				aclByKey(t, relationByName(t, snapshot, "assets").ACL, "RUNTIME", "SELECT").Grantor = "MIGRATOR"
			},
		},
		{
			name: "relation duplicate acl",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				aclByKey(t, relationByName(t, snapshot, "assets").ACL, "RUNTIME", "SELECT").Multiplicity = 2
			},
		},
		{
			name: "relation grant option",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				aclByKey(t, relationByName(t, snapshot, "assets").ACL, "RUNTIME", "SELECT").Grantable = true
			},
		},
		{
			name: "missing audit insert column",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns = removeColumnACL(snapshot.Columns, "audit_records", "details", "INSERT")
			},
		},
		{
			name: "unexpected audit insert column",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns = append(snapshot.Columns, testColumnACL("audit_records", "payload", "RUNTIME", "INSERT"))
			},
		},
		{
			name: "unexpected outbox update column",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns = append(snapshot.Columns, testColumnACL("outbox_events", "payload", "RUNTIME", "UPDATE"))
			},
		},
		{
			name: "missing limiter bucket cas column",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns = removeColumnACL(snapshot.Columns,
					"asset_source_limit_buckets", "last_receipt_id", "UPDATE")
			},
		},
		{
			name: "unexpected limiter bucket identity update",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns = append(snapshot.Columns,
					testColumnACL("asset_source_limit_buckets", "bucket_key", "RUNTIME", "UPDATE"))
			},
		},
		{
			name: "workload direct column acl",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns[0].ACL.Grantee = "WORKLOAD"
			},
		},
		{
			name: "column wrong grantor",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns[0].ACL.Grantor = "UNKNOWN:904"
			},
		},
		{
			name: "column duplicate acl",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Columns[0].ACL.Multiplicity = 2
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneDatabaseRoleAdmissionSnapshot(t, validDatabaseRoleAdmissionSnapshot("public"))
			test.mutate(&snapshot)
			assertDatabaseRoleAdmissionRejected(t, snapshot)
		})
	}
}

func TestDatabaseRoleAdmissionRejectsReviewedFunctionACLDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*databaseRoleAdmissionSnapshot)
	}{
		{
			name: "missing function",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				snapshot.Functions = snapshot.Functions[1:]
			},
		},
		{
			name: "wrong function owner",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				functionByIdentity(t, snapshot, "public.asset_catalog_text_valid(pg_catalog.text,pg_catalog.int4)").Owner = "RUNTIME"
			},
		},
		{
			name: "missing runtime execute",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot, "public.asset_catalog_text_valid(pg_catalog.text,pg_catalog.int4)")
				function.ACL = removeACL(function.ACL, "RUNTIME", "EXECUTE")
			},
		},
		{
			name: "missing runtime parent lock execute",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot,
					"public.asset_catalog_lock_exact_service_binding(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid)")
				function.ACL = removeACL(function.ACL, "RUNTIME", "EXECUTE")
			},
		},
		{
			name: "public execute",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot, "public.asset_catalog_text_valid(pg_catalog.text,pg_catalog.int4)")
				function.ACL = append(function.ACL, testACL("PUBLIC", "EXECUTE"))
			},
		},
		{
			name: "runtime trigger execute",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot, "public.reject_asset_catalog_delete()")
				function.ACL = append(function.ACL, testACL("RUNTIME", "EXECUTE"))
			},
		},
		{
			name: "workload direct execute",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot, "public.asset_catalog_sha256_valid(pg_catalog.text)")
				function.ACL = append(function.ACL, testACL("WORKLOAD", "EXECUTE"))
			},
		},
		{
			name: "unknown function grantor",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot, "public.asset_catalog_sha256_valid(pg_catalog.text)")
				aclByKey(t, function.ACL, "RUNTIME", "EXECUTE").Grantor = "UNKNOWN:905"
			},
		},
		{
			name: "function duplicate acl",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot, "public.asset_catalog_sha256_valid(pg_catalog.text)")
				aclByKey(t, function.ACL, "OWNER", "EXECUTE").Multiplicity = 2
			},
		},
		{
			name: "function grant option",
			mutate: func(snapshot *databaseRoleAdmissionSnapshot) {
				function := functionByIdentity(t, snapshot, "public.asset_catalog_sha256_valid(pg_catalog.text)")
				aclByKey(t, function.ACL, "RUNTIME", "EXECUTE").Grantable = true
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneDatabaseRoleAdmissionSnapshot(t, validDatabaseRoleAdmissionSnapshot("public"))
			test.mutate(&snapshot)
			assertDatabaseRoleAdmissionRejected(t, snapshot)
		})
	}
}

func TestDatabaseRoleAdmissionFailsClosedAtEveryBoundary(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*databaseRoleAdmissionDatabaseStub)
		wantQueries   int
		wantRollbacks int
	}{
		{
			name: "begin",
			configure: func(stub *databaseRoleAdmissionDatabaseStub) {
				stub.beginErr = errors.New("secret begin failure")
			},
			wantQueries: 0,
		},
		{
			name: "set local",
			configure: func(stub *databaseRoleAdmissionDatabaseStub) {
				stub.execErr = errors.New("secret set local failure")
			},
			wantQueries:   0,
			wantRollbacks: 1,
		},
		{
			name: "query",
			configure: func(stub *databaseRoleAdmissionDatabaseStub) {
				stub.rowErr = errors.New("secret query failure")
			},
			wantQueries:   1,
			wantRollbacks: 1,
		},
		{
			name: "rollback",
			configure: func(stub *databaseRoleAdmissionDatabaseStub) {
				stub.rollbackErr = errors.New("secret rollback failure")
			},
			wantQueries:   1,
			wantRollbacks: 1,
		},
		{
			name: "invalid json",
			configure: func(stub *databaseRoleAdmissionDatabaseStub) {
				stub.rawSnapshot = []byte(`{"session_user":`)
			},
			wantQueries:   1,
			wantRollbacks: 1,
		},
		{
			name: "unknown json field",
			configure: func(stub *databaseRoleAdmissionDatabaseStub) {
				raw, err := json.Marshal(stub.snapshot)
				if err != nil {
					panic(err)
				}
				stub.rawSnapshot = append(raw[:len(raw)-1], []byte(`,"unreviewed":true}`)...)
			},
			wantQueries:   1,
			wantRollbacks: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &databaseRoleAdmissionDatabaseStub{
				snapshot: validDatabaseRoleAdmissionSnapshot("public"),
			}
			test.configure(stub)
			probe := newDatabaseRoleAdmission(stub, "public")

			err := probe.Check(context.Background())
			if !errors.Is(err, ErrDatabaseRoleUnavailable) {
				t.Fatalf("Check() error = %v, want %q", err, ErrDatabaseRoleUnavailable)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("Check() leaked database failure: %q", err)
			}
			if got := stub.queryCalls; got != test.wantQueries {
				t.Fatalf("Check() query calls = %d, want %d", got, test.wantQueries)
			}
			if got := stub.rollbackCalls; got != test.wantRollbacks {
				t.Fatalf("Check() rollback calls = %d, want %d", got, test.wantRollbacks)
			}
		})
	}
}

func TestDatabaseRoleAdmissionRejectsInvalidConstructionWithoutQuery(t *testing.T) {
	tests := []struct {
		name  string
		probe *DatabaseRoleAdmission
		ctx   context.Context
	}{
		{name: "nil receiver", probe: nil, ctx: context.Background()},
		{name: "nil pool", probe: NewDatabaseRoleAdmission(nil, "public"), ctx: context.Background()},
		{name: "empty schema", probe: newDatabaseRoleAdmission(&databaseRoleAdmissionDatabaseStub{}, ""), ctx: context.Background()},
		{name: "padded schema", probe: newDatabaseRoleAdmission(&databaseRoleAdmissionDatabaseStub{}, " public"), ctx: context.Background()},
		{name: "control schema", probe: newDatabaseRoleAdmission(&databaseRoleAdmissionDatabaseStub{}, "public\nshadow"), ctx: context.Background()},
		{name: "long schema", probe: newDatabaseRoleAdmission(&databaseRoleAdmissionDatabaseStub{}, strings.Repeat("s", 64)), ctx: context.Background()},
		{name: "nil context", probe: newDatabaseRoleAdmission(&databaseRoleAdmissionDatabaseStub{}, "public"), ctx: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.probe.Check(test.ctx)
			if !errors.Is(err, ErrDatabaseRoleUnavailable) {
				t.Fatalf("Check() error = %v, want %q", err, ErrDatabaseRoleUnavailable)
			}
		})
	}
}

func TestDatabaseRoleAdmissionUsesCatalogsAndExplicitTrustedSchema(t *testing.T) {
	stub := &databaseRoleAdmissionDatabaseStub{snapshot: validDatabaseRoleAdmissionSnapshot("control_plane")}
	probe := newDatabaseRoleAdmission(stub, "control_plane")

	if err := probe.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	lowerSQL := strings.ToLower(stub.lastSQL)
	for _, required := range []string{
		"session_user",
		"current_user",
		"pg_catalog.pg_auth_members",
		"pg_catalog.aclexplode",
		"pg_catalog.acldefault",
		"coalesce(namespace.nspacl",
		"with ordinality",
	} {
		if !strings.Contains(lowerSQL, required) {
			t.Fatalf("admission query missing reviewed catalog expression %q", required)
		}
	}
	for _, forbidden := range []string{"current_schema", "information_schema"} {
		if strings.Contains(lowerSQL, forbidden) {
			t.Fatalf("admission query relies on forbidden object resolution %q", forbidden)
		}
	}
	if got, want := strings.ToLower(databaseRoleAdmissionSetLocalSearchPathSQL), "set local search_path = pg_catalog, pg_temp"; got != want {
		t.Fatalf("SET LOCAL SQL = %q, want %q", got, want)
	}
}

func assertDatabaseRoleAdmissionRejected(t *testing.T, snapshot databaseRoleAdmissionSnapshot) {
	t.Helper()
	stub := &databaseRoleAdmissionDatabaseStub{snapshot: snapshot}
	probe := newDatabaseRoleAdmission(stub, "public")

	err := probe.Check(context.Background())
	if !errors.Is(err, ErrDatabaseRoleUnavailable) {
		t.Fatalf("Check() error = %v, want %q", err, ErrDatabaseRoleUnavailable)
	}
}

func cloneDatabaseRoleAdmissionSnapshot(
	t *testing.T,
	snapshot databaseRoleAdmissionSnapshot,
) databaseRoleAdmissionSnapshot {
	t.Helper()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var clone databaseRoleAdmissionSnapshot
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func validDatabaseRoleAdmissionSnapshot(trustedSchema string) databaseRoleAdmissionSnapshot {
	snapshot := databaseRoleAdmissionSnapshot{
		SessionUser: "aiops_control_plane_workload",
		CurrentUser: "aiops_control_plane_workload",
		Roles: []databaseRoleAdmissionRole{
			{Label: "MIGRATOR", Name: "aiops_migrator", Login: true, Inherit: false},
			{Label: "SCHEMA_OWNER", Name: "aiops_schema_owner", Login: false, Inherit: false},
			{Label: "RUNTIME", Name: "aiops_control_plane_runtime", Login: false, Inherit: false},
			{Label: "WORKLOAD", Name: "aiops_control_plane_workload", Login: true, Inherit: true},
		},
		Memberships: []databaseRoleAdmissionMembership{
			{Role: "SCHEMA_OWNER", Member: "MIGRATOR", Inherit: false, Set: true, Admin: false},
			{Role: "RUNTIME", Member: "WORKLOAD", Inherit: true, Set: false, Admin: false},
		},
		Capabilities: []databaseRoleAdmissionCapability{
			{Member: "MIGRATOR", Role: "SCHEMA_OWNER", Privilege: "SET", Allowed: true},
			{Member: "MIGRATOR", Role: "SCHEMA_OWNER", Privilege: "USAGE", Allowed: false},
			{Member: "WORKLOAD", Role: "RUNTIME", Privilege: "SET", Allowed: false},
			{Member: "WORKLOAD", Role: "RUNTIME", Privilege: "USAGE", Allowed: true},
			{Member: "WORKLOAD", Role: "MIGRATOR", Privilege: "SET", Allowed: false},
			{Member: "WORKLOAD", Role: "SCHEMA_OWNER", Privilege: "SET", Allowed: false},
		},
		Database: databaseRoleAdmissionObject{
			Owner: "OWNER",
			ACL: []databaseRoleAdmissionACL{
				testACL("OWNER", "CONNECT"),
				testACL("OWNER", "CREATE"),
				testACL("OWNER", "TEMPORARY"),
				testACL("MIGRATOR", "CONNECT"),
				testACL("WORKLOAD", "CONNECT"),
			},
		},
		Schema: databaseRoleAdmissionSchema{
			Name:  trustedSchema,
			Owner: "OWNER",
			ACL: []databaseRoleAdmissionACL{
				testACL("OWNER", "CREATE"),
				testACL("OWNER", "USAGE"),
				testACL("RUNTIME", "USAGE"),
			},
		},
	}

	relationRuntimePrivileges := map[string][]string{
		"workspaces":                        {"SELECT"},
		"environments":                      {"SELECT"},
		"services":                          {"SELECT"},
		"service_bindings":                  {"SELECT"},
		"audit_records":                     {"SELECT"},
		"outbox_events":                     {"SELECT"},
		"asset_sources":                     {"SELECT", "INSERT", "UPDATE"},
		"asset_source_revisions":            {"SELECT", "INSERT", "UPDATE"},
		"asset_source_revision_authorities": {"SELECT", "INSERT"},
		"asset_source_runs":                 {"SELECT", "INSERT", "UPDATE"},
		"asset_source_limit_buckets":        {"SELECT", "INSERT"},
		"asset_source_limit_permits":        {"SELECT", "INSERT"},
		"asset_observations":                {"SELECT", "INSERT"},
		"assets":                            {"SELECT", "INSERT", "UPDATE"},
		"asset_type_details":                {"SELECT", "INSERT"},
		"asset_conflicts":                   {"SELECT", "INSERT", "UPDATE"},
		"asset_relationships":               {"SELECT", "INSERT", "UPDATE"},
		"service_asset_bindings":            {"SELECT", "INSERT", "UPDATE"},
	}
	for _, relationName := range []string{
		"tenants",
		"integrations",
		"workspaces",
		"environments",
		"services",
		"service_bindings",
		"audit_records",
		"outbox_events",
		"asset_sources",
		"asset_source_revisions",
		"asset_source_revision_authorities",
		"asset_source_runs",
		"asset_source_limit_buckets",
		"asset_source_limit_permits",
		"asset_observations",
		"assets",
		"asset_type_details",
		"asset_conflicts",
		"asset_relationships",
		"service_asset_bindings",
	} {
		relation := databaseRoleAdmissionRelation{Name: relationName, Kind: "r", Owner: "OWNER"}
		for _, privilege := range []string{
			"DELETE", "INSERT", "MAINTAIN", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE",
		} {
			relation.ACL = append(relation.ACL, testACL("OWNER", privilege))
		}
		for _, privilege := range relationRuntimePrivileges[relationName] {
			relation.ACL = append(relation.ACL, testACL("RUNTIME", privilege))
		}
		snapshot.Relations = append(snapshot.Relations, relation)
	}

	for _, column := range []string{
		"id", "tenant_id", "workspace_id", "actor_type", "actor_id", "action", "resource_type",
		"resource_id", "request_id", "trace_id", "payload_hash", "details", "created_at",
	} {
		snapshot.Columns = append(snapshot.Columns, testColumnACL("audit_records", column, "RUNTIME", "INSERT"))
	}
	for _, column := range []string{
		"id", "tenant_id", "workspace_id", "aggregate_type", "aggregate_id", "aggregate_version",
		"event_type", "payload", "created_at", "available_at",
	} {
		snapshot.Columns = append(snapshot.Columns, testColumnACL("outbox_events", column, "RUNTIME", "INSERT"))
	}
	for _, column := range []string{
		"available_at", "claimed_at", "claimed_by", "claim_token", "claim_expires_at", "delivered_at",
		"delivered_claim_token", "attempts", "last_error_code",
	} {
		snapshot.Columns = append(snapshot.Columns, testColumnACL("outbox_events", column, "RUNTIME", "UPDATE"))
	}
	for _, column := range []string{"next_token_at", "last_receipt_id", "version", "updated_at"} {
		snapshot.Columns = append(snapshot.Columns,
			testColumnACL("asset_source_limit_buckets", column, "RUNTIME", "UPDATE"))
	}

	sourceRunsType := trustedSchema + ".asset_source_runs"
	sourceType := trustedSchema + ".asset_sources"
	sourceRevisionType := trustedSchema + ".asset_source_revisions"
	runtimeFunctions := map[string]bool{
		"asset_catalog_text_valid(pg_catalog.text,pg_catalog.int4)":                                                   true,
		"asset_catalog_code_valid(pg_catalog.text,pg_catalog.int4)":                                                   true,
		"asset_catalog_sha256_valid(pg_catalog.text)":                                                                 true,
		"asset_catalog_provider_kind_valid(pg_catalog.text)":                                                          true,
		"asset_catalog_idempotency_key_valid(pg_catalog.text)":                                                        true,
		"asset_catalog_json_object_valid(pg_catalog.bytea,pg_catalog.int4,pg_catalog.int4)":                           true,
		"asset_catalog_labels_valid(pg_catalog.jsonb)":                                                                true,
		"asset_catalog_checkpoint_envelope_valid(pg_catalog.bytea)":                                                   true,
		"asset_catalog_field_provenance_valid(pg_catalog.bytea)":                                                      true,
		"asset_catalog_framed_value_v1(pg_catalog.bytea)":                                                             true,
		"asset_catalog_source_run_no_credential_digest(" + sourceRunsType + ")":                                       true,
		"asset_catalog_source_run_delay_intent_digest(" + sourceRunsType + ",pg_catalog.text,pg_catalog.timestamptz)": true,
		"asset_catalog_source_run_failure_override_digest(" + sourceRunsType + ",pg_catalog.text)":                    true,
		"asset_catalog_source_run_terminal_digest(" + sourceRunsType + ",pg_catalog.text,pg_catalog.text)":            true,
		"asset_catalog_opaque_reference_valid(pg_catalog.text)":                                                       true,
		"asset_catalog_future_source_gate_admitted(" + sourceType + ")":                                               true,
		"asset_catalog_source_revision_binding_digest(" + sourceRevisionType + ")":                                    true,
		"asset_catalog_lock_exact_service_binding(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid)":   true,
	}
	for _, functionName := range []string{
		"asset_catalog_text_valid(pg_catalog.text,pg_catalog.int4)",
		"asset_catalog_code_valid(pg_catalog.text,pg_catalog.int4)",
		"asset_catalog_sha256_valid(pg_catalog.text)",
		"asset_catalog_provider_kind_valid(pg_catalog.text)",
		"asset_catalog_idempotency_key_valid(pg_catalog.text)",
		"asset_catalog_json_object_valid(pg_catalog.bytea,pg_catalog.int4,pg_catalog.int4)",
		"asset_catalog_labels_valid(pg_catalog.jsonb)",
		"asset_catalog_checkpoint_envelope_valid(pg_catalog.bytea)",
		"asset_catalog_field_provenance_valid(pg_catalog.bytea)",
		"asset_catalog_framed_value_v1(pg_catalog.bytea)",
		"asset_catalog_source_run_no_credential_digest(" + sourceRunsType + ")",
		"asset_catalog_source_run_delay_intent_digest(" + sourceRunsType + ",pg_catalog.text,pg_catalog.timestamptz)",
		"asset_catalog_source_run_failure_override_digest(" + sourceRunsType + ",pg_catalog.text)",
		"asset_catalog_source_run_terminal_digest(" + sourceRunsType + ",pg_catalog.text,pg_catalog.text)",
		"asset_catalog_opaque_reference_valid(pg_catalog.text)",
		"asset_catalog_future_source_gate_admitted(" + sourceType + ")",
		"asset_catalog_source_revision_binding_digest(" + sourceRevisionType + ")",
		"asset_catalog_lock_exact_service_binding(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid)",
		"validate_asset_management_audit_insert()",
		"reject_asset_catalog_immutable()",
		"reject_asset_catalog_delete()",
		"reject_asset_catalog_truncate()",
		"enforce_assets_transition()",
		"enforce_asset_conflict_transition()",
		"enforce_asset_catalog_edge_mutation()",
		"enforce_asset_relationship_mutation()",
		"validate_asset_relationship_page_closure()",
		"enforce_asset_sources_mutation()",
		"validate_asset_source_deferred_state()",
		"enforce_asset_source_revision_transition()",
		"validate_asset_source_revision_deferred_state()",
		"enforce_asset_source_run_mutation()",
		"validate_asset_source_run_page_closure()",
		"validate_asset_source_run_terminal_closure()",
		"enforce_asset_observation_admission()",
		"validate_asset_observation_page_closure()",
	} {
		identity := trustedSchema + "." + functionName
		function := databaseRoleAdmissionFunction{
			Identity: identity,
			Owner:    "OWNER",
			ACL:      []databaseRoleAdmissionACL{testACL("OWNER", "EXECUTE")},
		}
		if runtimeFunctions[functionName] {
			function.ACL = append(function.ACL, testACL("RUNTIME", "EXECUTE"))
		}
		snapshot.Functions = append(snapshot.Functions, function)
	}

	return snapshot
}

func testACL(grantee string, privilege string) databaseRoleAdmissionACL {
	return databaseRoleAdmissionACL{
		Grantee:      grantee,
		Grantor:      "OWNER",
		Privilege:    privilege,
		Grantable:    false,
		Multiplicity: 1,
	}
}

func testColumnACL(
	relation string,
	column string,
	grantee string,
	privilege string,
) databaseRoleAdmissionColumnACL {
	acl := testACL(grantee, privilege)
	return databaseRoleAdmissionColumnACL{Relation: relation, Column: column, ACL: acl}
}

func roleByLabel(
	t *testing.T,
	snapshot *databaseRoleAdmissionSnapshot,
	label string,
) *databaseRoleAdmissionRole {
	t.Helper()
	for index := range snapshot.Roles {
		if snapshot.Roles[index].Label == label {
			return &snapshot.Roles[index]
		}
	}
	t.Fatalf("missing role %q", label)
	return nil
}

func membership(
	t *testing.T,
	snapshot *databaseRoleAdmissionSnapshot,
	member string,
	role string,
) *databaseRoleAdmissionMembership {
	t.Helper()
	for index := range snapshot.Memberships {
		candidate := &snapshot.Memberships[index]
		if candidate.Member == member && candidate.Role == role {
			return candidate
		}
	}
	t.Fatalf("missing membership %s -> %s", member, role)
	return nil
}

func capability(
	t *testing.T,
	snapshot *databaseRoleAdmissionSnapshot,
	member string,
	role string,
	privilege string,
) *databaseRoleAdmissionCapability {
	t.Helper()
	for index := range snapshot.Capabilities {
		candidate := &snapshot.Capabilities[index]
		if candidate.Member == member && candidate.Role == role && candidate.Privilege == privilege {
			return candidate
		}
	}
	t.Fatalf("missing capability %s -> %s %s", member, role, privilege)
	return nil
}

func relationByName(
	t *testing.T,
	snapshot *databaseRoleAdmissionSnapshot,
	name string,
) *databaseRoleAdmissionRelation {
	t.Helper()
	for index := range snapshot.Relations {
		if snapshot.Relations[index].Name == name {
			return &snapshot.Relations[index]
		}
	}
	t.Fatalf("missing relation %q", name)
	return nil
}

func functionByIdentity(
	t *testing.T,
	snapshot *databaseRoleAdmissionSnapshot,
	identity string,
) *databaseRoleAdmissionFunction {
	t.Helper()
	for index := range snapshot.Functions {
		if snapshot.Functions[index].Identity == identity {
			return &snapshot.Functions[index]
		}
	}
	t.Fatalf("missing function %q", identity)
	return nil
}

func aclByKey(
	t *testing.T,
	acls []databaseRoleAdmissionACL,
	grantee string,
	privilege string,
) *databaseRoleAdmissionACL {
	t.Helper()
	for index := range acls {
		if acls[index].Grantee == grantee && acls[index].Privilege == privilege {
			return &acls[index]
		}
	}
	t.Fatalf("missing ACL %s %s", grantee, privilege)
	return nil
}

func removeACL(
	acls []databaseRoleAdmissionACL,
	grantee string,
	privilege string,
) []databaseRoleAdmissionACL {
	result := make([]databaseRoleAdmissionACL, 0, len(acls))
	for _, acl := range acls {
		if acl.Grantee == grantee && acl.Privilege == privilege {
			continue
		}
		result = append(result, acl)
	}
	return result
}

func removeColumnACL(
	columns []databaseRoleAdmissionColumnACL,
	relation string,
	column string,
	privilege string,
) []databaseRoleAdmissionColumnACL {
	result := make([]databaseRoleAdmissionColumnACL, 0, len(columns))
	for _, candidate := range columns {
		if candidate.Relation == relation && candidate.Column == column && candidate.ACL.Privilege == privilege {
			continue
		}
		result = append(result, candidate)
	}
	return result
}
