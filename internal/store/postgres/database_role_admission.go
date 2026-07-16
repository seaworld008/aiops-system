package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const DatabaseRoleUnavailableCode = "asset_catalog_unavailable"

var ErrDatabaseRoleUnavailable = errors.New(DatabaseRoleUnavailableCode)

type DatabaseRoleAdmission struct {
	database      databaseRoleAdmissionDatabase
	trustedSchema string
}

type databaseRoleAdmissionDatabase interface {
	BeginTx(context.Context, pgx.TxOptions) (databaseRoleAdmissionTransaction, error)
}

type databaseRoleAdmissionTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) databaseRoleAdmissionRow
	Rollback(context.Context) error
}

type databaseRoleAdmissionRow interface {
	Scan(...any) error
}

type pgxPoolDatabaseRoleAdmissionDatabase struct {
	pool *pgxpool.Pool
}

type pgxDatabaseRoleAdmissionTransaction struct {
	transaction pgx.Tx
}

func (database pgxPoolDatabaseRoleAdmissionDatabase) BeginTx(
	ctx context.Context,
	options pgx.TxOptions,
) (databaseRoleAdmissionTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return pgxDatabaseRoleAdmissionTransaction{transaction: transaction}, nil
}

func (transaction pgxDatabaseRoleAdmissionTransaction) Exec(
	ctx context.Context,
	sql string,
	args ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, sql, args...)
	return err
}

func (transaction pgxDatabaseRoleAdmissionTransaction) QueryRow(
	ctx context.Context,
	sql string,
	args ...any,
) databaseRoleAdmissionRow {
	return transaction.transaction.QueryRow(ctx, sql, args...)
}

func (transaction pgxDatabaseRoleAdmissionTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

type databaseRoleAdmissionSnapshot struct {
	SessionUser  string                            `json:"session_user"`
	CurrentUser  string                            `json:"current_user"`
	Roles        []databaseRoleAdmissionRole       `json:"roles"`
	Memberships  []databaseRoleAdmissionMembership `json:"memberships"`
	Capabilities []databaseRoleAdmissionCapability `json:"capabilities"`
	Database     databaseRoleAdmissionObject       `json:"database"`
	Schema       databaseRoleAdmissionSchema       `json:"schema"`
	Relations    []databaseRoleAdmissionRelation   `json:"relations"`
	Columns      []databaseRoleAdmissionColumnACL  `json:"columns"`
	Functions    []databaseRoleAdmissionFunction   `json:"functions"`
}

type databaseRoleAdmissionRole struct {
	Label       string `json:"label"`
	Name        string `json:"name"`
	Login       bool   `json:"login"`
	Inherit     bool   `json:"inherit"`
	Superuser   bool   `json:"superuser"`
	CreateDB    bool   `json:"create_db"`
	CreateRole  bool   `json:"create_role"`
	Replication bool   `json:"replication"`
	BypassRLS   bool   `json:"bypass_rls"`
}

type databaseRoleAdmissionMembership struct {
	Role    string `json:"role"`
	Member  string `json:"member"`
	Inherit bool   `json:"inherit"`
	Set     bool   `json:"set"`
	Admin   bool   `json:"admin"`
}

type databaseRoleAdmissionCapability struct {
	Member    string `json:"member"`
	Role      string `json:"role"`
	Privilege string `json:"privilege"`
	Allowed   bool   `json:"allowed"`
}

type databaseRoleAdmissionObject struct {
	Owner string                     `json:"owner"`
	ACL   []databaseRoleAdmissionACL `json:"acl"`
}

type databaseRoleAdmissionSchema struct {
	Name  string                     `json:"name"`
	Owner string                     `json:"owner"`
	ACL   []databaseRoleAdmissionACL `json:"acl"`
}

type databaseRoleAdmissionRelation struct {
	Name  string                     `json:"name"`
	Kind  string                     `json:"kind"`
	Owner string                     `json:"owner"`
	ACL   []databaseRoleAdmissionACL `json:"acl"`
}

type databaseRoleAdmissionColumnACL struct {
	Relation string                   `json:"relation"`
	Column   string                   `json:"column"`
	ACL      databaseRoleAdmissionACL `json:"acl"`
}

type databaseRoleAdmissionFunction struct {
	Identity string                     `json:"identity"`
	Owner    string                     `json:"owner"`
	ACL      []databaseRoleAdmissionACL `json:"acl"`
}

type databaseRoleAdmissionACL struct {
	Grantee      string `json:"grantee"`
	Grantor      string `json:"grantor"`
	Privilege    string `json:"privilege"`
	Grantable    bool   `json:"grantable"`
	Multiplicity int    `json:"multiplicity"`
}

const databaseRoleAdmissionSetLocalSearchPathSQL = `SET LOCAL search_path = pg_catalog, pg_temp`

// NewDatabaseRoleAdmission creates the application-startup role and ACL probe.
// The caller is intentionally not allowed to select a migrator admission mode.
func NewDatabaseRoleAdmission(pool *pgxpool.Pool, trustedSchema string) *DatabaseRoleAdmission {
	if pool == nil {
		return &DatabaseRoleAdmission{trustedSchema: trustedSchema}
	}
	return newDatabaseRoleAdmission(
		pgxPoolDatabaseRoleAdmissionDatabase{pool: pool},
		trustedSchema,
	)
}

func newDatabaseRoleAdmission(
	database databaseRoleAdmissionDatabase,
	trustedSchema string,
) *DatabaseRoleAdmission {
	return &DatabaseRoleAdmission{database: database, trustedSchema: trustedSchema}
}

// Check admits only an unaltered aiops_control_plane_workload application
// session and the exact reviewed PostgreSQL role and direct-ACL surface.
func (admission *DatabaseRoleAdmission) Check(ctx context.Context) error {
	if admission == nil || admission.database == nil || ctx == nil ||
		!databaseRoleTrustedSchemaValid(admission.trustedSchema) {
		return ErrDatabaseRoleUnavailable
	}

	transaction, err := admission.database.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return ErrDatabaseRoleUnavailable
	}

	actual, loadErr := loadDatabaseRoleAdmissionSnapshot(
		ctx,
		transaction,
		admission.trustedSchema,
	)
	rollbackErr := rollbackDatabaseRoleAdmissionTransaction(transaction)
	if loadErr != nil || rollbackErr != nil {
		return ErrDatabaseRoleUnavailable
	}

	expected := expectedDatabaseRoleAdmissionSnapshot(admission.trustedSchema)
	normalizeDatabaseRoleAdmissionSnapshot(&actual)
	normalizeDatabaseRoleAdmissionSnapshot(&expected)
	if !reflect.DeepEqual(actual, expected) {
		return ErrDatabaseRoleUnavailable
	}
	return nil
}

func loadDatabaseRoleAdmissionSnapshot(
	ctx context.Context,
	transaction databaseRoleAdmissionTransaction,
	trustedSchema string,
) (databaseRoleAdmissionSnapshot, error) {
	var snapshot databaseRoleAdmissionSnapshot
	// Object resolution is protected before PostgreSQL parses the catalog query.
	if err := transaction.Exec(ctx, databaseRoleAdmissionSetLocalSearchPathSQL); err != nil {
		return snapshot, err
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, databaseRoleAdmissionSQL, trustedSchema).Scan(&encoded); err != nil {
		return snapshot, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return databaseRoleAdmissionSnapshot{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return databaseRoleAdmissionSnapshot{}, errors.New("database role admission snapshot has trailing data")
	}
	return snapshot, nil
}

func rollbackDatabaseRoleAdmissionTransaction(transaction databaseRoleAdmissionTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return transaction.Rollback(ctx)
}

func databaseRoleTrustedSchemaValid(schema string) bool {
	if len(schema) == 0 || len(schema) > 63 || !utf8.ValidString(schema) ||
		strings.TrimSpace(schema) != schema {
		return false
	}
	for _, character := range schema {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func expectedDatabaseRoleAdmissionSnapshot(trustedSchema string) databaseRoleAdmissionSnapshot {
	snapshot := databaseRoleAdmissionSnapshot{
		SessionUser: "aiops_control_plane_workload",
		CurrentUser: "aiops_control_plane_workload",
		Roles: []databaseRoleAdmissionRole{
			{Label: "MIGRATOR", Name: "aiops_migrator", Login: true},
			{Label: "SCHEMA_OWNER", Name: "aiops_schema_owner"},
			{Label: "RUNTIME", Name: "aiops_control_plane_runtime"},
			{Label: "WORKLOAD", Name: "aiops_control_plane_workload", Login: true, Inherit: true},
		},
		Memberships: []databaseRoleAdmissionMembership{
			{Role: "SCHEMA_OWNER", Member: "MIGRATOR", Set: true},
			{Role: "RUNTIME", Member: "WORKLOAD", Inherit: true},
		},
		Capabilities: []databaseRoleAdmissionCapability{
			{Member: "MIGRATOR", Role: "SCHEMA_OWNER", Privilege: "SET", Allowed: true},
			{Member: "MIGRATOR", Role: "SCHEMA_OWNER", Privilege: "USAGE"},
			{Member: "WORKLOAD", Role: "RUNTIME", Privilege: "SET"},
			{Member: "WORKLOAD", Role: "RUNTIME", Privilege: "USAGE", Allowed: true},
			{Member: "WORKLOAD", Role: "MIGRATOR", Privilege: "SET"},
			{Member: "WORKLOAD", Role: "SCHEMA_OWNER", Privilege: "SET"},
		},
		Database: databaseRoleAdmissionObject{
			Owner: "OWNER",
			ACL: []databaseRoleAdmissionACL{
				newDatabaseRoleAdmissionACL("OWNER", "CONNECT"),
				newDatabaseRoleAdmissionACL("OWNER", "CREATE"),
				newDatabaseRoleAdmissionACL("OWNER", "TEMPORARY"),
				newDatabaseRoleAdmissionACL("MIGRATOR", "CONNECT"),
				newDatabaseRoleAdmissionACL("WORKLOAD", "CONNECT"),
			},
		},
		Schema: databaseRoleAdmissionSchema{
			Name:  trustedSchema,
			Owner: "OWNER",
			ACL: []databaseRoleAdmissionACL{
				newDatabaseRoleAdmissionACL("OWNER", "CREATE"),
				newDatabaseRoleAdmissionACL("OWNER", "USAGE"),
				newDatabaseRoleAdmissionACL("RUNTIME", "USAGE"),
			},
		},
	}

	runtimePrivileges := map[string][]string{
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
	for _, name := range databaseRoleAdmissionRelationNames {
		relation := databaseRoleAdmissionRelation{Name: name, Kind: "r", Owner: "OWNER"}
		for _, privilege := range []string{
			"DELETE", "INSERT", "MAINTAIN", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE",
		} {
			relation.ACL = append(relation.ACL, newDatabaseRoleAdmissionACL("OWNER", privilege))
		}
		for _, privilege := range runtimePrivileges[name] {
			relation.ACL = append(relation.ACL, newDatabaseRoleAdmissionACL("RUNTIME", privilege))
		}
		snapshot.Relations = append(snapshot.Relations, relation)
	}

	appendColumnACLs := func(relation string, privilege string, columns []string) {
		for _, column := range columns {
			snapshot.Columns = append(snapshot.Columns, databaseRoleAdmissionColumnACL{
				Relation: relation,
				Column:   column,
				ACL:      newDatabaseRoleAdmissionACL("RUNTIME", privilege),
			})
		}
	}
	appendColumnACLs("audit_records", "INSERT", []string{
		"id", "tenant_id", "workspace_id", "actor_type", "actor_id", "action", "resource_type",
		"resource_id", "request_id", "trace_id", "payload_hash", "details", "created_at",
	})
	appendColumnACLs("outbox_events", "INSERT", []string{
		"id", "tenant_id", "workspace_id", "aggregate_type", "aggregate_id", "aggregate_version",
		"event_type", "payload", "created_at", "available_at",
	})
	appendColumnACLs("outbox_events", "UPDATE", []string{
		"available_at", "claimed_at", "claimed_by", "claim_token", "claim_expires_at", "delivered_at",
		"delivered_claim_token", "attempts", "last_error_code",
	})
	appendColumnACLs("asset_source_limit_buckets", "UPDATE", []string{
		"next_token_at", "last_receipt_id", "version", "updated_at",
	})

	sourceRunsType := trustedSchema + ".asset_source_runs"
	sourceType := trustedSchema + ".asset_sources"
	sourceRevisionType := trustedSchema + ".asset_source_revisions"
	runtimeFunctions := map[string]struct{}{
		"asset_catalog_text_valid(pg_catalog.text,pg_catalog.int4)":                                                   {},
		"asset_catalog_code_valid(pg_catalog.text,pg_catalog.int4)":                                                   {},
		"asset_catalog_sha256_valid(pg_catalog.text)":                                                                 {},
		"asset_catalog_provider_kind_valid(pg_catalog.text)":                                                          {},
		"asset_catalog_idempotency_key_valid(pg_catalog.text)":                                                        {},
		"asset_catalog_json_object_valid(pg_catalog.bytea,pg_catalog.int4,pg_catalog.int4)":                           {},
		"asset_catalog_labels_valid(pg_catalog.jsonb)":                                                                {},
		"asset_catalog_checkpoint_envelope_valid(pg_catalog.bytea)":                                                   {},
		"asset_catalog_field_provenance_valid(pg_catalog.bytea)":                                                      {},
		"asset_catalog_framed_value_v1(pg_catalog.bytea)":                                                             {},
		"asset_catalog_source_run_no_credential_digest(" + sourceRunsType + ")":                                       {},
		"asset_catalog_source_run_delay_intent_digest(" + sourceRunsType + ",pg_catalog.text,pg_catalog.timestamptz)": {},
		"asset_catalog_source_run_failure_override_digest(" + sourceRunsType + ",pg_catalog.text)":                    {},
		"asset_catalog_source_run_terminal_digest(" + sourceRunsType + ",pg_catalog.text,pg_catalog.text)":            {},
		"asset_catalog_opaque_reference_valid(pg_catalog.text)":                                                       {},
		"asset_catalog_future_source_gate_admitted(" + sourceType + ")":                                               {},
		"asset_catalog_source_revision_binding_digest(" + sourceRevisionType + ")":                                    {},
		"asset_catalog_lock_exact_service_binding(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid)":   {},
	}
	functionSignatures := []string{
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
	}
	for _, signature := range functionSignatures {
		function := databaseRoleAdmissionFunction{
			Identity: trustedSchema + "." + signature,
			Owner:    "OWNER",
			ACL:      []databaseRoleAdmissionACL{newDatabaseRoleAdmissionACL("OWNER", "EXECUTE")},
		}
		if _, ok := runtimeFunctions[signature]; ok {
			function.ACL = append(function.ACL, newDatabaseRoleAdmissionACL("RUNTIME", "EXECUTE"))
		}
		snapshot.Functions = append(snapshot.Functions, function)
	}
	return snapshot
}

var databaseRoleAdmissionRelationNames = []string{
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
}

func newDatabaseRoleAdmissionACL(grantee string, privilege string) databaseRoleAdmissionACL {
	return databaseRoleAdmissionACL{
		Grantee:      grantee,
		Grantor:      "OWNER",
		Privilege:    privilege,
		Multiplicity: 1,
	}
}

func normalizeDatabaseRoleAdmissionSnapshot(snapshot *databaseRoleAdmissionSnapshot) {
	sort.Slice(snapshot.Roles, func(left int, right int) bool {
		return snapshot.Roles[left].Label < snapshot.Roles[right].Label
	})
	sort.Slice(snapshot.Memberships, func(left int, right int) bool {
		leftMembership := snapshot.Memberships[left]
		rightMembership := snapshot.Memberships[right]
		if leftMembership.Role != rightMembership.Role {
			return leftMembership.Role < rightMembership.Role
		}
		return leftMembership.Member < rightMembership.Member
	})
	sort.Slice(snapshot.Capabilities, func(left int, right int) bool {
		leftCapability := snapshot.Capabilities[left]
		rightCapability := snapshot.Capabilities[right]
		if leftCapability.Member != rightCapability.Member {
			return leftCapability.Member < rightCapability.Member
		}
		if leftCapability.Role != rightCapability.Role {
			return leftCapability.Role < rightCapability.Role
		}
		return leftCapability.Privilege < rightCapability.Privilege
	})
	normalizeDatabaseRoleAdmissionACLs(snapshot.Database.ACL)
	normalizeDatabaseRoleAdmissionACLs(snapshot.Schema.ACL)
	for index := range snapshot.Relations {
		normalizeDatabaseRoleAdmissionACLs(snapshot.Relations[index].ACL)
	}
	sort.Slice(snapshot.Relations, func(left int, right int) bool {
		return snapshot.Relations[left].Name < snapshot.Relations[right].Name
	})
	sort.Slice(snapshot.Columns, func(left int, right int) bool {
		leftColumn := snapshot.Columns[left]
		rightColumn := snapshot.Columns[right]
		if leftColumn.Relation != rightColumn.Relation {
			return leftColumn.Relation < rightColumn.Relation
		}
		if leftColumn.Column != rightColumn.Column {
			return leftColumn.Column < rightColumn.Column
		}
		return databaseRoleAdmissionACLLess(leftColumn.ACL, rightColumn.ACL)
	})
	for index := range snapshot.Functions {
		normalizeDatabaseRoleAdmissionACLs(snapshot.Functions[index].ACL)
	}
	sort.Slice(snapshot.Functions, func(left int, right int) bool {
		return snapshot.Functions[left].Identity < snapshot.Functions[right].Identity
	})
}

func normalizeDatabaseRoleAdmissionACLs(acls []databaseRoleAdmissionACL) {
	sort.Slice(acls, func(left int, right int) bool {
		return databaseRoleAdmissionACLLess(acls[left], acls[right])
	})
}

func databaseRoleAdmissionACLLess(left databaseRoleAdmissionACL, right databaseRoleAdmissionACL) bool {
	if left.Grantee != right.Grantee {
		return left.Grantee < right.Grantee
	}
	if left.Grantor != right.Grantor {
		return left.Grantor < right.Grantor
	}
	if left.Privilege != right.Privilege {
		return left.Privilege < right.Privilege
	}
	if left.Grantable != right.Grantable {
		return !left.Grantable
	}
	return left.Multiplicity < right.Multiplicity
}

const databaseRoleAdmissionSQL = `
WITH role_names(label, name) AS (
	VALUES
		('MIGRATOR'::text, 'aiops_migrator'::text),
		('SCHEMA_OWNER'::text, 'aiops_schema_owner'::text),
		('RUNTIME'::text, 'aiops_control_plane_runtime'::text),
		('WORKLOAD'::text, 'aiops_control_plane_workload'::text)
),
base_roles AS MATERIALIZED (
	SELECT
		names.label,
		names.name,
		role.oid,
		role.rolcanlogin AS login,
		role.rolinherit AS inherit,
		role.rolsuper AS superuser,
		role.rolcreatedb AS create_db,
		role.rolcreaterole AS create_role,
		role.rolreplication AS replication,
		role.rolbypassrls AS bypass_rls
	FROM role_names AS names
	JOIN pg_catalog.pg_roles AS role
	  ON role.rolname = names.name
),
membership_rows AS (
	SELECT
		COALESCE(
			(SELECT role.label FROM base_roles AS role WHERE role.oid = membership.roleid),
			'UNKNOWN:' || membership.roleid::text
		) AS role,
		COALESCE(
			(SELECT member.label FROM base_roles AS member WHERE member.oid = membership.member),
			'UNKNOWN:' || membership.member::text
		) AS member,
		membership.inherit_option AS inherit,
		membership.set_option AS set,
		membership.admin_option AS admin
	FROM pg_catalog.pg_auth_members AS membership
	WHERE EXISTS (
		SELECT 1
		FROM base_roles AS base_role
		WHERE base_role.oid = membership.roleid
		   OR base_role.oid = membership.member
	)
),
capability_specs(member_label, role_label, privilege) AS (
	VALUES
		('MIGRATOR'::text, 'SCHEMA_OWNER'::text, 'SET'::text),
		('MIGRATOR'::text, 'SCHEMA_OWNER'::text, 'USAGE'::text),
		('WORKLOAD'::text, 'RUNTIME'::text, 'SET'::text),
		('WORKLOAD'::text, 'RUNTIME'::text, 'USAGE'::text),
		('WORKLOAD'::text, 'MIGRATOR'::text, 'SET'::text),
		('WORKLOAD'::text, 'SCHEMA_OWNER'::text, 'SET'::text)
),
capability_rows AS (
	SELECT
		spec.member_label AS member,
		spec.role_label AS role,
		spec.privilege,
		CASE
			WHEN member.oid IS NULL OR target.oid IS NULL THEN false
			ELSE pg_catalog.pg_has_role(member.oid, target.oid, spec.privilege)
		END AS allowed
	FROM capability_specs AS spec
	LEFT JOIN base_roles AS member
	  ON member.label = spec.member_label
	LEFT JOIN base_roles AS target
	  ON target.label = spec.role_label
),
current_database_object AS MATERIALIZED (
	SELECT
		database.oid,
		database.datdba AS owner_oid,
		COALESCE(
			database.datacl,
			pg_catalog.acldefault('d', database.datdba)
		) AS acl
	FROM pg_catalog.pg_database AS database
	WHERE database.datname = pg_catalog.current_database()
),
database_acl_rows AS (
	SELECT
		semantic.grantee,
		semantic.grantor,
		entry.privilege_type AS privilege,
		entry.is_grantable AS grantable,
		pg_catalog.count(*)::integer AS multiplicity
	FROM current_database_object AS database
	CROSS JOIN LATERAL pg_catalog.aclexplode(database.acl) AS entry
	CROSS JOIN LATERAL (
		SELECT
			CASE
				WHEN entry.grantee = 0::oid THEN 'PUBLIC'
				WHEN entry.grantee = database.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantee),
					'UNKNOWN:' || entry.grantee::text
				)
			END AS grantee,
			CASE
				WHEN entry.grantor = database.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantor),
					'UNKNOWN:' || entry.grantor::text
				)
			END AS grantor
	) AS semantic
	GROUP BY semantic.grantee, semantic.grantor, entry.privilege_type, entry.is_grantable
),
trusted_namespace AS MATERIALIZED (
	SELECT
		namespace.oid,
		namespace.nspname AS name,
		namespace.nspowner AS owner_oid,
		COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner)) AS acl
	FROM pg_catalog.pg_namespace AS namespace
	WHERE namespace.nspname = $1
),
schema_acl_rows AS (
	SELECT
		semantic.grantee,
		semantic.grantor,
		entry.privilege_type AS privilege,
		entry.is_grantable AS grantable,
		pg_catalog.count(*)::integer AS multiplicity
	FROM trusted_namespace AS namespace
	CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.acl) AS entry
	CROSS JOIN LATERAL (
		SELECT
			CASE
				WHEN entry.grantee = 0::oid THEN 'PUBLIC'
				WHEN entry.grantee = namespace.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantee),
					'UNKNOWN:' || entry.grantee::text
				)
			END AS grantee,
			CASE
				WHEN entry.grantor = namespace.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantor),
					'UNKNOWN:' || entry.grantor::text
				)
			END AS grantor
	) AS semantic
	GROUP BY semantic.grantee, semantic.grantor, entry.privilege_type, entry.is_grantable
),
relation_names(name) AS (
	VALUES
		('tenants'::text),
		('integrations'::text),
		('workspaces'::text),
		('environments'::text),
		('services'::text),
		('service_bindings'::text),
		('audit_records'::text),
		('outbox_events'::text),
		('asset_sources'::text),
		('asset_source_revisions'::text),
		('asset_source_revision_authorities'::text),
		('asset_source_runs'::text),
		('asset_source_limit_buckets'::text),
		('asset_source_limit_permits'::text),
		('asset_observations'::text),
		('assets'::text),
		('asset_type_details'::text),
		('asset_conflicts'::text),
		('asset_relationships'::text),
		('service_asset_bindings'::text)
),
tracked_relations AS MATERIALIZED (
	SELECT
		relation.oid,
		relation.relname AS name,
		relation.relkind::text AS kind,
		relation.relowner AS owner_oid,
		COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner)) AS acl
	FROM pg_catalog.pg_class AS relation
	JOIN trusted_namespace AS namespace
	  ON namespace.oid = relation.relnamespace
	JOIN relation_names AS expected
	  ON expected.name = relation.relname
),
relation_acl_rows AS (
	SELECT
		relation.oid AS relation_oid,
		semantic.grantee,
		semantic.grantor,
		entry.privilege_type AS privilege,
		entry.is_grantable AS grantable,
		pg_catalog.count(*)::integer AS multiplicity
	FROM tracked_relations AS relation
	CROSS JOIN LATERAL pg_catalog.aclexplode(relation.acl) AS entry
	CROSS JOIN LATERAL (
		SELECT
			CASE
				WHEN entry.grantee = 0::oid THEN 'PUBLIC'
				WHEN entry.grantee = relation.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantee),
					'UNKNOWN:' || entry.grantee::text
				)
			END AS grantee,
			CASE
				WHEN entry.grantor = relation.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantor),
					'UNKNOWN:' || entry.grantor::text
				)
			END AS grantor
	) AS semantic
	GROUP BY relation.oid, semantic.grantee, semantic.grantor, entry.privilege_type, entry.is_grantable
),
column_acl_rows AS (
	SELECT
		relation.name AS relation,
		attribute.attname AS column,
		semantic.grantee,
		semantic.grantor,
		entry.privilege_type AS privilege,
		entry.is_grantable AS grantable,
		pg_catalog.count(*)::integer AS multiplicity
	FROM tracked_relations AS relation
	JOIN pg_catalog.pg_attribute AS attribute
	  ON attribute.attrelid = relation.oid
	 AND attribute.attnum > 0
	 AND NOT attribute.attisdropped
	CROSS JOIN LATERAL pg_catalog.aclexplode(
		COALESCE(attribute.attacl, pg_catalog.acldefault('c', relation.owner_oid))
	) AS entry
	CROSS JOIN LATERAL (
		SELECT
			CASE
				WHEN entry.grantee = 0::oid THEN 'PUBLIC'
				WHEN entry.grantee = relation.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantee),
					'UNKNOWN:' || entry.grantee::text
				)
			END AS grantee,
			CASE
				WHEN entry.grantor = relation.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantor),
					'UNKNOWN:' || entry.grantor::text
				)
			END AS grantor
	) AS semantic
	GROUP BY
		relation.name,
		attribute.attname,
		semantic.grantee,
		semantic.grantor,
		entry.privilege_type,
		entry.is_grantable
),
function_names(name) AS (
	VALUES
		('asset_catalog_text_valid'::text),
		('asset_catalog_code_valid'::text),
		('asset_catalog_sha256_valid'::text),
		('asset_catalog_provider_kind_valid'::text),
		('asset_catalog_idempotency_key_valid'::text),
		('asset_catalog_json_object_valid'::text),
		('asset_catalog_labels_valid'::text),
		('asset_catalog_checkpoint_envelope_valid'::text),
		('asset_catalog_field_provenance_valid'::text),
		('asset_catalog_framed_value_v1'::text),
		('asset_catalog_source_run_no_credential_digest'::text),
		('asset_catalog_source_run_delay_intent_digest'::text),
		('asset_catalog_source_run_failure_override_digest'::text),
		('asset_catalog_source_run_terminal_digest'::text),
		('asset_catalog_opaque_reference_valid'::text),
		('asset_catalog_future_source_gate_admitted'::text),
		('asset_catalog_source_revision_binding_digest'::text),
		('asset_catalog_lock_exact_service_binding'::text),
		('validate_asset_management_audit_insert'::text),
		('reject_asset_catalog_immutable'::text),
		('reject_asset_catalog_delete'::text),
		('reject_asset_catalog_truncate'::text),
		('enforce_assets_transition'::text),
		('enforce_asset_conflict_transition'::text),
		('enforce_asset_catalog_edge_mutation'::text),
		('enforce_asset_relationship_mutation'::text),
		('validate_asset_relationship_page_closure'::text),
		('enforce_asset_sources_mutation'::text),
		('validate_asset_source_deferred_state'::text),
		('enforce_asset_source_revision_transition'::text),
		('validate_asset_source_revision_deferred_state'::text),
		('enforce_asset_source_run_mutation'::text),
		('validate_asset_source_run_page_closure'::text),
		('validate_asset_source_run_terminal_closure'::text),
		('enforce_asset_observation_admission'::text),
		('validate_asset_observation_page_closure'::text)
),
tracked_functions AS MATERIALIZED (
	SELECT
		function.oid,
		namespace.name || '.' || function.proname || '(' ||
		COALESCE((
			SELECT pg_catalog.string_agg(
				type_namespace.nspname || '.' || argument_type.typname,
				',' ORDER BY argument.ordinality
			)
			FROM pg_catalog.unnest(function.proargtypes::pg_catalog.oid[]) WITH ORDINALITY
				AS argument(type_oid, ordinality)
			JOIN pg_catalog.pg_type AS argument_type
			  ON argument_type.oid = argument.type_oid
			JOIN pg_catalog.pg_namespace AS type_namespace
			  ON type_namespace.oid = argument_type.typnamespace
		), '') || ')' AS identity,
		function.proowner AS owner_oid,
		COALESCE(function.proacl, pg_catalog.acldefault('f', function.proowner)) AS acl
	FROM pg_catalog.pg_proc AS function
	JOIN trusted_namespace AS namespace
	  ON namespace.oid = function.pronamespace
	JOIN function_names AS expected
	  ON expected.name = function.proname
),
function_acl_rows AS (
	SELECT
		function.oid AS function_oid,
		semantic.grantee,
		semantic.grantor,
		entry.privilege_type AS privilege,
		entry.is_grantable AS grantable,
		pg_catalog.count(*)::integer AS multiplicity
	FROM tracked_functions AS function
	CROSS JOIN LATERAL pg_catalog.aclexplode(function.acl) AS entry
	CROSS JOIN LATERAL (
		SELECT
			CASE
				WHEN entry.grantee = 0::oid THEN 'PUBLIC'
				WHEN entry.grantee = function.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantee),
					'UNKNOWN:' || entry.grantee::text
				)
			END AS grantee,
			CASE
				WHEN entry.grantor = function.owner_oid THEN 'OWNER'
				ELSE COALESCE(
					(SELECT role.label FROM base_roles AS role WHERE role.oid = entry.grantor),
					'UNKNOWN:' || entry.grantor::text
				)
			END AS grantor
	) AS semantic
	GROUP BY function.oid, semantic.grantee, semantic.grantor, entry.privilege_type, entry.is_grantable
)
SELECT pg_catalog.convert_to(
	pg_catalog.jsonb_build_object(
		'session_user', SESSION_USER::text,
		'current_user', CURRENT_USER::text,
		'roles', COALESCE((
			SELECT pg_catalog.jsonb_agg(
				pg_catalog.jsonb_build_object(
					'label', role.label,
					'name', role.name,
					'login', role.login,
					'inherit', role.inherit,
					'superuser', role.superuser,
					'create_db', role.create_db,
					'create_role', role.create_role,
					'replication', role.replication,
					'bypass_rls', role.bypass_rls
				) ORDER BY role.label
			)
			FROM base_roles AS role
		), '[]'::jsonb),
		'memberships', COALESCE((
			SELECT pg_catalog.jsonb_agg(
				pg_catalog.jsonb_build_object(
					'role', membership.role,
					'member', membership.member,
					'inherit', membership.inherit,
					'set', membership.set,
					'admin', membership.admin
				) ORDER BY membership.role, membership.member
			)
			FROM membership_rows AS membership
		), '[]'::jsonb),
		'capabilities', COALESCE((
			SELECT pg_catalog.jsonb_agg(
				pg_catalog.jsonb_build_object(
					'member', capability.member,
					'role', capability.role,
					'privilege', capability.privilege,
					'allowed', capability.allowed
				) ORDER BY capability.member, capability.role, capability.privilege
			)
			FROM capability_rows AS capability
		), '[]'::jsonb),
		'database', (
			SELECT pg_catalog.jsonb_build_object(
				'owner', COALESCE(
					(
						SELECT CASE WHEN role.label = 'SCHEMA_OWNER' THEN 'OWNER' ELSE role.label END
						FROM base_roles AS role
						WHERE role.oid = database.owner_oid
					),
					'UNKNOWN:' || database.owner_oid::text
				),
				'acl', COALESCE((
					SELECT pg_catalog.jsonb_agg(
						pg_catalog.jsonb_build_object(
							'grantee', acl.grantee,
							'grantor', acl.grantor,
							'privilege', acl.privilege,
							'grantable', acl.grantable,
							'multiplicity', acl.multiplicity
						) ORDER BY acl.grantee, acl.grantor, acl.privilege, acl.grantable
					)
					FROM database_acl_rows AS acl
				), '[]'::jsonb)
			)
			FROM current_database_object AS database
		),
		'schema', COALESCE((
			SELECT pg_catalog.jsonb_build_object(
				'name', namespace.name,
				'owner', COALESCE(
					(
						SELECT CASE WHEN role.label = 'SCHEMA_OWNER' THEN 'OWNER' ELSE role.label END
						FROM base_roles AS role
						WHERE role.oid = namespace.owner_oid
					),
					'UNKNOWN:' || namespace.owner_oid::text
				),
				'acl', COALESCE((
					SELECT pg_catalog.jsonb_agg(
						pg_catalog.jsonb_build_object(
							'grantee', acl.grantee,
							'grantor', acl.grantor,
							'privilege', acl.privilege,
							'grantable', acl.grantable,
							'multiplicity', acl.multiplicity
						) ORDER BY acl.grantee, acl.grantor, acl.privilege, acl.grantable
					)
					FROM schema_acl_rows AS acl
				), '[]'::jsonb)
			)
			FROM trusted_namespace AS namespace
		), pg_catalog.jsonb_build_object('name', '', 'owner', '', 'acl', '[]'::jsonb)),
		'relations', COALESCE((
			SELECT pg_catalog.jsonb_agg(
				pg_catalog.jsonb_build_object(
					'name', relation.name,
					'kind', relation.kind,
					'owner', COALESCE(
						(
							SELECT CASE WHEN role.label = 'SCHEMA_OWNER' THEN 'OWNER' ELSE role.label END
							FROM base_roles AS role
							WHERE role.oid = relation.owner_oid
						),
						'UNKNOWN:' || relation.owner_oid::text
					),
					'acl', COALESCE((
						SELECT pg_catalog.jsonb_agg(
							pg_catalog.jsonb_build_object(
								'grantee', acl.grantee,
								'grantor', acl.grantor,
								'privilege', acl.privilege,
								'grantable', acl.grantable,
								'multiplicity', acl.multiplicity
							) ORDER BY acl.grantee, acl.grantor, acl.privilege, acl.grantable
						)
						FROM relation_acl_rows AS acl
						WHERE acl.relation_oid = relation.oid
					), '[]'::jsonb)
				) ORDER BY relation.name
			)
			FROM tracked_relations AS relation
		), '[]'::jsonb),
		'columns', COALESCE((
			SELECT pg_catalog.jsonb_agg(
				pg_catalog.jsonb_build_object(
					'relation', acl.relation,
					'column', acl.column,
					'acl', pg_catalog.jsonb_build_object(
						'grantee', acl.grantee,
						'grantor', acl.grantor,
						'privilege', acl.privilege,
						'grantable', acl.grantable,
						'multiplicity', acl.multiplicity
					)
				) ORDER BY acl.relation, acl.column, acl.grantee, acl.grantor, acl.privilege, acl.grantable
			)
			FROM column_acl_rows AS acl
		), '[]'::jsonb),
		'functions', COALESCE((
			SELECT pg_catalog.jsonb_agg(
				pg_catalog.jsonb_build_object(
					'identity', function.identity,
					'owner', COALESCE(
						(
							SELECT CASE WHEN role.label = 'SCHEMA_OWNER' THEN 'OWNER' ELSE role.label END
							FROM base_roles AS role
							WHERE role.oid = function.owner_oid
						),
						'UNKNOWN:' || function.owner_oid::text
					),
					'acl', COALESCE((
						SELECT pg_catalog.jsonb_agg(
							pg_catalog.jsonb_build_object(
								'grantee', acl.grantee,
								'grantor', acl.grantor,
								'privilege', acl.privilege,
								'grantable', acl.grantable,
								'multiplicity', acl.multiplicity
							) ORDER BY acl.grantee, acl.grantor, acl.privilege, acl.grantable
						)
						FROM function_acl_rows AS acl
						WHERE acl.function_oid = function.oid
					), '[]'::jsonb)
				) ORDER BY function.identity
			)
			FROM tracked_functions AS function
		), '[]'::jsonb)
	)::text,
	'UTF8'
)
`
