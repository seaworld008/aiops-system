package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const recoveryPostgreSQLImage = "postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"

type recoveryDocker struct {
	contextName string
}

type recoveryPostgreSQLContainer struct {
	docker              recoveryDocker
	name                string
	username            string
	password            string
	migrationPassword   string
	applicationPassword string
	databaseName        string
	hostPort            uint16
}

type recoveryPostgreSQLPair struct {
	source        *recoveryPostgreSQLContainer
	target        *recoveryPostgreSQLContainer
	sourceHarness *assetCatalogHarness
	targetHarness *assetCatalogHarness
	sourcePool    *pgxpool.Pool
	targetPool    *pgxpool.Pool
	sourceSystem  string
	targetSystem  string
}

var recoveryBaseRoleNames = []string{
	"aiops_migrator",
	"aiops_schema_owner",
	"aiops_control_plane_runtime",
	"aiops_control_plane_workload",
}

func prepareRecoveryPostgreSQLPair(t *testing.T) *recoveryPostgreSQLPair {
	t.Helper()
	required := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN")) != ""
	docker, err := discoverRecoveryDocker()
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	if err := docker.ensureRecoveryImage(); err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}

	source, err := startRecoveryPostgreSQLContainer(t, docker, "source")
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	target, err := startRecoveryPostgreSQLContainer(t, docker, "target")
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}

	sourceAdmin, sourceSystem, err := connectAndInspectRecoveryPostgreSQL(source)
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	t.Cleanup(sourceAdmin.Close)
	targetAdmin, targetSystem, err := connectAndInspectRecoveryPostgreSQL(target)
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	t.Cleanup(targetAdmin.Close)
	if sourceSystem == targetSystem {
		t.Fatalf("recovery source and target have the same PostgreSQL system_identifier")
	}

	sourceHarness, sourceRoleOIDs := newRecoveryAssetCatalogHarness(t, source, sourceAdmin, false)
	targetHarness, targetRoleOIDs := newRecoveryAssetCatalogHarness(t, target, targetAdmin, true)
	for _, role := range recoveryBaseRoleNames {
		if sourceRoleOIDs[role] == targetRoleOIDs[role] {
			t.Fatalf("recovery role %s reused cluster-local OID %d across source and target",
				role, sourceRoleOIDs[role])
		}
	}
	assertRecoveryTargetClean(t, targetHarness.db)

	return &recoveryPostgreSQLPair{
		source:        source,
		target:        target,
		sourceHarness: sourceHarness,
		targetHarness: targetHarness,
		sourcePool:    sourceHarness.db,
		targetPool:    targetHarness.db,
		sourceSystem:  sourceSystem,
		targetSystem:  targetSystem,
	}
}

func newRecoveryAssetCatalogHarness(
	t *testing.T,
	container *recoveryPostgreSQLContainer,
	admin *pgxpool.Pool,
	shiftRoleOIDs bool,
) (*assetCatalogHarness, map[string]int64) {
	t.Helper()
	if shiftRoleOIDs {
		burnRole := pgx.Identifier{"aiops_recovery_oid_burn_" + randomAssetHex(t, 8)}.Sanitize()
		if _, err := admin.Exec(context.Background(), "CREATE ROLE "+burnRole+" NOLOGIN"); err != nil {
			t.Fatalf("allocate target-only recovery role OID: %v", err)
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+burnRole); err != nil {
			t.Fatalf("release target-only recovery role OID: %v", err)
		}
	}

	bootstrapRecoveryRoleGraph(t, container, admin)
	bootstrapRecoveryDatabaseACL(t, container, admin)

	migration := openRecoveryRolePool(t, container, "aiops_migrator", container.migrationPassword, "")
	owner := openRecoveryRolePool(t, container, "aiops_migrator", container.migrationPassword, "aiops_schema_owner")
	application := openRecoveryRolePool(t, container, "aiops_control_plane_workload", container.applicationPassword, "")
	t.Cleanup(application.Close)
	t.Cleanup(owner.Close)
	t.Cleanup(migration.Close)

	assertRecoveryPoolIdentity(t, migration, "aiops_migrator", "aiops_migrator")
	assertRecoveryPoolIdentity(t, owner, "aiops_migrator", "aiops_schema_owner")
	assertRecoveryPoolIdentity(t, application, "aiops_control_plane_workload", "aiops_control_plane_workload")
	assertRecoveryBootstrapContract(t, admin, container.databaseName)

	return &assetCatalogHarness{
		admin:       admin,
		db:          owner,
		migration:   migration,
		application: application,
		name:        container.databaseName,
	}, recoveryRoleOIDs(t, admin)
}

func bootstrapRecoveryRoleGraph(
	t *testing.T,
	container *recoveryPostgreSQLContainer,
	admin *pgxpool.Pool,
) {
	t.Helper()
	roles := fmt.Sprintf(`
BEGIN;
CREATE ROLE aiops_migrator
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD '%s';
CREATE ROLE aiops_schema_owner
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE aiops_control_plane_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE aiops_control_plane_workload
  LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD '%s';
GRANT aiops_schema_owner TO aiops_migrator
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT aiops_control_plane_runtime TO aiops_control_plane_workload
  WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
COMMIT;
`, container.migrationPassword, container.applicationPassword)
	if _, err := admin.Exec(context.Background(), roles); err != nil {
		t.Fatalf("bootstrap exact recovery database role graph: %v", err)
	}
}

func bootstrapRecoveryDatabaseACL(
	t *testing.T,
	container *recoveryPostgreSQLContainer,
	admin *pgxpool.Pool,
) {
	t.Helper()
	database := pgx.Identifier{container.databaseName}.Sanitize()
	bootstrapAdmin := pgx.Identifier{container.username}.Sanitize()
	if _, err := admin.Exec(context.Background(), "ALTER DATABASE "+database+" OWNER TO aiops_schema_owner"); err != nil {
		t.Fatalf("assign recovery database owner: %v", err)
	}
	tx, err := admin.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin recovery database ACL bootstrap: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `SET LOCAL ROLE aiops_schema_owner`); err != nil {
		t.Fatalf("enter recovery schema-owner bootstrap context: %v", err)
	}
	for _, statement := range []string{
		"REVOKE ALL ON DATABASE " + database + " FROM PUBLIC, aiops_migrator, aiops_schema_owner, aiops_control_plane_runtime, aiops_control_plane_workload, " + bootstrapAdmin,
		"GRANT CONNECT, CREATE, TEMPORARY ON DATABASE " + database + " TO aiops_schema_owner",
		"GRANT CONNECT ON DATABASE " + database + " TO aiops_migrator, aiops_control_plane_workload",
		`ALTER SCHEMA public OWNER TO aiops_schema_owner`,
		"REVOKE ALL ON SCHEMA public FROM PUBLIC, aiops_migrator, aiops_schema_owner, aiops_control_plane_runtime, aiops_control_plane_workload, " + bootstrapAdmin,
		`GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner`,
		`GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime`,
	} {
		if _, err := tx.Exec(context.Background(), statement); err != nil {
			t.Fatalf("bootstrap exact recovery database/schema ACL: %v", err)
		}
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit recovery database/schema ACL bootstrap: %v", err)
	}
}

func openRecoveryRolePool(
	t *testing.T,
	container *recoveryPostgreSQLContainer,
	username string,
	password string,
	setRole string,
) *pgxpool.Pool {
	t.Helper()
	config, err := recoveryPoolConfig(container, username, password)
	if err != nil {
		t.Fatalf("construct isolated PostgreSQL %s connection configuration", username)
	}
	if setRole != "" {
		config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
			var sessionUser, currentUser string
			if err := connection.QueryRow(ctx, `SELECT session_user, current_user`).Scan(&sessionUser, &currentUser); err != nil {
				return errors.New("inspect recovery owner-context identity")
			}
			if sessionUser != username || currentUser != username {
				return errors.New("recovery owner-context login identity drifted")
			}
			if _, err := connection.Exec(ctx, "SET ROLE "+pgx.Identifier{setRole}.Sanitize()); err != nil {
				return errors.New("enter recovery owner-context role")
			}
			if err := connection.QueryRow(ctx, `SELECT session_user, current_user`).Scan(&sessionUser, &currentUser); err != nil {
				return errors.New("verify recovery owner-context identity")
			}
			if sessionUser != username || currentUser != setRole {
				return errors.New("recovery owner-context role switch drifted")
			}
			return nil
		}
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("connect isolated PostgreSQL %s identity: unavailable", username)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Fatalf("ping isolated PostgreSQL %s identity: unavailable", username)
	}
	return pool
}

func recoveryPoolConfig(
	container *recoveryPostgreSQLContainer,
	username string,
	password string,
) (*pgxpool.Config, error) {
	connectionURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(int(container.hostPort))),
		Path:   container.databaseName,
	}
	query := connectionURL.Query()
	query.Set("sslmode", "disable")
	connectionURL.RawQuery = query.Encode()
	config, err := pgxpool.ParseConfig(connectionURL.String())
	if err != nil {
		return nil, err
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	if config.MaxConns < 12 {
		config.MaxConns = 12
	}
	return config, nil
}

func assertRecoveryPoolIdentity(
	t *testing.T,
	pool *pgxpool.Pool,
	wantSession string,
	wantCurrent string,
) {
	t.Helper()
	var sessionUser, currentUser string
	if err := pool.QueryRow(context.Background(), `SELECT session_user, current_user`).Scan(&sessionUser, &currentUser); err != nil {
		t.Fatalf("read recovery PostgreSQL identity: %v", err)
	}
	if sessionUser != wantSession || currentUser != wantCurrent {
		t.Fatalf("recovery PostgreSQL identity=session:%q current:%q, want session:%q current:%q",
			sessionUser, currentUser, wantSession, wantCurrent)
	}
}

func assertRecoveryBootstrapContract(t *testing.T, admin *pgxpool.Pool, databaseName string) {
	t.Helper()
	var rolesExact, membershipsExact, capabilitiesExact bool
	if err := admin.QueryRow(context.Background(), `
SELECT count(*)=4 AND bool_and(
  NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND
  CASE rolname
    WHEN 'aiops_migrator' THEN rolcanlogin AND NOT rolinherit
    WHEN 'aiops_schema_owner' THEN NOT rolcanlogin AND NOT rolinherit
    WHEN 'aiops_control_plane_runtime' THEN NOT rolcanlogin AND NOT rolinherit
    WHEN 'aiops_control_plane_workload' THEN rolcanlogin AND rolinherit
    ELSE false
  END
)
FROM pg_catalog.pg_roles
WHERE rolname = ANY($1::text[])
`, recoveryBaseRoleNames).Scan(&rolesExact); err != nil {
		t.Fatalf("verify recovery role flags: %v", err)
	}
	if err := admin.QueryRow(context.Background(), `
WITH base_roles AS (
  SELECT oid, rolname FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])
), memberships AS (
  SELECT role_record.rolname AS role_name, member_record.rolname AS member_name,
         membership.admin_option, membership.inherit_option, membership.set_option
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS role_record ON role_record.oid=membership.roleid
  JOIN pg_catalog.pg_roles AS member_record ON member_record.oid=membership.member
  WHERE membership.roleid IN (SELECT oid FROM base_roles)
     OR membership.member IN (SELECT oid FROM base_roles)
)
SELECT count(*)=2 AND bool_and(
  (role_name='aiops_schema_owner' AND member_name='aiops_migrator' AND
   NOT admin_option AND NOT inherit_option AND set_option)
  OR
  (role_name='aiops_control_plane_runtime' AND member_name='aiops_control_plane_workload' AND
   NOT admin_option AND inherit_option AND NOT set_option)
)
FROM memberships
`, recoveryBaseRoleNames).Scan(&membershipsExact); err != nil {
		t.Fatalf("verify recovery role memberships: %v", err)
	}
	if err := admin.QueryRow(context.Background(), `
SELECT pg_catalog.pg_has_role('aiops_migrator','aiops_schema_owner','SET')
   AND NOT pg_catalog.pg_has_role('aiops_migrator','aiops_schema_owner','USAGE')
   AND pg_catalog.pg_has_role('aiops_control_plane_workload','aiops_control_plane_runtime','USAGE')
   AND NOT pg_catalog.pg_has_role('aiops_control_plane_workload','aiops_control_plane_runtime','SET')
   AND NOT pg_catalog.pg_has_role('aiops_control_plane_workload','aiops_migrator','SET')
   AND NOT pg_catalog.pg_has_role('aiops_control_plane_workload','aiops_schema_owner','SET')
`).Scan(&capabilitiesExact); err != nil {
		t.Fatalf("verify recovery role capabilities: %v", err)
	}
	if !rolesExact || !membershipsExact || !capabilitiesExact {
		t.Fatalf("recovery role bootstrap exact=(roles:%v memberships:%v capabilities:%v)",
			rolesExact, membershipsExact, capabilitiesExact)
	}

	assertRecoveryObjectACL(t, admin, databaseName, "database", []string{
		"aiops_control_plane_workload|aiops_schema_owner|CONNECT|false",
		"aiops_migrator|aiops_schema_owner|CONNECT|false",
		"aiops_schema_owner|aiops_schema_owner|CONNECT|false",
		"aiops_schema_owner|aiops_schema_owner|CREATE|false",
		"aiops_schema_owner|aiops_schema_owner|TEMPORARY|false",
	})
	assertRecoveryObjectACL(t, admin, "public", "schema", []string{
		"aiops_control_plane_runtime|aiops_schema_owner|USAGE|false",
		"aiops_schema_owner|aiops_schema_owner|CREATE|false",
		"aiops_schema_owner|aiops_schema_owner|USAGE|false",
	})
}

func assertRecoveryObjectACL(
	t *testing.T,
	admin *pgxpool.Pool,
	objectName string,
	objectKind string,
	want []string,
) {
	t.Helper()
	var owner string
	var actual []string
	var err error
	switch objectKind {
	case "database":
		err = admin.QueryRow(context.Background(), `
SELECT owner.rolname,
       COALESCE(array_agg(
         COALESCE(grantee.rolname,'PUBLIC') || '|' || grantor.rolname || '|' ||
         expanded.privilege_type || '|' || expanded.is_grantable::text
         ORDER BY COALESCE(grantee.rolname,'PUBLIC') COLLATE "C",
                  grantor.rolname COLLATE "C", expanded.privilege_type COLLATE "C",
                  expanded.is_grantable
       ), ARRAY[]::text[])
FROM pg_catalog.pg_database AS database_record
JOIN pg_catalog.pg_roles AS owner ON owner.oid=database_record.datdba
LEFT JOIN LATERAL pg_catalog.aclexplode(
  COALESCE(database_record.datacl,pg_catalog.acldefault('d',database_record.datdba))
) AS expanded ON true
LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=expanded.grantee
LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=expanded.grantor
WHERE database_record.datname=$1
GROUP BY owner.rolname
`, objectName).Scan(&owner, &actual)
	case "schema":
		err = admin.QueryRow(context.Background(), `
SELECT owner.rolname,
       COALESCE(array_agg(
         COALESCE(grantee.rolname,'PUBLIC') || '|' || grantor.rolname || '|' ||
         expanded.privilege_type || '|' || expanded.is_grantable::text
         ORDER BY COALESCE(grantee.rolname,'PUBLIC') COLLATE "C",
                  grantor.rolname COLLATE "C", expanded.privilege_type COLLATE "C",
                  expanded.is_grantable
       ), ARRAY[]::text[])
FROM pg_catalog.pg_namespace AS namespace_record
JOIN pg_catalog.pg_roles AS owner ON owner.oid=namespace_record.nspowner
LEFT JOIN LATERAL pg_catalog.aclexplode(
  COALESCE(namespace_record.nspacl,pg_catalog.acldefault('n',namespace_record.nspowner))
) AS expanded ON true
LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=expanded.grantee
LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=expanded.grantor
WHERE namespace_record.nspname=$1
GROUP BY owner.rolname
`, objectName).Scan(&owner, &actual)
	default:
		t.Fatalf("unknown recovery ACL object kind %q", objectKind)
	}
	if err != nil {
		t.Fatalf("verify recovery %s ACL: %v", objectKind, err)
	}
	if owner != "aiops_schema_owner" || strings.Join(actual, "\n") != strings.Join(want, "\n") {
		t.Fatalf("recovery %s owner/ACL=(%q,%v), want (%q,%v)",
			objectKind, owner, actual, "aiops_schema_owner", want)
	}
}

func recoveryRoleOIDs(t *testing.T, admin *pgxpool.Pool) map[string]int64 {
	t.Helper()
	rows, err := admin.Query(context.Background(), `
SELECT rolname, oid::bigint
FROM pg_catalog.pg_roles
WHERE rolname = ANY($1::text[])
ORDER BY rolname COLLATE "C"
`, recoveryBaseRoleNames)
	if err != nil {
		t.Fatalf("read recovery role OIDs: %v", err)
	}
	defer rows.Close()
	result := make(map[string]int64, len(recoveryBaseRoleNames))
	for rows.Next() {
		var role string
		var oid int64
		if err := rows.Scan(&role, &oid); err != nil {
			t.Fatalf("scan recovery role OID: %v", err)
		}
		result[role] = oid
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate recovery role OIDs: %v", err)
	}
	if len(result) != len(recoveryBaseRoleNames) {
		t.Fatalf("recovery role OID set has %d roles, want %d", len(result), len(recoveryBaseRoleNames))
	}
	return result
}

func assertRecoveryTargetClean(t *testing.T, owner *pgxpool.Pool) {
	t.Helper()
	var relations, functions int
	if err := owner.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM pg_catalog.pg_class AS relation
   JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
   WHERE namespace.nspname='public' AND relation.relkind IN ('r','p','v','m','S','f')),
  (SELECT count(*) FROM pg_catalog.pg_proc AS function_record
   JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=function_record.pronamespace
   WHERE namespace.nspname='public')
`).Scan(&relations, &functions); err != nil {
		t.Fatalf("verify clean recovery target: %v", err)
	}
	if relations != 0 || functions != 0 {
		t.Fatalf("recovery target is not clean: relations=%d functions=%d", relations, functions)
	}
}

func rejectRecoveryPrerequisite(t *testing.T, required bool, err error) {
	t.Helper()
	if required {
		t.Fatalf("PostgreSQL recovery prerequisite failed while AIOPS_TEST_POSTGRES_DSN is configured: %v", err)
	}
	t.Skipf("PostgreSQL recovery prerequisite is unavailable: %v", err)
}

func discoverRecoveryDocker() (recoveryDocker, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return recoveryDocker{}, errors.New("docker CLI was not found")
	}
	if name := strings.TrimSpace(os.Getenv("AIOPS_TEST_DOCKER_CONTEXT")); name != "" {
		return usableRecoveryDockerContext(name, "AIOPS_TEST_DOCKER_CONTEXT")
	}
	if name := strings.TrimSpace(os.Getenv("DOCKER_CONTEXT")); name != "" {
		return usableRecoveryDockerContext(name, "DOCKER_CONTEXT")
	}
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		if err := requireLocalUnixDockerEndpoint(host); err != nil {
			return recoveryDocker{}, fmt.Errorf("DOCKER_HOST is not an allowed local Unix endpoint: %w", err)
		}
		docker := recoveryDocker{}
		if err := docker.probe(); err != nil {
			return recoveryDocker{}, fmt.Errorf("DOCKER_HOST local daemon is unreachable: %w", err)
		}
		return docker, nil
	}

	current, currentErr := currentRecoveryDockerContext()
	if currentErr == nil {
		return current, nil
	}
	if errors.Is(currentErr, errRemoteDockerEndpoint) {
		return recoveryDocker{}, currentErr
	}

	contexts, err := localReachableRecoveryDockerContexts()
	if err != nil {
		return recoveryDocker{}, err
	}
	switch len(contexts) {
	case 0:
		return recoveryDocker{}, fmt.Errorf("no reachable local Unix Docker context; current context: %w", currentErr)
	case 1:
		return contexts[0], nil
	default:
		names := make([]string, 0, len(contexts))
		for _, candidate := range contexts {
			names = append(names, candidate.contextName)
		}
		sort.Strings(names)
		return recoveryDocker{}, fmt.Errorf("ambiguous reachable local Unix Docker contexts: %s", strings.Join(names, ", "))
	}
}

var errRemoteDockerEndpoint = errors.New("remote Docker endpoint is forbidden for recovery tests")

func TestRecoveryDockerEndpointPolicy(t *testing.T) {
	for _, endpoint := range []string{"unix:///var/run/docker.sock", "unix:/var/run/docker.sock"} {
		if err := requireLocalUnixDockerEndpoint(endpoint); err != nil {
			t.Errorf("local endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"tcp://127.0.0.1:2375",
		"ssh://operator@example.invalid",
		"npipe:////./pipe/docker_engine",
		"unix://relative/docker.sock",
		"/var/run/docker.sock",
	} {
		if err := requireLocalUnixDockerEndpoint(endpoint); !errors.Is(err, errRemoteDockerEndpoint) {
			t.Errorf("non-local-Unix endpoint %q error=%v, want remote-endpoint rejection", endpoint, err)
		}
	}
}

func TestRecoveryDockerContextOverridesRoutingEnvironment(t *testing.T) {
	filtered := withoutDockerRoutingEnvironment([]string{
		"PATH=/usr/bin",
		"DOCKER_CONTEXT=remote",
		"DOCKER_HOST=tcp://example.invalid:2375",
		"DOCKER_TLS_VERIFY=1",
		"DOCKER_CERT_PATH=/tmp/certs",
		"DOCKER_CONFIG=/tmp/docker-config",
	})
	joined := strings.Join(filtered, "\n")
	if joined != "PATH=/usr/bin\nDOCKER_CONFIG=/tmp/docker-config" {
		t.Fatalf("filtered Docker environment=%q", joined)
	}
}

func usableRecoveryDockerContext(name, source string) (recoveryDocker, error) {
	endpoint, err := inspectRecoveryDockerContextEndpoint(name)
	if err != nil {
		return recoveryDocker{}, fmt.Errorf("inspect Docker context selected by %s: %w", source, err)
	}
	if err := requireLocalUnixDockerEndpoint(endpoint); err != nil {
		return recoveryDocker{}, fmt.Errorf("Docker context %q selected by %s is not allowed: %w", name, source, err)
	}
	docker := recoveryDocker{contextName: name}
	if err := docker.probe(); err != nil {
		return recoveryDocker{}, fmt.Errorf("Docker context %q selected by %s is unreachable: %w", name, source, err)
	}
	return docker, nil
}

func currentRecoveryDockerContext() (recoveryDocker, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "context", "show").CombinedOutput()
	if err != nil {
		return recoveryDocker{}, fmt.Errorf("read current Docker context: %w: %s", err, sanitizeToolOutput(output))
	}
	name := strings.TrimSpace(string(output))
	if name == "" {
		return recoveryDocker{}, errors.New("current Docker context name is empty")
	}
	endpoint, err := inspectRecoveryDockerContextEndpoint(name)
	if err != nil {
		return recoveryDocker{}, fmt.Errorf("inspect current Docker context %q: %w", name, err)
	}
	if err := requireLocalUnixDockerEndpoint(endpoint); err != nil {
		return recoveryDocker{}, fmt.Errorf("current Docker context %q is forbidden: %w", name, err)
	}
	docker := recoveryDocker{contextName: name}
	if err := docker.probe(); err != nil {
		return recoveryDocker{}, fmt.Errorf("current Docker context %q is unreachable: %w", name, err)
	}
	return docker, nil
}

func localReachableRecoveryDockerContexts() ([]recoveryDocker, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "context", "ls", "--format", "{{.Name}}").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list Docker contexts: %w: %s", err, sanitizeToolOutput(output))
	}
	seen := make(map[string]struct{})
	var candidates []recoveryDocker
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.TrimSpace(strings.TrimSuffix(line, "*"))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		endpoint, inspectErr := inspectRecoveryDockerContextEndpoint(name)
		if inspectErr != nil || requireLocalUnixDockerEndpoint(endpoint) != nil {
			continue
		}
		docker := recoveryDocker{contextName: name}
		if docker.probe() == nil {
			candidates = append(candidates, docker)
		}
	}
	return candidates, nil
}

func inspectRecoveryDockerContextEndpoint(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "context", "inspect", name, "--format", "{{(index .Endpoints \"docker\").Host}}")
	command.Env = withoutDockerRoutingEnvironment(os.Environ())
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker context inspect failed: %w: %s", err, sanitizeToolOutput(output))
	}
	endpoint := strings.TrimSpace(string(output))
	if endpoint == "" {
		return "", errors.New("Docker context endpoint is empty")
	}
	return endpoint, nil
}

func requireLocalUnixDockerEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return errRemoteDockerEndpoint
	}
	if parsed.Scheme != "unix" || parsed.Host != "" || !filepath.IsAbs(parsed.Path) {
		return errRemoteDockerEndpoint
	}
	return nil
}

func (docker recoveryDocker) command(ctx context.Context, args ...string) *exec.Cmd {
	commandArgs := make([]string, 0, len(args)+2)
	if docker.contextName != "" {
		commandArgs = append(commandArgs, "--context", docker.contextName)
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, "docker", commandArgs...)
	if docker.contextName != "" {
		command.Env = withoutDockerRoutingEnvironment(os.Environ())
	}
	return command
}

func withoutDockerRoutingEnvironment(environment []string) []string {
	filtered := make([]string, 0, len(environment))
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		switch name {
		case "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
			continue
		default:
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func (docker recoveryDocker) probe() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := docker.command(ctx, "version", "--format", "{{.Server.Version}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker daemon probe failed: %w: %s", err, sanitizeToolOutput(output))
	}
	if strings.TrimSpace(string(output)) == "" {
		return errors.New("docker daemon returned an empty server version")
	}
	return nil
}

func (docker recoveryDocker) ensureRecoveryImage() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	output, err := docker.command(ctx, "image", "inspect", recoveryPostgreSQLImage, "--format", "{{.Id}}").CombinedOutput()
	cancel()
	if err == nil && strings.TrimSpace(string(output)) != "" {
		return nil
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output, err = docker.command(ctx, "pull", recoveryPostgreSQLImage).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pull digest-pinned PostgreSQL recovery image: %w: %s", err, sanitizeToolOutput(output))
	}
	return nil
}

func startRecoveryPostgreSQLContainer(
	t *testing.T,
	docker recoveryDocker,
	role string,
) (*recoveryPostgreSQLContainer, error) {
	t.Helper()
	suffix := randomAssetHex(t, 8)
	container := &recoveryPostgreSQLContainer{
		docker:              docker,
		name:                "aiops-assets-recovery-" + role + "-" + suffix,
		username:            "aiops_" + randomAssetHex(t, 6),
		password:            randomAssetHex(t, 24),
		migrationPassword:   randomAssetHex(t, 24),
		applicationPassword: randomAssetHex(t, 24),
		databaseName:        "assets_" + randomAssetHex(t, 6),
	}
	envFile := filepath.Join(t.TempDir(), role+".env")
	envContent := strings.Join([]string{
		"POSTGRES_USER=" + container.username,
		"POSTGRES_PASSWORD=" + container.password,
		"POSTGRES_DB=" + container.databaseName,
		"POSTGRES_INITDB_ARGS=--data-checksums",
		"",
	}, "\n")
	if err := os.WriteFile(envFile, []byte(envContent), 0o600); err != nil {
		return nil, fmt.Errorf("create private PostgreSQL environment file: %w", err)
	}
	// Register cleanup before docker run so a daemon-side create followed by a
	// client timeout cannot leave an untracked test container behind.
	t.Cleanup(func() { container.remove(t) })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	output, err := docker.command(ctx,
		"run", "--detach", "--rm",
		"--name", container.name,
		"--label", "aiops.test=asset-catalog-recovery",
		"--env-file", envFile,
		"--publish", "127.0.0.1::5432",
		recoveryPostgreSQLImage,
	).CombinedOutput()
	cancel()
	if err != nil {
		return nil, fmt.Errorf("start isolated PostgreSQL %s container: %w: %s", role, err, sanitizeToolOutput(output))
	}

	if err := container.assertPinnedImage(); err != nil {
		return container, err
	}
	port, err := container.publishedPort()
	if err != nil {
		return container, err
	}
	container.hostPort = port
	if err := container.waitUntilReady(); err != nil {
		return container, err
	}
	if err := container.assertToolVersions(); err != nil {
		return container, err
	}
	return container, nil
}

func (container *recoveryPostgreSQLContainer) assertPinnedImage() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := container.docker.command(ctx, "inspect", container.name, "--format", "{{.Config.Image}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect isolated PostgreSQL container image: %w: %s", err, sanitizeToolOutput(output))
	}
	if strings.TrimSpace(string(output)) != recoveryPostgreSQLImage {
		return errors.New("isolated PostgreSQL container is not using the required digest-pinned image")
	}
	return nil
}

func (container *recoveryPostgreSQLContainer) publishedPort() (uint16, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := container.docker.command(ctx, "port", container.name, "5432/tcp").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("read isolated PostgreSQL published port: %w: %s", err, sanitizeToolOutput(output))
	}
	line := strings.TrimSpace(strings.Split(string(output), "\n")[0])
	host, portText, err := net.SplitHostPort(line)
	if err != nil || host != "127.0.0.1" {
		return 0, fmt.Errorf("isolated PostgreSQL port is not bound to 127.0.0.1")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, errors.New("isolated PostgreSQL published port is invalid")
	}
	return uint16(port), nil
}

func (container *recoveryPostgreSQLContainer) waitUntilReady() error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := container.docker.command(ctx,
			"exec", container.name, "pg_isready", "--quiet",
			"--username", container.username, "--dbname", container.databaseName,
		).Run()
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("isolated PostgreSQL container did not become ready within 60 seconds")
}

func (container *recoveryPostgreSQLContainer) assertToolVersions() error {
	for _, tool := range []string{"pg_dump", "pg_restore"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		output, err := container.docker.command(ctx, "exec", container.name, tool, "--version").CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("run recovery %s version probe: %w: %s", tool, err, sanitizeToolOutput(output))
		}
		if !strings.Contains(string(output), "PostgreSQL) 18.4") {
			return fmt.Errorf("recovery %s is not PostgreSQL 18.4", tool)
		}
	}
	return nil
}

func (container *recoveryPostgreSQLContainer) remove(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := container.docker.command(ctx, "rm", "--force", container.name).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(output)), "no such container") {
		t.Errorf("remove isolated PostgreSQL recovery container: %v: %s", err, sanitizeToolOutput(output))
	}
}

func connectAndInspectRecoveryPostgreSQL(
	container *recoveryPostgreSQLContainer,
) (*pgxpool.Pool, string, error) {
	connectionURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(container.username, container.password),
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(int(container.hostPort))),
		Path:   container.databaseName,
	}
	query := connectionURL.Query()
	query.Set("sslmode", "disable")
	connectionURL.RawQuery = query.Encode()
	config, err := pgxpool.ParseConfig(connectionURL.String())
	if err != nil {
		return nil, "", errors.New("construct isolated PostgreSQL connection configuration")
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "public"
	if config.MaxConns < 12 {
		config.MaxConns = 12
	}
	deadline := time.Now().Add(15 * time.Second)
	var pool *pgxpool.Pool
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		pool, err = pgxpool.NewWithConfig(ctx, config)
		if err == nil {
			err = pool.Ping(ctx)
		}
		cancel()
		if err == nil {
			break
		}
		if pool != nil {
			pool.Close()
			pool = nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	if pool == nil {
		return nil, "", errors.New("connect to isolated PostgreSQL container through its loopback port")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var serverVersion int
	var dataChecksums, systemIdentifier string
	err = pool.QueryRow(ctx, `
		SELECT current_setting('server_version_num')::integer,
		       current_setting('data_checksums'),
		       (SELECT system_identifier::text FROM pg_control_system())
	`).Scan(&serverVersion, &dataChecksums, &systemIdentifier)
	if err != nil {
		pool.Close()
		return nil, "", errors.New("inspect isolated PostgreSQL server controls")
	}
	if serverVersion != 180004 {
		pool.Close()
		return nil, "", fmt.Errorf("isolated recovery server version=%d, want 180004", serverVersion)
	}
	if dataChecksums != "on" {
		pool.Close()
		return nil, "", errors.New("isolated recovery server data checksums are disabled")
	}
	if systemIdentifier == "" {
		pool.Close()
		return nil, "", errors.New("isolated recovery server system_identifier is empty")
	}
	return pool, systemIdentifier, nil
}

func logicalDumpDatabase(t *testing.T, container *recoveryPostgreSQLContainer) []byte {
	t.Helper()
	envFile := recoveryToolPasswordFile(t, "source-dump", container.migrationPassword)
	assertRecoveryToolIdentity(t, container, envFile)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := container.docker.command(ctx,
		"exec", "--env-file", envFile, container.name,
		"pg_dump", "--format=custom", "--role=aiops_schema_owner",
		"--host=127.0.0.1", "--port=5432", "--username=aiops_migrator",
		"--dbname="+container.databaseName, "--no-password",
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	backup, err := command.Output()
	if err != nil {
		t.Fatalf("pg_dump recovery source database inside its container: %v: %s", err, container.sanitizeToolOutput(stderr.Bytes()))
	}
	assertRecoveryArchiveOwners(t, container, backup)
	return backup
}

func restoreLogicalDump(t *testing.T, container *recoveryPostgreSQLContainer, backup []byte) {
	t.Helper()
	envFile := recoveryToolPasswordFile(t, "target-restore", container.migrationPassword)
	assertRecoveryToolIdentity(t, container, envFile)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := container.docker.command(ctx,
		"exec", "--interactive", "--env-file", envFile, container.name,
		"pg_restore", "--exit-on-error", "--single-transaction", "--role=aiops_schema_owner",
		"--host=127.0.0.1", "--port=5432", "--username=aiops_migrator",
		"--dbname="+container.databaseName, "--no-password",
	)
	command.Stdin = bytes.NewReader(backup)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("pg_restore recovery target database inside its container: %v: %s", err, container.sanitizeToolOutput(stderr.Bytes()))
	}
}

func recoveryToolPasswordFile(t *testing.T, purpose string, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), purpose+".env")
	if err := os.WriteFile(path, []byte("PGPASSWORD="+password+"\n"), 0o600); err != nil {
		t.Fatalf("create private PostgreSQL recovery tool environment: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("inspect private PostgreSQL recovery tool environment: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("PostgreSQL recovery tool environment mode=%#o, want 0600", info.Mode().Perm())
	}
	return path
}

func assertRecoveryToolIdentity(
	t *testing.T,
	container *recoveryPostgreSQLContainer,
	envFile string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := container.docker.command(ctx,
		"exec", "--env-file", envFile, container.name,
		"psql", "--host=127.0.0.1", "--port=5432", "--username=aiops_migrator",
		"--dbname="+container.databaseName, "--no-password", "--no-psqlrc",
		"--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1",
		"--command=SELECT session_user || '|' || current_user",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("verify PostgreSQL recovery tool login identity: %v: %s",
			err, container.sanitizeToolOutput(output))
	}
	if strings.TrimSpace(string(output)) != "aiops_migrator|aiops_migrator" {
		t.Fatal("PostgreSQL recovery tool login identity is not raw aiops_migrator")
	}
}

func assertRecoveryCatalogOwners(t *testing.T, database *pgxpool.Pool) {
	t.Helper()
	var schemaOwner string
	var unexpectedRelations, unexpectedFunctions int64
	if err := database.QueryRow(context.Background(), `
SELECT
  (SELECT owner.rolname
   FROM pg_catalog.pg_namespace AS namespace_record
   JOIN pg_catalog.pg_roles AS owner ON owner.oid=namespace_record.nspowner
   WHERE namespace_record.nspname='public'),
  (SELECT count(*)
   FROM pg_catalog.pg_class AS relation
   JOIN pg_catalog.pg_namespace AS namespace_record ON namespace_record.oid=relation.relnamespace
   JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner
   WHERE namespace_record.nspname='public'
     AND relation.relkind IN ('r','p','v','m','S','f')
     AND owner.rolname<>'aiops_schema_owner'),
  (SELECT count(*)
   FROM pg_catalog.pg_proc AS function_record
   JOIN pg_catalog.pg_namespace AS namespace_record ON namespace_record.oid=function_record.pronamespace
   JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_record.proowner
   WHERE namespace_record.nspname='public'
     AND owner.rolname<>'aiops_schema_owner')
`).Scan(&schemaOwner, &unexpectedRelations, &unexpectedFunctions); err != nil {
		t.Fatalf("verify recovery source catalog owners: %v", err)
	}
	if schemaOwner != "aiops_schema_owner" || unexpectedRelations != 0 || unexpectedFunctions != 0 {
		t.Fatalf("recovery source owner drift=(schema:%q relations:%d functions:%d)",
			schemaOwner, unexpectedRelations, unexpectedFunctions)
	}
}

func assertRecoveryArchiveOwners(
	t *testing.T,
	container *recoveryPostgreSQLContainer,
	backup []byte,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := container.docker.command(ctx,
		"exec", "--interactive", container.name,
		"pg_restore", "--list",
	)
	command.Stdin = bytes.NewReader(backup)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	listing, err := command.Output()
	if err != nil {
		t.Fatalf("list PostgreSQL recovery archive: %v: %s", err, container.sanitizeToolOutput(stderr.Bytes()))
	}
	owners := make(map[string]struct{})
	entries := 0
	for _, rawLine := range strings.Split(string(listing), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, ";", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			t.Fatalf("malformed PostgreSQL recovery archive list entry")
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 5 {
			t.Fatalf("incomplete PostgreSQL recovery archive list entry")
		}
		entries++
		owner := fields[len(fields)-1]
		if owner != "-" {
			owners[owner] = struct{}{}
		}
	}
	if entries == 0 {
		t.Fatal("PostgreSQL recovery archive list is empty")
	}
	if len(owners) != 1 {
		t.Fatalf("PostgreSQL recovery archive owner set=%v, want [aiops_schema_owner]", sortedRecoverySet(owners))
	}
	if _, ok := owners["aiops_schema_owner"]; !ok {
		t.Fatalf("PostgreSQL recovery archive owner set=%v, want [aiops_schema_owner]", sortedRecoverySet(owners))
	}
}

func sortedRecoverySet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (container *recoveryPostgreSQLContainer) sanitizeToolOutput(output []byte) string {
	return strings.NewReplacer(
		container.username, "<redacted-user>",
		container.password, "<redacted-password>",
		container.migrationPassword, "<redacted-migration-password>",
		container.applicationPassword, "<redacted-application-password>",
		container.databaseName, "<redacted-database>",
	).Replace(sanitizeToolOutput(output))
}

func sanitizeToolOutput(output []byte) string {
	value := strings.TrimSpace(string(output))
	if value == "" {
		return "<no diagnostic output>"
	}
	if len(value) > 1024 {
		return value[:1024] + "..."
	}
	return value
}
