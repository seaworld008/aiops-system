package postgres_test

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	runnerpostgres "github.com/seaworld008/aiops-system/internal/runneridentity/postgres"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const lockOrderRunnerID = "registered-read-runner-lock-order"

func TestAuthenticateTxDoesNotDeadlockWithConcurrentScopeDelete(t *testing.T) {
	harness := newLockOrderPostgresHarness(t)
	harness.applyThroughInvestigationRuntime(t)
	database := harness.database
	identityFixture := newLiveReadIdentityFixture(t)
	initialRevision := seedLockOrderRunner(t, database, identityFixture)

	var advisoryKey int64
	if err := database.QueryRow(context.Background(), `SELECT hashtextextended($1, 0)`, harness.schema).
		Scan(&advisoryKey); err != nil {
		t.Fatalf("derive lock-order advisory key: %v", err)
	}
	installScopeDeletePauseTrigger(t, database, advisoryKey)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	controller, err := database.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire advisory-lock controller: %v", err)
	}
	defer controller.Release()
	if _, err := controller.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryKey); err != nil {
		t.Fatalf("hold lock-order advisory lock: %v", err)
	}
	advisoryHeld := true
	defer func() {
		if advisoryHeld {
			_, _ = controller.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, advisoryKey)
		}
	}()

	mutationConnection, err := database.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire scope mutation connection: %v", err)
	}
	defer mutationConnection.Release()
	mutationPID := lockOrderBackendPID(t, ctx, mutationConnection)
	mutationTx, err := mutationConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin scope mutation transaction: %v", err)
	}
	if _, err := mutationTx.Exec(ctx, `SET LOCAL lock_timeout = '2s'; SET LOCAL statement_timeout = '4s'`); err != nil {
		t.Fatalf("bound scope mutation locks: %v", err)
	}
	mutationDone := make(chan error, 1)
	go func() {
		_, deleteErr := mutationTx.Exec(ctx, `
			DELETE FROM runner_scope_bindings
			WHERE tenant_id = $1::uuid AND runner_id = $2
			  AND workspace_id = $3::uuid AND environment_id = $4::uuid
		`, testTenantID, lockOrderRunnerID, testWorkspaceID, testEnvironmentID)
		if deleteErr != nil {
			_ = mutationTx.Rollback(context.Background())
			mutationDone <- deleteErr
			return
		}
		mutationDone <- mutationTx.Commit(ctx)
	}()
	if err := waitForBackendLock(ctx, database, mutationPID, true); err != nil {
		t.Fatalf("scope DELETE did not pause after taking its binding lock: %v", err)
	}

	authenticationConnection, err := database.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire authentication connection: %v", err)
	}
	defer authenticationConnection.Release()
	authenticationPID := lockOrderBackendPID(t, ctx, authenticationConnection)
	authenticationTx, err := authenticationConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin authentication transaction: %v", err)
	}
	if _, err := authenticationTx.Exec(ctx, `SET LOCAL lock_timeout = '2s'; SET LOCAL statement_timeout = '4s'`); err != nil {
		t.Fatalf("bound authentication locks: %v", err)
	}
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("create Runner identity repository: %v", err)
	}
	type authenticationOutcome struct {
		runner runnerpostgres.AuthenticatedRunner
		err    error
	}
	authenticationDone := make(chan authenticationOutcome, 1)
	go func() {
		authenticated, authenticateErr := repository.AuthenticateTx(ctx, authenticationTx, identityFixture.identity)
		if authenticateErr != nil {
			_ = authenticationTx.Rollback(context.Background())
			authenticationDone <- authenticationOutcome{err: authenticateErr}
			return
		}
		commitErr := authenticationTx.Commit(ctx)
		authenticationDone <- authenticationOutcome{runner: authenticated, err: commitErr}
	}()
	if err := waitForBackendLock(ctx, database, authenticationPID, false); err != nil {
		t.Fatalf("AuthenticateTx did not wait for the in-flight binding DELETE: %v", err)
	}

	var unlocked bool
	if err := controller.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, advisoryKey).Scan(&unlocked); err != nil || !unlocked {
		t.Fatalf("release lock-order advisory lock: unlocked=%v error=%v", unlocked, err)
	}
	advisoryHeld = false

	mutationErr, receiveErr := receiveLockOrderResult(ctx, mutationDone)
	if receiveErr != nil {
		t.Fatalf("scope mutation did not finish before its deadline: %v", receiveErr)
	}
	authenticationResult, receiveErr := receiveLockOrderResult(ctx, authenticationDone)
	if receiveErr != nil {
		t.Fatalf("AuthenticateTx did not finish before its deadline: %v", receiveErr)
	}
	if postgresDeadlock(mutationErr) || postgresDeadlock(authenticationResult.err) {
		t.Fatalf("binding-first scope mutation deadlocked with AuthenticateTx: mutation=%v authentication=%v",
			mutationErr, authenticationResult.err)
	}
	if mutationErr != nil {
		t.Fatalf("scope binding DELETE failed: %v", mutationErr)
	}
	if authenticationResult.err != nil {
		if !errors.Is(authenticationResult.err, runneridentity.ErrAuthenticationFailed) {
			t.Fatalf("AuthenticateTx returned an unexpected concurrent result: %v", authenticationResult.err)
		}
	} else {
		bindings := authenticationResult.runner.Bindings()
		if !authenticationResult.runner.Valid() || authenticationResult.runner.ScopeRevision() != initialRevision ||
			len(bindings) != 1 || bindings[0].WorkspaceID != testWorkspaceID ||
			bindings[0].EnvironmentID != testEnvironmentID {
			t.Fatalf("AuthenticateTx returned a mixed scope snapshot: revision=%d bindings=%#v",
				authenticationResult.runner.ScopeRevision(), bindings)
		}
	}

	var finalRevision int64
	var finalBindingCount int
	if err := database.QueryRow(context.Background(), `
		SELECT registration.scope_revision,
		       (SELECT count(*) FROM runner_scope_bindings AS binding
		         WHERE binding.tenant_id = registration.tenant_id
		           AND binding.runner_id = registration.runner_id)
		FROM runner_registrations AS registration
		WHERE registration.tenant_id = $1::uuid AND registration.runner_id = $2
	`, testTenantID, lockOrderRunnerID).Scan(&finalRevision, &finalBindingCount); err != nil {
		t.Fatalf("read final Runner scope: %v", err)
	}
	if finalRevision != initialRevision+1 || finalBindingCount != 0 {
		t.Fatalf("scope DELETE did not commit one complete revision: revision=%d bindings=%d, want %d/0",
			finalRevision, finalBindingCount, initialRevision+1)
	}
}

type lockOrderPostgresHarness struct {
	database *pgxpool.Pool
	schema   string
}

func newLockOrderPostgresHarness(t *testing.T) *lockOrderPostgresHarness {
	t.Helper()
	dsn := os.Getenv("AIOPS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AIOPS_TEST_POSTGRES_DSN is not configured; PostgreSQL 18.4 or newer 18.x lock-order regression was not run")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL integration DSN: %v", err)
	}
	adminConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect PostgreSQL integration database: %v", err)
	}
	var serverVersion int
	if err := admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
		admin.Close()
		t.Fatalf("read PostgreSQL server version: %v", err)
	}
	if serverVersion < 180004 || serverVersion >= 190000 {
		admin.Close()
		t.Fatalf("lock-order integration harness requires PostgreSQL 18.4 or newer 18.x, got server_version_num=%d", serverVersion)
	}

	schema := "aiops_runner_lock_" + lockOrderRandomHex(t, 8)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("parse isolated PostgreSQL config: %v", err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	if config.MaxConns < 8 {
		config.MaxConns = 8
	}
	database, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("connect isolated PostgreSQL schema: %v", err)
	}
	harness := &lockOrderPostgresHarness{database: database, schema: schema}
	t.Cleanup(func() {
		database.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	return harness
}

func (harness *lockOrderPostgresHarness) applyThroughInvestigationRuntime(t *testing.T) {
	t.Helper()
	directory := lockOrderMigrationDirectory(t)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read migration directory: %v", err)
	}
	files := make([]string, 0, 10)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") ||
			entry.Name() > "000010_investigation_runtime.up.sql" {
			continue
		}
		files = append(files, filepath.Join(directory, entry.Name()))
	}
	sort.Strings(files)
	for _, filename := range files {
		contents, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("read migration %s: %v", filepath.Base(filename), err)
		}
		if _, err := harness.database.Exec(context.Background(), string(contents)); err != nil {
			t.Fatalf("apply migration %s: %v", filepath.Base(filename), err)
		}
	}
}

func seedLockOrderRunner(t *testing.T, database *pgxpool.Pool, fixture identityFixture) int64 {
	t.Helper()
	ctx := context.Background()
	lockOrderExec(t, database, `INSERT INTO tenants (id, name) VALUES ($1::uuid, 'lock-order-tenant')`, testTenantID)
	lockOrderExec(t, database, `
		INSERT INTO workspaces (id, tenant_id, name)
		VALUES ($1::uuid, $2::uuid, 'lock-order-workspace')
	`, testWorkspaceID, testTenantID)
	lockOrderExec(t, database, `
		INSERT INTO environments (id, tenant_id, workspace_id, name, kind)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'lock-order-staging', 'STAGING')
	`, testEnvironmentID, testTenantID, testWorkspaceID)
	lockOrderExec(t, database, `
		INSERT INTO runner_registrations (
			runner_id, tenant_id, spiffe_uri, runner_pool, enabled,
			scope_revision, max_concurrency, credential_revocation_capable
		) VALUES ($1, $2::uuid, $3, 'READ', true, 1, 1, false)
	`, lockOrderRunnerID, testTenantID, fixture.identity.SPIFFEURI())
	lockOrderExec(t, database, `
		INSERT INTO runner_scope_bindings (runner_id, tenant_id, workspace_id, environment_id)
		VALUES ($1, $2::uuid, $3::uuid, $4::uuid)
	`, lockOrderRunnerID, testTenantID, testWorkspaceID, testEnvironmentID)
	evidence := fixture.identity.Evidence()
	lockOrderExec(t, database, `
		INSERT INTO runner_certificates (
			certificate_sha256, runner_id, tenant_id, issuer_key_id, serial_hex,
			spki_sha256, status, not_before, not_after
		) VALUES ($1, $2, $3::uuid, $4, $5, $6, 'ACTIVE', $7, $8)
	`, evidence.LeafSHA256(), lockOrderRunnerID, testTenantID, evidence.AuthorityKeyIDHex(),
		evidence.SerialHex(), evidence.SPKISHA256(), evidence.NotBefore(), evidence.NotAfter())
	var revision int64
	if err := database.QueryRow(ctx, `
		SELECT scope_revision FROM runner_registrations
		WHERE tenant_id = $1::uuid AND runner_id = $2
	`, testTenantID, lockOrderRunnerID).Scan(&revision); err != nil {
		t.Fatalf("read seeded Runner scope revision: %v", err)
	}
	return revision
}

func installScopeDeletePauseTrigger(t *testing.T, database *pgxpool.Pool, advisoryKey int64) {
	t.Helper()
	query := fmt.Sprintf(`
		CREATE FUNCTION aaa_lock_order_pause_scope_delete() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(%d);
			RETURN OLD;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER aaa_lock_order_pause_scope_delete
		AFTER DELETE ON runner_scope_bindings
		FOR EACH ROW EXECUTE FUNCTION aaa_lock_order_pause_scope_delete();
	`, advisoryKey)
	lockOrderExec(t, database, query)
}

func newLiveReadIdentityFixture(t *testing.T) identityFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	readCA := mustAuthority(t, "live-runner-read-root", now)
	writeCA := mustAuthority(t, "live-runner-write-root", now)
	spiffeURI := mustURL(t, "spiffe://aiops.example/runner/read/runner-read-lock-order")
	client, err := readCA.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffeURI}}, now)
	if err != nil {
		t.Fatalf("issue live READ Runner certificate: %v", err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create live Runner identity verifier: %v", err)
	}
	chains, err := client.Leaf.Verify(x509.VerifyOptions{
		Roots: readCA.CertPool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("verify live READ Runner certificate: %v", err)
	}
	identity, err := verifier.IdentityFromConnectionState(tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{client.Leaf, readCA.Certificate}, VerifiedChains: chains,
	})
	if err != nil {
		t.Fatalf("derive live READ Runner identity: %v", err)
	}
	return identityFixture{identity: identity, now: now}
}

func lockOrderBackendPID(t *testing.T, ctx context.Context, connection *pgxpool.Conn) int32 {
	t.Helper()
	var pid int32
	if err := connection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatalf("read PostgreSQL backend PID: %v", err)
	}
	return pid
}

func waitForBackendLock(ctx context.Context, database *pgxpool.Pool, pid int32, advisoryOnly bool) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := database.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE pid = $1 AND wait_event_type = 'Lock'
				  AND (NOT $2::boolean OR wait_event = 'advisory')
			)
		`, pid, advisoryOnly).Scan(&waiting); err != nil {
			return err
		}
		if waiting {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func receiveLockOrderResult[T any](ctx context.Context, results <-chan T) (T, error) {
	select {
	case result := <-results:
		return result, nil
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

func postgresDeadlock(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "40P01"
}

func lockOrderExec(t *testing.T, database *pgxpool.Pool, query string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(context.Background(), query, arguments...); err != nil {
		t.Fatalf("exec PostgreSQL lock-order fixture: %v", err)
	}
}

func lockOrderMigrationDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve lock-order integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../migrations"))
}

func lockOrderRandomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := cryptorand.Read(value); err != nil {
		t.Fatalf("generate isolated schema name: %v", err)
	}
	return hex.EncodeToString(value)
}
