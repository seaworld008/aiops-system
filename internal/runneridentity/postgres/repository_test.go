package postgres_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	runnerpostgres "github.com/seaworld008/aiops-system/internal/runneridentity/postgres"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	testTenantID      = "10000000-0000-4000-8000-000000000001"
	testWorkspaceID   = "20000000-0000-4000-8000-000000000002"
	testEnvironmentID = "30000000-0000-4000-8000-000000000003"
	testDBRunnerID    = "registered-write-runner-01"
)

const registrationQueryPattern = `(?s)SELECT runner_id, tenant_id::text, spiffe_uri, runner_pool, enabled,.*FROM runner_registrations.*WHERE spiffe_uri = \$1.*FOR SHARE`
const certificateQueryPattern = `(?s)SELECT runner_id, tenant_id::text, certificate_sha256, spki_sha256, serial_hex, issuer_key_id,.*FROM runner_certificates.*FOR SHARE`

func TestRepositoryAuthenticateRejectsRegistrationMismatchUniformlyAndRollsBack(t *testing.T) {
	tests := []struct {
		name         string
		registration func(identityFixture) []any
		noRows       bool
	}{
		{name: "unknown", noRows: true},
		{name: "invalid runner identifier", registration: func(f identityFixture) []any {
			row := registrationRow(f, true, string(f.identity.Pool()), f.identity.SPIFFEURI(), 7, 3, false)
			row[0] = "-invalid-runner"
			return row
		}},
		{name: "invalid runner identifier character", registration: func(f identityFixture) []any {
			row := registrationRow(f, true, string(f.identity.Pool()), f.identity.SPIFFEURI(), 7, 3, false)
			row[0] = "runner with space"
			return row
		}},
		{name: "oversized runner identifier", registration: func(f identityFixture) []any {
			row := registrationRow(f, true, string(f.identity.Pool()), f.identity.SPIFFEURI(), 7, 3, false)
			row[0] = strings.Repeat("r", 257)
			return row
		}},
		{name: "invalid tenant", registration: func(f identityFixture) []any {
			row := registrationRow(f, true, string(f.identity.Pool()), f.identity.SPIFFEURI(), 7, 3, false)
			row[1] = "tenant-name"
			return row
		}},
		{name: "disabled", registration: func(f identityFixture) []any {
			return registrationRow(f, false, string(f.identity.Pool()), f.identity.SPIFFEURI(), 7, 3, false)
		}},
		{name: "wrong SPIFFE", registration: func(f identityFixture) []any {
			return registrationRow(f, true, string(f.identity.Pool()), "spiffe://aiops.example/runner/write/other", 7, 3, false)
		}},
		{name: "wrong pool", registration: func(f identityFixture) []any {
			return registrationRow(f, true, string(runneridentity.PoolRead), f.identity.SPIFFEURI(), 7, 3, false)
		}},
		{name: "invalid revision", registration: func(f identityFixture) []any {
			return registrationRow(f, true, string(f.identity.Pool()), f.identity.SPIFFEURI(), 0, 3, false)
		}},
		{name: "invalid concurrency", registration: func(f identityFixture) []any {
			return registrationRow(f, true, string(f.identity.Pool()), f.identity.SPIFFEURI(), 7, 0, false)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIdentityFixture(t, runneridentity.PoolWrite)
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("pgxmock.NewPool() error = %v", err)
			}
			defer database.Close()
			repository, err := runnerpostgres.New(database)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			database.ExpectBegin()
			expectation := database.ExpectQuery(registrationQueryPattern).WithArgs(fixture.identity.SPIFFEURI())
			if test.noRows {
				expectation.WillReturnRows(pgxmock.NewRows(registrationColumns()))
			} else {
				expectation.WillReturnRows(pgxmock.NewRows(registrationColumns()).AddRow(test.registration(fixture)...))
			}
			database.ExpectRollback()

			authenticated, authenticateErr := repository.Authenticate(context.Background(), fixture.identity)
			if !errors.Is(authenticateErr, runneridentity.ErrAuthenticationFailed) || authenticated.Valid() {
				t.Fatalf("Authenticate() = %#v, %v; want uniform authentication failure", authenticated, authenticateErr)
			}
			if strings.Contains(authenticateErr.Error(), fixture.identity.Instance()) ||
				strings.Contains(authenticateErr.Error(), fixture.identity.Evidence().LeafSHA256()) {
				t.Fatalf("Authenticate() error leaked identity evidence: %v", authenticateErr)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet PostgreSQL expectations: %v", err)
			}
		})
	}
}

func TestRepositoryAuthenticateRejectsCredentialRevocationCapabilityOnReadPool(t *testing.T) {
	fixture := newIdentityFixture(t, runneridentity.PoolRead)
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin()
	expectRegistration(database, fixture, true, 7, 3, true)
	database.ExpectRollback()

	authenticated, authenticateErr := repository.Authenticate(context.Background(), fixture.identity)
	if !errors.Is(authenticateErr, runneridentity.ErrAuthenticationFailed) || authenticated.Valid() {
		t.Fatalf("Authenticate(READ revocation capability) = %#v, %v; want rejection", authenticated, authenticateErr)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

func TestRepositoryAuthenticateMapsUniqueSPIFFEToCertificateBoundDatabaseRunnerAndExactScope(t *testing.T) {
	fixture := newIdentityFixture(t, runneridentity.PoolWrite)
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	database.ExpectBegin()
	expectRegistration(database, fixture, true, int64(7), 3, true)
	expectCertificate(database, fixture, "ACTIVE", fixture.now)
	database.ExpectQuery(`(?s)SELECT workspace_id::text, environment_id::text.*FROM runner_scope_bindings AS binding.*FOR SHARE OF binding`).
		WithArgs(testDBRunnerID, testTenantID).
		WillReturnRows(pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(testWorkspaceID, testEnvironmentID))
	database.ExpectCommit()

	authenticated, err := repository.Authenticate(context.Background(), fixture.identity)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if fixture.identity.Instance() == testDBRunnerID {
		t.Fatal("test fixture must prove SPIFFE instance and database runner_id may differ")
	}
	if !authenticated.Valid() || authenticated.RunnerID() != testDBRunnerID ||
		authenticated.TenantID() != testTenantID || authenticated.Pool() != runneridentity.PoolWrite ||
		authenticated.ScopeRevision() != 7 || authenticated.MaxConcurrency() != 3 ||
		!authenticated.CredentialRevocationCapable() ||
		authenticated.CertificateSHA256() != fixture.identity.Evidence().LeafSHA256() ||
		!authenticated.CertificateNotAfter().Equal(fixture.identity.Evidence().NotAfter()) {
		t.Fatalf("Authenticate() = %#v", authenticated)
	}
	bindings := authenticated.Bindings()
	if len(bindings) != 1 || bindings[0].WorkspaceID != testWorkspaceID || bindings[0].EnvironmentID != testEnvironmentID {
		t.Fatalf("Authenticate().Bindings() = %#v", bindings)
	}
	if !authenticated.Allows(testWorkspaceID, testEnvironmentID) ||
		authenticated.Allows(testWorkspaceID, "40000000-0000-4000-8000-000000000004") ||
		authenticated.Allows("50000000-0000-4000-8000-000000000005", testEnvironmentID) {
		t.Fatal("AuthenticatedRunner.Allows() did not preserve exact workspace/environment pairs")
	}
	bindings[0].WorkspaceID = "mutated"
	if authenticated.Bindings()[0].WorkspaceID != testWorkspaceID {
		t.Fatal("AuthenticatedRunner.Bindings() returned shared mutable state")
	}
	if encoded, err := json.Marshal(authenticated); err == nil {
		t.Fatalf("json.Marshal(AuthenticatedRunner) = %s, nil; want rejection", encoded)
	}
	var decoded runnerpostgres.AuthenticatedRunner
	if err := json.Unmarshal([]byte(`{}`), &decoded); err == nil || decoded.Valid() {
		t.Fatalf("json.Unmarshal(AuthenticatedRunner) = %#v, %v; want rejection", decoded, err)
	}
	if rendered := fmt.Sprintf("%+v", authenticated); rendered != "<authenticated-postgres-runner>" ||
		strings.Contains(rendered, authenticated.RunnerID()) || strings.Contains(rendered, authenticated.CertificateSHA256()) {
		t.Fatalf("fmt authenticated Runner leaked identity: %q", rendered)
	}
	scope, err := authenticated.RunnerScope()
	if err != nil {
		t.Fatalf("AuthenticatedRunner.RunnerScope() error = %v", err)
	}
	if scope.RunnerID() != testDBRunnerID || scope.TenantID() != testTenantID ||
		scope.Pool() != executionlease.PoolWrite || scope.ScopeRevision() != 7 || scope.MaxConcurrency() != 3 ||
		len(scope.Bindings()) != 1 {
		t.Fatalf("AuthenticatedRunner.RunnerScope() = %#v", scope)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

func TestRepositoryAuthenticateRejectsCertificateMismatchUniformlyAndRollsBack(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(row []any, fixture identityFixture)
		noRows bool
	}{
		{name: "unknown", noRows: true},
		{name: "wrong runner", mutate: func(row []any, _ identityFixture) { row[0] = "other-runner" }},
		{name: "wrong tenant", mutate: func(row []any, _ identityFixture) { row[1] = "10000000-0000-4000-8000-000000000009" }},
		{name: "leaf digest mismatch", mutate: func(row []any, _ identityFixture) { row[2] = strings.Repeat("a", 64) }},
		{name: "SPKI mismatch", mutate: func(row []any, _ identityFixture) { row[3] = strings.Repeat("b", 64) }},
		{name: "serial mismatch", mutate: func(row []any, _ identityFixture) { row[4] = "01" }},
		{name: "AKI mismatch", mutate: func(row []any, _ identityFixture) { row[5] = "02" }},
		{name: "revoked", mutate: func(row []any, _ identityFixture) { row[6] = "REVOKED" }},
		{name: "not before mismatch", mutate: func(row []any, fixture identityFixture) {
			row[7] = fixture.identity.Evidence().NotBefore().Add(time.Second)
		}},
		{name: "not after mismatch", mutate: func(row []any, fixture identityFixture) {
			row[8] = fixture.identity.Evidence().NotAfter().Add(time.Second)
		}},
		{name: "expired at database statement", mutate: func(row []any, fixture identityFixture) {
			row[9] = fixture.identity.Evidence().NotAfter()
		}},
		{name: "not active at database statement", mutate: func(row []any, fixture identityFixture) {
			row[9] = fixture.identity.Evidence().NotBefore().Add(-time.Second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIdentityFixture(t, runneridentity.PoolWrite)
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("pgxmock.NewPool() error = %v", err)
			}
			defer database.Close()
			repository, err := runnerpostgres.New(database)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			database.ExpectBegin()
			expectRegistration(database, fixture, true, 7, 3, true)
			expectation := database.ExpectQuery(certificateQueryPattern).
				WithArgs(fixture.identity.Evidence().LeafSHA256())
			if test.noRows {
				expectation.WillReturnRows(pgxmock.NewRows(certificateColumns()))
			} else {
				row := certificateRow(fixture, "ACTIVE", fixture.now)
				test.mutate(row, fixture)
				expectation.WillReturnRows(pgxmock.NewRows(certificateColumns()).AddRow(row...))
			}
			database.ExpectRollback()

			authenticated, authenticateErr := repository.Authenticate(context.Background(), fixture.identity)
			if !errors.Is(authenticateErr, runneridentity.ErrAuthenticationFailed) || authenticated.Valid() {
				t.Fatalf("Authenticate() = %#v, %v; want uniform certificate authentication failure", authenticated, authenticateErr)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet PostgreSQL expectations: %v", err)
			}
		})
	}
}

func TestRepositoryAuthenticateRejectsInvalidExactScopeBindingsAndRollsBack(t *testing.T) {
	tests := []struct {
		name string
		rows *pgxmock.Rows
	}{
		{name: "empty", rows: pgxmock.NewRows([]string{"workspace_id", "environment_id"})},
		{name: "duplicate pair", rows: pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(testWorkspaceID, testEnvironmentID).
			AddRow(testWorkspaceID, testEnvironmentID)},
		{name: "invalid workspace UUID", rows: pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow("workspace-name", testEnvironmentID)},
		{name: "invalid environment UUID", rows: pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(testWorkspaceID, "PRODUCTION")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIdentityFixture(t, runneridentity.PoolWrite)
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("pgxmock.NewPool() error = %v", err)
			}
			defer database.Close()
			repository, err := runnerpostgres.New(database)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			database.ExpectBegin()
			expectRegistration(database, fixture, true, 7, 3, true)
			expectCertificate(database, fixture, "ACTIVE", fixture.now)
			database.ExpectQuery(`(?s)SELECT workspace_id::text, environment_id::text.*FROM runner_scope_bindings AS binding.*FOR SHARE OF binding`).
				WithArgs(testDBRunnerID, testTenantID).
				WillReturnRows(test.rows)
			database.ExpectRollback()

			authenticated, authenticateErr := repository.Authenticate(context.Background(), fixture.identity)
			if !errors.Is(authenticateErr, runneridentity.ErrAuthenticationFailed) || authenticated.Valid() {
				t.Fatalf("Authenticate() = %#v, %v; want invalid exact-scope rejection", authenticated, authenticateErr)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet PostgreSQL expectations: %v", err)
			}
		})
	}
}

func TestRepositoryAuthenticateTxReusesCallerTransactionAndPreservesLockOrder(t *testing.T) {
	fixture := newIdentityFixture(t, runneridentity.PoolWrite)
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	expectRegistration(database, fixture, true, 9, 4, true)
	expectCertificate(database, fixture, "ACTIVE", fixture.now)
	database.ExpectQuery(`(?s)SELECT workspace_id::text, environment_id::text.*FROM runner_scope_bindings AS binding.*FOR SHARE OF binding`).
		WithArgs(testDBRunnerID, testTenantID).
		WillReturnRows(pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(testWorkspaceID, testEnvironmentID))
	database.ExpectQuery(`SELECT 1`).WillReturnRows(pgxmock.NewRows([]string{"one"}).AddRow(1))
	database.ExpectRollback()

	authenticated, err := repository.AuthenticateTx(context.Background(), tx, fixture.identity)
	if err != nil || !authenticated.Valid() || authenticated.ScopeRevision() != 9 {
		t.Fatalf("AuthenticateTx() = %#v, %v", authenticated, err)
	}
	var one int
	if err := tx.QueryRow(context.Background(), `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("caller transaction was not reusable after AuthenticateTx: one=%d error=%v", one, err)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatalf("caller Rollback() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

func TestRepositoryAuthenticateTxFailureLeavesCallerTransactionUsable(t *testing.T) {
	fixture := newIdentityFixture(t, runneridentity.PoolWrite)
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	database.ExpectQuery(registrationQueryPattern).WithArgs(fixture.identity.SPIFFEURI()).
		WillReturnRows(pgxmock.NewRows(registrationColumns()))
	database.ExpectQuery(`SELECT 1`).WillReturnRows(pgxmock.NewRows([]string{"one"}).AddRow(1))
	database.ExpectRollback()

	authenticated, authenticateErr := repository.AuthenticateTx(context.Background(), tx, fixture.identity)
	if !errors.Is(authenticateErr, runneridentity.ErrAuthenticationFailed) || authenticated.Valid() {
		t.Fatalf("AuthenticateTx(unknown) = %#v, %v", authenticated, authenticateErr)
	}
	var one int
	if err := tx.QueryRow(context.Background(), `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("caller transaction was closed by failed AuthenticateTx: one=%d error=%v", one, err)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatalf("caller Rollback() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

func TestRepositoryDatabaseFailuresRemainDiagnosableWithoutIdentityLeakage(t *testing.T) {
	fixture := newIdentityFixture(t, runneridentity.PoolWrite)
	canary := errors.New("database-transport-canary")
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin().WillReturnError(canary)

	authenticated, authenticateErr := repository.Authenticate(context.Background(), fixture.identity)
	if authenticated.Valid() || !errors.Is(authenticateErr, runnerpostgres.ErrDatabase) || !errors.Is(authenticateErr, canary) {
		t.Fatalf("Authenticate(database failure) = %#v, %v", authenticated, authenticateErr)
	}
	for _, sensitive := range []string{
		fixture.identity.Instance(), fixture.identity.SPIFFEURI(), fixture.identity.Evidence().LeafSHA256(),
	} {
		if strings.Contains(authenticateErr.Error(), sensitive) {
			t.Fatalf("database error leaked Runner identity %q: %v", sensitive, authenticateErr)
		}
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

func TestRepositoryCertificateQueryFailureIsDiagnosableAndRollsBack(t *testing.T) {
	fixture := newIdentityFixture(t, runneridentity.PoolWrite)
	canary := fmt.Errorf(
		"certificate-query-canary spiffe=%s certificate=%s",
		fixture.identity.SPIFFEURI(), fixture.identity.Evidence().LeafSHA256(),
	)
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin()
	expectRegistration(database, fixture, true, 7, 3, true)
	database.ExpectQuery(certificateQueryPattern).WithArgs(fixture.identity.Evidence().LeafSHA256()).
		WillReturnError(canary)
	database.ExpectRollback()

	authenticated, authenticateErr := repository.Authenticate(context.Background(), fixture.identity)
	if authenticated.Valid() || !errors.Is(authenticateErr, runnerpostgres.ErrDatabase) || !errors.Is(authenticateErr, canary) {
		t.Fatalf("Authenticate(certificate query failure) = %#v, %v", authenticated, authenticateErr)
	}
	for _, sensitive := range []string{fixture.identity.SPIFFEURI(), fixture.identity.Evidence().LeafSHA256()} {
		if strings.Contains(authenticateErr.Error(), sensitive) {
			t.Fatalf("Authenticate(certificate query failure) leaked Runner identity %q: %v", sensitive, authenticateErr)
		}
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

func TestRepositoryCommitFailureIsDiagnosableAndAttemptsRollback(t *testing.T) {
	fixture := newIdentityFixture(t, runneridentity.PoolWrite)
	canary := errors.New("commit-canary")
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	repository, err := runnerpostgres.New(database)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	database.ExpectBegin()
	expectRegistration(database, fixture, true, 7, 3, true)
	expectCertificate(database, fixture, "ACTIVE", fixture.now)
	database.ExpectQuery(`(?s)SELECT workspace_id::text, environment_id::text.*FROM runner_scope_bindings AS binding.*FOR SHARE OF binding`).
		WithArgs(testDBRunnerID, testTenantID).
		WillReturnRows(pgxmock.NewRows([]string{"workspace_id", "environment_id"}).
			AddRow(testWorkspaceID, testEnvironmentID))
	database.ExpectCommit().WillReturnError(canary)
	database.ExpectRollback()

	authenticated, authenticateErr := repository.Authenticate(context.Background(), fixture.identity)
	if authenticated.Valid() || !errors.Is(authenticateErr, runnerpostgres.ErrDatabase) || !errors.Is(authenticateErr, canary) {
		t.Fatalf("Authenticate(commit failure) = %#v, %v", authenticated, authenticateErr)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet PostgreSQL expectations: %v", err)
	}
}

type identityFixture struct {
	identity runneridentity.Identity
	now      time.Time
}

func newIdentityFixture(t *testing.T, pool runneridentity.Pool) identityFixture {
	t.Helper()
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	authority := readCA
	poolPath := "read"
	instance := "runner-read-01"
	if pool == runneridentity.PoolWrite {
		authority = writeCA
		poolPath = "write"
		instance = "runner-write-01"
	}
	spiffeURI := mustURL(t, "spiffe://aiops.example/runner/"+poolPath+"/"+instance)
	client, err := authority.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffeURI}}, now)
	if err != nil {
		t.Fatalf("Authority.IssueClient() error = %v", err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("runneridentity.NewVerifier() error = %v", err)
	}
	chains, err := client.Leaf.Verify(x509.VerifyOptions{
		Roots: authority.CertPool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("verify test Runner certificate: %v", err)
	}
	identity, err := verifier.IdentityFromConnectionState(tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{client.Leaf, authority.Certificate}, VerifiedChains: chains,
	})
	if err != nil {
		t.Fatalf("IdentityFromConnectionState() error = %v", err)
	}
	return identityFixture{identity: identity, now: now}
}

func expectRegistration(
	database pgxmock.PgxPoolIface,
	fixture identityFixture,
	enabled bool,
	revision int64,
	maxConcurrency int,
	revocationCapable bool,
) {
	database.ExpectQuery(registrationQueryPattern).
		WithArgs(fixture.identity.SPIFFEURI()).
		WillReturnRows(pgxmock.NewRows([]string{
			"runner_id", "tenant_id", "spiffe_uri", "runner_pool", "enabled",
			"scope_revision", "max_concurrency", "credential_revocation_capable",
		}).AddRow(
			testDBRunnerID, testTenantID, fixture.identity.SPIFFEURI(), fixture.identity.Pool(), enabled,
			revision, maxConcurrency, revocationCapable,
		))
}

func registrationColumns() []string {
	return []string{
		"runner_id", "tenant_id", "spiffe_uri", "runner_pool", "enabled",
		"scope_revision", "max_concurrency", "credential_revocation_capable",
	}
}

func registrationRow(
	fixture identityFixture,
	enabled bool,
	pool string,
	spiffeURI string,
	revision int64,
	maxConcurrency int,
	revocationCapable bool,
) []any {
	return []any{
		testDBRunnerID, testTenantID, spiffeURI, pool, enabled,
		revision, maxConcurrency, revocationCapable,
	}
}

func expectCertificate(database pgxmock.PgxPoolIface, fixture identityFixture, status string, databaseNow time.Time) {
	database.ExpectQuery(`(?s)SELECT runner_id, tenant_id::text, certificate_sha256, spki_sha256, serial_hex, issuer_key_id,.*FROM runner_certificates.*FOR SHARE`).
		WithArgs(fixture.identity.Evidence().LeafSHA256()).
		WillReturnRows(pgxmock.NewRows(certificateColumns()).AddRow(certificateRow(fixture, status, databaseNow)...))
}

func certificateColumns() []string {
	return []string{
		"runner_id", "tenant_id", "certificate_sha256", "spki_sha256", "serial_hex", "issuer_key_id",
		"status", "not_before", "not_after", "database_now",
	}
}

func certificateRow(fixture identityFixture, status string, databaseNow time.Time) []any {
	evidence := fixture.identity.Evidence()
	return []any{
		testDBRunnerID, testTenantID, evidence.LeafSHA256(), evidence.SPKISHA256(),
		evidence.SerialHex(), evidence.AuthorityKeyIDHex(), status, evidence.NotBefore(), evidence.NotAfter(), databaseNow,
	}
}

func mustAuthority(t *testing.T, name string, now time.Time) *testpki.Authority {
	t.Helper()
	authority, err := testpki.NewAuthority(name, now)
	if err != nil {
		t.Fatalf("testpki.NewAuthority(%q) error = %v", name, err)
	}
	return authority
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", raw, err)
	}
	return value
}
