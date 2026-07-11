package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

var ErrDatabase = errors.New("runner identity database operation failed")

const maximumScopeBindings = 4096

type DB interface {
	Begin(context.Context) (pgx.Tx, error)
}

type Repository struct {
	database DB
}

func New(database DB) (*Repository, error) {
	if database == nil {
		return nil, fmt.Errorf("runner identity PostgreSQL database is required")
	}
	return &Repository{database: database}, nil
}

type authenticatedState struct {
	runnerID                    string
	tenantID                    string
	pool                        runneridentity.Pool
	scopeRevision               int64
	maxConcurrency              int
	credentialRevocationCapable bool
	certificateSHA256           string
	certificateNotAfter         time.Time
	bindings                    []execution.RunnerScopeBinding
}

type AuthenticatedRunner struct {
	state *authenticatedState
}

func (runner AuthenticatedRunner) Valid() bool {
	if runner.state == nil || !validRunnerIdentifier(runner.state.runnerID) || !validUUID(runner.state.tenantID) ||
		!runner.state.pool.Valid() ||
		runner.state.scopeRevision <= 0 || runner.state.maxConcurrency < 1 || runner.state.maxConcurrency > 1024 ||
		!validSHA256(runner.state.certificateSHA256) || !validFiniteTime(runner.state.certificateNotAfter) ||
		len(runner.state.bindings) == 0 || len(runner.state.bindings) > maximumScopeBindings ||
		runner.state.credentialRevocationCapable && runner.state.pool != runneridentity.PoolWrite {
		return false
	}
	seen := make(map[string]struct{}, len(runner.state.bindings))
	for _, binding := range runner.state.bindings {
		if !validUUID(binding.WorkspaceID) || !validUUID(binding.EnvironmentID) {
			return false
		}
		key := binding.WorkspaceID + "\x00" + binding.EnvironmentID
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func (runner AuthenticatedRunner) RunnerID() string {
	if runner.state == nil {
		return ""
	}
	return runner.state.runnerID
}

func (runner AuthenticatedRunner) TenantID() string {
	if runner.state == nil {
		return ""
	}
	return runner.state.tenantID
}

func (runner AuthenticatedRunner) Pool() runneridentity.Pool {
	if runner.state == nil {
		return ""
	}
	return runner.state.pool
}

func (runner AuthenticatedRunner) ScopeRevision() int64 {
	if runner.state == nil {
		return 0
	}
	return runner.state.scopeRevision
}

func (runner AuthenticatedRunner) MaxConcurrency() int {
	if runner.state == nil {
		return 0
	}
	return runner.state.maxConcurrency
}

func (runner AuthenticatedRunner) CredentialRevocationCapable() bool {
	return runner.state != nil && runner.state.credentialRevocationCapable
}

func (runner AuthenticatedRunner) CertificateSHA256() string {
	if runner.state == nil {
		return ""
	}
	return runner.state.certificateSHA256
}

func (runner AuthenticatedRunner) CertificateNotAfter() time.Time {
	if runner.state == nil {
		return time.Time{}
	}
	return runner.state.certificateNotAfter
}

func (runner AuthenticatedRunner) Bindings() []execution.RunnerScopeBinding {
	if runner.state == nil {
		return nil
	}
	return append([]execution.RunnerScopeBinding(nil), runner.state.bindings...)
}

func (runner AuthenticatedRunner) Allows(workspaceID, environmentID string) bool {
	if !runner.Valid() {
		return false
	}
	for _, binding := range runner.state.bindings {
		if binding.WorkspaceID == workspaceID && binding.EnvironmentID == environmentID {
			return true
		}
	}
	return false
}

func (runner AuthenticatedRunner) RunnerScope() (execution.RunnerScope, error) {
	if !runner.Valid() {
		return execution.RunnerScope{}, runneridentity.ErrAuthenticationFailed
	}
	pool := executionlease.PoolRead
	if runner.state.pool == runneridentity.PoolWrite {
		pool = executionlease.PoolWrite
	}
	registration := execution.RunnerRegistration{
		RunnerID: runner.state.runnerID, TenantID: runner.state.tenantID, Pool: pool, Enabled: true,
		ScopeRevision: runner.state.scopeRevision, MaxConcurrency: runner.state.maxConcurrency,
		ScopeBindings: runner.Bindings(),
	}
	scope, err := registration.Scope()
	if err != nil {
		return execution.RunnerScope{}, runneridentity.ErrAuthenticationFailed
	}
	return scope, nil
}

func (AuthenticatedRunner) MarshalJSON() ([]byte, error) { return nil, runneridentity.ErrWireIdentity }
func (*AuthenticatedRunner) UnmarshalJSON([]byte) error  { return runneridentity.ErrWireIdentity }
func (AuthenticatedRunner) String() string               { return "<authenticated-postgres-runner>" }
func (runner AuthenticatedRunner) GoString() string      { return runner.String() }
func (runner AuthenticatedRunner) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(runner.String()))
}

func (repository *Repository) Authenticate(ctx context.Context, identity runneridentity.Identity) (AuthenticatedRunner, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
		}
		return AuthenticatedRunner{}, ctx.Err()
	}
	if repository == nil || repository.database == nil || !identity.Valid() {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}
	tx, err := repository.database.Begin(ctx)
	if err != nil {
		return AuthenticatedRunner{}, databaseError("begin Runner identity authentication", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	authenticated, err := repository.AuthenticateTx(ctx, tx, identity)
	if err != nil {
		return AuthenticatedRunner{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthenticatedRunner{}, databaseError("commit Runner identity authentication", err)
	}
	committed = true
	return authenticated, nil
}

func (repository *Repository) AuthenticateTx(
	ctx context.Context,
	tx pgx.Tx,
	identity runneridentity.Identity,
) (AuthenticatedRunner, error) {
	if ctx == nil || tx == nil || repository == nil || !identity.Valid() {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}
	if err := ctx.Err(); err != nil {
		return AuthenticatedRunner{}, err
	}

	var runnerID, tenantID, spiffeURI, pool string
	var enabled, credentialRevocationCapable bool
	var scopeRevision int64
	var maxConcurrency int
	err := tx.QueryRow(ctx, `
		SELECT runner_id, tenant_id::text, spiffe_uri, runner_pool, enabled,
			scope_revision, max_concurrency, credential_revocation_capable
		FROM runner_registrations
		WHERE spiffe_uri = $1
		FOR SHARE
	`, identity.SPIFFEURI()).Scan(
		&runnerID, &tenantID, &spiffeURI, &pool, &enabled,
		&scopeRevision, &maxConcurrency, &credentialRevocationCapable,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}
	if err != nil {
		return AuthenticatedRunner{}, databaseError("lock Runner registration", err)
	}
	if !validRunnerIdentifier(runnerID) || !validUUID(tenantID) || spiffeURI != identity.SPIFFEURI() || !enabled ||
		pool != string(identity.Pool()) || identity.Evidence().RootPool() != identity.Pool() ||
		scopeRevision <= 0 || maxConcurrency < 1 || maxConcurrency > 1024 ||
		credentialRevocationCapable && identity.Pool() != runneridentity.PoolWrite {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}

	evidence := identity.Evidence()
	var certificateRunnerID, certificateTenantID, certificateSHA256, spkiSHA256 string
	var serialHex, issuerKeyID, status string
	var notBefore, notAfter, databaseNow time.Time
	err = tx.QueryRow(ctx, `
		SELECT runner_id, tenant_id::text, certificate_sha256, spki_sha256, serial_hex, issuer_key_id,
			status, not_before, not_after, statement_timestamp() AS database_now
		FROM runner_certificates
		WHERE certificate_sha256 = $1
		FOR SHARE
	`, evidence.LeafSHA256()).Scan(
		&certificateRunnerID, &certificateTenantID, &certificateSHA256, &spkiSHA256, &serialHex, &issuerKeyID,
		&status, &notBefore, &notAfter, &databaseNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}
	if err != nil {
		return AuthenticatedRunner{}, databaseError("lock Runner certificate", err)
	}
	if certificateRunnerID != runnerID || certificateTenantID != tenantID || certificateSHA256 != evidence.LeafSHA256() ||
		spkiSHA256 != evidence.SPKISHA256() || serialHex != evidence.SerialHex() || issuerKeyID != evidence.AuthorityKeyIDHex() ||
		status != "ACTIVE" || !validFiniteTime(notBefore) || !validFiniteTime(notAfter) || !validFiniteTime(databaseNow) ||
		!notBefore.Equal(evidence.NotBefore()) || !notAfter.Equal(evidence.NotAfter()) ||
		databaseNow.Before(notBefore) || !databaseNow.Before(notAfter) {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}

	rows, err := tx.Query(ctx, `
		SELECT workspace_id::text, environment_id::text
		FROM runner_scope_bindings AS binding
		WHERE binding.runner_id = $1 AND binding.tenant_id = $2::uuid
		ORDER BY binding.workspace_id, binding.environment_id
		FOR SHARE OF binding
	`, runnerID, tenantID)
	if err != nil {
		return AuthenticatedRunner{}, databaseError("lock Runner scope bindings", err)
	}
	defer rows.Close()
	bindings := make([]execution.RunnerScopeBinding, 0)
	seenBindings := make(map[string]struct{})
	for rows.Next() {
		var binding execution.RunnerScopeBinding
		if err := rows.Scan(&binding.WorkspaceID, &binding.EnvironmentID); err != nil {
			return AuthenticatedRunner{}, databaseError("scan Runner scope binding", err)
		}
		if !validUUID(binding.WorkspaceID) || !validUUID(binding.EnvironmentID) || len(bindings) == maximumScopeBindings {
			return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
		}
		key := binding.WorkspaceID + "\x00" + binding.EnvironmentID
		if _, duplicate := seenBindings[key]; duplicate {
			return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
		}
		seenBindings[key] = struct{}{}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return AuthenticatedRunner{}, databaseError("read Runner scope bindings", err)
	}
	if len(bindings) == 0 {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}
	authenticated := AuthenticatedRunner{state: &authenticatedState{
		runnerID: runnerID, tenantID: tenantID, pool: identity.Pool(), scopeRevision: scopeRevision,
		maxConcurrency: maxConcurrency, credentialRevocationCapable: credentialRevocationCapable,
		certificateSHA256: certificateSHA256, certificateNotAfter: notAfter.UTC(), bindings: bindings,
	}}
	if !authenticated.Valid() {
		return AuthenticatedRunner{}, runneridentity.ErrAuthenticationFailed
	}
	return authenticated, nil
}

var (
	runnerIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)
	uuidPattern             = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	sha256Pattern           = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func validRunnerIdentifier(value string) bool {
	return len(value) >= 1 && len(value) <= 256 && runnerIdentifierPattern.MatchString(value)
}

func validUUID(value string) bool   { return uuidPattern.MatchString(value) }
func validSHA256(value string) bool { return sha256Pattern.MatchString(value) }

func validFiniteTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func databaseError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return databaseOperationError{operation: operation, cause: err}
}

// databaseOperationError keeps the underlying cause available to errors.Is and
// errors.As without copying its potentially identity-bearing text into API,
// audit, trace, or log output.
type databaseOperationError struct {
	operation string
	cause     error
}

func (failure databaseOperationError) Error() string {
	return failure.operation + ": " + ErrDatabase.Error()
}

func (failure databaseOperationError) Unwrap() []error {
	return []error{ErrDatabase, failure.cause}
}

var _ json.Marshaler = AuthenticatedRunner{}
var _ json.Unmarshaler = (*AuthenticatedRunner)(nil)
