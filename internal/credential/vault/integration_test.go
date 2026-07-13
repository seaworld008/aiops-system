package vault_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"maps"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/seaworld008/aiops-system/internal/credential"
	vaultclient "github.com/seaworld008/aiops-system/internal/credential/vault"
)

const (
	integrationRequestTimeout = 20 * time.Second
	integrationPollTimeout    = 20 * time.Second
	integrationBodyLimit      = 64 << 10
	integrationJSONDepth      = 32
	// Vault 2.0.3's token store returns StatusBadRequest("invalid accessor").
	// Core transports that route error through go-multierror v1.1.1 before the
	// HTTP layer serializes it, so the public error string has this exact form.
	integrationInvalidAccessorRouteError = "1 error occurred:\n\t* invalid accessor\n\n"
)

var (
	integrationDatabaseNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	integrationIdentifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	integrationEnvelopeFields      = []string{
		"request_id", "lease_id", "renewable", "lease_duration", "data", "wrap_info", "warnings", "auth", "mount_type",
	}
	integrationAuthFields = []string{
		"client_token", "accessor", "policies", "token_policies", "metadata", "lease_duration",
		"renewable", "entity_id", "token_type", "orphan", "mfa_requirement", "num_uses",
	}
	integrationLookupFields = []string{
		"id", "accessor", "policies", "path", "meta", "display_name", "num_uses", "orphan",
		"creation_time", "creation_ttl", "expire_time", "ttl", "explicit_max_ttl", "entity_id",
		"type", "renewable", "issue_time",
	}
)

func TestVault203IntegrationAddressRequiresNumericLoopbackForHTTPAndHTTPS(t *testing.T) {
	t.Parallel()
	for _, address := range []string{
		"http://vault.example.test:8200",
		"https://vault.example.test:8200",
		"http://localhost:8200",
		"https://localhost:8200",
	} {
		if _, err := validateIntegrationVaultAddress(address); err == nil {
			t.Errorf("non-numeric-loopback Vault integration address was accepted")
		}
	}
	for _, address := range []string{"http://127.0.0.1:8200", "https://[::1]:8200"} {
		if _, err := validateIntegrationVaultAddress(address); err != nil {
			t.Errorf("numeric-loopback Vault integration address was rejected")
		}
	}
}

func TestVault203IntegrationVaultPostgresTargetIsTheExplicitCIService(t *testing.T) {
	t.Parallel()
	if !validIntegrationVaultPostgresTarget("postgres:5432") {
		t.Fatal("explicit Vault-to-PostgreSQL CI service target was rejected")
	}
	for _, target := range []string{"127.0.0.1:5432", "database:5432", "postgres:15432", "postgres"} {
		if validIntegrationVaultPostgresTarget(target) {
			t.Errorf("Vault-to-PostgreSQL target outside the explicit CI service was accepted")
		}
	}
}

func TestVault203IntegrationPostgresDSNRequiresExplicitNumericLoopback(t *testing.T) {
	t.Parallel()
	valid := "postgres://aiops:aiops-test-only@127.0.0.1:5432/aiops_test?sslmode=disable"
	if config, err := parseIntegrationPostgresDSN(valid); err != nil || config.Host != "127.0.0.1" {
		t.Fatal("explicit numeric-loopback PostgreSQL CI DSN was rejected")
	}
	for _, dsn := range []string{
		"",
		"postgres://aiops:aiops-test-only@localhost:5432/aiops_test?sslmode=disable",
		"postgres://aiops:aiops-test-only@192.0.2.10:5432/aiops_test?sslmode=disable",
		"postgres://aiops:aiops-test-only@127.0.0.1:5432/aiops_test?sslmode=disable&host=192.0.2.10",
		"postgres://aiops@127.0.0.1:5432/aiops_test?sslmode=disable",
	} {
		if _, err := parseIntegrationPostgresDSN(dsn); err == nil {
			t.Errorf("unsafe PostgreSQL integration DSN was accepted")
		}
	}
}

// This test exercises Vault 2.0.3 and PostgreSQL 18.4 or newer 18.x through real HTTP APIs.
// The raw setup helper is intentionally independent from the production Vault
// client's private response validators. The production path is exercised only
// through exported Profile, IssuerClient, and RevocationClient APIs over a TLS
// 1.3 / HTTP/1.1 proxy.
// This dev-mode proxy is not evidence for real Vault server PKI, namespaces,
// HA/failover, audit canaries, or production listener/network-policy gates.
//
// Sources:
//   - https://github.com/hashicorp/vault/blob/v2.0.3/vault/request_handling.go#L1276-L1312
//   - https://developer.hashicorp.com/vault/api-docs/auth/token
//   - https://developer.hashicorp.com/vault/api-docs/secret/databases
//   - https://developer.hashicorp.com/vault/api-docs/system/leases
func TestVault203DurableClientAndLimitedUseDatabaseCredentials(t *testing.T) {
	fixture := newVault203Fixture(t)

	t.Run("production-client-closure", func(t *testing.T) {
		fixture.proveProductionClientClosure(t)
	})
	t.Run("one-use-cannot-return-leased-secret", func(t *testing.T) {
		fixture.proveOneUseCannotReturnLeasedSecret(t)
	})
	t.Run("two-uses-return-exactly-one-leased-secret", func(t *testing.T) {
		fixture.proveTwoUsesReturnExactlyOneLeasedSecret(t)
	})
	t.Run("renewable-lease-cannot-be-renewed-by-child", func(t *testing.T) {
		fixture.proveRenewableLeaseCannotBeRenewed(t)
	})
	t.Run("real-kv-empty-lease-is-rejected-by-production-client", func(t *testing.T) {
		fixture.proveEmptyLeaseRejected(t)
	})
	t.Run("entity-contaminated-child-is-rejected-by-production-inspection", func(t *testing.T) {
		fixture.proveEntityContaminationRejected(t)
	})
	t.Run("parent-accessor-revocation-cascades", func(t *testing.T) {
		fixture.proveParentAccessorCascade(t)
	})
}

type vault203Fixture struct {
	raw                *integrationVaultHTTPClient
	rootToken          []byte
	postgres           *pgx.ConnConfig
	vaultPostgresURL   string
	databaseName       string
	suffix             string
	databaseMount      string
	databaseConnection string
	databaseRole       string
	childPolicy        string
	managerPolicy      string
	revokerPolicy      string
	tokenRole          string
	kvMount            string
	kvPolicy           string
	kvSecret           string
	entityManagerRole  string
	entityAlias        string
	profileID          string
	profileRevision    string
	profileMetadata    map[string]string
	manager            *integrationToken
	revoker            *integrationToken
	proxy              *integrationTLSProxy
	issuer             *vaultclient.IssuerClient
	revocation         *vaultclient.RevocationClient
	managerSource      *integrationTokenSource
	revokerSource      *integrationTokenSource
}

type integrationVaultHTTPClient struct {
	baseURL url.URL
	client  *http.Client
}

type integrationResponse struct {
	status int
	body   []byte
}

func (response *integrationResponse) destroy() {
	if response == nil {
		return
	}
	clear(response.body)
	response.body = nil
}

type integrationToken struct {
	token    []byte
	accessor []byte
	entityID string
	orphan   bool
	numUses  int64
}

func (token *integrationToken) destroy() {
	if token == nil {
		return
	}
	clear(token.token)
	clear(token.accessor)
	token.token, token.accessor = nil, nil
}

type integrationDatabaseCredential struct {
	username  string
	password  []byte
	leaseID   []byte
	renewable bool
}

func (value *integrationDatabaseCredential) destroy() {
	if value == nil {
		return
	}
	clear(value.password)
	clear(value.leaseID)
	value.password, value.leaseID = nil, nil
}

type integrationLookup struct {
	numUses  int64
	entityID string
	orphan   bool
	policies []string
	role     string
	metadata map[string]string
}

type integrationTLSProxy struct {
	server *httptest.Server
	caPEM  []byte
}

type integrationTokenSource struct {
	sourceID string
	token    []byte
	requests atomic.Int64
}

func (source *integrationTokenSource) SourceID() string { return source.sourceID }

func (source *integrationTokenSource) Token(ctx context.Context) (credential.SensitiveValue, error) {
	if source == nil || ctx == nil || ctx.Err() != nil || !validIntegrationBearer(source.token) {
		return credential.SensitiveValue{}, errors.New("integration token source unavailable")
	}
	source.requests.Add(1)
	return credential.NewSensitiveValue(source.token)
}

func validateIntegrationVaultAddress(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return nil, errors.New("Vault integration address is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Opaque != "" || parsed.ForceQuery ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && parsed.Path != "/") || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("invalid Vault integration address")
	}
	host := net.ParseIP(parsed.Hostname())
	if host == nil || !host.IsLoopback() {
		return nil, errors.New("Vault integration address must use numeric loopback")
	}
	return parsed, nil
}

func validIntegrationVaultPostgresTarget(value string) bool {
	return value == "postgres:5432"
}

func parseIntegrationPostgresDSN(raw string) (*pgx.ConnConfig, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return nil, errors.New("PostgreSQL integration DSN is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil ||
		parsed.RawPath != "" || parsed.RawQuery == "" || parsed.Fragment != "" || parsed.Hostname() == "" ||
		parsed.Port() == "" || !integrationDatabaseNamePattern.MatchString(strings.TrimPrefix(parsed.Path, "/")) ||
		strings.Count(parsed.Path, "/") != 1 {
		return nil, errors.New("invalid PostgreSQL integration DSN")
	}
	password, passwordPresent := parsed.User.Password()
	if parsed.User.Username() == "" || !passwordPresent || password == "" {
		return nil, errors.New("PostgreSQL integration DSN requires explicit credentials")
	}
	host := net.ParseIP(parsed.Hostname())
	if host == nil || !host.IsLoopback() {
		return nil, errors.New("PostgreSQL integration DSN must use numeric loopback")
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("PostgreSQL integration DSN requires an explicit port")
	}
	query := parsed.Query()
	if len(query) != 1 || len(query["sslmode"]) != 1 || query.Get("sslmode") != "disable" {
		return nil, errors.New("PostgreSQL integration DSN has unsafe query parameters")
	}
	config, err := pgx.ParseConfig(raw)
	if err != nil || net.ParseIP(config.Host) == nil || !net.ParseIP(config.Host).Equal(host) ||
		config.Port != uint16(port) || config.User != parsed.User.Username() || config.Password != password ||
		config.Database != strings.TrimPrefix(parsed.Path, "/") || config.TLSConfig != nil {
		return nil, errors.New("PostgreSQL integration DSN changed meaning during parsing")
	}
	config.ConnectTimeout = 2 * time.Second
	return config, nil
}

func newVault203Fixture(t *testing.T) *vault203Fixture {
	t.Helper()
	address, addressConfigured := os.LookupEnv("AIOPS_TEST_VAULT_ADDR")
	rootToken, tokenConfigured := os.LookupEnv("AIOPS_TEST_VAULT_ROOT_TOKEN")
	if !addressConfigured && !tokenConfigured {
		t.Skip("AIOPS_TEST_VAULT_ADDR and AIOPS_TEST_VAULT_ROOT_TOKEN are not configured")
	}
	if !addressConfigured || !tokenConfigured || address == "" || rootToken == "" {
		t.Fatal("Vault integration address and root token must be configured together")
	}
	parsedAddress, err := validateIntegrationVaultAddress(address)
	if err != nil {
		t.Fatal("Vault integration address is outside the loopback test boundary")
	}
	rootTokenBytes := []byte(rootToken)
	if !validIntegrationBearer(rootTokenBytes) {
		clear(rootTokenBytes)
		t.Fatal("Vault integration root token is invalid")
	}
	t.Cleanup(func() { clear(rootTokenBytes) })

	postgresDSN, postgresConfigured := os.LookupEnv("AIOPS_TEST_POSTGRES_DSN")
	if !postgresConfigured || postgresDSN == "" {
		t.Fatal("AIOPS_TEST_POSTGRES_DSN must be explicitly configured")
	}
	postgresConfig, err := parseIntegrationPostgresDSN(postgresDSN)
	if err != nil {
		t.Fatal("PostgreSQL integration DSN is outside the numeric-loopback test boundary")
	}
	vaultPostgresTarget, targetConfigured := os.LookupEnv("AIOPS_TEST_VAULT_POSTGRES_HOST")
	if !targetConfigured || !validIntegrationVaultPostgresTarget(vaultPostgresTarget) {
		t.Fatal("AIOPS_TEST_VAULT_POSTGRES_HOST must be the explicit postgres:5432 CI service")
	}

	var randomSuffix [6]byte
	if _, err := rand.Read(randomSuffix[:]); err != nil {
		t.Fatal("could not allocate a unique Vault integration fixture")
	}
	suffix := hex.EncodeToString(randomSuffix[:])
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = false
	raw := &integrationVaultHTTPClient{
		baseURL: *parsedAddress,
		client: &http.Client{
			Transport: transport,
			Timeout:   integrationRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	fixture := &vault203Fixture{
		raw: raw, rootToken: rootTokenBytes, postgres: postgresConfig,
		vaultPostgresURL: "postgresql://{{username}}:{{password}}@" + vaultPostgresTarget + "/" +
			postgresConfig.Database + "?sslmode=disable",
		databaseName: postgresConfig.Database, suffix: suffix,
		databaseMount: "aiops-db-" + suffix, databaseConnection: "pg-" + suffix,
		databaseRole: "db-" + suffix, childPolicy: "aiops-child-" + suffix,
		managerPolicy: "aiops-manager-" + suffix, revokerPolicy: "aiops-revoker-" + suffix,
		tokenRole: "aiops-job-" + suffix, kvMount: "aiops-kv-" + suffix,
		kvPolicy: "aiops-kv-child-" + suffix, kvSecret: "empty-lease",
		entityManagerRole: "aiops-entity-manager-" + suffix, entityAlias: "aiops-entity-" + suffix,
		profileID: "vault-db-" + suffix, profileRevision: "rev-" + suffix,
	}
	fixture.profileMetadata = map[string]string{
		"profile":  fixture.profileID,
		"revision": fixture.profileRevision,
	}
	fixture.assertVault203(t)
	fixture.configureInfrastructure(t)

	fixture.manager = fixture.createToken(t, fixture.rootToken, "/v1/auth/token/create-orphan", map[string]any{
		"policies": []string{fixture.managerPolicy}, "ttl": "20m", "explicit_max_ttl": "20m",
		"no_default_policy": true, "display_name": "aiops-manager", "num_uses": 0,
		"renewable": false, "type": "service",
	}, integrationTokenExpectation{
		policies: []string{fixture.managerPolicy}, orphan: true, numUses: 0,
	})
	t.Cleanup(fixture.manager.destroy)
	fixture.registerTokenCleanup(t, fixture.manager.accessor)

	fixture.revoker = fixture.createToken(t, fixture.rootToken, "/v1/auth/token/create-orphan", map[string]any{
		"policies": []string{fixture.revokerPolicy}, "ttl": "20m", "explicit_max_ttl": "20m",
		"no_default_policy": true, "display_name": "aiops-revoker", "num_uses": 0,
		"renewable": false, "type": "service",
	}, integrationTokenExpectation{
		policies: []string{fixture.revokerPolicy}, orphan: true, numUses: 0,
	})
	t.Cleanup(fixture.revoker.destroy)
	fixture.registerTokenCleanup(t, fixture.revoker.accessor)

	allowed := map[string]struct{}{
		http.MethodGet + " /v1/auth/token/lookup-self":                                      {},
		http.MethodPost + " /v1/auth/token/create/" + fixture.tokenRole:                     {},
		http.MethodPost + " /v1/auth/token/lookup-accessor":                                 {},
		http.MethodPost + " /v1/auth/token/revoke-accessor":                                 {},
		http.MethodGet + " /v1/" + fixture.databaseMount + "/creds/" + fixture.databaseRole: {},
		http.MethodGet + " /v1/" + fixture.kvMount + "/" + fixture.kvSecret:                 {},
	}
	fixture.proxy = newIntegrationTLSProxy(t, parsedAddress, allowed)
	fixture.managerSource = &integrationTokenSource{sourceID: "manager-src-" + suffix, token: fixture.manager.token}
	fixture.revokerSource = &integrationTokenSource{sourceID: "revoker-src-" + suffix, token: fixture.revoker.token}
	profile, err := vaultclient.NewProfile(vaultclient.ProfileConfig{
		IssuerID: fixture.profileID, Revision: fixture.profileRevision,
		Address: fixture.proxy.server.URL, ServerName: "127.0.0.1", CAPEM: fixture.proxy.caPEM,
		ManagerPolicy: fixture.managerPolicy, TokenRole: fixture.tokenRole, ChildPolicy: fixture.childPolicy,
		DynamicPath: fixture.databaseMount + "/creds/" + fixture.databaseRole, MountType: "database",
		Metadata: fixture.profileMetadata,
		SecretFields: []vaultclient.SecretField{
			{Name: "username", MaxBytes: 512},
			{Name: "password", MaxBytes: 512},
		},
	})
	if err != nil {
		t.Fatal("could not construct the immutable production Vault profile")
	}
	fixture.issuer, err = vaultclient.NewIssuerClient(profile, fixture.managerSource)
	if err != nil {
		t.Fatal("could not construct the production Vault issuer client")
	}
	fixture.revocation, err = vaultclient.NewRevocationClient(profile, fixture.revokerSource)
	if err != nil {
		t.Fatal("could not construct the production Vault revocation client")
	}
	type accessorRevoker interface {
		RevokeAccessor(context.Context, *credential.SensitiveReference) error
	}
	if _, exposed := any(fixture.issuer).(accessorRevoker); exposed {
		t.Fatal("production Vault issuer client exposed revocation capability")
	}
	if _, exposed := any(fixture.revocation).(credential.DurableIssuer); exposed {
		t.Fatal("production Vault revocation client exposed issuance capability")
	}
	return fixture
}

func (fixture *vault203Fixture) assertVault203(t *testing.T) {
	t.Helper()
	response := fixture.mustCall(t, http.MethodGet, "/v1/sys/health", fixture.rootToken, nil)
	defer response.destroy()
	if response.status != http.StatusOK || rejectIntegrationDuplicateKeys(response.body) != nil {
		t.Fatal("Vault integration service did not return a valid healthy response")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.body, &fields); err != nil {
		t.Fatal("Vault integration service health response was not JSON")
	}
	defer destroyIntegrationRawMap(fields)
	var version string
	if err := json.Unmarshal(fields["version"], &version); err != nil || version != "2.0.3" {
		t.Fatal("Vault integration service is not the required 2.0.3 release")
	}
}

func (fixture *vault203Fixture) configureInfrastructure(t *testing.T) {
	t.Helper()
	fixture.mustStatus(t, http.MethodPost, "/v1/sys/mounts/"+fixture.databaseMount, fixture.rootToken,
		map[string]any{
			"type":   "database",
			"config": map[string]string{"default_lease_ttl": "45s", "max_lease_ttl": "45s"},
		}, http.StatusNoContent)
	fixture.registerResourceCleanup(t, http.MethodDelete, "/v1/sys/mounts/"+fixture.databaseMount, nil)

	fixture.mustStatus(t, http.MethodPost,
		"/v1/"+fixture.databaseMount+"/config/"+fixture.databaseConnection,
		fixture.rootToken, map[string]any{
			"plugin_name": "postgresql-database-plugin", "allowed_roles": []string{fixture.databaseRole},
			"connection_url": fixture.vaultPostgresURL, "username": fixture.postgres.User,
			"password": fixture.postgres.Password, "verify_connection": true,
		}, http.StatusNoContent)

	databaseName := `"` + fixture.databaseName + `"`
	fixture.mustStatus(t, http.MethodPost,
		"/v1/"+fixture.databaseMount+"/roles/"+fixture.databaseRole,
		fixture.rootToken, map[string]any{
			"db_name": fixture.databaseConnection,
			"creation_statements": []string{
				`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; ` +
					`GRANT CONNECT ON DATABASE ` + databaseName + ` TO "{{name}}";`,
			},
			"revocation_statements": []string{
				`REVOKE CONNECT ON DATABASE ` + databaseName + ` FROM "{{name}}"; DROP ROLE IF EXISTS "{{name}}";`,
			},
			"credential_type": "password", "default_ttl": "45s", "max_ttl": "45s",
		}, http.StatusNoContent)

	fixture.writePolicy(t, fixture.childPolicy,
		`path "`+fixture.databaseMount+`/creds/`+fixture.databaseRole+`" { capabilities = ["read"] }`)
	fixture.writePolicy(t, fixture.managerPolicy,
		`path "auth/token/create/`+fixture.tokenRole+`" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/lookup-accessor" { capabilities = ["update"] }`)
	fixture.writePolicy(t, fixture.revokerPolicy,
		`path "auth/token/revoke-accessor" { capabilities = ["update"] }`)

	fixture.mustStatus(t, http.MethodPost, "/v1/auth/token/roles/"+fixture.tokenRole,
		fixture.rootToken, map[string]any{
			"allowed_policies": []string{fixture.childPolicy}, "disallowed_policies": []string{"default"},
			"orphan": false, "renewable": false, "token_explicit_max_ttl": "15m",
			"token_no_default_policy": true, "token_num_uses": 2, "token_type": "service",
		}, http.StatusNoContent)
	fixture.registerResourceCleanup(t, http.MethodDelete, "/v1/auth/token/roles/"+fixture.tokenRole, nil)

	fixture.mustStatus(t, http.MethodPost, "/v1/sys/mounts/"+fixture.kvMount, fixture.rootToken,
		map[string]any{
			"type": "kv", "options": map[string]string{"version": "1"},
			"config": map[string]string{"default_lease_ttl": "45s", "max_lease_ttl": "45s"},
		}, http.StatusNoContent)
	fixture.registerResourceCleanup(t, http.MethodDelete, "/v1/sys/mounts/"+fixture.kvMount, nil)
	fixture.mustStatus(t, http.MethodPost, "/v1/"+fixture.kvMount+"/"+fixture.kvSecret,
		fixture.rootToken, map[string]string{"value": "kv-empty-lease-canary"}, http.StatusNoContent)
	fixture.writePolicy(t, fixture.kvPolicy,
		`path "`+fixture.kvMount+`/`+fixture.kvSecret+`" { capabilities = ["read"] }`)
}

func (fixture *vault203Fixture) writePolicy(t *testing.T, name, policy string) {
	t.Helper()
	fixture.mustStatus(t, http.MethodPost, "/v1/sys/policies/acl/"+name, fixture.rootToken,
		map[string]string{"policy": policy}, http.StatusNoContent)
	fixture.registerResourceCleanup(t, http.MethodDelete, "/v1/sys/policies/acl/"+name, nil)
}

type integrationSensitive []byte

func (value *integrationSensitive) UnmarshalJSON(encoded []byte) error {
	if value == nil || len(encoded) < 2 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return errors.New("invalid sensitive JSON value")
	}
	plaintext := encoded[1 : len(encoded)-1]
	if (len(plaintext) > 0 && !validIntegrationBearer(plaintext)) || bytes.ContainsRune(plaintext, '\\') ||
		bytes.ContainsRune(plaintext, '"') {
		return errors.New("escaped or invalid sensitive JSON value")
	}
	*value = append((*value)[:0], plaintext...)
	return nil
}

func (value *integrationSensitive) destroy() {
	if value == nil {
		return
	}
	clear(*value)
	*value = nil
}

type integrationEnvelope struct {
	RequestID     string               `json:"request_id"`
	LeaseID       integrationSensitive `json:"lease_id"`
	Renewable     bool                 `json:"renewable"`
	LeaseDuration int64                `json:"lease_duration"`
	Data          json.RawMessage      `json:"data"`
	WrapInfo      json.RawMessage      `json:"wrap_info"`
	Warnings      []string             `json:"warnings"`
	Auth          json.RawMessage      `json:"auth"`
	MountType     string               `json:"mount_type"`
}

func (value *integrationEnvelope) destroy() {
	if value == nil {
		return
	}
	value.LeaseID.destroy()
	clear(value.Data)
	clear(value.WrapInfo)
	clear(value.Auth)
	value.Data, value.WrapInfo, value.Auth = nil, nil, nil
}

type integrationAuth struct {
	ClientToken      integrationSensitive `json:"client_token"`
	Accessor         integrationSensitive `json:"accessor"`
	Policies         []string             `json:"policies"`
	TokenPolicies    []string             `json:"token_policies"`
	IdentityPolicies []string             `json:"identity_policies,omitempty"`
	Metadata         map[string]string    `json:"metadata"`
	LeaseDuration    int64                `json:"lease_duration"`
	Renewable        bool                 `json:"renewable"`
	EntityID         string               `json:"entity_id"`
	TokenType        string               `json:"token_type"`
	Orphan           bool                 `json:"orphan"`
	MFARequirement   json.RawMessage      `json:"mfa_requirement"`
	NumUses          int64                `json:"num_uses"`
}

func (value *integrationAuth) destroy() {
	if value == nil {
		return
	}
	value.ClientToken.destroy()
	value.Accessor.destroy()
	clear(value.MFARequirement)
	value.MFARequirement = nil
}

type integrationLookupData struct {
	ID                        integrationSensitive `json:"id"`
	Accessor                  integrationSensitive `json:"accessor"`
	Policies                  []string             `json:"policies"`
	Path                      string               `json:"path"`
	Meta                      map[string]string    `json:"meta"`
	DisplayName               string               `json:"display_name"`
	NumUses                   int64                `json:"num_uses"`
	Orphan                    bool                 `json:"orphan"`
	CreationTime              int64                `json:"creation_time"`
	CreationTTL               int64                `json:"creation_ttl"`
	ExpireTime                json.RawMessage      `json:"expire_time"`
	TTL                       int64                `json:"ttl"`
	ExplicitMaxTTL            int64                `json:"explicit_max_ttl"`
	EntityID                  string               `json:"entity_id"`
	Type                      string               `json:"type"`
	Role                      string               `json:"role,omitempty"`
	Period                    int64                `json:"period,omitempty"`
	BoundCIDRs                []string             `json:"bound_cidrs,omitempty"`
	NamespacePath             string               `json:"namespace_path,omitempty"`
	Renewable                 bool                 `json:"renewable"`
	IssueTime                 json.RawMessage      `json:"issue_time"`
	LastRenewalTime           int64                `json:"last_renewal_time,omitempty"`
	LastRenewal               json.RawMessage      `json:"last_renewal,omitempty"`
	IdentityPolicies          []string             `json:"identity_policies,omitempty"`
	ExternalNamespacePolicies map[string][]string  `json:"external_namespace_policies,omitempty"`
}

func (value *integrationLookupData) destroy() {
	if value == nil {
		return
	}
	value.ID.destroy()
	value.Accessor.destroy()
	clear(value.ExpireTime)
	clear(value.IssueTime)
	clear(value.LastRenewal)
	value.ExpireTime, value.IssueTime, value.LastRenewal = nil, nil, nil
}

type integrationErrorEnvelope struct {
	Errors []string `json:"errors"`
}

type integrationTokenExpectation struct {
	policies      []string
	metadata      map[string]string
	warnings      []string
	orphan        bool
	numUses       int64
	entityID      string
	requireEntity bool
}

func (fixture *vault203Fixture) createToken(
	t *testing.T,
	parentToken []byte,
	path string,
	payload map[string]any,
	expected integrationTokenExpectation,
) *integrationToken {
	t.Helper()
	response := fixture.mustCall(t, http.MethodPost, path, parentToken, payload)
	defer response.destroy()
	if response.status != http.StatusOK {
		t.Fatalf("Vault token creation returned status %d", response.status)
	}
	return decodeIntegrationToken(t, response.body, expected)
}

func decodeIntegrationToken(
	t *testing.T,
	body []byte,
	expected integrationTokenExpectation,
) *integrationToken {
	t.Helper()
	var envelope integrationEnvelope
	if err := decodeIntegrationJSON(body, &envelope, integrationEnvelopeFields); err != nil ||
		!validIntegrationIdentifier(envelope.RequestID, 256) || len(envelope.LeaseID) != 0 || envelope.Renewable ||
		envelope.LeaseDuration != 0 || !integrationJSONNull(envelope.Data) || !integrationJSONNull(envelope.WrapInfo) ||
		!slices.Equal(envelope.Warnings, expected.warnings) || !integrationJSONObject(envelope.Auth) ||
		envelope.MountType != "token" {
		envelope.destroy()
		t.Fatal("Vault token creation returned an invalid strict envelope")
	}
	defer envelope.destroy()
	var auth integrationAuth
	if err := decodeIntegrationJSON(envelope.Auth, &auth, integrationAuthFields); err != nil ||
		!validIntegrationBearer(auth.ClientToken) || !validIntegrationBearer(auth.Accessor) ||
		bytes.Equal(auth.ClientToken, auth.Accessor) || !exactIntegrationStringSet(auth.Policies, expected.policies) ||
		!exactIntegrationStringSet(auth.TokenPolicies, expected.policies) || len(auth.IdentityPolicies) != 0 ||
		!maps.Equal(auth.Metadata, expected.metadata) || auth.LeaseDuration <= 0 || auth.Renewable ||
		auth.TokenType != "service" || auth.Orphan != expected.orphan || !integrationJSONNull(auth.MFARequirement) ||
		auth.NumUses != expected.numUses || (!expected.requireEntity && auth.EntityID != expected.entityID) ||
		(expected.requireEntity && auth.EntityID == "") {
		auth.destroy()
		t.Fatal("Vault token creation returned invalid service-token semantics")
	}
	defer auth.destroy()
	return &integrationToken{
		token: append([]byte(nil), auth.ClientToken...), accessor: append([]byte(nil), auth.Accessor...),
		entityID: auth.EntityID, orphan: auth.Orphan, numUses: auth.NumUses,
	}
}

func (fixture *vault203Fixture) mustStatus(
	t *testing.T,
	method, path string,
	token []byte,
	payload any,
	expected int,
) {
	t.Helper()
	response := fixture.mustCall(t, method, path, token, payload)
	defer response.destroy()
	if response.status != expected {
		t.Fatalf("Vault fixture request returned status %d, want %d", response.status, expected)
	}
}

func (fixture *vault203Fixture) mustCall(
	t *testing.T,
	method, path string,
	token []byte,
	payload any,
) *integrationResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), integrationRequestTimeout)
	defer cancel()
	response, err := fixture.raw.call(ctx, method, path, token, payload)
	if err != nil {
		t.Fatal("Vault integration request failed without exposing its bearer or body")
	}
	return response
}

func (fixture *vault203Fixture) registerResourceCleanup(t *testing.T, method, path string, payload any) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), integrationRequestTimeout)
		defer cancel()
		response, err := fixture.raw.call(ctx, method, path, fixture.rootToken, payload)
		if err != nil {
			t.Errorf("Vault fixture resource cleanup failed")
			return
		}
		defer response.destroy()
		if response.status != http.StatusNoContent {
			t.Errorf("Vault fixture resource cleanup returned status %d, want 204", response.status)
		}
	})
}

func (fixture *vault203Fixture) registerTokenCleanup(t *testing.T, accessor []byte) {
	t.Helper()
	ownedAccessor := append([]byte(nil), accessor...)
	t.Cleanup(func() {
		defer clear(ownedAccessor)
		ctx, cancel := context.WithTimeout(context.Background(), integrationRequestTimeout)
		defer cancel()
		response, err := fixture.raw.call(ctx, http.MethodPost, "/v1/auth/token/revoke-accessor",
			fixture.rootToken, map[string]string{"accessor": string(ownedAccessor)})
		if err != nil {
			t.Errorf("Vault token cleanup failed")
			return
		}
		defer response.destroy()
		switch response.status {
		case http.StatusNoContent:
			return
		case http.StatusOK:
			if !integrationAbsentRevokeResponse(response.body) {
				t.Errorf("Vault idempotent token cleanup returned invalid semantics")
			}
		default:
			t.Errorf("Vault token cleanup returned status %d", response.status)
		}
	})
}

func integrationAbsentRevokeResponse(body []byte) bool {
	var envelope integrationEnvelope
	if err := decodeIntegrationJSON(body, &envelope, integrationEnvelopeFields); err != nil {
		envelope.destroy()
		return false
	}
	defer envelope.destroy()
	return validIntegrationIdentifier(envelope.RequestID, 256) && len(envelope.LeaseID) == 0 &&
		!envelope.Renewable && envelope.LeaseDuration == 0 && integrationJSONNull(envelope.Data) &&
		integrationJSONNull(envelope.WrapInfo) && integrationJSONNull(envelope.Auth) && envelope.MountType == "token" &&
		len(envelope.Warnings) == 1 && envelope.Warnings[0] == "No token found with this accessor"
}

func (client *integrationVaultHTTPClient) call(
	ctx context.Context,
	method, path string,
	token []byte,
	payload any,
) (*integrationResponse, error) {
	if ctx == nil || !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#") ||
		!validIntegrationBearer(token) {
		return nil, errors.New("invalid Vault integration request")
	}
	endpoint := client.baseURL
	endpoint.Path = path
	endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "", "", ""
	var encoded []byte
	var requestBody io.Reader = http.NoBody
	if payload != nil {
		var err error
		encoded, err = json.Marshal(payload)
		if err != nil || len(encoded) > integrationBodyLimit {
			clear(encoded)
			return nil, errors.New("invalid Vault integration payload")
		}
		requestBody = bytes.NewReader(encoded)
	}
	defer clear(encoded)
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return nil, errors.New("invalid Vault integration request")
	}
	request.Close = true
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("X-Vault-Token", string(token))
	response, err := client.client.Do(request)
	request.Header.Del("X-Vault-Token")
	if response != nil && response.Request != nil {
		response.Request.Header.Del("X-Vault-Token")
	}
	if err != nil {
		return nil, errors.New("Vault integration transport failure")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, integrationBodyLimit+1))
	if err != nil || len(body) > integrationBodyLimit {
		clear(body)
		return nil, errors.New("Vault integration response exceeded its bound")
	}
	if len(body) > 0 {
		mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" {
			clear(body)
			return nil, errors.New("Vault integration response was not JSON")
		}
	}
	return &integrationResponse{status: response.StatusCode, body: body}, nil
}

func validIntegrationBearer(value []byte) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func decodeIntegrationJSON(data []byte, destination any, required []string) error {
	if len(data) == 0 || len(data) > integrationBodyLimit || rejectIntegrationDuplicateKeys(data) != nil {
		return errors.New("invalid strict Vault JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid strict Vault JSON")
	}
	if err := integrationJSONEOF(decoder); err != nil {
		return errors.New("invalid strict Vault JSON")
	}
	if len(required) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.New("invalid strict Vault JSON object")
	}
	defer destroyIntegrationRawMap(fields)
	for _, field := range required {
		if _, present := fields[field]; !present {
			return errors.New("missing strict Vault JSON field")
		}
	}
	return nil
}

func rejectIntegrationDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanIntegrationJSONValue(decoder, 0); err != nil {
		return err
	}
	return integrationJSONEOF(decoder)
}

func scanIntegrationJSONValue(decoder *json.Decoder, depth int) error {
	if depth > integrationJSONDepth {
		return errors.New("Vault JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid Vault JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate Vault JSON object key")
			}
			seen[key] = struct{}{}
			if err := scanIntegrationJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid Vault JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanIntegrationJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid Vault JSON array")
		}
	default:
		return errors.New("invalid Vault JSON delimiter")
	}
	return nil
}

func integrationJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple Vault JSON values")
		}
		return err
	}
	return nil
}

func destroyIntegrationRawMap(fields map[string]json.RawMessage) {
	for key, value := range fields {
		clear(value)
		delete(fields, key)
	}
}

func integrationJSONNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func integrationJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func validIntegrationIdentifier(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func exactIntegrationStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualCopy, expectedCopy := slices.Clone(actual), slices.Clone(expected)
	slices.Sort(actualCopy)
	slices.Sort(expectedCopy)
	return slices.Equal(actualCopy, expectedCopy)
}

func decodeIntegrationError(body []byte, expected string) bool {
	var response integrationErrorEnvelope
	return decodeIntegrationJSON(body, &response, []string{"errors"}) == nil &&
		len(response.Errors) == 1 && response.Errors[0] == expected
}

func newIntegrationTLSProxy(
	t *testing.T,
	target *url.URL,
	allowed map[string]struct{},
) *integrationTLSProxy {
	t.Helper()
	caCertificate, serverCertificate, caPEM := integrationTestCertificates(t)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 || request.ProtoMajor != 1 ||
			!request.Close || request.URL.RawQuery != "" {
			http.Error(writer, "invalid proxy transport", http.StatusBadRequest)
			return
		}
		if _, ok := allowed[request.Method+" "+request.URL.Path]; !ok {
			http.Error(writer, "proxy path denied", http.StatusForbidden)
			return
		}
		proxyIntegrationVaultRequest(writer, request, target)
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	proxy := &integrationTLSProxy{server: server, caPEM: caPEM}
	t.Cleanup(func() {
		server.Close()
		clear(proxy.caPEM)
		proxy.caPEM = nil
	})
	_ = caCertificate
	return proxy
}

func integrationTestCertificates(t *testing.T) (*x509.Certificate, tls.Certificate, []byte) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not generate test-only Vault proxy CA key")
	}
	caTemplate := &x509.Certificate{
		SerialNumber: integrationCertificateSerial(t),
		Subject:      pkix.Name{CommonName: "AIOps Vault integration test CA"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("could not issue test-only Vault proxy CA")
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal("could not parse test-only Vault proxy CA")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not generate test-only Vault proxy server key")
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: integrationCertificateSerial(t),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("could not issue test-only Vault proxy server certificate")
	}
	serverCertificate := tls.Certificate{
		Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey,
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if len(caPEM) == 0 {
		t.Fatal("could not encode test-only Vault proxy CA")
	}
	return caCertificate, serverCertificate, caPEM
}

func integrationCertificateSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() <= 0 {
		t.Fatal("could not generate test-only certificate serial")
	}
	return serial
}

func proxyIntegrationVaultRequest(writer http.ResponseWriter, inbound *http.Request, target *url.URL) {
	requestBody, err := io.ReadAll(io.LimitReader(inbound.Body, integrationBodyLimit+1))
	if err != nil || len(requestBody) > integrationBodyLimit {
		clear(requestBody)
		http.Error(writer, "proxy request bound exceeded", http.StatusRequestEntityTooLarge)
		return
	}
	defer clear(requestBody)
	token := []byte(inbound.Header.Get("X-Vault-Token"))
	inbound.Header.Del("X-Vault-Token")
	defer clear(token)
	if !validIntegrationBearer(token) || inbound.Header.Get("X-Vault-Namespace") != "" {
		http.Error(writer, "proxy bearer rejected", http.StatusUnauthorized)
		return
	}
	endpoint := *target
	endpoint.Path = inbound.URL.Path
	endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "", "", ""
	var body io.Reader = http.NoBody
	if len(requestBody) > 0 {
		body = bytes.NewReader(requestBody)
	}
	request, err := http.NewRequestWithContext(inbound.Context(), inbound.Method, endpoint.String(), body)
	if err != nil {
		http.Error(writer, "proxy request rejected", http.StatusBadGateway)
		return
	}
	request.Close = true
	request.GetBody = nil
	request.ContentLength = int64(len(requestBody))
	request.Header.Set("Accept", "application/json")
	if contentType := inbound.Header.Get("Content-Type"); contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("X-Vault-Token", string(token))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true, DisableCompression: true,
		ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols: protocols, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: integrationRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	request.Header.Del("X-Vault-Token")
	if response != nil && response.Request != nil {
		response.Request.Header.Del("X-Vault-Token")
	}
	if err != nil {
		http.Error(writer, "proxy upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, integrationBodyLimit+1))
	if err != nil || len(responseBody) > integrationBodyLimit {
		clear(responseBody)
		http.Error(writer, "proxy response bound exceeded", http.StatusBadGateway)
		return
	}
	defer clear(responseBody)
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	if cacheControl := response.Header.Get("Cache-Control"); cacheControl != "" {
		writer.Header().Set("Cache-Control", cacheControl)
	}
	writer.WriteHeader(response.StatusCode)
	if len(responseBody) > 0 {
		_, _ = writer.Write(responseBody)
	}
}

func (fixture *vault203Fixture) lookupAccessor(t *testing.T, accessor []byte) (integrationLookup, bool) {
	t.Helper()
	response := fixture.mustCall(t, http.MethodPost, "/v1/auth/token/lookup-accessor", fixture.rootToken,
		map[string]string{"accessor": string(accessor)})
	defer response.destroy()
	if response.status == http.StatusBadRequest {
		if !decodeIntegrationError(response.body, integrationInvalidAccessorRouteError) {
			t.Fatal("Vault accessor lookup returned unsafe 400 semantics")
		}
		return integrationLookup{}, false
	}
	if response.status != http.StatusOK {
		t.Fatalf("Vault accessor lookup returned status %d", response.status)
	}
	return decodeIntegrationLookup(t, response.body, accessor), true
}

func decodeIntegrationLookup(t *testing.T, body, expectedAccessor []byte) integrationLookup {
	t.Helper()
	var envelope integrationEnvelope
	if err := decodeIntegrationJSON(body, &envelope, integrationEnvelopeFields); err != nil ||
		!validIntegrationIdentifier(envelope.RequestID, 256) || len(envelope.LeaseID) != 0 || envelope.Renewable ||
		envelope.LeaseDuration != 0 || !integrationJSONObject(envelope.Data) ||
		!integrationJSONNull(envelope.WrapInfo) || len(envelope.Warnings) != 0 ||
		!integrationJSONNull(envelope.Auth) || envelope.MountType != "token" {
		envelope.destroy()
		t.Fatal("Vault accessor lookup returned an invalid strict envelope")
	}
	defer envelope.destroy()
	var data integrationLookupData
	if err := decodeIntegrationJSON(envelope.Data, &data, integrationLookupFields); err != nil ||
		len(data.ID) != 0 || !bytes.Equal(data.Accessor, expectedAccessor) || data.Type != "service" {
		data.destroy()
		t.Fatal("Vault accessor lookup returned invalid token data")
	}
	defer data.destroy()
	return integrationLookup{
		numUses: data.NumUses, entityID: data.EntityID, orphan: data.Orphan,
		policies: slices.Clone(data.Policies), role: data.Role, metadata: maps.Clone(data.Meta),
	}
}

func (fixture *vault203Fixture) assertAccessorMissing(t *testing.T, accessor []byte) {
	t.Helper()
	fixture.eventually(t, func() bool {
		response := fixture.mustCall(t, http.MethodPost, "/v1/auth/token/lookup-accessor", fixture.rootToken,
			map[string]string{"accessor": string(accessor)})
		defer response.destroy()
		switch response.status {
		case http.StatusOK:
			_ = decodeIntegrationLookup(t, response.body, accessor)
			fixture.assertRootAvailable(t)
			return false
		case http.StatusBadRequest:
			if !decodeIntegrationError(response.body, integrationInvalidAccessorRouteError) {
				t.Fatal("Vault accessor missing response had unsafe error semantics")
			}
			fixture.assertRootAvailable(t)
			return true
		case http.StatusForbidden:
			// A transient authorization response is never accepted as
			// revocation evidence. Prove the root token is still valid and
			// continue polling until Vault returns the exact missing-accessor
			// semantics or the bounded assertion times out.
			fixture.assertRootAvailable(t)
			return false
		default:
			t.Fatalf("Vault accessor missing check returned status %d; only exact 400 is revocation evidence", response.status)
			return false
		}
	}, "Vault accessor remained valid after revocation")
}

func (fixture *vault203Fixture) assertLeaseExists(t *testing.T, leaseID []byte) {
	t.Helper()
	response := fixture.mustCall(t, http.MethodPost, "/v1/sys/leases/lookup", fixture.rootToken,
		map[string]string{"lease_id": string(leaseID)})
	defer response.destroy()
	if response.status != http.StatusOK {
		t.Fatalf("Vault lease lookup returned status %d, want 200", response.status)
	}
	fixture.assertRootAvailable(t)
}

func (fixture *vault203Fixture) assertLeaseMissing(t *testing.T, leaseID []byte) {
	t.Helper()
	fixture.eventually(t, func() bool {
		response := fixture.mustCall(t, http.MethodPost, "/v1/sys/leases/lookup", fixture.rootToken,
			map[string]string{"lease_id": string(leaseID)})
		defer response.destroy()
		switch response.status {
		case http.StatusOK:
			fixture.assertRootAvailable(t)
			return false
		case http.StatusBadRequest:
			if !decodeIntegrationError(response.body, "invalid lease") {
				t.Fatal("Vault lease missing response had unsafe error semantics")
			}
			fixture.assertRootAvailable(t)
			return true
		case http.StatusForbidden:
			fixture.assertRootAvailable(t)
			return false
		default:
			t.Fatalf("Vault lease missing check returned status %d; only exact 400 is revocation evidence", response.status)
			return false
		}
	}, "Vault lease remained valid after token revocation")
}

func (fixture *vault203Fixture) assertRootAvailable(t *testing.T) {
	t.Helper()
	response := fixture.mustCall(t, http.MethodGet, "/v1/auth/token/lookup-self", fixture.rootToken, nil)
	defer response.destroy()
	if response.status != http.StatusOK {
		t.Fatalf("Vault root lookup-self returned status %d during revocation verification", response.status)
	}
}

func (fixture *vault203Fixture) revokeAccessorRaw(t *testing.T, accessor []byte) {
	t.Helper()
	response := fixture.mustCall(t, http.MethodPost, "/v1/auth/token/revoke-accessor", fixture.rootToken,
		map[string]string{"accessor": string(accessor)})
	defer response.destroy()
	if response.status != http.StatusNoContent {
		t.Fatalf("Vault accessor revocation returned status %d, want 204", response.status)
	}
}

func (fixture *vault203Fixture) eventually(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(integrationPollTimeout)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type integrationDatabaseData struct {
	Username string               `json:"username"`
	Password integrationSensitive `json:"password"`
}

func (fixture *vault203Fixture) createDatabaseChild(
	t *testing.T,
	parent *integrationToken,
	numUses int64,
) *integrationToken {
	t.Helper()
	child := fixture.createToken(t, parent.token, "/v1/auth/token/create/"+fixture.tokenRole, map[string]any{
		"policies": []string{fixture.childPolicy}, "ttl": "2m", "explicit_max_ttl": "2m",
		"no_default_policy": true, "display_name": "aiops-job", "num_uses": numUses,
		"renewable": false, "type": "service", "meta": fixture.profileMetadata,
	}, integrationTokenExpectation{
		policies: []string{fixture.childPolicy}, metadata: fixture.profileMetadata,
		warnings: []string{"Explicit max TTL specified both during creation call and in role; using the lesser value of 120 seconds"},
		orphan:   false, numUses: numUses, entityID: parent.entityID,
	})
	t.Cleanup(child.destroy)
	fixture.registerTokenCleanup(t, child.accessor)
	lookup, found := fixture.lookupAccessor(t, child.accessor)
	if !found || lookup.numUses != numUses || lookup.entityID != parent.entityID || lookup.orphan ||
		!exactIntegrationStringSet(lookup.policies, []string{fixture.childPolicy}) ||
		lookup.role != fixture.tokenRole || !maps.Equal(lookup.metadata, fixture.profileMetadata) {
		t.Fatal("created database child did not preserve its bounded role, policy, metadata, use count, and identity")
	}
	return child
}

func (fixture *vault203Fixture) issueRawDatabaseCredential(
	t *testing.T,
	token []byte,
) *integrationDatabaseCredential {
	t.Helper()
	response := fixture.mustCall(t, http.MethodGet,
		"/v1/"+fixture.databaseMount+"/creds/"+fixture.databaseRole, token, nil)
	defer response.destroy()
	if response.status != http.StatusOK {
		t.Fatalf("Vault dynamic database issuance returned status %d", response.status)
	}
	var envelope integrationEnvelope
	if err := decodeIntegrationJSON(response.body, &envelope, integrationEnvelopeFields); err != nil ||
		!validIntegrationIdentifier(envelope.RequestID, 256) || !validIntegrationBearer(envelope.LeaseID) ||
		!envelope.Renewable || envelope.LeaseDuration <= 0 || envelope.LeaseDuration > 45 ||
		!integrationJSONObject(envelope.Data) || !integrationJSONNull(envelope.WrapInfo) ||
		len(envelope.Warnings) != 0 || !integrationJSONNull(envelope.Auth) || envelope.MountType != "database" {
		envelope.destroy()
		t.Fatal("Vault dynamic database issuance returned invalid leased-secret semantics")
	}
	defer envelope.destroy()
	var data integrationDatabaseData
	if err := decodeIntegrationJSON(envelope.Data, &data, []string{"username", "password"}); err != nil ||
		data.Username == "" || !validIntegrationBearer(data.Password) {
		data.Password.destroy()
		t.Fatal("Vault dynamic database issuance returned invalid credential data")
	}
	defer data.Password.destroy()
	return &integrationDatabaseCredential{
		username: data.Username, password: append([]byte(nil), data.Password...),
		leaseID: append([]byte(nil), envelope.LeaseID...), renewable: envelope.Renewable,
	}
}

func (fixture *vault203Fixture) proveOneUseCannotReturnLeasedSecret(t *testing.T) {
	t.Helper()
	child := fixture.createDatabaseChild(t, fixture.manager, 1)
	response := fixture.mustCall(t, http.MethodGet,
		"/v1/"+fixture.databaseMount+"/creds/"+fixture.databaseRole, child.token, nil)
	defer response.destroy()
	if response.status != http.StatusBadRequest || !decodeIntegrationError(response.body,
		"Secret cannot be returned; token had one use left, so leased credentials were immediately revoked.") {
		t.Fatalf("one-use leased-secret request returned status %d without exact final-use semantics", response.status)
	}
	fixture.assertAccessorMissing(t, child.accessor)
}

func (fixture *vault203Fixture) proveTwoUsesReturnExactlyOneLeasedSecret(t *testing.T) {
	t.Helper()
	child := fixture.createDatabaseChild(t, fixture.manager, 2)
	issued := fixture.issueRawDatabaseCredential(t, child.token)
	defer issued.destroy()
	fixture.assertDatabaseCredentialWorks(t, issued)
	fixture.assertLeaseExists(t, issued.leaseID)
	lookup, found := fixture.lookupAccessor(t, child.accessor)
	if !found || lookup.numUses != 1 {
		t.Fatal("two-use child did not retain exactly one use after its first dynamic issuance")
	}
	response := fixture.mustCall(t, http.MethodGet,
		"/v1/"+fixture.databaseMount+"/creds/"+fixture.databaseRole, child.token, nil)
	defer response.destroy()
	if response.status != http.StatusBadRequest || !decodeIntegrationError(response.body,
		"Secret cannot be returned; token had one use left, so leased credentials were immediately revoked.") {
		t.Fatalf("second two-use leased-secret request returned status %d without exact final-use semantics", response.status)
	}
	fixture.assertAccessorMissing(t, child.accessor)
	fixture.assertLeaseMissing(t, issued.leaseID)
	fixture.assertDatabaseCredentialRejected(t, issued)
}

func (fixture *vault203Fixture) proveRenewableLeaseCannotBeRenewed(t *testing.T) {
	t.Helper()
	child := fixture.createDatabaseChild(t, fixture.manager, 2)
	issued := fixture.issueRawDatabaseCredential(t, child.token)
	defer issued.destroy()
	if !issued.renewable {
		t.Fatal("Vault PostgreSQL dynamic credential was not marked renewable")
	}
	fixture.assertDatabaseCredentialWorks(t, issued)
	response := fixture.mustCall(t, http.MethodPost, "/v1/sys/leases/renew", child.token,
		map[string]any{"lease_id": string(issued.leaseID), "increment": 60})
	defer response.destroy()
	if response.status != http.StatusForbidden || !validIntegrationErrorEnvelope(response.body) {
		t.Fatalf("narrow child lease renewal returned status %d without a strict denial", response.status)
	}
	fixture.assertAccessorMissing(t, child.accessor)
	fixture.assertLeaseMissing(t, issued.leaseID)
	fixture.assertDatabaseCredentialRejected(t, issued)
}

func (fixture *vault203Fixture) proveParentAccessorCascade(t *testing.T) {
	t.Helper()
	child := fixture.createDatabaseChild(t, fixture.manager, 2)
	issued := fixture.issueRawDatabaseCredential(t, child.token)
	defer issued.destroy()
	fixture.assertDatabaseCredentialWorks(t, issued)
	fixture.assertLeaseExists(t, issued.leaseID)
	fixture.revokeAccessorRaw(t, fixture.manager.accessor)
	fixture.assertAccessorMissing(t, fixture.manager.accessor)
	fixture.assertAccessorMissing(t, child.accessor)
	fixture.assertLeaseMissing(t, issued.leaseID)
	fixture.assertDatabaseCredentialRejected(t, issued)
}

func validIntegrationErrorEnvelope(body []byte) bool {
	var response integrationErrorEnvelope
	if decodeIntegrationJSON(body, &response, []string{"errors"}) != nil || len(response.Errors) != 1 {
		return false
	}
	errorText := response.Errors[0]
	return errorText != "" && strings.TrimSpace(errorText) != "" && !strings.ContainsFunc(errorText, func(value rune) bool {
		return unicode.IsControl(value) && value != '\n' && value != '\r' && value != '\t'
	})
}

func (fixture *vault203Fixture) assertDatabaseCredentialWorks(
	t *testing.T,
	value *integrationDatabaseCredential,
) {
	t.Helper()
	if !fixture.databaseCredentialWorks(value) {
		t.Fatal("Vault dynamic database credential could not establish and query a PostgreSQL connection")
	}
}

func (fixture *vault203Fixture) databaseCredentialWorks(value *integrationDatabaseCredential) bool {
	config := fixture.postgres.Copy()
	config.User = value.username
	config.Password = string(value.password)
	defer func() { config.Password = "" }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return false
	}
	defer connection.Close(context.Background())
	var one int
	return connection.QueryRow(ctx, "SELECT 1").Scan(&one) == nil && one == 1
}

func (fixture *vault203Fixture) rootDatabaseWorks() bool {
	config := fixture.postgres.Copy()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return false
	}
	defer connection.Close(context.Background())
	var one int
	return connection.QueryRow(ctx, "SELECT 1").Scan(&one) == nil && one == 1
}

func (fixture *vault203Fixture) assertDatabaseCredentialRejected(
	t *testing.T,
	value *integrationDatabaseCredential,
) {
	t.Helper()
	fixture.eventually(t, func() bool {
		return !fixture.databaseCredentialWorks(value) && fixture.rootDatabaseWorks()
	}, "revoked Vault database credential remained usable while PostgreSQL stayed healthy")
}

func (fixture *vault203Fixture) proveProductionClientClosure(t *testing.T) {
	t.Helper()
	managerCtx, managerCancel := integrationOperationContext()
	managerErr := fixture.issuer.ValidateManager(managerCtx)
	managerCancel()
	if managerErr != nil {
		t.Fatal("production Vault client rejected the real entity-free orphan manager")
	}
	authorizedAt := credential.CanonicalCredentialExpiry(time.Now().UTC())
	deadline := credential.CanonicalCredentialExpiry(authorizedAt.Add(3 * time.Minute))
	createRequest := credential.DurableChildCreateRequest{
		RevocationID: fixture.revocationID("10000000"), ProfileRevision: fixture.profileRevision,
		DatabaseAuthorizedAt: authorizedAt, TTL: 2 * time.Minute, CredentialExpiresAt: deadline,
	}
	createCtx, createCancel := integrationOperationContext()
	child, err := fixture.issuer.CreateChild(createCtx, createRequest)
	createCancel()
	var accessor []byte
	defer clear(accessor)
	if child.Accessor != nil {
		accessor = child.Accessor.Bytes()
		fixture.registerTokenCleanup(t, accessor)
	}
	childTokenBytes := child.Token.Bytes()
	childTokenPresent := len(childTokenBytes) > 0
	clear(childTokenBytes)
	if err != nil || child.Accessor == nil || !childTokenPresent ||
		!child.ExpiresAt.After(authorizedAt) || child.ExpiresAt.After(deadline) {
		child.Token.Destroy()
		if child.Accessor != nil {
			child.Accessor.Destroy()
		}
		t.Fatal("production Vault client could not create a bounded real child token")
	}
	defer child.Token.Destroy()
	defer child.Accessor.Destroy()
	inspectCtx, inspectCancel := integrationOperationContext()
	inspectErr := fixture.issuer.InspectChild(inspectCtx, child.Accessor, credential.DurableChildInspectionRequest{
		RevocationID: createRequest.RevocationID, ProfileRevision: fixture.profileRevision,
		CredentialExpiresAt: deadline, ExpectedTTL: 2 * time.Minute,
	})
	inspectCancel()
	if inspectErr != nil {
		t.Fatal("production Vault client rejected its real metadata-bound child during lookup-accessor inspection")
	}
	issueCtx, issueCancel := integrationOperationContext()
	dynamic, err := fixture.issuer.IssueDynamic(issueCtx, child.Token, credential.DurableDynamicIssueRequest{
		RevocationID: createRequest.RevocationID, ProfileRevision: fixture.profileRevision,
		CredentialExpiresAt: deadline,
	})
	issueCancel()
	if err != nil || !dynamic.ExpiresAt.After(time.Now().UTC()) || dynamic.ExpiresAt.After(deadline) ||
		dynamic.ExpiresAt.After(child.ExpiresAt) {
		dynamic.Secret.Destroy()
		t.Fatal("production Vault client could not issue a bounded real PostgreSQL credential")
	}
	defer dynamic.Secret.Destroy()
	secretBytes := dynamic.Secret.Bytes()
	defer clear(secretBytes)
	var data integrationDatabaseData
	if err := decodeIntegrationJSON(secretBytes, &data, []string{"username", "password"}); err != nil ||
		data.Username == "" || !validIntegrationBearer(data.Password) {
		data.Password.destroy()
		t.Fatal("production Vault client returned invalid allowlisted PostgreSQL credential data")
	}
	defer data.Password.destroy()
	issued := &integrationDatabaseCredential{
		username: data.Username,
		password: append([]byte(nil), data.Password...),
	}
	defer issued.destroy()
	fixture.assertDatabaseCredentialWorks(t, issued)
	if fixture.revokerSource.requests.Load() != 0 {
		t.Fatal("production Vault issuer client acquired the revoker TokenSource")
	}
	managerRequests := fixture.managerSource.requests.Load()
	revokeCtx, revokeCancel := integrationOperationContext()
	revokeErr := fixture.revocation.RevokeAccessor(revokeCtx, child.Accessor)
	revokeCancel()
	if revokeErr != nil {
		t.Fatal("production Vault client could not revoke its real child by independent revoker accessor")
	}
	confirmCtx, confirmCancel := integrationOperationContext()
	confirmErr := fixture.revocation.RevokeAccessor(confirmCtx, child.Accessor)
	confirmCancel()
	if confirmErr != nil {
		t.Fatal("production Vault client did not idempotently confirm an already revoked accessor")
	}
	if fixture.managerSource.requests.Load() != managerRequests || fixture.revokerSource.requests.Load() != 2 {
		t.Fatal("production Vault revocation client crossed the manager/revoker TokenSource boundary")
	}
	fixture.assertAccessorMissing(t, accessor)
	fixture.assertDatabaseCredentialRejected(t, issued)
}

func integrationOperationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), integrationRequestTimeout)
}

func (fixture *vault203Fixture) proveEmptyLeaseRejected(t *testing.T) {
	t.Helper()
	kvToken := fixture.createToken(t, fixture.rootToken, "/v1/auth/token/create-orphan", map[string]any{
		"policies": []string{fixture.kvPolicy}, "ttl": "2m", "explicit_max_ttl": "2m",
		"no_default_policy": true, "display_name": "aiops-kv-child", "num_uses": 2,
		"renewable": false, "type": "service",
	}, integrationTokenExpectation{policies: []string{fixture.kvPolicy}, orphan: true, numUses: 2})
	t.Cleanup(kvToken.destroy)
	fixture.registerTokenCleanup(t, kvToken.accessor)
	fixture.assertRawKVEmptyLease(t, kvToken.token)
	lookup, found := fixture.lookupAccessor(t, kvToken.accessor)
	if !found || lookup.numUses != 1 {
		t.Fatal("real KV child did not retain exactly one use after its first static read")
	}
	kvProfileID := "vault-kv-" + fixture.suffix
	kvRevision := "kv-rev-" + fixture.suffix
	kvProfile, err := vaultclient.NewProfile(vaultclient.ProfileConfig{
		IssuerID: kvProfileID, Revision: kvRevision,
		Address: fixture.proxy.server.URL, ServerName: "127.0.0.1", CAPEM: fixture.proxy.caPEM,
		ManagerPolicy: fixture.managerPolicy, TokenRole: fixture.tokenRole, ChildPolicy: fixture.kvPolicy,
		DynamicPath: fixture.kvMount + "/" + fixture.kvSecret, MountType: "kv",
		Metadata:     map[string]string{"profile": kvProfileID, "revision": kvRevision},
		SecretFields: []vaultclient.SecretField{{Name: "value", MaxBytes: 256}},
	})
	if err != nil {
		t.Fatal("could not construct the real KV empty-lease profile")
	}
	kvClient, err := vaultclient.NewIssuerClient(kvProfile,
		&integrationTokenSource{sourceID: "kv-manager-src-" + fixture.suffix, token: fixture.manager.token})
	if err != nil {
		t.Fatal("could not construct the real KV empty-lease client")
	}
	childToken, err := credential.NewSensitiveValue(kvToken.token)
	if err != nil {
		t.Fatal("could not wrap the real KV child token")
	}
	defer childToken.Destroy()
	deadline := credential.CanonicalCredentialExpiry(time.Now().UTC().Add(2 * time.Minute))
	result, issueErr := kvClient.IssueDynamic(context.Background(), childToken, credential.DurableDynamicIssueRequest{
		RevocationID: fixture.revocationID("20000000"), ProfileRevision: kvRevision,
		CredentialExpiresAt: deadline,
	})
	defer result.Secret.Destroy()
	resultBytes := result.Secret.Bytes()
	defer clear(resultBytes)
	var clientError *vaultclient.ClientError
	if issueErr == nil || !errors.As(issueErr, &clientError) || clientError.Operation != "issue_dynamic" ||
		clientError.Class != vaultclient.ErrorProtocol || !clientError.Ambiguous || len(resultBytes) != 0 {
		t.Fatal("production Vault client did not reject the real KV response with an empty lease ID")
	}
	fixture.assertAccessorMissing(t, kvToken.accessor)
}

func (fixture *vault203Fixture) assertRawKVEmptyLease(t *testing.T, token []byte) {
	t.Helper()
	response := fixture.mustCall(t, http.MethodGet, "/v1/"+fixture.kvMount+"/"+fixture.kvSecret, token, nil)
	defer response.destroy()
	if response.status != http.StatusOK {
		t.Fatalf("real KV v1 read returned status %d", response.status)
	}
	var envelope integrationEnvelope
	if err := decodeIntegrationJSON(response.body, &envelope, integrationEnvelopeFields); err != nil ||
		!validIntegrationIdentifier(envelope.RequestID, 256) || len(envelope.LeaseID) != 0 || envelope.Renewable ||
		envelope.LeaseDuration <= 0 || envelope.LeaseDuration > 45 || !integrationJSONObject(envelope.Data) ||
		!integrationJSONNull(envelope.WrapInfo) || len(envelope.Warnings) != 0 ||
		!integrationJSONNull(envelope.Auth) || envelope.MountType != "kv" {
		envelope.destroy()
		t.Fatal("real KV v1 response did not isolate a bounded empty-lease condition")
	}
	defer envelope.destroy()
	var data struct {
		Value string `json:"value"`
	}
	if err := decodeIntegrationJSON(envelope.Data, &data, []string{"value"}); err != nil ||
		data.Value != "kv-empty-lease-canary" {
		t.Fatal("real KV v1 response data did not match the fixed test canary")
	}
}

func (fixture *vault203Fixture) proveEntityContaminationRejected(t *testing.T) {
	t.Helper()
	roleResponse := fixture.mustCall(t, http.MethodPost,
		"/v1/auth/token/roles/"+fixture.entityManagerRole, fixture.rootToken, map[string]any{
			"allowed_policies": []string{fixture.managerPolicy}, "disallowed_policies": []string{"default"},
			"allowed_entity_aliases": []string{fixture.entityAlias}, "orphan": false, "renewable": false,
			"token_explicit_max_ttl": "5m", "token_no_default_policy": true, "token_type": "service",
		})
	defer roleResponse.destroy()
	if roleResponse.status != http.StatusNoContent {
		t.Fatalf("Vault entity manager role returned status %d", roleResponse.status)
	}
	fixture.registerResourceCleanup(t, http.MethodDelete, "/v1/auth/token/roles/"+fixture.entityManagerRole, nil)

	parentResponse := fixture.mustCall(t, http.MethodPost,
		"/v1/auth/token/create/"+fixture.entityManagerRole, fixture.rootToken, map[string]any{
			"policies": []string{fixture.managerPolicy}, "entity_alias": fixture.entityAlias,
			"ttl": "5m", "no_default_policy": true,
			"display_name": "aiops-entity-manager", "num_uses": 0, "renewable": false, "type": "service",
		})
	defer parentResponse.destroy()
	if parentResponse.status != http.StatusOK {
		t.Fatalf("Vault entity-associated parent creation returned status %d", parentResponse.status)
	}
	entityParent := decodeIntegrationToken(t, parentResponse.body, integrationTokenExpectation{
		policies: []string{fixture.managerPolicy}, orphan: false, numUses: 0, requireEntity: true,
	})
	t.Cleanup(entityParent.destroy)
	if !integrationIdentifierPattern.MatchString(entityParent.entityID) {
		t.Fatal("Vault entity-associated parent returned an unsafe EntityID")
	}
	fixture.registerResourceCleanup(t, http.MethodDelete,
		"/v1/identity/entity/id/"+entityParent.entityID, nil)
	fixture.registerTokenCleanup(t, entityParent.accessor)
	child := fixture.createDatabaseChild(t, entityParent, 2)
	if child.entityID == "" || child.entityID != entityParent.entityID {
		t.Fatal("Vault non-orphan child did not inherit the entity-associated parent identity")
	}
	accessor, err := credential.NewSensitiveReference(child.accessor)
	if err != nil {
		t.Fatal("could not wrap the entity-contaminated child accessor")
	}
	defer accessor.Destroy()
	deadline := credential.CanonicalCredentialExpiry(time.Now().UTC().Add(3 * time.Minute))
	inspectErr := fixture.issuer.InspectChild(context.Background(), accessor, credential.DurableChildInspectionRequest{
		RevocationID: fixture.revocationID("30000000"), ProfileRevision: fixture.profileRevision,
		CredentialExpiresAt: deadline, ExpectedTTL: 2 * time.Minute,
	})
	var clientError *vaultclient.ClientError
	if inspectErr == nil || !errors.As(inspectErr, &clientError) || clientError.Class != vaultclient.ErrorProtocol {
		t.Fatal("production Vault client accepted an EntityID-contaminated child inspection")
	}
	fixture.revokeAccessorRaw(t, entityParent.accessor)
	fixture.assertAccessorMissing(t, entityParent.accessor)
	fixture.assertAccessorMissing(t, child.accessor)
}

func (fixture *vault203Fixture) revocationID(prefix string) string {
	return prefix + "-0000-4000-8000-" + fixture.suffix
}
