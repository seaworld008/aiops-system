package config_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/config"
)

func TestLoadUsesSafeDefaults(t *testing.T) {
	clearRunnerGatewayEnvironment(t)
	clearControlPlaneOIDCEnvironment(t)
	t.Setenv("AIOPS_HTTP_ADDR", "")
	t.Setenv("AIOPS_SHUTDOWN_TIMEOUT", "")
	t.Setenv("AIOPS_ENVIRONMENT", "")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", "")
	t.Setenv("AIOPS_WRITE_EXECUTION_MODE", "")
	t.Setenv("AIOPS_OIDC_RECENT_AUTH_WINDOW", "")
	t.Setenv("AIOPS_CONTROL_PLANE_CURSOR_HMAC_SECRET", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.Environment != "development" {
		t.Fatalf("Environment = %q, want development", cfg.Environment)
	}
	if cfg.WriteExecutionMode != config.WriteExecutionModeDisabled {
		t.Fatalf("WriteExecutionMode = %q, want %q", cfg.WriteExecutionMode, config.WriteExecutionModeDisabled)
	}
	if cfg.OIDCRecentAuthWindow != 5*time.Minute {
		t.Fatalf("OIDCRecentAuthWindow = %s, want 5m", cfg.OIDCRecentAuthWindow)
	}
	if cfg.OIDCIssuer != "" || cfg.OIDCAPIAudience != "" || cfg.OIDCAuthorizedParty != "" ||
		cfg.WebOIDCURL != "" || cfg.WebOIDCRealm != "" || cfg.WebOIDCClientID != "" {
		t.Fatalf("OIDC/browser configuration = %#v, want disabled", cfg)
	}
	if len(cfg.ControlPlaneCursorHMACSecret) != 0 {
		t.Fatalf("ControlPlaneCursorHMACSecret length = %d, want 0", len(cfg.ControlPlaneCursorHMACSecret))
	}
	if cfg.RunnerGateway != nil {
		t.Fatalf("RunnerGateway = %#v, want disabled", cfg.RunnerGateway)
	}
}

func TestLoadAcceptsCompleteRunnerGatewayConfiguration(t *testing.T) {
	clearRunnerGatewayEnvironment(t)
	root := t.TempDir()
	values := map[string]string{
		"AIOPS_RUNNER_GATEWAY_ADDR":                 ":8443",
		"AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE":     filepath.Join(root, "server-chain.pem"),
		"AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE":      filepath.Join(root, "server-key.pem"),
		"AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE":  filepath.Join(root, "read-roots.pem"),
		"AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE": filepath.Join(root, "write-roots.pem"),
		"AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE":  filepath.Join(root, "credential-keyring.json"),
		"AIOPS_RUNNER_TRUST_DOMAIN":                 "aiops.example.internal",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	t.Setenv("AIOPS_DATABASE_URL", "postgres://configured")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RunnerGateway == nil {
		t.Fatal("RunnerGateway = nil, want enabled configuration")
	}
	if cfg.RunnerGateway.Addr != ":8443" || cfg.RunnerGateway.TrustDomain != "aiops.example.internal" ||
		cfg.RunnerGateway.ServerCertFile != values["AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE"] ||
		cfg.RunnerGateway.ServerKeyFile != values["AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE"] ||
		cfg.RunnerGateway.ReadClientCAFile != values["AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE"] ||
		cfg.RunnerGateway.WriteClientCAFile != values["AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE"] ||
		cfg.RunnerGateway.CredentialKeyringFile != values["AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE"] {
		t.Fatalf("RunnerGateway = %#v", cfg.RunnerGateway)
	}
}

func TestLoadRejectsPartialRunnerGatewayConfiguration(t *testing.T) {
	keys := []string{
		"AIOPS_RUNNER_GATEWAY_ADDR",
		"AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE",
		"AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE",
		"AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE",
		"AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE",
		"AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE",
		"AIOPS_RUNNER_TRUST_DOMAIN",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			clearRunnerGatewayEnvironment(t)
			t.Setenv(key, "configured")
			t.Setenv("AIOPS_DATABASE_URL", "postgres://configured")
			if _, err := config.Load(); err == nil {
				t.Fatalf("Load() error = nil with only %s, want all-or-none rejection", key)
			}
		})
	}
}

func TestLoadRejectsRunnerGatewayWithoutPostgreSQL(t *testing.T) {
	setRunnerGatewayEnvironment(t)
	t.Setenv("AIOPS_DATABASE_URL", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want PostgreSQL requirement")
	}
}

func TestLoadRejectsInvalidRunnerTrustDomains(t *testing.T) {
	for _, value := range []string{
		"AIops.example.internal", "aiops.example.internal.", "*.example.internal", "https://example.internal",
		"example.internal:443", "127.0.0.1", "-aiops.example", "aiops-.example", "aiops..example",
		" aiops.example", "aiops.example ", "aiops_example.internal", "",
	} {
		t.Run(value, func(t *testing.T) {
			setRunnerGatewayEnvironment(t)
			t.Setenv("AIOPS_RUNNER_TRUST_DOMAIN", value)
			if _, err := config.Load(); err == nil {
				t.Fatalf("Load() error = nil for trust domain %q", value)
			}
		})
	}
}

func TestLoadRejectsUnsafeRunnerGatewayPathsAndAddresses(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "relative cert", key: "AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE", value: "server.pem"},
		{name: "unclean key", key: "AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE", value: "/safe/../server.key"},
		{name: "control in ca", key: "AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE", value: "/safe/read\n.pem"},
		{name: "relative credential keyring", key: "AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE", value: "keyring.json"},
		{name: "missing port", key: "AIOPS_RUNNER_GATEWAY_ADDR", value: "localhost"},
		{name: "zero port", key: "AIOPS_RUNNER_GATEWAY_ADDR", value: ":0"},
		{name: "public collision", key: "AIOPS_RUNNER_GATEWAY_ADDR", value: ":8080"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setRunnerGatewayEnvironment(t)
			t.Setenv(test.key, test.value)
			if _, err := config.Load(); err == nil {
				t.Fatalf("Load() error = nil for %s=%q", test.key, test.value)
			}
		})
	}
}

func TestLoadRejectsOverlappingRunnerGatewayFiles(t *testing.T) {
	for _, pair := range [][2]string{
		{"AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE", "AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE"},
		{"AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE", "AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE"},
		{"AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE", "AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE"},
	} {
		t.Run(pair[0]+"="+pair[1], func(t *testing.T) {
			setRunnerGatewayEnvironment(t)
			shared := filepath.Join(t.TempDir(), "shared.pem")
			t.Setenv(pair[0], shared)
			t.Setenv(pair[1], shared)
			if _, err := config.Load(); err == nil {
				t.Fatal("Load() error = nil, want distinct file rejection")
			}
		})
	}
}

func TestLoadRejectsInvalidShutdownTimeout(t *testing.T) {
	t.Setenv("AIOPS_SHUTDOWN_TIMEOUT", "not-a-duration")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestLoadAcceptsOIDCRecentAuthenticationWindowBoundaries(t *testing.T) {
	for _, value := range []string{"1m", "5m", "15m"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("AIOPS_OIDC_RECENT_AUTH_WINDOW", value)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			want, err := time.ParseDuration(value)
			if err != nil {
				t.Fatalf("ParseDuration(%q) error = %v", value, err)
			}
			if cfg.OIDCRecentAuthWindow != want {
				t.Fatalf("OIDCRecentAuthWindow = %s, want %s", cfg.OIDCRecentAuthWindow, want)
			}
		})
	}
}

func TestLoadRejectsOIDCRecentAuthenticationWindowOutsideOneToFifteenMinutes(t *testing.T) {
	for _, value := range []string{
		"not-a-duration",
		"-1m",
		"0s",
		"59.999999999s",
		"15m0.000000001s",
		"1h",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("AIOPS_OIDC_RECENT_AUTH_WINDOW", value)

			if _, err := config.Load(); err == nil {
				t.Fatalf("Load() error = nil for AIOPS_OIDC_RECENT_AUTH_WINDOW=%q, want validation error", value)
			}
		})
	}
}

func TestLoadAcceptsOnlySupportedWriteExecutionModes(t *testing.T) {
	for _, testCase := range []struct {
		input string
		want  config.WriteExecutionMode
	}{
		{input: "disabled", want: config.WriteExecutionModeDisabled},
		{input: "non-production", want: config.WriteExecutionModeNonProduction},
	} {
		t.Run(testCase.input, func(t *testing.T) {
			t.Setenv("AIOPS_WRITE_EXECUTION_MODE", testCase.input)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.WriteExecutionMode != testCase.want {
				t.Fatalf("WriteExecutionMode = %q, want %q", cfg.WriteExecutionMode, testCase.want)
			}
		})
	}
}

func TestLoadRejectsUnsupportedWriteExecutionModesWithoutNormalization(t *testing.T) {
	for _, mode := range []string{
		"production",
		"prod",
		"enabled",
		"true",
		"1",
		"DISABLED",
		"NON-PRODUCTION",
		"Disabled",
		"Non-Production",
		" disabled",
		"disabled ",
		"\tdisabled",
		"non-production\n",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("AIOPS_WRITE_EXECUTION_MODE", mode)

			if _, err := config.Load(); err == nil {
				t.Fatalf("Load() error = nil for AIOPS_WRITE_EXECUTION_MODE=%q, want fail-closed rejection", mode)
			}
		})
	}
}

func TestLoadRejectsProductionWithoutWebhookSecret(t *testing.T) {
	t.Setenv("AIOPS_ENVIRONMENT", "production")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRET", "")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", "")
	t.Setenv("AIOPS_DATABASE_URL", "postgres://configured")
	setOIDCEnvironment(t)

	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want fail-closed production configuration")
	}
}

func TestLoadRejectsProductionWithoutDatabaseURL(t *testing.T) {
	t.Setenv("AIOPS_ENVIRONMENT", "production")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRET", "")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", `{"33333333-3333-4333-8333-333333333333/alertmanager":"configured"}`)
	t.Setenv("AIOPS_DATABASE_URL", "")
	setOIDCEnvironment(t)

	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want database fail-closed production configuration")
	}
}

func TestLoadParsesIntegrationScopedWebhookSecrets(t *testing.T) {
	t.Setenv("AIOPS_ENVIRONMENT", "production")
	t.Setenv("AIOPS_DATABASE_URL", "postgres://configured")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRET", "")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", `{"33333333-3333-4333-8333-333333333333/alertmanager":"secret"}`)
	setOIDCEnvironment(t)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.WebhookHMACSecrets["33333333-3333-4333-8333-333333333333/alertmanager"] != "secret" {
		t.Fatalf("WebhookHMACSecrets = %#v", cfg.WebhookHMACSecrets)
	}
}

func TestLoadRejectsProductionWithoutOIDCConfiguration(t *testing.T) {
	t.Setenv("AIOPS_ENVIRONMENT", "production")
	t.Setenv("AIOPS_DATABASE_URL", "postgres://configured")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", `{"33333333-3333-4333-8333-333333333333/alertmanager":"secret"}`)
	clearControlPlaneOIDCEnvironment(t)
	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want OIDC fail-closed production configuration")
	}
}

func TestLoadRequiresAllSixControlPlaneOIDCValuesTogether(t *testing.T) {
	keys := []string{
		"AIOPS_OIDC_ISSUER",
		"AIOPS_OIDC_API_AUDIENCE",
		"AIOPS_OIDC_AUTHORIZED_PARTY",
		"AIOPS_WEB_OIDC_URL",
		"AIOPS_WEB_OIDC_REALM",
		"AIOPS_WEB_OIDC_CLIENT_ID",
	}
	values := []string{
		"https://identity.example.com/realms/aiops",
		"aiops-control-plane",
		"control-plane-web",
		"https://identity.example.com",
		"aiops",
		"control-plane-web",
	}
	for index, key := range keys {
		index, key := index, key
		t.Run(key, func(t *testing.T) {
			clearControlPlaneOIDCEnvironment(t)
			t.Setenv(key, values[index])
			if _, err := config.Load(); err == nil {
				t.Fatalf("Load() error = nil with only %s", key)
			}
		})
	}
}

func TestLoadAcceptsSeparatedBrowserAndAPIOIDCConfiguration(t *testing.T) {
	setOIDCEnvironment(t)
	t.Setenv("AIOPS_CONTROL_PLANE_CURSOR_HMAC_SECRET", "0123456789abcdef0123456789abcdef")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OIDCIssuer != "https://identity.example.com/realms/aiops" ||
		cfg.OIDCAPIAudience != "aiops-control-plane" ||
		cfg.OIDCAuthorizedParty != "control-plane-web" ||
		cfg.WebOIDCURL != "https://identity.example.com" ||
		cfg.WebOIDCRealm != "aiops" ||
		cfg.WebOIDCClientID != "control-plane-web" {
		t.Fatalf("OIDC/browser configuration = %#v", cfg)
	}
	if string(cfg.ControlPlaneCursorHMACSecret) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("cursor secret was not copied exactly")
	}
}

func TestLoadRejectsLegacyOrDriftedControlPlaneOIDCConfiguration(t *testing.T) {
	tests := map[string]func(*testing.T){
		"legacy client id": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_OIDC_CLIENT_ID", "aiops-control-plane")
		},
		"wrong API audience": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_OIDC_API_AUDIENCE", "control-plane-web")
		},
		"wrong authorized party": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_OIDC_AUTHORIZED_PARTY", "another-client")
		},
		"browser client drift": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_WEB_OIDC_CLIENT_ID", "another-client")
		},
		"issuer realm drift": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_OIDC_ISSUER", "https://identity.example.com/realms/other")
		},
		"unsafe browser url": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_WEB_OIDC_URL", "http://identity.example.com")
		},
		"unclean issuer path": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_OIDC_ISSUER", "https://identity.example.com/a/../realms/aiops")
		},
		"unclean browser url path": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_WEB_OIDC_URL", "https://identity.example.com/a/..")
		},
		"private browser url": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_WEB_OIDC_URL", "https://10.0.0.1")
			t.Setenv("AIOPS_OIDC_ISSUER", "https://10.0.0.1/realms/aiops")
		},
		"internal browser host": func(t *testing.T) {
			setOIDCEnvironment(t)
			t.Setenv("AIOPS_WEB_OIDC_URL", "https://identity.internal")
			t.Setenv("AIOPS_OIDC_ISSUER", "https://identity.internal/realms/aiops")
		},
	}
	for name, arrange := range tests {
		name, arrange := name, arrange
		t.Run(name, func(t *testing.T) {
			clearControlPlaneOIDCEnvironment(t)
			t.Setenv("AIOPS_OIDC_CLIENT_ID", "")
			arrange(t)
			if _, err := config.Load(); err == nil {
				t.Fatal("Load() error = nil, want fail-closed rejection")
			}
		})
	}
}

func TestLoadRejectsMalformedWebhookSecretRegistry(t *testing.T) {
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", `{`)
	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want malformed registry rejection")
	}
}

func TestLoadNormalizesProductionAliasesBeforeFailClosedChecks(t *testing.T) {
	for _, environment := range []string{" Production ", "PROD"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("AIOPS_ENVIRONMENT", environment)
			t.Setenv("AIOPS_DATABASE_URL", "")
			t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", "")
			if _, err := config.Load(); err == nil {
				t.Fatal("Load() error = nil, want production fail-closed validation")
			}
		})
	}
}

func setOIDCEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("AIOPS_OIDC_ISSUER", "https://identity.example.com/realms/aiops")
	t.Setenv("AIOPS_OIDC_API_AUDIENCE", "aiops-control-plane")
	t.Setenv("AIOPS_OIDC_AUTHORIZED_PARTY", "control-plane-web")
	t.Setenv("AIOPS_WEB_OIDC_URL", "https://identity.example.com")
	t.Setenv("AIOPS_WEB_OIDC_REALM", "aiops")
	t.Setenv("AIOPS_WEB_OIDC_CLIENT_ID", "control-plane-web")
	t.Setenv("AIOPS_OIDC_CLIENT_ID", "")
}

func clearControlPlaneOIDCEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"AIOPS_OIDC_ISSUER",
		"AIOPS_OIDC_API_AUDIENCE",
		"AIOPS_OIDC_AUTHORIZED_PARTY",
		"AIOPS_WEB_OIDC_URL",
		"AIOPS_WEB_OIDC_REALM",
		"AIOPS_WEB_OIDC_CLIENT_ID",
		"AIOPS_OIDC_CLIENT_ID",
	} {
		t.Setenv(key, "")
	}
}

func clearRunnerGatewayEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"AIOPS_RUNNER_GATEWAY_ADDR",
		"AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE",
		"AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE",
		"AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE",
		"AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE",
		"AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE",
		"AIOPS_RUNNER_TRUST_DOMAIN",
	} {
		t.Setenv(key, "")
	}
}

func setRunnerGatewayEnvironment(t *testing.T) {
	t.Helper()
	clearRunnerGatewayEnvironment(t)
	root := t.TempDir()
	t.Setenv("AIOPS_RUNNER_GATEWAY_ADDR", ":8443")
	t.Setenv("AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE", filepath.Join(root, "server-chain.pem"))
	t.Setenv("AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE", filepath.Join(root, "server-key.pem"))
	t.Setenv("AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE", filepath.Join(root, "read-roots.pem"))
	t.Setenv("AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE", filepath.Join(root, "write-roots.pem"))
	t.Setenv("AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE", filepath.Join(root, "credential-keyring.json"))
	t.Setenv("AIOPS_RUNNER_TRUST_DOMAIN", "aiops.example.internal")
	t.Setenv("AIOPS_DATABASE_URL", "postgres://configured")
}

func TestLoadRejectsUnknownEnvironment(t *testing.T) {
	t.Setenv("AIOPS_ENVIRONMENT", "prodution")
	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want unknown environment rejection")
	}
}
