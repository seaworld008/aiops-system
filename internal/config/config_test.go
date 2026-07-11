package config_test

import (
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/config"
)

func TestLoadUsesSafeDefaults(t *testing.T) {
	t.Setenv("AIOPS_HTTP_ADDR", "")
	t.Setenv("AIOPS_SHUTDOWN_TIMEOUT", "")
	t.Setenv("AIOPS_ENVIRONMENT", "")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", "")
	t.Setenv("AIOPS_WRITE_EXECUTION_MODE", "")
	t.Setenv("AIOPS_OIDC_RECENT_AUTH_WINDOW", "")

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
	t.Setenv("AIOPS_OIDC_ISSUER", "")
	t.Setenv("AIOPS_OIDC_CLIENT_ID", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want OIDC fail-closed production configuration")
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
	t.Setenv("AIOPS_OIDC_ISSUER", "https://keycloak.example.com/realms/aiops")
	t.Setenv("AIOPS_OIDC_CLIENT_ID", "aiops-control-plane")
}

func TestLoadRejectsUnknownEnvironment(t *testing.T) {
	t.Setenv("AIOPS_ENVIRONMENT", "prodution")
	if _, err := config.Load(); err == nil {
		t.Fatal("Load() error = nil, want unknown environment rejection")
	}
}
