package config_test

import (
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/config"
)

func TestLoadUsesSafeDefaults(t *testing.T) {
	t.Setenv("AIOPS_HTTP_ADDR", "")
	t.Setenv("AIOPS_SHUTDOWN_TIMEOUT", "")
	t.Setenv("AIOPS_ENVIRONMENT", "")
	t.Setenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON", "")

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
}

func TestLoadRejectsInvalidShutdownTimeout(t *testing.T) {
	t.Setenv("AIOPS_SHUTDOWN_TIMEOUT", "not-a-duration")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
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
