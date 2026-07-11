package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultHTTPAddr        = ":8080"
	defaultEnvironment     = "development"
	defaultShutdownTimeout = 10 * time.Second
)

type WriteExecutionMode string

const (
	WriteExecutionModeDisabled      WriteExecutionMode = "disabled"
	WriteExecutionModeNonProduction WriteExecutionMode = "non-production"
)

type Config struct {
	HTTPAddr           string
	Environment        string
	ShutdownTimeout    time.Duration
	WebhookHMACSecret  string
	WebhookHMACSecrets map[string]string
	DatabaseURL        string
	OIDCIssuer         string
	OIDCClientID       string
	OIDCMaxSessionAge  time.Duration
	WriteExecutionMode WriteExecutionMode
}

func Load() (Config, error) {
	var writeExecutionMode WriteExecutionMode
	switch os.Getenv("AIOPS_WRITE_EXECUTION_MODE") {
	case "", string(WriteExecutionModeDisabled):
		writeExecutionMode = WriteExecutionModeDisabled
	case string(WriteExecutionModeNonProduction):
		writeExecutionMode = WriteExecutionModeNonProduction
	default:
		return Config{}, fmt.Errorf("AIOPS_WRITE_EXECUTION_MODE must be disabled or non-production")
	}

	environment := strings.ToLower(strings.TrimSpace(valueOrDefault("AIOPS_ENVIRONMENT", defaultEnvironment)))
	if environment == "prod" {
		environment = "production"
	}
	switch environment {
	case "development", "test", "staging", "production":
	default:
		return Config{}, fmt.Errorf("AIOPS_ENVIRONMENT must be development, test, staging, or production")
	}
	cfg := Config{
		HTTPAddr:           valueOrDefault("AIOPS_HTTP_ADDR", defaultHTTPAddr),
		Environment:        environment,
		ShutdownTimeout:    defaultShutdownTimeout,
		WebhookHMACSecret:  os.Getenv("AIOPS_WEBHOOK_HMAC_SECRET"),
		WebhookHMACSecrets: make(map[string]string),
		DatabaseURL:        os.Getenv("AIOPS_DATABASE_URL"),
		OIDCIssuer:         strings.TrimSpace(os.Getenv("AIOPS_OIDC_ISSUER")),
		OIDCClientID:       strings.TrimSpace(os.Getenv("AIOPS_OIDC_CLIENT_ID")),
		OIDCMaxSessionAge:  12 * time.Hour,
		WriteExecutionMode: writeExecutionMode,
	}
	if raw := os.Getenv("AIOPS_WEBHOOK_HMAC_SECRETS_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg.WebhookHMACSecrets); err != nil {
			return Config{}, fmt.Errorf("parse AIOPS_WEBHOOK_HMAC_SECRETS_JSON: %w", err)
		}
		if len(cfg.WebhookHMACSecrets) > 1000 {
			return Config{}, fmt.Errorf("AIOPS_WEBHOOK_HMAC_SECRETS_JSON exceeds 1000 integrations")
		}
		for key, secret := range cfg.WebhookHMACSecrets {
			parts := strings.Split(key, "/")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" || secret == "" {
				return Config{}, fmt.Errorf("AIOPS_WEBHOOK_HMAC_SECRETS_JSON contains an invalid integration/provider entry")
			}
		}
	}

	if raw := os.Getenv("AIOPS_SHUTDOWN_TIMEOUT"); raw != "" {
		duration, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse AIOPS_SHUTDOWN_TIMEOUT: %w", err)
		}
		if duration <= 0 {
			return Config{}, fmt.Errorf("AIOPS_SHUTDOWN_TIMEOUT must be positive")
		}
		cfg.ShutdownTimeout = duration
	}
	if raw := os.Getenv("AIOPS_OIDC_MAX_SESSION_AGE"); raw != "" {
		duration, err := time.ParseDuration(raw)
		if err != nil || duration < time.Minute || duration > 24*time.Hour {
			return Config{}, fmt.Errorf("AIOPS_OIDC_MAX_SESSION_AGE must be between 1m and 24h")
		}
		cfg.OIDCMaxSessionAge = duration
	}
	if (cfg.OIDCIssuer == "") != (cfg.OIDCClientID == "") {
		return Config{}, fmt.Errorf("AIOPS_OIDC_ISSUER and AIOPS_OIDC_CLIENT_ID must be configured together")
	}
	if cfg.Environment == "production" && len(cfg.WebhookHMACSecrets) == 0 {
		return Config{}, fmt.Errorf("AIOPS_WEBHOOK_HMAC_SECRETS_JSON is required in production")
	}
	if cfg.Environment == "production" && cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("AIOPS_DATABASE_URL is required in production")
	}
	if cfg.Environment == "production" && (cfg.OIDCIssuer == "" || cfg.OIDCClientID == "") {
		return Config{}, fmt.Errorf("AIOPS_OIDC_ISSUER and AIOPS_OIDC_CLIENT_ID are required in production")
	}

	return cfg, nil
}

func valueOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
