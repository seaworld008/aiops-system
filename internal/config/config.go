package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
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

type RunnerGatewayConfig struct {
	Addr                  string
	ServerCertFile        string
	ServerKeyFile         string
	ReadClientCAFile      string
	WriteClientCAFile     string
	CredentialKeyringFile string
	TrustDomain           string
}

type Config struct {
	HTTPAddr             string
	Environment          string
	ShutdownTimeout      time.Duration
	WebhookHMACSecret    string
	WebhookHMACSecrets   map[string]string
	DatabaseURL          string
	OIDCIssuer           string
	OIDCClientID         string
	OIDCMaxSessionAge    time.Duration
	OIDCRecentAuthWindow time.Duration
	WriteExecutionMode   WriteExecutionMode
	RunnerGateway        *RunnerGatewayConfig
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
		HTTPAddr:             valueOrDefault("AIOPS_HTTP_ADDR", defaultHTTPAddr),
		Environment:          environment,
		ShutdownTimeout:      defaultShutdownTimeout,
		WebhookHMACSecret:    os.Getenv("AIOPS_WEBHOOK_HMAC_SECRET"),
		WebhookHMACSecrets:   make(map[string]string),
		DatabaseURL:          os.Getenv("AIOPS_DATABASE_URL"),
		OIDCIssuer:           strings.TrimSpace(os.Getenv("AIOPS_OIDC_ISSUER")),
		OIDCClientID:         strings.TrimSpace(os.Getenv("AIOPS_OIDC_CLIENT_ID")),
		OIDCMaxSessionAge:    12 * time.Hour,
		OIDCRecentAuthWindow: 5 * time.Minute,
		WriteExecutionMode:   writeExecutionMode,
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
	if raw := os.Getenv("AIOPS_OIDC_RECENT_AUTH_WINDOW"); raw != "" {
		duration, err := time.ParseDuration(raw)
		if err != nil || duration < time.Minute || duration > 15*time.Minute {
			return Config{}, fmt.Errorf("AIOPS_OIDC_RECENT_AUTH_WINDOW must be between 1m and 15m")
		}
		cfg.OIDCRecentAuthWindow = duration
	}
	if (cfg.OIDCIssuer == "") != (cfg.OIDCClientID == "") {
		return Config{}, fmt.Errorf("AIOPS_OIDC_ISSUER and AIOPS_OIDC_CLIENT_ID must be configured together")
	}
	runnerGateway, err := loadRunnerGatewayConfig(cfg.HTTPAddr, cfg.DatabaseURL)
	if err != nil {
		return Config{}, err
	}
	cfg.RunnerGateway = runnerGateway
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

func loadRunnerGatewayConfig(publicAddr, databaseURL string) (*RunnerGatewayConfig, error) {
	values := []string{
		os.Getenv("AIOPS_RUNNER_GATEWAY_ADDR"),
		os.Getenv("AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE"),
		os.Getenv("AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE"),
		os.Getenv("AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE"),
		os.Getenv("AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE"),
		os.Getenv("AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE"),
		os.Getenv("AIOPS_RUNNER_TRUST_DOMAIN"),
	}
	nonEmpty := 0
	for _, value := range values {
		if value != "" {
			nonEmpty++
		}
	}
	if nonEmpty == 0 {
		return nil, nil
	}
	if nonEmpty != len(values) {
		return nil, fmt.Errorf("Runner Gateway configuration must be all present or all absent")
	}
	if databaseURL == "" {
		return nil, fmt.Errorf("AIOPS_DATABASE_URL is required when Runner Gateway is configured")
	}
	configuration := &RunnerGatewayConfig{
		Addr: values[0], ServerCertFile: values[1], ServerKeyFile: values[2],
		ReadClientCAFile: values[3], WriteClientCAFile: values[4],
		CredentialKeyringFile: values[5], TrustDomain: values[6],
	}
	if !validListenAddress(configuration.Addr) || configuration.Addr == publicAddr {
		return nil, fmt.Errorf("AIOPS_RUNNER_GATEWAY_ADDR must be a distinct bounded TCP listen address")
	}
	paths := []string{
		configuration.ServerCertFile, configuration.ServerKeyFile,
		configuration.ReadClientCAFile, configuration.WriteClientCAFile,
		configuration.CredentialKeyringFile,
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !validAbsoluteConfigPath(path) {
			return nil, fmt.Errorf("Runner Gateway certificate and key paths must be distinct clean absolute paths")
		}
		if _, duplicate := seen[path]; duplicate {
			return nil, fmt.Errorf("Runner Gateway certificate and key paths must be distinct clean absolute paths")
		}
		seen[path] = struct{}{}
	}
	if !validTrustDomain(configuration.TrustDomain) {
		return nil, fmt.Errorf("AIOPS_RUNNER_TRUST_DOMAIN must be a canonical lowercase DNS name")
	}
	return configuration, nil
}

func validListenAddress(value string) bool {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || containsControl(value) {
		return false
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || portText == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return false
	}
	return host == "" || net.ParseIP(host) != nil || validTrustDomain(host)
}

func validAbsoluteConfigPath(value string) bool {
	return value != "" && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value &&
		strings.TrimSpace(value) == value && !containsControl(value)
}

func validTrustDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || strings.HasSuffix(value, ".") ||
		strings.TrimSpace(value) != value || containsControl(value) || net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func valueOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
