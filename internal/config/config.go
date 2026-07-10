package config

import (
	"fmt"
	"os"
	"time"
)

const (
	defaultHTTPAddr        = ":8080"
	defaultEnvironment     = "development"
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	HTTPAddr          string
	Environment       string
	ShutdownTimeout   time.Duration
	WebhookHMACSecret string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:          valueOrDefault("AIOPS_HTTP_ADDR", defaultHTTPAddr),
		Environment:       valueOrDefault("AIOPS_ENVIRONMENT", defaultEnvironment),
		ShutdownTimeout:   defaultShutdownTimeout,
		WebhookHMACSecret: os.Getenv("AIOPS_WEBHOOK_HMAC_SECRET"),
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
	if cfg.Environment == "production" && cfg.WebhookHMACSecret == "" {
		return Config{}, fmt.Errorf("AIOPS_WEBHOOK_HMAC_SECRET is required in production")
	}

	return cfg, nil
}

func valueOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
