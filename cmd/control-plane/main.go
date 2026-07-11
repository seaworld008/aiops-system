package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/buildinfo"
	"github.com/seaworld008/aiops-system/internal/config"
	credentialpostgres "github.com/seaworld008/aiops-system/internal/credential/postgres"
	"github.com/seaworld008/aiops-system/internal/credentialadmin"
	"github.com/seaworld008/aiops-system/internal/httpapi"
	signalservice "github.com/seaworld008/aiops-system/internal/signal"
	"github.com/seaworld008/aiops-system/internal/store/memory"
	postgresstore "github.com/seaworld008/aiops-system/internal/store/postgres"
	"github.com/seaworld008/aiops-system/internal/webhook"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load configuration", "error", err)
		os.Exit(1)
	}

	var repository signalservice.Repository
	ready := func() error { return nil }
	var databasePool *pgxpool.Pool
	if cfg.DatabaseURL == "" {
		repository = memory.New()
		slog.Warn("using in-memory repository; data will not survive restart")
	} else {
		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		databasePool, err = pgxpool.New(connectCtx, cfg.DatabaseURL)
		if err == nil {
			err = databasePool.Ping(connectCtx)
		}
		cancel()
		if err != nil {
			slog.Error("connect PostgreSQL", "error", err)
			if databasePool != nil {
				databasePool.Close()
			}
			os.Exit(1)
		}
		defer databasePool.Close()
		repository = postgresstore.New(databasePool)
		ready = func() error {
			pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return databasePool.Ping(pingCtx)
		}
	}
	signalIngestor := signalservice.NewService(repository, time.Now)
	webhookVerifier := webhook.NewHMACVerifier(func(integrationID, provider string) ([]byte, error) {
		if secret := cfg.WebhookHMACSecrets[integrationID+"/"+provider]; secret != "" {
			return []byte(secret), nil
		}
		if cfg.Environment != "production" && cfg.WebhookHMACSecret != "" {
			return []byte(cfg.WebhookHMACSecret), nil
		}
		return nil, webhook.ErrSecretUnavailable
	})
	var authenticator *authn.Authenticator
	if cfg.OIDCIssuer != "" {
		discoveryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		keycloakVerifier, verifierErr := authn.NewKeycloakVerifier(discoveryCtx, cfg.OIDCIssuer, cfg.OIDCClientID)
		cancel()
		if verifierErr != nil {
			slog.Error("configure Keycloak OIDC", "error", verifierErr)
			os.Exit(1)
		}
		authenticator, err = authn.NewAuthenticator(keycloakVerifier, authn.Options{MaxSessionAge: cfg.OIDCMaxSessionAge}, time.Now)
		if err != nil {
			slog.Error("configure OIDC authentication", "error", err)
			os.Exit(1)
		}
	}
	var credentialRevocations httpapi.CredentialRevocationManager
	if databasePool != nil {
		authorizer, authorizerErr := authz.NewAuthorizer(cfg.OIDCRecentAuthWindow, time.Now)
		if authorizerErr != nil {
			slog.Error("configure credential revocation authorization", "error", authorizerErr)
			os.Exit(1)
		}
		managementStore, managementErr := credentialpostgres.NewManagement(databasePool)
		if managementErr != nil {
			slog.Error("configure credential revocation management store", "error", managementErr)
			os.Exit(1)
		}
		credentialRevocations, err = credentialadmin.New(managementStore, authorizer)
		if err != nil {
			slog.Error("configure credential revocation management", "error", err)
			os.Exit(1)
		}
	}
	server := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Dependencies{
			Version:               buildinfo.Version,
			Ready:                 ready,
			SignalIngestor:        signalIngestor,
			WebhookVerifier:       webhookVerifier,
			Authenticator:         authenticator,
			CredentialRevocations: credentialRevocations,
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("control plane listening", "addr", cfg.HTTPAddr, "environment", cfg.Environment)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve HTTP", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown HTTP server", "error", err)
	}
}
