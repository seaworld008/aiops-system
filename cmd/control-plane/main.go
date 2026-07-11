package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	if err := run(); err != nil {
		slog.Error("control plane stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
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
			if databasePool != nil {
				databasePool.Close()
			}
			return fmt.Errorf("connect PostgreSQL: %w", err)
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
			return fmt.Errorf("configure Keycloak OIDC: %w", verifierErr)
		}
		authenticator, err = authn.NewAuthenticator(
			keycloakVerifier, authn.Options{MaxSessionAge: cfg.OIDCMaxSessionAge}, time.Now,
		)
		if err != nil {
			return fmt.Errorf("configure OIDC authentication: %w", err)
		}
	}

	var credentialRevocations httpapi.CredentialRevocationManager
	if databasePool != nil {
		authorizer, authorizerErr := authz.NewAuthorizer(cfg.OIDCRecentAuthWindow, time.Now)
		if authorizerErr != nil {
			return fmt.Errorf("configure credential revocation authorization: %w", authorizerErr)
		}
		managementStore, managementErr := credentialpostgres.NewManagement(databasePool)
		if managementErr != nil {
			return fmt.Errorf("configure credential revocation management store: %w", managementErr)
		}
		credentialRevocations, err = credentialadmin.New(managementStore, authorizer)
		if err != nil {
			return fmt.Errorf("configure credential revocation management: %w", err)
		}
	}

	publicServer := &http.Server{
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

	gatewayRuntime, err := newRunnerGatewayRuntime(cfg.RunnerGateway, cfg.WriteExecutionMode, databasePool)
	if err != nil {
		return err
	}
	if gatewayRuntime != nil {
		defer gatewayRuntime.Destroy()
	}

	publicListener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen on public API address: %w", err)
	}
	defer publicListener.Close()
	var gatewayListener net.Listener
	if gatewayRuntime != nil {
		gatewayListener, err = net.Listen("tcp", cfg.RunnerGateway.Addr)
		if err != nil {
			return fmt.Errorf("listen on Runner Gateway address: %w", err)
		}
		defer gatewayListener.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serveErrors := make(chan error, 2)
	serve := func(component string, function func() error) {
		if serveErr := function(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) &&
			!errors.Is(serveErr, net.ErrClosed) {
			serveErrors <- fmt.Errorf("serve %s: %w", component, serveErr)
		}
	}

	slog.Info("control plane listening", "addr", cfg.HTTPAddr, "environment", cfg.Environment)
	go serve("public API", func() error { return publicServer.Serve(publicListener) })
	if gatewayRuntime != nil {
		slog.Info("Runner Gateway listening", "addr", cfg.RunnerGateway.Addr, "write_execution_mode", cfg.WriteExecutionMode)
		go serve("Runner Gateway", func() error { return gatewayRuntime.Serve(gatewayListener) })
	}

	var serveFailure error
	select {
	case <-ctx.Done():
	case serveFailure = <-serveErrors:
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	shutdownCount := 1
	if gatewayRuntime != nil {
		shutdownCount++
	}
	shutdownErrors := make(chan error, shutdownCount)
	go func() { shutdownErrors <- publicServer.Shutdown(shutdownCtx) }()
	if gatewayRuntime != nil {
		go func() { shutdownErrors <- gatewayRuntime.Shutdown(shutdownCtx) }()
	}
	var shutdownFailure error
	for range shutdownCount {
		shutdownFailure = errors.Join(shutdownFailure, <-shutdownErrors)
	}
	return errors.Join(serveFailure, shutdownFailure)
}
