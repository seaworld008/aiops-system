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

	"github.com/aiops-system/control-plane/internal/buildinfo"
	"github.com/aiops-system/control-plane/internal/config"
	"github.com/aiops-system/control-plane/internal/httpapi"
	signalservice "github.com/aiops-system/control-plane/internal/signal"
	"github.com/aiops-system/control-plane/internal/store/memory"
	postgresstore "github.com/aiops-system/control-plane/internal/store/postgres"
	"github.com/aiops-system/control-plane/internal/webhook"
	"github.com/jackc/pgx/v5/pgxpool"
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
	server := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Dependencies{
			Version:         buildinfo.Version,
			Ready:           ready,
			SignalIngestor:  signalIngestor,
			WebhookVerifier: webhookVerifier,
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
