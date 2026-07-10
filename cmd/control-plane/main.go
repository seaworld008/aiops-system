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
	"github.com/aiops-system/control-plane/internal/webhook"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load configuration", "error", err)
		os.Exit(1)
	}

	repository := memory.New()
	signalIngestor := signalservice.NewService(repository, time.Now)
	webhookVerifier := webhook.NewHMACVerifier(func(_, _ string) ([]byte, error) {
		if cfg.WebhookHMACSecret == "" {
			return nil, webhook.ErrSecretUnavailable
		}
		return []byte(cfg.WebhookHMACSecret), nil
	})
	server := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Dependencies{
			Version:         buildinfo.Version,
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
