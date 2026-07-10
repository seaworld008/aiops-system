package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/aiops-system/control-plane/internal/signal"
	"github.com/aiops-system/control-plane/internal/store"
	"github.com/go-chi/chi/v5"
)

type SignalIngestor interface {
	Ingest(context.Context, string, string, string, []byte) (signal.IngestResult, error)
}

type Dependencies struct {
	Version        string
	Ready          func() error
	SignalIngestor SignalIngestor
}

func NewRouter(deps Dependencies) http.Handler {
	if deps.Ready == nil {
		deps.Ready = func() error { return nil }
	}

	router := chi.NewRouter()
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": deps.Version,
		})
	})
	router.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := deps.Ready(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Post("/api/v1/integrations/{integrationID}/webhooks/{provider}", webhookHandler(deps.SignalIngestor))

	return router
}

func webhookHandler(ingestor SignalIngestor) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if ingestor == nil {
			writeProblem(w, http.StatusServiceUnavailable, "signal_ingestor_unavailable", "Signal ingestion is unavailable")
			return
		}
		if contentType := request.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
			writeProblem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}
		workspaceID := request.Header.Get("X-Workspace-ID")
		if workspaceID == "" {
			writeProblem(w, http.StatusBadRequest, "workspace_required", "X-Workspace-ID is required")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 1<<20))
		if err != nil {
			writeProblem(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Webhook payload exceeds 1 MiB")
			return
		}
		result, err := ingestor.Ingest(
			request.Context(),
			workspaceID,
			chi.URLParam(request, "integrationID"),
			chi.URLParam(request, "provider"),
			body,
		)
		if err != nil {
			switch {
			case errors.Is(err, signal.ErrInvalidPayload):
				writeProblem(w, http.StatusBadRequest, "invalid_signal_payload", "Signal payload is invalid")
			case errors.Is(err, signal.ErrUnsupportedProvider):
				writeProblem(w, http.StatusNotFound, "unsupported_signal_provider", "Signal provider is not supported")
			case errors.Is(err, store.ErrIdempotencyConflict):
				writeProblem(w, http.StatusConflict, "provider_event_conflict", "Provider event ID was reused with a different payload")
			default:
				writeProblem(w, http.StatusInternalServerError, "signal_ingestion_failed", "Signal ingestion failed")
			}
			return
		}
		writeJSON(w, http.StatusAccepted, result)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"code":   code,
		"detail": detail,
	})
}
