package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/aiops-system/control-plane/internal/ids"
	"github.com/aiops-system/control-plane/internal/requestmeta"
	"github.com/aiops-system/control-plane/internal/signal"
	"github.com/aiops-system/control-plane/internal/store"
	"github.com/aiops-system/control-plane/internal/webhook"
	"github.com/go-chi/chi/v5"
)

var ErrInvalidWebhookSignature = webhook.ErrInvalidSignature

type SignalIngestor interface {
	Ingest(context.Context, string, string, string, []byte) (signal.IngestResult, error)
}

type WebhookVerifier interface {
	Verify(integrationID, provider string, headers http.Header, body []byte) error
}

type Dependencies struct {
	Version         string
	Ready           func() error
	SignalIngestor  SignalIngestor
	WebhookVerifier WebhookVerifier
}

func NewRouter(deps Dependencies) http.Handler {
	if deps.Ready == nil {
		deps.Ready = func() error { return nil }
	}

	router := chi.NewRouter()
	router.Use(requestIDMiddleware)
	router.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeProblem(w, http.StatusNotFound, "route_not_found", "The requested route does not exist")
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed for this route")
	})
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": deps.Version,
		})
	})
	router.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := deps.Ready(); err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "not_ready", "The service is not ready")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Post("/api/v1/integrations/{integrationID}/webhooks/{provider}", webhookHandler(deps.SignalIngestor, deps.WebhookVerifier))

	return router
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestID := ids.NewUUID()
		w.Header().Set("X-Request-ID", requestID)
		ctx := requestmeta.With(request.Context(), requestmeta.Metadata{RequestID: requestID})
		next.ServeHTTP(w, request.WithContext(ctx))
	})
}

func webhookHandler(ingestor SignalIngestor, verifier WebhookVerifier) http.HandlerFunc {
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
		if verifier == nil {
			writeProblem(w, http.StatusServiceUnavailable, "webhook_verifier_unavailable", "Webhook verification is unavailable")
			return
		}
		integrationID := chi.URLParam(request, "integrationID")
		provider := chi.URLParam(request, "provider")
		if err := verifier.Verify(integrationID, provider, request.Header, body); err != nil {
			if errors.Is(err, webhook.ErrInvalidSignature) {
				writeProblem(w, http.StatusUnauthorized, "invalid_webhook_signature", "Webhook signature is invalid")
			} else {
				writeProblem(w, http.StatusServiceUnavailable, "webhook_verification_failed", "Webhook verification could not be completed")
			}
			return
		}
		result, err := ingestor.Ingest(
			request.Context(),
			workspaceID,
			integrationID,
			provider,
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
			case errors.Is(err, store.ErrScopeViolation):
				writeProblem(w, http.StatusForbidden, "integration_scope_violation", "Integration is not authorized for this workspace or provider")
			case errors.Is(err, store.ErrNotFound):
				writeProblem(w, http.StatusNotFound, "integration_not_found", "Integration was not found")
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
