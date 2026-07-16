package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
	"github.com/seaworld008/aiops-system/internal/signal"
	"github.com/seaworld008/aiops-system/internal/store"
	"github.com/seaworld008/aiops-system/internal/webhook"
)

var ErrInvalidWebhookSignature = webhook.ErrInvalidSignature

type SignalIngestor interface {
	Ingest(context.Context, string, string, string, []byte) (signal.IngestResult, error)
}

type WebhookVerifier interface {
	Verify(integrationID, provider string, headers http.Header, body []byte) error
}

type Authenticator interface {
	Authenticate(*http.Request) (authn.Principal, error)
}

type Dependencies struct {
	Version               string
	Ready                 func() error
	SignalIngestor        SignalIngestor
	WebhookVerifier       WebhookVerifier
	Authenticator         Authenticator
	CredentialRevocations CredentialRevocationManager
	BrowserConfig         *BrowserConfig
	ControlPlaneCursor    *ControlPlaneCursorCodec
	Assets                assetcatalog.AssetManager
	AssetRelations        assetcatalog.RelationshipManager
	AssetSources          assetcatalog.SourceManager
	AssetConflicts        assetcatalog.ConflictManager
	ServiceAssetBindings  assetcatalog.BindingManager
	WebUI                 *WebUI
}

func NewRouter(deps Dependencies) http.Handler {
	if deps.Ready == nil {
		deps.Ready = func() error { return nil }
	}

	router := chi.NewRouter()
	router.Use(requestIDMiddleware)
	router.Use(controlPlaneResponseHeaders)
	router.NotFound(func(w http.ResponseWriter, request *http.Request) {
		writeRequestProblem(w, request, http.StatusNotFound, "route_not_found", "The requested route does not exist")
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, request *http.Request) {
		writeRequestProblem(w, request, http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed for this route")
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
	router.Get("/api/v1/browser-config", browserConfigHandler(deps.BrowserConfig))
	router.With(authenticationMiddleware(deps.Authenticator)).Get("/api/v1/session", sessionHandler)
	router.Route("/api/v1", func(api chi.Router) {
		api.Group(func(governed chi.Router) {
			governed.Use(authenticationMiddleware(deps.Authenticator))
			governed.Get(
				"/workspaces/{workspaceID}/environments/{environmentID}/assets",
				listAssetsHandler(deps.Assets, deps.ControlPlaneCursor),
			)
			governed.Post(
				"/workspaces/{workspaceID}/environments/{environmentID}/assets",
				createAssetHandler(deps.Assets),
			)
			governed.Get(
				"/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}",
				getAssetHandler(deps.Assets),
			)
			governed.Patch(
				"/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}",
				patchAssetHandler(deps.Assets),
			)
			governed.Post(
				"/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}:quarantine",
				quarantineAssetHandler(deps.Assets),
			)
			governed.Post(
				"/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}:retire",
				retireAssetHandler(deps.Assets),
			)
			governed.Get(
				"/workspaces/{workspaceID}/environments/{environmentID}/asset-relations",
				listAssetRelationsHandler(deps.AssetRelations, deps.ControlPlaneCursor),
			)
			governed.Get(
				"/workspaces/{workspaceID}/environments/{environmentID}/service-asset-bindings",
				listServiceAssetBindingsHandler(deps.ServiceAssetBindings, deps.ControlPlaneCursor),
			)
			governed.Post(
				"/workspaces/{workspaceID}/environments/{environmentID}/service-asset-bindings",
				createServiceAssetBindingHandler(deps.ServiceAssetBindings),
			)
			governed.Delete(
				"/workspaces/{workspaceID}/environments/{environmentID}/service-asset-bindings/{bindingID}",
				deleteServiceAssetBindingHandler(deps.ServiceAssetBindings),
			)
			governed.Get(
				"/workspaces/{workspaceID}/asset-sources",
				listAssetSourcesHandler(deps.AssetSources, deps.ControlPlaneCursor),
			)
			governed.Get(
				"/workspaces/{workspaceID}/asset-sources/{sourceID}",
				getAssetSourceHandler(deps.AssetSources),
			)
			governed.Get(
				"/workspaces/{workspaceID}/asset-source-runs/{runID}",
				getAssetSourceRunHandler(deps.AssetSources),
			)
			governed.Get(
				"/workspaces/{workspaceID}/asset-conflicts",
				listAssetConflictsHandler(deps.AssetConflicts, deps.ControlPlaneCursor),
			)
			governed.Post(
				"/workspaces/{workspaceID}/asset-conflicts/{conflictID}:resolve",
				resolveAssetConflictHandler(deps.AssetConflicts),
			)
		})
	})
	router.With(authenticationMiddleware(deps.Authenticator)).Get(
		"/api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations",
		credentialRevocationListHandler(deps.CredentialRevocations),
	)
	router.With(authenticationMiddleware(deps.Authenticator)).Get(
		"/api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations/{revocationID}",
		credentialRevocationGetHandler(deps.CredentialRevocations),
	)
	router.With(authenticationMiddleware(deps.Authenticator)).Post(
		"/api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations/{revocationID}/requeues",
		credentialRevocationRequeueHandler(deps.CredentialRevocations),
	)
	router.With(authenticationMiddleware(deps.Authenticator)).Post(
		"/api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations/{revocationID}/external-confirmations",
		credentialRevocationConfirmationHandler(deps.CredentialRevocations),
	)

	if deps.WebUI != nil {
		return deps.WebUI.Wrap(router)
	}
	return router
}

func authenticationMiddleware(authenticator Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if nilHTTPDependency(authenticator) {
				writeRequestProblem(w, request, http.StatusServiceUnavailable, "authentication_unavailable", "OIDC authentication is unavailable")
				return
			}
			principal, err := authenticator.Authenticate(request)
			if err != nil {
				writeRequestProblem(w, request, http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required")
				return
			}
			next.ServeHTTP(w, request.WithContext(authn.WithPrincipal(request.Context(), principal)))
		})
	}
}

func nilHTTPDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return (reflected.Kind() == reflect.Chan || reflected.Kind() == reflect.Func || reflected.Kind() == reflect.Interface ||
		reflected.Kind() == reflect.Map || reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Slice) && reflected.IsNil()
}

func sessionHandler(w http.ResponseWriter, request *http.Request) {
	principal, ok := authn.PrincipalFromContext(request.Context())
	if !ok {
		writeRequestProblem(w, request, http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": principal.Subject, "username": principal.Username, "roles": principal.Roles,
		"workspace_ids": principal.WorkspaceIDs, "environment_ids": principal.EnvironmentIDs,
		"service_ids": principal.ServiceIDs, "authenticated_at": principal.AuthenticatedAt, "expires_at": principal.ExpiresAt,
	})
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestID := ids.NewUUID()
		traceID := traceIDFromRequest(request)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Trace-ID", traceID)
		ctx := requestmeta.With(request.Context(), requestmeta.Metadata{RequestID: requestID, TraceID: traceID})
		next.ServeHTTP(w, request.WithContext(ctx))
	})
}

func traceIDFromRequest(request *http.Request) string {
	parts := strings.Split(request.Header.Get("traceparent"), "-")
	if len(parts) == 4 && parts[0] == "00" && validHex(parts[1], 32) &&
		strings.Trim(parts[1], "0") != "" && validHex(parts[2], 16) && strings.Trim(parts[2], "0") != "" && validHex(parts[3], 2) {
		return strings.ToLower(parts[1])
	}
	return strings.ReplaceAll(ids.NewUUID(), "-", "")
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func webhookHandler(ingestor SignalIngestor, verifier WebhookVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if ingestor == nil {
			writeRequestProblem(w, request, http.StatusServiceUnavailable, "signal_ingestor_unavailable", "Signal ingestion is unavailable")
			return
		}
		if contentType := request.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
			writeRequestProblem(w, request, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}
		workspaceID := request.Header.Get("X-Workspace-ID")
		if workspaceID == "" {
			writeRequestProblem(w, request, http.StatusBadRequest, "workspace_required", "X-Workspace-ID is required")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 1<<20))
		if err != nil {
			writeRequestProblem(w, request, http.StatusRequestEntityTooLarge, "payload_too_large", "Webhook payload exceeds 1 MiB")
			return
		}
		if verifier == nil {
			writeRequestProblem(w, request, http.StatusServiceUnavailable, "webhook_verifier_unavailable", "Webhook verification is unavailable")
			return
		}
		integrationID := chi.URLParam(request, "integrationID")
		provider := chi.URLParam(request, "provider")
		if err := verifier.Verify(integrationID, provider, request.Header, body); err != nil {
			if errors.Is(err, webhook.ErrInvalidSignature) {
				writeRequestProblem(w, request, http.StatusUnauthorized, "invalid_webhook_signature", "Webhook signature is invalid")
			} else {
				writeRequestProblem(w, request, http.StatusServiceUnavailable, "webhook_verification_failed", "Webhook verification could not be completed")
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
				writeRequestProblem(w, request, http.StatusBadRequest, "invalid_signal_payload", "Signal payload is invalid")
			case errors.Is(err, signal.ErrUnsupportedProvider):
				writeRequestProblem(w, request, http.StatusNotFound, "unsupported_signal_provider", "Signal provider is not supported")
			case errors.Is(err, store.ErrIdempotencyConflict):
				writeRequestProblem(w, request, http.StatusConflict, "provider_event_conflict", "Provider event ID was reused with a different payload")
			case errors.Is(err, store.ErrScopeViolation):
				writeRequestProblem(w, request, http.StatusForbidden, "integration_scope_violation", "Integration is not authorized for this workspace or provider")
			case errors.Is(err, store.ErrNotFound):
				writeRequestProblem(w, request, http.StatusNotFound, "integration_not_found", "Integration was not found")
			default:
				writeRequestProblem(w, request, http.StatusInternalServerError, "signal_ingestion_failed", "Signal ingestion failed")
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
