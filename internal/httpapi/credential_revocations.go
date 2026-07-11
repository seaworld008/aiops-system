package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/credentialadmin"
)

const credentialManagementPathMarker = "/credential-revocations"

type CredentialRevocationManager interface {
	List(context.Context, authn.Principal, credentialadmin.ListRequest) (credential.ManagementPage, error)
	Get(context.Context, authn.Principal, credentialadmin.ItemRequest) (credential.ManagementRecord, error)
	Requeue(context.Context, authn.Principal, credentialadmin.ItemRequest) (credential.ManagementRecord, error)
	Confirm(context.Context, authn.Principal, credentialadmin.ConfirmationRequest) (credential.ManagementRecord, error)
}

type credentialRevocationResponse struct {
	ID                     string                      `json:"id"`
	WorkspaceID            string                      `json:"workspace_id"`
	EnvironmentID          string                      `json:"environment_id"`
	ActionID               string                      `json:"action_id"`
	TargetKey              string                      `json:"target_key"`
	ActionType             string                      `json:"action_type"`
	ConnectorID            string                      `json:"connector_id"`
	Status                 credential.RevocationStatus `json:"status"`
	AccessorPresent        bool                        `json:"accessor_present"`
	CredentialExpiresAt    time.Time                   `json:"credential_expires_at"`
	Attempt                int                         `json:"attempt"`
	FailureCount           int                         `json:"failure_count"`
	FailureCode            credential.FailureCode      `json:"failure_code,omitempty"`
	FailureDetailSHA256    string                      `json:"failure_detail_sha256,omitempty"`
	AvailableAt            time.Time                   `json:"available_at"`
	EvidenceHash           string                      `json:"evidence_hash,omitempty"`
	ConfirmationCount      int                         `json:"confirmation_count"`
	PlatformAdminConfirmed bool                        `json:"platform_admin_confirmed"`
	ManualRequiredAt       *time.Time                  `json:"manual_required_at,omitempty"`
	RevokedAt              *time.Time                  `json:"revoked_at,omitempty"`
	Version                int64                       `json:"version"`
	CreatedAt              time.Time                   `json:"created_at"`
	UpdatedAt              time.Time                   `json:"updated_at"`
}

type credentialRevocationPageResponse struct {
	Items      []credentialRevocationResponse `json:"items"`
	NextCursor string                         `json:"next_cursor,omitempty"`
}

func credentialManagementResponseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if isCredentialManagementPath(request.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		next.ServeHTTP(w, request)
	})
}

func isCredentialManagementPath(path string) bool {
	return strings.HasPrefix(path, "/api/v1/workspaces/") && strings.Contains(path, credentialManagementPathMarker)
}

func credentialRevocationListHandler(manager CredentialRevocationManager) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if credentialManagerUnavailable(manager) {
			writeProblem(w, http.StatusServiceUnavailable, "credential_revocation_management_unavailable", "Credential revocation management is unavailable")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required")
			return
		}
		managementRequest, err := parseCredentialRevocationListRequest(request)
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		page, err := manager.List(request.Context(), principal, managementRequest)
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		response := credentialRevocationPageResponse{
			Items: make([]credentialRevocationResponse, 0, len(page.Items)),
		}
		for _, record := range page.Items {
			response.Items = append(response.Items, credentialRevocationDTO(record))
		}
		if page.Next != nil {
			response.NextCursor = encodeManagementCursor(*page.Next)
		}
		writeJSON(w, http.StatusOK, response)
	}
}

func credentialRevocationGetHandler(manager CredentialRevocationManager) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if credentialManagerUnavailable(manager) {
			writeProblem(w, http.StatusServiceUnavailable, "credential_revocation_management_unavailable", "Credential revocation management is unavailable")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required")
			return
		}
		managementRequest, err := parseCredentialRevocationItemRequest(request)
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		record, err := manager.Get(request.Context(), principal, managementRequest)
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, credentialRevocationDTO(record))
	}
}

func credentialRevocationRequeueHandler(manager CredentialRevocationManager) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if credentialManagerUnavailable(manager) {
			writeProblem(w, http.StatusServiceUnavailable, "credential_revocation_management_unavailable", "Credential revocation management is unavailable")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required")
			return
		}
		managementRequest, err := parseCredentialRevocationItemRequest(request)
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 1))
		if err != nil || len(body) != 0 {
			writeCredentialManagementError(w, credentialadmin.ErrInvalidRequest)
			return
		}
		record, err := manager.Requeue(request.Context(), principal, managementRequest)
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, credentialRevocationDTO(record))
	}
}

func credentialRevocationConfirmationHandler(manager CredentialRevocationManager) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if credentialManagerUnavailable(manager) {
			writeProblem(w, http.StatusServiceUnavailable, "credential_revocation_management_unavailable", "Credential revocation management is unavailable")
			return
		}
		principal, ok := authn.PrincipalFromContext(request.Context())
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required")
			return
		}
		item, err := parseCredentialRevocationItemRequest(request)
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		contentTypes := request.Header.Values("Content-Type")
		if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
			writeProblem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 4<<10))
		if err != nil {
			var maximum *http.MaxBytesError
			if errors.As(err, &maximum) {
				writeProblem(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Credential revocation confirmation exceeds 4 KiB")
				return
			}
			writeCredentialManagementError(w, credentialadmin.ErrInvalidRequest)
			return
		}
		evidenceHash, err := decodeEvidenceHash(body)
		if err != nil || !credential.ValidSHA256(evidenceHash) {
			writeCredentialManagementError(w, credentialadmin.ErrInvalidRequest)
			return
		}
		record, err := manager.Confirm(request.Context(), principal, credentialadmin.ConfirmationRequest{
			WorkspaceID: item.WorkspaceID, EnvironmentID: item.EnvironmentID,
			RevocationID: item.RevocationID, EvidenceHash: evidenceHash,
		})
		if err != nil {
			writeCredentialManagementError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, credentialRevocationDTO(record))
	}
}

func decodeEvidenceHash(body []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", credentialadmin.ErrInvalidRequest
	}
	var evidenceHash string
	seen := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil || key != "evidence_hash" || seen {
			return "", credentialadmin.ErrInvalidRequest
		}
		if err := decoder.Decode(&evidenceHash); err != nil {
			return "", credentialadmin.ErrInvalidRequest
		}
		seen = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seen {
		return "", credentialadmin.ErrInvalidRequest
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", credentialadmin.ErrInvalidRequest
	}
	return evidenceHash, nil
}

func parseCredentialRevocationItemRequest(request *http.Request) (credentialadmin.ItemRequest, error) {
	result := credentialadmin.ItemRequest{
		WorkspaceID: chi.URLParam(request, "workspaceID"), EnvironmentID: chi.URLParam(request, "environmentID"),
		RevocationID: chi.URLParam(request, "revocationID"),
	}
	if !credential.ValidManagementScope(credential.ManagementScope{
		WorkspaceID: result.WorkspaceID, EnvironmentID: result.EnvironmentID,
	}) || !credential.ValidRevocationID(result.RevocationID) {
		return credentialadmin.ItemRequest{}, credentialadmin.ErrInvalidRequest
	}
	return result, nil
}

func parseCredentialRevocationListRequest(request *http.Request) (credentialadmin.ListRequest, error) {
	workspaceID := chi.URLParam(request, "workspaceID")
	environmentID := chi.URLParam(request, "environmentID")
	if !credential.ValidManagementScope(credential.ManagementScope{WorkspaceID: workspaceID, EnvironmentID: environmentID}) {
		return credentialadmin.ListRequest{}, credentialadmin.ErrInvalidRequest
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return credentialadmin.ListRequest{}, credentialadmin.ErrInvalidRequest
	}
	for key, values := range query {
		if (key != "status" && key != "limit" && key != "cursor") || len(values) != 1 || values[0] == "" {
			return credentialadmin.ListRequest{}, credentialadmin.ErrInvalidRequest
		}
	}
	result := credentialadmin.ListRequest{
		WorkspaceID: workspaceID, EnvironmentID: environmentID,
		Status: credential.StatusManualRequired, Limit: credential.DefaultManagementPageSize,
	}
	if values, ok := query["status"]; ok {
		result.Status = credential.RevocationStatus(values[0])
		if !credential.ValidRevocationStatus(result.Status) {
			return credentialadmin.ListRequest{}, credentialadmin.ErrInvalidRequest
		}
	}
	if values, ok := query["limit"]; ok {
		limit, err := strconv.Atoi(values[0])
		if err != nil || strconv.Itoa(limit) != values[0] || limit < 1 || limit > credential.MaxManagementPageSize {
			return credentialadmin.ListRequest{}, credentialadmin.ErrInvalidRequest
		}
		result.Limit = limit
	}
	if values, ok := query["cursor"]; ok {
		cursor, err := decodeManagementCursor(values[0])
		if err != nil {
			return credentialadmin.ListRequest{}, credentialadmin.ErrInvalidRequest
		}
		result.After = &cursor
	}
	return result, nil
}

func encodeManagementCursor(cursor credential.ManagementCursor) string {
	payload := "v1\n" + cursor.CreatedAt.UTC().Format(time.RFC3339Nano) + "\n" + cursor.RevocationID
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeManagementCursor(value string) (credential.ManagementCursor, error) {
	if len(value) > 512 || strings.Contains(value, "=") {
		return credential.ManagementCursor{}, credentialadmin.ErrInvalidRequest
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return credential.ManagementCursor{}, credentialadmin.ErrInvalidRequest
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 3 || parts[0] != "v1" {
		return credential.ManagementCursor{}, credentialadmin.ErrInvalidRequest
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339Nano) != parts[1] {
		return credential.ManagementCursor{}, credentialadmin.ErrInvalidRequest
	}
	cursor := credential.ManagementCursor{CreatedAt: createdAt, RevocationID: parts[2]}
	if !credential.ValidManagementCursor(&cursor) {
		return credential.ManagementCursor{}, credentialadmin.ErrInvalidRequest
	}
	return cursor, nil
}

func credentialManagerUnavailable(manager CredentialRevocationManager) bool {
	return nilHTTPDependency(manager)
}

func credentialRevocationDTO(record credential.ManagementRecord) credentialRevocationResponse {
	return credentialRevocationResponse{
		ID: record.ID, WorkspaceID: record.WorkspaceID, EnvironmentID: record.EnvironmentID,
		ActionID: record.ActionID, TargetKey: record.TargetKey, ActionType: record.ActionType, ConnectorID: record.ConnectorID,
		Status: record.Status, AccessorPresent: record.AccessorPresent, CredentialExpiresAt: record.CredentialExpiresAt.UTC(),
		Attempt: record.Attempt, FailureCount: record.FailureCount, FailureCode: record.FailureCode,
		FailureDetailSHA256: record.FailureDetailSHA256, AvailableAt: record.AvailableAt.UTC(), EvidenceHash: record.EvidenceHash,
		ConfirmationCount: record.ConfirmationCount, PlatformAdminConfirmed: record.PlatformAdminConfirmed,
		ManualRequiredAt: optionalTime(record.ManualRequiredAt), RevokedAt: optionalTime(record.RevokedAt),
		Version: record.Version, CreatedAt: record.CreatedAt.UTC(), UpdatedAt: record.UpdatedAt.UTC(),
	}
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func writeCredentialManagementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, credentialadmin.ErrInvalidRequest), errors.Is(err, credential.ErrInvalidRevocationRequest):
		writeProblem(w, http.StatusBadRequest, "invalid_credential_revocation_request", "Credential revocation management request is invalid")
	case errors.Is(err, credential.ErrRevocationNotFound):
		writeProblem(w, http.StatusNotFound, "credential_revocation_not_found", "Credential revocation was not found")
	case errors.Is(err, authz.ErrForbidden):
		writeProblem(w, http.StatusForbidden, "credential_revocation_forbidden", "Credential revocation operation is forbidden")
	case errors.Is(err, authz.ErrReauthenticationRequired):
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication"`)
		writeProblem(w, http.StatusUnauthorized, "credential_revocation_reauthentication_required", "Recent OIDC authentication is required")
	case errors.Is(err, credential.ErrInvalidTransition), errors.Is(err, credential.ErrEvidenceConflict),
		errors.Is(err, credential.ErrPlatformAdminRequired), errors.Is(err, credential.ErrIdempotencyConflict),
		errors.Is(err, credential.ErrCompletionConflict):
		writeProblem(w, http.StatusConflict, "credential_revocation_conflict", "Credential revocation state conflicts with this operation")
	case errors.Is(err, credential.ErrRevocationPersistence), errors.Is(err, context.DeadlineExceeded):
		writeProblem(w, http.StatusServiceUnavailable, "credential_revocation_management_unavailable", "Credential revocation management is unavailable")
	default:
		writeProblem(w, http.StatusInternalServerError, "credential_revocation_management_failed", "Credential revocation management failed")
	}
}
