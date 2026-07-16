package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/credentialadmin"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

const (
	httpWorkspaceID   = "11111111-1111-4111-8111-111111111111"
	httpEnvironmentID = "22222222-2222-4222-8222-222222222222"
	httpRevocationID  = "33333333-3333-4333-8333-333333333333"
	httpManagementURL = "/api/v1/workspaces/" + httpWorkspaceID + "/environments/" + httpEnvironmentID + "/credential-revocations"
	httpTraceparent   = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
)

func TestCredentialRevocationListUsesSafeNoStoreProjection(t *testing.T) {
	t.Parallel()

	record := validHTTPManagementRecord()
	manager := &credentialManagerStub{page: credential.ManagementPage{Items: []credential.ManagementRecord{record}}}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
		CredentialRevocations: manager,
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, httpManagementURL, nil))

	if response.Code != http.StatusOK {
		t.Fatalf("GET list response = %d %s", response.Code, response.Body.String())
	}
	assertCredentialManagementSecurityHeaders(t, response)
	if manager.listRequest.Status != credential.StatusManualRequired || manager.listRequest.Limit != credential.DefaultManagementPageSize ||
		manager.listRequest.WorkspaceID != httpWorkspaceID || manager.listRequest.EnvironmentID != httpEnvironmentID {
		t.Fatalf("List request = %#v", manager.listRequest)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("list response = %#v", body)
	}
	encoded := response.Body.String()
	for _, forbidden := range []string{
		"accessor_hmac", "encryption_key_id", "claim_token", "claimed_by", "runner_id", "tenant_id", "permission", "resource",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("safe response exposed forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func TestCredentialRevocationGetUsesExactPathScope(t *testing.T) {
	t.Parallel()

	manager := &credentialManagerStub{record: validHTTPManagementRecord()}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAuditor)},
		CredentialRevocations: manager,
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, httpManagementURL+"/"+httpRevocationID, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET item response = %d %s", response.Code, response.Body.String())
	}
	assertCredentialManagementSecurityHeaders(t, response)
	if manager.getRequest != (credentialadmin.ItemRequest{
		WorkspaceID: httpWorkspaceID, EnvironmentID: httpEnvironmentID, RevocationID: httpRevocationID,
	}) {
		t.Fatalf("Get request = %#v", manager.getRequest)
	}
}

func TestCredentialRevocationRequeueRequiresEmptyBody(t *testing.T) {
	t.Parallel()

	path := httpManagementURL + "/" + httpRevocationID + "/requeues"
	manager := &credentialManagerStub{record: validHTTPManagementRecord()}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAdmin)},
		CredentialRevocations: manager,
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
	if response.Code != http.StatusAccepted {
		t.Fatalf("POST requeue response = %d %s", response.Code, response.Body.String())
	}
	assertCredentialManagementSecurityHeaders(t, response)
	if manager.requeueRequest.RevocationID != httpRevocationID || manager.requeueRequest.WorkspaceID != httpWorkspaceID ||
		manager.requeueRequest.EnvironmentID != httpEnvironmentID {
		t.Fatalf("Requeue request = %#v", manager.requeueRequest)
	}

	for _, body := range []string{" ", "{}", "null"} {
		body := body
		t.Run("reject body "+body, func(t *testing.T) {
			manager := &credentialManagerStub{record: validHTTPManagementRecord()}
			router := httpapi.NewRouter(httpapi.Dependencies{
				Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAdmin)}, CredentialRevocations: manager,
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
			if response.Code != http.StatusBadRequest || manager.requeueRequest.RevocationID != "" {
				t.Fatalf("POST requeue body %q response/request = %d %s / %#v", body, response.Code, response.Body.String(), manager.requeueRequest)
			}
		})
	}
}

func TestCredentialRevocationConfirmationUsesStrictBoundedJSON(t *testing.T) {
	t.Parallel()

	path := httpManagementURL + "/" + httpRevocationID + "/external-confirmations"
	evidenceHash := credential.SHA256Hex([]byte("external-evidence"))
	manager := &credentialManagerStub{record: validHTTPManagementRecord()}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
		CredentialRevocations: manager,
	})
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"evidence_hash":"`+evidenceHash+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("POST confirmation response = %d %s", response.Code, response.Body.String())
	}
	if manager.confirmationRequest.EvidenceHash != evidenceHash || manager.confirmationRequest.RevocationID != httpRevocationID {
		t.Fatalf("Confirmation request = %#v", manager.confirmationRequest)
	}

	invalidBodies := map[string]string{
		"missing field":     `{}`,
		"unknown field":     `{"evidence_hash":"` + evidenceHash + `","subject":"forged"}`,
		"duplicate field":   `{"evidence_hash":"` + evidenceHash + `","evidence_hash":"` + evidenceHash + `"}`,
		"trailing value":    `{"evidence_hash":"` + evidenceHash + `"}{}`,
		"uppercase hash":    `{"evidence_hash":"` + strings.ToUpper(evidenceHash) + `"}`,
		"non-object":        `[]`,
		"oversized payload": `{"evidence_hash":"` + strings.Repeat("a", 4097) + `"}`,
	}
	for name, body := range invalidBodies {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			manager := &credentialManagerStub{record: validHTTPManagementRecord()}
			router := httpapi.NewRouter(httpapi.Dependencies{
				Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)}, CredentialRevocations: manager,
			})
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			wantStatus := http.StatusBadRequest
			if name == "oversized payload" {
				wantStatus = http.StatusRequestEntityTooLarge
			}
			if response.Code != wantStatus || manager.confirmationRequest.RevocationID != "" {
				t.Fatalf("response/request = %d %s / %#v", response.Code, response.Body.String(), manager.confirmationRequest)
			}
		})
	}

	for _, contentType := range []string{"", "text/plain", "application/json; charset=utf-8"} {
		contentType := contentType
		t.Run("content type "+contentType, func(t *testing.T) {
			manager := &credentialManagerStub{record: validHTTPManagementRecord()}
			router := httpapi.NewRouter(httpapi.Dependencies{
				Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)}, CredentialRevocations: manager,
			})
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"evidence_hash":"`+evidenceHash+`"}`))
			if contentType != "" {
				request.Header.Set("Content-Type", contentType)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnsupportedMediaType || manager.confirmationRequest.RevocationID != "" {
				t.Fatalf("response/request = %d %s / %#v", response.Code, response.Body.String(), manager.confirmationRequest)
			}
		})
	}
	t.Run("duplicate content type", func(t *testing.T) {
		manager := &credentialManagerStub{record: validHTTPManagementRecord()}
		router := httpapi.NewRouter(httpapi.Dependencies{
			Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)}, CredentialRevocations: manager,
		})
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"evidence_hash":"`+evidenceHash+`"}`))
		request.Header.Add("Content-Type", "application/json")
		request.Header.Add("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnsupportedMediaType || manager.confirmationRequest.RevocationID != "" {
			t.Fatalf("response/request = %d %s / %#v", response.Code, response.Body.String(), manager.confirmationRequest)
		}
	})
}

func TestCredentialRevocationProblemsCarryRequestTraceAcrossHandlerFailures(t *testing.T) {
	t.Parallel()

	confirmationPath := httpManagementURL + "/" + httpRevocationID + "/external-confirmations"
	tests := []struct {
		name         string
		deps         httpapi.Dependencies
		method       string
		path         string
		body         string
		contentTypes []string
		wantStatus   int
		wantCode     string
		wantDetail   string
	}{
		{
			name: "manager nil",
			deps: httpapi.Dependencies{
				Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAdmin)},
			},
			method: http.MethodGet, path: httpManagementURL,
			wantStatus: http.StatusServiceUnavailable, wantCode: "credential_revocation_management_unavailable",
			wantDetail: "Credential revocation management is unavailable",
		},
		{
			name:   "authentication unavailable",
			deps:   httpapi.Dependencies{},
			method: http.MethodGet, path: httpManagementURL,
			wantStatus: http.StatusServiceUnavailable, wantCode: "authentication_unavailable",
			wantDetail: "OIDC authentication is unavailable",
		},
		{
			name: "authentication required",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{err: authn.ErrUnauthenticated},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodGet, path: httpManagementURL,
			wantStatus: http.StatusUnauthorized, wantCode: "authentication_required",
			wantDetail: "A valid OIDC bearer token is required",
		},
		{
			name: "list query parse",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodGet, path: httpManagementURL + "?limit=0",
			wantStatus: http.StatusBadRequest, wantCode: "invalid_credential_revocation_request",
			wantDetail: "Credential revocation management request is invalid",
		},
		{
			name: "item path parse",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodGet, path: httpManagementURL + "/NOT-A-UUID",
			wantStatus: http.StatusBadRequest, wantCode: "invalid_credential_revocation_request",
			wantDetail: "Credential revocation management request is invalid",
		},
		{
			name: "requeue body",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAdmin)},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodPost, path: httpManagementURL + "/" + httpRevocationID + "/requeues", body: "{}",
			wantStatus: http.StatusBadRequest, wantCode: "invalid_credential_revocation_request",
			wantDetail: "Credential revocation management request is invalid",
		},
		{
			name: "confirmation media",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodPost, path: confirmationPath, body: "{}",
			wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type",
			wantDetail: "Content-Type must be application/json",
		},
		{
			name: "confirmation duplicate media",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodPost, path: confirmationPath, body: "{}",
			contentTypes: []string{"application/json", "application/json"},
			wantStatus:   http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type",
			wantDetail: "Content-Type must be application/json",
		},
		{
			name: "confirmation body",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodPost, path: confirmationPath, body: "{}",
			contentTypes: []string{"application/json"},
			wantStatus:   http.StatusBadRequest, wantCode: "invalid_credential_revocation_request",
			wantDetail: "Credential revocation management request is invalid",
		},
		{
			name: "confirmation too large",
			deps: httpapi.Dependencies{
				Authenticator:         fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)},
				CredentialRevocations: &credentialManagerStub{},
			},
			method: http.MethodPost, path: confirmationPath,
			body:         `{"evidence_hash":"` + strings.Repeat("a", 4097) + `"}`,
			contentTypes: []string{"application/json"},
			wantStatus:   http.StatusRequestEntityTooLarge, wantCode: "payload_too_large",
			wantDetail: "Credential revocation confirmation exceeds 4 KiB",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			for _, contentType := range test.contentTypes {
				request.Header.Add("Content-Type", contentType)
			}
			response := httptest.NewRecorder()
			httpapi.NewRouter(test.deps).ServeHTTP(response, request)
			assertCredentialManagementProblem(
				t, response, test.wantStatus, test.wantCode, test.wantDetail,
			)
		})
	}
}

func TestCredentialRevocationListParsesStrictKeysetCursorAndFilters(t *testing.T) {
	t.Parallel()

	record := validHTTPManagementRecord()
	next := credential.ManagementCursor{CreatedAt: record.CreatedAt, RevocationID: record.ID}
	manager := &credentialManagerStub{page: credential.ManagementPage{
		Items: []credential.ManagementRecord{record}, Next: &next,
	}}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)}, CredentialRevocations: manager,
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, httpManagementURL, nil))
	var first struct {
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &first); err != nil || first.NextCursor == "" {
		t.Fatalf("first page cursor = %q, %v; body=%s", first.NextCursor, err, response.Body.String())
	}

	manager.page = credential.ManagementPage{Items: []credential.ManagementRecord{record}}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		httpManagementURL+"?status=MANUAL_REQUIRED&limit=100&cursor="+first.NextCursor, nil))
	if response.Code != http.StatusOK || manager.listRequest.After == nil {
		t.Fatalf("second page response/request = %d %s / %#v", response.Code, response.Body.String(), manager.listRequest)
	}
	if manager.listRequest.Limit != 100 || manager.listRequest.Status != credential.StatusManualRequired ||
		!manager.listRequest.After.CreatedAt.Equal(next.CreatedAt) || manager.listRequest.After.RevocationID != next.RevocationID {
		t.Fatalf("second page request = %#v", manager.listRequest)
	}

	invalidQueries := []string{
		"?unknown=value", "?status=", "?status=INVALID", "?limit=0", "?limit=101", "?limit=01", "?limit=abc",
		"?limit=1&limit=2", "?cursor=bad+cursor", "?cursor=" + first.NextCursor + "=", "?cursor=" + strings.Repeat("a", 513),
		"?status=%zz", "?status=MANUAL_REQUIRED;limit=1",
	}
	for _, query := range invalidQueries {
		query := query
		t.Run(query, func(t *testing.T) {
			manager := &credentialManagerStub{}
			router := httpapi.NewRouter(httpapi.Dependencies{
				Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)}, CredentialRevocations: manager,
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, httpManagementURL+query, nil))
			if response.Code != http.StatusBadRequest || manager.listRequest.WorkspaceID != "" {
				t.Fatalf("response/request = %d %s / %#v", response.Code, response.Body.String(), manager.listRequest)
			}
		})
	}
}

func TestCredentialRevocationPathsRequireCanonicalUUIDs(t *testing.T) {
	t.Parallel()

	manager := &credentialManagerStub{}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)}, CredentialRevocations: manager,
	})
	paths := []string{
		"/api/v1/workspaces/not-a-uuid/environments/" + httpEnvironmentID + "/credential-revocations",
		httpManagementURL + "/NOT-A-UUID",
		httpManagementURL + "/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
	}
	for _, path := range paths {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("GET %s response = %d %s", path, response.Code, response.Body.String())
		}
	}
}

func TestCredentialRevocationErrorsUseUniformProblemMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantDetail string
		wantWWW    string
	}{
		{
			name:       "management invalid request",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credentialadmin.ErrInvalidRequest),
			wantStatus: http.StatusBadRequest, wantCode: "invalid_credential_revocation_request",
			wantDetail: "Credential revocation management request is invalid",
		},
		{
			name:       "credential invalid request",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrInvalidRevocationRequest),
			wantStatus: http.StatusBadRequest, wantCode: "invalid_credential_revocation_request",
			wantDetail: "Credential revocation management request is invalid",
		},
		{
			name:       "not found",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrRevocationNotFound),
			wantStatus: http.StatusNotFound, wantCode: "credential_revocation_not_found",
			wantDetail: "Credential revocation was not found",
		},
		{
			name:       "forbidden role",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", authz.ErrForbidden),
			wantStatus: http.StatusForbidden, wantCode: "credential_revocation_forbidden",
			wantDetail: "Credential revocation operation is forbidden",
		},
		{
			name:       "reauthentication required",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", authz.ErrReauthenticationRequired),
			wantStatus: http.StatusUnauthorized, wantCode: "credential_revocation_reauthentication_required",
			wantDetail: "Recent OIDC authentication is required",
			wantWWW:    `Bearer error="insufficient_user_authentication"`,
		},
		{
			name:       "invalid transition",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrInvalidTransition),
			wantStatus: http.StatusConflict, wantCode: "credential_revocation_conflict",
			wantDetail: "Credential revocation state conflicts with this operation",
		},
		{
			name:       "evidence conflict",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrEvidenceConflict),
			wantStatus: http.StatusConflict, wantCode: "credential_revocation_conflict",
			wantDetail: "Credential revocation state conflicts with this operation",
		},
		{
			name:       "admin required",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrPlatformAdminRequired),
			wantStatus: http.StatusConflict, wantCode: "credential_revocation_conflict",
			wantDetail: "Credential revocation state conflicts with this operation",
		},
		{
			name:       "idempotency conflict",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrIdempotencyConflict),
			wantStatus: http.StatusConflict, wantCode: "credential_revocation_conflict",
			wantDetail: "Credential revocation state conflicts with this operation",
		},
		{
			name:       "completion conflict",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrCompletionConflict),
			wantStatus: http.StatusConflict, wantCode: "credential_revocation_conflict",
			wantDetail: "Credential revocation state conflicts with this operation",
		},
		{
			name:       "persistence unavailable",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credential.ErrRevocationPersistence),
			wantStatus: http.StatusServiceUnavailable, wantCode: "credential_revocation_management_unavailable",
			wantDetail: "Credential revocation management is unavailable",
		},
		{
			name:       "deadline unavailable",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", context.DeadlineExceeded),
			wantStatus: http.StatusServiceUnavailable, wantCode: "credential_revocation_management_unavailable",
			wantDetail: "Credential revocation management is unavailable",
		},
		{
			name:       "unsafe store result",
			err:        fmt.Errorf("underlying-sensitive-marker: %w", credentialadmin.ErrUnsafeStoreResult),
			wantStatus: http.StatusInternalServerError, wantCode: "credential_revocation_management_failed",
			wantDetail: "Credential revocation management failed",
		},
		{
			name:       "unknown failure",
			err:        fmt.Errorf("underlying-sensitive-marker: postgres://operator:secret@private-endpoint"),
			wantStatus: http.StatusInternalServerError, wantCode: "credential_revocation_management_failed",
			wantDetail: "Credential revocation management failed",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			manager := &credentialManagerStub{err: test.err}
			router := httpapi.NewRouter(httpapi.Dependencies{
				Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAdmin)}, CredentialRevocations: manager,
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, httpManagementURL+"/"+httpRevocationID, nil))
			assertCredentialManagementProblem(
				t, response, test.wantStatus, test.wantCode, test.wantDetail,
			)
			if got := response.Header().Get("WWW-Authenticate"); got != test.wantWWW {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, test.wantWWW)
			}
		})
	}
}

func TestCredentialRevocationCrossScopeAndUnknownAreIndistinguishable(t *testing.T) {
	t.Parallel()

	manager := &credentialManagerStub{err: credential.ErrRevocationNotFound}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleSRE)}, CredentialRevocations: manager,
	})
	paths := []string{
		httpManagementURL + "/" + httpRevocationID,
		"/api/v1/workspaces/44444444-4444-4444-8444-444444444444/environments/" + httpEnvironmentID +
			"/credential-revocations/55555555-5555-4555-8555-555555555555",
	}
	var firstBody string
	for _, path := range paths {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("traceparent", httpTraceparent)
		router.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("GET %s response = %d %s", path, response.Code, response.Body.String())
		}
		assertCredentialManagementProblem(
			t, response, http.StatusNotFound,
			"credential_revocation_not_found", "Credential revocation was not found",
		)
		if firstBody == "" {
			firstBody = response.Body.String()
		} else if response.Body.String() != firstBody {
			t.Fatalf("404 bodies differ: %q / %q", firstBody, response.Body.String())
		}
	}
}

func TestCredentialManagementHeadersCoverAuthenticationNotFoundAndMethodNotAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		path   string
		deps   httpapi.Dependencies
		status int
		code   string
		detail string
	}{
		{
			http.MethodGet, httpManagementURL, httpapi.Dependencies{},
			http.StatusServiceUnavailable, "authentication_unavailable", "OIDC authentication is unavailable",
		},
		{
			http.MethodGet, httpManagementURL,
			httpapi.Dependencies{Authenticator: fakeAuthenticator{err: authn.ErrUnauthenticated}},
			http.StatusUnauthorized, "authentication_required", "A valid OIDC bearer token is required",
		},
		{
			http.MethodGet, httpManagementURL + "/" + httpRevocationID + "/unknown", httpapi.Dependencies{},
			http.StatusNotFound, "route_not_found", "The requested route does not exist",
		},
		{
			http.MethodPut, httpManagementURL, httpapi.Dependencies{},
			http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed for this route",
		},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		httpapi.NewRouter(test.deps).ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		assertCredentialManagementProblem(t, response, test.status, test.code, test.detail)
	}
}

func TestCredentialRevocationManagementIsUnavailableWithoutDurableManager(t *testing.T) {
	t.Parallel()

	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAdmin)},
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, httpManagementURL, nil))
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"credential_revocation_management_unavailable"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	assertCredentialManagementProblem(
		t, response, http.StatusServiceUnavailable,
		"credential_revocation_management_unavailable", "Credential revocation management is unavailable",
	)

	var typedNil *credentialManagerStub
	router = httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: validHTTPPrincipal(authn.RoleAdmin)}, CredentialRevocations: typedNil,
	})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, httpManagementURL, nil))
	assertCredentialManagementProblem(
		t, response, http.StatusServiceUnavailable,
		"credential_revocation_management_unavailable", "Credential revocation management is unavailable",
	)
}

type credentialManagerStub struct {
	page                credential.ManagementPage
	record              credential.ManagementRecord
	err                 error
	listRequest         credentialadmin.ListRequest
	getRequest          credentialadmin.ItemRequest
	requeueRequest      credentialadmin.ItemRequest
	confirmationRequest credentialadmin.ConfirmationRequest
}

func (stub *credentialManagerStub) List(_ context.Context, _ authn.Principal, request credentialadmin.ListRequest) (credential.ManagementPage, error) {
	stub.listRequest = request
	return stub.page, stub.err
}

func (stub *credentialManagerStub) Get(_ context.Context, _ authn.Principal, request credentialadmin.ItemRequest) (credential.ManagementRecord, error) {
	stub.getRequest = request
	return stub.record, stub.err
}

func (stub *credentialManagerStub) Requeue(_ context.Context, _ authn.Principal, request credentialadmin.ItemRequest) (credential.ManagementRecord, error) {
	stub.requeueRequest = request
	return stub.record, stub.err
}

func (stub *credentialManagerStub) Confirm(_ context.Context, _ authn.Principal, request credentialadmin.ConfirmationRequest) (credential.ManagementRecord, error) {
	stub.confirmationRequest = request
	return stub.record, stub.err
}

func validHTTPPrincipal(roles ...authn.Role) authn.Principal {
	now := time.Now().UTC()
	return authn.Principal{
		Subject: "subject-1", Roles: roles,
		WorkspaceIDs: []string{httpWorkspaceID}, EnvironmentIDs: []string{httpEnvironmentID},
		AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func validHTTPManagementRecord() credential.ManagementRecord {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	return credential.ManagementRecord{
		ID: httpRevocationID, WorkspaceID: httpWorkspaceID, EnvironmentID: httpEnvironmentID,
		ActionID: "action-1", TargetKey: "kubernetes:cluster/ns/deployment", ActionType: "KUBERNETES_SCALE",
		ConnectorID: "connector-1", Status: credential.StatusManualRequired, AccessorPresent: true,
		CredentialExpiresAt: now.Add(-5 * time.Minute), Attempt: 12, FailureCount: 12,
		FailureCode: credential.FailureTimeout, FailureDetailSHA256: credential.SHA256Hex([]byte("sanitized")),
		AvailableAt: now, ManualRequiredAt: now, Version: 13, CreatedAt: now.Add(-10 * time.Minute), UpdatedAt: now,
	}
}

func assertCredentialManagementSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func assertCredentialManagementProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantStatus int,
	wantCode string,
	wantDetail string,
) {
	t.Helper()
	if response.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, wantStatus, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", got)
	}
	assertCredentialManagementSecurityHeaders(t, response)
	responseTraceID := response.Header().Get("X-Trace-ID")
	if len(responseTraceID) != 32 || responseTraceID != strings.ToLower(responseTraceID) ||
		strings.Trim(responseTraceID, "0123456789abcdef") != "" || strings.Trim(responseTraceID, "0") == "" {
		t.Fatalf("X-Trace-ID = %q, want a non-zero lowercase 32-character hex trace ID", responseTraceID)
	}
	var problem struct {
		Type    string `json:"type"`
		Title   string `json:"title"`
		Status  int    `json:"status"`
		Code    string `json:"code"`
		Detail  string `json:"detail"`
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode Problem: %v; body=%s", err, response.Body.String())
	}
	if problem.Type != "about:blank" || problem.Title != http.StatusText(wantStatus) ||
		problem.Status != wantStatus || problem.Code != wantCode || problem.Detail != wantDetail {
		t.Fatalf("Problem = %#v", problem)
	}
	if problem.TraceID == "" || problem.TraceID != responseTraceID {
		t.Fatalf("Problem trace_id = %q, X-Trace-ID = %q", problem.TraceID, responseTraceID)
	}
	if strings.Contains(strings.ToLower(response.Body.String()), "underlying-sensitive-marker") {
		t.Fatalf("Problem leaked the underlying error: %s", response.Body.String())
	}
}
