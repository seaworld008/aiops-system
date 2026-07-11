package runnergateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const testLeaseToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNewRouterRequiresTrustDependencies(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	var nilVerifier *staticVerifier
	var nilBackend *fakeBackend
	for _, dependencies := range []struct {
		verifier IdentityVerifier
		backend  Backend
	}{
		{nil, &fakeBackend{}}, {nilVerifier, &fakeBackend{}}, {&staticVerifier{identity: identity}, nil},
		{&staticVerifier{identity: identity}, nilBackend},
	} {
		if handler, err := NewRouter(dependencies.verifier, dependencies.backend); err == nil || handler != nil {
			t.Fatalf("NewRouter(%T, %T) = %#v, %v; want fail closed", dependencies.verifier, dependencies.backend, handler, err)
		}
	}
}

func TestRouterReauthenticatesEveryKeepaliveRequestAndRejectsIdentityHeaders(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	verifier := &staticVerifier{identity: identity}
	backend := &fakeBackend{identityResponse: validIdentityResponse(identity)}
	handler := mustRouter(t, verifier, backend)

	for range 2 {
		response := serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
		assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	}
	if verifier.calls != 2 || backend.authCalls != 2 || backend.identityCalls != 2 {
		t.Fatalf("keepalive calls verifier/auth/identity = %d/%d/%d, want 2/2/2", verifier.calls, backend.authCalls, backend.identityCalls)
	}

	response := serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, http.Header{
		"X-Forwarded-Client-Cert": {"forged"},
	})
	assertProblem(t, response, http.StatusBadRequest, "urn:aiops:problem:runner:forbidden-identity-field", "forbidden_runner_identity_field")
	if verifier.calls != 3 || backend.authCalls != 3 || backend.identityCalls != 2 {
		t.Fatal("malformed keepalive request was not authenticated exactly once before shape rejection")
	}
}

func TestIdentityRejectsContentEncodingBeforeItsHandler(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	backend := &fakeBackend{identityResponse: validIdentityResponse(identity)}
	handler := mustRouter(t, &staticVerifier{identity: identity}, backend)
	response := serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, http.Header{"Content-Encoding": {"gzip"}})
	assertProblemCode(t, response, http.StatusUnsupportedMediaType, "runner_unsupported_media_type")
	if backend.authCalls != 1 || backend.identityCalls != 0 {
		t.Fatalf("content-encoded identity request calls auth/handler = %d/%d", backend.authCalls, backend.identityCalls)
	}
}

func TestRouterRejectsRequestsWithoutVerifiedTLSIdentity(t *testing.T) {
	t.Parallel()
	verifier := &staticVerifier{err: runneridentity.ErrAuthenticationFailed}
	handler := mustRouter(t, verifier, &fakeBackend{})
	request := httptest.NewRequest(http.MethodGet, "/runner/v1/identity", nil)
	request.TLS = nil
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assertProblem(t, recorder.Result(), http.StatusForbidden, "urn:aiops:problem:runner:identity-rejected", "runner_identity_rejected")
	if verifier.calls != 0 {
		t.Fatal("nil TLS state reached identity verifier")
	}

	response := serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
	assertProblem(t, response, http.StatusForbidden, "urn:aiops:problem:runner:identity-rejected", "runner_identity_rejected")
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
}

func TestRouterRechecksServerSideRegistrationBeforeParsingEveryRequest(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	backend := &fakeBackend{authErr: ErrForbidden, identityResponse: validIdentityResponse(identity)}
	handler := mustRouter(t, &staticVerifier{identity: identity}, backend)
	response := serve(t, handler, http.MethodPost, "/runner/v1/jobs:lease", []byte(`not-json`), nil)
	assertProblemCode(t, response, http.StatusForbidden, "runner_identity_rejected")
	if backend.authCalls != 1 || backend.identityCalls != 0 {
		t.Fatalf("request auth/handler calls = %d/%d", backend.authCalls, backend.identityCalls)
	}

	backend.authErr = ErrUnavailable
	response = serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
	assertProblemCode(t, response, http.StatusServiceUnavailable, "runner_dependency_unavailable")
	if backend.authCalls != 2 || backend.identityCalls != 0 {
		t.Fatalf("unavailable auth/handler calls = %d/%d", backend.authCalls, backend.identityCalls)
	}
}

func TestRouterRejectsDetachedServerSidePrincipalBeforeBackendDispatch(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	for _, mutate := range []func(*testPrincipal){
		func(principal *testPrincipal) { principal.pool = runneridentity.PoolWrite },
		func(principal *testPrincipal) { principal.certificateSHA256 = strings.Repeat("f", 64) },
		func(principal *testPrincipal) { principal.scopeRevision = 0 },
		func(principal *testPrincipal) { principal.maxConcurrency = 0 },
		func(principal *testPrincipal) { principal.tenantID = "not-a-tenant" },
	} {
		principal := testPrincipalForIdentity(identity, false)
		mutate(principal)
		backend := &fakeBackend{principal: principal, identityResponse: validIdentityResponse(identity)}
		handler := mustRouter(t, &staticVerifier{identity: identity}, backend)
		response := serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
		assertProblemCode(t, response, http.StatusForbidden, "runner_identity_rejected")
		if backend.identityCalls != 0 {
			t.Fatal("detached principal reached identity backend")
		}
	}
}

func TestRouterEnforcesStrictJSONAndEndpointBodyLimits(t *testing.T) {
	t.Parallel()
	handler := mustRouter(t, &staticVerifier{identity: testIdentity(t)}, &fakeBackend{})
	tests := []struct {
		name       string
		body       []byte
		headers    http.Header
		wantStatus int
		wantCode   string
	}{
		{name: "duplicate", body: []byte(`{"schema_version":"runner-job-lease-request.v1","schema_version":"runner-job-lease-request.v1"}`), wantStatus: 400, wantCode: "invalid_runner_json"},
		{name: "escaped duplicate", body: []byte(`{"schema_version":"runner-job-lease-request.v1","schema_\u0076ersion":"runner-job-lease-request.v1"}`), wantStatus: 400, wantCode: "invalid_runner_json"},
		{name: "unknown", body: []byte(`{"schema_version":"runner-job-lease-request.v1","runner_id":"forged"}`), wantStatus: 400, wantCode: "invalid_runner_json"},
		{name: "case folded field", body: []byte(`{"SCHEMA_VERSION":"runner-job-lease-request.v1"}`), wantStatus: 400, wantCode: "invalid_runner_json"},
		{name: "trailing", body: []byte(`{"schema_version":"runner-job-lease-request.v1"}{}`), wantStatus: 400, wantCode: "invalid_runner_json"},
		{name: "invalid UTF-8", body: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, wantStatus: 400, wantCode: "invalid_runner_json"},
		{name: "missing content type", body: []byte(`{"schema_version":"runner-job-lease-request.v1"}`), headers: http.Header{"Content-Type": nil}, wantStatus: 415, wantCode: "runner_unsupported_media_type"},
		{name: "content type parameters", body: []byte(`{"schema_version":"runner-job-lease-request.v1"}`), headers: http.Header{"Content-Type": {"application/json; charset=utf-8"}}, wantStatus: 415, wantCode: "runner_unsupported_media_type"},
		{name: "content encoding", body: []byte(`{"schema_version":"runner-job-lease-request.v1"}`), headers: http.Header{"Content-Encoding": {"gzip"}}, wantStatus: 415, wantCode: "runner_unsupported_media_type"},
		{name: "wrong schema", body: []byte(`{"schema_version":"runner-job-lease-request.v2"}`), wantStatus: 400, wantCode: "invalid_runner_request"},
		{name: "unexpected authorization", body: []byte(`{"schema_version":"runner-job-lease-request.v1"}`), headers: http.Header{"Authorization": {"AIOPS-Job-Lease " + testLeaseToken}}, wantStatus: 400, wantCode: "invalid_runner_request"},
		{name: "over limit", body: bytes.Repeat([]byte{' '}, int(leaseBodyLimit+1)), wantStatus: 413, wantCode: "runner_payload_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := test.headers.Clone()
			if headers == nil {
				headers = make(http.Header)
			}
			if _, exists := headers["Content-Type"]; !exists {
				headers.Set("Content-Type", "application/json")
			}
			response := serve(t, handler, http.MethodPost, "/runner/v1/jobs:lease", test.body, headers)
			assertProblemCode(t, response, test.wantStatus, test.wantCode)
		})
	}
}

func TestRouterRequiresOneExactLeaseAuthorizationAndNeverAcceptsEncodedPaths(t *testing.T) {
	t.Parallel()
	backend := &fakeBackend{startResponse: validStartResponse()}
	handler := mustRouter(t, &staticVerifier{identity: testIdentityForPool(t, runneridentity.PoolWrite)}, backend)
	body := []byte(`{"schema_version":"runner-job-start-request.v1","lease_epoch":"1"}`)
	for _, authorization := range [][]string{
		nil,
		{"Bearer " + testLeaseToken},
		{"AIOPS-Job-Lease short"},
		{"AIOPS-Job-Lease " + testLeaseToken + " "},
		{"AIOPS-Job-Lease " + testLeaseToken, "AIOPS-Job-Lease " + testLeaseToken},
	} {
		headers := http.Header{"Content-Type": {"application/json"}, "Authorization": authorization}
		response := serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:start", body, headers)
		assertProblemCode(t, response, http.StatusUnauthorized, "runner_lease_authentication_failed")
		if response.Header.Get("WWW-Authenticate") == "" {
			t.Fatal("401 response lacks WWW-Authenticate")
		}
	}

	headers := http.Header{"Content-Type": {"application/json"}, "Authorization": {"AIOPS-Job-Lease " + testLeaseToken}}
	response := serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:start", body, headers)
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)
	if backend.lastResourceID != "job-1" || backend.lastToken != testLeaseToken || backend.startCalls != 1 {
		t.Fatalf("backend fence = %q/%q calls=%d", backend.lastResourceID, backend.lastToken, backend.startCalls)
	}

	response = serve(t, handler, http.MethodPost, "/runner/v1/jobs/job%2fother:start", body, headers)
	assertProblemCode(t, response, http.StatusBadRequest, "forbidden_runner_identity_field")
}

func TestRouterRejectsReadPoolBeforeWriteBackendDispatch(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	backend := &fakeBackend{startResponse: validStartResponse()}
	handler := mustRouter(t, &staticVerifier{identity: identity}, backend)
	response := serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:start",
		[]byte(`{"schema_version":"runner-job-start-request.v1","lease_epoch":"1"}`),
		http.Header{"Content-Type": {"application/json"}, "Authorization": {"AIOPS-Job-Lease " + testLeaseToken}},
	)
	assertProblemCode(t, response, http.StatusForbidden, "runner_identity_rejected")
	if backend.startCalls != 0 {
		t.Fatalf("READ request reached WRITE start backend %d times", backend.startCalls)
	}

	response = serve(t, handler, http.MethodPost, "/runner/v1/jobs:lease",
		[]byte(`{"schema_version":"runner-job-lease-request.v1"}`), http.Header{"Content-Type": {"application/json"}})
	assertStatusAndBoundaryHeaders(t, response, http.StatusNoContent)
	if backend.leaseCalls != 0 {
		t.Fatalf("READ no-job request reached WRITE queue backend %d times", backend.leaseCalls)
	}
}

func TestRouterRejectsRevocationLeaseWithoutCapabilityBeforeBackendDispatch(t *testing.T) {
	t.Parallel()
	identity := testIdentityForPool(t, runneridentity.PoolWrite)
	backend := &fakeBackend{}
	handler := mustRouter(t, &staticVerifier{identity: identity}, backend)
	response := serve(t, handler, http.MethodPost, "/runner/v1/revocations:lease",
		[]byte(`{"schema_version":"runner-revocation-lease-request.v1"}`),
		http.Header{"Content-Type": {"application/json"}},
	)
	assertProblemCode(t, response, http.StatusForbidden, "runner_identity_rejected")
	if backend.revocationLeaseCalls != 0 {
		t.Fatalf("Runner without revocation capability reached backend %d times", backend.revocationLeaseCalls)
	}
}

func TestRouterRejectsCaseFoldedNestedJSONFields(t *testing.T) {
	t.Parallel()
	handler := mustRouter(t,
		&staticVerifier{identity: testIdentityForPool(t, runneridentity.PoolWrite)},
		&fakeBackend{completeResponse: validCompletionResponse("FINALIZING")},
	)
	response := serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:complete",
		[]byte(`{"schema_version":"runner-job-complete-request.v1","lease_epoch":"1","result":{"Outcome":"SUCCEEDED","code":"OK","verification":"PASSED","changed":true}}`),
		http.Header{"Content-Type": {"application/json"}, "Authorization": {"AIOPS-Job-Lease " + testLeaseToken}},
	)
	assertProblemCode(t, response, http.StatusBadRequest, "invalid_runner_json")
}

func TestRouterNoJobAndUnknownRoutesStillCarrySecurityHeaders(t *testing.T) {
	t.Parallel()
	handler := mustRouter(t, &staticVerifier{identity: testIdentity(t)}, &fakeBackend{})
	headers := http.Header{"Content-Type": {"application/json"}}
	response := serve(t, handler, http.MethodPost, "/runner/v1/jobs:lease", []byte(`{"schema_version":"runner-job-lease-request.v1"}`), headers)
	assertStatusAndBoundaryHeaders(t, response, http.StatusNoContent)
	if body := readBody(t, response); len(body) != 0 {
		t.Fatalf("204 body = %q", body)
	}

	response = serve(t, handler, http.MethodGet, "/runner/v1/unknown", nil, nil)
	assertProblemCode(t, response, http.StatusNotFound, "runner_resource_not_found")
	response = serve(t, handler, http.MethodDelete, "/runner/v1/identity", nil, nil)
	assertProblemCode(t, response, http.StatusNotFound, "runner_resource_not_found")
}

func TestRouterRejectsQueryIdentitySmugglingAndSanitizesPanics(t *testing.T) {
	t.Parallel()
	verifier := &staticVerifier{identity: testIdentity(t)}
	backend := &fakeBackend{panicIdentity: true}
	handler := mustRouter(t, verifier, backend)

	response := serve(t, handler, http.MethodGet, "/runner/v1/identity?runner_id=forged", nil, nil)
	assertProblemCode(t, response, http.StatusBadRequest, "invalid_runner_request")
	if verifier.calls != 1 || backend.authCalls != 1 || backend.identityCalls != 0 {
		t.Fatal("query-bearing request did not perform exactly one request authentication before rejection")
	}

	response = serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
	body := assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")
	if strings.Contains(string(body), "panic secret") {
		t.Fatal("panic detail leaked")
	}
}

func TestRecoveryDiscardsPartialSuccessBeforeWritingAProblem(t *testing.T) {
	t.Parallel()
	handler := recoveryBoundary(responseHeadersBoundary(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"partial":true}`))
		panic("must not escape")
	})))
	request := httptest.NewRequest(http.MethodGet, "/runner/v1/identity", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	body := assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")
	if bytes.Contains(body, []byte("partial")) {
		t.Fatalf("partial success escaped recovery buffer: %s", body)
	}
}

func TestSafeRequestIDContainsRandomSourcePanics(t *testing.T) {
	t.Parallel()
	got := safeRequestID(func() string { panic("entropy unavailable") })
	if got != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("safeRequestID() = %q", got)
	}
}

func TestRevocationLeaseAuthenticationUsesItsOwnChallenge(t *testing.T) {
	t.Parallel()
	identity := testIdentityForPool(t, runneridentity.PoolWrite)
	handler := mustRouter(t, &staticVerifier{identity: identity}, &fakeBackend{revocationCapable: true})
	response := serve(t, handler, http.MethodPost,
		"/runner/v1/revocations/11111111-1111-4111-8111-111111111111:heartbeat",
		[]byte(`{"schema_version":"runner-revocation-heartbeat-request.v1","claim_epoch":"1","sequence":"1"}`),
		http.Header{"Content-Type": {"application/json"}},
	)
	assertProblemCode(t, response, http.StatusUnauthorized, "runner_lease_authentication_failed")
	if got := response.Header.Get("WWW-Authenticate"); got != `AIOPS-Revocation-Lease realm="runner-gateway"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestBackendErrorsMapOnlyToTheStableRFC9457Catalog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err         error
		status      int
		problemType string
		code        string
	}{
		{ErrInvalidRequest, 400, "urn:aiops:problem:runner:invalid-request", "invalid_runner_request"},
		{ErrLeaseAuthentication, 401, "urn:aiops:problem:runner:lease-authentication-failed", "runner_lease_authentication_failed"},
		{ErrForbidden, 403, "urn:aiops:problem:runner:identity-rejected", "runner_identity_rejected"},
		{ErrNotFound, 404, "urn:aiops:problem:runner:resource-not-found", "runner_resource_not_found"},
		{ErrStaleLease, 409, "urn:aiops:problem:runner:stale-lease", "runner_stale_lease"},
		{ErrStateConflict, 409, "urn:aiops:problem:runner:state-conflict", "runner_state_conflict"},
		{ErrHeartbeatConflict, 409, "urn:aiops:problem:runner:heartbeat-sequence-conflict", "runner_heartbeat_sequence_conflict"},
		{ErrCredentialConflict, 409, "urn:aiops:problem:runner:credential-anchor-conflict", "runner_credential_anchor_conflict"},
		{ErrResultConflict, 409, "urn:aiops:problem:runner:result-conflict", "runner_result_conflict"},
		{ErrRateLimited, 429, "urn:aiops:problem:runner:rate-limited", "runner_rate_limited"},
		{ErrClaimsDisabled, 503, "urn:aiops:problem:runner:claims-disabled", "runner_claims_disabled"},
		{ErrUnavailable, 503, "urn:aiops:problem:runner:dependency-unavailable", "runner_dependency_unavailable"},
		{errors.New("sensitive backend detail"), 500, "urn:aiops:problem:runner:internal-error", "runner_internal_error"},
	}
	for _, test := range tests {
		got := backendProblem(test.err)
		if got.status != test.status || got.typeID != test.problemType || got.code != test.code || strings.Contains(got.detail, "sensitive") {
			t.Errorf("backendProblem(%v) = %#v", test.err, got)
		}
	}
}

func TestRouterRestrictsBackendErrorsToEachOperationResponseSet(t *testing.T) {
	t.Parallel()
	identity := testIdentityForPool(t, runneridentity.PoolWrite)
	backend := &fakeBackend{identityErr: ErrStateConflict, leaseErr: ErrRateLimited, startErr: ErrRateLimited}
	handler := mustRouter(t, &staticVerifier{identity: identity}, backend)

	response := serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
	assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")
	response = serve(t, handler, http.MethodPost, "/runner/v1/jobs:lease",
		[]byte(`{"schema_version":"runner-job-lease-request.v1"}`), http.Header{"Content-Type": {"application/json"}})
	assertProblemCode(t, response, http.StatusTooManyRequests, "runner_rate_limited")
	response = serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:start",
		[]byte(`{"schema_version":"runner-job-start-request.v1","lease_epoch":"1"}`),
		http.Header{"Content-Type": {"application/json"}, "Authorization": {"AIOPS-Job-Lease " + testLeaseToken}})
	assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")
}

func TestRouterFailsClosedOnOversizedOrUnsafeBackendResponses(t *testing.T) {
	t.Parallel()
	identity := testIdentity(t)
	identityResponse := validIdentityResponse(identity)
	identityResponse.RunnerID = strings.Repeat("x", int(defaultBodyLimit))
	backend := &fakeBackend{identityResponse: identityResponse}
	handler := mustRouter(t, &staticVerifier{identity: identity}, backend)
	response := serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
	assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")

	unsafeIdentity := validIdentityResponse(identity)
	unsafeIdentity.Pool = "READ"
	unsafeIdentity.Capabilities = []string{"CREDENTIAL_REVOCATION"}
	backend.identityResponse = unsafeIdentity
	response = serve(t, handler, http.MethodGet, "/runner/v1/identity", nil, nil)
	assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")
}

func TestRouterCompleteUsesAcceptedOnlyWhileFinalizing(t *testing.T) {
	t.Parallel()
	backend := &fakeBackend{completeResponse: validCompletionResponse("FINALIZING")}
	handler := mustRouter(t, &staticVerifier{identity: testIdentityForPool(t, runneridentity.PoolWrite)}, backend)
	headers := http.Header{"Content-Type": {"application/json"}, "Authorization": {"AIOPS-Job-Lease " + testLeaseToken}}
	body := []byte(`{"schema_version":"runner-job-complete-request.v1","lease_epoch":"1","result":{"outcome":"SUCCEEDED","code":"OK","verification":"PASSED","changed":true}}`)
	response := serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:complete", body, headers)
	assertStatusAndBoundaryHeaders(t, response, http.StatusAccepted)

	backend.completeResponse = validCompletionResponse("SUCCEEDED")
	response = serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:complete", body, headers)
	assertStatusAndBoundaryHeaders(t, response, http.StatusOK)

	backend.completeResponse.CredentialCleanupStatus = "PENDING"
	response = serve(t, handler, http.MethodPost, "/runner/v1/jobs/job-1:complete", body, headers)
	assertProblemCode(t, response, http.StatusInternalServerError, "runner_internal_error")
}

func TestRouterRejectsForbiddenOrNullUnionFieldsBeforeBackendDispatch(t *testing.T) {
	t.Parallel()
	identity := testIdentityForPool(t, runneridentity.PoolWrite)
	backend := &fakeBackend{
		completeResponse:  validCompletionResponse("FINALIZING"),
		revocationCapable: true,
		anchorResponse: CredentialAnchorResponse{
			SchemaVersion: "runner-credential-anchor-response.v1", JobID: "job-1",
			RevocationID: "11111111-1111-4111-8111-111111111111", Status: "ACTIVE",
		},
	}
	handler := mustRouter(t, &staticVerifier{identity: identity}, backend)
	jobHeaders := http.Header{"Content-Type": {"application/json"}, "Authorization": {"AIOPS-Job-Lease " + testLeaseToken}}
	revocationHeaders := http.Header{"Content-Type": {"application/json"}, "Authorization": {"AIOPS-Revocation-Lease " + testLeaseToken}}
	tests := []struct {
		name    string
		path    string
		body    string
		headers http.Header
	}{
		{name: "activate empty permit", path: "/runner/v1/jobs/job-1:credential-anchor", headers: jobHeaders,
			body: `{"schema_version":"runner-credential-anchor-request.v1","phase":"ACTIVATE","lease_epoch":"1","revocation_id":"11111111-1111-4111-8111-111111111111","child_create_permit":""}`},
		{name: "activate null permit", path: "/runner/v1/jobs/job-1:credential-anchor", headers: jobHeaders,
			body: `{"schema_version":"runner-credential-anchor-request.v1","phase":"ACTIVATE","lease_epoch":"1","revocation_id":"11111111-1111-4111-8111-111111111111","child_create_permit":null}`},
		{name: "revoked empty failure", path: "/runner/v1/revocations/11111111-1111-4111-8111-111111111111:complete", headers: revocationHeaders,
			body: `{"schema_version":"runner-revocation-complete-request.v1","claim_epoch":"1","outcome":"REVOKED","failure_code":""}`},
		{name: "revoked null failure", path: "/runner/v1/revocations/11111111-1111-4111-8111-111111111111:complete", headers: revocationHeaders,
			body: `{"schema_version":"runner-revocation-complete-request.v1","claim_epoch":"1","outcome":"REVOKED","failure_code":null}`},
		{name: "result empty external ref", path: "/runner/v1/jobs/job-1:complete", headers: jobHeaders,
			body: `{"schema_version":"runner-job-complete-request.v1","lease_epoch":"1","result":{"outcome":"SUCCEEDED","code":"OK","verification":"PASSED","changed":true,"external_operation_ref_hash":""}}`},
		{name: "result null external ref", path: "/runner/v1/jobs/job-1:complete", headers: jobHeaders,
			body: `{"schema_version":"runner-job-complete-request.v1","lease_epoch":"1","result":{"outcome":"SUCCEEDED","code":"OK","verification":"PASSED","changed":true,"external_operation_ref_hash":null}}`},
		{name: "result missing changed", path: "/runner/v1/jobs/job-1:complete", headers: jobHeaders,
			body: `{"schema_version":"runner-job-complete-request.v1","lease_epoch":"1","result":{"outcome":"SUCCEEDED","code":"OK","verification":"PASSED"}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serve(t, handler, http.MethodPost, test.path, []byte(test.body), test.headers)
			assertProblemCode(t, response, http.StatusBadRequest, "invalid_runner_json")
		})
	}
	if backend.anchorCalls != 0 || backend.completeCalls != 0 || backend.revocationCompleteCalls != 0 {
		t.Fatalf("invalid union reached backend: anchor=%d complete=%d revocation=%d",
			backend.anchorCalls, backend.completeCalls, backend.revocationCompleteCalls)
	}
}

func TestRequestValidationClosesCredentialAndResultUnions(t *testing.T) {
	t.Parallel()
	validResult := JobCompleteRequest{
		SchemaVersion: "runner-job-complete-request.v1", LeaseEpoch: 1,
		Result: execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "OK", Verification: execution.VerificationPassed},
	}
	if !validResult.valid() {
		t.Fatal("valid result rejected")
	}
	for _, mutate := range []func(*JobCompleteRequest){
		func(value *JobCompleteRequest) { value.Result.Verification = execution.VerificationFailed },
		func(value *JobCompleteRequest) { value.Result.Outcome = "UNKNOWN" },
		func(value *JobCompleteRequest) { value.Result.Code = "lowercase" },
		func(value *JobCompleteRequest) { value.Result.ExternalOperationRefHash = strings.Repeat("A", 64) },
	} {
		candidate := validResult
		mutate(&candidate)
		if candidate.valid() {
			t.Fatalf("illegal result accepted: %#v", candidate)
		}
	}

	base := CredentialAnchorRequest{SchemaVersion: "runner-credential-anchor-request.v1", LeaseEpoch: 1, RevocationID: "11111111-1111-4111-8111-111111111111"}
	for _, valid := range []CredentialAnchorRequest{
		func() CredentialAnchorRequest {
			value := base
			value.Phase = "AUTHORIZE_CHILD_CREATE"
			value.ChildCreatePermit = testLeaseToken
			return value
		}(),
		func() CredentialAnchorRequest {
			value := base
			value.Phase = "RECORD_ANCHOR"
			value.RevokeAccessorB64U = "YWNjZXNzb3I"
			return value
		}(),
		func() CredentialAnchorRequest { value := base; value.Phase = "ACTIVATE"; return value }(),
	} {
		if !valid.valid() {
			t.Fatalf("valid credential phase rejected: %#v", valid)
		}
	}
	invalid := base
	invalid.Phase = "ACTIVATE"
	invalid.ChildCreatePermit = testLeaseToken
	if invalid.valid() {
		t.Fatal("cross-phase credential field accepted")
	}
}

func TestDecimalInt64WireContractUsesCanonicalStringsWithoutPrecisionLoss(t *testing.T) {
	t.Parallel()
	const beyondIJSON = int64(1<<53 + 1)
	encoded, err := json.Marshal(struct {
		Epoch DecimalInt64 `json:"epoch"`
	}{Epoch: DecimalInt64(beyondIJSON)})
	if err != nil || string(encoded) != `{"epoch":"9007199254740993"}` {
		t.Fatalf("Marshal bigint = %s, %v", encoded, err)
	}
	for _, raw := range []string{`{"lease_epoch":1}`, `{"lease_epoch":"01"}`, `{"lease_epoch":"-1"}`, `{"lease_epoch":"9223372036854775808"}`} {
		var request JobStartRequest
		if err := json.Unmarshal([]byte(raw), &request); err == nil {
			t.Fatalf("non-canonical bigint accepted: %s", raw)
		}
	}
	var request JobStartRequest
	if err := json.Unmarshal([]byte(`{"schema_version":"runner-job-start-request.v1","lease_epoch":"9007199254740993"}`), &request); err != nil || request.LeaseEpoch.Int64() != beyondIJSON {
		t.Fatalf("Unmarshal bigint = %#v, %v", request, err)
	}
}

func TestUUIDWireBoundaryMatchesExistingDomainVersions(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"11111111-1111-1111-8111-111111111111",
		"55555555-5555-5555-a555-555555555555",
	} {
		if !uuidPattern.MatchString(value) {
			t.Errorf("domain-compatible UUID rejected: %s", value)
		}
	}
	for _, value := range []string{
		"00000000-0000-0000-8000-000000000000",
		"66666666-6666-6666-8666-666666666666",
		"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
	} {
		if uuidPattern.MatchString(value) {
			t.Errorf("out-of-contract UUID accepted: %s", value)
		}
	}
}

func TestOptionalResponseTimestampsAreAbsentOutsideTheirWireUnionBranch(t *testing.T) {
	t.Parallel()
	for _, value := range []any{
		CredentialAnchorResponse{
			SchemaVersion: "runner-credential-anchor-response.v1", JobID: "job-1",
			RevocationID: "11111111-1111-4111-8111-111111111111", Status: "ANCHORED",
		},
		RevocationCompletionResponse{
			SchemaVersion: "runner-revocation-completion-response.v1", RevocationID: "11111111-1111-4111-8111-111111111111",
			Status: "REVOKED", ClaimEpoch: 1,
		},
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(`"database_authorized_at"`)) ||
			bytes.Contains(encoded, []byte(`"credential_expires_at"`)) ||
			bytes.Contains(encoded, []byte(`"available_at"`)) {
			t.Fatalf("inactive oneOf field was serialized: %s", encoded)
		}
	}
}

func TestJobDescriptorRequiresPathSafeIDAndNonEmptySignature(t *testing.T) {
	t.Parallel()
	valid := validJobDescriptor()
	if !valid.valid() {
		t.Fatal("valid signed descriptor rejected")
	}
	unsafeID := valid
	unsafeID.ID = "jobs/unreachable"
	unsafeID.Payload.ActionID = unsafeID.ID
	if unsafeID.valid() {
		t.Fatal("job ID that cannot round-trip through Runner paths was accepted")
	}
	unsigned := valid
	unsigned.Payload.Signature = action.Signature{}
	if unsigned.valid() {
		t.Fatal("unsigned WRITE job was accepted")
	}
}

func TestBackendResponsesAreBoundToTheAuthenticatedRequestFence(t *testing.T) {
	t.Parallel()
	identity := testIdentityForPool(t, runneridentity.PoolWrite)
	now := time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC)
	const revocationID = "11111111-1111-4111-8111-111111111111"
	binding := backendResponseBinding{
		identity: identity, principal: testPrincipalForIdentity(identity, true), jobID: "job-1", revocationID: revocationID,
		epoch: 7, sequence: 9, credentialPhase: "ACTIVATE",
		resultOutcome: execution.ExecutorSucceeded, revocationOutcome: "FAILED",
	}
	identityResponse := validIdentityResponse(identity)
	identityResponse.Capabilities = []string{"CREDENTIAL_REVOCATION"}
	valid := []any{
		identityResponse,
		CredentialAnchorResponse{SchemaVersion: "runner-credential-anchor-response.v1", JobID: "job-1", RevocationID: revocationID, Status: "ACTIVE"},
		JobStartResponse{
			SchemaVersion: "runner-job-start-response.v1", JobID: "job-1", Status: "RUNNING", LeaseEpoch: 7,
			ScopeRevision: 1, StartedAt: now, CredentialPrepare: CredentialPrepare{
				RevocationID: revocationID, ChildCreatePermit: testLeaseToken,
				IssuerID: "vault-issuer", IssuerRevision: "issuer-revision-1",
				CredentialExpiresAt: now.Add(10 * time.Minute),
			},
		},
		JobHeartbeatResponse{
			SchemaVersion: "runner-job-heartbeat-response.v1", JobID: "job-1", AcceptedSequence: 9,
			Directive: "CONTINUE", LeaseExpiresAt: now.Add(30 * time.Second), HeartbeatAfterSeconds: 10,
		},
		JobStateResponse{SchemaVersion: "runner-job-state-response.v1", JobID: "job-1", Status: "QUEUED", LeaseEpoch: 7},
		JobCompletionResponse{
			SchemaVersion: "runner-job-completion-response.v1", JobID: "job-1", Status: "FINALIZING",
			CompletionStatus: "SUCCEEDED", ReceiptHash: strings.Repeat("b", 64), CredentialCleanupStatus: "PENDING",
		},
		RevocationHeartbeatResponse{
			SchemaVersion: "runner-revocation-heartbeat-response.v1", RevocationID: revocationID,
			AcceptedSequence: 9, Directive: "CONTINUE", ClaimExpiresAt: now.Add(30 * time.Second), HeartbeatAfterSeconds: 10,
		},
		RevocationCompletionResponse{
			SchemaVersion: "runner-revocation-completion-response.v1", RevocationID: revocationID,
			Status: "MANUAL_REQUIRED", ClaimEpoch: 7,
		},
		&JobLeaseResponse{
			SchemaVersion: "runner-job-lease-response.v1", Job: validJobDescriptor(), LeaseToken: testLeaseToken,
			LeaseEpoch: 1, ScopeRevision: 1, LeaseExpiresAt: now.Add(30 * time.Second), HeartbeatAfterSeconds: 10,
		},
		&RevocationLeaseResponse{
			SchemaVersion: "runner-revocation-lease-response.v1", RevocationID: revocationID, ClaimToken: testLeaseToken,
			ClaimEpoch: 1, ClaimExpiresAt: now.Add(30 * time.Second), HeartbeatAfterSeconds: 10,
			TenantID:    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			WorkspaceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", EnvironmentID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
			IssuerID: "vault-issuer", IssuerRevision: "issuer-revision-1", RevokeAccessorB64U: "YWNjZXNzb3I",
		},
	}
	for _, response := range valid {
		if !validBackendResponse(response, binding) {
			t.Fatalf("valid bound response rejected: %#v", response)
		}
	}

	mismatches := []any{
		func() RunnerIdentityResponse {
			value := identityResponse
			value.CertificateSHA256 = strings.Repeat("f", 64)
			return value
		}(),
		func() RunnerIdentityResponse {
			value := identityResponse
			value.ScopeRevision = 2
			return value
		}(),
		CredentialAnchorResponse{SchemaVersion: "runner-credential-anchor-response.v1", JobID: "another-job", RevocationID: revocationID, Status: "ACTIVE"},
		func() JobStartResponse {
			value := valid[2].(JobStartResponse)
			value.LeaseEpoch = 8
			return value
		}(),
		func() JobHeartbeatResponse {
			value := valid[3].(JobHeartbeatResponse)
			value.AcceptedSequence = 8
			return value
		}(),
		JobStateResponse{SchemaVersion: "runner-job-state-response.v1", JobID: "job-1", Status: "RUNNING", LeaseEpoch: 7},
		func() JobCompletionResponse {
			value := valid[5].(JobCompletionResponse)
			value.CompletionStatus = "FAILED"
			return value
		}(),
		func() RevocationHeartbeatResponse {
			value := valid[6].(RevocationHeartbeatResponse)
			value.RevocationID = "22222222-2222-4222-8222-222222222222"
			return value
		}(),
		func() RevocationCompletionResponse {
			value := valid[7].(RevocationCompletionResponse)
			value.ClaimEpoch = 8
			return value
		}(),
		func() *JobLeaseResponse {
			value := *valid[8].(*JobLeaseResponse)
			value.ScopeRevision = 2
			return &value
		}(),
		func() *RevocationLeaseResponse {
			value := *valid[9].(*RevocationLeaseResponse)
			value.TenantID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
			return &value
		}(),
	}
	for _, response := range mismatches {
		if validBackendResponse(response, binding) {
			t.Fatalf("response detached from request fence was accepted: %#v", response)
		}
	}
	deniedPrincipal := *binding.principal.(*testPrincipal)
	deniedPrincipal.allowedWorkspaceEnvironment = func(string, string) bool { return false }
	deniedBinding := binding
	deniedBinding.principal = &deniedPrincipal
	if validBackendResponse(valid[8], deniedBinding) || validBackendResponse(valid[9], deniedBinding) {
		t.Fatal("out-of-scope job or revocation response was accepted")
	}
	readBinding := binding
	readBinding.identity = testIdentity(t)
	readBinding.principal = testPrincipalForIdentity(readBinding.identity, false)
	if validBackendResponse(valid[1], readBinding) {
		t.Fatal("READ certificate accepted a WRITE action state response")
	}
}

type staticVerifier struct {
	identity runneridentity.Identity
	err      error
	calls    int
}

func (verifier *staticVerifier) IdentityFromConnectionState(tls.ConnectionState) (runneridentity.Identity, error) {
	verifier.calls++
	return verifier.identity, verifier.err
}

type fakeBackend struct {
	identityResponse            RunnerIdentityResponse
	jobLeaseResponse            *JobLeaseResponse
	anchorResponse              CredentialAnchorResponse
	startResponse               JobStartResponse
	heartbeatResponse           JobHeartbeatResponse
	releaseResponse             JobStateResponse
	completeResponse            JobCompletionResponse
	revocationLeaseResponse     *RevocationLeaseResponse
	revocationHeartbeatResponse RevocationHeartbeatResponse
	revocationCompleteResponse  RevocationCompletionResponse
	identityErr                 error
	leaseErr                    error
	startErr                    error
	identityCalls               int
	authCalls                   int
	authErr                     error
	principal                   RequestPrincipal
	revocationCapable           bool
	startCalls                  int
	leaseCalls                  int
	anchorCalls                 int
	completeCalls               int
	revocationCompleteCalls     int
	revocationLeaseCalls        int
	lastResourceID              string
	lastToken                   string
	panicIdentity               bool
}

func (backend *fakeBackend) AuthenticateRequest(_ context.Context, identity runneridentity.Identity) (RequestPrincipal, error) {
	backend.authCalls++
	if backend.authErr != nil {
		return nil, backend.authErr
	}
	if !nilInterface(backend.principal) {
		return backend.principal, nil
	}
	return testPrincipalForIdentity(identity, backend.revocationCapable), nil
}

func (backend *fakeBackend) Identity(context.Context, runneridentity.Identity) (RunnerIdentityResponse, error) {
	backend.identityCalls++
	if backend.panicIdentity {
		panic("panic secret")
	}
	return backend.identityResponse, backend.identityErr
}
func (backend *fakeBackend) LeaseJob(context.Context, runneridentity.Identity, JobLeaseRequest) (*JobLeaseResponse, error) {
	backend.leaseCalls++
	return backend.jobLeaseResponse, backend.leaseErr
}
func (backend *fakeBackend) AnchorCredential(context.Context, runneridentity.Identity, string, string, CredentialAnchorRequest) (CredentialAnchorResponse, error) {
	backend.anchorCalls++
	return backend.anchorResponse, nil
}
func (backend *fakeBackend) StartJob(_ context.Context, _ runneridentity.Identity, resourceID, token string, _ JobStartRequest) (JobStartResponse, error) {
	backend.startCalls++
	backend.lastResourceID, backend.lastToken = resourceID, token
	return backend.startResponse, backend.startErr
}
func (backend *fakeBackend) HeartbeatJob(context.Context, runneridentity.Identity, string, string, JobHeartbeatRequest) (JobHeartbeatResponse, error) {
	return backend.heartbeatResponse, nil
}
func (backend *fakeBackend) ReleaseJob(context.Context, runneridentity.Identity, string, string, JobReleaseRequest) (JobStateResponse, error) {
	return backend.releaseResponse, nil
}
func (backend *fakeBackend) CompleteJob(_ context.Context, _ runneridentity.Identity, resourceID, token string, _ JobCompleteRequest) (JobCompletionResponse, error) {
	backend.completeCalls++
	backend.lastResourceID, backend.lastToken = resourceID, token
	return backend.completeResponse, nil
}
func (backend *fakeBackend) LeaseRevocation(context.Context, runneridentity.Identity, RevocationLeaseRequest) (*RevocationLeaseResponse, error) {
	backend.revocationLeaseCalls++
	return backend.revocationLeaseResponse, nil
}
func (backend *fakeBackend) HeartbeatRevocation(context.Context, runneridentity.Identity, string, string, RevocationHeartbeatRequest) (RevocationHeartbeatResponse, error) {
	return backend.revocationHeartbeatResponse, nil
}
func (backend *fakeBackend) CompleteRevocation(context.Context, runneridentity.Identity, string, string, RevocationCompleteRequest) (RevocationCompletionResponse, error) {
	backend.revocationCompleteCalls++
	return backend.revocationCompleteResponse, nil
}

type testPrincipal struct {
	valid                       bool
	runnerID                    string
	tenantID                    string
	pool                        runneridentity.Pool
	scopeRevision               int64
	maxConcurrency              int
	credentialRevocation        bool
	certificateSHA256           string
	certificateNotAfter         time.Time
	allowedWorkspaceEnvironment func(string, string) bool
}

func testPrincipalForIdentity(identity runneridentity.Identity, revocationCapable bool) *testPrincipal {
	return &testPrincipal{
		valid: true, runnerID: identity.Instance(), tenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		pool: identity.Pool(), scopeRevision: 1, maxConcurrency: 1,
		credentialRevocation: revocationCapable,
		certificateSHA256:    identity.Evidence().LeafSHA256(), certificateNotAfter: identity.Evidence().NotAfter(),
		allowedWorkspaceEnvironment: func(string, string) bool { return true },
	}
}

func (principal *testPrincipal) Valid() bool { return principal != nil && principal.valid }
func (principal *testPrincipal) RunnerID() string {
	if principal == nil {
		return ""
	}
	return principal.runnerID
}
func (principal *testPrincipal) TenantID() string {
	if principal == nil {
		return ""
	}
	return principal.tenantID
}
func (principal *testPrincipal) Pool() runneridentity.Pool {
	if principal == nil {
		return ""
	}
	return principal.pool
}
func (principal *testPrincipal) ScopeRevision() int64 {
	if principal == nil {
		return 0
	}
	return principal.scopeRevision
}
func (principal *testPrincipal) MaxConcurrency() int {
	if principal == nil {
		return 0
	}
	return principal.maxConcurrency
}
func (principal *testPrincipal) CredentialRevocationCapable() bool {
	return principal != nil && principal.credentialRevocation
}
func (principal *testPrincipal) CertificateSHA256() string {
	if principal == nil {
		return ""
	}
	return principal.certificateSHA256
}
func (principal *testPrincipal) CertificateNotAfter() time.Time {
	if principal == nil {
		return time.Time{}
	}
	return principal.certificateNotAfter
}
func (principal *testPrincipal) Allows(workspaceID, environmentID string) bool {
	return principal != nil && principal.allowedWorkspaceEnvironment != nil &&
		principal.allowedWorkspaceEnvironment(workspaceID, environmentID)
}

func testIdentity(t *testing.T) runneridentity.Identity {
	return testIdentityForPool(t, runneridentity.PoolRead)
}

func testIdentityForPool(t *testing.T, pool runneridentity.Pool) runneridentity.Identity {
	t.Helper()
	now := time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC)
	readCA, err := testpki.NewAuthority("read", now)
	if err != nil {
		t.Fatal(err)
	}
	writeCA, err := testpki.NewAuthority("write", now)
	if err != nil {
		t.Fatal(err)
	}
	poolPath := "read"
	instance := "reader-1"
	clientCA := readCA
	if pool == runneridentity.PoolWrite {
		poolPath = "write"
		instance = "writer-1"
		clientCA = writeCA
	}
	uri, err := url.Parse("spiffe://aiops.example/runner/" + poolPath + "/" + instance)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientCA.IssueClient(testpki.ClientOptions{URIs: []*url.URL{uri}}, now)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	chains, err := client.Leaf.Verify(x509.VerifyOptions{
		Roots: clientCA.CertPool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verifier.IdentityFromConnectionState(tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{client.Leaf, readCA.Certificate}, VerifiedChains: chains,
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func validIdentityResponse(identity runneridentity.Identity) RunnerIdentityResponse {
	return RunnerIdentityResponse{
		SchemaVersion: "runner-identity-response.v1", RunnerID: identity.Instance(), Pool: string(identity.Pool()), ScopeRevision: 1,
		MaxConcurrency: 1, Capabilities: []string{}, CertificateSHA256: identity.Evidence().LeafSHA256(),
		CertificateNotAfter: identity.Evidence().NotAfter(),
	}
}

func validStartResponse() JobStartResponse {
	return JobStartResponse{
		SchemaVersion: "runner-job-start-response.v1", JobID: "job-1", Status: "RUNNING", LeaseEpoch: 1,
		ScopeRevision: 1, StartedAt: time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC),
		CredentialPrepare: CredentialPrepare{
			RevocationID: "11111111-1111-4111-8111-111111111111", ChildCreatePermit: testLeaseToken,
			IssuerID: "vault-issuer", IssuerRevision: "issuer-revision-1",
			CredentialExpiresAt: time.Date(2040, 1, 2, 3, 14, 5, 0, time.UTC),
		},
	}
}

func validCompletionResponse(status string) JobCompletionResponse {
	cleanup := "PENDING"
	if status == "SUCCEEDED" || status == "FAILED" {
		cleanup = "TERMINAL"
	}
	return JobCompletionResponse{
		SchemaVersion: "runner-job-completion-response.v1", JobID: "job-1", Status: status,
		CompletionStatus: "SUCCEEDED", ReceiptHash: strings.Repeat("b", 64), CredentialCleanupStatus: cleanup,
	}
}

func validJobDescriptor() JobDescriptor {
	now := time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC)
	planHash := strings.Repeat("c", 64)
	envelope := action.Envelope{
		SchemaVersion: action.SchemaVersionV1, ActionID: "job-1", WorkspaceID: "workspace-1",
		IncidentID: "incident-1", RequestedBy: "requester-1", ActionType: action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "service-1", EnvironmentID: "staging", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-1", Namespace: "payments", Name: "api", UID: "uid-1", ResourceVersion: "42",
		}},
		Parameters: action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "verified recovery"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{
			Generation: 1, Replicas: 2, AvailableReplicas: 2, UpdatedReplicas: 2,
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "42", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 300},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "follow runbook"},
		Risk:          action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"STAGING_CHANGE"}},
		PolicyVersion: "policy-v1",
		CredentialScope: action.CredentialScope{
			ConnectorID: "kubernetes-staging", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-1/payments/deployment/api", TTLSeconds: 600,
		},
		IdempotencyKey: "idem-job-1", NotBefore: now, ExpiresAt: now.Add(15 * time.Minute),
		TraceID: strings.Repeat("a", 32), PlanHash: planHash,
		Signature: action.Signature{
			Algorithm: action.SignatureEd25519, KeyID: "control-plane-key-1",
			Value: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		},
	}
	return JobDescriptor{
		ID: "job-1", Kind: "WRITE_ACTION", Payload: envelope, PlanHash: planHash,
		EnvironmentRevision: "environment-revision-1", Production: false,
	}
}

func mustRouter(t *testing.T, verifier IdentityVerifier, backend Backend) http.Handler {
	t.Helper()
	handler, err := NewRouter(verifier, backend)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serve(t *testing.T, handler http.Handler, method, target string, body []byte, headers http.Header) *http.Response {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	for key, values := range headers {
		request.Header.Del(key)
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Result()
}

func assertStatusAndBoundaryHeaders(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response.StatusCode != want {
		t.Fatalf("status = %d, want %d; body=%s", response.StatusCode, want, readBody(t, response))
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("X-Request-ID") == "" {
		t.Fatalf("security headers = %#v", response.Header)
	}
}

func assertProblemCode(t *testing.T, response *http.Response, status int, code string) []byte {
	t.Helper()
	body := readBody(t, response)
	var value problem
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode problem: %v; body=%s", err, body)
	}
	assertStatusAndBoundaryHeadersNoRead(t, response, status)
	if value.Code != code || value.Status != status {
		t.Fatalf("problem = %#v, want status/code %d/%s", value, status, code)
	}
	return body
}

func assertProblem(t *testing.T, response *http.Response, status int, problemType, code string) []byte {
	t.Helper()
	body := assertProblemCode(t, response, status, code)
	var value problem
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	if value.Type != problemType || !strings.HasPrefix(value.Instance, "urn:aiops:request:") {
		t.Fatalf("problem = %#v", value)
	}
	return body
}

func assertStatusAndBoundaryHeadersNoRead(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response.StatusCode != want {
		t.Fatalf("status = %d, want %d", response.StatusCode, want)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("X-Request-ID") == "" {
		t.Fatalf("security headers = %#v", response.Header)
	}
}

func readBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
