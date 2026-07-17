package httpapi_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

const (
	sourceTestRunID      = "99999999-9999-4999-8999-999999999999"
	sourceTestRevisionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	sourceTestBasePath   = "/api/v1/workspaces/" + assetTestWorkspaceID + "/asset-sources"
)

func TestAssetSourceReadRoutesPreserveManualUsageScope(t *testing.T) {
	t.Parallel()
	view := safeSourceView()
	manager := &recordingSourceManager{
		page: assetcatalog.SourceViewPage{Items: []assetcatalog.SourceView{view}},
		view: view,
		run:  assetcatalog.SourceRunView{Run: safeSourceRun(), EffectiveActions: []assetcatalog.EffectiveAction{}},
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:  manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	listPath := sourceTestBasePath + "?usage=manual_asset_create&environment_id=" +
		assetTestEnvironmentID + "&kinds=MANUAL&statuses=ACTIVE&gate_statuses=AVAILABLE&limit=10"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, listPath, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET sources = %d %s", response.Code, response.Body.String())
	}
	if manager.collection.WorkspaceID != assetTestWorkspaceID ||
		manager.input.Usage != assetcatalog.SourceUsageManualAssetCreate ||
		manager.input.EnvironmentID != assetTestEnvironmentID || manager.input.Limit != 10 {
		t.Fatalf("manager request = %#v %#v", manager.collection, manager.input)
	}
	if !strings.Contains(response.Body.String(), `"effective_actions":["CREATE_ASSET"]`) {
		t.Fatalf("source response = %s", response.Body.String())
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath+"/"+assetTestSourceID, nil))
	if response.Code != http.StatusOK || manager.path.SourceID != assetTestSourceID {
		t.Fatalf("GET source = %d %s / %#v", response.Code, response.Body.String(), manager.path)
	}
	if got := response.Header().Get("ETag"); got != `"asset-source:`+assetTestSourceID+`:v3"` {
		t.Fatalf("source ETag = %q", got)
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/workspaces/"+assetTestWorkspaceID+"/asset-source-runs/"+sourceTestRunID,
		nil,
	))
	if response.Code != http.StatusOK || manager.runPath.RunID != sourceTestRunID {
		t.Fatalf("GET source run = %d %s / %#v", response.Code, response.Body.String(), manager.runPath)
	}
	if got := response.Header().Get("ETag"); got != `"asset-source-run:`+sourceTestRunID+`:v4"` {
		t.Fatalf("run ETag = %q", got)
	}

}

func TestAssetSourceCreateUsesClosedDTOIdempotencyAndServerReceipt(t *testing.T) {
	t.Parallel()
	manager := &recordingSourceManager{revisionMutation: safeSourceRevisionMutation()}
	request := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath,
		strings.NewReader(`{"name":"manual","source_profile_id":"manual-v1","authority_environment_ids":["`+
			assetTestEnvironmentID+`"]}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "source:create:manual-1")
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:       manager,
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("POST source = %d %s, want 201", response.Code, response.Body.String())
	}
	if manager.createInput.SourceProfileID != assetcatalog.SourceProfileIDManualV1 ||
		manager.metadata.IdempotencyKey != "source:create:manual-1" {
		t.Fatalf("create request = %#v / %#v", manager.createInput, manager.metadata)
	}
	if got := response.Header().Get("ETag"); got !=
		`"asset-source-revision:`+assetTestSourceID+`:r1:sv3:rv1"` {
		t.Fatalf("create ETag = %q", got)
	}
	if got := response.Header().Get("Location"); got !=
		sourceTestBasePath+"/"+assetTestSourceID {
		t.Fatalf("create Location = %q", got)
	}
}

func TestAssetSourceDTOOmitsCheckpointCiphertextLeaseAndCleanupAttemptMaterial(t *testing.T) {
	t.Parallel()
	manager := &recordingSourceManager{view: safeSourceView()}
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:  manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath+"/"+assetTestSourceID, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET source = %d %s", response.Code, response.Body.String())
	}
	lower := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		"canonical_profile_manifest", "canonical_provider_schema", "checkpoint_ciphertext",
		"checkpoint_key_id", "cleanup_attempt", "lease_owner", "lease_token",
		"credential_value", "trust_bundle", "network_policy_document", "upstream_error",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("source DTO contains %q: %s", forbidden, lower)
		}
	}
}

func TestAssetSourceRevisionActionsAreBoundToTheExactRevision(t *testing.T) {
	t.Parallel()
	view := safeSourceView()
	published := view.ReadModel.LatestRevision.Clone()
	latest := published.Clone()
	latest.Revision = 2
	latest.Status = assetcatalog.SourceRevisionDraft
	latest.Version = 1
	latest.CanonicalRevisionDigest = strings.Repeat("d", 64)
	view.ReadModel.LatestRevision = latest
	view.ReadModel.PublishedRevision = &published
	view.EffectiveActions = []assetcatalog.EffectiveAction{
		assetcatalog.ActionCreateSourceRevision,
		assetcatalog.ActionDisableSource,
		assetcatalog.ActionValidateSourceRevision,
	}
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:       &recordingSourceManager{view: view},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, sourceTestBasePath+"/"+assetTestSourceID, nil),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("GET source = %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Summary struct {
			EffectiveActions []string `json:"effective_actions"`
		} `json:"summary"`
		LatestRevision struct {
			EffectiveActions []string `json:"effective_actions"`
		} `json:"latest_revision"`
		PublishedRevision *struct {
			EffectiveActions []string `json:"effective_actions"`
		} `json:"published_revision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(body.Summary.EffectiveActions, []string{
		"CREATE_SOURCE_REVISION", "DISABLE_SOURCE",
	}) {
		t.Fatalf("source actions = %#v", body.Summary.EffectiveActions)
	}
	if !slices.Equal(body.LatestRevision.EffectiveActions, []string{"VALIDATE_SOURCE_REVISION"}) {
		t.Fatalf("latest revision actions = %#v", body.LatestRevision.EffectiveActions)
	}
	if body.PublishedRevision == nil || len(body.PublishedRevision.EffectiveActions) != 0 {
		t.Fatalf("published revision actions = %#v", body.PublishedRevision)
	}
}

func TestAssetSourceRoutesRejectInvalidQueriesAndMissingManager(t *testing.T) {
	t.Parallel()
	for _, query := range []string{
		"?usage=manual_asset_create",
		"?environment_id=" + assetTestEnvironmentID,
		"?unknown=value",
		"?limit=01",
		"?kinds=MANUAL,UNKNOWN",
	} {
		manager := &recordingSourceManager{}
		response := httptest.NewRecorder()
		httpapi.NewRouter(httpapi.Dependencies{
			Authenticator: fakeAuthenticator{principal: assetHTTPPrincipal()},
			AssetSources:  manager, ControlPlaneCursor: mustControlPlaneCursorCodec(t),
		}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath+query, nil))
		if response.Code != http.StatusBadRequest || manager.collection.WorkspaceID != "" {
			t.Errorf("%s response/request = %d %s / %#v", query, response.Code, response.Body.String(), manager.collection)
		}
	}
	response := httptest.NewRecorder()
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, sourceTestBasePath, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager response = %d %s", response.Code, response.Body.String())
	}
}

func TestAssetSourceCreateRejectsCallerOwnedFieldsStrictly(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		sourceTestBasePath,
		strings.NewReader(`{"name":"manual","source_profile_id":"manual-v1","authority_environment_ids":["`+
			assetTestEnvironmentID+`"],"tenant_id":"`+assetTestTenantID+`","credential":"secret"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "source:create:red-1")
	httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:       &recordingSourceManager{},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	}).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("POST source unsafe fields = %d %s, want 400", response.Code, response.Body.String())
	}
}

func TestAssetSourceMutationRoutesEnforceETagIdempotencyAndClosedBodies(t *testing.T) {
	t.Parallel()
	manager := &recordingSourceManager{
		revisionMutation: safeSourceRevisionMutation(),
		sourceMutation:   safeSourceMutation(),
		runMutation:      safeSourceRunMutation(),
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:       manager,
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	sourceETag := `"asset-source:` + assetTestSourceID + `:v3"`
	revisionETag := `"asset-source-revision:` + assetTestSourceID + `:r1:sv3:rv1"`

	createRevision := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+"/revisions",
		strings.NewReader(`{"source_profile_id":"manual-v1","authority_environment_ids":["`+
			assetTestEnvironmentID+`"],"change_reason_code":"SOURCE_CONFIG_CHANGED"}`),
	)
	setSourceMutationHeaders(createRevision, sourceETag, "source:revision:create-1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, createRevision)
	if response.Code != http.StatusCreated || manager.createRevisionCalls != 1 ||
		manager.metadata.ExpectedVersion != 3 {
		t.Fatalf("create revision = %d %s / calls=%d metadata=%#v",
			response.Code, response.Body.String(), manager.createRevisionCalls, manager.metadata)
	}

	validate := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+"/revisions/1:validate",
		strings.NewReader(`{}`),
	)
	setSourceMutationHeaders(validate, revisionETag, "source:revision:validate-1")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, validate)
	if response.Code != http.StatusOK || manager.validateCalls != 1 ||
		manager.metadata.ExpectedVersion != 3 || manager.metadata.ExpectedRevisionVersion != 1 {
		t.Fatalf("validate revision = %d %s / calls=%d metadata=%#v",
			response.Code, response.Body.String(), manager.validateCalls, manager.metadata)
	}

	publish := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+"/revisions/1:publish",
		strings.NewReader(`{"reason_code":"SOURCE_VALIDATED"}`),
	)
	setSourceMutationHeaders(publish, revisionETag, "source:revision:publish-1")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, publish)
	if response.Code != http.StatusOK || manager.publishCalls != 1 ||
		manager.reasonInput.ReasonCode != "SOURCE_VALIDATED" {
		t.Fatalf("publish revision = %d %s / calls=%d input=%#v",
			response.Code, response.Body.String(), manager.publishCalls, manager.reasonInput)
	}

	disable := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+":disable",
		strings.NewReader(`{"reason_code":"SOURCE_RETIRED"}`),
	)
	setSourceMutationHeaders(disable, sourceETag, "source:disable-1")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, disable)
	if response.Code != http.StatusOK || manager.disableCalls != 1 {
		t.Fatalf("disable source = %d %s / calls=%d", response.Code, response.Body.String(), manager.disableCalls)
	}

	syncRequest := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+":sync",
		strings.NewReader(`{}`),
	)
	setSourceMutationHeaders(syncRequest, sourceETag, "source:sync-1")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, syncRequest)
	if response.Code != http.StatusAccepted || manager.syncCalls != 1 {
		t.Fatalf("sync source = %d %s / calls=%d", response.Code, response.Body.String(), manager.syncCalls)
	}

	unsafePublish := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+"/revisions/1:publish",
		strings.NewReader(`{"reason_code":"SOURCE_VALIDATED","revision_digest":"caller","credential":"secret"}`),
	)
	setSourceMutationHeaders(unsafePublish, revisionETag, "source:revision:publish-unsafe")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, unsafePublish)
	if response.Code != http.StatusBadRequest || manager.publishCalls != 1 {
		t.Fatalf("unsafe publish = %d %s / calls=%d, want 400 without manager call",
			response.Code, response.Body.String(), manager.publishCalls)
	}

	weakETag := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+"/revisions/1:validate",
		strings.NewReader(`{}`),
	)
	setSourceMutationHeaders(weakETag, `W/`+revisionETag, "source:revision:validate-weak")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, weakETag)
	if response.Code != http.StatusBadRequest || manager.validateCalls != 1 {
		t.Fatalf("weak ETag = %d %s / calls=%d, want 400 without manager call",
			response.Code, response.Body.String(), manager.validateCalls)
	}

	missingIdempotency := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+":sync",
		strings.NewReader(`{}`),
	)
	missingIdempotency.Header.Set("Content-Type", "application/json")
	missingIdempotency.Header.Set("If-Match", sourceETag)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, missingIdempotency)
	if response.Code != http.StatusBadRequest || manager.syncCalls != 1 {
		t.Fatalf("missing idempotency = %d %s / calls=%d, want 400 without manager call",
			response.Code, response.Body.String(), manager.syncCalls)
	}
}

func TestAssetSourceOIDCAndMutualTLSIdentitiesRemainIsolated(t *testing.T) {
	t.Parallel()
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{principal: assetHTTPPrincipal()},
		AssetSources:       &recordingSourceManager{},
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	ingestionPath := sourceTestBasePath + "/" + assetTestSourceID + "/ingestion-batches"

	for name, mutate := range map[string]func(*http.Request){
		"browser bearer": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer oidc-token")
		},
		"missing workload certificate": func(*http.Request) {},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, ingestionPath, strings.NewReader(`{}`))
			mutate(request)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized ||
				!strings.Contains(response.Body.String(), `"code":"source_workload_identity_mismatch"`) {
				t.Fatalf("ingestion identity response = %d %s", response.Code, response.Body.String())
			}
		})
	}

	unboundURI, err := url.Parse("spiffe://unbound.invalid/source/not-bound")
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{URIs: []*url.URL{unboundURI}}
	unboundWorkload := httptest.NewRequest(http.MethodPost, ingestionPath, strings.NewReader(`{}`))
	unboundWorkload.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, unboundWorkload)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"source_ingestion_unavailable"`) {
		t.Fatalf("unbound certificate must remain closed = %d %s", response.Code, response.Body.String())
	}

	importRequest := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+"/imports",
		strings.NewReader("--source-boundary--\r\n"),
	)
	importRequest.Header.Set("Content-Type", "multipart/form-data; boundary=source-boundary")
	importRequest.Header.Set("Idempotency-Key", "source:import-1")
	importRequest.Header.Set("If-Match", `"asset-source:`+assetTestSourceID+`:v3"`)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, importRequest)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"source_import_unavailable"`) {
		t.Fatalf("closed import runtime = %d %s", response.Code, response.Body.String())
	}

	humanManager := &recordingSourceManager{revisionMutation: safeSourceRevisionMutation()}
	humanRouter := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator:      fakeAuthenticator{err: authn.ErrUnauthenticated},
		AssetSources:       humanManager,
		ControlPlaneCursor: mustControlPlaneCursorCodec(t),
	})
	humanPublish := httptest.NewRequest(
		http.MethodPost, sourceTestBasePath+"/"+assetTestSourceID+"/revisions/1:publish",
		strings.NewReader(`{"reason_code":"SOURCE_VALIDATED"}`),
	)
	humanPublish.TLS = unboundWorkload.TLS
	setSourceMutationHeaders(
		humanPublish,
		`"asset-source-revision:`+assetTestSourceID+`:r1:sv3:rv1"`,
		"source:revision:publish-workload",
	)
	response = httptest.NewRecorder()
	humanRouter.ServeHTTP(response, humanPublish)
	if response.Code != http.StatusUnauthorized || humanManager.publishCalls != 0 {
		t.Fatalf("workload on human route = %d %s / calls=%d",
			response.Code, response.Body.String(), humanManager.publishCalls)
	}
}

func setSourceMutationHeaders(request *http.Request, etag, idempotencyKey string) {
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", etag)
	request.Header.Set("Idempotency-Key", idempotencyKey)
}

type recordingSourceManager struct {
	page                assetcatalog.SourceViewPage
	view                assetcatalog.SourceView
	run                 assetcatalog.SourceRunView
	revisionMutation    assetcatalog.SourceRevisionMutationView
	sourceMutation      assetcatalog.SourceMutationView
	runMutation         assetcatalog.SourceRunMutationView
	err                 error
	collection          assetcatalog.SourceCollectionRequest
	path                assetcatalog.SourcePathRequest
	runPath             assetcatalog.SourceRunPathRequest
	input               assetcatalog.SourceListInput
	revisionPath        assetcatalog.SourceRevisionPathRequest
	createInput         assetcatalog.CreateSourceInput
	createRevisionInput assetcatalog.CreateSourceRevisionInput
	reasonInput         assetcatalog.SourceReasonInput
	metadata            assetcatalog.ServerRequestMetadata
	createCalls         int
	createRevisionCalls int
	validateCalls       int
	publishCalls        int
	disableCalls        int
	syncCalls           int
}

func (manager *recordingSourceManager) ListSources(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.SourceCollectionRequest,
	input assetcatalog.SourceListInput,
) (assetcatalog.SourceViewPage, error) {
	manager.collection, manager.input = collection, input
	return manager.page, manager.err
}

func (manager *recordingSourceManager) GetSource(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourcePathRequest,
) (assetcatalog.SourceView, error) {
	manager.path = path
	return manager.view, manager.err
}

func (manager *recordingSourceManager) GetSourceRun(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourceRunPathRequest,
) (assetcatalog.SourceRunView, error) {
	manager.runPath = path
	return manager.run, manager.err
}

func (manager *recordingSourceManager) CreateSource(
	_ context.Context,
	_ authn.Principal,
	collection assetcatalog.SourceCollectionRequest,
	input assetcatalog.CreateSourceInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.SourceRevisionMutationView, error) {
	manager.createCalls++
	manager.collection, manager.createInput, manager.metadata = collection, input, metadata
	manager.revisionMutation.Receipt = sourceMutationReceipt(manager.revisionMutation.Receipt, metadata.TraceID)
	return manager.revisionMutation, manager.err
}

func (manager *recordingSourceManager) CreateSourceRevision(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourcePathRequest,
	input assetcatalog.CreateSourceRevisionInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.SourceRevisionMutationView, error) {
	manager.createRevisionCalls++
	manager.path, manager.createRevisionInput, manager.metadata = path, input, metadata
	manager.revisionMutation.Receipt = sourceMutationReceipt(manager.revisionMutation.Receipt, metadata.TraceID)
	return manager.revisionMutation, manager.err
}

func (manager *recordingSourceManager) ValidateSourceRevision(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourceRevisionPathRequest,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.SourceRunMutationView, error) {
	manager.validateCalls++
	manager.revisionPath, manager.metadata = path, metadata
	manager.runMutation.Receipt = sourceMutationReceipt(manager.runMutation.Receipt, metadata.TraceID)
	return manager.runMutation, manager.err
}

func (manager *recordingSourceManager) PublishSourceRevision(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourceRevisionPathRequest,
	input assetcatalog.SourceReasonInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.SourceRevisionMutationView, error) {
	manager.publishCalls++
	manager.revisionPath, manager.reasonInput, manager.metadata = path, input, metadata
	manager.revisionMutation.Receipt = sourceMutationReceipt(manager.revisionMutation.Receipt, metadata.TraceID)
	return manager.revisionMutation, manager.err
}

func (manager *recordingSourceManager) DisableSource(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourcePathRequest,
	input assetcatalog.SourceReasonInput,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.SourceMutationView, error) {
	manager.disableCalls++
	manager.path, manager.reasonInput, manager.metadata = path, input, metadata
	manager.sourceMutation.Receipt = sourceMutationReceipt(manager.sourceMutation.Receipt, metadata.TraceID)
	return manager.sourceMutation, manager.err
}

func (manager *recordingSourceManager) SyncSource(
	_ context.Context,
	_ authn.Principal,
	path assetcatalog.SourcePathRequest,
	metadata assetcatalog.ServerRequestMetadata,
) (assetcatalog.SourceRunMutationView, error) {
	manager.syncCalls++
	manager.path, manager.metadata = path, metadata
	manager.runMutation.Receipt = sourceMutationReceipt(manager.runMutation.Receipt, metadata.TraceID)
	return manager.runMutation, manager.err
}

func sourceMutationReceipt(receipt assetcatalog.MutationReceipt, traceID string) assetcatalog.MutationReceipt {
	if receipt.AuditID == "" {
		receipt.AuditID = assetTestAuditID
	}
	receipt.TraceID = traceID
	return receipt
}

func safeSourceRevisionMutation() assetcatalog.SourceRevisionMutationView {
	view := safeSourceView()
	return assetcatalog.SourceRevisionMutationView{
		Source: view.ReadModel.Source, Revision: view.ReadModel.LatestRevision,
		EffectiveActions: view.EffectiveActions,
	}
}

func safeSourceMutation() assetcatalog.SourceMutationView {
	view := safeSourceView()
	return assetcatalog.SourceMutationView{
		Source: view.ReadModel.Source, EffectiveActions: view.EffectiveActions,
	}
}

func safeSourceRunMutation() assetcatalog.SourceRunMutationView {
	view := safeSourceView()
	return assetcatalog.SourceRunMutationView{
		Source: view.ReadModel.Source, Revision: view.ReadModel.LatestRevision,
		Run: safeSourceRun(), EffectiveActions: view.EffectiveActions,
	}
}

func safeSourceView() assetcatalog.SourceView {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	run := safeSourceRun()
	revision := assetcatalog.SourceRevision{
		ID: sourceTestRevisionID, SourceID: assetTestSourceID,
		TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
		Revision: 1, Status: assetcatalog.SourceRevisionPublished,
		ProfileCode: "MANUAL_V1", SyncMode: assetcatalog.SyncModeManual,
		AuthorityEnvironmentIDs: []string{assetTestEnvironmentID},
		SourceDefinitionDigest:  strings.Repeat("a", 64),
		CanonicalRevisionDigest: strings.Repeat("b", 64),
		Version:                 1,
		CreatedAt:               now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Hour),
	}
	return assetcatalog.SourceView{
		ReadModel: assetcatalog.SourceReadModel{
			Source: assetcatalog.Source{
				ID: assetTestSourceID, TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID,
				ProviderKind: "MANUAL_V1", Name: "manual", Kind: assetcatalog.SourceKindManual,
				Status: assetcatalog.SourceStatusActive, PublishedRevision: 1,
				PublishedRevisionDigest: strings.Repeat("b", 64),
				GateStatus:              assetcatalog.SourceGateAvailable, GateReasonCode: "READY", GateRevision: 2,
				CheckpointSHA256: strings.Repeat("c", 64), CheckpointVersion: 1,
				LastSuccessRunID: sourceTestRunID, LastSuccessAt: pointerTime(now.Add(-time.Minute)),
				LastCompleteSnapshotRunID: "", LastCompleteSnapshotAt: nil,
				Version: 3, CreatedAt: now.Add(-3 * time.Hour), UpdatedAt: now,
			},
			LatestRevision: revision, PublishedRevision: &revision,
			CurrentRun: nil, LastSuccessfulRun: &run,
		},
		EffectiveActions: []assetcatalog.EffectiveAction{assetcatalog.ActionCreateAsset},
	}
}

func safeSourceRun() assetcatalog.SourceRun {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	return assetcatalog.SourceRun{
		ID: sourceTestRunID, SourceID: assetTestSourceID,
		Scope:          assetcatalog.SourceScope{TenantID: assetTestTenantID, WorkspaceID: assetTestWorkspaceID},
		SourceRevision: 1, SourceRevisionDigest: strings.Repeat("b", 64),
		Kind: assetcatalog.RunKindManualMutation, Status: assetcatalog.RunStatusSucceeded,
		Stage: assetcatalog.RunStageCompleted, StageChangedAt: now,
		TriggerType: assetcatalog.TriggerHuman, GateRevision: 2,
		PageSequence: 1, RelationPageSequence: 1,
		CursorBeforeSHA256: strings.Repeat("d", 64), CursorAfterSHA256: strings.Repeat("e", 64),
		CheckpointVersion: 1, NotBefore: now.Add(-time.Minute),
		FinalPage: true, CompleteSnapshot: false, EffectiveCompleteSnapshot: false,
		WorkResultKind:   assetcatalog.WorkResultDataProjection,
		WorkResultStatus: assetcatalog.WorkResultStatusSucceeded,
		WorkResultDigest: strings.Repeat("f", 64), WorkResultRecordedAt: pointerTime(now),
		CredentialCleanupStatus: assetcatalog.CredentialCleanupNoCredential,
		Observed:                1, Created: 1, Changed: 0, Unchanged: 0, Conflicts: 0,
		Missing: 0, Stale: 0, Restored: 0, Tombstoned: 0, Rejected: 0,
		TraceID: "0123456789abcdef0123456789abcdef", Version: 4,
		CreatedAt: now.Add(-time.Minute), StartedAt: pointerTime(now.Add(-30 * time.Second)),
		HeartbeatAt: pointerTime(now.Add(-10 * time.Second)), CompletedAt: pointerTime(now),
	}
}

func pointerTime(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}

var _ assetcatalog.SourceManager = (*recordingSourceManager)(nil)
