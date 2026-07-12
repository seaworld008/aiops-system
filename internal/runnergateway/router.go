package runnergateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

type identityContextKey struct{}
type principalContextKey struct{}
type requestIDContextKey struct{}

type problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
}

type protocolProblem struct {
	status int
	typeID string
	code   string
	title  string
	detail string
}

type operationClass uint8

const (
	identityOperation operationClass = iota
	leaseOperation
	resourceOperation
)

func NewRouter(verifier IdentityVerifier, backend Backend) (http.Handler, error) {
	return newRouter(verifier, backend, nil)
}

// NewRouterWithReadTasks adds the READ-only investigation task protocol to
// the existing TLS-only Runner listener. READ routes share the mature outer
// mTLS/request-shape boundaries but retain a distinct backend, DTO set, paths,
// and lease scheme from WRITE jobs.
func NewRouterWithReadTasks(
	verifier IdentityVerifier,
	backend Backend,
	readBackend ReadTaskBackend,
) (http.Handler, error) {
	if nilInterface(readBackend) {
		return nil, fmt.Errorf("READ Task Gateway backend is required")
	}
	return newRouter(verifier, backend, readBackend)
}

func newRouter(verifier IdentityVerifier, backend Backend, readBackend ReadTaskBackend) (http.Handler, error) {
	if nilInterface(verifier) || nilInterface(backend) {
		return nil, fmt.Errorf("Runner Gateway verifier and backend are required")
	}
	router := chi.NewRouter()
	router.Use(recoveryBoundary)
	router.Use(responseHeadersBoundary)
	router.Use(identityBoundary(verifier, backend))
	router.Use(requestShapeBoundary)
	router.NotFound(func(writer http.ResponseWriter, request *http.Request) {
		writeProtocolProblem(writer, request, notFoundProblem())
	})
	router.MethodNotAllowed(func(writer http.ResponseWriter, request *http.Request) {
		writeProtocolProblem(writer, request, notFoundProblem())
	})
	router.Get("/runner/v1/identity", func(writer http.ResponseWriter, request *http.Request) {
		if !bodyAbsent(request) || len(request.Header.Values("Authorization")) != 0 {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		identity := identityFromContext(request.Context())
		response, err := backend.Identity(request.Context(), identity)
		writeBackendResult(writer, request, identityOperation, http.StatusOK, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity})
	})
	router.Post("/runner/v1/jobs:lease", func(writer http.ResponseWriter, request *http.Request) {
		var input JobLeaseRequest
		if len(request.Header.Values("Authorization")) != 0 {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		if !decodeRequest(writer, request, leaseBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		principal := principalFromContext(request.Context())
		if principal.Pool() == runneridentity.PoolRead {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		if !writePrincipal(principal) {
			writeProtocolProblem(writer, request, identityRejectedProblem())
			return
		}
		identity := identityFromContext(request.Context())
		response, err := backend.LeaseJob(request.Context(), identity, input)
		if err == nil && response == nil {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writeBackendResult(writer, request, leaseOperation, http.StatusOK, leaseBodyLimit, response, err,
			backendResponseBinding{identity: identity})
	})
	router.Post("/runner/v1/jobs/{job_id}:credential-anchor", jobLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, resourceID, token string, writer http.ResponseWriter, request *http.Request,
	) {
		var input CredentialAnchorRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		response, err := backend.AnchorCredential(ctx, identity, resourceID, token, input)
		writeBackendResult(writer, request, resourceOperation, http.StatusOK, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity, jobID: resourceID, revocationID: input.RevocationID,
				epoch: input.LeaseEpoch, credentialPhase: input.Phase})
	}))
	router.Post("/runner/v1/jobs/{job_id}:start", jobLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, resourceID, token string, writer http.ResponseWriter, request *http.Request,
	) {
		var input JobStartRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		response, err := backend.StartJob(ctx, identity, resourceID, token, input)
		writeBackendResult(writer, request, resourceOperation, http.StatusOK, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity, jobID: resourceID, epoch: input.LeaseEpoch})
	}))
	router.Post("/runner/v1/jobs/{job_id}:heartbeat", jobLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, resourceID, token string, writer http.ResponseWriter, request *http.Request,
	) {
		var input JobHeartbeatRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		response, err := backend.HeartbeatJob(ctx, identity, resourceID, token, input)
		writeBackendResult(writer, request, resourceOperation, http.StatusOK, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity, jobID: resourceID, epoch: input.LeaseEpoch, sequence: input.Sequence})
	}))
	router.Post("/runner/v1/jobs/{job_id}:release", jobLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, resourceID, token string, writer http.ResponseWriter, request *http.Request,
	) {
		var input JobReleaseRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		response, err := backend.ReleaseJob(ctx, identity, resourceID, token, input)
		writeBackendResult(writer, request, resourceOperation, http.StatusOK, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity, jobID: resourceID, epoch: input.LeaseEpoch})
	}))
	router.Post("/runner/v1/jobs/{job_id}:complete", jobLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, resourceID, token string, writer http.ResponseWriter, request *http.Request,
	) {
		var input JobCompleteRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		response, err := backend.CompleteJob(ctx, identity, resourceID, token, input)
		status := http.StatusOK
		if response.Status == "FINALIZING" {
			status = http.StatusAccepted
		}
		writeBackendResult(writer, request, resourceOperation, status, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity, jobID: resourceID, epoch: input.LeaseEpoch,
				resultOutcome: input.Result.Outcome})
	}))
	router.Post("/runner/v1/revocations:lease", func(writer http.ResponseWriter, request *http.Request) {
		var input RevocationLeaseRequest
		if len(request.Header.Values("Authorization")) != 0 {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		if !decodeRequest(writer, request, leaseBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		if !revocationPrincipal(principalFromContext(request.Context())) {
			writeProtocolProblem(writer, request, identityRejectedProblem())
			return
		}
		identity := identityFromContext(request.Context())
		response, err := backend.LeaseRevocation(request.Context(), identity, input)
		if err == nil && response == nil {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writeBackendResult(writer, request, leaseOperation, http.StatusOK, leaseBodyLimit, response, err,
			backendResponseBinding{identity: identity})
	})
	router.Post("/runner/v1/revocations/{revocation_id}:heartbeat", revocationLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, resourceID, token string, writer http.ResponseWriter, request *http.Request,
	) {
		var input RevocationHeartbeatRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		response, err := backend.HeartbeatRevocation(ctx, identity, resourceID, token, input)
		writeBackendResult(writer, request, resourceOperation, http.StatusOK, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity, revocationID: resourceID, epoch: input.ClaimEpoch, sequence: input.Sequence})
	}))
	router.Post("/runner/v1/revocations/{revocation_id}:complete", revocationLeaseHandler(func(
		ctx context.Context, identity runneridentity.Identity, resourceID, token string, writer http.ResponseWriter, request *http.Request,
	) {
		var input RevocationCompleteRequest
		if !decodeRequest(writer, request, defaultBodyLimit, &input) {
			return
		}
		if !input.valid() {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		response, err := backend.CompleteRevocation(ctx, identity, resourceID, token, input)
		writeBackendResult(writer, request, resourceOperation, http.StatusOK, defaultBodyLimit, response, err,
			backendResponseBinding{identity: identity, revocationID: resourceID, epoch: input.ClaimEpoch,
				revocationOutcome: input.Outcome})
	}))
	if !nilInterface(readBackend) {
		registerReadTaskRoutes(router, readBackend)
	}
	return router, nil
}

type leasedResourceHandler func(context.Context, runneridentity.Identity, string, string, http.ResponseWriter, *http.Request)

func jobLeaseHandler(next leasedResourceHandler) http.HandlerFunc {
	return leasedHandler("job_id", "AIOPS-Job-Lease ", validPathResourceID, writePrincipal, next)
}

func revocationLeaseHandler(next leasedResourceHandler) http.HandlerFunc {
	return leasedHandler("revocation_id", "AIOPS-Revocation-Lease ", uuidPattern.MatchString, revocationPrincipal, next)
}

func leasedHandler(
	pathParameter, scheme string,
	validID func(string) bool,
	principalAllowed func(RequestPrincipal) bool,
	next leasedResourceHandler,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !principalAllowed(principalFromContext(request.Context())) {
			writeProtocolProblem(writer, request, identityRejectedProblem())
			return
		}
		resourceID := chi.URLParam(request, pathParameter)
		if !validID(resourceID) {
			writeProtocolProblem(writer, request, notFoundProblem())
			return
		}
		token, ok := leaseAuthorization(request, scheme)
		if !ok {
			writeProtocolProblem(writer, request, leaseAuthenticationProblem())
			return
		}
		next(request.Context(), identityFromContext(request.Context()), resourceID, token, writer, request)
	}
}

func writePrincipal(principal RequestPrincipal) bool {
	return !nilInterface(principal) && principal.Valid() && principal.Pool() == runneridentity.PoolWrite
}

func revocationPrincipal(principal RequestPrincipal) bool {
	return writePrincipal(principal) && principal.CredentialRevocationCapable()
}

func responseHeadersBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		requestID := safeRequestID(ids.NewUUID)
		writer.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(request.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func requestShapeBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if len(request.Header.Values("Content-Encoding")) != 0 {
			writeProtocolProblem(writer, request, unsupportedMediaTypeProblem())
			return
		}
		if strings.Contains(request.URL.EscapedPath(), "%") || forbiddenIdentityHeader(request.Header) {
			writeProtocolProblem(writer, request, forbiddenIdentityFieldProblem())
			return
		}
		if request.URL.RawQuery != "" {
			writeProtocolProblem(writer, request, invalidRequestProblem())
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func recoveryBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		buffer := newBufferedResponse()
		defer func() {
			if recover() != nil {
				requestID := buffer.Header().Get("X-Request-ID")
				if requestID == "" {
					requestID = safeRequestID(ids.NewUUID)
				}
				buffer.reset()
				buffer.Header().Set("Cache-Control", "no-store")
				buffer.Header().Set("X-Content-Type-Options", "nosniff")
				buffer.Header().Set("X-Request-ID", requestID)
				ctx := context.WithValue(request.Context(), requestIDContextKey{}, requestID)
				writeProtocolProblem(buffer, request.WithContext(ctx), internalProblem())
			}
			buffer.commit(writer)
		}()
		next.ServeHTTP(buffer, request)
	})
}

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header)}
}

func (response *bufferedResponse) Header() http.Header { return response.header }

func (response *bufferedResponse) WriteHeader(status int) {
	if response.status == 0 {
		response.status = status
	}
}

func (response *bufferedResponse) Write(value []byte) (int, error) {
	if response.status == 0 {
		response.status = http.StatusOK
	}
	return response.body.Write(value)
}

func (response *bufferedResponse) reset() {
	response.header = make(http.Header)
	clear(response.body.Bytes())
	response.body.Reset()
	response.status = 0
}

func (response *bufferedResponse) commit(writer http.ResponseWriter) {
	body := response.body.Bytes()
	if len(body) != 0 {
		defer func() {
			clear(body)
			response.body.Reset()
		}()
	}
	for name, values := range response.header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	writer.WriteHeader(status)
	if len(body) != 0 {
		_, _ = writer.Write(body)
	}
}

func safeRequestID(generate func() string) (requestID string) {
	requestID = "00000000-0000-4000-8000-000000000000"
	defer func() { _ = recover() }()
	if generated := generate(); generated != "" {
		requestID = generated
	}
	return requestID
}

func identityBoundary(verifier IdentityVerifier, backend Backend) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.TLS == nil {
				writeProtocolProblem(writer, request, identityRejectedProblem())
				return
			}
			identity, err := verifier.IdentityFromConnectionState(*request.TLS)
			if err != nil || !identity.Valid() {
				writeProtocolProblem(writer, request, identityRejectedProblem())
				return
			}
			principal, err := backend.AuthenticateRequest(request.Context(), identity)
			if err != nil {
				if errors.Is(err, ErrUnavailable) {
					writeProtocolProblem(writer, request, backendProblem(err))
				} else {
					writeProtocolProblem(writer, request, identityRejectedProblem())
				}
				return
			}
			if !validRequestPrincipal(identity, principal) {
				writeProtocolProblem(writer, request, identityRejectedProblem())
				return
			}
			ctx := context.WithValue(request.Context(), identityContextKey{}, identity)
			ctx = context.WithValue(ctx, principalContextKey{}, principal)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

func decodeRequest(writer http.ResponseWriter, request *http.Request, limit int64, target any) bool {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" || len(request.Header.Values("Content-Encoding")) != 0 {
		writeProtocolProblem(writer, request, unsupportedMediaTypeProblem())
		return false
	}
	if request.ContentLength > limit {
		writeProtocolProblem(writer, request, payloadTooLargeProblem())
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil {
		writeProtocolProblem(writer, request, invalidJSONProblem())
		return false
	}
	if int64(len(body)) > limit {
		writeProtocolProblem(writer, request, payloadTooLargeProblem())
		return false
	}
	if len(body) == 0 || !utf8.Valid(body) || rejectDuplicateOrTrailingJSON(body) != nil {
		writeProtocolProblem(writer, request, invalidJSONProblem())
		return false
	}
	if exactJSONFieldNames(body, reflect.TypeOf(target)) != nil {
		writeProtocolProblem(writer, request, invalidJSONProblem())
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeProtocolProblem(writer, request, invalidJSONProblem())
		return false
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeProtocolProblem(writer, request, invalidJSONProblem())
		return false
	}
	if requestFieldPresence(body, target) != nil {
		writeProtocolProblem(writer, request, invalidJSONProblem())
		return false
	}
	return true
}

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

func exactJSONFieldNames(encoded []byte, targetType reflect.Type) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return validateJSONFieldNames(value, targetType)
}

func validateJSONFieldNames(value any, targetType reflect.Type) error {
	if targetType == nil {
		return errors.New("missing JSON target type")
	}
	for targetType.Kind() == reflect.Pointer {
		if targetType.Implements(jsonUnmarshalerType) {
			return nil
		}
		targetType = targetType.Elem()
	}
	if targetType.Implements(jsonUnmarshalerType) ||
		(targetType.Kind() != reflect.Pointer && reflect.PointerTo(targetType).Implements(jsonUnmarshalerType)) {
		return nil
	}
	if value == nil {
		return errors.New("explicit JSON null is not allowed")
	}
	switch targetType.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("JSON value is not an object")
		}
		fields := make(map[string]reflect.Type, targetType.NumField())
		for index := 0; index < targetType.NumField(); index++ {
			field := targetType.Field(index)
			if field.PkgPath != "" {
				continue
			}
			tag := field.Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, child := range object {
			fieldType, exists := fields[name]
			if !exists {
				return errors.New("JSON property name does not exactly match the wire contract")
			}
			if err := validateJSONFieldNames(child, fieldType); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		values, ok := value.([]any)
		if !ok {
			return errors.New("JSON value is not an array")
		}
		for _, child := range values {
			if err := validateJSONFieldNames(child, targetType.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || targetType.Key().Kind() != reflect.String {
			return errors.New("JSON value is not a string-keyed object")
		}
		for _, child := range object {
			if err := validateJSONFieldNames(child, targetType.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func requestFieldPresence(encoded []byte, target any) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		return err
	}
	switch request := target.(type) {
	case *CredentialAnchorRequest:
		_, permitPresent := object["child_create_permit"]
		_, accessorPresent := object["revoke_accessor_b64u"]
		switch request.Phase {
		case "AUTHORIZE_CHILD_CREATE":
			if !permitPresent || accessorPresent {
				return errors.New("credential authorization fields do not match phase")
			}
		case "RECORD_ANCHOR":
			if permitPresent || !accessorPresent {
				return errors.New("credential anchor fields do not match phase")
			}
		case "ACTIVATE", "NO_CREDENTIAL", "REQUEST_REVOCATION":
			if permitPresent || accessorPresent {
				return errors.New("credential state phase contains a forbidden field")
			}
		}
	case *RevocationCompleteRequest:
		_, failurePresent := object["failure_code"]
		if (request.Outcome == "FAILED") != failurePresent {
			return errors.New("revocation completion fields do not match outcome")
		}
	case *JobCompleteRequest:
		var result map[string]json.RawMessage
		if err := json.Unmarshal(object["result"], &result); err != nil {
			return err
		}
		if _, present := result["changed"]; !present {
			return errors.New("executor result changed field is required")
		}
		if raw, present := result["external_operation_ref_hash"]; present {
			var value string
			if err := json.Unmarshal(raw, &value); err != nil || value == "" {
				return errors.New("external operation reference hash is empty or null")
			}
		}
	case *ReadTaskCompleteRequest:
		_, schemaPresent := object["schema_version"]
		_, epochPresent := object["lease_epoch"]
		_, outcomePresent := object["outcome"]
		_, evidencePresent := object["evidence"]
		_, failurePresent := object["failure_code"]
		if !schemaPresent || !epochPresent || !outcomePresent {
			return errors.New("READ completion required fields are missing")
		}
		switch request.Outcome {
		case readtask.CompletionEvidence:
			if !evidencePresent || failurePresent {
				return errors.New("READ Evidence completion fields do not match outcome")
			}
			var evidence map[string]json.RawMessage
			if err := json.Unmarshal(object["evidence"], &evidence); err != nil {
				return err
			}
			if _, present := evidence["collected_at"]; !present {
				return errors.New("READ Evidence collected_at field is required")
			}
			if _, present := evidence["items"]; !present {
				return errors.New("READ Evidence items field is required")
			}
		case readtask.CompletionFailed, readtask.CompletionCancelled:
			if evidencePresent || !failurePresent {
				return errors.New("READ failure completion fields do not match outcome")
			}
		}
	}
	return nil
}

func rejectDuplicateOrTrailingJSON(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := walkJSONValue(decoder, first); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			child, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONValue(decoder, child); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
		return nil
	case '[':
		for decoder.More() {
			child, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONValue(decoder, child); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("trailing JSON value")
}

func writeBackendResult(
	writer http.ResponseWriter,
	request *http.Request,
	operation operationClass,
	status int,
	limit int64,
	value any,
	err error,
	binding backendResponseBinding,
) {
	if err != nil {
		problem := backendProblem(err)
		if !operationAllowsStatus(operation, problem.status) {
			problem = internalProblem()
		}
		writeProtocolProblem(writer, request, problem)
		return
	}
	binding.identity = identityFromContext(request.Context())
	binding.principal = principalFromContext(request.Context())
	if !validBackendResponse(value, binding) {
		writeProtocolProblem(writer, request, internalProblem())
		return
	}
	encoded, marshalErr := json.Marshal(value)
	if marshalErr != nil || int64(len(encoded)) > limit {
		writeProtocolProblem(writer, request, internalProblem())
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func operationAllowsStatus(operation operationClass, status int) bool {
	switch operation {
	case identityOperation:
		return status == http.StatusForbidden || status == http.StatusServiceUnavailable || status == http.StatusInternalServerError
	case leaseOperation:
		return status == http.StatusBadRequest || status == http.StatusForbidden || status == http.StatusTooManyRequests ||
			status == http.StatusServiceUnavailable || status == http.StatusInternalServerError
	case resourceOperation:
		return status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden ||
			status == http.StatusNotFound || status == http.StatusConflict || status == http.StatusServiceUnavailable ||
			status == http.StatusInternalServerError
	default:
		return status == http.StatusInternalServerError
	}
}

func writeProtocolProblem(writer http.ResponseWriter, request *http.Request, value protocolProblem) {
	requestID, _ := request.Context().Value(requestIDContextKey{}).(string)
	if requestID == "" {
		requestID = safeRequestID(ids.NewUUID)
	}
	encoded, err := json.Marshal(problem{
		Type: value.typeID, Title: value.title, Status: value.status, Code: value.code,
		Detail: value.detail, Instance: "urn:aiops:request:" + requestID,
	})
	if err != nil {
		encoded = []byte(`{"type":"urn:aiops:problem:runner:internal-error","title":"Internal error","status":500,"code":"runner_internal_error","detail":"The request could not be completed","instance":"urn:aiops:request:00000000-0000-4000-8000-000000000000"}`)
		value.status = http.StatusInternalServerError
	}
	writer.Header().Set("Content-Type", "application/problem+json")
	if value.status == http.StatusUnauthorized {
		challenge := "AIOPS-Job-Lease realm=\"runner-gateway\""
		if strings.Contains(request.URL.Path, "/read-tasks/") {
			challenge = "AIOPS-Read-Task-Lease realm=\"runner-gateway\""
		} else if strings.Contains(request.URL.Path, "/revocations/") {
			challenge = "AIOPS-Revocation-Lease realm=\"runner-gateway\""
		}
		writer.Header().Set("WWW-Authenticate", challenge)
	}
	if value.status == http.StatusTooManyRequests {
		writer.Header().Set("Retry-After", "1")
	}
	writer.WriteHeader(value.status)
	_, _ = writer.Write(encoded)
}

func backendProblem(err error) protocolProblem {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return invalidRequestProblem()
	case errors.Is(err, ErrLeaseAuthentication):
		return leaseAuthenticationProblem()
	case errors.Is(err, ErrForbidden):
		return identityRejectedProblem()
	case errors.Is(err, ErrNotFound):
		return notFoundProblem()
	case errors.Is(err, ErrStaleLease):
		return protocolProblem{409, "urn:aiops:problem:runner:stale-lease", "runner_stale_lease", "Stale lease", "The lease fence is no longer current"}
	case errors.Is(err, ErrHeartbeatConflict):
		return protocolProblem{409, "urn:aiops:problem:runner:heartbeat-sequence-conflict", "runner_heartbeat_sequence_conflict", "Heartbeat conflict", "The heartbeat sequence is not current"}
	case errors.Is(err, ErrCredentialConflict):
		return protocolProblem{409, "urn:aiops:problem:runner:credential-anchor-conflict", "runner_credential_anchor_conflict", "Credential conflict", "The credential phase conflicts with durable state"}
	case errors.Is(err, ErrResultConflict):
		return protocolProblem{409, "urn:aiops:problem:runner:result-conflict", "runner_result_conflict", "Result conflict", "The result conflicts with the durable receipt"}
	case errors.Is(err, ErrStateConflict):
		return protocolProblem{409, "urn:aiops:problem:runner:state-conflict", "runner_state_conflict", "State conflict", "The resource is not in the required state"}
	case errors.Is(err, ErrRateLimited):
		return protocolProblem{429, "urn:aiops:problem:runner:rate-limited", "runner_rate_limited", "Rate limited", "The Runner request rate limit was exceeded"}
	case errors.Is(err, ErrClaimsDisabled):
		return protocolProblem{503, "urn:aiops:problem:runner:claims-disabled", "runner_claims_disabled", "Claims disabled", "Runner claims are disabled"}
	case errors.Is(err, ErrUnavailable):
		return protocolProblem{503, "urn:aiops:problem:runner:dependency-unavailable", "runner_dependency_unavailable", "Dependency unavailable", "A required dependency is unavailable"}
	default:
		return internalProblem()
	}
}

func invalidRequestProblem() protocolProblem {
	return protocolProblem{400, "urn:aiops:problem:runner:invalid-request", "invalid_runner_request", "Invalid request", "The Runner request is invalid"}
}
func invalidJSONProblem() protocolProblem {
	return protocolProblem{400, "urn:aiops:problem:runner:invalid-json", "invalid_runner_json", "Invalid JSON", "The JSON body is not a single strict object"}
}
func forbiddenIdentityFieldProblem() protocolProblem {
	return protocolProblem{400, "urn:aiops:problem:runner:forbidden-identity-field", "forbidden_runner_identity_field", "Forbidden identity field", "Runner identity must come only from mTLS"}
}
func leaseAuthenticationProblem() protocolProblem {
	return protocolProblem{401, "urn:aiops:problem:runner:lease-authentication-failed", "runner_lease_authentication_failed", "Lease authentication failed", "A valid lease authorization is required"}
}
func identityRejectedProblem() protocolProblem {
	return protocolProblem{403, "urn:aiops:problem:runner:identity-rejected", "runner_identity_rejected", "Identity rejected", "The mTLS Runner identity is not authorized"}
}
func notFoundProblem() protocolProblem {
	return protocolProblem{404, "urn:aiops:problem:runner:resource-not-found", "runner_resource_not_found", "Resource not found", "The requested Runner resource was not found"}
}
func payloadTooLargeProblem() protocolProblem {
	return protocolProblem{413, "urn:aiops:problem:runner:payload-too-large", "runner_payload_too_large", "Payload too large", "The request body exceeds the endpoint limit"}
}
func unsupportedMediaTypeProblem() protocolProblem {
	return protocolProblem{415, "urn:aiops:problem:runner:unsupported-media-type", "runner_unsupported_media_type", "Unsupported media type", "Content-Type must be exactly application/json"}
}
func internalProblem() protocolProblem {
	return protocolProblem{500, "urn:aiops:problem:runner:internal-error", "runner_internal_error", "Internal error", "The request could not be completed"}
}

func leaseAuthorization(request *http.Request, scheme string) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], scheme) {
		return "", false
	}
	token := strings.TrimPrefix(values[0], scheme)
	return token, tokenPattern.MatchString(token)
}

func forbiddenIdentityHeader(header http.Header) bool {
	for name := range header {
		normalized := strings.ToLower(name)
		if strings.Contains(normalized, "client-cert") || strings.Contains(normalized, "client-certificate") ||
			strings.Contains(normalized, "ssl-client") || strings.Contains(normalized, "forwarded-client") ||
			strings.Contains(normalized, "runner-id") || strings.Contains(normalized, "runner-pool") ||
			strings.Contains(normalized, "scope-revision") || strings.Contains(normalized, "spiffe") {
			return true
		}
	}
	return false
}

func bodyAbsent(request *http.Request) bool {
	return request.ContentLength == 0 && len(request.TransferEncoding) == 0
}

func identityFromContext(ctx context.Context) runneridentity.Identity {
	identity, _ := ctx.Value(identityContextKey{}).(runneridentity.Identity)
	return identity
}

func principalFromContext(ctx context.Context) RequestPrincipal {
	principal, _ := ctx.Value(principalContextKey{}).(RequestPrincipal)
	return principal
}

func validRequestPrincipal(identity runneridentity.Identity, principal RequestPrincipal) bool {
	return identity.Valid() && !nilInterface(principal) && principal.Valid() && validResourceID(principal.RunnerID()) &&
		uuidPattern.MatchString(principal.TenantID()) && principal.Pool().Valid() && principal.Pool() == identity.Pool() &&
		principal.ScopeRevision() > 0 && principal.MaxConcurrency() >= 1 && principal.MaxConcurrency() <= 1024 &&
		(!principal.CredentialRevocationCapable() || principal.Pool() == runneridentity.PoolWrite) &&
		hashPattern.MatchString(principal.CertificateSHA256()) && !principal.CertificateNotAfter().IsZero() &&
		principal.CertificateSHA256() == identity.Evidence().LeafSHA256() &&
		principal.CertificateNotAfter().Equal(identity.Evidence().NotAfter())
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
