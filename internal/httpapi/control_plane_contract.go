package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

var (
	errInvalidControlPlaneRequest       = errors.New("invalid control plane request")
	errUnsupportedControlPlaneMediaType = errors.New("unsupported control plane media type")
	errControlPlaneBodyTooLarge         = errors.New("control plane body too large")
)

const controlPlaneContractDigest = "sha256:5f3d4bb6c3b7473f2655f4c7b4839e9d4cb3bf3b115a2ce2e2dd47b32e020082"

type controlPlaneCursor struct {
	Kind        string `json:"kind"`
	QueryDigest string `json:"query_digest"`
	Sort        string `json:"sort"`
	Value       string `json:"value"`
	ID          string `json:"id"`
}

type ControlPlaneCursorCodec struct {
	key [sha256.Size]byte
}

func NewControlPlaneCursorCodec(secret []byte) (*ControlPlaneCursorCodec, error) {
	if len(secret) != sha256.Size {
		return nil, errors.New("control plane cursor secret must contain exactly 32 bytes")
	}
	codec := &ControlPlaneCursorCodec{}
	copy(codec.key[:], secret)
	return codec, nil
}

func (codec *ControlPlaneCursorCodec) encode(cursor controlPlaneCursor) (string, error) {
	if codec == nil || !validControlPlaneCursor(cursor) {
		return "", errInvalidControlPlaneRequest
	}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", errInvalidControlPlaneRequest
	}
	mac := hmac.New(sha256.New, codec.key[:])
	_, _ = mac.Write(payload)
	sealed := make([]byte, 0, len(payload)+sha256.Size)
	sealed = append(sealed, payload...)
	sealed = append(sealed, mac.Sum(nil)...)
	encoded := base64.RawURLEncoding.EncodeToString(sealed)
	if len(encoded) > 2048 {
		return "", errInvalidControlPlaneRequest
	}
	return encoded, nil
}

func (codec *ControlPlaneCursorCodec) decode(encoded, expectedKind string) (controlPlaneCursor, error) {
	if codec == nil || encoded == "" || len(encoded) > 2048 || strings.Contains(encoded, "=") {
		return controlPlaneCursor{}, errInvalidControlPlaneRequest
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(sealed) <= sha256.Size {
		return controlPlaneCursor{}, errInvalidControlPlaneRequest
	}
	payload := sealed[:len(sealed)-sha256.Size]
	actualMAC := sealed[len(sealed)-sha256.Size:]
	expectedMAC := hmac.New(sha256.New, codec.key[:])
	_, _ = expectedMAC.Write(payload)
	if !hmac.Equal(actualMAC, expectedMAC.Sum(nil)) || rejectDuplicateJSONKeys(payload) != nil {
		return controlPlaneCursor{}, errInvalidControlPlaneRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var cursor controlPlaneCursor
	if err := decoder.Decode(&cursor); err != nil {
		return controlPlaneCursor{}, errInvalidControlPlaneRequest
	}
	if err := requireJSONEOF(decoder); err != nil || !validControlPlaneCursor(cursor) || cursor.Kind != expectedKind {
		return controlPlaneCursor{}, errInvalidControlPlaneRequest
	}
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(canonical, payload) {
		return controlPlaneCursor{}, errInvalidControlPlaneRequest
	}
	return cursor, nil
}

func validControlPlaneCursor(cursor controlPlaneCursor) bool {
	sorts := map[string]map[string]struct{}{
		"assets": {
			"display_name_asc": {}, "last_observed_at_desc": {},
		},
		"asset-relations": {
			"relationship_type_asc": {},
		},
		"asset-sources": {
			"source_id_asc": {},
		},
		"asset-conflicts": {
			"created_at_desc": {},
		},
		"service-asset-bindings": {
			"service_id_asc": {},
		},
	}
	allowedSorts, ok := sorts[cursor.Kind]
	if !ok {
		return false
	}
	if _, ok := allowedSorts[cursor.Sort]; !ok {
		return false
	}
	return validSHA256Hex(cursor.QueryDigest) && validControlPlaneUUID(cursor.ID) &&
		len(cursor.Value) <= 1024 && utf8.ValidString(cursor.Value) &&
		strings.TrimSpace(cursor.Value) == cursor.Value &&
		strings.IndexFunc(cursor.Value, unicode.IsControl) < 0
}

func parseIdempotencyKey(request *http.Request) (string, error) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !domain.ValidIdempotencyKey(values[0]) {
		return "", errInvalidControlPlaneRequest
	}
	return values[0], nil
}

func parseVersionETag(request *http.Request, resourceType, resourceID string) (int64, error) {
	values := request.Header.Values("If-Match")
	if len(values) != 1 || !validETagResourceType(resourceType) || !validETagResourceID(resourceID) {
		return 0, errInvalidControlPlaneRequest
	}
	value := values[0]
	prefix := `"` + resourceType + ":" + resourceID + ":v"
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, `"`) ||
		strings.HasPrefix(value, `W/`) || strings.Contains(value, ",") {
		return 0, errInvalidControlPlaneRequest
	}
	versionText := strings.TrimSuffix(strings.TrimPrefix(value, prefix), `"`)
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version <= 0 || strconv.FormatInt(version, 10) != versionText {
		return 0, errInvalidControlPlaneRequest
	}
	return version, nil
}

func sourceVersionETag(sourceID string, sourceVersion int64) string {
	if !validControlPlaneUUID(sourceID) || sourceVersion <= 0 {
		return ""
	}
	return `"asset-source:` + sourceID + `:v` + strconv.FormatInt(sourceVersion, 10) + `"`
}

func sourceRevisionETag(
	sourceID string,
	revision int64,
	sourceVersion int64,
	revisionVersion int64,
) string {
	if !validControlPlaneUUID(sourceID) || revision <= 0 ||
		sourceVersion <= 0 || revisionVersion <= 0 {
		return ""
	}
	return `"asset-source-revision:` + sourceID +
		`:r` + strconv.FormatInt(revision, 10) +
		`:sv` + strconv.FormatInt(sourceVersion, 10) +
		`:rv` + strconv.FormatInt(revisionVersion, 10) + `"`
}

func parseSourceRevisionETag(
	request *http.Request,
	sourceID string,
	revision int64,
) (int64, int64, error) {
	values := request.Header.Values("If-Match")
	if len(values) != 1 || !validControlPlaneUUID(sourceID) || revision <= 0 {
		return 0, 0, errInvalidControlPlaneRequest
	}
	value := values[0]
	prefix := `"asset-source-revision:` + sourceID +
		`:r` + strconv.FormatInt(revision, 10) + `:sv`
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, `"`) ||
		strings.HasPrefix(value, `W/`) || strings.Contains(value, ",") {
		return 0, 0, errInvalidControlPlaneRequest
	}
	versions := strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, prefix), `"`), ":rv")
	if len(versions) != 2 {
		return 0, 0, errInvalidControlPlaneRequest
	}
	sourceVersion, sourceErr := strconv.ParseInt(versions[0], 10, 64)
	revisionVersion, revisionErr := strconv.ParseInt(versions[1], 10, 64)
	if sourceErr != nil || revisionErr != nil || sourceVersion <= 0 || revisionVersion <= 0 ||
		strconv.FormatInt(sourceVersion, 10) != versions[0] ||
		strconv.FormatInt(revisionVersion, 10) != versions[1] {
		return 0, 0, errInvalidControlPlaneRequest
	}
	return sourceVersion, revisionVersion, nil
}

func writeSourceRevisionETag(
	writer http.ResponseWriter,
	sourceID string,
	revision int64,
	sourceVersion int64,
	revisionVersion int64,
) {
	if value := sourceRevisionETag(sourceID, revision, sourceVersion, revisionVersion); value != "" {
		writer.Header().Set("ETag", value)
	}
}

func writeVersionETag(writer http.ResponseWriter, resourceType, resourceID string, version int64) {
	if !validETagResourceType(resourceType) || !validETagResourceID(resourceID) || version <= 0 {
		return
	}
	writer.Header().Set("ETag", `"`+resourceType+":"+resourceID+":v"+strconv.FormatInt(version, 10)+`"`)
}

func validETagResourceType(value string) bool {
	if value == "" || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validETagResourceID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\"\\,\r\n\t\x00")
}

func decodeStrictJSON(
	writer http.ResponseWriter,
	request *http.Request,
	target any,
	maxBytes int64,
) error {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || target == nil || maxBytes <= 0 {
		return errUnsupportedControlPlaneMediaType
	}
	contentType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || contentType != "application/json" {
		return errUnsupportedControlPlaneMediaType
	}
	if len(parameters) > 1 || (len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8")) {
		return errUnsupportedControlPlaneMediaType
	}
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxBytes))
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			return errControlPlaneBodyTooLarge
		}
		return errInvalidControlPlaneRequest
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || rejectDuplicateJSONKeys(trimmed) != nil {
		return errInvalidControlPlaneRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidControlPlaneRequest
	}
	if err := requireJSONEOF(decoder); err != nil {
		return errInvalidControlPlaneRequest
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 0); err != nil {
		return errInvalidControlPlaneRequest
	}
	return requireJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= 32 {
		return errInvalidControlPlaneRequest
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return errInvalidControlPlaneRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return errInvalidControlPlaneRequest
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidControlPlaneRequest
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidControlPlaneRequest
		}
	default:
		return errInvalidControlPlaneRequest
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidControlPlaneRequest
	}
	return nil
}

type problemDTO struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Detail  string `json:"detail"`
	TraceID string `json:"trace_id"`
}

func writeRequestProblem(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	code string,
	detail string,
) {
	traceID := requestmeta.From(request.Context()).TraceID
	if !validTraceID(traceID) {
		traceID = writer.Header().Get("X-Trace-ID")
	}
	writeProblemWithTrace(writer, status, code, detail, traceID)
}

func writeProblem(writer http.ResponseWriter, status int, code, detail string) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"type": "about:blank", "title": http.StatusText(status), "status": status,
		"code": code, "detail": detail,
	})
}

func writeProblemWithTrace(writer http.ResponseWriter, status int, code, detail, traceID string) {
	if !validTraceID(traceID) {
		traceID = strings.ReplaceAll(ids.NewUUID(), "-", "")
		writer.Header().Set("X-Trace-ID", traceID)
	}
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(problemDTO{
		Type: "about:blank", Title: http.StatusText(status), Status: status,
		Code: code, Detail: detail, TraceID: traceID,
	})
}

func controlPlaneResponseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1" || strings.HasPrefix(request.URL.Path, "/api/v1/") {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Pragma", "no-cache")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("Referrer-Policy", "no-referrer")
		}
		next.ServeHTTP(writer, request)
	})
}

func validTraceID(value string) bool {
	return len(value) == 32 && value == strings.ToLower(value) && validHex(value, 32) &&
		strings.Trim(value, "0") != ""
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validControlPlaneSafeText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == utf8.RuneError || character == 0 || character == '\r' || character == '\n' ||
			unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func validControlPlaneReasonCode(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if character < 'A' || character > 'Z' {
			if character < '0' || character > '9' {
				if character != '_' {
					return false
				}
			}
		}
	}
	return true
}

func validControlPlaneUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value || parsed.Variant() != uuid.RFC4122 {
		return false
	}
	version := parsed.Version()
	return version >= 1 && version <= 5
}

func parseControlPlaneQuery(request *http.Request, allowed ...string) (url.Values, error) {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, errInvalidControlPlaneRequest
	}
	for key, entries := range values {
		if _, ok := allowedSet[key]; !ok || len(entries) != 1 || entries[0] == "" {
			return nil, errInvalidControlPlaneRequest
		}
	}
	return values, nil
}

func parseControlPlaneLimit(values url.Values) (int, error) {
	raw := values.Get("limit")
	if raw == "" {
		return 50, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != raw {
		return 0, errInvalidControlPlaneRequest
	}
	return limit, nil
}

func parseControlPlaneStringSet[T ~string](
	raw string,
	maximum int,
	valid func(T) bool,
) ([]T, error) {
	if raw == "" {
		return []T{}, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maximum {
		return nil, errInvalidControlPlaneRequest
	}
	seen := make(map[T]struct{}, len(parts))
	result := make([]T, 0, len(parts))
	for _, part := range parts {
		value := T(part)
		if part == "" || !valid(value) {
			return nil, errInvalidControlPlaneRequest
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errInvalidControlPlaneRequest
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func parseControlPlaneUUIDSet(raw string, maximum int) ([]string, error) {
	return parseControlPlaneStringSet(raw, maximum, validControlPlaneUUID)
}

func ControlPlaneContractDigest() string {
	return controlPlaneContractDigest
}
