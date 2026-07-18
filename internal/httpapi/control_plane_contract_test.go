package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

const (
	contractTestAssetID            = "11111111-1111-4111-8111-111111111111"
	contractTestDigest             = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contractTestTraceID            = "0123456789abcdef0123456789abcdef"
	contractTestControlPlaneDigest = "sha256:79b697cfef1646ce9b54595dcd30dc42fbd03f8e79d3d9f731fd7c349017611d"
)

func TestControlPlaneContractDigestPinsSessionContractRevision(t *testing.T) {
	t.Parallel()
	if got := ControlPlaneContractDigest(); got != contractTestControlPlaneDigest {
		t.Fatalf("ControlPlaneContractDigest() = %q, want %q", got, contractTestControlPlaneDigest)
	}
}

func TestDecodeStrictJSONRejectsDuplicateUnknownTrailingAndNonObjectValues(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"duplicate":        `{"reason_code":"A","reason_code":"B"}`,
		"nested duplicate": `{"reason_code":"A","nested":{"x":1,"x":2}}`,
		"unknown":          `{"reason_code":"A","unknown":true}`,
		"trailing":         `{"reason_code":"A"}{"reason_code":"B"}`,
		"null":             `null`,
		"array":            `[]`,
		"empty":            ``,
	}
	for name, body := range cases {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			var target struct {
				ReasonCode string `json:"reason_code"`
			}
			if err := decodeStrictJSON(recorder, request, &target, 1024); !errors.Is(err, errInvalidControlPlaneRequest) {
				t.Fatalf("decodeStrictJSON(%s) error = %v, want invalid request", name, err)
			}
		})
	}
}

func TestDecodeStrictJSONRejectsUnsupportedMediaTypeOversizeAndExcessiveDepth(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		contentTypes []string
	}{
		{name: "missing"},
		{name: "wrong", contentTypes: []string{"text/plain"}},
		{name: "duplicate", contentTypes: []string{"application/json", "application/json"}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason_code":"A"}`))
			for _, contentType := range test.contentTypes {
				request.Header.Add("Content-Type", contentType)
			}
			var target struct {
				ReasonCode string `json:"reason_code"`
			}
			if err := decodeStrictJSON(httptest.NewRecorder(), request, &target, 1024); !errors.Is(err, errUnsupportedControlPlaneMediaType) {
				t.Fatalf("decodeStrictJSON Content-Type %q error = %v", test.contentTypes, err)
			}
		})
	}

	oversized := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason_code":"`+strings.Repeat("a", 1024)+`"}`))
	oversized.Header.Set("Content-Type", "application/json")
	var target struct {
		ReasonCode string `json:"reason_code"`
	}
	if err := decodeStrictJSON(httptest.NewRecorder(), oversized, &target, 64); !errors.Is(err, errControlPlaneBodyTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}

	deep := strings.Repeat(`{"x":`, 33) + `1` + strings.Repeat(`}`, 33)
	deepRequest := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(deep))
	deepRequest.Header.Set("Content-Type", "application/json")
	var nested map[string]any
	if err := decodeStrictJSON(httptest.NewRecorder(), deepRequest, &nested, 4096); !errors.Is(err, errInvalidControlPlaneRequest) {
		t.Fatalf("deep JSON error = %v", err)
	}
}

func TestDecodeStrictJSONAcceptsOneClosedObject(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason_code":"A"}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	var target struct {
		ReasonCode string `json:"reason_code"`
	}
	if err := decodeStrictJSON(httptest.NewRecorder(), request, &target, 1024); err != nil {
		t.Fatalf("decodeStrictJSON() error = %v", err)
	}
	if target.ReasonCode != "A" {
		t.Fatalf("ReasonCode = %q", target.ReasonCode)
	}
}

func TestParseIdempotencyKeyUsesCanonicalDomainGrammar(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Idempotency-Key", "asset:create:request-1")
	if value, err := parseIdempotencyKey(request); err != nil || value != "asset:create:request-1" {
		t.Fatalf("parseIdempotencyKey() = (%q, %v)", value, err)
	}
	for _, values := range [][]string{
		nil,
		{"UPPERCASE"},
		{"contains space"},
		{"a", "b"},
		{strings.Repeat("a", 129)},
	} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		for _, value := range values {
			request.Header.Add("Idempotency-Key", value)
		}
		if _, err := parseIdempotencyKey(request); !errors.Is(err, errInvalidControlPlaneRequest) {
			t.Errorf("values %#v error = %v", values, err)
		}
	}
}

func TestVersionETagRejectsWeakWildcardMultipleAndWrongResource(t *testing.T) {
	t.Parallel()
	valid := httptest.NewRequest(http.MethodPatch, "/", nil)
	valid.Header.Set("If-Match", `"asset:`+contractTestAssetID+`:v2"`)
	if version, err := parseVersionETag(valid, "asset", contractTestAssetID); err != nil || version != 2 {
		t.Fatalf("parseVersionETag(valid) = (%d, %v)", version, err)
	}

	for _, values := range [][]string{
		{`W/"asset:` + contractTestAssetID + `:v2"`},
		{"*"},
		{`"source:` + contractTestAssetID + `:v2"`},
		{`"asset:22222222-2222-4222-8222-222222222222:v2"`},
		{`"asset:` + contractTestAssetID + `:v0"`},
		{`"asset:` + contractTestAssetID + `:v2","asset:` + contractTestAssetID + `:v3"`},
		{`"asset:` + contractTestAssetID + `:v2"`, `"asset:` + contractTestAssetID + `:v2"`},
	} {
		request := httptest.NewRequest(http.MethodPatch, "/", nil)
		for _, value := range values {
			request.Header.Add("If-Match", value)
		}
		if _, err := parseVersionETag(request, "asset", contractTestAssetID); !errors.Is(err, errInvalidControlPlaneRequest) {
			t.Errorf("If-Match %#v error = %v", values, err)
		}
	}
}

func TestWriteVersionETagEmitsExactStrongValidator(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	writeVersionETag(recorder, "asset", contractTestAssetID, 9)
	if got := recorder.Header().Get("ETag"); got != `"asset:`+contractTestAssetID+`:v9"` {
		t.Fatalf("ETag = %q", got)
	}
}

func TestSourceRevisionETagBindsSourceRevisionAndBothCASVersions(t *testing.T) {
	t.Parallel()

	valid := httptest.NewRequest(http.MethodPost, "/", nil)
	valid.Header.Set(
		"If-Match",
		`"asset-source-revision:`+contractTestAssetID+`:r2:sv3:rv4"`,
	)
	sourceVersion, revisionVersion, err := parseSourceRevisionETag(
		valid, contractTestAssetID, 2,
	)
	if err != nil || sourceVersion != 3 || revisionVersion != 4 {
		t.Fatalf(
			"parseSourceRevisionETag(valid) = (%d, %d, %v)",
			sourceVersion,
			revisionVersion,
			err,
		)
	}

	cases := map[string][]string{
		"missing":        nil,
		"weak":           {`W/"asset-source-revision:` + contractTestAssetID + `:r2:sv3:rv4"`},
		"wildcard":       {"*"},
		"wrong source":   {`"asset-source-revision:22222222-2222-4222-8222-222222222222:r2:sv3:rv4"`},
		"wrong revision": {`"asset-source-revision:` + contractTestAssetID + `:r3:sv3:rv4"`},
		"leading zero":   {`"asset-source-revision:` + contractTestAssetID + `:r2:sv03:rv4"`},
		"multiple": {
			`"asset-source-revision:` + contractTestAssetID + `:r2:sv3:rv4"`,
			`"asset-source-revision:` + contractTestAssetID + `:r2:sv3:rv4"`,
		},
	}
	for name, values := range cases {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		for _, value := range values {
			request.Header.Add("If-Match", value)
		}
		if _, _, err := parseSourceRevisionETag(
			request, contractTestAssetID, 2,
		); !errors.Is(err, errInvalidControlPlaneRequest) {
			t.Errorf("%s error = %v, want invalid request", name, err)
		}
	}

	recorder := httptest.NewRecorder()
	writeSourceRevisionETag(recorder, contractTestAssetID, 2, 3, 4)
	if got := recorder.Header().Get("ETag"); got !=
		`"asset-source-revision:`+contractTestAssetID+`:r2:sv3:rv4"` {
		t.Fatalf("source revision ETag = %q", got)
	}
}

func TestCursorCodecRejectsTamperingKindQueryAndSortConfusion(t *testing.T) {
	t.Parallel()
	codec, err := NewControlPlaneCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewControlPlaneCursorCodec() error = %v", err)
	}
	cursor := controlPlaneCursor{
		Kind: "assets", QueryDigest: contractTestDigest, Sort: "display_name_asc",
		Value: "api", ID: contractTestAssetID,
	}
	encoded, err := codec.encode(cursor)
	if err != nil {
		t.Fatalf("encode() error = %v", err)
	}
	decoded, err := codec.decode(encoded, "assets")
	if err != nil || decoded != cursor {
		t.Fatalf("decode() = (%#v, %v)", decoded, err)
	}
	for name, candidate := range map[string]string{
		"tampered": encoded + "x",
		"oversize": strings.Repeat("a", 2049),
	} {
		if _, err := codec.decode(candidate, "assets"); !errors.Is(err, errInvalidControlPlaneRequest) {
			t.Errorf("%s cursor error = %v", name, err)
		}
	}
	if _, err := codec.decode(encoded, "conflicts"); !errors.Is(err, errInvalidControlPlaneRequest) {
		t.Fatalf("cross-kind cursor error = %v", err)
	}
	for name, mutation := range map[string]func(*controlPlaneCursor){
		"query digest": func(value *controlPlaneCursor) { value.QueryDigest = strings.Repeat("b", 64) },
		"sort":         func(value *controlPlaneCursor) { value.Sort = "created_at_desc" },
		"id":           func(value *controlPlaneCursor) { value.ID = "not-a-uuid" },
	} {
		changed := cursor
		mutation(&changed)
		changedEncoded, encodeErr := codec.encode(changed)
		if encodeErr == nil && changedEncoded == encoded {
			t.Errorf("%s mutation preserved cursor", name)
		}
	}
}

func TestCursorCodecRequiresExactlyThirtyTwoSecretBytes(t *testing.T) {
	t.Parallel()
	for _, secret := range [][]byte{nil, []byte("short"), []byte(strings.Repeat("a", 31)), []byte(strings.Repeat("a", 33))} {
		if _, err := NewControlPlaneCursorCodec(secret); err == nil {
			t.Errorf("secret length %d accepted", len(secret))
		}
	}
}

func TestWriteRequestProblemUsesRequestTraceAndStablePublicShape(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(requestmeta.With(request.Context(), requestmeta.Metadata{TraceID: contractTestTraceID}))
	recorder := httptest.NewRecorder()
	writeRequestProblem(recorder, request, http.StatusBadRequest, "invalid_request", "The request is invalid")
	body := recorder.Body.String()
	for _, required := range []string{
		`"type":"about:blank"`, `"status":400`, `"code":"invalid_request"`,
		`"trace_id":"` + contractTestTraceID + `"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("Problem body missing %s: %s", required, body)
		}
	}
	if strings.Contains(body, "internal") {
		t.Fatalf("Problem exposed internal detail: %s", body)
	}
}

func FuzzRejectDuplicateJSONKeys(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"a":1}`),
		[]byte(`{"a":1,"a":2}`),
		[]byte(`{"a":[{"b":true}]}`),
		{0xff, 0x00, '{'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = rejectDuplicateJSONKeys(raw)
	})
}
