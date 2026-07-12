// Package readexecutor defines the fixed, in-process READ execution contract.
// It deliberately has no dependency on WRITE execution, arbitrary commands,
// shell arguments, environment injection, or mutation adapters.
package readexecutor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readconnector"
)

const (
	ProfileSchemaVersion = "read-executor-profile.v1"

	// CurrentProfileDigest is pinned after review of the canonical contract
	// below. Any semantic executor change must create a new profile/digest and
	// retain the old implementation until its bound tasks are terminal.
	CurrentProfileDigest = "d776a2e45f33496a8a2558fba82096064c3aed10be588627a337e70983485e63"

	MaximumUpstreamResponseBytes = 1 << 20
	MaximumResponseHeaderBytes   = 32 << 10
	MaximumRequestFormBytes      = 16 << 10
	DialTimeout                  = 5 * time.Second
	TLSHandshakeTimeout          = 5 * time.Second
	ResponseHeaderTimeout        = 10 * time.Second
	RequestTimeout               = 20 * time.Second
	UpstreamQueryTimeout         = 10 * time.Second
	MaximumDNSAnswers            = 16
	MinimumBearerBytes           = 16
	MaximumBearerBytes           = 4096
)

var ErrProfileRejected = errors.New("READ executor profile rejected")

type profileSeal struct{ value byte }

var currentProfileSeal = &profileSeal{value: 1}

// Profile is an immutable capability describing exactly the READ operations
// this binary understands. It contains policy facts only and no target,
// credential, query, or task data.
type Profile struct {
	digest string
	seal   *profileSeal
	self   *Profile
}

func NewProfile() (*Profile, error) {
	digest, err := currentProfileContractDigest()
	if err != nil || !domain.ValidSHA256Hex(digest) || digest != CurrentProfileDigest {
		return nil, ErrProfileRejected
	}
	created := &Profile{digest: digest, seal: currentProfileSeal}
	created.self = created
	return created, nil
}

func (profile *Profile) Ready() bool {
	return profile != nil && profile.self == profile && profile.seal == currentProfileSeal &&
		domain.ValidSHA256Hex(profile.digest) && profile.digest == CurrentProfileDigest
}

func (profile *Profile) Digest() string {
	if !profile.Ready() {
		return ""
	}
	return profile.digest
}

func (profile *Profile) Supports(kind readconnector.Kind, operation string) bool {
	_, ok := profile.EndpointPath(kind, operation)
	return ok
}

func (profile *Profile) EndpointPath(kind readconnector.Kind, operation string) (string, bool) {
	if !profile.Ready() {
		return "", false
	}
	switch {
	case kind == readconnector.KindPrometheus && operation == readconnector.OperationPrometheusRangeQuery:
		return "/api/v1/query_range", true
	case kind == readconnector.KindVictoriaLogs && operation == readconnector.OperationVictoriaLogsSearch:
		return "/select/logsql/query", true
	default:
		return "", false
	}
}

func (Profile) String() string   { return "<aiops-read-executor-profile>" }
func (Profile) GoString() string { return "<aiops-read-executor-profile>" }
func (Profile) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-executor-profile>")
}
func (Profile) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Profile) UnmarshalJSON([]byte) error  { return ErrProfileRejected }

type profileEndpoint struct {
	Kind                  readconnector.Kind `json:"kind"`
	Operation             string             `json:"operation"`
	Path                  string             `json:"path"`
	RequestEncoding       string             `json:"request_encoding"`
	ResponseProfile       string             `json:"response_profile"`
	PartialResultPolicy   string             `json:"partial_result_policy"`
	AllowedContentTypes   []string           `json:"allowed_content_types"`
	NativeHistogramPolicy string             `json:"native_histogram_policy,omitempty"`
	FormFields            []string           `json:"form_fields"`
	LimitProfile          string             `json:"limit_profile"`
	TimeWindowProfile     string             `json:"time_window_profile"`
	OrderingProfile       string             `json:"ordering_profile"`
	UpstreamTimeoutNanos  int64              `json:"upstream_timeout_nanos"`
}

type profileTransport struct {
	TLSMinimumVersion         string `json:"tls_minimum_version"`
	TLSMaximumVersion         string `json:"tls_maximum_version"`
	TLSVerificationProfile    string `json:"tls_verification_profile"`
	HTTPVersion               string `json:"http_version"`
	AuthenticationProfile     string `json:"authentication_profile"`
	CredentialProviderProfile string `json:"credential_provider_profile"`
	NetworkPolicyProfile      string `json:"network_policy_profile"`
	ProxyPolicy               string `json:"proxy_policy"`
	RedirectPolicy            string `json:"redirect_policy"`
	CompressionPolicy         string `json:"compression_policy"`
	CookiePolicy              string `json:"cookie_policy"`
	SystemRootPolicy          string `json:"system_root_policy"`
	Method                    string `json:"method"`
	RequestHeadersProfile     string `json:"request_headers_profile"`
	ContextValueProfile       string `json:"context_value_profile"`
	StatusCodeProfile         string `json:"status_code_profile"`
	MaximumRequestFormBytes   int    `json:"maximum_request_form_bytes"`
	DNSLookupTimeoutNanos     int64  `json:"dns_lookup_timeout_nanos"`
	DialTimeoutNanos          int64  `json:"dial_timeout_nanos"`
	TLSHandshakeTimeoutNanos  int64  `json:"tls_handshake_timeout_nanos"`
	HeaderTimeoutNanos        int64  `json:"header_timeout_nanos"`
	RequestTimeoutNanos       int64  `json:"request_timeout_nanos"`
	MaximumHeaderBytes        int    `json:"maximum_header_bytes"`
	MaximumBodyBytes          int    `json:"maximum_body_bytes"`
	DNSPolicy                 string `json:"dns_policy"`
	MaximumDNSAnswers         int    `json:"maximum_dns_answers"`
	DialPolicy                string `json:"dial_policy"`
	RemoteAddressProfile      string `json:"remote_address_profile"`
	EgressPolicySchema        string `json:"egress_policy_schema"`
	EgressAdmissionProfile    string `json:"egress_admission_profile"`
	HardDenyProfile           string `json:"hard_deny_profile"`
	ConnectionReusePolicy     string `json:"connection_reuse_policy"`
	RetryPolicy               string `json:"retry_policy"`
	TrailerPolicy             string `json:"trailer_policy"`
	ContentEncodingPolicy     string `json:"content_encoding_policy"`
	CredentialLifetimePolicy  string `json:"credential_lifetime_policy"`
	MinimumBearerBytes        int    `json:"minimum_bearer_bytes"`
	MaximumBearerBytes        int    `json:"maximum_bearer_bytes"`
}

func currentProfileContractDigest() (string, error) {
	document := struct {
		SchemaVersion              string            `json:"schema_version"`
		Implementation             string            `json:"implementation"`
		ExecutionBindingProfile    string            `json:"execution_binding_profile"`
		ExecutionCapabilityProfile string            `json:"execution_capability_profile"`
		StrictJSONProfile          string            `json:"strict_json_profile"`
		Transport                  profileTransport  `json:"transport"`
		Endpoints                  []profileEndpoint `json:"endpoints"`
		EvidenceSchema             string            `json:"evidence_schema"`
		EvidenceProjection         string            `json:"evidence_projection"`
		FailureCodeProfile         string            `json:"failure_code_profile"`
	}{
		SchemaVersion:              ProfileSchemaVersion,
		Implementation:             "fixed-in-process-read-executor.v1",
		ExecutionBindingProfile:    "persisted-input-hash-and-runtime-component-fences.v1",
		ExecutionCapabilityProfile: "one-shot-start-bound-result-and-context-check-through-response-projection.v1",
		StrictJSONProfile:          "utf8-depth16-no-duplicate-unsafe-or-case-folded-field-alias.v1",
		Transport: profileTransport{
			TLSMinimumVersion: "1.3", TLSMaximumVersion: "1.3",
			TLSVerificationProfile:    "explicit-ca-exact-sni-no-callbacks-or-client-certificate.v1",
			HTTPVersion:               "1.1",
			AuthenticationProfile:     "bearer-role.v1",
			CredentialProviderProfile: "trusted-synchronous-context-bounded-single-callback.v1",
			NetworkPolicyProfile:      "content-addressed-egress-policy.v1",
			ProxyPolicy:               "deny", RedirectPolicy: "deny", CompressionPolicy: "deny",
			CookiePolicy: "deny", SystemRootPolicy: "deny", Method: "POST",
			RequestHeadersProfile:   "fixed-accept-content-type-no-store-user-agent-connection-close.v1",
			ContextValueProfile:     "strip-all-caller-values-before-dns-credential-and-http.v1",
			StatusCodeProfile:       "transport-invariants-before-readtask-low-cardinality-http-status.v1",
			MaximumRequestFormBytes: MaximumRequestFormBytes, DNSLookupTimeoutNanos: int64(DialTimeout),
			DialTimeoutNanos: int64(DialTimeout), TLSHandshakeTimeoutNanos: int64(TLSHandshakeTimeout),
			HeaderTimeoutNanos: int64(ResponseHeaderTimeout), RequestTimeoutNanos: int64(RequestTimeout),
			MaximumHeaderBytes: MaximumResponseHeaderBytes, MaximumBodyBytes: MaximumUpstreamResponseBytes,
			DNSPolicy: allAnswersPolicyV1, MaximumDNSAnswers: MaximumDNSAnswers,
			DialPolicy: literalDialPolicyV1, RemoteAddressProfile: "exact-literal-address-and-port.v1",
			EgressPolicySchema:     EgressPolicySchemaVersion,
			EgressAdmissionProfile: "canonical-nonoverlap-max32-v4-min24-v6-min64.v1",
			HardDenyProfile:        hardDenyProfileV1,
			ConnectionReusePolicy:  "deny", RetryPolicy: "deny", TrailerPolicy: "deny",
			ContentEncodingPolicy:    "deny",
			CredentialLifetimePolicy: "single-synchronous-callback-through-response-projection-with-contamination-reject.v1",
			MinimumBearerBytes:       MinimumBearerBytes, MaximumBearerBytes: MaximumBearerBytes,
		},
		Endpoints: []profileEndpoint{
			{
				Kind: readconnector.KindPrometheus, Operation: readconnector.OperationPrometheusRangeQuery,
				Path: "/api/v1/query_range", RequestEncoding: "application/x-www-form-urlencoded",
				ResponseProfile: "prometheus-matrix-float-samples.v1", PartialResultPolicy: "reject",
				AllowedContentTypes: []string{"application/json"}, NativeHistogramPolicy: "reject",
				FormFields:   []string{"end", "limit", "query", "start", "step", "timeout"},
				LimitProfile: "max-plus-one-reject-overflow.v1", TimeWindowProfile: "inclusive-start-inclusive-end.v1",
				OrderingProfile: "strict-metric-and-step-grid.v1", UpstreamTimeoutNanos: int64(UpstreamQueryTimeout),
			},
			{
				Kind: readconnector.KindVictoriaLogs, Operation: readconnector.OperationVictoriaLogsSearch,
				Path: "/select/logsql/query", RequestEncoding: "application/x-www-form-urlencoded",
				ResponseProfile: "victorialogs-json-lines-primitives.v1", PartialResultPolicy: "reject",
				AllowedContentTypes: []string{"", "application/json", "application/stream+json"},
				FormFields:          []string{"end", "limit", "query", "start", "timeout"},
				LimitProfile:        "max-plus-one-reject-overflow.v1", TimeWindowProfile: "inclusive-start-exclusive-end.v1",
				OrderingProfile: "canonical-time-then-jcs.v1", UpstreamTimeoutNanos: int64(UpstreamQueryTimeout),
			},
		},
		EvidenceSchema:     "readtask-evidence-completion.v1",
		EvidenceProjection: "read-connector-validator.v2",
		FailureCodeProfile: "readtask-low-cardinality-failure.v1",
	}
	wire, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
