package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/credential"
)

const (
	managerTokenCanary = "hvs.manager-token-canary"
	revokerTokenCanary = "hvs.revoker-token-canary"
)

func TestVaultClientsExposeDisjointCapabilitiesAndTokenSources(t *testing.T) {
	t.Parallel()

	issuerType := reflect.TypeOf((*IssuerClient)(nil))
	revocationType := reflect.TypeOf((*RevocationClient)(nil))
	if got, want := exportedMethodNames(issuerType), []string{
		"CreateChild", "GoString", "InspectChild", "IssueDynamic", "MarshalJSON", "String", "ValidateManager",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IssuerClient methods = %v, want %v", got, want)
	}
	if got, want := exportedMethodNames(revocationType), []string{
		"GoString", "MarshalJSON", "RevokeAccessor", "String",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RevocationClient methods = %v, want %v", got, want)
	}
	if !issuerType.Implements(reflect.TypeOf((*credential.DurableIssuer)(nil)).Elem()) {
		t.Fatal("IssuerClient does not implement credential.DurableIssuer")
	}
	if got := tokenSourceFields(reflect.TypeOf(IssuerClient{})); !reflect.DeepEqual(got, []string{"manager"}) {
		t.Fatalf("IssuerClient TokenSource fields = %v, want manager only", got)
	}
	if got := tokenSourceFields(reflect.TypeOf(RevocationClient{})); !reflect.DeepEqual(got, []string{"revoker"}) {
		t.Fatalf("RevocationClient TokenSource fields = %v, want revoker only", got)
	}
}

func exportedMethodNames(clientType reflect.Type) []string {
	methods := make([]string, 0, clientType.NumMethod())
	for index := 0; index < clientType.NumMethod(); index++ {
		methods = append(methods, clientType.Method(index).Name)
	}
	return methods
}

func tokenSourceFields(clientType reflect.Type) []string {
	tokenSourceType := reflect.TypeOf((*TokenSource)(nil)).Elem()
	var fields []string
	for index := 0; index < clientType.NumField(); index++ {
		field := clientType.Field(index)
		if field.Type.Implements(tokenSourceType) {
			fields = append(fields, field.Name)
		}
	}
	return fields
}

func TestClientValidateManagerUsesOneShotTLS13HTTP1(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/v1/auth/token/lookup-self" {
			t.Errorf("manager lookup request = %s %s", request.Method, request.URL.Path)
		}
		if request.ProtoMajor != 1 || !request.Close {
			t.Errorf("manager lookup transport = %s close=%t", request.Proto, request.Close)
		}
		if request.Header.Get("X-Vault-Token") != managerTokenCanary || request.Header.Get("X-Vault-Namespace") != "aiops" {
			t.Error("manager lookup omitted trusted token or namespace")
		}
		if request.Header.Get("Idempotency-Key") != "" || request.Header.Get("X-Idempotency-Key") != "" {
			t.Error("manager lookup sent an idempotency header")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{
			"request_id":"request-manager-1","lease_id":"","renewable":false,"lease_duration":0,
			"data":{"id":"hvs.manager-token-canary","accessor":"manager-accessor","policies":["aiops-issuer-manager"],"path":"auth/token/create","meta":{},"display_name":"aiops-manager","num_uses":0,"orphan":true,"creation_time":1783700000,"creation_ttl":7200,"expire_time":"2026-07-11T01:00:00Z","ttl":3600,"explicit_max_ttl":7200,"entity_id":"","type":"service","renewable":false,"issue_time":"2026-07-10T23:00:00Z"},
			"wrap_info":null,"warnings":null,"auth":null,"mount_type":"token"
		}`)
	}))
	client := newTestClient(t, server)

	if err := client.ValidateManager(context.Background()); err != nil {
		t.Fatalf("ValidateManager() error = %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("manager lookup requests = %d, want 1", requestCount.Load())
	}
}

func TestNewClientsRejectInvalidTokenSourcesIndependently(t *testing.T) {
	t.Parallel()

	server := newVaultTLSServer(t, http.HandlerFunc(writeValidManagerResponse))
	profile, err := NewProfile(profileConfigForServer(t, server))
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	tests := map[string]TokenSource{
		"nil":       nil,
		"typed nil": (*staticTokenSource)(nil),
		"empty ID":  &staticTokenSource{},
	}
	for name, source := range tests {
		if _, err := NewIssuerClient(profile, source); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("NewIssuerClient(%s) error = %v, want ErrInvalidClient", name, err)
		}
		if _, err := NewRevocationClient(profile, source); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("NewRevocationClient(%s) error = %v, want ErrInvalidClient", name, err)
		}
	}
}

func TestClientDestroysTokenReturnedAlongsideSourceError(t *testing.T) {
	t.Parallel()

	server := newVaultTLSServer(t, http.HandlerFunc(writeValidManagerResponse))
	profile, err := NewProfile(profileConfigForServer(t, server))
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	value, err := credential.NewSensitiveValue([]byte(managerTokenCanary))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	source := &failingTokenSource{id: "issuer-manager-source", value: value}
	client, err := NewIssuerClient(profile, source)
	if err != nil {
		t.Fatalf("NewIssuerClient() error = %v", err)
	}

	err = client.ValidateManager(context.Background())
	if err == nil || strings.Contains(err.Error(), "source-error-secret-canary") || strings.Contains(err.Error(), managerTokenCanary) {
		t.Fatalf("ValidateManager(source error) error = %v", err)
	}
	if got := source.value.Bytes(); len(got) != 0 {
		t.Fatalf("source error retained token %q", got)
	}
}

func TestClientRejectsDuplicateSecurityJSONWithoutRetry(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"request_id":"first","request_id":"upstream-secret-canary"}`)
	}))
	client := newTestClient(t, server)

	err := client.ValidateManager(context.Background())
	if err == nil || strings.Contains(err.Error(), "upstream-secret-canary") || strings.Contains(err.Error(), managerTokenCanary) {
		t.Fatalf("ValidateManager(duplicate JSON) error = %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("duplicate JSON requests = %d, want 1", requestCount.Load())
	}
}

func TestStrictJSONByteScannerPreservesDuplicateDepthAndUnicodeChecks(t *testing.T) {
	t.Parallel()

	valid := []byte(`{"value":"secret-password-canary","unicode":"\ud83d\ude00","number":-1.25e+3}`)
	if err := rejectDuplicateJSONKeys(valid, maxJSONDepth); err != nil {
		t.Fatalf("rejectDuplicateJSONKeys(valid) error = %v", err)
	}
	invalidUTF8 := append([]byte(`{"value":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
	tests := map[string][]byte{
		"escaped duplicate": []byte(`{"accessor":1,"access\u006fr":2}`),
		"high surrogate":    []byte(`{"value":"\ud800"}`),
		"low surrogate":     []byte(`{"value":"\udc00"}`),
		"invalid UTF-8":     invalidUTF8,
		"trailing comma":    []byte(`{"value":1,}`),
	}
	for name, document := range tests {
		if err := rejectDuplicateJSONKeys(document, maxJSONDepth); err == nil {
			t.Errorf("rejectDuplicateJSONKeys(%s) unexpectedly succeeded", name)
		}
		clear(document)
	}
}

func TestClientRejectsOversizedResponseWithoutRetry(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, strings.Repeat("x", maxSuccessBodyBytes+1))
	}))
	client := newTestClient(t, server)

	if err := client.ValidateManager(context.Background()); err == nil {
		t.Fatal("ValidateManager(oversized response) unexpectedly succeeded")
	}
	if requestCount.Load() != 1 {
		t.Fatalf("oversized response requests = %d, want 1", requestCount.Load())
	}
}

func TestClientDoesNotFollowRedirectOrForwardToken(t *testing.T) {
	t.Parallel()

	var sourceCount, targetCount atomic.Int32
	target := newVaultTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCount.Add(1)
	}))
	source := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		sourceCount.Add(1)
		writer.Header().Set("Location", target.URL+"/captured")
		writer.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(writer, "upstream-redirect-body-canary")
	}))
	client := newTestClient(t, source)

	err := client.ValidateManager(context.Background())
	if err == nil || strings.Contains(err.Error(), "upstream-redirect-body-canary") || strings.Contains(err.Error(), managerTokenCanary) {
		t.Fatalf("ValidateManager(redirect) error = %v", err)
	}
	if sourceCount.Load() != 1 || targetCount.Load() != 0 {
		t.Fatalf("redirect request counts source/target = %d/%d", sourceCount.Load(), targetCount.Load())
	}
}

func TestClientIgnoresProxyEnvironment(t *testing.T) {
	var proxyCount atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		proxyCount.Add(1)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	server := newVaultTLSServer(t, http.HandlerFunc(writeValidManagerResponse))
	client := newTestClient(t, server)
	if err := client.ValidateManager(context.Background()); err != nil {
		t.Fatalf("ValidateManager(proxy environment) error = %v", err)
	}
	if proxyCount.Load() != 0 {
		t.Fatalf("proxy received %d requests", proxyCount.Load())
	}
}

func TestClientRejectsTLS12AndHTTP2WithoutRetry(t *testing.T) {
	t.Run("TLS 1.2", func(t *testing.T) {
		var requestCount atomic.Int32
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requestCount.Add(1)
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
		server.StartTLS()
		t.Cleanup(server.Close)
		client := newTestClient(t, server)
		if err := client.ValidateManager(context.Background()); err == nil {
			t.Fatal("ValidateManager(TLS 1.2) unexpectedly succeeded")
		}
		if requestCount.Load() != 0 {
			t.Fatalf("TLS 1.2 handler requests = %d", requestCount.Load())
		}
	})

	t.Run("HTTP/2-only application", func(t *testing.T) {
		var requestCount atomic.Int32
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requestCount.Add(1)
			if request.ProtoMajor != 2 {
				writer.WriteHeader(http.StatusHTTPVersionNotSupported)
				return
			}
			writeValidManagerResponse(writer, request)
		}))
		server.EnableHTTP2 = true
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
		server.StartTLS()
		t.Cleanup(server.Close)
		client := newTestClient(t, server)
		if err := client.ValidateManager(context.Background()); err == nil {
			t.Fatal("ValidateManager(HTTP/2-only application) unexpectedly succeeded")
		}
		if requestCount.Load() != 1 {
			t.Fatalf("HTTP/2-only requests = %d, want one HTTP/1.1 rejection", requestCount.Load())
		}
	})
}

func TestClientRejectsWrongExplicitCAWithoutDispatch(t *testing.T) {
	t.Parallel()

	var targetCount atomic.Int32
	target := newVaultTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCount.Add(1)
	}))
	config := profileConfigForServer(t, target)
	config.CAPEM = unrelatedCAPEM(t)
	profile, err := NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	client, err := NewIssuerClient(profile,
		&staticTokenSource{id: "issuer-manager-source", value: []byte(managerTokenCanary)})
	if err != nil {
		t.Fatalf("NewIssuerClient() error = %v", err)
	}

	err = client.ValidateManager(context.Background())
	if err == nil || strings.Contains(err.Error(), managerTokenCanary) {
		t.Fatalf("ValidateManager(wrong CA) error = %v", err)
	}
	if targetCount.Load() != 0 {
		t.Fatalf("wrong-CA request reached handler %d times", targetCount.Load())
	}
}

func unrelatedCAPEM(t *testing.T) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unrelated CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "unrelated-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create unrelated CA: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestClientDoesNotReplayAfterConnectionDrop(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack connection: %v", err)
			return
		}
		_ = connection.Close()
	}))
	client := newTestClient(t, server)

	if err := client.ValidateManager(context.Background()); err == nil {
		t.Fatal("ValidateManager(connection drop) unexpectedly succeeded")
	}
	if requestCount.Load() != 1 {
		t.Fatalf("connection-drop requests = %d, want 1", requestCount.Load())
	}
}

func TestClientUsesFreshConnectionForEveryRequest(t *testing.T) {
	t.Parallel()

	remoteAddresses := make(chan string, 2)
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		remoteAddresses <- request.RemoteAddr
		writeValidManagerResponse(writer, request)
	}))
	client := newTestClient(t, server)
	if err := client.ValidateManager(context.Background()); err != nil {
		t.Fatalf("first ValidateManager() error = %v", err)
	}
	if err := client.ValidateManager(context.Background()); err != nil {
		t.Fatalf("second ValidateManager() error = %v", err)
	}
	first, second := <-remoteAddresses, <-remoteAddresses
	if first == second {
		t.Fatalf("requests reused connection %q", first)
	}
}

func TestClientRejectsRenewableOrPeriodicManager(t *testing.T) {
	t.Parallel()

	valid := validManagerResponseJSON()
	tests := map[string]string{
		"renewable": strings.Replace(valid, `"renewable":false,"issue_time"`, `"renewable":true,"issue_time"`, 1),
		"periodic":  strings.Replace(valid, `"type":"service","renewable"`, `"type":"service","period":60,"renewable"`, 1),
	}
	for name, responseBody := range tests {
		name, responseBody := name, responseBody
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, responseBody)
			}))
			client := newTestClient(t, server)
			if err := client.ValidateManager(context.Background()); err == nil {
				t.Fatalf("ValidateManager(%s manager) unexpectedly succeeded", name)
			}
		})
	}
}

func TestClientRejectsManagerIdentityOrPolicyDrift(t *testing.T) {
	t.Parallel()

	valid := validManagerResponseJSON()
	tests := map[string]string{
		"entity":             strings.Replace(valid, `"entity_id":""`, `"entity_id":"entity-canary"`, 1),
		"identity policy":    strings.Replace(valid, `"type":"service"`, `"identity_policies":["unexpected"],"type":"service"`, 1),
		"external policy":    strings.Replace(valid, `"type":"service"`, `"external_namespace_policies":{"root/":["unexpected"]},"type":"service"`, 1),
		"batch":              strings.Replace(valid, `"type":"service"`, `"type":"batch"`, 1),
		"limited uses":       strings.Replace(valid, `"num_uses":0`, `"num_uses":1`, 1),
		"extra policy":       strings.Replace(valid, `["aiops-issuer-manager"]`, `["aiops-issuer-manager","default"]`, 1),
		"not orphan":         strings.Replace(valid, `"orphan":true`, `"orphan":false`, 1),
		"invalid issue time": strings.Replace(valid, `"issue_time":"2026-07-10T23:00:00Z"`, `"issue_time":"not-a-time"`, 1),
	}
	for name, responseBody := range tests {
		name, responseBody := name, responseBody
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, responseBody)
			}))
			client := newTestClient(t, server)
			if err := client.ValidateManager(context.Background()); err == nil {
				t.Fatalf("ValidateManager(%s drift) unexpectedly succeeded", name)
			}
		})
	}
}

func TestClientCreateChildUsesExactRoleAndSecurityBody(t *testing.T) {
	t.Parallel()

	request := validChildCreateRequestNow()
	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		requestCount.Add(1)
		if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != "/v1/auth/token/create/aiops-db-job" {
			t.Errorf("child create request = %s %s", httpRequest.Method, httpRequest.URL.Path)
		}
		if httpRequest.Header.Get("X-Vault-Token") != managerTokenCanary || httpRequest.Close != true || httpRequest.ProtoMajor != 1 {
			t.Error("child create did not use the one-shot manager transport")
		}
		var body struct {
			Policies        []string          `json:"policies"`
			TTL             string            `json:"ttl"`
			ExplicitMaxTTL  string            `json:"explicit_max_ttl"`
			NoDefaultPolicy bool              `json:"no_default_policy"`
			DisplayName     string            `json:"display_name"`
			NumUses         int               `json:"num_uses"`
			Renewable       bool              `json:"renewable"`
			Type            string            `json:"type"`
			Meta            map[string]string `json:"meta"`
		}
		decoder := json.NewDecoder(httpRequest.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Errorf("decode child create body: %v", err)
		}
		if !slices.Equal(body.Policies, []string{"aiops-db-job"}) || body.TTL != "240s" || body.ExplicitMaxTTL != body.TTL ||
			!body.NoDefaultPolicy || body.DisplayName != "aiops-job" || body.NumUses != 2 || body.Renewable ||
			body.Type != "service" || !maps.Equal(body.Meta, map[string]string{"profile": "vault-database-nonprod", "revision": "rev-1"}) {
			t.Errorf("child create body = %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, validChildCreateResponseJSON())
	}))
	client := newTestClient(t, server)

	child, err := client.CreateChild(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateChild() error = %v", err)
	}
	defer child.Token.Destroy()
	defer child.Accessor.Destroy()
	if string(child.Token.Bytes()) != "hvs.child-token-canary" || string(child.Accessor.Bytes()) != "child-accessor-canary" ||
		!child.ExpiresAt.After(time.Now().UTC()) || child.ExpiresAt.After(request.CredentialExpiresAt) {
		t.Fatalf("CreateChild() = token %s accessor %s expires %s", child.Token, child.Accessor, child.ExpiresAt)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("child create requests = %d, want 1", requestCount.Load())
	}
}

func TestClientCreateChildReturnsAccessorBeforeRejectingUnsafeSemantics(t *testing.T) {
	t.Parallel()

	request := validChildCreateRequestNow()
	valid := validChildCreateResponseJSON()
	tests := map[string]string{
		"entity":       strings.Replace(valid, `"entity_id":""`, `"entity_id":"entity-canary"`, 1),
		"policy":       strings.Replace(valid, `["aiops-db-job"]`, `["aiops-db-job","default"]`, 1),
		"uses":         strings.Replace(valid, `"num_uses":2`, `"num_uses":3`, 1),
		"missing uses": strings.Replace(valid, `,"num_uses":2`, ``, 1),
		"missing role cap warning": strings.Replace(valid,
			`"warnings":["Explicit max TTL specified both during creation call and in role; using the lesser value of 240 seconds"]`,
			`"warnings":null`, 1),
		"wrong role cap warning": strings.Replace(valid,
			`lesser value of 240 seconds`, `lesser value of 239 seconds`, 1),
		"extra role cap warning": strings.Replace(valid,
			`240 seconds"]`, `240 seconds","unexpected warning"]`, 1),
	}
	for name, responseBody := range tests {
		name, responseBody := name, responseBody
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, responseBody)
			}))
			client := newTestClient(t, server)
			child, err := client.CreateChild(context.Background(), request)
			if err == nil || child.Accessor == nil {
				t.Fatalf("CreateChild(%s drift) child/error = %#v/%v", name, child, err)
			}
			defer child.Accessor.Destroy()
			defer child.Token.Destroy()
			if got := string(child.Accessor.Bytes()); got != "child-accessor-canary" {
				t.Fatalf("CreateChild(%s drift) accessor = %q", name, got)
			}
			if got := child.Token.Bytes(); len(got) != 0 {
				t.Fatalf("CreateChild(%s drift) returned unsafe child token = %q", name, got)
			}
			var failure *ClientError
			if !errors.As(err, &failure) || !failure.Ambiguous {
				t.Fatalf("CreateChild(%s drift) error = %v, want ambiguous ClientError", name, err)
			}
		})
	}
}

func TestClientCreateChildSalvagesAccessorOnlyAfterUnknownFieldStrictFailure(t *testing.T) {
	t.Parallel()

	request := validChildCreateRequestNow()
	valid := validChildCreateResponseJSON()
	tests := map[string]string{
		"top-level unknown field": strings.Replace(
			valid,
			`"mount_type":"token"`,
			`"unknown_top":{"auth":{"accessor":"nested-accessor-canary"}},"mount_type":"token"`,
			1,
		),
		"auth unknown field": strings.Replace(
			valid,
			`"num_uses":2`,
			`"num_uses":2,"unknown_auth":{"accessor":"nested-accessor-canary"}`,
			1,
		),
	}
	for name, responseBody := range tests {
		name, responseBody := name, responseBody
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, responseBody)
			}))
			client := newTestClient(t, server)

			child, err := client.CreateChild(context.Background(), request)
			if err == nil || child.Accessor == nil {
				t.Fatalf("CreateChild(%s) child/error = %#v/%v", name, child, err)
			}
			defer child.Accessor.Destroy()
			defer child.Token.Destroy()
			if got := string(child.Accessor.Bytes()); got != "child-accessor-canary" {
				t.Fatalf("CreateChild(%s) accessor = %q", name, got)
			}
			if got := child.Token.Bytes(); len(got) != 0 {
				t.Fatalf("CreateChild(%s) returned token = %q", name, got)
			}
			var failure *ClientError
			if !errors.As(err, &failure) || !failure.Ambiguous {
				t.Fatalf("CreateChild(%s) error = %v, want ambiguous ClientError", name, err)
			}
		})
	}
}

func TestClientCreateChildDoesNotSalvageAccessorFromInvalidJSON(t *testing.T) {
	t.Parallel()

	request := validChildCreateRequestNow()
	valid := validChildCreateResponseJSON()
	deep := `{"auth":{"accessor":"child-accessor-canary"},"unknown":` + strings.Repeat("[", maxJSONDepth+2) +
		`null` + strings.Repeat("]", maxJSONDepth+2) + `}`
	tests := map[string]string{
		"duplicate auth": strings.Replace(
			valid,
			`"mount_type":"token"`,
			`"auth":{"accessor":"nested-accessor-canary"},"mount_type":"token"`,
			1,
		),
		"duplicate accessor": strings.Replace(
			valid,
			`"accessor":"child-accessor-canary"`,
			`"accessor":"child-accessor-canary","accessor":"nested-accessor-canary"`,
			1,
		),
		"escaped duplicate accessor": strings.Replace(
			valid,
			`"accessor":"child-accessor-canary"`,
			`"accessor":"child-accessor-canary","access\u006fr":"nested-accessor-canary"`,
			1,
		),
		"case-folded auth": strings.Replace(valid, `"auth":`, `"Auth":`, 1),
		"case-folded accessor": strings.Replace(
			valid,
			`"accessor":"child-accessor-canary"`,
			`"Accessor":"child-accessor-canary"`,
			1,
		),
		"nested bait only": `{
			"request_id":"request-create-1","lease_id":"","renewable":false,"lease_duration":0,"data":null,
			"wrap_info":null,"warnings":null,"auth":null,
			"unknown":{"auth":{"accessor":"nested-accessor-canary"}},"mount_type":"token"
		}`,
		"truncated": valid[:len(valid)-1],
		"too deep":  deep,
		"invalid unicode surrogate": strings.Replace(
			valid,
			`"mount_type":"token"`,
			`"unknown":"\ud800","mount_type":"token"`,
			1,
		),
		"too large": strings.Replace(
			valid,
			`"mount_type":"token"`,
			`"unknown":"`+strings.Repeat("x", maxSuccessBodyBytes)+`","mount_type":"token"`,
			1,
		),
	}
	for name, responseBody := range tests {
		name, responseBody := name, responseBody
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, responseBody)
			}))
			client := newTestClient(t, server)

			child, err := client.CreateChild(context.Background(), request)
			if err == nil || child.Accessor != nil || len(child.Token.Bytes()) != 0 {
				t.Fatalf("CreateChild(%s) child/error = %#v/%v", name, child, err)
			}
			var failure *ClientError
			if !errors.As(err, &failure) || !failure.Ambiguous {
				t.Fatalf("CreateChild(%s) error = %v, want ambiguous ClientError", name, err)
			}
		})
	}
}

func TestClientCreateChildUsesDispatchTimeForConservativeExpiry(t *testing.T) {
	t.Parallel()

	request := validChildCreateRequestNow()
	receivedAt := make(chan time.Time, 1)
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		receivedAt <- time.Now().UTC()
		time.Sleep(150 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, validChildCreateResponseJSON())
	}))
	client := newTestClient(t, server)

	child, err := client.CreateChild(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateChild(delayed response) error = %v", err)
	}
	defer child.Token.Destroy()
	defer child.Accessor.Destroy()
	requestReceivedAt := <-receivedAt
	responseObservedAt := time.Now().UTC()
	maximumConservativeExpiry := credential.CanonicalCredentialExpiry(requestReceivedAt.Add(240 * time.Second))
	if child.ExpiresAt.After(maximumConservativeExpiry) || !child.ExpiresAt.After(responseObservedAt) ||
		child.ExpiresAt.After(request.CredentialExpiresAt) {
		t.Fatalf("CreateChild(delayed response) expiry = %s, response=%s maximum=%s deadline=%s",
			child.ExpiresAt, responseObservedAt, maximumConservativeExpiry, request.CredentialExpiresAt)
	}
}

func validChildCreateRequestNow() credential.DurableChildCreateRequest {
	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	return credential.DurableChildCreateRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		DatabaseAuthorizedAt: now, TTL: 4 * time.Minute, CredentialExpiresAt: now.Add(5 * time.Minute),
	}
}

func TestClientCreateChildRejectsUnsafeDatabaseAuthorizationBeforeDispatch(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requestCount.Add(1)
	}))
	client := newTestClient(t, server)
	now := time.Date(2026, 7, 10, 23, 0, 0, 0, time.UTC)
	base := credential.DurableChildCreateRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		DatabaseAuthorizedAt: now, TTL: 4 * time.Minute, CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	tests := map[string]func(*credential.DurableChildCreateRequest){
		"profile revision": func(request *credential.DurableChildCreateRequest) { request.ProfileRevision = "rev-2" },
		"revocation ID":    func(request *credential.DurableChildCreateRequest) { request.RevocationID = "not-a-uuid" },
		"fractional TTL":   func(request *credential.DurableChildCreateRequest) { request.TTL += time.Nanosecond },
		"maximum TTL": func(request *credential.DurableChildCreateRequest) {
			request.TTL = credential.MaxCredentialTTL + time.Second
		},
		"noncanonical DB time": func(request *credential.DurableChildCreateRequest) {
			request.DatabaseAuthorizedAt = request.DatabaseAuthorizedAt.Add(time.Nanosecond)
		},
		"noncanonical expiry": func(request *credential.DurableChildCreateRequest) {
			request.CredentialExpiresAt = request.CredentialExpiresAt.Add(time.Nanosecond)
		},
		"missing reserve": func(request *credential.DurableChildCreateRequest) {
			request.CredentialExpiresAt = request.DatabaseAuthorizedAt.Add(request.TTL + credential.ChildCreateExpiryReserve - time.Microsecond)
		},
	}
	for name, mutate := range tests {
		request := base
		mutate(&request)
		if child, err := client.CreateChild(context.Background(), request); !errors.Is(err, ErrInvalidClient) ||
			child.Accessor != nil || len(child.Token.Bytes()) != 0 {
			t.Errorf("CreateChild(%s) child/error = %#v/%v", name, child, err)
		}
	}
	if requestCount.Load() != 0 {
		t.Fatalf("unsafe create authorizations dispatched %d requests", requestCount.Load())
	}
}

func TestClientCreateChildDoesNotReplayAmbiguousDispatch(t *testing.T) {
	t.Parallel()

	request := validChildCreateRequestNow()
	tests := map[string]http.Handler{
		"server error": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(writer, "upstream-create-error child-accessor-canary hvs.child-token-canary")
		}),
		"connection drop": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			connection, _, err := writer.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
		}),
	}
	for name, handler := range tests {
		name, handler := name, handler
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var requestCount atomic.Int32
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
				requestCount.Add(1)
				handler.ServeHTTP(writer, httpRequest)
			}))
			client := newTestClient(t, server)
			child, err := client.CreateChild(context.Background(), request)
			var failure *ClientError
			if err == nil || !errors.As(err, &failure) || !failure.Ambiguous || child.Accessor != nil ||
				strings.Contains(err.Error(), "upstream-create-error") || strings.Contains(err.Error(), "child-accessor-canary") ||
				strings.Contains(err.Error(), "hvs.child-token-canary") {
				t.Fatalf("CreateChild(%s) child/error = %#v/%v", name, child, err)
			}
			if requestCount.Load() != 1 {
				t.Fatalf("CreateChild(%s) requests = %d, want 1", name, requestCount.Load())
			}
		})
	}
}

func validChildCreateResponseJSON() string {
	return `{
		"request_id":"request-create-1","lease_id":"","renewable":false,"lease_duration":0,"data":null,
		"wrap_info":null,"warnings":["Explicit max TTL specified both during creation call and in role; using the lesser value of 240 seconds"],
		"auth":{"client_token":"hvs.child-token-canary","accessor":"child-accessor-canary","policies":["aiops-db-job"],"token_policies":["aiops-db-job"],"identity_policies":[],"metadata":{"profile":"vault-database-nonprod","revision":"rev-1"},"lease_duration":240,"renewable":false,"entity_id":"","token_type":"service","orphan":false,"mfa_requirement":null,"num_uses":2},
		"mount_type":"token"
	}`
}

func TestClientInspectChildUsesManagerLookupAccessorOnly(t *testing.T) {
	t.Parallel()

	accessor, err := credential.NewSensitiveReference([]byte("child-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	defer accessor.Destroy()
	request := credential.DurableChildInspectionRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		ExpectedTTL: 4 * time.Minute, CredentialExpiresAt: time.Date(2026, 7, 10, 23, 5, 0, 0, time.UTC),
	}
	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		requestCount.Add(1)
		if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != "/v1/auth/token/lookup-accessor" {
			t.Errorf("child inspection request = %s %s", httpRequest.Method, httpRequest.URL.Path)
		}
		if httpRequest.Header.Get("X-Vault-Token") != managerTokenCanary {
			t.Error("child inspection did not use manager token")
		}
		body, readErr := io.ReadAll(httpRequest.Body)
		if readErr != nil || string(body) != `{"accessor":"child-accessor-canary"}` {
			t.Errorf("child inspection body = %q, %v", body, readErr)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, validChildInspectionResponseJSON())
	}))
	client := newTestClient(t, server)

	if err := client.InspectChild(context.Background(), accessor, request); err != nil {
		t.Fatalf("InspectChild() error = %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("child inspection requests = %d, want 1", requestCount.Load())
	}
}

func TestClientInspectChildRejectsProfileOrIdentityDrift(t *testing.T) {
	t.Parallel()

	request := credential.DurableChildInspectionRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		ExpectedTTL: 4 * time.Minute, CredentialExpiresAt: time.Date(2026, 7, 10, 23, 5, 0, 0, time.UTC),
	}
	valid := validChildInspectionResponseJSON()
	tests := map[string]string{
		"entity":           strings.Replace(valid, `"entity_id":""`, `"entity_id":"entity-canary"`, 1),
		"policy":           strings.Replace(valid, `["aiops-db-job"]`, `["aiops-db-job","default"]`, 1),
		"uses":             strings.Replace(valid, `"num_uses":2`, `"num_uses":1`, 1),
		"namespace":        strings.Replace(valid, `"namespace_path":"aiops/"`, `"namespace_path":"other/"`, 1),
		"explicit max TTL": strings.Replace(valid, `"explicit_max_ttl":240`, `"explicit_max_ttl":241`, 1),
	}
	for name, responseBody := range tests {
		name, responseBody := name, responseBody
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			accessor, err := credential.NewSensitiveReference([]byte("child-accessor-canary"))
			if err != nil {
				t.Fatalf("NewSensitiveReference() error = %v", err)
			}
			defer accessor.Destroy()
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, responseBody)
			}))
			client := newTestClient(t, server)
			if err := client.InspectChild(context.Background(), accessor, request); err == nil ||
				strings.Contains(err.Error(), "child-accessor-canary") || strings.Contains(err.Error(), managerTokenCanary) {
				t.Fatalf("InspectChild(%s drift) error = %v", name, err)
			}
		})
	}
}

func validChildInspectionResponseJSON() string {
	return `{
		"request_id":"request-inspect-1","lease_id":"","renewable":false,"lease_duration":0,
		"data":{"id":"","accessor":"child-accessor-canary","policies":["aiops-db-job"],"path":"auth/token/create/aiops-db-job","meta":{"profile":"vault-database-nonprod","revision":"rev-1"},"display_name":"token-aiops-job","num_uses":2,"orphan":false,"creation_time":1783724400,"creation_ttl":240,"expire_time":"2026-07-10T23:04:00Z","ttl":230,"explicit_max_ttl":240,"entity_id":"","type":"service","role":"aiops-db-job","renewable":false,"issue_time":"2026-07-10T23:00:00Z","namespace_path":"aiops/"},
		"wrap_info":null,"warnings":null,"auth":null,"mount_type":"token"
	}`
}

func TestClientIssueDynamicUsesChildOnceAndReturnsOnlyAllowlistedSecret(t *testing.T) {
	t.Parallel()

	childToken, err := credential.NewSensitiveValue([]byte("hvs.child-token-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	defer childToken.Destroy()
	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	request := credential.DurableDynamicIssueRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		requestCount.Add(1)
		if httpRequest.Method != http.MethodGet || httpRequest.URL.Path != "/v1/database/creds/aiops-db-job" {
			t.Errorf("dynamic issue request = %s %s", httpRequest.Method, httpRequest.URL.Path)
		}
		if httpRequest.Header.Get("X-Vault-Token") != "hvs.child-token-canary" || httpRequest.ContentLength != 0 {
			t.Error("dynamic issue did not use the child token with an empty fixed request")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, validDynamicResponseJSON())
	}))
	client := newTestClient(t, server)
	before := time.Now().UTC()

	dynamic, err := client.IssueDynamic(context.Background(), childToken, request)
	if err != nil {
		t.Fatalf("IssueDynamic() error = %v", err)
	}
	defer dynamic.Secret.Destroy()
	after := time.Now().UTC()
	material := dynamic.Secret.Bytes()
	defer clear(material)
	if string(material) != `{"username":"job_user","password":"secret-password-canary"}` {
		t.Fatalf("IssueDynamic() material = %q", material)
	}
	if dynamic.ExpiresAt.Before(before.Add(180*time.Second-time.Microsecond)) || dynamic.ExpiresAt.After(after.Add(180*time.Second)) ||
		dynamic.ExpiresAt.After(request.CredentialExpiresAt) {
		t.Fatalf("IssueDynamic() expiry = %s outside safe response window", dynamic.ExpiresAt)
	}
	if !dynamic.ExpiresAt.Equal(credential.CanonicalCredentialExpiry(dynamic.ExpiresAt)) {
		t.Fatalf("IssueDynamic() expiry = %s, want canonical PostgreSQL precision", dynamic.ExpiresAt)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("dynamic issue requests = %d, want 1", requestCount.Load())
	}
}

func TestClientIssueDynamicRejectsUnsafeLeaseAndSecretShape(t *testing.T) {
	t.Parallel()

	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	request := credential.DurableDynamicIssueRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	valid := validDynamicResponseJSON()
	tests := map[string]string{
		"empty lease":      strings.Replace(valid, "database/creds/aiops-db-job/lease-canary", "", 1),
		"past deadline":    strings.Replace(valid, `"lease_duration":180`, `"lease_duration":600`, 1),
		"extra field":      strings.Replace(valid, `"password":"secret-password-canary"`, `"password":"secret-password-canary","extra":"secret-extra-canary"`, 1),
		"missing field":    strings.Replace(valid, `,"password":"secret-password-canary"`, ``, 1),
		"wrong field type": strings.Replace(valid, `"password":"secret-password-canary"`, `"password":42`, 1),
	}
	for name, responseBody := range tests {
		name, responseBody := name, responseBody
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			childToken, tokenErr := credential.NewSensitiveValue([]byte("hvs.child-token-canary"))
			if tokenErr != nil {
				t.Fatalf("NewSensitiveValue() error = %v", tokenErr)
			}
			defer childToken.Destroy()
			var requestCount atomic.Int32
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				requestCount.Add(1)
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, responseBody)
			}))
			client := newTestClient(t, server)
			dynamic, err := client.IssueDynamic(context.Background(), childToken, request)
			var failure *ClientError
			if err == nil || !errors.As(err, &failure) || !failure.Ambiguous || len(dynamic.Secret.Bytes()) != 0 ||
				strings.Contains(err.Error(), "secret-password-canary") || strings.Contains(err.Error(), "lease-canary") ||
				strings.Contains(err.Error(), "hvs.child-token-canary") {
				t.Fatalf("IssueDynamic(%s) result/error = %#v/%v", name, dynamic, err)
			}
			if requestCount.Load() != 1 {
				t.Fatalf("IssueDynamic(%s) requests = %d, want 1", name, requestCount.Load())
			}
		})
	}
}

func TestClientIssueDynamicAcceptsRenewableDatabaseLeaseWithoutExposingLeaseID(t *testing.T) {
	t.Parallel()

	childToken, err := credential.NewSensitiveValue([]byte("hvs.child-token-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	defer childToken.Destroy()
	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	request := credential.DurableDynamicIssueRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, strings.Replace(validDynamicResponseJSON(), `"renewable":false`, `"renewable":true`, 1))
	}))
	client := newTestClient(t, server)

	dynamic, err := client.IssueDynamic(context.Background(), childToken, request)
	if err != nil {
		t.Fatalf("IssueDynamic(renewable database lease) error = %v", err)
	}
	defer dynamic.Secret.Destroy()
	material := dynamic.Secret.Bytes()
	defer clear(material)
	encoded, marshalErr := json.Marshal(dynamic)
	defer clear(encoded)
	if marshalErr != nil || bytesContainsAny(material, "lease-canary", managerTokenCanary, "hvs.child-token-canary") ||
		bytesContainsAny(encoded, "lease-canary", "secret-password-canary", "hvs.child-token-canary") {
		t.Fatalf("IssueDynamic(renewable database lease) leaked sensitive wire data")
	}
	if requestCount.Load() != 1 {
		t.Fatalf("IssueDynamic(renewable database lease) requests = %d, want 1", requestCount.Load())
	}
}

func TestClientIssueDynamicUsesDispatchTimeForConservativeExpiry(t *testing.T) {
	t.Parallel()

	childToken, err := credential.NewSensitiveValue([]byte("hvs.child-token-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	defer childToken.Destroy()
	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	request := credential.DurableDynamicIssueRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	receivedAt := make(chan time.Time, 1)
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		receivedAt <- time.Now().UTC()
		time.Sleep(150 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		response := strings.Replace(validDynamicResponseJSON(), `"lease_duration":180`, `"lease_duration":2`, 1)
		_, _ = io.WriteString(writer, response)
	}))
	client := newTestClient(t, server)

	dynamic, err := client.IssueDynamic(context.Background(), childToken, request)
	if err != nil {
		t.Fatalf("IssueDynamic(delayed response) error = %v", err)
	}
	defer dynamic.Secret.Destroy()
	requestReceivedAt := <-receivedAt
	responseObservedAt := time.Now().UTC()
	maximumConservativeExpiry := credential.CanonicalCredentialExpiry(requestReceivedAt.Add(2 * time.Second))
	if dynamic.ExpiresAt.After(maximumConservativeExpiry) || !dynamic.ExpiresAt.After(responseObservedAt) ||
		dynamic.ExpiresAt.After(request.CredentialExpiresAt) {
		t.Fatalf("IssueDynamic(delayed response) expiry = %s, response=%s maximum=%s deadline=%s",
			dynamic.ExpiresAt, responseObservedAt, maximumConservativeExpiry, request.CredentialExpiresAt)
	}
}

func TestConservativeLeaseExpiryRequiresLiveMonotonicLeaseWithinDatabaseDeadline(t *testing.T) {
	t.Parallel()

	dispatchedAt := time.Now()
	databaseDeadline := credential.CanonicalCredentialExpiry(dispatchedAt.Add(10 * time.Second).UTC())
	expiresAt, ok := conservativeLeaseExpiry(dispatchedAt, dispatchedAt.Add(2*time.Second), 5, databaseDeadline)
	wantExpiry := credential.CanonicalCredentialExpiry(dispatchedAt.Add(5 * time.Second).UTC())
	if !ok || !expiresAt.Equal(wantExpiry) || !expiresAt.Equal(credential.CanonicalCredentialExpiry(expiresAt)) {
		t.Fatalf("conservativeLeaseExpiry(valid) = %s/%t, want %s/true", expiresAt, ok, wantExpiry)
	}
	if expiry, valid := conservativeLeaseExpiry(dispatchedAt, dispatchedAt.Add(6*time.Second), 5, databaseDeadline); valid || !expiry.IsZero() {
		t.Fatalf("conservativeLeaseExpiry(expired at response) = %s/%t", expiry, valid)
	}
	shortDeadline := credential.CanonicalCredentialExpiry(dispatchedAt.Add(4 * time.Second).UTC())
	if expiry, valid := conservativeLeaseExpiry(dispatchedAt, dispatchedAt.Add(time.Second), 5, shortDeadline); valid ||
		!expiry.IsZero() {
		t.Fatalf("conservativeLeaseExpiry(after DB deadline) = %s/%t", expiry, valid)
	}
}

func bytesContainsAny(value []byte, needles ...string) bool {
	for _, needle := range needles {
		if bytes.Contains(value, []byte(needle)) {
			return true
		}
	}
	return false
}

func TestClientIssueDynamicDoesNotReplay4xxOrDisconnect(t *testing.T) {
	t.Parallel()

	now := credential.CanonicalCredentialExpiry(time.Now().UTC())
	request := credential.DurableDynamicIssueRequest{
		RevocationID: "30000000-0000-4000-8000-000000000020", ProfileRevision: "rev-1",
		CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	tests := map[string]http.Handler{
		"permission response": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, "upstream-secret-password-canary")
		}),
		"connection drop": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			connection, _, hijackErr := writer.(http.Hijacker).Hijack()
			if hijackErr == nil {
				_ = connection.Close()
			}
		}),
	}
	for name, handler := range tests {
		name, handler := name, handler
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			childToken, tokenErr := credential.NewSensitiveValue([]byte("hvs.child-token-canary"))
			if tokenErr != nil {
				t.Fatalf("NewSensitiveValue() error = %v", tokenErr)
			}
			defer childToken.Destroy()
			var requestCount atomic.Int32
			server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
				requestCount.Add(1)
				handler.ServeHTTP(writer, httpRequest)
			}))
			client := newTestClient(t, server)
			_, err := client.IssueDynamic(context.Background(), childToken, request)
			var failure *ClientError
			if err == nil || !errors.As(err, &failure) || !failure.Ambiguous ||
				strings.Contains(err.Error(), "upstream-secret-password-canary") || strings.Contains(err.Error(), "hvs.child-token-canary") {
				t.Fatalf("IssueDynamic(%s) error = %v", name, err)
			}
			if requestCount.Load() != 1 {
				t.Fatalf("IssueDynamic(%s) requests = %d, want 1", name, requestCount.Load())
			}
		})
	}
}

func validDynamicResponseJSON() string {
	return `{
		"request_id":"request-dynamic-1","lease_id":"database/creds/aiops-db-job/lease-canary","renewable":false,"lease_duration":180,
		"data":{"username":"job_user","password":"secret-password-canary"},
		"wrap_info":null,"warnings":null,"auth":null,"mount_type":"database"
	}`
}

func TestClientRevokeAccessorUsesIndependentRevokerSource(t *testing.T) {
	t.Parallel()

	accessor, err := credential.NewSensitiveReference([]byte("child-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	defer accessor.Destroy()
	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		requestCount.Add(1)
		if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != "/v1/auth/token/revoke-accessor" {
			t.Errorf("revoke request = %s %s", httpRequest.Method, httpRequest.URL.Path)
		}
		if httpRequest.Header.Get("X-Vault-Token") != revokerTokenCanary {
			t.Error("revoke accessor did not use the independent revoker token")
		}
		body, readErr := io.ReadAll(httpRequest.Body)
		if readErr != nil || string(body) != `{"accessor":"child-accessor-canary"}` {
			t.Errorf("revoke body = %q, %v", body, readErr)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	client := newTestRevocationClient(t, server)

	if err := client.RevokeAccessor(context.Background(), accessor); err != nil {
		t.Fatalf("RevokeAccessor() error = %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("revoke requests = %d, want 1", requestCount.Load())
	}
}

func TestClientRevokeAccessorKeepsHTTP400Retryable(t *testing.T) {
	t.Parallel()

	accessor, err := credential.NewSensitiveReference([]byte("child-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	defer accessor.Destroy()
	var requestCount atomic.Int32
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, "child-accessor-canary hvs.revoker-token-canary upstream-error-canary")
	}))
	client := newTestRevocationClient(t, server)

	err = client.RevokeAccessor(context.Background(), accessor)
	var failure *ClientError
	if err == nil || !errors.As(err, &failure) || failure.StatusCode != http.StatusBadRequest || !failure.Ambiguous ||
		strings.Contains(err.Error(), "child-accessor-canary") || strings.Contains(err.Error(), revokerTokenCanary) ||
		strings.Contains(err.Error(), "upstream-error-canary") {
		t.Fatalf("RevokeAccessor(400) error = %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("RevokeAccessor(400) requests = %d, want 1", requestCount.Load())
	}
}

func TestClientRevokeAccessorAcceptsExactAlreadyAbsentWarning(t *testing.T) {
	t.Parallel()

	accessor, err := credential.NewSensitiveReference([]byte("child-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	defer accessor.Destroy()
	server := newVaultTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"request_id":"request-revoke-absent","lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":["No token found with this accessor"],"auth":null,"mount_type":"token"}`)
	}))
	client := newTestRevocationClient(t, server)
	if err := client.RevokeAccessor(context.Background(), accessor); err != nil {
		t.Fatalf("RevokeAccessor(already absent) error = %v", err)
	}
}

func writeValidManagerResponse(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, validManagerResponseJSON())
}

func validManagerResponseJSON() string {
	return `{
		"request_id":"request-manager-valid","lease_id":"","renewable":false,"lease_duration":0,
		"data":{"id":"hvs.manager-token-canary","accessor":"manager-accessor","policies":["aiops-issuer-manager"],"path":"auth/token/create","meta":{},"display_name":"aiops-manager","num_uses":0,"orphan":true,"creation_time":1783700000,"creation_ttl":7200,"expire_time":"2026-07-11T01:00:00Z","ttl":3600,"explicit_max_ttl":7200,"entity_id":"","type":"service","renewable":false,"issue_time":"2026-07-10T23:00:00Z"},
		"wrap_info":null,"warnings":null,"auth":null,"mount_type":"token"
	}`
}

type staticTokenSource struct {
	mu       sync.Mutex
	id       string
	value    []byte
	requests int
}

type failingTokenSource struct {
	id    string
	value credential.SensitiveValue
}

func (source *failingTokenSource) SourceID() string { return source.id }

func (source *failingTokenSource) Token(context.Context) (credential.SensitiveValue, error) {
	return source.value, errors.New("source-error-secret-canary")
}

func (source *staticTokenSource) SourceID() string { return source.id }

func (source *staticTokenSource) Token(ctx context.Context) (credential.SensitiveValue, error) {
	if err := ctx.Err(); err != nil {
		return credential.SensitiveValue{}, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.requests++
	return credential.NewSensitiveValue(source.value)
}

func newTestClient(t *testing.T, server *httptest.Server) *IssuerClient {
	t.Helper()
	profile, err := NewProfile(profileConfigForServer(t, server))
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	client, err := NewIssuerClient(profile,
		&staticTokenSource{id: "issuer-manager-source", value: []byte(managerTokenCanary)})
	if err != nil {
		t.Fatalf("NewIssuerClient() error = %v", err)
	}
	return client
}

func newTestRevocationClient(t *testing.T, server *httptest.Server) *RevocationClient {
	t.Helper()
	profile, err := NewProfile(profileConfigForServer(t, server))
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	client, err := NewRevocationClient(profile,
		&staticTokenSource{id: "revoker-source", value: []byte(revokerTokenCanary)})
	if err != nil {
		t.Fatalf("NewRevocationClient() error = %v", err)
	}
	return client
}

func profileConfigForServer(t *testing.T, server *httptest.Server) ProfileConfig {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return ProfileConfig{
		IssuerID: "vault-database-nonprod", Revision: "rev-1", Address: server.URL,
		ServerName: serverURL.Hostname(),
		CAPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		Namespace:  "aiops", ManagerPolicy: "aiops-issuer-manager", TokenRole: "aiops-db-job",
		ChildPolicy: "aiops-db-job", DynamicPath: "database/creds/aiops-db-job", MountType: "database",
		Metadata: map[string]string{"profile": "vault-database-nonprod", "revision": "rev-1"},
		SecretFields: []SecretField{
			{Name: "username", MaxBytes: 256}, {Name: "password", MaxBytes: 4096},
		},
	}
}

func newVaultTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
