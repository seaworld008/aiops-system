package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestNewKeycloakVerifierRejectsUnsafeDiscoveryConfiguration(t *testing.T) {
	t.Parallel()
	var exactConstructor func(context.Context, string, string, string) (*KeycloakVerifier, error) = NewKeycloakVerifier
	if exactConstructor == nil {
		t.Fatal("NewKeycloakVerifier constructor is nil")
	}

	for _, test := range []struct {
		issuer, audience, authorizedParty string
	}{
		{"", "aiops-control-plane", "control-plane-web"},
		{"http://keycloak.example.com/realms/aiops", "aiops-control-plane", "control-plane-web"},
		{"https://user@keycloak.example.com/realms/aiops", "aiops-control-plane", "control-plane-web"},
		{"https://keycloak.example.com/realms/aiops?unsafe=x", "aiops-control-plane", "control-plane-web"},
		{"https://keycloak.example.com/a/../realms/aiops", "aiops-control-plane", "control-plane-web"},
		{"https://keycloak.example.com/realms/aiops", "", "control-plane-web"},
		{"https://keycloak.example.com/realms/aiops", "aiops-control-plane", ""},
	} {
		if _, err := NewKeycloakVerifier(
			context.Background(), test.issuer, test.audience, test.authorizedParty,
		); err == nil {
			t.Fatalf("NewKeycloakVerifier(%q, %q, %q) error = nil", test.issuer, test.audience, test.authorizedParty)
		}
	}
}

func TestKeycloakVerifierUsesOnlyFixedTenantClaim(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate OIDC test key: %v", err)
	}
	const keyID = "keycloak-test-key"
	publicKey := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
				"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/keys",
				"id_token_signing_alg_values_supported": []string{string(jose.RS256)},
			})
		case "/keys":
			_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	const clientID = testKeycloakAudience
	oidcContext := oidc.ClientContext(context.Background(), server.Client())
	provider, err := oidc.NewProvider(oidcContext, server.URL)
	if err != nil {
		t.Fatalf("discover test OIDC provider: %v", err)
	}
	verifier := &KeycloakVerifier{
		audience: clientID, authorizedParty: testKeycloakAuthorizedParty,
		verifier: provider.Verifier(&oidc.Config{
			ClientID:             clientID,
			SupportedSigningAlgs: []string{oidc.RS256},
		}),
	}
	now := time.Now().UTC().Truncate(time.Second)
	rawToken := signKeycloakTestToken(t, privateKey, keyID, map[string]any{
		"iss": server.URL, "sub": "subject-1", "aud": []string{clientID},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"preferred_username": "alice", "aiops_tenant_id": "11111111-1111-4111-8111-111111111111",
		"tenant_id": "22222222-2222-4222-8222-222222222222", "tenant": "33333333-3333-4333-8333-333333333333",
		"aiops_workspaces": []string{"workspace-1"}, "aiops_environments": []string{"PROD"}, "aiops_services": []string{"service-1"},
		"realm_access": map[string]any{"roles": []string{"SRE"}},
		"resource_access": map[string]any{
			clientID:                         map[string]any{"roles": []string{"VIEWER"}},
			testKeycloakAuthorizedParty:      map[string]any{"roles": []string{"ADMIN"}},
			"unrelated-control-plane-client": map[string]any{"roles": []string{"AUDITOR"}},
		},
	})
	claims, err := verifier.Verify(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.TenantID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("Verify().TenantID = %q, want only aiops_tenant_id", claims.TenantID)
	}
	if !reflect.DeepEqual(claims.Roles, []string{"SRE", "VIEWER"}) {
		t.Fatalf("Verify().Roles = %#v, want realm plus API-audience roles only", claims.Roles)
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing azp": func(claims map[string]any) { delete(claims, "azp") },
		"wrong azp":   func(claims map[string]any) { claims["azp"] = "other-client" },
		"extra aud": func(claims map[string]any) {
			claims["aud"] = []string{clientID, "other-api"}
		},
		"wrong aud": func(claims map[string]any) { claims["aud"] = []string{"other-api"} },
	} {
		tokenClaims := map[string]any{
			"iss": server.URL, "sub": "subject-1", "aud": []string{clientID},
			"azp": testKeycloakAuthorizedParty,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
			"aiops_tenant_id": "11111111-1111-4111-8111-111111111111",
		}
		mutate(tokenClaims)
		candidate := signKeycloakTestTokenExact(t, privateKey, keyID, tokenClaims)
		if verified, verifyErr := verifier.Verify(context.Background(), candidate); !errors.Is(verifyErr, ErrUnauthenticated) ||
			!reflect.DeepEqual(verified, VerifiedClaims{}) {
			t.Errorf("Verify(%s) = (%#v, %v), want fail closed", name, verified, verifyErr)
		}
	}
	authenticator, err := NewAuthenticator(verifier, Options{MaxSessionAge: 12 * time.Hour}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	for name, tenantID := range map[string]string{
		"uppercase":       "11111111-1111-4111-8111-AAAAAAAAAAAA",
		"trailing space":  "11111111-1111-4111-8111-111111111111 ",
		"version zero":    "11111111-1111-0111-8111-111111111111",
		"non-RFC variant": "11111111-1111-4111-7111-111111111111",
	} {
		invalidToken := signKeycloakTestToken(t, privateKey, keyID, map[string]any{
			"iss": server.URL, "sub": "subject-1", "aud": []string{clientID},
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
			"aiops_tenant_id": tenantID, "aiops_workspaces": []string{testKeycloakWorkspaceID},
			"aiops_environments": []string{"PROD"}, "realm_access": map[string]any{"roles": []string{"SRE"}},
		})
		decoded, verifyErr := verifier.Verify(context.Background(), invalidToken)
		if verifyErr == nil && decoded.TenantID != tenantID {
			t.Errorf("Verify(%s) normalized tenant %q to %q", name, tenantID, decoded.TenantID)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", "Bearer "+invalidToken)
		principal, authenticateErr := authenticator.Authenticate(request)
		if !errors.Is(authenticateErr, ErrUnauthenticated) || !reflect.DeepEqual(principal, Principal{}) {
			t.Errorf("Authenticate(%s tenant) = (%#v, %v), want fail closed", name, principal, authenticateErr)
		}
	}

	missingFixedClaim := signKeycloakTestToken(t, privateKey, keyID, map[string]any{
		"iss": server.URL, "sub": "subject-1", "aud": []string{clientID},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"tenant_id": "22222222-2222-4222-8222-222222222222", "tenant": "33333333-3333-4333-8333-333333333333",
		"workspace_id": testKeycloakWorkspaceID, "environment_id": "PROD",
		"aiops_workspaces": []string{testKeycloakWorkspaceID}, "aiops_environments": []string{"PROD"}, "aiops_services": []string{"service-1"},
		"realm_access": map[string]any{"roles": []string{"SRE"}},
	})
	claims, err = verifier.Verify(context.Background(), missingFixedClaim)
	if err != nil {
		t.Fatalf("Verify(missing fixed claim) error = %v", err)
	}
	if claims.TenantID != "" {
		t.Fatalf("Verify(missing fixed claim).TenantID = %q, adjacent claim became tenant authority", claims.TenantID)
	}
	request := httptest.NewRequest(http.MethodPost, "/?tenant_id=44444444-4444-4444-8444-444444444444", strings.NewReader(`{"tenant_id":"55555555-5555-4555-8555-555555555555"}`))
	request.Header.Set("Authorization", "Bearer "+missingFixedClaim)
	request.Header.Set("X-Tenant-ID", "66666666-6666-4666-8666-666666666666")
	principal, err := authenticator.Authenticate(request)
	if !errors.Is(err, ErrUnauthenticated) || !reflect.DeepEqual(principal, Principal{}) {
		t.Fatalf("Authenticate(adjacent tenant claims) = (%#v, %v), want zero Principal and ErrUnauthenticated", principal, err)
	}

	nonStringFixedClaim := signKeycloakTestToken(t, privateKey, keyID, map[string]any{
		"iss": server.URL, "sub": "subject-1", "aud": []string{clientID},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"aiops_tenant_id": []string{"11111111-1111-4111-8111-111111111111"},
	})
	if claims, err := verifier.Verify(context.Background(), nonStringFixedClaim); err == nil || claims.TenantID != "" {
		t.Fatalf("Verify(non-string aiops_tenant_id) = (%#v, %v), want decode rejection", claims, err)
	}

	wrongCaseClaim := signKeycloakTestToken(t, privateKey, keyID, map[string]any{
		"iss": server.URL, "sub": "subject-1", "aud": []string{clientID},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"AIOPS_TENANT_ID":  "11111111-1111-4111-8111-111111111111",
		"aiops_workspaces": []string{testKeycloakWorkspaceID}, "aiops_environments": []string{"PROD"},
		"realm_access": map[string]any{"roles": []string{"SRE"}},
	})
	if claims, err := verifier.Verify(context.Background(), wrongCaseClaim); err == nil && claims.TenantID != "" {
		t.Fatalf("Verify(wrong-case tenant claim) = %#v, claim key match was not exact", claims)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+wrongCaseClaim)
	if principal, err := authenticator.Authenticate(request); !errors.Is(err, ErrUnauthenticated) || !reflect.DeepEqual(principal, Principal{}) {
		t.Fatalf("Authenticate(wrong-case tenant claim) = (%#v, %v), want fail closed", principal, err)
	}

	for name, duplicateTail := range map[string]string{
		"same duplicate":        `"aiops_tenant_id":"11111111-1111-4111-8111-111111111111"`,
		"conflicting duplicate": `"aiops_tenant_id":"22222222-2222-4222-8222-222222222222"`,
	} {
		payload := []byte(fmt.Sprintf(`{"iss":%q,"sub":"subject-1","aud":[%q],"azp":%q,"iat":%d,"exp":%d,"auth_time":%d,"aiops_tenant_id":"11111111-1111-4111-8111-111111111111",%s,"aiops_workspaces":[%q],"aiops_environments":["PROD"],"realm_access":{"roles":["SRE"]}}`, server.URL, clientID, testKeycloakAuthorizedParty, now.Unix(), now.Add(time.Hour).Unix(), now.Add(-time.Minute).Unix(), duplicateTail, testKeycloakWorkspaceID))
		duplicateToken := signKeycloakTestPayload(t, privateKey, keyID, payload)
		if claims, err := verifier.Verify(context.Background(), duplicateToken); err == nil || claims.TenantID != "" {
			t.Errorf("Verify(%s tenant claim) = (%#v, %v), want duplicate rejection", name, claims, err)
		}
	}
}

const (
	testKeycloakWorkspaceID     = "workspace-1"
	testKeycloakAudience        = "aiops-control-plane"
	testKeycloakAuthorizedParty = "control-plane-web"
)

func signKeycloakTestToken(t *testing.T, privateKey *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	cloned := make(map[string]any, len(claims)+1)
	for key, value := range claims {
		cloned[key] = value
	}
	if _, present := cloned["azp"]; !present {
		cloned["azp"] = testKeycloakAuthorizedParty
	}
	return signKeycloakTestTokenExact(t, privateKey, keyID, cloned)
}

func signKeycloakTestTokenExact(t *testing.T, privateKey *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: privateKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}, nil)
	if err != nil {
		t.Fatalf("create OIDC signer: %v", err)
	}
	rawToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign OIDC token: %v", err)
	}
	return rawToken
}

func signKeycloakTestPayload(t *testing.T, privateKey *rsa.PrivateKey, keyID string, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: privateKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}, nil)
	if err != nil {
		t.Fatalf("create raw OIDC signer: %v", err)
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign raw OIDC payload: %v", err)
	}
	rawToken, err := signature.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize raw OIDC token: %v", err)
	}
	return rawToken
}
