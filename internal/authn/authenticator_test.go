package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestAuthenticatorBuildsPrincipalOnlyFromVerifiedBearerClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	verifier := &fakeVerifier{claims: VerifiedClaims{
		Subject: "keycloak-subject-1", Username: "alice", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Roles: []string{"SRE", "UNKNOWN", "SRE"}, WorkspaceIDs: []string{"workspace-b", "workspace-a", "workspace-a"},
		EnvironmentIDs: []string{"PROD"},
		ServiceIDs:     []string{"service-payments", "service-payments"},
	}}
	authenticator, err := NewAuthenticator(verifier, Options{MaxSessionAge: 12 * time.Hour}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer signed-token")
	request.Header.Set("X-User-ID", "attacker-controlled")

	principal, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if principal.Subject != "keycloak-subject-1" || principal.Username != "alice" || verifier.token != "signed-token" {
		t.Fatalf("principal/verifier = %#v/%q", principal, verifier.token)
	}
	if !reflect.DeepEqual(principal.Roles, []Role{RoleSRE}) || !reflect.DeepEqual(principal.WorkspaceIDs, []string{"workspace-a", "workspace-b"}) || !reflect.DeepEqual(principal.EnvironmentIDs, []string{"PROD"}) || !reflect.DeepEqual(principal.ServiceIDs, []string{"service-payments"}) {
		t.Fatalf("normalized principal = %#v", principal)
	}
}

func TestAuthenticatorRejectsMalformedExpiredOrStaleIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		headers []string
		claims  VerifiedClaims
	}{
		"missing bearer":                 {claims: validClaims(now)},
		"multiple authorization headers": {headers: []string{"Bearer one", "Bearer two"}, claims: validClaims(now)},
		"expired":                        {headers: []string{"Bearer token"}, claims: func() VerifiedClaims { value := validClaims(now); value.ExpiresAt = now; return value }()},
		"stale auth": {headers: []string{"Bearer token"}, claims: func() VerifiedClaims {
			value := validClaims(now)
			value.AuthenticatedAt = now.Add(-13 * time.Hour)
			return value
		}()},
		"future auth": {headers: []string{"Bearer token"}, claims: func() VerifiedClaims {
			value := validClaims(now)
			value.AuthenticatedAt = now.Add(2 * time.Minute)
			return value
		}()},
		"no platform role":     {headers: []string{"Bearer token"}, claims: func() VerifiedClaims { value := validClaims(now); value.Roles = []string{"UNKNOWN"}; return value }()},
		"no workspace scope":   {headers: []string{"Bearer token"}, claims: func() VerifiedClaims { value := validClaims(now); value.WorkspaceIDs = nil; return value }()},
		"no environment scope": {headers: []string{"Bearer token"}, claims: func() VerifiedClaims { value := validClaims(now); value.EnvironmentIDs = nil; return value }()},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			verifier := &fakeVerifier{claims: test.claims}
			authenticator, err := NewAuthenticator(verifier, Options{MaxSessionAge: 12 * time.Hour}, func() time.Time { return now })
			if err != nil {
				t.Fatalf("NewAuthenticator() error = %v", err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, header := range test.headers {
				request.Header.Add("Authorization", header)
			}
			if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate() error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestPrincipalContextRoundTrip(t *testing.T) {
	t.Parallel()

	principal := Principal{Subject: "subject-1"}
	ctx := WithPrincipal(context.Background(), principal)
	got, ok := PrincipalFromContext(ctx)
	if !ok || got.Subject != principal.Subject {
		t.Fatalf("PrincipalFromContext() = (%#v, %v)", got, ok)
	}
}

type fakeVerifier struct {
	claims VerifiedClaims
	err    error
	token  string
}

func (verifier *fakeVerifier) Verify(_ context.Context, token string) (VerifiedClaims, error) {
	verifier.token = token
	return verifier.claims, verifier.err
}

func validClaims(now time.Time) VerifiedClaims {
	return VerifiedClaims{
		Subject: "subject-1", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Roles: []string{"SRE"}, WorkspaceIDs: []string{"workspace-1"}, EnvironmentIDs: []string{"PROD"}, ServiceIDs: []string{"service-1"},
	}
}
