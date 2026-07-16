package authn

import (
	"context"
	"errors"
	"fmt"
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
		Subject: "keycloak-subject-1", Username: "alice", TenantID: "11111111-1111-4111-8111-111111111111", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
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
	if principal.Subject != "keycloak-subject-1" || principal.Username != "alice" || principal.TenantID != "11111111-1111-4111-8111-111111111111" || verifier.token != "signed-token" {
		t.Fatalf("principal/verifier = %#v/%q", principal, verifier.token)
	}
	if !reflect.DeepEqual(principal.Roles, []Role{RoleSRE}) || !reflect.DeepEqual(principal.WorkspaceIDs, []string{"workspace-a", "workspace-b"}) || !reflect.DeepEqual(principal.EnvironmentIDs, []string{"PROD"}) || !reflect.DeepEqual(principal.ServiceIDs, []string{"service-payments"}) {
		t.Fatalf("normalized principal = %#v", principal)
	}
}

func TestAuthenticatorAcceptsViewerAsAClosedAssetReadRole(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	claims := validClaims(now)
	claims.Roles = []string{"VIEWER", "UNKNOWN", "VIEWER"}
	authenticator, err := NewAuthenticator(
		&fakeVerifier{claims: claims},
		Options{MaxSessionAge: 12 * time.Hour},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	request.Header.Set("Authorization", "Bearer signed-token")

	principal, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !reflect.DeepEqual(principal.Roles, []Role{RoleViewer}) {
		t.Fatalf("principal roles = %#v, want VIEWER only", principal.Roles)
	}
}

func TestAuthenticatedPrincipalRequiresCanonicalTenantID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 15, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		tenantID string
		wantOK   bool
	}{
		{name: "missing", tenantID: ""},
		{name: "uppercase", tenantID: "11111111-1111-4111-8111-AAAAAAAAAAAA"},
		{name: "braced", tenantID: "{11111111-1111-4111-8111-111111111111}"},
		{name: "trailing whitespace", tenantID: "11111111-1111-4111-8111-111111111111 "},
		{name: "newline", tenantID: "11111111-1111-4111-8111-111111111111\n"},
		{name: "NUL", tenantID: "11111111-1111-4111-8111-111111111111\x00"},
	}
	for _, version := range "12345" {
		for _, variant := range "89ab" {
			tests = append(tests, struct {
				name     string
				tenantID string
				wantOK   bool
			}{
				name:     fmt.Sprintf("canonical version %c RFC variant %c UUID", version, variant),
				tenantID: fmt.Sprintf("11111111-1111-%c111-%c111-111111111111", version, variant),
				wantOK:   true,
			})
		}
	}
	for _, version := range "06789abcdef" {
		tests = append(tests, struct {
			name     string
			tenantID string
			wantOK   bool
		}{name: fmt.Sprintf("invalid version nibble %c", version), tenantID: fmt.Sprintf("11111111-1111-%c111-8111-111111111111", version)})
	}
	for _, variant := range "01234567cdef" {
		tests = append(tests, struct {
			name     string
			tenantID string
			wantOK   bool
		}{name: fmt.Sprintf("invalid variant nibble %c", variant), tenantID: fmt.Sprintf("11111111-1111-4111-%c111-111111111111", variant)})
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(now)
			claims.TenantID = test.tenantID
			authenticator, err := NewAuthenticator(&fakeVerifier{claims: claims}, Options{MaxSessionAge: 12 * time.Hour}, func() time.Time { return now })
			if err != nil {
				t.Fatalf("NewAuthenticator() error = %v", err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", "Bearer signed-token")
			principal, err := authenticator.Authenticate(request)
			if test.wantOK {
				if err != nil || principal.TenantID != test.tenantID {
					t.Fatalf("Authenticate() = (%#v, %v), want canonical tenant", principal, err)
				}
				return
			}
			if !errors.Is(err, ErrUnauthenticated) || !reflect.DeepEqual(principal, Principal{}) {
				t.Fatalf("Authenticate() = (%#v, %v), want zero Principal and ErrUnauthenticated", principal, err)
			}
		})
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

	principal := Principal{Subject: "subject-1", TenantID: "11111111-1111-4111-8111-111111111111"}
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
		Subject: "subject-1", TenantID: "11111111-1111-4111-8111-111111111111", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Roles: []string{"SRE"}, WorkspaceIDs: []string{"workspace-1"}, EnvironmentIDs: []string{"PROD"}, ServiceIDs: []string{"service-1"},
	}
}
