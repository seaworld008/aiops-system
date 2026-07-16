package authn

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

var ErrUnauthenticated = errors.New("unauthenticated")

type Role string

const (
	RoleViewer       Role = "VIEWER"
	RoleSRE          Role = "SRE"
	RoleServiceOwner Role = "SERVICE_OWNER"
	RoleApprover     Role = "APPROVER"
	RoleAuditor      Role = "AUDITOR"
	RoleAdmin        Role = "ADMIN"
)

type VerifiedClaims struct {
	Subject         string
	Username        string
	TenantID        string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Roles           []string
	WorkspaceIDs    []string
	EnvironmentIDs  []string
	ServiceIDs      []string
}

type TokenVerifier interface {
	Verify(context.Context, string) (VerifiedClaims, error)
}

type Principal struct {
	Subject         string
	Username        string
	TenantID        string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Roles           []Role
	WorkspaceIDs    []string
	EnvironmentIDs  []string
	ServiceIDs      []string
}

type Options struct {
	MaxSessionAge time.Duration
}

type Authenticator struct {
	verifier TokenVerifier
	options  Options
	clock    func() time.Time
}

var (
	scopePattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	canonicalTenantIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func NewAuthenticator(verifier TokenVerifier, options Options, clock func() time.Time) (*Authenticator, error) {
	if verifier == nil || options.MaxSessionAge < time.Minute || options.MaxSessionAge > 24*time.Hour {
		return nil, errors.New("verifier and max session age between 1m and 24h are required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Authenticator{verifier: verifier, options: options, clock: clock}, nil
}

func (authenticator *Authenticator) Authenticate(request *http.Request) (Principal, error) {
	headers := request.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
		return Principal{}, ErrUnauthenticated
	}
	token := strings.TrimPrefix(headers[0], "Bearer ")
	if token == "" || len(token) > 16<<10 || strings.ContainsAny(token, " \t\r\n\x00") {
		return Principal{}, ErrUnauthenticated
	}
	claims, err := authenticator.verifier.Verify(request.Context(), token)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	now := authenticator.clock().UTC()
	if !validClaimsTime(claims, now, authenticator.options.MaxSessionAge) ||
		!scopePattern.MatchString(claims.Subject) ||
		!canonicalTenantIDPattern.MatchString(claims.TenantID) ||
		len(claims.Username) > 256 {
		return Principal{}, ErrUnauthenticated
	}
	roles := normalizeRoles(claims.Roles)
	workspaces, ok := normalizeScopes(claims.WorkspaceIDs, 1000)
	if len(roles) == 0 || !ok || len(workspaces) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	services, ok := normalizeScopes(claims.ServiceIDs, 5000)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	environments, ok := normalizeScopes(claims.EnvironmentIDs, 100)
	if !ok || len(environments) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{
		Subject: claims.Subject, Username: claims.Username, TenantID: claims.TenantID,
		AuthenticatedAt: claims.AuthenticatedAt.UTC(), ExpiresAt: claims.ExpiresAt.UTC(),
		Roles: roles, WorkspaceIDs: workspaces, EnvironmentIDs: environments, ServiceIDs: services,
	}, nil
}

func validClaimsTime(claims VerifiedClaims, now time.Time, maxSessionAge time.Duration) bool {
	if claims.AuthenticatedAt.IsZero() || claims.ExpiresAt.IsZero() || !now.Before(claims.ExpiresAt) {
		return false
	}
	if claims.AuthenticatedAt.After(now.Add(30 * time.Second)) {
		return false
	}
	return now.Sub(claims.AuthenticatedAt) <= maxSessionAge
}

func normalizeRoles(values []string) []Role {
	seen := make(map[Role]struct{}, len(values))
	for _, value := range values {
		role := Role(value)
		switch role {
		case RoleViewer, RoleSRE, RoleServiceOwner, RoleApprover, RoleAuditor, RoleAdmin:
			seen[role] = struct{}{}
		}
	}
	roles := make([]Role, 0, len(seen))
	for role := range seen {
		roles = append(roles, role)
	}
	slices.Sort(roles)
	return roles
}

func normalizeScopes(values []string, maximum int) ([]string, bool) {
	if len(values) > maximum {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !scopePattern.MatchString(value) {
			return nil, false
		}
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	slices.Sort(result)
	return result, true
}

type principalContextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}
