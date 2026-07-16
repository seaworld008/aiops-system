package authn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type KeycloakVerifier struct {
	audience        string
	authorizedParty string
	verifier        *oidc.IDTokenVerifier
}

func NewKeycloakVerifier(
	ctx context.Context,
	issuer string,
	audience string,
	authorizedParty string,
) (*KeycloakVerifier, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || issuer != strings.TrimSpace(issuer) || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawPath != "" || path.Clean(parsed.Path) != parsed.Path {
		return nil, fmt.Errorf("Keycloak issuer must be a clean HTTPS URL")
	}
	if !scopePattern.MatchString(audience) || !scopePattern.MatchString(authorizedParty) {
		return nil, fmt.Errorf("valid Keycloak audience and authorized party are required")
	}
	strictClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("OIDC discovery redirects are disabled")
		},
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, strictClient), issuer)
	if err != nil {
		return nil, fmt.Errorf("discover Keycloak issuer: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: audience,
		SupportedSigningAlgs: []string{
			oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.ES512,
		},
	})
	return &KeycloakVerifier{
		audience: audience, authorizedParty: authorizedParty, verifier: verifier,
	}, nil
}

func (verifier *KeycloakVerifier) Verify(ctx context.Context, rawToken string) (VerifiedClaims, error) {
	token, err := verifier.verifier.Verify(ctx, rawToken)
	if err != nil || len(token.Audience) != 1 || token.Audience[0] != verifier.audience {
		return VerifiedClaims{}, ErrUnauthenticated
	}
	tenantID, err := decodeFixedTenantClaim(rawToken)
	if err != nil {
		return VerifiedClaims{}, ErrUnauthenticated
	}
	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		AuthTime          int64    `json:"auth_time"`
		AuthorizedParty   string   `json:"azp"`
		WorkspaceIDs      []string `json:"aiops_workspaces"`
		EnvironmentIDs    []string `json:"aiops_environments"`
		ServiceIDs        []string `json:"aiops_services"`
		RealmAccess       struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		ResourceAccess map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if err := token.Claims(&claims); err != nil || claims.AuthTime <= 0 ||
		claims.AuthorizedParty != verifier.authorizedParty {
		return VerifiedClaims{}, ErrUnauthenticated
	}
	roles := append([]string(nil), claims.RealmAccess.Roles...)
	roles = append(roles, claims.ResourceAccess[verifier.audience].Roles...)
	return VerifiedClaims{
		Subject: token.Subject, Username: claims.PreferredUsername, TenantID: tenantID,
		AuthenticatedAt: unixTime(claims.AuthTime), ExpiresAt: token.Expiry,
		Roles: roles, WorkspaceIDs: claims.WorkspaceIDs, EnvironmentIDs: claims.EnvironmentIDs, ServiceIDs: claims.ServiceIDs,
	}, nil
}

func decodeFixedTenantClaim(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", ErrUnauthenticated
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 64<<10 {
		return "", ErrUnauthenticated
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", ErrUnauthenticated
	}
	seen := make(map[string]struct{})
	tenantID := ""
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return "", ErrUnauthenticated
		}
		if _, duplicate := seen[key]; duplicate {
			return "", ErrUnauthenticated
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", ErrUnauthenticated
		}
		if key == "aiops_tenant_id" {
			if err := json.Unmarshal(value, &tenantID); err != nil {
				return "", ErrUnauthenticated
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || decoder.More() {
		return "", ErrUnauthenticated
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", ErrUnauthenticated
	}
	return tenantID, nil
}

func unixTime(seconds int64) time.Time {
	return time.Unix(seconds, 0).UTC()
}
