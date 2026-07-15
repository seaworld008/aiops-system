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
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type KeycloakVerifier struct {
	clientID string
	verifier *oidc.IDTokenVerifier
}

func NewKeycloakVerifier(ctx context.Context, issuer, clientID string) (*KeycloakVerifier, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || issuer != strings.TrimSpace(issuer) || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, fmt.Errorf("Keycloak issuer must be a clean HTTPS URL")
	}
	if !scopePattern.MatchString(clientID) {
		return nil, fmt.Errorf("valid Keycloak client id is required")
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
		ClientID: clientID,
		SupportedSigningAlgs: []string{
			oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.ES512,
		},
	})
	return &KeycloakVerifier{clientID: clientID, verifier: verifier}, nil
}

func (verifier *KeycloakVerifier) Verify(ctx context.Context, rawToken string) (VerifiedClaims, error) {
	token, err := verifier.verifier.Verify(ctx, rawToken)
	if err != nil {
		return VerifiedClaims{}, ErrUnauthenticated
	}
	tenantID, err := decodeFixedTenantClaim(rawToken)
	if err != nil {
		return VerifiedClaims{}, ErrUnauthenticated
	}
	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		AuthTime          int64    `json:"auth_time"`
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
	if err := token.Claims(&claims); err != nil || claims.AuthTime <= 0 {
		return VerifiedClaims{}, ErrUnauthenticated
	}
	roles := append([]string(nil), claims.RealmAccess.Roles...)
	roles = append(roles, claims.ResourceAccess[verifier.clientID].Roles...)
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
