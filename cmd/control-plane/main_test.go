package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

func TestCombineReadinessFailsClosedAndRequiresEveryCheck(t *testing.T) {
	t.Parallel()

	expected := errors.New("web assets unavailable")
	calls := make([]string, 0, 3)
	ready := combineReadiness(
		func() error {
			calls = append(calls, "database")
			return nil
		},
		func() error {
			calls = append(calls, "web")
			return expected
		},
		func() error {
			calls = append(calls, "late")
			return nil
		},
	)
	if err := ready(); !errors.Is(err, expected) {
		t.Fatalf("ready() error = %v, want %v", err, expected)
	}
	if strings.Join(calls, ",") != "database,web" {
		t.Fatalf("readiness calls = %v", calls)
	}

	if err := combineReadiness(nil)(); err == nil {
		t.Fatal("nil readiness check did not fail closed")
	}
}

func TestNewOptionalWebUIKeepsDevelopmentDisabledAndConfiguredRootsFailClosed(t *testing.T) {
	t.Parallel()

	webUI, err := newOptionalWebUI("", "")
	if err != nil || webUI != nil {
		t.Fatalf("newOptionalWebUI(disabled) = (%#v, %v), want (nil, nil)", webUI, err)
	}

	webUI, err = newOptionalWebUI(
		t.TempDir(),
		"https://identity.example.com",
	)
	if err == nil || webUI != nil {
		t.Fatalf(
			"newOptionalWebUI(missing artifacts) = (%#v, %v), want closed error",
			webUI,
			err,
		)
	}
}

func TestNewAssetCatalogAssemblyFailsClosedWhenAnyDependencyIsMissing(t *testing.T) {
	t.Parallel()
	authorizer, err := authz.NewAuthorizer(5*time.Minute, time.Now)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	codec, err := httpapi.NewControlPlaneCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewControlPlaneCursorCodec() error = %v", err)
	}
	placeholderPool := &pgxpool.Pool{}
	placeholderAdmission := assetpostgres.NewSchemaAdmission(nil, "public")
	for name, dependencies := range map[string]struct {
		pool       *pgxpool.Pool
		authorizer *authz.Authorizer
		codec      *httpapi.ControlPlaneCursorCodec
		admission  *assetpostgres.SchemaAdmission
	}{
		"pool":       {nil, authorizer, codec, placeholderAdmission},
		"authorizer": {placeholderPool, nil, codec, placeholderAdmission},
		"cursor":     {placeholderPool, authorizer, nil, placeholderAdmission},
		"admission":  {placeholderPool, authorizer, codec, nil},
	} {
		assembly, err := newAssetCatalogAssembly(
			context.Background(),
			dependencies.pool, dependencies.authorizer, dependencies.codec, dependencies.admission,
		)
		if err == nil {
			t.Errorf("%s omission error = nil", name)
		}
		if assembly != (assetCatalogAssembly{}) {
			t.Errorf("%s omission assembly = %#v", name, assembly)
		}
	}
}

func TestNewAssetCatalogAssemblyRejectsUnavailableSchemaAdmission(t *testing.T) {
	t.Parallel()
	authorizer, err := authz.NewAuthorizer(5*time.Minute, time.Now)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	codec, err := httpapi.NewControlPlaneCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewControlPlaneCursorCodec() error = %v", err)
	}
	assembly, err := newAssetCatalogAssembly(
		context.Background(), &pgxpool.Pool{}, authorizer, codec,
		assetpostgres.NewSchemaAdmission(nil, "public"),
	)
	if err == nil || assembly != (assetCatalogAssembly{}) {
		t.Fatalf("unavailable admission assembly/error = (%#v, %v)", assembly, err)
	}
}

func TestAssetWriteRoutesReturnServiceUnavailableWhenAssemblyIsClosed(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	router := httpapi.NewRouter(httpapi.Dependencies{
		Authenticator: mainTestAuthenticator{principal: authn.Principal{
			Subject: "admin", TenantID: "11111111-1111-4111-8111-111111111111",
			Roles:           []authn.Role{authn.RoleAdmin},
			WorkspaceIDs:    []string{"22222222-2222-4222-8222-222222222222"},
			EnvironmentIDs:  []string{"33333333-3333-4333-8333-333333333333"},
			AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		}},
	})
	base := "/api/v1/workspaces/22222222-2222-4222-8222-222222222222/environments/" +
		"33333333-3333-4333-8333-333333333333"
	tests := []struct {
		method, path, body string
	}{
		{http.MethodPost, base + "/assets", `{}`},
		{http.MethodPatch, base + "/assets/44444444-4444-4444-8444-444444444444", `{}`},
		{http.MethodPost, base + "/assets/44444444-4444-4444-8444-444444444444:quarantine", `{}`},
		{http.MethodPost, base + "/assets/44444444-4444-4444-8444-444444444444:retire", `{}`},
		{http.MethodPost, base + "/service-asset-bindings", `{}`},
		{http.MethodDelete, base + "/service-asset-bindings/55555555-5555-4555-8555-555555555555", `{}`},
		{http.MethodPost, "/api/v1/workspaces/22222222-2222-4222-8222-222222222222/" +
			"asset-conflicts/66666666-6666-4666-8666-666666666666:resolve", `{}`},
	}
	for _, test := range tests {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable ||
			!strings.Contains(response.Body.String(), `"code":"asset_catalog_unavailable"`) {
			t.Errorf("%s %s = %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
}

type mainTestAuthenticator struct {
	principal authn.Principal
}

func (authenticator mainTestAuthenticator) Authenticate(*http.Request) (authn.Principal, error) {
	return authenticator.principal, nil
}
