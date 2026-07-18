package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/config"
	"github.com/seaworld008/aiops-system/internal/httpapi"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
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

func TestControlPlaneCMDBProfileAssemblyConsumesNeutralExactAdmission(t *testing.T) {
	closed, err := newSourceProfileAssembly(nil)
	if err != nil {
		t.Fatalf("newSourceProfileAssembly(nil) error = %v", err)
	}
	if closed.validationAdmission.Valid() {
		t.Fatal("disabled CMDB profile assembly opened validation")
	}
	if _, err := closed.registry.Resolve(sourceprofile.ExternalCMDBProfileSelector); !errors.Is(
		err, assetcatalog.ErrNotFound,
	) {
		t.Fatalf("disabled CMDB selector error = %v", err)
	}

	profileConfig := exactControlPlaneCMDBProfileConfig()
	assembly, err := newSourceProfileAssembly(profileConfig)
	if err != nil {
		t.Fatalf("newSourceProfileAssembly(exact) error = %v", err)
	}
	profile, err := assembly.registry.Resolve(sourceprofile.ExternalCMDBProfileSelector)
	if err != nil {
		t.Fatal(err)
	}
	if profile.SourceKind != assetcatalog.SourceKindExternalCMDB ||
		profile.ProviderKind != sourceprofile.ExternalCMDBV1().ProviderKind() ||
		profile.ProfileCode != sourceprofile.ExternalCMDBV1().ProfileCode() ||
		profile.IntegrationID != profileConfig.IntegrationID ||
		string(profile.CredentialReferenceID) != profileConfig.CredentialReferenceID ||
		string(profile.TrustReferenceID) != profileConfig.TrustReferenceID ||
		string(profile.NetworkPolicyReferenceID) != profileConfig.NetworkPolicyReferenceID ||
		!assembly.validationAdmission.Valid() ||
		assembly.validationAdmission.RuntimeManifestDigestSHA256() !=
			profileConfig.RuntimeAdmissionManifestSHA256 {
		t.Fatalf("CMDB profile assembly = profile:%#v admission:%#v", profile, assembly)
	}

	drifted := *profileConfig
	drifted.RuntimeAdmissionManifestJSON = []byte(strings.Replace(
		string(profileConfig.RuntimeAdmissionManifestJSON),
		sourceprofile.ExternalCMDBV1().DigestSHA256(),
		strings.Repeat("f", 64),
		1,
	))
	digest := sha256.Sum256(drifted.RuntimeAdmissionManifestJSON)
	drifted.RuntimeAdmissionManifestSHA256 = hex.EncodeToString(digest[:])
	if value, err := newSourceProfileAssembly(&drifted); err == nil ||
		value.validationAdmission.Valid() {
		t.Fatalf("newSourceProfileAssembly(drift) = (%#v, %v)", value, err)
	}
	endpointShaped := *profileConfig
	endpointShaped.CredentialReferenceID = "https://cmdb.invalid/token"
	if value, err := newSourceProfileAssembly(&endpointShaped); err == nil ||
		value.validationAdmission.Valid() {
		t.Fatalf("newSourceProfileAssembly(endpoint-shaped reference) = (%#v, %v)",
			value, err)
	}
}

func TestControlPlaneCMDBProfileImportBoundary(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list control-plane dependencies: %v\n%s", err, output)
	}
	dependencies := string(output)
	for _, forbidden := range []string{
		"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb",
		"github.com/seaworld008/aiops-system/internal/discoveryruntime",
		"github.com/seaworld008/aiops-system/internal/discoveryworker",
	} {
		if strings.Contains(dependencies, forbidden+"\n") {
			t.Errorf("control-plane production graph imports forbidden dependency %q", forbidden)
		}
	}
}

func exactControlPlaneCMDBProfileConfig() *config.ExternalCMDBProfileConfig {
	canonical := []byte(
		`{"schema_version":"discovery-worker-runtime-admission.v1","providers":[{"provider_kind":"CMDB_CATALOG_V1","profile_code":"CMDB_CATALOG_V1","canonical_descriptor_digest":"04a55074842e641d87ad67c42f1020b9b097ad15c3e781aaeffa3887837fdd08","runtime_recovery_capability_digest":"92f56dca945425f4129703183c71ba9c0aa08f47c3f8e8ec2ed6cdea2951f5aa"}]}`,
	)
	digest := sha256.Sum256(canonical)
	return &config.ExternalCMDBProfileConfig{
		IntegrationID:                  "40000000-0000-4000-8000-000000000211",
		CredentialReferenceID:          "50000000-0000-4000-8000-000000000211",
		TrustReferenceID:               "60000000-0000-4000-8000-000000000211",
		NetworkPolicyReferenceID:       "70000000-0000-4000-8000-000000000211",
		RuntimeAdmissionManifestJSON:   canonical,
		RuntimeAdmissionManifestSHA256: hex.EncodeToString(digest[:]),
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
