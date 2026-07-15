package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const parityManualManifestV1 = `{"backpressure_base_seconds":1,"backpressure_max_seconds":1,"compatibility_class":"MANUAL_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CATALOG_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":65536,"max_page_items":1,"max_page_relations":0,"network_mode":"NONE","parser_code":"MANUAL_ASSET_V1","profile_code":"MANUAL_V1","provider_kind":"MANUAL_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":[],"schedule_mode":"NONE","source_kind":"MANUAL","sync_mode":"MANUAL","trust_mode":"NONE","trusted_path_codes":["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
const parityManualProviderSchemaV1 = `{"additionalProperties":false,"properties":{},"type":"object"}`
const parityVictoriaManifestV1 = `{"backpressure_base_seconds":5,"backpressure_max_seconds":300,"compatibility_class":"VICTORIAMETRICS_OPERATOR_V1","credential_purpose":"KUBERNETES_DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CHECKPOINT_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":8388608,"max_page_items":500,"max_page_relations":2000,"network_mode":"REQUIRED","parser_code":"VICTORIAMETRICS_OPERATOR_ASSET_V1","profile_code":"VICTORIAMETRICS_OPERATOR_V1","provider_kind":"VICTORIAMETRICS_OPERATOR_V1","rate_limit_requests":100,"rate_limit_window_seconds":60,"relationship_types":["CONFIGURES","CONTAINS","MANAGED_BY","PRIMARY_RUNTIME_FOR"],"schedule_mode":"REQUIRED","source_kind":"KUBERNETES_OPERATOR","sync_mode":"SCHEDULED","trust_mode":"REQUIRED","trusted_path_codes":["VICTORIAMETRICS_OPERATOR_V1_API_VERSION","VICTORIAMETRICS_OPERATOR_V1_COMPATIBILITY_STATUS","VICTORIAMETRICS_OPERATOR_V1_CONDITIONS","VICTORIAMETRICS_OPERATOR_V1_CREDENTIAL_REFERENCE","VICTORIAMETRICS_OPERATOR_V1_DESIRED_REPLICAS","VICTORIAMETRICS_OPERATOR_V1_DISPLAY_NAME","VICTORIAMETRICS_OPERATOR_V1_EXTERNAL_ID","VICTORIAMETRICS_OPERATOR_V1_GENERATION","VICTORIAMETRICS_OPERATOR_V1_NAMESPACE_DIGEST","VICTORIAMETRICS_OPERATOR_V1_OBJECT_UID","VICTORIAMETRICS_OPERATOR_V1_PRODUCT_VERSION","VICTORIAMETRICS_OPERATOR_V1_READY_REPLICAS","VICTORIAMETRICS_OPERATOR_V1_RESOURCE_KIND","VICTORIAMETRICS_OPERATOR_V1_TAXONOMY_CLASS"],"typed_extension_code":"VICTORIAMETRICS_OPERATOR_V1","version":"asset-source-profile-manifest.v1"}`
const parityVictoriaProviderSchemaV1 = `{"additionalProperties":false,"properties":{"api_version":{"maxLength":64,"minLength":1,"type":"string"},"conditions":{"items":{"additionalProperties":false,"properties":{"status":{"enum":["False","True","Unknown"]},"type":{"enum":["Available","Degraded","Progressing","Ready"]}},"required":["status","type"],"type":"object"},"maxItems":4,"type":"array"},"credential_reference":{"pattern":"^vmuser-credential-v1-[a-f0-9]{64}$","type":"string"},"desired_replicas":{"minimum":0,"type":"integer"},"generation":{"minimum":0,"type":"integer"},"namespace_digest":{"pattern":"^[a-f0-9]{64}$","type":"string"},"object_uid":{"maxLength":128,"minLength":1,"type":"string"},"product_version":{"maxLength":128,"minLength":1,"type":"string"},"ready_replicas":{"minimum":0,"type":"integer"},"resource_kind":{"maxLength":64,"minLength":1,"type":"string"},"taxonomy_class":{"maxLength":64,"minLength":1,"type":"string"}},"required":["api_version","generation","namespace_digest","object_uid","resource_kind","taxonomy_class"],"type":"object"}`
const parityAWXManifestV1 = `{"backpressure_base_seconds":5,"backpressure_max_seconds":300,"compatibility_class":"AWX_READ_V1","credential_purpose":"READ_AUTOMATION","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_TIME_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":16384,"max_page_bytes":1048576,"max_page_items":200,"max_page_relations":0,"network_mode":"REQUIRED","parser_code":"AWX_INVENTORY_HOST_V1","profile_code":"AWX_READ_V1","provider_kind":"AWX_API","rate_limit_requests":60,"rate_limit_window_seconds":60,"relationship_types":[],"schedule_mode":"REQUIRED","source_kind":"AWX_INVENTORY","sync_mode":"SCHEDULED","trust_mode":"REQUIRED","trusted_path_codes":["AWX_READ_V1_ASSET_KIND","AWX_READ_V1_DISPLAY_NAME","AWX_READ_V1_ENABLED","AWX_READ_V1_EXTERNAL_ID","AWX_READ_V1_INVENTORY_REFERENCE","AWX_READ_V1_PROVIDER_MODIFIED_AT"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`
const parityAWXProviderSchemaV1 = `{"additionalProperties":false,"properties":{"asset_kind":{"enum":["BARE_METAL_HOST","LINUX_VM","WINDOWS_VM"]},"display_name":{"maxLength":256,"minLength":1,"type":"string"},"enabled":{"type":"boolean"},"inventory_reference":{"pattern":"^awx-inventory-v1-[a-f0-9]{64}$","type":"string"},"provider_modified_at":{"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z$","type":"string"}},"required":["asset_kind","display_name","enabled","inventory_reference","provider_modified_at"],"type":"object"}`

func TestBindingDigestParityWithPostgreSQL18Framing(t *testing.T) {
	if strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN")) == "" {
		t.Fatal("AIOPS_TEST_POSTGRES_DSN is required; BindingDigest parity may not skip the real PostgreSQL 18.4 harness")
	}
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	t.Run("authority scope", func(t *testing.T) {
		environments := []string{
			"77777777-7777-4777-8777-777777777777",
			"44444444-4444-4444-8444-444444444444",
		}
		frames := [][]byte{
			[]byte("asset-source-authority-scope.v1"), []byte("2"),
			[]byte(environments[1]), []byte(environments[0]),
		}
		assertPostgresFramedTuple(t, harness.application, frames, 0, "", func(sqlDigest string) {
			goDigest, err := assetcatalog.AuthorityScopeDigest(environments)
			if err != nil || goDigest != sqlDigest {
				t.Fatalf("AuthorityScopeDigest() = (%q, %v), PostgreSQL = %q", goDigest, err, sqlDigest)
			}
		})
	})

	definitionFixtures := []struct {
		name, sourceKind, providerKind, profileCode string
		manifest, providerSchema                    string
		manifestLength, schemaLength, framedLength  int
		manifestDigest, schemaDigest, definition    string
		revision                                    assetcatalog.SourceRevision
	}{
		{
			"manual", "MANUAL", "MANUAL_V1", "MANUAL_V1", parityManualManifestV1, parityManualProviderSchemaV1,
			794, 62, 144, "57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96", "99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa", "7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c",
			assetcatalog.SourceRevision{
				SyncMode: assetcatalog.SyncMode("MANUAL"), AuthorityEnvironmentIDs: []string{"44444444-4444-4444-8444-444444444444"},
				RateLimitRequests: 1, RateLimitWindowSeconds: 1, BackpressureBaseSeconds: 1, BackpressureMaxSeconds: 1,
			},
		},
		{
			"VictoriaMetrics Operator", "KUBERNETES_OPERATOR", "VICTORIAMETRICS_OPERATOR_V1", "VICTORIAMETRICS_OPERATOR_V1", parityVictoriaManifestV1, parityVictoriaProviderSchemaV1,
			1573, 1026, 193, "fcfbd34fa6678a7eb98694327949e49cc0809111c5273c9b130c4fa230c49132", "c9e7d80a6ee64ef4f1d999894d3df5aba312a0a38cc539afd1d4c5f86273d8a1", "fe6a235ff65e962bc3520cd62165da630416b0fd90a85e3c8bec00c80c192b7f",
			assetcatalog.SourceRevision{
				SyncMode: assetcatalog.SyncMode("SCHEDULED"), AuthorityEnvironmentIDs: []string{"44444444-4444-4444-8444-444444444444"},
				CredentialReferenceID: "cred-ref-v1", TrustReferenceID: "trust-ref-v1", NetworkPolicyReferenceID: "network-ref-v1",
				RateLimitRequests: 100, RateLimitWindowSeconds: 60, BackpressureBaseSeconds: 5, BackpressureMaxSeconds: 300,
				ScheduleExpression: "0 */5 * * * *", TypedExtensionCode: "VICTORIAMETRICS_OPERATOR_V1", PreparedExtensionDigest: strings.Repeat("a", 64),
			},
		},
		{
			"AWX inventory", "AWX_INVENTORY", "AWX_API", "AWX_READ_V1", parityAWXManifestV1, parityAWXProviderSchemaV1,
			954, 520, 151, "4f02470a1d0ce77867b1319ba202880e0e8d79f5a5740af34de3b6131f86f792", "2600fd15bc9ff6ab9b839fe46ac476d801a8c41c8740de9cc0958a9bfc843ad5", "af073d77f4ecd7b0191ccdb18e9cba6e95abec0774dff81dc9f5f33451f5e84f",
			assetcatalog.SourceRevision{
				SyncMode: assetcatalog.SyncMode("SCHEDULED"), AuthorityEnvironmentIDs: []string{"44444444-4444-4444-8444-444444444444"},
				IntegrationID: "44444444-4444-4444-8444-444444444444", CredentialReferenceID: "cred-ref-v1", TrustReferenceID: "trust-ref-v1", NetworkPolicyReferenceID: "network-ref-v1",
				RateLimitRequests: 60, RateLimitWindowSeconds: 60, BackpressureBaseSeconds: 5, BackpressureMaxSeconds: 300,
				ScheduleExpression: "0 */5 * * * *",
			},
		},
	}
	for _, fixture := range definitionFixtures {
		fixture := fixture
		t.Run(fixture.name+" source definition", func(t *testing.T) {
			if len(fixture.manifest) != fixture.manifestLength || len(fixture.providerSchema) != fixture.schemaLength {
				t.Fatalf("fixture bytes = manifest %d/schema %d, want %d/%d", len(fixture.manifest), len(fixture.providerSchema), fixture.manifestLength, fixture.schemaLength)
			}
			frames := [][]byte{
				[]byte("asset-source-definition.v2"), []byte(fixture.sourceKind), []byte(fixture.providerKind), []byte(fixture.profileCode),
				mustDecodeParityHex(t, fixture.manifestDigest), mustDecodeParityHex(t, fixture.schemaDigest),
			}
			assertPostgresFramedTuple(t, harness.application, frames, fixture.framedLength, fixture.definition, func(sqlDigest string) {
				source := assetcatalog.Source{Kind: assetcatalog.SourceKind(fixture.sourceKind), ProviderKind: fixture.providerKind}
				revision := fixture.revision
				revision.ProfileCode = assetcatalog.ProfileCode(fixture.profileCode)
				revision.CanonicalProfileManifest = []byte(fixture.manifest)
				revision.CanonicalProviderSchema = []byte(fixture.providerSchema)
				revision.ProfileManifestSHA256 = strings.Repeat("f", 64)
				revision.CanonicalProviderSchemaSHA256 = strings.Repeat("e", 64)
				goDigest, err := assetcatalog.SourceDefinitionDigest(source, revision)
				if err != nil || goDigest != sqlDigest {
					t.Fatalf("SourceDefinitionDigest() = (%q, %v), PostgreSQL = %q", goDigest, err, sqlDigest)
				}
			})
		})
	}

	t.Run("all optional values present", func(t *testing.T) {
		frames, revision := presentBindingParityFixture()
		assertPostgresFramedTuple(t, harness.application, frames, 495, "49f8013b8e3cccdcbeb1d125915b2bf424815306494318ee2d3b7e298f3f6b74", func(sqlDigest string) {
			if goDigest := revision.BindingDigest(); goDigest != sqlDigest {
				t.Fatalf("present BindingDigest() = %q, PostgreSQL = %q", goDigest, sqlDigest)
			}
			if functionDigest := postgresBindingDigest(t, harness.application, revision); functionDigest != sqlDigest {
				t.Fatalf("asset_catalog_source_revision_binding_digest() = %q, framed SQL = %q", functionDigest, sqlDigest)
			}
		})
	})

	t.Run("SQL NULL optional values", func(t *testing.T) {
		frames, revision := manualBindingParityFixture()
		for _, index := range []int{6, 8, 9, 10, 17, 18, 19} {
			if frames[index] != nil {
				t.Fatalf("frame %d must be SQL NULL, got present-empty", index+1)
			}
		}
		assertPostgresFramedTuple(t, harness.application, frames, 296, "88965ba68eb1d6450b1252a0a261bfaa282556e0ec569b6db2c0153d235912b5", func(sqlDigest string) {
			if goDigest := revision.BindingDigest(); goDigest != sqlDigest {
				t.Fatalf("manual BindingDigest() = %q, PostgreSQL = %q", goDigest, sqlDigest)
			}
			if functionDigest := postgresBindingDigest(t, harness.application, revision); functionDigest != sqlDigest {
				t.Fatalf("asset_catalog_source_revision_binding_digest() = %q, framed SQL = %q", functionDigest, sqlDigest)
			}
		})
	})
}

func postgresBindingDigest(t *testing.T, pool *pgxpool.Pool, revision assetcatalog.SourceRevision) string {
	t.Helper()
	optional := func(value string) any {
		if value == "" {
			return nil
		}
		return value
	}
	document, err := json.Marshal(map[string]any{
		"tenant_id": revision.TenantID, "workspace_id": revision.WorkspaceID, "source_id": revision.SourceID,
		"revision": revision.Revision, "source_definition_digest": revision.SourceDefinitionDigest,
		"integration_id": optional(revision.IntegrationID), "sync_mode": revision.SyncMode,
		"credential_reference_id":     optional(string(revision.CredentialReferenceID)),
		"trust_reference_id":          optional(string(revision.TrustReferenceID)),
		"network_policy_reference_id": optional(string(revision.NetworkPolicyReferenceID)),
		"authority_scope_digest":      revision.AuthorityScopeDigest,
		"rate_limit_requests":         revision.RateLimitRequests, "rate_limit_window_seconds": revision.RateLimitWindowSeconds,
		"backpressure_base_seconds": revision.BackpressureBaseSeconds, "backpressure_max_seconds": revision.BackpressureMaxSeconds,
		"profile_code": revision.ProfileCode, "schedule_expression": optional(revision.ScheduleExpression),
		"typed_extension_code": optional(string(revision.TypedExtensionCode)), "prepared_extension_digest": optional(revision.PreparedExtensionDigest),
	})
	if err != nil {
		t.Fatalf("encode PostgreSQL binding composite fixture: %v", err)
	}
	var digest string
	if err := pool.QueryRow(context.Background(), `
SELECT public.asset_catalog_source_revision_binding_digest(
    pg_catalog.json_populate_record(NULL::public.asset_source_revisions, $1::json)
)`, string(document)).Scan(&digest); err != nil {
		t.Fatalf("execute Task 1 binding digest function: %v", err)
	}
	return digest
}

func assertPostgresFramedTuple(t *testing.T, pool *pgxpool.Pool, frames [][]byte, goldenLength int, goldenDigest string, compareGo func(string)) {
	t.Helper()
	wantBytes := parityFramedTuple(frames)
	wantDigestArray := sha256.Sum256(wantBytes)
	wantDigest := hex.EncodeToString(wantDigestArray[:])
	if goldenLength > 0 && len(wantBytes) != goldenLength {
		t.Fatalf("independent framed length = %d, want %d", len(wantBytes), goldenLength)
	}
	if goldenDigest != "" && wantDigest != goldenDigest {
		t.Fatalf("independent framed digest = %q, want %q", wantDigest, goldenDigest)
	}

	query := strings.Builder{}
	query.WriteString("SELECT framed.tuple, pg_catalog.encode(pg_catalog.sha256(framed.tuple), 'hex') FROM (SELECT ")
	arguments := make([]any, len(frames))
	for index, frame := range frames {
		if index > 0 {
			query.WriteString(" || ")
		}
		query.WriteString("public.asset_catalog_framed_value_v1($")
		query.WriteString(strconv.Itoa(index + 1))
		query.WriteString("::bytea)")
		arguments[index] = frame
	}
	query.WriteString(" AS tuple) AS framed")
	var sqlBytes []byte
	var sqlDigest string
	if err := pool.QueryRow(context.Background(), query.String(), arguments...).Scan(&sqlBytes, &sqlDigest); err != nil {
		t.Fatalf("execute PostgreSQL framed tuple oracle: %v", err)
	}
	if !bytes.Equal(sqlBytes, wantBytes) {
		t.Fatalf("PostgreSQL framed bytes differ: got length %d, want %d", len(sqlBytes), len(wantBytes))
	}
	if sqlDigest != wantDigest {
		t.Fatalf("PostgreSQL framed digest = %q, want %q", sqlDigest, wantDigest)
	}
	compareGo(sqlDigest)
}

func presentBindingParityFixture() ([][]byte, assetcatalog.SourceRevision) {
	definition := bytes.Repeat([]byte{0x11}, 32)
	authority := bytes.Repeat([]byte{0x22}, 32)
	extension := bytes.Repeat([]byte{0x33}, 32)
	frames := [][]byte{
		[]byte("asset-source-revision-binding.v1"),
		[]byte("11111111-1111-4111-8111-111111111111"), []byte("22222222-2222-4222-8222-222222222222"), []byte("33333333-3333-4333-8333-333333333333"),
		[]byte("7"), definition, []byte("44444444-4444-4444-8444-444444444444"), []byte("SCHEDULED"),
		[]byte("cred-ref-v1"), []byte("trust-ref-v1"), []byte("network-ref-v1"), authority,
		[]byte("100"), []byte("60"), []byte("5"), []byte("300"), []byte("VICTORIAMETRICS_OPERATOR_V1"),
		[]byte("0 */5 * * * *"), []byte("VICTORIAMETRICS_OPERATOR_V1"), extension,
	}
	revision := assetcatalog.SourceRevision{
		TenantID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222", SourceID: "33333333-3333-4333-8333-333333333333", Revision: 7,
		SourceDefinitionDigest: hex.EncodeToString(definition), IntegrationID: "44444444-4444-4444-8444-444444444444", SyncMode: assetcatalog.SyncMode("SCHEDULED"),
		CredentialReferenceID: assetcatalog.CredentialReferenceID("cred-ref-v1"), TrustReferenceID: assetcatalog.TrustReferenceID("trust-ref-v1"), NetworkPolicyReferenceID: assetcatalog.NetworkPolicyReferenceID("network-ref-v1"),
		AuthorityScopeDigest: hex.EncodeToString(authority), RateLimitRequests: 100, RateLimitWindowSeconds: 60, BackpressureBaseSeconds: 5, BackpressureMaxSeconds: 300,
		ProfileCode: assetcatalog.ProfileCode("VICTORIAMETRICS_OPERATOR_V1"), ScheduleExpression: "0 */5 * * * *", TypedExtensionCode: assetcatalog.ExtensionCode("VICTORIAMETRICS_OPERATOR_V1"), PreparedExtensionDigest: hex.EncodeToString(extension),
	}
	return frames, revision
}

func manualBindingParityFixture() ([][]byte, assetcatalog.SourceRevision) {
	definition := bytes.Repeat([]byte{0xaa}, 32)
	authority := bytes.Repeat([]byte{0xbb}, 32)
	frames := [][]byte{
		[]byte("asset-source-revision-binding.v1"),
		[]byte("11111111-1111-4111-8111-111111111111"), []byte("22222222-2222-4222-8222-222222222222"), []byte("33333333-3333-4333-8333-333333333333"),
		[]byte("1"), definition, nil, []byte("MANUAL"), nil, nil, nil, authority,
		[]byte("1"), []byte("1"), []byte("1"), []byte("1"), []byte("MANUAL_V1"), nil, nil, nil,
	}
	revision := assetcatalog.SourceRevision{
		TenantID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222", SourceID: "33333333-3333-4333-8333-333333333333", Revision: 1,
		SourceDefinitionDigest: hex.EncodeToString(definition), SyncMode: assetcatalog.SyncMode("MANUAL"), AuthorityScopeDigest: hex.EncodeToString(authority),
		RateLimitRequests: 1, RateLimitWindowSeconds: 1, BackpressureBaseSeconds: 1, BackpressureMaxSeconds: 1, ProfileCode: assetcatalog.ProfileCode("MANUAL_V1"),
	}
	return frames, revision
}

func parityFramedTuple(frames [][]byte) []byte {
	result := make([]byte, 0)
	for _, frame := range frames {
		if frame == nil {
			result = append(result, 0)
			continue
		}
		result = append(result, 1)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(frame)))
		result = append(result, length[:]...)
		result = append(result, frame...)
	}
	return result
}

func mustDecodeParityHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode parity fixture: %v", err)
	}
	return decoded
}
