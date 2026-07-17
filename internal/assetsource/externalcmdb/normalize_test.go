package externalcmdb

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

const normalizeTestEnvironmentID = "44444444-4444-4444-8444-444444444444"

func TestNormalizeAssetUsesClosedMappingExactFreshnessAndProvenance(t *testing.T) {
	t.Parallel()

	updatedAt := time.Date(2026, 7, 17, 9, 30, 0, 123456000, time.UTC)
	got, err := normalizeAsset(normalizeTestEnvironmentID, catalogAsset{
		ExternalID:     "vm-0001",
		TypeCode:       "LINUX_VM",
		DisplayName:    "payments-api-01",
		ObjectRevision: 7,
		UpdatedAt:      updatedAt,
		Attributes: map[string]string{
			"cpu_count":  "4",
			"os_version": "24.04",
		},
	})
	if err != nil {
		t.Fatalf("normalizeAsset() error = %v", err)
	}
	if got.EnvironmentID != normalizeTestEnvironmentID ||
		got.ProviderKind != providerKind ||
		got.ExternalID != "vm-0001" ||
		got.Kind != assetcatalog.KindLinuxVM ||
		got.DisplayName != "payments-api-01" {
		t.Fatalf("normalized identity = %#v", got)
	}
	if got.Freshness.Kind != assetcatalog.FreshnessObjectTimeSequence ||
		got.Freshness.OrderTime == nil ||
		!got.Freshness.OrderTime.Equal(updatedAt) ||
		got.Freshness.OrderSequence != 7 ||
		got.Freshness.ProviderVersionSHA256 != independentVersionDigest("cmdb-object-version.v1", 7) {
		t.Fatalf("freshness = %#v", got.Freshness)
	}
	wantProvenance := []assetdiscovery.FieldProvenance{
		{FieldCode: "display_name", ProviderPathCode: "CMDB_V1_DISPLAY_NAME", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "environment_id", ProviderPathCode: "CMDB_V1_ENVIRONMENT_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "external_id", ProviderPathCode: "CMDB_V1_EXTERNAL_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "kind", ProviderPathCode: "CMDB_V1_KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "provider_kind", ProviderPathCode: "CMDB_V1_PROVIDER_KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		{FieldCode: "type_details", ProviderPathCode: "CMDB_V1_TYPE_DETAILS", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
	}
	if len(got.FieldProvenance) != len(wantProvenance) {
		t.Fatalf("provenance count = %d", len(got.FieldProvenance))
	}
	for index := range wantProvenance {
		if got.FieldProvenance[index] != wantProvenance[index] {
			t.Fatalf("provenance[%d] = %#v, want %#v", index, got.FieldProvenance[index], wantProvenance[index])
		}
	}
}

func TestNormalizeAssetRejectsUnknownTypeAndDLP(t *testing.T) {
	t.Parallel()

	secretLike := "sk-" + strings.Repeat("a", 20)
	tests := []struct {
		name           string
		mutate         func(*catalogAsset)
		forbidden      string
		wantSchemaCode string
	}{
		{
			name: "unknown type",
			mutate: func(asset *catalogAsset) {
				asset.TypeCode = "ROUTER"
			},
		},
		{
			name: "secret attribute name",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"api_token": "redacted"}
			},
		},
		{
			name: "secret attribute value",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": secretLike}
			},
			forbidden: secretLike,
		},
		{
			name: "URL attribute value",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": "https://db.internal:5432"}
			},
			forbidden:      "db.internal:5432",
			wantSchemaCode: "DLP_REJECTED",
		},
		{
			name: "DSN attribute value",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": "host=db.internal port=5432"}
			},
			forbidden:      "db.internal",
			wantSchemaCode: "DLP_REJECTED",
		},
		{
			name: "JDBC Oracle thin DSN",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": "jdbc:oracle:thin:@db.internal:1521/prod"}
			},
			forbidden:      "db.internal:1521",
			wantSchemaCode: "DLP_REJECTED",
		},
		{
			name: "mixed-case JDBC Derby DSN",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": "JDBC:Derby:memory:inventory;create=true"}
			},
			forbidden:      "JDBC:Derby",
			wantSchemaCode: "DLP_REJECTED",
		},
		{
			name: "authority userinfo with password",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": "readonly:s3cret@db.internal:5432"}
			},
			forbidden:      "readonly:s3cret",
			wantSchemaCode: "DLP_REJECTED",
		},
		{
			name: "authority userinfo without password",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": "readonly@db.internal:5432"}
			},
			forbidden:      "readonly@db.internal",
			wantSchemaCode: "DLP_REJECTED",
		},
		{
			name: "formula display name",
			mutate: func(asset *catalogAsset) {
				asset.DisplayName = "=HYPERLINK(\"https://example.invalid\")"
			},
		},
		{
			name: "formula attribute value",
			mutate: func(asset *catalogAsset) {
				asset.Attributes = map[string]string{"hostname": "@SUM(1,1)"}
			},
		},
		{
			name: "html script shape",
			mutate: func(asset *catalogAsset) {
				asset.DisplayName = "<script>alert(1)</script>"
			},
		},
		{
			name: "sub-microsecond freshness",
			mutate: func(asset *catalogAsset) {
				asset.UpdatedAt = asset.UpdatedAt.Add(time.Nanosecond)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			asset := validCatalogAsset()
			test.mutate(&asset)
			if test.wantSchemaCode != "" {
				if got := validateCatalogAssetSchema(asset, 64<<10); got != test.wantSchemaCode {
					t.Fatalf("validateCatalogAssetSchema() = %q, want %q", got, test.wantSchemaCode)
				}
			}
			got, err := normalizeAsset(normalizeTestEnvironmentID, asset)
			if err == nil {
				t.Fatalf("normalizeAsset() = %#v, want rejection", got)
			}
			if test.forbidden != "" && strings.Contains(err.Error(), test.forbidden) {
				t.Fatalf("error leaked rejected payload: %v", err)
			}
		})
	}
}

func TestEndpointDLPAllowsOrdinarySafeText(t *testing.T) {
	t.Parallel()

	asset := validCatalogAsset()
	asset.ExternalID = "opaque:id.with-dots-01@tenant"
	asset.DisplayName = "payments-api.prod - maintenance 09:30"
	asset.Attributes = map[string]string{
		"hostname": "db.internal",
		"name":     "ops@example.internal",
		"version":  "2026.07-rc1",
	}
	if got, err := normalizeAsset(normalizeTestEnvironmentID, asset); err != nil {
		t.Fatalf("ordinary safe text rejected: %v", err)
	} else if got.ExternalID != asset.ExternalID || got.DisplayName != asset.DisplayName {
		t.Fatalf("ordinary safe text drifted: %#v", got)
	}
}

func TestNormalizeTombstoneEmitsIdentityFreshnessAndProvenanceOnly(t *testing.T) {
	t.Parallel()

	asset := validCatalogAsset()
	asset.Deleted = true
	asset.TombstoneReason = "SOURCE_DELETED"
	got, err := normalizeAsset(normalizeTestEnvironmentID, asset)
	if err != nil {
		t.Fatalf("normalizeAsset() error = %v", err)
	}
	if !got.Tombstone || got.TombstoneReason != "SOURCE_DELETED" {
		t.Fatalf("tombstone = %#v", got)
	}
	if got.Kind != "" || got.DisplayName != "" || got.SchemaVersion != "" ||
		len(got.Document) != 0 || got.DocumentSHA256 != "" || len(got.Fingerprints) != 0 {
		t.Fatalf("tombstone leaked live fields: %#v", got)
	}
	if len(got.FieldProvenance) != 3 {
		t.Fatalf("tombstone provenance = %#v", got.FieldProvenance)
	}

	asset.Attributes = map[string]string{"unapproved_metadata": "value"}
	if got, err := normalizeAsset(normalizeTestEnvironmentID, asset); err == nil {
		t.Fatalf("tombstone with non-allow-list attributes = %#v, want rejection", got)
	}

	tests := []struct {
		name   string
		mutate func(*catalogAsset)
	}{
		{
			name: "unknown type",
			mutate: func(value *catalogAsset) {
				value.TypeCode = "ROUTER"
			},
		},
		{
			name: "oversized display name",
			mutate: func(value *catalogAsset) {
				value.DisplayName = strings.Repeat("a", 257)
			},
		},
		{
			name: "control character display name",
			mutate: func(value *catalogAsset) {
				value.DisplayName = "unsafe\nname"
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			value := validCatalogAsset()
			value.Deleted = true
			value.TombstoneReason = "SOURCE_DELETED"
			test.mutate(&value)
			if got, err := normalizeAsset(normalizeTestEnvironmentID, value); err == nil {
				t.Fatalf("invalid tombstone = %#v, want rejection", got)
			}
		})
	}
}

func TestNormalizeRelationRejectsUnknownTypeAndUsesClosedPath(t *testing.T) {
	t.Parallel()

	relation := catalogRelation{
		ExternalID:     "rel-0001",
		FromExternalID: "vm-0001",
		ToExternalID:   "service-0001",
		TypeCode:       "DEPENDS_ON",
		ObjectRevision: 11,
		UpdatedAt:      time.Date(2026, 7, 17, 9, 30, 0, 654321000, time.UTC),
	}
	got, err := normalizeRelation(normalizeTestEnvironmentID, relation)
	if err != nil {
		t.Fatalf("normalizeRelation() error = %v", err)
	}
	if got.Type != assetcatalog.RelationshipDependsOn ||
		got.ProviderPathCode != "CMDB_V1_RELATION" ||
		got.Freshness.ProviderVersionSHA256 != independentVersionDigest("cmdb-relation-version.v1", 11) {
		t.Fatalf("normalized relation = %#v", got)
	}

	relation.TypeCode = "CONNECTED_TO"
	if got, err := normalizeRelation(normalizeTestEnvironmentID, relation); err == nil {
		t.Fatalf("normalizeRelation() = %#v, want unknown-type rejection", got)
	}

	relation.TypeCode = "DEPENDS_ON"
	relation.FromExternalID = "db.internal:5432"
	if got, err := normalizeRelation(normalizeTestEnvironmentID, relation); err == nil {
		t.Fatalf("endpoint-shaped relation = %#v, want rejection", got)
	} else if strings.Contains(err.Error(), relation.FromExternalID) {
		t.Fatalf("relation rejection leaked endpoint: %v", err)
	}
}

func validCatalogAsset() catalogAsset {
	return catalogAsset{
		ExternalID:     "vm-0001",
		TypeCode:       "LINUX_VM",
		DisplayName:    "payments-api-01",
		ObjectRevision: 7,
		UpdatedAt:      time.Date(2026, 7, 17, 9, 30, 0, 123456000, time.UTC),
		Attributes:     map[string]string{"hostname": "payments-api-01"},
	}
}

func independentVersionDigest(domain string, revision int64) string {
	hasher := sha256.New()
	var length [4]byte
	for _, value := range []string{domain, strconv.FormatInt(revision, 10)} {
		_, _ = hasher.Write([]byte{1})
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(value))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
