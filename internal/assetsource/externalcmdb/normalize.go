package externalcmdb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

const normalizedSchemaVersion = "CMDB_CATALOG_V1"

var errNormalization = errors.New("external cmdb normalization rejected")

func normalizeAsset(environmentID string, asset catalogAsset) (assetdiscovery.NormalizedItem, error) {
	if !canonicalUUIDPattern.MatchString(environmentID) {
		return assetdiscovery.NormalizedItem{}, normalizationError("AUTHORITY_REJECTED")
	}
	switch validateCatalogAssetSchema(asset, 64<<10) {
	case "":
	case "DLP_REJECTED":
		return assetdiscovery.NormalizedItem{}, normalizationError("DLP_REJECTED")
	default:
		return assetdiscovery.NormalizedItem{}, normalizationError("SCHEMA_REJECTED")
	}
	orderTime, err := normalizedFreshnessTime(asset.UpdatedAt)
	if err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	freshness := assetdiscovery.FreshnessCandidate{
		Kind:                  assetcatalog.FreshnessObjectTimeSequence,
		OrderTime:             &orderTime,
		OrderSequence:         asset.ObjectRevision,
		ProviderVersionSHA256: digestFramedTuple("cmdb-object-version.v1", strconv.FormatInt(asset.ObjectRevision, 10)),
	}

	if asset.Deleted {
		item := assetdiscovery.NormalizedItem{
			EnvironmentID:   environmentID,
			ProviderKind:    providerKind,
			ExternalID:      asset.ExternalID,
			Freshness:       freshness,
			Tombstone:       true,
			TombstoneReason: asset.TombstoneReason,
			FieldProvenance: tombstoneProvenance(),
		}
		if err := validateNormalizedItem(item, nil); err != nil {
			return assetdiscovery.NormalizedItem{}, err
		}
		return item, nil
	}

	kind, ok := catalogAssetKind(asset.TypeCode)
	if !ok {
		return assetdiscovery.NormalizedItem{}, normalizationError("TYPE_CODE_REJECTED")
	}
	attributes, attributeCodes, err := normalizeAttributes(asset.Attributes)
	if err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	document, err := canonicalAttributesDocument(attributes)
	if err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	documentDigest := sha256.Sum256(document)
	item := assetdiscovery.NormalizedItem{
		EnvironmentID:   environmentID,
		ProviderKind:    providerKind,
		ExternalID:      asset.ExternalID,
		Kind:            kind,
		DisplayName:     asset.DisplayName,
		SchemaVersion:   normalizedSchemaVersion,
		Document:        document,
		DocumentSHA256:  hex.EncodeToString(documentDigest[:]),
		Freshness:       freshness,
		FieldProvenance: liveAssetProvenance(),
		Fingerprints:    map[string]string{"provider_instance_id": asset.ExternalID},
	}
	if err := validateNormalizedItem(item, attributeCodes); err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	return item, nil
}

func normalizeRelation(
	environmentID string,
	relation catalogRelation,
) (assetdiscovery.ObservedRelation, error) {
	if !canonicalUUIDPattern.MatchString(environmentID) ||
		!safeText(relation.ExternalID, 1, 512) ||
		!safeText(relation.FromExternalID, 1, 512) ||
		!safeText(relation.ToExternalID, 1, 512) ||
		relation.FromExternalID == relation.ToExternalID ||
		relation.ObjectRevision <= 0 ||
		relation.Deleted {
		return assetdiscovery.ObservedRelation{}, normalizationError("RELATION_SCHEMA_REJECTED")
	}
	if unsafeCatalogText(relation.ExternalID) ||
		unsafeCatalogText(relation.FromExternalID) ||
		unsafeCatalogText(relation.ToExternalID) {
		return assetdiscovery.ObservedRelation{}, normalizationError("DLP_REJECTED")
	}
	relationType, ok := catalogRelationshipType(relation.TypeCode)
	if !ok {
		return assetdiscovery.ObservedRelation{}, normalizationError("RELATION_TYPE_REJECTED")
	}
	orderTime, err := normalizedFreshnessTime(relation.UpdatedAt)
	if err != nil {
		return assetdiscovery.ObservedRelation{}, err
	}
	normalized := assetdiscovery.ObservedRelation{
		SourceEnvironmentID: environmentID,
		TargetEnvironmentID: environmentID,
		FromExternalID:      relation.FromExternalID,
		ToExternalID:        relation.ToExternalID,
		Type:                relationType,
		ProviderPathCode:    "CMDB_V1_RELATION",
		Confidence:          100,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:                  assetcatalog.FreshnessObjectTimeSequence,
			OrderTime:             &orderTime,
			OrderSequence:         relation.ObjectRevision,
			ProviderVersionSHA256: digestFramedTuple("cmdb-relation-version.v1", strconv.FormatInt(relation.ObjectRevision, 10)),
		},
	}
	policy := normalizedFactPolicy(environmentID, nil)
	policy.RelationshipTypes = []assetcatalog.RelationshipType{relationType}
	if err := assetdiscovery.ValidateFacts(nil, []assetdiscovery.ObservedRelation{normalized}, policy); err != nil {
		return assetdiscovery.ObservedRelation{}, normalizationError("RELATION_FACT_REJECTED")
	}
	return normalized, nil
}

func catalogAssetKind(typeCode string) (assetcatalog.Kind, bool) {
	switch typeCode {
	case "SERVICE":
		return assetcatalog.KindService, true
	case "LINUX_VM":
		return assetcatalog.KindLinuxVM, true
	case "WINDOWS_VM":
		return assetcatalog.KindWindowsVM, true
	case "BARE_METAL_HOST":
		return assetcatalog.KindBareMetalHost, true
	case "KUBERNETES_CLUSTER":
		return assetcatalog.KindKubernetesCluster, true
	case "KUBERNETES_NAMESPACE":
		return assetcatalog.KindKubernetesNamespace, true
	case "KUBERNETES_WORKLOAD":
		return assetcatalog.KindKubernetesWorkload, true
	case "DATABASE_INSTANCE":
		return assetcatalog.KindDatabaseInstance, true
	case "DATABASE":
		return assetcatalog.KindDatabase, true
	case "METRICS_SOURCE":
		return assetcatalog.KindMetricsSource, true
	case "LOG_SOURCE":
		return assetcatalog.KindLogSource, true
	case "TRACE_SOURCE":
		return assetcatalog.KindTraceSource, true
	case "AWX_INVENTORY":
		return assetcatalog.KindAWXInventory, true
	case "ARGO_APPLICATION":
		return assetcatalog.KindArgoApplication, true
	case "CI_PIPELINE":
		return assetcatalog.KindCIPipeline, true
	case "GIT_REPOSITORY":
		return assetcatalog.KindGitRepository, true
	case "CLOUD_RESOURCE":
		return assetcatalog.KindCloudResource, true
	default:
		return "", false
	}
}

func catalogRelationshipType(typeCode string) (assetcatalog.RelationshipType, bool) {
	switch typeCode {
	case "RUNS_ON":
		return assetcatalog.RelationshipRunsOn, true
	case "CONTAINS":
		return assetcatalog.RelationshipContains, true
	case "DEPENDS_ON":
		return assetcatalog.RelationshipDependsOn, true
	case "MONITORED_BY":
		return assetcatalog.RelationshipMonitoredBy, true
	case "LOGS_TO":
		return assetcatalog.RelationshipLogsTo, true
	case "TRACES_TO":
		return assetcatalog.RelationshipTracesTo, true
	case "DELIVERED_BY":
		return assetcatalog.RelationshipDeliveredBy, true
	case "MANAGED_BY":
		return assetcatalog.RelationshipManagedBy, true
	case "PRIMARY_RUNTIME_FOR":
		return assetcatalog.RelationshipPrimaryRuntimeFor, true
	default:
		return "", false
	}
}

func normalizeAttributes(values map[string]string) (map[string]string, []string, error) {
	normalized := make(map[string]string, len(values))
	codes := make([]string, 0, len(values))
	for code, value := range values {
		if !allowedAttributeCode(code) {
			return nil, nil, normalizationError("ATTRIBUTE_CODE_REJECTED")
		}
		if unsafeCatalogText(value) {
			return nil, nil, normalizationError("DLP_REJECTED")
		}
		normalized[code] = value
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return normalized, codes, nil
}

func allowedAttributeCode(code string) bool {
	switch code {
	case "architecture", "cluster_name", "cpu_count", "database_engine", "hostname",
		"memory_mb", "name", "os_name", "os_version", "region", "resource_class",
		"runtime", "version", "zone":
		return true
	default:
		return false
	}
}

func canonicalAttributesDocument(attributes map[string]string) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(attributes); err != nil {
		return nil, normalizationError("DOCUMENT_ENCODING_REJECTED")
	}
	document := bytes.TrimSuffix(output.Bytes(), []byte{'\n'})
	if len(document) > 64<<10 {
		return nil, normalizationError("DOCUMENT_LIMIT_REJECTED")
	}
	return append([]byte(nil), document...), nil
}

func normalizedFreshnessTime(value time.Time) (time.Time, error) {
	if value.IsZero() || value.Year() < 1970 || value.Year() > 9999 || value.Nanosecond()%1_000 != 0 {
		return time.Time{}, normalizationError("FRESHNESS_REJECTED")
	}
	return value.UTC(), nil
}

func liveAssetProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		sourceProvenance("display_name", "CMDB_V1_DISPLAY_NAME"),
		sourceProvenance("environment_id", "CMDB_V1_ENVIRONMENT_ID"),
		sourceProvenance("external_id", "CMDB_V1_EXTERNAL_ID"),
		sourceProvenance("kind", "CMDB_V1_KIND"),
		sourceProvenance("provider_kind", "CMDB_V1_PROVIDER_KIND"),
		sourceProvenance("type_details", "CMDB_V1_TYPE_DETAILS"),
	}
}

func tombstoneProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		sourceProvenance("environment_id", "CMDB_V1_ENVIRONMENT_ID"),
		sourceProvenance("external_id", "CMDB_V1_EXTERNAL_ID"),
		sourceProvenance("provider_kind", "CMDB_V1_PROVIDER_KIND"),
	}
}

func sourceProvenance(fieldCode string, pathCode string) assetdiscovery.FieldProvenance {
	return assetdiscovery.FieldProvenance{
		FieldCode:        fieldCode,
		ProviderPathCode: pathCode,
		Ownership:        assetcatalog.FieldOwnershipSource,
		Confidence:       100,
	}
}

func validateNormalizedItem(item assetdiscovery.NormalizedItem, attributeCodes []string) error {
	policy := normalizedFactPolicy(item.EnvironmentID, attributeCodes)
	if !item.Tombstone {
		policy.AllowedDocumentFields = map[assetcatalog.Kind][]string{item.Kind: attributeCodes}
	}
	if err := assetdiscovery.ValidateFacts([]assetdiscovery.NormalizedItem{item}, nil, policy); err != nil {
		return normalizationError("FACT_CONTRACT_REJECTED")
	}
	return nil
}

func normalizedFactPolicy(environmentID string, attributeCodes []string) assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind:            providerKind,
		FreshnessKind:           assetcatalog.FreshnessObjectTimeSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{environmentID},
		TrustedPathCodes: []string{
			"CMDB_V1_DISPLAY_NAME",
			"CMDB_V1_ENVIRONMENT_ID",
			"CMDB_V1_EXTERNAL_ID",
			"CMDB_V1_KIND",
			"CMDB_V1_PROVIDER_KIND",
			"CMDB_V1_RELATION",
			"CMDB_V1_TYPE_DETAILS",
		},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{},
	}
}

func normalizationError(code string) error {
	return fmt.Errorf("%w: %s", errNormalization, code)
}
