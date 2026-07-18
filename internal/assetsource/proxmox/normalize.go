package proxmox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const checkpointTimeLayout = "2006-01-02T15:04:05.000000Z"

var (
	errNormalization  = errors.New("proxmox normalization rejected")
	credentialPattern = regexp.MustCompile(
		`(?i)(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{16,}\b|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`,
	)
	macPattern = regexp.MustCompile(
		`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}`,
	)
)

var trustedPathCodes = []string{
	"PROXMOX_V1_CONTAINS",
	"PROXMOX_V1_DISPLAY_NAME",
	"PROXMOX_V1_ENVIRONMENT_ID",
	"PROXMOX_V1_EXTERNAL_ID",
	"PROXMOX_V1_KIND",
	"PROXMOX_V1_PROVIDER_KIND",
	"PROXMOX_V1_RUNS_ON",
	"PROXMOX_V1_TYPE_DETAILS",
}

type inventorySnapshot struct {
	clusterIdentityDigest string
	clusterGeneration     int64
	orderSequence         int64
	completedAt           time.Time
	nodes                 []Node
	resources             []ClusterResource
}

type normalizedInventoryResult struct {
	Items     []assetdiscovery.NormalizedItem
	Relations []assetdiscovery.ObservedRelation
}

type providerCheckpoint struct {
	ClusterIdentityDigest string `json:"cluster_identity_digest"`
	ClusterGeneration     int64  `json:"cluster_generation"`
	ResourceDigest        string `json:"resource_digest"`
	CompletedAt           string `json:"completed_at"`
}

type nodeDocument struct {
	CPUCount    int64  `json:"cpu_count"`
	MemoryBytes uint64 `json:"memory_bytes"`
	NodeStatus  string `json:"node_status"`
}

type resourceDocument struct {
	CPUCount    uint64 `json:"cpu_count"`
	MemoryBytes uint64 `json:"memory_bytes"`
	Status      string `json:"status"`
	Subtype     string `json:"subtype"`
	Template    bool   `json:"template"`
}

func normalizeInventory(
	environmentID string,
	snapshot inventorySnapshot,
	limits discoverysource.Limits,
) (normalizedInventoryResult, providerCheckpoint, error) {
	if !canonicalUUIDPattern.MatchString(environmentID) ||
		!lowercaseDigest.MatchString(snapshot.clusterIdentityDigest) ||
		snapshot.clusterGeneration <= 0 ||
		snapshot.orderSequence <= 0 ||
		!validCompletedAt(snapshot.completedAt) ||
		len(snapshot.nodes) == 0 ||
		len(snapshot.nodes)+len(snapshot.resources) > maxInventoryResources ||
		int64(len(snapshot.nodes)+len(snapshot.resources)) > limits.MaxPageItems ||
		int64(len(snapshot.resources)*2) > limits.MaxPageRelations {
		return normalizedInventoryResult{}, providerCheckpoint{}, normalizationError("SNAPSHOT_REJECTED")
	}
	nodes := slices.Clone(snapshot.nodes)
	resources := slices.Clone(snapshot.resources)
	slices.SortFunc(nodes, func(left, right Node) int {
		return strings.Compare(left.Name, right.Name)
	})
	slices.SortFunc(resources, func(left, right ClusterResource) int {
		return strings.Compare(left.ID, right.ID)
	})
	for index, node := range nodes {
		if !validNode(node) || index > 0 && nodes[index-1].Name == node.Name {
			return normalizedInventoryResult{}, providerCheckpoint{}, normalizationError("NODE_REJECTED")
		}
	}
	nodeNames := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		nodeNames[node.Name] = struct{}{}
	}
	for index, resource := range resources {
		if !validResource(resource) ||
			index > 0 && resources[index-1].ID == resource.ID {
			return normalizedInventoryResult{}, providerCheckpoint{}, normalizationError("RESOURCE_REJECTED")
		}
		if _, found := nodeNames[resource.Node]; !found {
			return normalizedInventoryResult{}, providerCheckpoint{}, normalizationError("RESOURCE_NODE_REJECTED")
		}
	}

	resourceDigest := digestInventoryResources(nodes, resources)
	identityRaw, err := hex.DecodeString(snapshot.clusterIdentityDigest)
	if err != nil || len(identityRaw) != sha256.Size {
		return normalizedInventoryResult{}, providerCheckpoint{}, normalizationError("IDENTITY_DIGEST_REJECTED")
	}
	resourceRaw, err := hex.DecodeString(resourceDigest)
	if err != nil || len(resourceRaw) != sha256.Size {
		clear(identityRaw)
		return normalizedInventoryResult{}, providerCheckpoint{}, normalizationError("RESOURCE_DIGEST_REJECTED")
	}
	defer clear(identityRaw)
	defer clear(resourceRaw)

	items := make([]assetdiscovery.NormalizedItem, 0, len(nodes)+len(resources))
	for _, node := range nodes {
		item, err := normalizeNode(
			environmentID,
			snapshot.clusterGeneration,
			snapshot.orderSequence,
			identityRaw,
			resourceRaw,
			node,
			limits.MaxDocumentBytes,
		)
		if err != nil {
			return normalizedInventoryResult{}, providerCheckpoint{}, err
		}
		items = append(items, item)
	}
	for _, resource := range resources {
		item, err := normalizeResource(
			environmentID,
			snapshot.clusterGeneration,
			snapshot.orderSequence,
			identityRaw,
			resourceRaw,
			resource,
			limits.MaxDocumentBytes,
		)
		if err != nil {
			return normalizedInventoryResult{}, providerCheckpoint{}, err
		}
		items = append(items, item)
	}
	slices.SortFunc(items, func(left, right assetdiscovery.NormalizedItem) int {
		return strings.Compare(left.ExternalID, right.ExternalID)
	})

	relations := make([]assetdiscovery.ObservedRelation, 0, len(resources)*2)
	for _, resource := range resources {
		nodeID := "node/" + resource.Node
		runsOn, err := normalizeRelation(
			environmentID,
			resource.ID,
			nodeID,
			assetcatalog.RelationshipRunsOn,
			"PROXMOX_V1_RUNS_ON",
			snapshot.clusterGeneration,
			snapshot.orderSequence,
			identityRaw,
			resourceRaw,
		)
		if err != nil {
			return normalizedInventoryResult{}, providerCheckpoint{}, err
		}
		contains, err := normalizeRelation(
			environmentID,
			nodeID,
			resource.ID,
			assetcatalog.RelationshipContains,
			"PROXMOX_V1_CONTAINS",
			snapshot.clusterGeneration,
			snapshot.orderSequence,
			identityRaw,
			resourceRaw,
		)
		if err != nil {
			return normalizedInventoryResult{}, providerCheckpoint{}, err
		}
		relations = append(relations, contains, runsOn)
	}
	slices.SortFunc(relations, compareNormalizedRelation)

	policy := normalizedFactPolicy(environmentID)
	if err := assetdiscovery.ValidateFacts(items, relations, policy); err != nil {
		return normalizedInventoryResult{}, providerCheckpoint{}, normalizationError("FACT_CONTRACT_REJECTED")
	}
	checkpoint := providerCheckpoint{
		ClusterIdentityDigest: snapshot.clusterIdentityDigest,
		ClusterGeneration:     snapshot.clusterGeneration,
		ResourceDigest:        resourceDigest,
		CompletedAt:           snapshot.completedAt.UTC().Format(checkpointTimeLayout),
	}
	if _, err := encodeProviderCheckpoint(checkpoint); err != nil {
		return normalizedInventoryResult{}, providerCheckpoint{}, err
	}
	return normalizedInventoryResult{
		Items:     items,
		Relations: relations,
	}, checkpoint, nil
}

func normalizeNode(
	environmentID string,
	generation int64,
	orderSequence int64,
	identityDigest []byte,
	resourceDigest []byte,
	node Node,
	maxDocumentBytes int64,
) (assetdiscovery.NormalizedItem, error) {
	document, err := canonicalDocument(nodeDocument{
		CPUCount:    node.CPUCount,
		MemoryBytes: node.MemoryBytes,
		NodeStatus:  node.Status,
	})
	if err != nil || int64(len(document)) > maxDocumentBytes {
		return assetdiscovery.NormalizedItem{}, normalizationError("NODE_DOCUMENT_REJECTED")
	}
	externalID := "node/" + node.Name
	return normalizedItem(
		environmentID,
		externalID,
		assetcatalog.KindBareMetalHost,
		node.Name,
		document,
		generation,
		orderSequence,
		identityDigest,
		resourceDigest,
	)
}

func normalizeResource(
	environmentID string,
	generation int64,
	orderSequence int64,
	identityDigest []byte,
	resourceDigest []byte,
	resource ClusterResource,
	maxDocumentBytes int64,
) (assetdiscovery.NormalizedItem, error) {
	document, err := canonicalDocument(resourceDocument{
		CPUCount:    resource.CPUCount,
		MemoryBytes: resource.MemoryBytes,
		Status:      resource.Status,
		Subtype:     strings.ToUpper(resource.Type),
		Template:    resource.Template,
	})
	if err != nil || int64(len(document)) > maxDocumentBytes {
		return assetdiscovery.NormalizedItem{}, normalizationError("RESOURCE_DOCUMENT_REJECTED")
	}
	return normalizedItem(
		environmentID,
		resource.ID,
		assetcatalog.KindCloudResource,
		resource.Name,
		document,
		generation,
		orderSequence,
		identityDigest,
		resourceDigest,
	)
}

func normalizedItem(
	environmentID string,
	externalID string,
	kind assetcatalog.Kind,
	displayName string,
	document []byte,
	generation int64,
	orderSequence int64,
	identityDigest []byte,
	resourceDigest []byte,
) (assetdiscovery.NormalizedItem, error) {
	if !safeNormalizedValue(externalID, 1, 512) ||
		!safeNormalizedValue(displayName, 1, 256) ||
		unsafeNormalizedText(externalID) ||
		unsafeNormalizedText(displayName) {
		return assetdiscovery.NormalizedItem{}, normalizationError("ITEM_IDENTITY_REJECTED")
	}
	documentDigest := sha256.Sum256(document)
	item := assetdiscovery.NormalizedItem{
		EnvironmentID:  environmentID,
		ProviderKind:   providerKind,
		ExternalID:     externalID,
		Kind:           kind,
		DisplayName:    displayName,
		SchemaVersion:  providerKind,
		Document:       append([]byte(nil), document...),
		DocumentSHA256: hex.EncodeToString(documentDigest[:]),
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:          assetcatalog.FreshnessCheckpointSequence,
			OrderSequence: orderSequence,
			ProviderVersionSHA256: digestRawFramedTuple(
				[]byte("proxmox-object-version.v1"),
				identityDigest,
				[]byte(strconv.FormatInt(generation, 10)),
				resourceDigest,
				[]byte(externalID),
			),
		},
		FieldProvenance: liveProvenance(),
	}
	return item, nil
}

func normalizeRelation(
	environmentID string,
	fromExternalID string,
	toExternalID string,
	relationType assetcatalog.RelationshipType,
	pathCode string,
	generation int64,
	orderSequence int64,
	identityDigest []byte,
	resourceDigest []byte,
) (assetdiscovery.ObservedRelation, error) {
	if !slices.Contains(
		[]assetcatalog.RelationshipType{
			assetcatalog.RelationshipContains,
			assetcatalog.RelationshipRunsOn,
		},
		relationType,
	) ||
		!slices.Contains(trustedPathCodes, pathCode) ||
		!safeNormalizedValue(fromExternalID, 1, 512) ||
		!safeNormalizedValue(toExternalID, 1, 512) ||
		fromExternalID == toExternalID {
		return assetdiscovery.ObservedRelation{}, normalizationError("RELATION_REJECTED")
	}
	return assetdiscovery.ObservedRelation{
		SourceEnvironmentID: environmentID,
		TargetEnvironmentID: environmentID,
		FromExternalID:      fromExternalID,
		ToExternalID:        toExternalID,
		Type:                relationType,
		ProviderPathCode:    pathCode,
		Confidence:          100,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:          assetcatalog.FreshnessCheckpointSequence,
			OrderSequence: orderSequence,
			ProviderVersionSHA256: digestRawFramedTuple(
				[]byte("proxmox-relation-version.v1"),
				identityDigest,
				[]byte(strconv.FormatInt(generation, 10)),
				resourceDigest,
				[]byte(fromExternalID),
				[]byte(toExternalID),
				[]byte(relationType),
			),
		},
	}, nil
}

func normalizedFactPolicy(environmentID string) assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind:            providerKind,
		FreshnessKind:           assetcatalog.FreshnessCheckpointSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{environmentID},
		TrustedPathCodes:        slices.Clone(trustedPathCodes),
		RelationshipTypes: []assetcatalog.RelationshipType{
			assetcatalog.RelationshipContains,
			assetcatalog.RelationshipRunsOn,
		},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{
			assetcatalog.KindBareMetalHost: {
				"cpu_count",
				"memory_bytes",
				"node_status",
			},
			assetcatalog.KindCloudResource: {
				"cpu_count",
				"memory_bytes",
				"status",
				"subtype",
				"template",
			},
		},
	}
}

func liveProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		sourceProvenance("display_name", "PROXMOX_V1_DISPLAY_NAME"),
		sourceProvenance("environment_id", "PROXMOX_V1_ENVIRONMENT_ID"),
		sourceProvenance("external_id", "PROXMOX_V1_EXTERNAL_ID"),
		sourceProvenance("kind", "PROXMOX_V1_KIND"),
		sourceProvenance("provider_kind", "PROXMOX_V1_PROVIDER_KIND"),
		sourceProvenance("type_details", "PROXMOX_V1_TYPE_DETAILS"),
	}
}

func sourceProvenance(fieldCode, pathCode string) assetdiscovery.FieldProvenance {
	return assetdiscovery.FieldProvenance{
		FieldCode:        fieldCode,
		ProviderPathCode: pathCode,
		Ownership:        assetcatalog.FieldOwnershipSource,
		Confidence:       100,
	}
}

func compareNormalizedRelation(
	left assetdiscovery.ObservedRelation,
	right assetdiscovery.ObservedRelation,
) int {
	for _, pair := range [][2]string{
		{left.FromExternalID, right.FromExternalID},
		{left.ToExternalID, right.ToExternalID},
		{string(left.Type), string(right.Type)},
		{left.ProviderPathCode, right.ProviderPathCode},
	} {
		if comparison := strings.Compare(pair[0], pair[1]); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func digestInventoryResources(nodes []Node, resources []ClusterResource) string {
	fields := [][]byte{[]byte("proxmox-resource-set.v1")}
	for _, node := range nodes {
		fields = append(fields,
			[]byte("node"),
			[]byte(node.Name),
			[]byte(node.Status),
			[]byte(strconv.FormatInt(node.CPUCount, 10)),
			[]byte(strconv.FormatUint(node.MemoryBytes, 10)),
		)
	}
	for _, resource := range resources {
		fields = append(fields,
			[]byte("resource"),
			[]byte(resource.ID),
			[]byte(resource.Type),
			[]byte(strconv.FormatUint(resource.VMID, 10)),
			[]byte(resource.Name),
			[]byte(resource.Node),
			[]byte(resource.Status),
			[]byte(strconv.FormatBool(resource.Template)),
			[]byte(strconv.FormatUint(resource.CPUCount, 10)),
			[]byte(strconv.FormatUint(resource.MemoryBytes, 10)),
		)
	}
	return digestRawFramedTuple(fields...)
}

func digestRawFramedTuple(fields ...[]byte) string {
	hasher := sha256.New()
	for _, field := range fields {
		writeDigestFrame(hasher, field)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func canonicalDocument(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func encodeProviderCheckpoint(value providerCheckpoint) ([]byte, error) {
	if !validProviderCheckpoint(value) {
		return nil, normalizationError("CHECKPOINT_REJECTED")
	}
	return canonicalDocument(value)
}

func decodeProviderCheckpoint(
	checkpoint discoverysource.Checkpoint,
) (providerCheckpoint, bool, error) {
	var (
		value   providerCheckpoint
		present bool
	)
	err := discoverysource.WithCheckpointBytes(checkpoint, profileCode, func(canonical []byte) error {
		if len(canonical) == 0 {
			return nil
		}
		decoded, err := decodeProviderCheckpointCanonical(canonical)
		if err != nil {
			return err
		}
		value = decoded
		present = true
		return nil
	})
	if err != nil {
		return providerCheckpoint{}, false, err
	}
	return value, present, nil
}

func decodeProviderCheckpointCanonical(canonical []byte) (providerCheckpoint, error) {
	if len(canonical) == 0 ||
		len(canonical) > discoverysource.MaxCheckpointCanonicalBytes ||
		!utf8.Valid(canonical) {
		return providerCheckpoint{}, normalizationError("CHECKPOINT_CANONICAL_REJECTED")
	}
	if err := rejectDuplicateJSONFields(canonical); err != nil {
		return providerCheckpoint{}, normalizationError("CHECKPOINT_CANONICAL_REJECTED")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var value providerCheckpoint
	if decoder.Decode(&value) != nil {
		return providerCheckpoint{}, normalizationError("CHECKPOINT_CANONICAL_REJECTED")
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return providerCheckpoint{}, normalizationError("CHECKPOINT_TRAILING_REJECTED")
	}
	if !validProviderCheckpoint(value) {
		return providerCheckpoint{}, normalizationError("CHECKPOINT_REJECTED")
	}
	reencoded, err := encodeProviderCheckpoint(value)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return providerCheckpoint{}, normalizationError("CHECKPOINT_NON_CANONICAL")
	}
	return value, nil
}

func validProviderCheckpoint(value providerCheckpoint) bool {
	if !lowercaseDigest.MatchString(value.ClusterIdentityDigest) ||
		!lowercaseDigest.MatchString(value.ResourceDigest) ||
		value.ClusterGeneration <= 0 {
		return false
	}
	completedAt, err := time.Parse(checkpointTimeLayout, value.CompletedAt)
	return err == nil && validCompletedAt(completedAt)
}

func validCompletedAt(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Equal(value.Truncate(time.Microsecond))
}

func safeNormalizedValue(value string, minimum, maximum int) bool {
	if len(value) < minimum ||
		len(value) > maximum ||
		!utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func unsafeNormalizedText(value string) bool {
	if !utf8.ValidString(value) ||
		credentialPattern.MatchString(value) ||
		macPattern.MatchString(value) ||
		net.ParseIP(value) != nil {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"-----begin",
		"authorization",
		"bearer ",
		"cloud-init",
		"cloud_init",
		"console",
		"credential",
		"dsn=",
		"endpoint",
		"password",
		"private_key",
		"private-key",
		"pveapitoken",
		"secret",
		"ssh-rsa",
		"token",
		"vnc",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func normalizationError(code string) error {
	return errors.Join(errNormalization, providerError(code))
}
