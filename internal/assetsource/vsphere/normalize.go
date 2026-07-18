package vsphere

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/vmware/govmomi/vim25/types"
)

const (
	normalizedSchemaVersion = "VSPHERE_VCENTER_V1"
	maxCPUCount             = int64(65_536)
	maxMemoryMB             = int64(1 << 34)
)

var (
	errNormalization = errors.New("vsphere normalization rejected")

	allowedObjectTypes = []string{
		"ClusterComputeResource",
		"Datacenter",
		"Datastore",
		"Folder",
		"HostSystem",
		"Network",
		"ResourcePool",
		"VirtualMachine",
	}
	normalizedDocumentFieldAllowlist = []string{
		"connection_state",
		"cpu_count",
		"guest_family_code",
		"memory_mb",
		"object_type",
		"power_state",
	}
	trustedPathCodes = []string{
		"VSPHERE_V1_CONTAINS",
		"VSPHERE_V1_DISPLAY_NAME",
		"VSPHERE_V1_ENVIRONMENT_ID",
		"VSPHERE_V1_EXTERNAL_ID",
		"VSPHERE_V1_KIND",
		"VSPHERE_V1_PROVIDER_KIND",
		"VSPHERE_V1_RUNS_ON",
		"VSPHERE_V1_TYPE_DETAILS",
	}
	secretValuePattern = regexp.MustCompile(
		`(?i)(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{16,}\b|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`,
	)
	macValuePattern = regexp.MustCompile(
		`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}`,
	)
)

type inventoryObject struct {
	Reference       types.ManagedObjectReference
	AuthorityRoot   types.ManagedObjectReference
	Name            string
	GuestID         string
	PowerState      string
	ConnectionState string
	CPUCount        int64
	MemoryMB        int64
}

type inventoryRelation struct {
	FromReference types.ManagedObjectReference
	ToReference   types.ManagedObjectReference
	FromRoot      types.ManagedObjectReference
	ToRoot        types.ManagedObjectReference
	Type          assetcatalog.RelationshipType
	TopologyPath  string
}

func normalizeObject(
	scope normalizationScope,
	object inventoryObject,
	orderSequence int64,
) (assetdiscovery.NormalizedItem, error) {
	if !scope.valid() ||
		orderSequence <= 0 ||
		!authorityContains(scope.AuthorityRoots, object.AuthorityRoot) ||
		!validManagedObjectReference(object.Reference) ||
		!slices.Contains(allowedObjectTypes, object.Reference.Type) ||
		!safeRuntimeText(object.Name, 1, 256) ||
		unsafeNormalizedText(object.Name) ||
		unsafeNormalizedText(object.Reference.Type) ||
		unsafeNormalizedText(object.Reference.Value) {
		return assetdiscovery.NormalizedItem{}, normalizationError("OBJECT_REJECTED")
	}

	kind, guestFamily, err := normalizedKindAndFamily(object)
	if err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	documentFields, err := normalizedDocument(object, guestFamily)
	if err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	document, err := json.Marshal(documentFields)
	if err != nil || len(document) == 0 || len(document) > 64<<10 {
		return assetdiscovery.NormalizedItem{}, normalizationError("DOCUMENT_REJECTED")
	}
	documentDigest := sha256.Sum256(document)
	externalID, err := namespacedMoRef(scope.InstanceUUID, object.Reference)
	if err != nil {
		return assetdiscovery.NormalizedItem{}, err
	}
	versionDigest := digestFramedStrings(
		"vsphere-object-version.v1",
		scope.InstanceUUID,
		object.Reference.Type,
		object.Reference.Value,
		hex.EncodeToString(documentDigest[:]),
	)
	item := assetdiscovery.NormalizedItem{
		EnvironmentID:  scope.EnvironmentID,
		ProviderKind:   providerKind,
		ExternalID:     externalID,
		Kind:           kind,
		DisplayName:    object.Name,
		SchemaVersion:  normalizedSchemaVersion,
		Document:       document,
		DocumentSHA256: hex.EncodeToString(documentDigest[:]),
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:                  assetcatalog.FreshnessCheckpointSequence,
			OrderSequence:         orderSequence,
			ProviderVersionSHA256: versionDigest,
		},
		FieldProvenance: liveObjectProvenance(),
	}
	if err := assetdiscovery.ValidateFacts(
		[]assetdiscovery.NormalizedItem{item},
		nil,
		factPolicyForItem(scope, item),
	); err != nil {
		return assetdiscovery.NormalizedItem{}, normalizationError("FACT_CONTRACT_REJECTED")
	}
	return item, nil
}

func normalizeRelation(
	scope normalizationScope,
	relation inventoryRelation,
	orderSequence int64,
) (assetdiscovery.ObservedRelation, error) {
	if !scope.valid() ||
		orderSequence <= 0 ||
		compareManagedObjectReference(relation.FromRoot, relation.ToRoot) != 0 ||
		!authorityContains(scope.AuthorityRoots, relation.FromRoot) ||
		!validManagedObjectReference(relation.FromReference) ||
		!validManagedObjectReference(relation.ToReference) ||
		!slices.Contains(allowedObjectTypes, relation.FromReference.Type) ||
		!slices.Contains(allowedObjectTypes, relation.ToReference.Type) ||
		compareManagedObjectReference(relation.FromReference, relation.ToReference) == 0 ||
		!validRelationShape(relation) {
		return assetdiscovery.ObservedRelation{}, normalizationError("RELATION_REJECTED")
	}
	fromExternalID, err := namespacedMoRef(scope.InstanceUUID, relation.FromReference)
	if err != nil {
		return assetdiscovery.ObservedRelation{}, err
	}
	toExternalID, err := namespacedMoRef(scope.InstanceUUID, relation.ToReference)
	if err != nil {
		return assetdiscovery.ObservedRelation{}, err
	}
	pathCode := "VSPHERE_V1_CONTAINS"
	if relation.Type == assetcatalog.RelationshipRunsOn {
		pathCode = "VSPHERE_V1_RUNS_ON"
	}
	normalized := assetdiscovery.ObservedRelation{
		SourceEnvironmentID: scope.EnvironmentID,
		TargetEnvironmentID: scope.EnvironmentID,
		FromExternalID:      fromExternalID,
		ToExternalID:        toExternalID,
		Type:                relation.Type,
		ProviderPathCode:    pathCode,
		Confidence:          100,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:          assetcatalog.FreshnessCheckpointSequence,
			OrderSequence: orderSequence,
			ProviderVersionSHA256: digestFramedStrings(
				"vsphere-relation-version.v1",
				scope.InstanceUUID,
				relation.FromReference.Type,
				relation.FromReference.Value,
				relation.ToReference.Type,
				relation.ToReference.Value,
				string(relation.Type),
			),
		},
	}
	if err := assetdiscovery.ValidateFacts(
		nil,
		[]assetdiscovery.ObservedRelation{normalized},
		factPolicyForRelation(scope, relation.Type),
	); err != nil {
		return assetdiscovery.ObservedRelation{}, normalizationError("RELATION_FACT_REJECTED")
	}
	return normalized, nil
}

func normalizedKindAndFamily(
	object inventoryObject,
) (assetcatalog.Kind, string, error) {
	switch object.Reference.Type {
	case "Folder", "Datacenter", "ClusterComputeResource", "ResourcePool", "Datastore", "Network":
		if object.GuestID != "" ||
			object.PowerState != "" ||
			object.ConnectionState != "" ||
			object.CPUCount != 0 ||
			object.MemoryMB != 0 {
			return "", "", normalizationError("OBJECT_PROPERTY_REJECTED")
		}
		return assetcatalog.KindCloudResource, "", nil
	case "HostSystem":
		if object.GuestID != "" ||
			object.PowerState != "" ||
			!validHostConnectionState(object.ConnectionState) ||
			!validCapacity(object.CPUCount, object.MemoryMB) {
			return "", "", normalizationError("HOST_PROPERTY_REJECTED")
		}
		return assetcatalog.KindBareMetalHost, "", nil
	case "VirtualMachine":
		if !safeRuntimeText(object.GuestID, 1, 64) ||
			unsafeNormalizedText(object.GuestID) ||
			!validPowerState(object.PowerState) ||
			!validVirtualMachineConnectionState(object.ConnectionState) ||
			!validCapacity(object.CPUCount, object.MemoryMB) {
			return "", "", normalizationError("VM_PROPERTY_REJECTED")
		}
		switch object.GuestID {
		case "amazonlinux2_64Guest",
			"centos7_64Guest",
			"debian11_64Guest",
			"debian12_64Guest",
			"otherLinux64Guest",
			"rhel8_64Guest",
			"rhel9_64Guest",
			"rockylinux_64Guest",
			"ubuntu64Guest":
			return assetcatalog.KindLinuxVM, "LINUX", nil
		case "windows9_64Guest",
			"windows11_64Guest",
			"windows2019srv_64Guest",
			"windows2022srvNext_64Guest",
			"windows9Server64Guest":
			return assetcatalog.KindWindowsVM, "WINDOWS", nil
		default:
			return assetcatalog.KindCloudResource, "UNKNOWN", nil
		}
	default:
		return "", "", normalizationError("OBJECT_TYPE_REJECTED")
	}
}

func normalizedDocument(
	object inventoryObject,
	guestFamily string,
) (map[string]any, error) {
	document := map[string]any{"object_type": object.Reference.Type}
	switch object.Reference.Type {
	case "HostSystem":
		document["connection_state"] = object.ConnectionState
		document["cpu_count"] = object.CPUCount
		document["memory_mb"] = object.MemoryMB
	case "VirtualMachine":
		document["connection_state"] = object.ConnectionState
		document["cpu_count"] = object.CPUCount
		document["guest_family_code"] = guestFamily
		document["memory_mb"] = object.MemoryMB
		document["power_state"] = object.PowerState
	}
	for key, value := range document {
		if !slices.Contains(normalizedDocumentFieldAllowlist, key) {
			return nil, normalizationError("DOCUMENT_FIELD_REJECTED")
		}
		if text, ok := value.(string); ok && unsafeNormalizedText(text) {
			return nil, normalizationError("DOCUMENT_VALUE_REJECTED")
		}
	}
	return document, nil
}

func factPolicyForItem(
	scope normalizationScope,
	item assetdiscovery.NormalizedItem,
) assetdiscovery.FactPolicy {
	var document map[string]json.RawMessage
	_ = json.Unmarshal(item.Document, &document)
	fields := make([]string, 0, len(document))
	for field := range document {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return assetdiscovery.FactPolicy{
		ProviderKind:            providerKind,
		FreshnessKind:           assetcatalog.FreshnessCheckpointSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{scope.EnvironmentID},
		TrustedPathCodes:        slices.Clone(trustedPathCodes),
		RelationshipTypes: []assetcatalog.RelationshipType{
			assetcatalog.RelationshipContains,
			assetcatalog.RelationshipRunsOn,
		},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{
			item.Kind: fields,
		},
	}
}

func factPolicyForRelation(
	scope normalizationScope,
	relationType assetcatalog.RelationshipType,
) assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind:            providerKind,
		FreshnessKind:           assetcatalog.FreshnessCheckpointSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingSingle,
		AuthorityEnvironmentIDs: []string{scope.EnvironmentID},
		TrustedPathCodes:        slices.Clone(trustedPathCodes),
		RelationshipTypes:       []assetcatalog.RelationshipType{relationType},
		AllowedDocumentFields:   map[assetcatalog.Kind][]string{},
	}
}

func liveObjectProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		sourceProvenance("display_name", "VSPHERE_V1_DISPLAY_NAME"),
		sourceProvenance("environment_id", "VSPHERE_V1_ENVIRONMENT_ID"),
		sourceProvenance("external_id", "VSPHERE_V1_EXTERNAL_ID"),
		sourceProvenance("kind", "VSPHERE_V1_KIND"),
		sourceProvenance("provider_kind", "VSPHERE_V1_PROVIDER_KIND"),
		sourceProvenance("type_details", "VSPHERE_V1_TYPE_DETAILS"),
	}
}

func sourceProvenance(
	fieldCode string,
	pathCode string,
) assetdiscovery.FieldProvenance {
	return assetdiscovery.FieldProvenance{
		FieldCode:        fieldCode,
		ProviderPathCode: pathCode,
		Ownership:        assetcatalog.FieldOwnershipSource,
		Confidence:       100,
	}
}

func authorityContains(
	roots []types.ManagedObjectReference,
	candidate types.ManagedObjectReference,
) bool {
	_, found := slices.BinarySearchFunc(roots, candidate, compareManagedObjectReference)
	return found
}

func namespacedMoRef(
	instanceUUID string,
	reference types.ManagedObjectReference,
) (string, error) {
	if !instanceUUIDPattern.MatchString(instanceUUID) ||
		!validManagedObjectReference(reference) ||
		unsafeNormalizedText(reference.Type) ||
		unsafeNormalizedText(reference.Value) {
		return "", normalizationError("MOREF_REJECTED")
	}
	value := strings.Join([]string{
		"vsphere",
		instanceUUID,
		reference.Type,
		reference.Value,
	}, ":")
	if !safeRuntimeText(value, 1, 512) {
		return "", normalizationError("MOREF_REJECTED")
	}
	return value, nil
}

func validCapacity(cpuCount, memoryMB int64) bool {
	return cpuCount > 0 &&
		cpuCount <= maxCPUCount &&
		memoryMB > 0 &&
		memoryMB <= maxMemoryMB
}

func validPowerState(value string) bool {
	switch value {
	case "poweredOff", "poweredOn", "suspended":
		return true
	default:
		return false
	}
}

func validHostConnectionState(value string) bool {
	switch types.HostSystemConnectionState(value) {
	case types.HostSystemConnectionStateConnected,
		types.HostSystemConnectionStateDisconnected,
		types.HostSystemConnectionStateNotResponding:
		return true
	default:
		return false
	}
}

func validVirtualMachineConnectionState(value string) bool {
	switch types.VirtualMachineConnectionState(value) {
	case types.VirtualMachineConnectionStateConnected,
		types.VirtualMachineConnectionStateDisconnected,
		types.VirtualMachineConnectionStateOrphaned,
		types.VirtualMachineConnectionStateInaccessible,
		types.VirtualMachineConnectionStateInvalid:
		return true
	default:
		return false
	}
}

func validRelationShape(relation inventoryRelation) bool {
	switch relation.Type {
	case assetcatalog.RelationshipRunsOn:
		return relation.FromReference.Type == "VirtualMachine" &&
			relation.ToReference.Type == "HostSystem"
	case assetcatalog.RelationshipContains:
		switch relation.FromReference.Type {
		case "Folder":
			switch relation.ToReference.Type {
			case "Folder", "Datacenter", "ClusterComputeResource", "Datastore", "HostSystem", "Network", "ResourcePool", "VirtualMachine":
				return true
			}
		case "Datacenter":
			switch relation.ToReference.Type {
			case "Folder", "ClusterComputeResource", "Datastore", "Network", "VirtualMachine":
				return true
			}
		case "ClusterComputeResource":
			switch relation.ToReference.Type {
			case "HostSystem", "ResourcePool", "VirtualMachine":
				return true
			}
		case "ResourcePool":
			switch relation.ToReference.Type {
			case "ResourcePool", "VirtualMachine":
				return true
			}
		}
		return false
	default:
		return false
	}
}

func unsafeNormalizedText(value string) bool {
	if sensitiveRuntimeText(value) ||
		secretValuePattern.MatchString(value) ||
		containsNetworkIdentifier(value) {
		return true
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return true
	}
	lower := strings.ToLower(trimmed)
	for _, marker := range []string{
		"dsn=",
		"host=",
		"jdbc:",
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	tokens := strings.FieldsFunc(trimmed, func(character rune) bool {
		return strings.ContainsRune(" \t\r\n,;\"'(){}<>", character)
	})
	for _, token := range tokens {
		candidate := strings.Trim(token, ".,")
		host, port, err := net.SplitHostPort(candidate)
		if err == nil && host != "" && port != "" {
			return true
		}
	}
	return false
}

func containsNetworkIdentifier(value string) bool {
	for start := 0; start < len(value); start++ {
		if !ipLiteralByte(value[start]) {
			continue
		}
		for end := start + 1; end <= len(value) && end-start <= 45; end++ {
			if !ipLiteralByte(value[end-1]) {
				break
			}
			if net.ParseIP(value[start:end]) != nil {
				return true
			}
		}
	}
	for _, candidate := range macValuePattern.FindAllString(value, -1) {
		if _, err := net.ParseMAC(candidate); err == nil {
			return true
		}
	}
	return false
}

func ipLiteralByte(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F' ||
		value == '.' ||
		value == ':'
}

func normalizationError(code string) error {
	return fmt.Errorf("%w: %s", errNormalization, code)
}
