package vsphere

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/vmware/govmomi/vim25/types"
)

func TestNormalizeObjectUsesNamespacedMoRefClosedKindMappingAndSingleEnvironment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		object   inventoryObject
		wantKind assetcatalog.Kind
	}{
		{
			name: "folder",
			object: inventoryObject{
				Reference:     types.ManagedObjectReference{Type: "Folder", Value: "group-v3"},
				AuthorityRoot: testAuthorityRoot,
				Name:          "vm-folder",
			},
			wantKind: assetcatalog.KindCloudResource,
		},
		{
			name: "datacenter",
			object: inventoryObject{
				Reference:     types.ManagedObjectReference{Type: "Datacenter", Value: "datacenter-2"},
				AuthorityRoot: testAuthorityRoot,
				Name:          "DC0",
			},
			wantKind: assetcatalog.KindCloudResource,
		},
		{
			name: "cluster",
			object: inventoryObject{
				Reference:     types.ManagedObjectReference{Type: "ClusterComputeResource", Value: "domain-c7"},
				AuthorityRoot: testAuthorityRoot,
				Name:          "cluster-a",
			},
			wantKind: assetcatalog.KindCloudResource,
		},
		{
			name: "host",
			object: inventoryObject{
				Reference:       types.ManagedObjectReference{Type: "HostSystem", Value: "host-21"},
				AuthorityRoot:   testAuthorityRoot,
				Name:            "esxi-21",
				ConnectionState: "connected",
				CPUCount:        64,
				MemoryMB:        262_144,
			},
			wantKind: assetcatalog.KindBareMetalHost,
		},
		{
			name: "linux vm",
			object: inventoryObject{
				Reference:       types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
				AuthorityRoot:   testAuthorityRoot,
				Name:            "payments-api-01",
				GuestID:         "ubuntu64Guest",
				PowerState:      "poweredOn",
				ConnectionState: "connected",
				CPUCount:        4,
				MemoryMB:        8_192,
			},
			wantKind: assetcatalog.KindLinuxVM,
		},
		{
			name: "windows vm",
			object: inventoryObject{
				Reference:       types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-43"},
				AuthorityRoot:   testAuthorityRoot,
				Name:            "payments-sql-01",
				GuestID:         "windows2019srv_64Guest",
				PowerState:      "poweredOff",
				ConnectionState: "disconnected",
				CPUCount:        8,
				MemoryMB:        16_384,
			},
			wantKind: assetcatalog.KindWindowsVM,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			scope := validNormalizationScope(t)
			got, err := normalizeObject(scope, test.object, 7)
			if err != nil {
				t.Fatalf("normalizeObject() error = %v", err)
			}
			wantExternalID := strings.Join([]string{
				"vsphere",
				testInstanceUUID,
				test.object.Reference.Type,
				test.object.Reference.Value,
			}, ":")
			if got.EnvironmentID != testEnvironmentID ||
				got.ProviderKind != providerKind ||
				got.ExternalID != wantExternalID ||
				got.Kind != test.wantKind ||
				got.DisplayName != test.object.Name {
				t.Fatalf("normalized identity = %#v", got)
			}
			if got.Freshness.Kind != assetcatalog.FreshnessCheckpointSequence ||
				got.Freshness.OrderSequence != 7 ||
				got.Freshness.ProviderVersionSHA256 == "" {
				t.Fatalf("freshness = %#v", got.Freshness)
			}
			if got.SchemaVersion != normalizedSchemaVersion {
				t.Fatalf("schema version = %q", got.SchemaVersion)
			}
			if err := assetdiscovery.ValidateFacts(
				[]assetdiscovery.NormalizedItem{got},
				nil,
				factPolicyForItem(scope, got),
			); err != nil {
				t.Fatalf("normalized item violates fact contract: %v", err)
			}
			assertDocumentContainsNoForbiddenFields(t, got.Document)
		})
	}
}

func TestNormalizeUnknownGuestIDFallsBackToCloudResourceWithoutGuessing(t *testing.T) {
	t.Parallel()

	scope := validNormalizationScope(t)
	object := validVirtualMachineObject()
	object.GuestID = "futureUnknownGuest"

	got, err := normalizeObject(scope, object, 8)
	if err != nil {
		t.Fatalf("normalizeObject() error = %v", err)
	}
	if got.Kind != assetcatalog.KindCloudResource {
		t.Fatalf("kind = %q, want CLOUD_RESOURCE", got.Kind)
	}
	var document map[string]any
	if err := json.Unmarshal(got.Document, &document); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	if document["guest_family_code"] != "UNKNOWN" {
		t.Fatalf("guest family = %#v", document["guest_family_code"])
	}
	if strings.Contains(strings.ToLower(got.DisplayName), "linux") ||
		strings.Contains(strings.ToLower(got.DisplayName), "windows") {
		t.Fatalf("display name was used to guess guest family: %#v", got)
	}
}

func TestNormalizeConnectionStateUsesObjectSpecificClosedSets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		object   inventoryObject
		accepted []string
		rejected []string
	}{
		{
			name:   "virtual machine",
			object: validVirtualMachineObject(),
			accepted: []string{
				string(types.VirtualMachineConnectionStateConnected),
				string(types.VirtualMachineConnectionStateDisconnected),
				string(types.VirtualMachineConnectionStateOrphaned),
				string(types.VirtualMachineConnectionStateInaccessible),
				string(types.VirtualMachineConnectionStateInvalid),
			},
			rejected: []string{
				string(types.HostSystemConnectionStateNotResponding),
				"futureVmState",
			},
		},
		{
			name: "host system",
			object: inventoryObject{
				Reference: types.ManagedObjectReference{
					Type:  "HostSystem",
					Value: "host-21",
				},
				AuthorityRoot:   testAuthorityRoot,
				Name:            "esxi-21",
				ConnectionState: "connected",
				CPUCount:        64,
				MemoryMB:        262_144,
			},
			accepted: []string{
				string(types.HostSystemConnectionStateConnected),
				string(types.HostSystemConnectionStateDisconnected),
				string(types.HostSystemConnectionStateNotResponding),
			},
			rejected: []string{
				string(types.VirtualMachineConnectionStateOrphaned),
				string(types.VirtualMachineConnectionStateInaccessible),
				string(types.VirtualMachineConnectionStateInvalid),
				"futureHostState",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, state := range test.accepted {
				state := state
				t.Run(string(state), func(t *testing.T) {
					t.Parallel()

					object := test.object
					object.ConnectionState = state
					if _, err := normalizeObject(
						validNormalizationScope(t),
						object,
						8,
					); err != nil {
						t.Fatalf("valid %s connection state %q rejected: %v", test.name, state, err)
					}
				})
			}

			for _, state := range test.rejected {
				state := state
				t.Run("reject "+state, func(t *testing.T) {
					t.Parallel()

					object := test.object
					object.ConnectionState = state
					if got, err := normalizeObject(
						validNormalizationScope(t),
						object,
						8,
					); err == nil {
						t.Fatalf("unknown %s connection state %q normalized as %#v", test.name, state, got)
					}
				})
			}
		})
	}
}

func TestNormalizeProviderVersionsIgnoreCheckpointOrder(t *testing.T) {
	t.Parallel()

	t.Run("item", func(t *testing.T) {
		scope := validNormalizationScope(t)
		first, err := normalizeObject(scope, validVirtualMachineObject(), 7)
		if err != nil {
			t.Fatalf("normalizeObject(first) error = %v", err)
		}
		next, err := normalizeObject(scope, validVirtualMachineObject(), 8)
		if err != nil {
			t.Fatalf("normalizeObject(next) error = %v", err)
		}
		if first.Freshness.OrderSequence != 7 ||
			next.Freshness.OrderSequence != 8 {
			t.Fatalf("item order sequences = %d/%d", first.Freshness.OrderSequence, next.Freshness.OrderSequence)
		}
		if first.Freshness.ProviderVersionSHA256 != next.Freshness.ProviderVersionSHA256 {
			t.Fatalf(
				"item provider versions changed with checkpoint order: %q != %q",
				first.Freshness.ProviderVersionSHA256,
				next.Freshness.ProviderVersionSHA256,
			)
		}
	})

	t.Run("relation", func(t *testing.T) {
		scope := validNormalizationScope(t)
		relation := inventoryRelation{
			FromReference: types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
			ToReference:   types.ManagedObjectReference{Type: "HostSystem", Value: "host-21"},
			FromRoot:      testAuthorityRoot,
			ToRoot:        testAuthorityRoot,
			Type:          assetcatalog.RelationshipRunsOn,
		}
		first, err := normalizeRelation(scope, relation, 11)
		if err != nil {
			t.Fatalf("normalizeRelation(first) error = %v", err)
		}
		next, err := normalizeRelation(scope, relation, 12)
		if err != nil {
			t.Fatalf("normalizeRelation(next) error = %v", err)
		}
		if first.Freshness.OrderSequence != 11 ||
			next.Freshness.OrderSequence != 12 {
			t.Fatalf("relation order sequences = %d/%d", first.Freshness.OrderSequence, next.Freshness.OrderSequence)
		}
		if first.Freshness.ProviderVersionSHA256 != next.Freshness.ProviderVersionSHA256 {
			t.Fatalf(
				"relation provider versions changed with checkpoint order: %q != %q",
				first.Freshness.ProviderVersionSHA256,
				next.Freshness.ProviderVersionSHA256,
			)
		}
	})
}

func TestNormalizeRejectsOutsideAuthorityRootCrossRootRelationAndDuplicateRoots(t *testing.T) {
	t.Parallel()

	scope := validNormalizationScope(t)
	outsideRoot := types.ManagedObjectReference{Type: "Folder", Value: "group-outside"}
	object := validVirtualMachineObject()
	object.AuthorityRoot = outsideRoot
	if got, err := normalizeObject(scope, object, 9); err == nil {
		t.Fatalf("normalizeObject() = %#v, want outside-root rejection", got)
	}

	relation := inventoryRelation{
		FromReference: types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
		ToReference:   types.ManagedObjectReference{Type: "HostSystem", Value: "host-21"},
		FromRoot:      testAuthorityRoot,
		ToRoot:        outsideRoot,
		Type:          assetcatalog.RelationshipRunsOn,
	}
	if got, err := normalizeRelation(scope, relation, 9); err == nil {
		t.Fatalf("normalizeRelation() = %#v, want cross-root rejection", got)
	}

	if got, err := NewAuthorityHandle(
		testInstanceUUID,
		testEnvironmentID,
		[]types.ManagedObjectReference{testAuthorityRoot, testAuthorityRoot},
	); err == nil {
		t.Fatalf("NewAuthorityHandle() = %#v, want duplicate-root rejection", got)
	}
}

func TestNormalizeRejectsOversizeSecretEndpointAndInvalidCapacityWithoutLeaking(t *testing.T) {
	t.Parallel()

	secret := "sk-" + strings.Repeat("a", 24)
	tests := []struct {
		name      string
		mutate    func(*inventoryObject)
		forbidden string
	}{
		{
			name: "oversize name",
			mutate: func(object *inventoryObject) {
				object.Name = strings.Repeat("n", 257)
			},
		},
		{
			name: "secret shaped name",
			mutate: func(object *inventoryObject) {
				object.Name = secret
			},
			forbidden: secret,
		},
		{
			name: "endpoint shaped name",
			mutate: func(object *inventoryObject) {
				object.Name = "https://vcenter.internal/sdk"
			},
			forbidden: "vcenter.internal",
		},
		{
			name: "IP shaped name",
			mutate: func(object *inventoryObject) {
				object.Name = "node-10.20.30.40"
			},
			forbidden: "10.20.30.40",
		},
		{
			name: "overlapping IPv4 shaped name",
			mutate: func(object *inventoryObject) {
				object.Name = "node-999.10.20.30.40"
			},
			forbidden: "10.20.30.40",
		},
		{
			name: "overlapping IPv6 shaped name",
			mutate: func(object *inventoryObject) {
				object.Name = "node-fffff:2001:db8::1"
			},
			forbidden: "2001:db8::1",
		},
		{
			name: "MAC shaped name",
			mutate: func(object *inventoryObject) {
				object.Name = "host-00:50:56:aa:bb:cc"
			},
			forbidden: "00:50:56:aa:bb:cc",
		},
		{
			name: "negative CPU",
			mutate: func(object *inventoryObject) {
				object.CPUCount = -1
			},
		},
		{
			name: "oversize memory",
			mutate: func(object *inventoryObject) {
				object.MemoryMB = maxMemoryMB + 1
			},
		},
		{
			name: "secret shaped MoRef",
			mutate: func(object *inventoryObject) {
				object.Reference.Value = "vm-" + secret
			},
			forbidden: secret,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			object := validVirtualMachineObject()
			test.mutate(&object)
			got, err := normalizeObject(validNormalizationScope(t), object, 10)
			if err == nil {
				t.Fatalf("normalizeObject() = %#v, want rejection", got)
			}
			if test.forbidden != "" && strings.Contains(err.Error(), test.forbidden) {
				t.Fatalf("normalization error leaked rejected value: %v", err)
			}
		})
	}
}

func TestNormalizeRelationUsesNamespacedMoRefsAndClosedProvenance(t *testing.T) {
	t.Parallel()

	scope := validNormalizationScope(t)
	got, err := normalizeRelation(scope, inventoryRelation{
		FromReference: types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
		ToReference:   types.ManagedObjectReference{Type: "HostSystem", Value: "host-21"},
		FromRoot:      testAuthorityRoot,
		ToRoot:        testAuthorityRoot,
		Type:          assetcatalog.RelationshipRunsOn,
	}, 11)
	if err != nil {
		t.Fatalf("normalizeRelation() error = %v", err)
	}
	if got.SourceEnvironmentID != testEnvironmentID ||
		got.TargetEnvironmentID != testEnvironmentID ||
		got.FromExternalID != "vsphere:"+testInstanceUUID+":VirtualMachine:vm-42" ||
		got.ToExternalID != "vsphere:"+testInstanceUUID+":HostSystem:host-21" ||
		got.Type != assetcatalog.RelationshipRunsOn ||
		got.ProviderPathCode != "VSPHERE_V1_RUNS_ON" ||
		got.CrossEnvironmentPolicyReferenceID != "" {
		t.Fatalf("normalized relation = %#v", got)
	}
	if err := assetdiscovery.ValidateFacts(
		nil,
		[]assetdiscovery.ObservedRelation{got},
		factPolicyForRelation(scope, got.Type),
	); err != nil {
		t.Fatalf("normalized relation violates fact contract: %v", err)
	}
}

func TestNormalizeContainsUsesClosedHierarchy(t *testing.T) {
	t.Parallel()

	valid := []inventoryRelation{
		{
			FromReference: types.ManagedObjectReference{Type: "Folder", Value: "group-v3"},
			ToReference:   types.ManagedObjectReference{Type: "Datacenter", Value: "datacenter-2"},
		},
		{
			FromReference: types.ManagedObjectReference{Type: "Datacenter", Value: "datacenter-2"},
			ToReference:   types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
		},
		{
			FromReference: types.ManagedObjectReference{Type: "ClusterComputeResource", Value: "domain-c7"},
			ToReference:   types.ManagedObjectReference{Type: "HostSystem", Value: "host-21"},
		},
		{
			FromReference: types.ManagedObjectReference{Type: "ResourcePool", Value: "resgroup-8"},
			ToReference:   types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
		},
	}
	for _, relation := range valid {
		relation.FromRoot = testAuthorityRoot
		relation.ToRoot = testAuthorityRoot
		relation.Type = assetcatalog.RelationshipContains
		if _, err := normalizeRelation(validNormalizationScope(t), relation, 12); err != nil {
			t.Fatalf("valid CONTAINS %#v rejected: %v", relation, err)
		}
	}

	for _, relation := range []inventoryRelation{
		{
			FromReference: types.ManagedObjectReference{Type: "ResourcePool", Value: "resgroup-8"},
			ToReference:   types.ManagedObjectReference{Type: "Datacenter", Value: "datacenter-2"},
		},
		{
			FromReference: types.ManagedObjectReference{Type: "ClusterComputeResource", Value: "domain-c7"},
			ToReference:   types.ManagedObjectReference{Type: "Datacenter", Value: "datacenter-2"},
		},
		{
			FromReference: types.ManagedObjectReference{Type: "Datastore", Value: "datastore-9"},
			ToReference:   types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
		},
	} {
		relation.FromRoot = testAuthorityRoot
		relation.ToRoot = testAuthorityRoot
		relation.Type = assetcatalog.RelationshipContains
		if got, err := normalizeRelation(validNormalizationScope(t), relation, 12); err == nil {
			t.Fatalf("invalid CONTAINS %#v normalized as %#v", relation, got)
		}
	}
}

func validNormalizationScope(t *testing.T) normalizationScope {
	t.Helper()
	authority, err := NewAuthorityHandle(
		testInstanceUUID,
		testEnvironmentID,
		[]types.ManagedObjectReference{testAuthorityRoot},
	)
	if err != nil {
		t.Fatalf("NewAuthorityHandle() error = %v", err)
	}
	return authority.normalizationScope()
}

func validVirtualMachineObject() inventoryObject {
	return inventoryObject{
		Reference:       types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
		AuthorityRoot:   testAuthorityRoot,
		Name:            "payments-api-01",
		GuestID:         "ubuntu64Guest",
		PowerState:      "poweredOn",
		ConnectionState: "connected",
		CPUCount:        4,
		MemoryMB:        8_192,
	}
}

func assertDocumentContainsNoForbiddenFields(t *testing.T, document []byte) {
	t.Helper()

	var fields map[string]any
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatalf("decode normalized document: %v", err)
	}
	for _, forbidden := range []string{
		"ip",
		"ip_address",
		"mac",
		"mac_address",
		"custom_attributes",
		"annotation",
		"alarm",
		"event",
		"endpoint",
		"credential",
		"secret",
		"session",
	} {
		if _, found := fields[forbidden]; found {
			t.Fatalf("normalized document contains forbidden field %q: %s", forbidden, document)
		}
	}
}
