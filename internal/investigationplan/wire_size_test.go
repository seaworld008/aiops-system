package investigationplan

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestManifestWireCounterMatchesEncodingJSONExactly(t *testing.T) {
	definition := Definition{
		RegistryDigest: "digest\\\"<>&\u2028\u2029",
		Profiles: []ProfileDefinition{{
			Scope: Scope{
				TenantID: "tenant", WorkspaceID: "workspace",
				EnvironmentID: "environment", ServiceID: "service",
			},
			Match: MatchDefinition{
				IntegrationID: "integration", Provider: "provider",
				Labels: []LabelMatch{{Key: "label", Value: "slash\\quote\"<>&\u2028\u2029"}},
			},
			Tasks: []TaskDefinition{{
				Key: "task", ConnectorID: "connector", Operation: "operation",
				Input: json.RawMessage(`{"value":"<>&\u2028\u2029"}`),
			}},
		}},
	}
	encoded, err := json.Marshal(manifestDocument{
		SchemaVersion: ManifestSchemaVersion, RegistryDigest: definition.RegistryDigest,
		Profiles: definition.Profiles,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	counted, overflow, err := countManifestWire(definition, math.MaxInt)
	if err != nil || overflow || counted != len(encoded) {
		t.Fatalf("countManifestWire() = (%d, %t, %v), encoded bytes = %d", counted, overflow, err, len(encoded))
	}
}

func TestManifestWireCounterRejectsHugeInvalidStringByLowerBound(t *testing.T) {
	definition := Definition{RegistryDigest: strings.Repeat("x", MaximumDefinitionBytes) + string([]byte{0xff})}
	_, overflow, err := countManifestWire(definition, MaximumDefinitionBytes)
	if err != nil || !overflow {
		t.Fatalf("countManifestWire() overflow = %t, error = %v; want O(1) overflow rejection", overflow, err)
	}
}
