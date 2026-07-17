package externalcmdb

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"go.yaml.in/yaml/v3"
)

func TestRequestsExposeNoCallerSelectedWireSurface(t *testing.T) {
	t.Parallel()

	for _, requestType := range []reflect.Type{
		reflect.TypeOf(discoverysource.ValidationRequest{}),
		reflect.TypeOf(discoverysource.DiscoverRequest{}),
	} {
		for _, forbidden := range []string{"URL", "Endpoint", "Path", "Method", "Header", "Body", "Query"} {
			if _, ok := requestType.FieldByName(forbidden); ok {
				t.Fatalf("%s exposes forbidden wire field %s", requestType.Name(), forbidden)
			}
		}
	}
}

func TestValidateCapabilitiesRequiresPinnedAuthorityProtocolAndExactReadOnlyPermissions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)
	valid := catalogCapabilities{
		ProtocolVersion:   catalogProtocolVersion,
		AuthorityID:       "cmdb-production-01",
		SnapshotEpoch:     "snapshot-0001",
		MaxPageSize:       500,
		SupportsDelta:     true,
		SupportsTombstone: true,
		ServerTime:        now,
		Permissions:       []string{"assets.read", "relations.read"},
	}

	tests := []struct {
		name       string
		mutate     func(*catalogCapabilities)
		wantPassed bool
		wantCode   string
	}{
		{
			name:       "accepted",
			mutate:     func(*catalogCapabilities) {},
			wantPassed: true,
			wantCode:   "CAPABILITIES_ACCEPTED",
		},
		{
			name: "authority mismatch",
			mutate: func(capabilities *catalogCapabilities) {
				capabilities.AuthorityID = "cmdb-staging-01"
			},
			wantCode: "AUTHORITY_MISMATCH",
		},
		{
			name: "protocol mismatch",
			mutate: func(capabilities *catalogCapabilities) {
				capabilities.ProtocolVersion = "cmdb-catalog/v2"
			},
			wantCode: "PROTOCOL_MISMATCH",
		},
		{
			name: "write permission",
			mutate: func(capabilities *catalogCapabilities) {
				capabilities.Permissions = append(capabilities.Permissions, "assets.write")
			},
			wantCode: "PERMISSION_SCOPE_MISMATCH",
		},
		{
			name: "missing relation read",
			mutate: func(capabilities *catalogCapabilities) {
				capabilities.Permissions = []string{"assets.read"}
			},
			wantCode: "PERMISSION_SCOPE_MISMATCH",
		},
		{
			name: "snapshot endpoint",
			mutate: func(capabilities *catalogCapabilities) {
				capabilities.SnapshotEpoch = "https://db.internal:5432/snapshot"
			},
			wantCode: "CAPABILITY_SCHEMA_MISMATCH",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			capabilities := valid
			capabilities.Permissions = append([]string(nil), valid.Permissions...)
			test.mutate(&capabilities)

			got := validateCapabilities(capabilities, "cmdb-production-01", now)
			if got.Passed != test.wantPassed || got.Code != test.wantCode {
				t.Fatalf("validateCapabilities() = %#v, want passed=%t code=%q", got, test.wantPassed, test.wantCode)
			}
			if strings.Contains(got.Code, "db.internal") || strings.Contains(got.Code, "5432") {
				t.Fatalf("capability rejection leaked endpoint: %#v", got)
			}
		})
	}
}

func TestStrictDecoderRejectsEveryMissingRequiredWireField(t *testing.T) {
	t.Parallel()

	capabilitiesJSON := `{
		"protocol_version":"cmdb-catalog/v1",
		"authority_id":"cmdb-production-01",
		"snapshot_epoch":"snapshot-0001",
		"max_page_size":500,
		"supports_delta":true,
		"supports_tombstone":true,
		"server_time":"2026-07-17T09:30:00Z",
		"permissions":["assets.read","relations.read"]
	}`
	for _, field := range []string{
		"protocol_version", "authority_id", "snapshot_epoch", "max_page_size",
		"supports_delta", "supports_tombstone", "server_time", "permissions",
	} {
		field := field
		t.Run("capabilities_"+field, func(t *testing.T) {
			t.Parallel()

			payload := mutateWireJSON(t, capabilitiesJSON, func(root map[string]any) {
				delete(root, field)
			})
			var destination catalogCapabilities
			if err := decodeStrictJSON(bytes.NewReader(payload), maxCapabilitiesBodyBytes, &destination); err == nil {
				t.Fatalf("missing %s accepted: %#v", field, destination)
			}
		})
	}

	assetPageJSON := `{
		"items":[{
			"external_id":"vm-0001",
			"type_code":"LINUX_VM",
			"display_name":"payments-api-01",
			"object_revision":7,
			"updated_at":"2026-07-17T09:30:00.123456Z",
			"deleted":false,
			"tombstone_reason":"",
			"attributes":{}
		}],
		"next_cursor":"",
		"snapshot_epoch":"snapshot-0001",
		"final_page":true,
		"complete_snapshot":true
	}`
	for _, field := range []string{
		"external_id", "type_code", "display_name", "object_revision",
		"updated_at", "deleted", "tombstone_reason", "attributes",
	} {
		field := field
		t.Run("asset_"+field, func(t *testing.T) {
			t.Parallel()

			payload := mutateWireJSON(t, assetPageJSON, func(root map[string]any) {
				delete(firstWireItem(t, root), field)
			})
			var destination catalogPage[catalogAsset]
			if err := decodeStrictJSON(bytes.NewReader(payload), maxPageBodyBytes, &destination); err == nil {
				t.Fatalf("missing %s accepted: %#v", field, destination)
			}
		})
	}
	for _, field := range []string{"items", "next_cursor", "snapshot_epoch", "final_page", "complete_snapshot"} {
		field := field
		t.Run("asset_page_"+field, func(t *testing.T) {
			t.Parallel()

			payload := mutateWireJSON(t, assetPageJSON, func(root map[string]any) {
				delete(root, field)
			})
			var destination catalogPage[catalogAsset]
			if err := decodeStrictJSON(bytes.NewReader(payload), maxPageBodyBytes, &destination); err == nil {
				t.Fatalf("missing %s accepted: %#v", field, destination)
			}
		})
	}

	relationPageJSON := `{
		"items":[{
			"external_id":"rel-0001",
			"from_external_id":"vm-0001",
			"to_external_id":"service-0001",
			"type_code":"DEPENDS_ON",
			"object_revision":11,
			"updated_at":"2026-07-17T09:30:00.654321Z",
			"deleted":false
		}],
		"next_cursor":"",
		"snapshot_epoch":"snapshot-0001",
		"final_page":true,
		"complete_snapshot":true
	}`
	for _, field := range []string{
		"external_id", "from_external_id", "to_external_id", "type_code",
		"object_revision", "updated_at", "deleted",
	} {
		field := field
		t.Run("relation_"+field, func(t *testing.T) {
			t.Parallel()

			payload := mutateWireJSON(t, relationPageJSON, func(root map[string]any) {
				delete(firstWireItem(t, root), field)
			})
			var destination catalogPage[catalogRelation]
			if err := decodeStrictJSON(bytes.NewReader(payload), maxPageBodyBytes, &destination); err == nil {
				t.Fatalf("missing %s accepted: %#v", field, destination)
			}
		})
	}
}

func TestStrictDecoderRejectsInvalidUTF8NullAndNonUTCMicrosecondTime(t *testing.T) {
	t.Parallel()

	valid := `{
		"protocol_version":"cmdb-catalog/v1",
		"authority_id":"cmdb-production-01",
		"snapshot_epoch":"snapshot-0001",
		"max_page_size":500,
		"supports_delta":true,
		"supports_tombstone":true,
		"server_time":"2026-07-17T09:30:00Z",
		"permissions":["assets.read","relations.read"]
	}`
	invalidUTF8 := bytes.Replace(
		[]byte(valid),
		[]byte("cmdb-production-01"),
		[]byte{'c', 'm', 'd', 'b', '-', 0xff},
		1,
	)
	var capabilities catalogCapabilities
	if err := decodeStrictJSON(bytes.NewReader(invalidUTF8), maxCapabilitiesBodyBytes, &capabilities); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
	for _, timestamp := range []string{
		"2026-07-17T09:30:00+00:00",
		"2026-07-17T09:30:00.1234567Z",
	} {
		timestamp := timestamp
		t.Run(timestamp, func(t *testing.T) {
			t.Parallel()

			payload := mutateWireJSON(t, valid, func(root map[string]any) {
				root["server_time"] = timestamp
			})
			var destination catalogCapabilities
			if err := decodeStrictJSON(bytes.NewReader(payload), maxCapabilitiesBodyBytes, &destination); err == nil {
				t.Fatalf("timestamp %q was accepted", timestamp)
			}
		})
	}

	assetPageJSON := `{
		"items":[{
			"external_id":"vm-0001",
			"type_code":"LINUX_VM",
			"display_name":"payments-api-01",
			"object_revision":7,
			"updated_at":"2026-07-17T09:30:00Z",
			"deleted":false,
			"tombstone_reason":"",
			"attributes":{}
		}],
		"next_cursor":"",
		"snapshot_epoch":"snapshot-0001",
		"final_page":true,
		"complete_snapshot":true
	}`
	nullAttributes := mutateWireJSON(t, assetPageJSON, func(root map[string]any) {
		firstWireItem(t, root)["attributes"] = nil
	})
	var page catalogPage[catalogAsset]
	if err := decodeStrictJSON(bytes.NewReader(nullAttributes), maxPageBodyBytes, &page); err == nil {
		t.Fatal("null required attributes were accepted")
	}
	for _, timestamp := range []string{
		"2026-07-17T09:30:00+00:00",
		"2026-07-17T09:30:00.1234567Z",
	} {
		payload := mutateWireJSON(t, assetPageJSON, func(root map[string]any) {
			firstWireItem(t, root)["updated_at"] = timestamp
		})
		var destination catalogPage[catalogAsset]
		if err := decodeStrictJSON(bytes.NewReader(payload), maxPageBodyBytes, &destination); err == nil {
			t.Fatalf("asset timestamp %q was accepted", timestamp)
		}
	}
}

func TestStrictDecoderRejectsCaseFoldedAliasesAtRootAndNestedObjects(t *testing.T) {
	t.Parallel()

	capabilitiesJSON := `{
		"protocol_version":"cmdb-catalog/v1",
		"authority_id":"cmdb-production-01",
		"snapshot_epoch":"snapshot-0001",
		"max_page_size":500,
		"supports_delta":true,
		"supports_tombstone":true,
		"server_time":"2026-07-17T09:30:00Z",
		"permissions":["assets.read","relations.read"]
	}`
	rootAlias := mutateWireJSON(t, capabilitiesJSON, func(root map[string]any) {
		root["Authority_ID"] = "alias-must-not-win"
	})
	var capabilities catalogCapabilities
	if err := decodeStrictJSON(bytes.NewReader(rootAlias), maxCapabilitiesBodyBytes, &capabilities); err == nil {
		t.Fatalf("case-folded root alias was accepted: %#v", capabilities)
	}

	assetPageJSON := `{
		"items":[{
			"external_id":"vm-0001",
			"type_code":"LINUX_VM",
			"display_name":"payments-api-01",
			"object_revision":7,
			"updated_at":"2026-07-17T09:30:00Z",
			"deleted":false,
			"tombstone_reason":"",
			"attributes":{}
		}],
		"next_cursor":"",
		"snapshot_epoch":"snapshot-0001",
		"final_page":true,
		"complete_snapshot":true
	}`
	nestedAlias := mutateWireJSON(t, assetPageJSON, func(root map[string]any) {
		firstWireItem(t, root)["Display_Name"] = "alias-must-not-win"
	})
	var page catalogPage[catalogAsset]
	if err := decodeStrictJSON(bytes.NewReader(nestedAlias), maxPageBodyBytes, &page); err == nil {
		t.Fatalf("case-folded nested alias was accepted: %#v", page)
	}
}

func TestExternalCMDBOpenAPIContractIsClosedAndMatchesWireTypes(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not return the contract test path")
	}
	contractPath := filepath.Clean(filepath.Join(
		filepath.Dir(currentFile),
		"..", "..", "..",
		"api", "openapi", "external-cmdb-catalog-v1.yaml",
	))
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read external CMDB OpenAPI: %v", err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse external CMDB OpenAPI: %v", err)
	}
	if document["openapi"] != "3.1.0" ||
		document["jsonSchemaDialect"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("OpenAPI dialect = %#v/%#v", document["openapi"], document["jsonSchemaDialect"])
	}

	strictHTTP := contractMap(t, document["x-aiops-strict-http"], "x-aiops-strict-http")
	for _, field := range []string{
		"environment_proxy",
		"follow_redirects",
	} {
		if strictHTTP[field] != false {
			t.Errorf("%s = %#v, want false", field, strictHTTP[field])
		}
	}
	for _, field := range []string{
		"reject_duplicate_json_keys",
		"reject_unknown_json_fields",
		"reject_trailing_json_values",
		"reject_executable_text",
	} {
		if strictHTTP[field] != true {
			t.Errorf("%s = %#v, want true", field, strictHTTP[field])
		}
	}
	if strictHTTP["tls_min_version"] != "1.3" ||
		strictHTTP["max_response_header_bytes"] != 65536 ||
		strictHTTP["request_timeout_seconds"] != 15 {
		t.Errorf("strict transport limits = %#v", strictHTTP)
	}

	paths := contractMap(t, document["paths"], "paths")
	wantPaths := []string{capabilitiesPath, assetsPath, relationsPath}
	gotPaths := make([]string, 0, len(paths))
	for path := range paths {
		gotPaths = append(gotPaths, path)
	}
	slices.Sort(gotPaths)
	slices.Sort(wantPaths)
	if !slices.Equal(gotPaths, wantPaths) {
		t.Fatalf("paths = %v, want %v", gotPaths, wantPaths)
	}
	for _, path := range wantPaths {
		pathItem := contractMap(t, paths[path], "paths."+path)
		if len(pathItem) != 1 {
			t.Fatalf("%s exposes non-GET surface: %#v", path, pathItem)
		}
		operation := contractMap(t, pathItem["get"], "paths."+path+".get")
		if _, present := operation["requestBody"]; present {
			t.Fatalf("GET %s exposes requestBody", path)
		}
		if _, present := operation["operationId"]; !present {
			t.Fatalf("GET %s has no operationId", path)
		}
	}

	components := contractMap(t, document["components"], "components")
	schemas := contractMap(t, components["schemas"], "components.schemas")
	assertWireSchemaMatchesType(t, schemas, "CatalogCapabilities", reflect.TypeOf(catalogCapabilities{}))
	assertWireSchemaMatchesType(t, schemas, "CatalogAsset", reflect.TypeOf(catalogAsset{}))
	assertWireSchemaMatchesType(t, schemas, "CatalogRelation", reflect.TypeOf(catalogRelation{}))
	assertWireSchemaFields(t, schemas, "AssetPage", []string{
		"complete_snapshot", "final_page", "items", "next_cursor", "snapshot_epoch",
	})
	assertWireSchemaFields(t, schemas, "RelationPage", []string{
		"complete_snapshot", "final_page", "items", "next_cursor", "snapshot_epoch",
	})
	for _, schemaName := range []string{
		"CatalogCapabilities", "CatalogAsset", "CatalogRelation", "AssetPage", "RelationPage", "AssetAttributes",
	} {
		schema := contractMap(t, schemas[schemaName], "components.schemas."+schemaName)
		if schema["additionalProperties"] != false {
			t.Errorf("%s additionalProperties = %#v, want false", schemaName, schema["additionalProperties"])
		}
	}

	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		"password:", "private_key:", "client_secret:", "access_token:", "raw_payload:",
		"endpoint:", "arbitrary_header:", "request_body:", "command:", "sql:",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("OpenAPI contains forbidden field surface %q", forbidden)
		}
	}
}

func assertWireSchemaMatchesType(t *testing.T, schemas map[string]any, name string, typ reflect.Type) {
	t.Helper()

	fields := make([]string, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		tag := strings.Split(typ.Field(index).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			t.Fatalf("%s.%s has invalid JSON tag %q", typ.Name(), typ.Field(index).Name, tag)
		}
		fields = append(fields, tag)
	}
	assertWireSchemaFields(t, schemas, name, fields)
}

func assertWireSchemaFields(t *testing.T, schemas map[string]any, name string, want []string) {
	t.Helper()

	schema := contractMap(t, schemas[name], "components.schemas."+name)
	properties := contractMap(t, schema["properties"], "components.schemas."+name+".properties")
	required, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("%s.required = %#v", name, schema["required"])
	}
	gotProperties := make([]string, 0, len(properties))
	for field := range properties {
		gotProperties = append(gotProperties, field)
	}
	gotRequired := make([]string, 0, len(required))
	for _, value := range required {
		field, ok := value.(string)
		if !ok {
			t.Fatalf("%s.required contains %#v", name, value)
		}
		gotRequired = append(gotRequired, field)
	}
	slices.Sort(gotProperties)
	slices.Sort(gotRequired)
	slices.Sort(want)
	if !slices.Equal(gotProperties, want) || !slices.Equal(gotRequired, want) {
		t.Fatalf("%s fields properties=%v required=%v want=%v", name, gotProperties, gotRequired, want)
	}
}

func contractMap(t *testing.T, value any, path string) map[string]any {
	t.Helper()

	mapped, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", path, value)
	}
	return mapped
}

func mutateWireJSON(t *testing.T, raw string, mutate func(map[string]any)) []byte {
	t.Helper()

	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatalf("decode wire fixture: %v", err)
	}
	mutate(root)
	payload, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("encode wire fixture: %v", err)
	}
	return payload
}

func firstWireItem(t *testing.T, root map[string]any) map[string]any {
	t.Helper()

	items, ok := root["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("wire fixture items = %#v", root["items"])
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("wire fixture item = %#v", items[0])
	}
	return item
}
