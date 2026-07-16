package openapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/httpapi"
	"go.yaml.in/yaml/v3"
)

func TestControlPlaneContractHasExactAssetRoutes(t *testing.T) {
	raw, document := readControlPlaneContract(t)
	if document["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %#v, want 3.1.0", document["openapi"])
	}
	if document["jsonSchemaDialect"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("jsonSchemaDialect = %#v", document["jsonSchemaDialect"])
	}

	required := map[string][]string{
		"/api/v1/browser-config": {"get"},
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets": {
			"get", "post",
		},
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}": {
			"get", "patch",
		},
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}:quarantine": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}:retire": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/asset-relations": {
			"get",
		},
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/service-asset-bindings": {
			"get", "post",
		},
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/service-asset-bindings/{binding_id}": {
			"delete",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources": {
			"get",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}": {
			"get",
		},
		"/api/v1/workspaces/{workspace_id}/asset-source-runs/{run_id}": {
			"get",
		},
		"/api/v1/workspaces/{workspace_id}/asset-conflicts": {
			"get",
		},
		"/api/v1/workspaces/{workspace_id}/asset-conflicts/{conflict_id}:resolve": {
			"post",
		},
	}
	paths := mustMap(t, document["paths"], "#/paths")
	if len(paths) != len(required) {
		t.Fatalf("path count = %d, want %d", len(paths), len(required))
	}
	operationIDs := make(map[string]string)
	for path, methods := range required {
		pathItem := mustMap(t, paths[path], "#/paths/"+path)
		for _, method := range methods {
			operation := mustMap(t, pathItem[method], "#/paths/"+path+"/"+method)
			operationID, ok := operation["operationId"].(string)
			if !ok || operationID == "" {
				t.Fatalf("%s %s has no operationId", method, path)
			}
			if previous, duplicate := operationIDs[operationID]; duplicate {
				t.Fatalf("operationId %q reused by %s and %s %s", operationID, previous, method, path)
			}
			operationIDs[operationID] = method + " " + path
		}
	}

	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		"secret", "password", "access_token", "refresh_token", "private_key",
		"dsn", "connection_string", "raw_payload", "normalized_document",
		"arbitrary_header", "command_text", "sql_text", "request_body",
	} {
		if strings.Contains(lower, forbidden+":") {
			t.Errorf("browser contract contains forbidden field %s", forbidden)
		}
	}
}

func TestControlPlaneContractClosesObjectsAndUsesProblemResponses(t *testing.T) {
	_, document := readControlPlaneContract(t)
	assertControlPlaneClosedObjects(t, "#", document)

	paths := mustMap(t, document["paths"], "#/paths")
	for path, rawPathItem := range paths {
		pathItem := mustMap(t, rawPathItem, "#/paths/"+path)
		for method, rawOperation := range pathItem {
			if method == "parameters" {
				continue
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				continue
			}
			responses := mustMap(t, operation["responses"], "#/paths/"+path+"/"+method+"/responses")
			for status, rawResponse := range responses {
				if !strings.HasPrefix(status, "4") && !strings.HasPrefix(status, "5") {
					continue
				}
				response := mustMap(t, rawResponse, "#/paths/"+path+"/"+method+"/responses/"+status)
				response = resolveControlPlaneResponse(t, document, response)
				content := mustMap(t, response["content"], "#/paths/"+path+"/"+method+"/responses/"+status+"/content")
				problem := mustMap(t, content["application/problem+json"], "problem content")
				schema := mustMap(t, problem["schema"], "problem schema")
				if schema["$ref"] != "#/components/schemas/Problem" {
					t.Fatalf("%s %s response %s does not reference Problem: %#v", method, path, status, schema)
				}
			}
		}
	}
}

func resolveControlPlaneResponse(
	t *testing.T,
	document map[string]any,
	response map[string]any,
) map[string]any {
	t.Helper()
	reference, ok := response["$ref"].(string)
	if !ok {
		return response
	}
	const prefix = "#/components/responses/"
	if !strings.HasPrefix(reference, prefix) {
		t.Fatalf("unsupported response reference %q", reference)
	}
	components := mustMap(t, document["components"], "#/components")
	responses := mustMap(t, components["responses"], "#/components/responses")
	return mustMap(t, responses[strings.TrimPrefix(reference, prefix)], reference)
}

func TestControlPlaneBrowserConfigIsAnonymousAndAllOtherOperationsAreSecured(t *testing.T) {
	_, document := readControlPlaneContract(t)
	globalSecurity, ok := document["security"].([]any)
	if !ok || len(globalSecurity) != 1 {
		t.Fatalf("global security = %#v", document["security"])
	}
	paths := mustMap(t, document["paths"], "#/paths")
	browser := mustMap(t, mustMap(t, paths["/api/v1/browser-config"], "browser path")["get"], "browser get")
	browserSecurity, ok := browser["security"].([]any)
	if !ok || len(browserSecurity) != 0 {
		t.Fatalf("browser-config security = %#v, want []", browser["security"])
	}
}

func TestControlPlaneContractDigestMatchesBrowserBuildMetadata(t *testing.T) {
	raw, _ := readControlPlaneContract(t)
	digest := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(digest[:])
	if got := httpapi.ControlPlaneContractDigest(); got != want {
		t.Fatalf("ControlPlaneContractDigest() = %q, want %q", got, want)
	}
}

func TestControlPlaneObjectSchemasRequireEveryDeclaredProperty(t *testing.T) {
	_, document := readControlPlaneContract(t)
	components := mustMap(t, document["components"], "#/components")
	schemas := mustMap(t, components["schemas"], "#/components/schemas")
	for name, rawSchema := range schemas {
		schema := mustMap(t, rawSchema, "#/components/schemas/"+name)
		if schema["type"] != "object" {
			continue
		}
		properties := mustMap(t, schema["properties"], "#/components/schemas/"+name+"/properties")
		required, ok := schema["required"].([]any)
		if !ok {
			t.Errorf("%s required = %#v", name, schema["required"])
			continue
		}
		requiredSet := make(map[string]struct{}, len(required))
		for _, rawName := range required {
			propertyName, ok := rawName.(string)
			if !ok {
				t.Errorf("%s required entry = %#v", name, rawName)
				continue
			}
			requiredSet[propertyName] = struct{}{}
		}
		if len(requiredSet) != len(properties) {
			t.Errorf("%s requires %d of %d properties", name, len(requiredSet), len(properties))
		}
		for propertyName := range properties {
			if _, ok := requiredSet[propertyName]; !ok {
				t.Errorf("%s property %s is not required", name, propertyName)
			}
		}
	}
}

func TestEveryControlPlaneResponseDeclaresSecurityHeaders(t *testing.T) {
	_, document := readControlPlaneContract(t)
	paths := mustMap(t, document["paths"], "#/paths")
	for path, rawPathItem := range paths {
		pathItem := mustMap(t, rawPathItem, "#/paths/"+path)
		for method, rawOperation := range pathItem {
			if method == "parameters" {
				continue
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				continue
			}
			responses := mustMap(t, operation["responses"], "#/paths/"+path+"/"+method+"/responses")
			for status, rawResponse := range responses {
				response := resolveControlPlaneResponse(
					t, document, mustMap(t, rawResponse, method+" "+path+" "+status),
				)
				headers := mustMap(t, response["headers"], method+" "+path+" "+status+"/headers")
				for _, header := range []string{
					"Cache-Control", "X-Content-Type-Options", "Referrer-Policy", "X-Trace-ID",
				} {
					if _, ok := headers[header]; !ok {
						t.Errorf("%s %s response %s lacks %s", method, path, status, header)
					}
				}
			}
		}
	}
}

func readControlPlaneContract(t *testing.T) ([]byte, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("control-plane-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return raw, document
}

func assertControlPlaneClosedObjects(t *testing.T, path string, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if typed["type"] == "object" {
			if additional, ok := typed["additionalProperties"]; !ok || additional != false {
				t.Errorf("%s object is not closed: additionalProperties=%#v", path, additional)
			}
		}
		for key, child := range typed {
			assertControlPlaneClosedObjects(t, path+"/"+key, child)
		}
	case []any:
		for index, child := range typed {
			assertControlPlaneClosedObjects(t, path+"/"+string(rune(index)), child)
		}
	}
}

func mustMap(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", path, value)
	}
	return result
}
