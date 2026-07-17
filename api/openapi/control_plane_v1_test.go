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

func TestControlPlaneContractHasExactRoutes(t *testing.T) {
	raw, document := readControlPlaneContract(t)
	if document["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %#v, want 3.1.0", document["openapi"])
	}
	if document["jsonSchemaDialect"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("jsonSchemaDialect = %#v", document["jsonSchemaDialect"])
	}

	required := map[string][]string{
		"/api/v1/browser-config": {"get"},
		"/api/v1/session":        {"get"},
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
			"get", "post",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}": {
			"get",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:validate": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:publish": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}:disable": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}:sync": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/imports": {
			"post",
		},
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/ingestion-batches": {
			"post",
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

func TestControlPlaneSourceMutationAndIngestionRoutes(t *testing.T) {
	_, document := readControlPlaneContract(t)
	paths := mustMap(t, document["paths"], "#/paths")
	required := map[string]string{
		"/api/v1/workspaces/{workspace_id}/asset-sources":                                           "createAssetSource",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions":                     "createAssetSourceRevision",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:validate": "validateAssetSourceRevision",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:publish":  "publishAssetSourceRevision",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}:disable":                       "disableAssetSource",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}:sync":                          "syncAssetSource",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/imports":                       "createAssetSourceImport",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/ingestion-batches":             "createAssetSourceIngestionBatch",
	}
	for path, operationID := range required {
		pathItem, exists := paths[path]
		if !exists {
			t.Errorf("missing Source path %s", path)
			continue
		}
		operation := mustMap(t, mustMap(t, pathItem, path)["post"], path+" post")
		if got := operation["operationId"]; got != operationID {
			t.Errorf("POST %s operationId = %#v, want %q", path, got, operationID)
		}
		responses := mustMap(t, operation["responses"], path+" responses")
		if _, exists := responses["503"]; !exists {
			t.Errorf("POST %s lacks current fail-closed 503 response", path)
		}
	}
}

func TestControlPlaneSourceIngestionUsesOnlyMutualTLSAndClosedSchemas(t *testing.T) {
	_, document := readControlPlaneContract(t)
	components := mustMap(t, document["components"], "#/components")
	securitySchemes := mustMap(t, components["securitySchemes"], "#/components/securitySchemes")
	mutualTLS := mustMap(t, securitySchemes["mutualTLS"], "mutualTLS")
	if mutualTLS["type"] != "mutualTLS" {
		t.Fatalf("mutualTLS scheme = %#v", mutualTLS)
	}

	paths := mustMap(t, document["paths"], "#/paths")
	const ingestionPath = "/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/ingestion-batches"
	ingestion := mustMap(
		t,
		mustMap(t, paths[ingestionPath], ingestionPath)["post"],
		ingestionPath+" post",
	)
	security, ok := ingestion["security"].([]any)
	if !ok || len(security) != 1 {
		t.Fatalf("ingestion security = %#v", ingestion["security"])
	}
	requirement := mustMap(t, security[0], "ingestion security requirement")
	if len(requirement) != 1 {
		t.Fatalf("ingestion security requirement = %#v", requirement)
	}
	scopes, ok := requirement["mutualTLS"].([]any)
	if !ok || len(scopes) != 0 {
		t.Fatalf("ingestion mutualTLS scopes = %#v", requirement["mutualTLS"])
	}
	if _, hasOIDC := requirement["oidc"]; hasOIDC {
		t.Fatalf("ingestion security unexpectedly includes OIDC: %#v", requirement)
	}
	if body, exists := ingestion["requestBody"]; exists {
		t.Fatalf("Task 14 must not predeclare Task 16 ingestion body: %#v", body)
	}
	for _, operationID := range []string{
		"createAssetSource",
		"createAssetSourceRevision",
		"validateAssetSourceRevision",
		"publishAssetSourceRevision",
		"disableAssetSource",
		"syncAssetSource",
		"createAssetSourceImport",
	} {
		for path, rawPathItem := range paths {
			pathItem := mustMap(t, rawPathItem, path)
			post, exists := pathItem["post"]
			if !exists {
				continue
			}
			operation := mustMap(t, post, path+" post")
			if operation["operationId"] == operationID {
				if securityOverride, overridden := operation["security"]; overridden {
					t.Fatalf("%s security override = %#v, want inherited OIDC", operationID, securityOverride)
				}
			}
		}
	}

	schemas := mustMap(t, components["schemas"], "#/components/schemas")
	for _, name := range []string{
		"CreateAssetSourceRequest",
		"CreateAssetSourceRevisionRequest",
		"SourceReasonRequest",
		"EmptySourceRequest",
		"CreateAssetSourceImportRequest",
		"AssetSourceRevisionMutationResult",
		"AssetSourceMutationResult",
		"AssetSourceRunMutationResult",
	} {
		schema := mustMap(t, schemas[name], "#/components/schemas/"+name)
		if schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Errorf("%s is not a closed object: %#v", name, schema)
		}
	}
}

func TestControlPlaneSessionContractMatchesAuthenticatedPrincipal(t *testing.T) {
	_, document := readControlPlaneContract(t)
	paths := mustMap(t, document["paths"], "#/paths")
	sessionPath := mustMap(t, paths["/api/v1/session"], "#/paths/~1api~1v1~1session")
	session := mustMap(t, sessionPath["get"], "#/paths/~1api~1v1~1session/get")

	if got := session["operationId"]; got != "getSession" {
		t.Fatalf("session operationId = %#v, want getSession", got)
	}
	assertExactStrings(t, session["tags"], []string{"Browser"}, "session tags")
	if security, overridden := session["security"]; overridden {
		t.Fatalf("session security override = %#v, want inherited global OIDC security", security)
	}

	responses := mustMap(t, session["responses"], "session responses")
	wantResponses := map[string]string{
		"200": "#/components/responses/SessionOK",
		"401": "#/components/responses/Problem401",
		"503": "#/components/responses/Problem503",
	}
	if len(responses) != len(wantResponses) {
		t.Fatalf("session response count = %d, want %d", len(responses), len(wantResponses))
	}
	for status, wantReference := range wantResponses {
		response := mustMap(t, responses[status], "session response "+status)
		if got := response["$ref"]; got != wantReference {
			t.Fatalf("session response %s ref = %#v, want %q", status, got, wantReference)
		}
	}

	sessionOK := resolveControlPlaneResponse(
		t,
		document,
		mustMap(t, responses["200"], "session response 200"),
	)
	content := mustMap(t, sessionOK["content"], "SessionOK content")
	mediaType := mustMap(t, content["application/json"], "SessionOK application/json")
	responseSchema := mustMap(t, mediaType["schema"], "SessionOK schema")
	if got := responseSchema["$ref"]; got != "#/components/schemas/Session" {
		t.Fatalf("SessionOK schema ref = %#v, want Session", got)
	}

	components := mustMap(t, document["components"], "#/components")
	schemas := mustMap(t, components["schemas"], "#/components/schemas")
	schema := mustMap(t, schemas["Session"], "#/components/schemas/Session")
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("Session schema is not a closed object: %#v", schema)
	}
	fields := []string{
		"subject",
		"username",
		"roles",
		"workspace_ids",
		"environment_ids",
		"service_ids",
		"authenticated_at",
		"expires_at",
	}
	assertExactStrings(t, schema["required"], fields, "Session required")
	properties := mustMap(t, schema["properties"], "Session properties")
	assertExactMapKeys(t, properties, fields, "Session properties")

	subject := mustMap(t, properties["subject"], "Session subject")
	if subject["type"] != "string" || subject["minLength"] != 1 || subject["maxLength"] != 256 ||
		subject["pattern"] != "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$" {
		t.Fatalf("Session subject schema = %#v", subject)
	}
	username := mustMap(t, properties["username"], "Session username")
	if username["type"] != "string" || username["maxLength"] != 256 {
		t.Fatalf("Session username schema = %#v", username)
	}
	if minimum, present := username["minLength"]; present {
		t.Fatalf("Session username minLength = %#v, want absent because username may be empty", minimum)
	}

	roles := mustMap(t, properties["roles"], "Session roles")
	if roles["type"] != "array" || roles["minItems"] != 1 || roles["maxItems"] != 6 ||
		roles["uniqueItems"] != true {
		t.Fatalf("Session roles schema = %#v", roles)
	}
	roleItems := mustMap(t, roles["items"], "Session role items")
	if roleItems["type"] != "string" {
		t.Fatalf("Session role item type = %#v, want string", roleItems["type"])
	}
	assertExactStrings(
		t,
		roleItems["enum"],
		[]string{"VIEWER", "SRE", "SERVICE_OWNER", "APPROVER", "AUDITOR", "ADMIN"},
		"Session role enum",
	)

	assertSessionScopeArray(t, properties, "workspace_ids", 1, 1000)
	assertSessionScopeArray(t, properties, "environment_ids", 1, 100)
	assertSessionScopeArray(t, properties, "service_ids", 0, 5000)

	for _, field := range []string{"authenticated_at", "expires_at"} {
		timestamp := mustMap(t, properties[field], "Session "+field)
		if timestamp["type"] != "string" || timestamp["format"] != "date-time" {
			t.Fatalf("Session %s schema = %#v", field, timestamp)
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
	oidcSecurity := mustMap(t, globalSecurity[0], "global security requirement")
	if len(oidcSecurity) != 1 {
		t.Fatalf("global security requirement = %#v, want only oidc", oidcSecurity)
	}
	oidcScopes, ok := oidcSecurity["oidc"].([]any)
	if !ok || len(oidcScopes) != 0 {
		t.Fatalf("global oidc scopes = %#v, want []", oidcSecurity["oidc"])
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

func assertExactStrings(t *testing.T, value any, want []string, path string) {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %#v, want string array", path, value)
	}
	if len(values) != len(want) {
		t.Fatalf("%s length = %d, want %d", path, len(values), len(want))
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, item := range want {
		wantSet[item] = struct{}{}
	}
	for _, raw := range values {
		item, ok := raw.(string)
		if !ok {
			t.Fatalf("%s entry = %#v, want string", path, raw)
		}
		if _, exists := wantSet[item]; !exists {
			t.Fatalf("%s contains unexpected value %q", path, item)
		}
		delete(wantSet, item)
	}
	if len(wantSet) != 0 {
		t.Fatalf("%s is missing values %#v", path, wantSet)
	}
}

func assertExactMapKeys(t *testing.T, values map[string]any, want []string, path string) {
	t.Helper()
	if len(values) != len(want) {
		t.Fatalf("%s count = %d, want %d", path, len(values), len(want))
	}
	for _, key := range want {
		if _, ok := values[key]; !ok {
			t.Fatalf("%s lacks %q", path, key)
		}
	}
}

func assertSessionScopeArray(
	t *testing.T,
	properties map[string]any,
	field string,
	minimum int,
	maximum int,
) {
	t.Helper()
	schema := mustMap(t, properties[field], "Session "+field)
	if schema["type"] != "array" || schema["maxItems"] != maximum || schema["uniqueItems"] != true {
		t.Fatalf("Session %s schema = %#v", field, schema)
	}
	if minimum == 0 {
		if value, present := schema["minItems"]; present {
			t.Fatalf("Session %s minItems = %#v, want absent", field, value)
		}
	} else if schema["minItems"] != minimum {
		t.Fatalf("Session %s minItems = %#v, want %d", field, schema["minItems"], minimum)
	}
	items := mustMap(t, schema["items"], "Session "+field+" items")
	if items["type"] != "string" || items["minLength"] != 1 || items["maxLength"] != 256 ||
		items["pattern"] != "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$" {
		t.Fatalf("Session %s item schema = %#v", field, items)
	}
}
