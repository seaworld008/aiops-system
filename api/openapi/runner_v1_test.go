package openapi_test

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestRunnerV1Contract(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("runner-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("runner OpenAPI is not strict JSON: %v", err)
	}
	if bytes.Contains(raw, []byte(`"writeOnly"`)) {
		t.Fatal("response-only Runner secret/token fields must not be marked writeOnly")
	}
	if document["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %#v, want 3.1.0", document["openapi"])
	}
	strictHTTP := object(t, document["x-aiops-strict-http"], "x-aiops-strict-http")
	for _, name := range []string{
		"reject_duplicate_json_keys", "reject_unknown_json_fields", "reject_trailing_json_values",
		"reject_content_encoding", "reject_identity_headers", "all_responses_no_store", "all_responses_nosniff",
	} {
		if strictHTTP[name] != true {
			t.Errorf("strict HTTP contract %s = %#v, want true", name, strictHTTP[name])
		}
	}
	paths := object(t, document["paths"], "paths")
	want := []string{
		"/runner/v1/identity",
		"/runner/v1/jobs:lease",
		"/runner/v1/jobs/{job_id}:credential-anchor",
		"/runner/v1/jobs/{job_id}:start",
		"/runner/v1/jobs/{job_id}:heartbeat",
		"/runner/v1/jobs/{job_id}:release",
		"/runner/v1/jobs/{job_id}:complete",
		"/runner/v1/revocations:lease",
		"/runner/v1/revocations/{revocation_id}:heartbeat",
		"/runner/v1/revocations/{revocation_id}:complete",
	}
	got := make([]string, 0, len(paths))
	for path := range paths {
		got = append(got, path)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("paths = %v, want %v", got, want)
		}
	}

	components := object(t, document["components"], "components")
	securitySchemes := object(t, components["securitySchemes"], "components.securitySchemes")
	for _, name := range []string{"mutualTLS", "jobLease", "revocationLease"} {
		if _, ok := securitySchemes[name]; !ok {
			t.Errorf("missing security scheme %s", name)
		}
	}
	if object(t, securitySchemes["mutualTLS"], "mutualTLS")["type"] != "mutualTLS" {
		t.Error("mutualTLS scheme is not OpenAPI mutualTLS")
	}
	for _, name := range []string{"jobLease", "revocationLease"} {
		scheme := object(t, securitySchemes[name], name)
		if scheme["type"] != "apiKey" || scheme["in"] != "header" || scheme["name"] != "Authorization" {
			t.Errorf("%s = %#v, want Authorization header apiKey", name, scheme)
		}
	}
	assertOperationContracts(t, document, paths)
	assertResponseHeaders(t, document, paths)
	schemas := object(t, components["schemas"], "components.schemas")
	for _, name := range []string{
		"Problem", "RunnerIdentityResponse", "JobLeaseRequest", "JobLeaseResponse", "JobStartRequest",
		"JobStartResponse", "CredentialAnchorRequest", "CredentialAnchorResponse", "JobHeartbeatRequest",
		"JobHeartbeatResponse", "JobReleaseRequest", "JobCompleteRequest", "JobCompletionResponse",
		"RevocationLeaseRequest", "RevocationLeaseResponse", "RevocationHeartbeatRequest",
		"RevocationHeartbeatResponse", "RevocationCompleteRequest", "RevocationCompletionResponse",
	} {
		schema, ok := schemas[name]
		if !ok {
			t.Errorf("missing schema %s", name)
			continue
		}
		value := object(t, schema, "components.schemas."+name)
		if value["type"] == "object" && value["additionalProperties"] != false {
			t.Errorf("schema %s permits unknown fields", name)
		}
	}
	assertClosedObjects(t, schemas, "components.schemas")
	assertRunnerCapabilityBoundary(t, schemas)
	assertTypedActionEnvelope(t, schemas)
	assertExecutorResultUnion(t, schemas)
	if countMapKey(document, "lease_token") != 1 || countMapKey(document, "claim_token") != 1 {
		t.Errorf("raw lease/claim token schema locations = %d/%d, want 1/1",
			countMapKey(document, "lease_token"), countMapKey(document, "claim_token"))
	}
	if countMapKey(document, "result_hash") != 0 {
		t.Error("wire contract allows Runner-supplied result_hash")
	}
	if countMapKey(document, "child_create_permit") != 2 || countMapKey(document, "revoke_accessor_b64u") != 2 {
		t.Errorf("sensitive credential field locations permit/accessor = %d/%d, want 2/2",
			countMapKey(document, "child_create_permit"), countMapKey(document, "revoke_accessor_b64u"))
	}
	assertProblemContracts(t, document, components)
}

func assertOperationContracts(t *testing.T, document, paths map[string]any) {
	t.Helper()
	wantMethod := map[string]string{
		"/runner/v1/identity":                              "get",
		"/runner/v1/jobs:lease":                            "post",
		"/runner/v1/jobs/{job_id}:credential-anchor":       "post",
		"/runner/v1/jobs/{job_id}:start":                   "post",
		"/runner/v1/jobs/{job_id}:heartbeat":               "post",
		"/runner/v1/jobs/{job_id}:release":                 "post",
		"/runner/v1/jobs/{job_id}:complete":                "post",
		"/runner/v1/revocations:lease":                     "post",
		"/runner/v1/revocations/{revocation_id}:heartbeat": "post",
		"/runner/v1/revocations/{revocation_id}:complete":  "post",
	}
	for path, method := range wantMethod {
		pathItem := object(t, paths[path], path)
		operation := object(t, pathItem[method], path+"."+method)
		wantLimit := float64(65536)
		if strings.HasSuffix(path, ":lease") {
			wantLimit = 262144
		}
		if operation["x-aiops-max-response-body-bytes"] != wantLimit {
			t.Errorf("%s response body limit = %#v, want %.0f", path, operation["x-aiops-max-response-body-bytes"], wantLimit)
		}
		if method == "post" && (operation["x-aiops-max-request-body-bytes"] != wantLimit || operation["requestBody"] == nil) {
			t.Errorf("%s request body contract = %#v, want limit %.0f and requestBody", path, operation["x-aiops-max-request-body-bytes"], wantLimit)
		}
		if strings.Contains(path, "/jobs/{job_id}:") {
			assertANDSecurity(t, operation, "jobLease", path)
		}
		if strings.Contains(path, "/revocations/{revocation_id}:") {
			assertANDSecurity(t, operation, "revocationLease", path)
		}
		if strings.Contains(path, "/revocations") {
			if operation["x-aiops-required-pool"] != "WRITE" || operation["x-aiops-required-capability"] != "CREDENTIAL_REVOCATION" {
				t.Errorf("%s capability boundary = pool %#v, capability %#v", path, operation["x-aiops-required-pool"], operation["x-aiops-required-capability"])
			}
		}
	}
	globalSecurity, ok := document["security"].([]any)
	if !ok || len(globalSecurity) != 1 {
		t.Fatalf("global security = %#v", document["security"])
	}
	entry := object(t, globalSecurity[0], "global security[0]")
	if len(entry) != 1 || entry["mutualTLS"] == nil {
		t.Fatalf("global security = %#v, want mutualTLS only", entry)
	}
}

func assertRunnerCapabilityBoundary(t *testing.T, schemas map[string]any) {
	t.Helper()
	identity := object(t, schemas["RunnerIdentityResponse"], "RunnerIdentityResponse")
	conditions, ok := identity["allOf"].([]any)
	if !ok || len(conditions) != 1 {
		t.Fatalf("RunnerIdentityResponse.allOf = %#v, want one READ capability condition", identity["allOf"])
	}
	condition := object(t, conditions[0], "RunnerIdentityResponse.allOf[0]")
	ifSchema := object(t, condition["if"], "RunnerIdentityResponse.if")
	ifProperties := object(t, ifSchema["properties"], "RunnerIdentityResponse.if.properties")
	if object(t, ifProperties["pool"], "RunnerIdentityResponse.if.pool")["const"] != "READ" {
		t.Error("RunnerIdentityResponse capability condition does not select READ pool")
	}
	thenSchema := object(t, condition["then"], "RunnerIdentityResponse.then")
	thenProperties := object(t, thenSchema["properties"], "RunnerIdentityResponse.then.properties")
	if object(t, thenProperties["capabilities"], "RunnerIdentityResponse.then.capabilities")["maxItems"] != float64(0) {
		t.Error("READ Runner can expose a capability")
	}
}

func assertANDSecurity(t *testing.T, operation map[string]any, leaseScheme, name string) {
	t.Helper()
	security, ok := operation["security"].([]any)
	if !ok || len(security) != 1 {
		t.Errorf("%s security = %#v, want one AND entry", name, operation["security"])
		return
	}
	entry := object(t, security[0], name+" security")
	if len(entry) != 2 || entry["mutualTLS"] == nil || entry[leaseScheme] == nil {
		t.Errorf("%s security = %#v, want mutualTLS AND %s", name, entry, leaseScheme)
	}
}

func assertResponseHeaders(t *testing.T, document, paths map[string]any) {
	t.Helper()
	for path, rawPath := range paths {
		pathItem := object(t, rawPath, path)
		for _, method := range []string{"get", "post"} {
			rawOperation, exists := pathItem[method]
			if !exists {
				continue
			}
			operation := object(t, rawOperation, path+"."+method)
			responses := object(t, operation["responses"], path+" responses")
			for status, rawResponse := range responses {
				response := resolveObject(t, document, rawResponse, path+" response "+status)
				headers := object(t, response["headers"], path+" response "+status+" headers")
				if headers["Cache-Control"] == nil || headers["X-Content-Type-Options"] == nil {
					t.Errorf("%s %s response lacks no-store/nosniff contract", path, status)
				}
			}
		}
	}
}

func assertTypedActionEnvelope(t *testing.T, schemas map[string]any) {
	t.Helper()
	descriptor := object(t, schemas["JobDescriptor"], "JobDescriptor")
	properties := object(t, descriptor["properties"], "JobDescriptor.properties")
	payload := object(t, properties["payload"], "JobDescriptor.payload")
	if payload["$ref"] != "#/components/schemas/ActionEnvelopeV1" {
		t.Errorf("job payload = %#v, want typed ActionEnvelopeV1", payload)
	}
	production := object(t, properties["production"], "JobDescriptor.production")
	if production["const"] != false {
		t.Errorf("production = %#v, want const false", production)
	}
	envelope := object(t, schemas["ActionEnvelopeV1"], "ActionEnvelopeV1")
	if envelope["type"] != "object" || envelope["additionalProperties"] != false || envelope["allOf"] == nil {
		t.Errorf("ActionEnvelopeV1 is not a closed typed union")
	}
}

func assertExecutorResultUnion(t *testing.T, schemas map[string]any) {
	t.Helper()
	result := object(t, schemas["ExecutorResult"], "ExecutorResult")
	variants, ok := result["oneOf"].([]any)
	if !ok || len(variants) != 3 {
		t.Fatalf("ExecutorResult oneOf = %#v, want 3", result["oneOf"])
	}
	want := map[string]string{"ExecutorSucceededResult": "PASSED", "ExecutorFailedResult": "FAILED", "ExecutorUncertainResult": "UNKNOWN"}
	for name, verification := range want {
		variant := object(t, schemas[name], name)
		properties := object(t, variant["properties"], name+".properties")
		if object(t, properties["verification"], name+".verification")["const"] != verification {
			t.Errorf("%s verification is not %s", name, verification)
		}
	}
}

func assertProblemContracts(t *testing.T, document, components map[string]any) {
	t.Helper()
	responses := object(t, components["responses"], "components.responses")
	want := map[string][]string{
		"Problem400": {
			"urn:aiops:problem:runner:invalid-request|invalid_runner_request",
			"urn:aiops:problem:runner:invalid-json|invalid_runner_json",
			"urn:aiops:problem:runner:forbidden-identity-field|forbidden_runner_identity_field",
		},
		"Problem401": {"urn:aiops:problem:runner:lease-authentication-failed|runner_lease_authentication_failed"},
		"Problem403": {"urn:aiops:problem:runner:identity-rejected|runner_identity_rejected"},
		"Problem404": {"urn:aiops:problem:runner:resource-not-found|runner_resource_not_found"},
		"Problem409": {
			"urn:aiops:problem:runner:stale-lease|runner_stale_lease",
			"urn:aiops:problem:runner:state-conflict|runner_state_conflict",
			"urn:aiops:problem:runner:heartbeat-sequence-conflict|runner_heartbeat_sequence_conflict",
			"urn:aiops:problem:runner:credential-anchor-conflict|runner_credential_anchor_conflict",
			"urn:aiops:problem:runner:result-conflict|runner_result_conflict",
		},
		"Problem413":  {"urn:aiops:problem:runner:payload-too-large|runner_payload_too_large"},
		"Problem415":  {"urn:aiops:problem:runner:unsupported-media-type|runner_unsupported_media_type"},
		"RateLimited": {"urn:aiops:problem:runner:rate-limited|runner_rate_limited"},
		"Problem503": {
			"urn:aiops:problem:runner:claims-disabled|runner_claims_disabled",
			"urn:aiops:problem:runner:dependency-unavailable|runner_dependency_unavailable",
		},
		"Problem500": {"urn:aiops:problem:runner:internal-error|runner_internal_error"},
	}
	for responseName, wantPairs := range want {
		response := object(t, responses[responseName], responseName)
		rawPairs, ok := response["x-aiops-problems"].([]any)
		if !ok || len(rawPairs) != len(wantPairs) {
			t.Errorf("%s problem catalog = %#v, want %v", responseName, response["x-aiops-problems"], wantPairs)
			continue
		}
		gotPairs := make([]string, 0, len(rawPairs))
		for index, rawPair := range rawPairs {
			pair := object(t, rawPair, responseName+".x-aiops-problems["+strconv.Itoa(index)+"]")
			if len(pair) != 2 {
				t.Errorf("%s problem pair has unexpected fields: %#v", responseName, pair)
			}
			problemType, typeOK := pair["type"].(string)
			code, codeOK := pair["code"].(string)
			if !typeOK || !codeOK {
				t.Errorf("%s problem pair = %#v, want string type/code", responseName, pair)
				continue
			}
			gotPairs = append(gotPairs, problemType+"|"+code)
		}
		if strings.Join(gotPairs, "\n") != strings.Join(wantPairs, "\n") {
			t.Errorf("%s problem catalog = %v, want %v", responseName, gotPairs, wantPairs)
		}
	}
	problem401 := object(t, responses["Problem401"], "Problem401")
	if object(t, problem401["headers"], "Problem401.headers")["WWW-Authenticate"] == nil {
		t.Error("401 response lacks WWW-Authenticate")
	}
	_ = document
}

func object(t *testing.T, value any, name string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", name, value)
	}
	return object
}

func resolveObject(t *testing.T, document map[string]any, value any, name string) map[string]any {
	t.Helper()
	current := object(t, value, name)
	for current["$ref"] != nil {
		ref, ok := current["$ref"].(string)
		if !ok || !strings.HasPrefix(ref, "#/") {
			t.Fatalf("%s has invalid ref %#v", name, current["$ref"])
		}
		var resolved any = document
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			resolved = object(t, resolved, ref)[part]
		}
		current = object(t, resolved, ref)
	}
	return current
}

func countMapKey(value any, target string) int {
	count := 0
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == target {
				count++
			}
			count += countMapKey(child, target)
		}
	case []any:
		for _, child := range typed {
			count += countMapKey(child, target)
		}
	}
	return count
}

func assertClosedObjects(t *testing.T, value any, path string) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if typed["type"] == "object" && typed["additionalProperties"] != false {
			t.Errorf("%s permits unknown fields", path)
		}
		for key, child := range typed {
			assertClosedObjects(t, child, path+"."+key)
		}
	case []any:
		for index, child := range typed {
			assertClosedObjects(t, child, path+"["+strconv.Itoa(index)+"]")
		}
	}
}
