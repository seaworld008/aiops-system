package openapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	assertLocalReferencesResolve(t, document)
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
		"/runner/v1/read-tasks/{task_id}:claim",
		"/runner/v1/read-tasks/{task_id}:start",
		"/runner/v1/read-tasks/{task_id}:heartbeat",
		"/runner/v1/read-tasks/{task_id}:release",
		"/runner/v1/read-tasks/{task_id}:complete",
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
	for _, name := range []string{"mutualTLS", "jobLease", "revocationLease", "readTaskLease"} {
		if _, ok := securitySchemes[name]; !ok {
			t.Errorf("missing security scheme %s", name)
		}
	}
	if object(t, securitySchemes["mutualTLS"], "mutualTLS")["type"] != "mutualTLS" {
		t.Error("mutualTLS scheme is not OpenAPI mutualTLS")
	}
	for _, name := range []string{"jobLease", "revocationLease", "readTaskLease"} {
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
		"ReadTaskDescriptor", "ReadTaskClaimRequest", "ReadTaskClaimResponse", "ReadTaskStartRequest",
		"ReadTaskStartResponse", "ReadTaskHeartbeatRequest", "ReadTaskHeartbeatResponse",
		"ReadTaskReleaseRequest", "ReadTaskReleaseResponse", "ReadTaskEvidenceCompletion",
		"ReadTaskCompleteRequest", "ReadTaskEvidenceCompleteRequest", "ReadTaskFailedCompleteRequest",
		"ReadTaskCancelledCompleteRequest", "ReadTaskCompleteResponse", "ReadTaskFailureCode",
		"ReadTaskLeaseToken", "RunnerResourceID",
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
	assertRunnerWirePrimitives(t, components, paths, schemas)
	assertTypedActionEnvelope(t, schemas)
	assertExecutorResultUnion(t, schemas)
	assertCompletionResponseBoundary(t, components, schemas)
	assertReadTaskContract(t, components, paths, schemas)
	if countMapKey(document, "lease_token") != 2 || countMapKey(document, "claim_token") != 1 {
		t.Errorf("raw lease/claim token schema locations = %d/%d, want 2/1",
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

func assertCompletionResponseBoundary(t *testing.T, components, schemas map[string]any) {
	t.Helper()
	completion := object(t, schemas["JobCompletionResponse"], "JobCompletionResponse")
	conditions, ok := completion["allOf"].([]any)
	if !ok || len(conditions) != 3 {
		t.Fatalf("JobCompletionResponse.allOf = %#v, want three result-correlation conditions", completion["allOf"])
	}
	seen := make(map[string]bool, 3)
	for index, rawCondition := range conditions {
		condition := object(t, rawCondition, fmt.Sprintf("JobCompletionResponse.allOf[%d]", index))
		ifSchema := object(t, condition["if"], "JobCompletionResponse.if")
		ifProperties := object(t, ifSchema["properties"], "JobCompletionResponse.if.properties")
		status, _ := object(t, ifProperties["status"], "JobCompletionResponse.if.status")["const"].(string)
		thenSchema := object(t, condition["then"], "JobCompletionResponse.then")
		properties := object(t, thenSchema["properties"], "JobCompletionResponse.then.properties")
		if object(t, properties["completion_status"], "JobCompletionResponse.then.completion_status")["const"] != status {
			t.Errorf("%s completion status is not correlated", status)
		}
		if status == "SUCCEEDED" || status == "FAILED" {
			cleanup := object(t, properties["credential_cleanup_status"], "JobCompletionResponse.then.cleanup")
			values, enumOK := cleanup["enum"].([]any)
			if !enumOK || len(values) != 2 || values[0] != "NOT_REQUIRED" || values[1] != "TERMINAL" {
				t.Errorf("%s credential cleanup enum = %#v", status, cleanup["enum"])
			}
		}
		seen[status] = true
	}
	for _, status := range []string{"SUCCEEDED", "FAILED", "UNCERTAIN"} {
		if !seen[status] {
			t.Errorf("JobCompletionResponse lacks %s correlation", status)
		}
	}

	responses := object(t, components["responses"], "components.responses")
	assertCompletionHTTPStatusSchema(t, responses, "JobCompletionAccepted", "FINALIZING")
	assertCompletionHTTPStatusSchema(t, responses, "JobCompletionOK", "UNCERTAIN", "SUCCEEDED", "FAILED")

	revocation := object(t, schemas["RevocationCompletionResponse"], "RevocationCompletionResponse")
	revocationConditions, ok := revocation["allOf"].([]any)
	if !ok || len(revocationConditions) != 1 {
		t.Fatalf("RevocationCompletionResponse.allOf = %#v", revocation["allOf"])
	}
	condition := object(t, revocationConditions[0], "RevocationCompletionResponse.allOf[0]")
	thenSchema := object(t, condition["then"], "RevocationCompletionResponse.then")
	thenRequired, thenOK := thenSchema["required"].([]any)
	elseSchema := object(t, condition["else"], "RevocationCompletionResponse.else")
	forbidden := object(t, elseSchema["not"], "RevocationCompletionResponse.else.not")
	elseRequired, elseOK := forbidden["required"].([]any)
	if !thenOK || !elseOK || len(thenRequired) != 1 || len(elseRequired) != 1 ||
		thenRequired[0] != "available_at" || elseRequired[0] != "available_at" {
		t.Error("RevocationCompletionResponse does not make available_at PENDING-only")
	}
}

func assertCompletionHTTPStatusSchema(t *testing.T, responses map[string]any, name string, statuses ...string) {
	t.Helper()
	response := object(t, responses[name], name)
	content := object(t, response["content"], name+".content")
	media := object(t, content["application/json"], name+".application/json")
	schema := object(t, media["schema"], name+".schema")
	parts, ok := schema["allOf"].([]any)
	if !ok || len(parts) != 2 {
		t.Fatalf("%s schema = %#v", name, schema)
	}
	restriction := object(t, parts[1], name+".restriction")
	properties := object(t, restriction["properties"], name+".restriction.properties")
	status := object(t, properties["status"], name+".restriction.status")
	if len(statuses) == 1 {
		if status["const"] != statuses[0] {
			t.Errorf("%s status = %#v, want %s", name, status, statuses[0])
		}
		return
	}
	values, ok := status["enum"].([]any)
	if !ok || len(values) != len(statuses) {
		t.Errorf("%s status enum = %#v", name, status["enum"])
		return
	}
	for index, want := range statuses {
		if values[index] != want {
			t.Errorf("%s status[%d] = %#v, want %s", name, index, values[index], want)
		}
	}
}

func assertRunnerWirePrimitives(t *testing.T, components, paths, schemas map[string]any) {
	t.Helper()
	parameters := object(t, components["parameters"], "components.parameters")
	jobIDParameter := object(t, parameters["JobID"], "components.parameters.JobID")
	if object(t, jobIDParameter["schema"], "JobID.schema")["$ref"] != "#/components/schemas/RunnerJobID" {
		t.Error("job path parameter is not constrained to RunnerJobID")
	}
	readTaskIDParameter := object(t, parameters["ReadTaskID"], "components.parameters.ReadTaskID")
	if object(t, readTaskIDParameter["schema"], "ReadTaskID.schema")["$ref"] != "#/components/schemas/UUID" {
		t.Error("read task path parameter is not constrained to UUID")
	}
	for schemaName, propertyName := range map[string]string{
		"JobDescriptor": "id", "ActionEnvelopeV1": "action_id",
		"CredentialChildAuthorizationResponse": "job_id", "CredentialStateResponse": "job_id",
		"JobStartResponse": "job_id", "JobHeartbeatResponse": "job_id", "JobStateResponse": "job_id",
		"JobCompletionResponse": "job_id",
	} {
		schema := object(t, schemas[schemaName], schemaName)
		properties := object(t, schema["properties"], schemaName+".properties")
		property := object(t, properties[propertyName], schemaName+"."+propertyName)
		if property["$ref"] != "#/components/schemas/RunnerJobID" {
			t.Errorf("%s.%s = %#v, want RunnerJobID", schemaName, propertyName, property)
		}
	}
	jobID := object(t, schemas["RunnerJobID"], "RunnerJobID")
	if jobID["pattern"] != "^[A-Za-z0-9][A-Za-z0-9._@-]{0,255}$" {
		t.Errorf("RunnerJobID pattern = %#v", jobID["pattern"])
	}
	uuid := object(t, schemas["UUID"], "UUID")
	if uuid["pattern"] != "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" {
		t.Errorf("UUID pattern = %#v, want domain-compatible v1-v5", uuid["pattern"])
	}
	for _, name := range []string{"DecimalInt64", "PositiveDecimalInt64"} {
		schema := object(t, schemas[name], name)
		if schema["x-aiops-maximum-int64"] != "9223372036854775807" {
			t.Errorf("%s lacks exact int64 maximum: %#v", name, schema)
		}
	}
	identity := object(t, object(t, paths["/runner/v1/identity"], "identity path")["get"], "identity get")
	responses := object(t, identity["responses"], "identity responses")
	for _, status := range []string{"400", "415"} {
		if responses[status] == nil {
			t.Errorf("identity operation does not declare runtime %s response", status)
		}
	}
}

func assertReadTaskContract(t *testing.T, components, paths, schemas map[string]any) {
	t.Helper()

	readTaskLease := object(t, object(t, components["securitySchemes"], "securitySchemes")["readTaskLease"], "readTaskLease")
	if readTaskLease["type"] != "apiKey" || readTaskLease["in"] != "header" || readTaskLease["name"] != "Authorization" ||
		!strings.Contains(fmt.Sprint(readTaskLease["description"]), "AIOPS-Read-Task-Lease") {
		t.Errorf("readTaskLease = %#v, want dedicated Authorization scheme", readTaskLease)
	}
	readChallenge := object(t, object(t, components["headers"], "headers")["ReadTaskLeaseChallenge"], "ReadTaskLeaseChallenge")
	if object(t, readChallenge["schema"], "ReadTaskLeaseChallenge.schema")["const"] != `AIOPS-Read-Task-Lease realm="runner-gateway"` {
		t.Errorf("READ lease challenge = %#v", readChallenge)
	}
	read401 := object(t, object(t, components["responses"], "responses")["ReadTaskLeaseAuthenticationFailed"], "ReadTaskLeaseAuthenticationFailed")
	if object(t, object(t, read401["headers"], "ReadTaskLeaseAuthenticationFailed.headers")["WWW-Authenticate"], "READ WWW-Authenticate")["$ref"] != "#/components/headers/ReadTaskLeaseChallenge" {
		t.Error("READ 401 does not return the dedicated lease challenge")
	}

	token := object(t, schemas["ReadTaskLeaseToken"], "ReadTaskLeaseToken")
	if token["minLength"] != float64(43) || token["maxLength"] != float64(43) || token["pattern"] != "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$" ||
		token["readOnly"] != true || token["x-sensitive"] != true || token["x-log-redact"] != true {
		t.Errorf("ReadTaskLeaseToken = %#v, want exact redacted 32-byte base64url token", token)
	}
	claim := object(t, schemas["ReadTaskClaimResponse"], "ReadTaskClaimResponse")
	claimProperties := object(t, claim["properties"], "ReadTaskClaimResponse.properties")
	if object(t, claimProperties["lease_token"], "ReadTaskClaimResponse.lease_token")["$ref"] != "#/components/schemas/ReadTaskLeaseToken" {
		t.Error("READ raw token is not confined to ReadTaskClaimResponse")
	}
	for _, schemaName := range []string{"ReadTaskClaimResponse", "ReadTaskHeartbeatResponse"} {
		response := object(t, schemas[schemaName], schemaName)
		properties := object(t, response["properties"], schemaName+".properties")
		heartbeatAfter := object(t, properties["heartbeat_after_seconds"], schemaName+".heartbeat_after_seconds")
		if heartbeatAfter["const"] != float64(10) {
			t.Errorf("%s heartbeat interval = %#v, want const 10", schemaName, heartbeatAfter)
		}
	}
	for _, requestName := range []string{
		"ReadTaskClaimRequest", "ReadTaskStartRequest", "ReadTaskHeartbeatRequest", "ReadTaskReleaseRequest",
		"ReadTaskEvidenceCompleteRequest", "ReadTaskFailedCompleteRequest", "ReadTaskCancelledCompleteRequest",
	} {
		if countMapKey(schemas[requestName], "lease_token") != 0 {
			t.Errorf("%s accepts a raw lease token in JSON", requestName)
		}
	}

	descriptor := object(t, schemas["ReadTaskDescriptor"], "ReadTaskDescriptor")
	descriptorProperties := object(t, descriptor["properties"], "ReadTaskDescriptor.properties")
	descriptorInput := object(t, descriptorProperties["input"], "ReadTaskDescriptor.input")
	if descriptorInput["x-aiops-max-json-depth"] != float64(32) || descriptorInput["x-aiops-trusted-registry-validation"] != true {
		t.Errorf("ReadTaskDescriptor input boundary = %#v", descriptorInput)
	}
	inputHash := object(t, descriptorProperties["input_hash"], "ReadTaskDescriptor.input_hash")
	if inputHash["x-aiops-hash-input"] != "exact-jcs-bytes" ||
		!strings.Contains(fmt.Sprint(inputHash["description"]), "exact JCS-canonical input bytes") {
		t.Errorf("ReadTaskDescriptor input hash contract = %#v", inputHash)
	}
	for _, forbidden := range []string{
		"tenant_id", "workspace_id", "environment_id", "incident_id", "investigation_id", "runner_id",
		"scope_revision", "certificate_sha256", "target", "url", "headers", "credential",
	} {
		if descriptorProperties[forbidden] != nil {
			t.Errorf("ReadTaskDescriptor exposes server-owned field %q", forbidden)
		}
	}

	complete := object(t, schemas["ReadTaskCompleteRequest"], "ReadTaskCompleteRequest")
	variants, ok := complete["oneOf"].([]any)
	if !ok || len(variants) != 3 {
		t.Fatalf("ReadTaskCompleteRequest.oneOf = %#v, want three outcome variants", complete["oneOf"])
	}
	wantOutcomes := map[string]string{
		"ReadTaskEvidenceCompleteRequest":  "EVIDENCE",
		"ReadTaskFailedCompleteRequest":    "FAILED",
		"ReadTaskCancelledCompleteRequest": "CANCELLED",
	}
	for name, outcome := range wantOutcomes {
		variant := object(t, schemas[name], name)
		properties := object(t, variant["properties"], name+".properties")
		if object(t, properties["outcome"], name+".outcome")["const"] != outcome {
			t.Errorf("%s outcome is not %s", name, outcome)
		}
		if outcome == "EVIDENCE" {
			if properties["evidence"] == nil || properties["failure_code"] != nil {
				t.Errorf("%s does not require evidence exclusively", name)
			}
		} else if properties["failure_code"] == nil || properties["evidence"] != nil {
			t.Errorf("%s does not require failure_code exclusively", name)
		}
	}
	failedProperties := object(t, object(t, schemas["ReadTaskFailedCompleteRequest"], "ReadTaskFailedCompleteRequest")["properties"], "failed properties")
	if object(t, failedProperties["failure_code"], "failed failure_code")["$ref"] != "#/components/schemas/ReadTaskFailureCode" {
		t.Error("FAILED completion does not use the closed failure code schema")
	}
	failedEnum, ok := object(t, schemas["ReadTaskFailureCode"], "ReadTaskFailureCode")["enum"].([]any)
	if !ok || len(failedEnum) != 8 {
		t.Fatalf("ReadTaskFailureCode enum = %#v", failedEnum)
	}
	for _, code := range failedEnum {
		if code == "cancelled" {
			t.Errorf("ReadTaskFailureCode includes cancelled: %#v", failedEnum)
		}
	}
	cancelled := object(t, schemas["ReadTaskCancelledCompleteRequest"], "ReadTaskCancelledCompleteRequest")
	cancelledProperties := object(t, cancelled["properties"], "cancelled properties")
	if object(t, cancelledProperties["failure_code"], "cancelled failure_code")["const"] != "cancelled" {
		t.Error("CANCELLED completion does not require the cancelled failure code")
	}

	evidence := object(t, schemas["ReadTaskEvidenceCompletion"], "ReadTaskEvidenceCompletion")
	evidenceProperties := object(t, evidence["properties"], "ReadTaskEvidenceCompletion.properties")
	items := object(t, evidenceProperties["items"], "ReadTaskEvidenceCompletion.items")
	if items["type"] != "array" || items["maxItems"] != float64(256) || items["x-aiops-max-total-json-bytes"] != float64(65536) ||
		items["x-aiops-max-json-depth"] != float64(16) {
		t.Errorf("ReadTask evidence bounds = %#v", items)
	}
	itemSchema := object(t, items["items"], "ReadTaskEvidenceCompletion.items.items")
	if itemSchema["type"] != "object" || itemSchema["x-aiops-trusted-registry-validation"] != true {
		t.Errorf("ReadTask evidence item boundary = %#v", itemSchema)
	}

	completeResponse := object(t, schemas["ReadTaskCompleteResponse"], "ReadTaskCompleteResponse")
	conditions, ok := completeResponse["allOf"].([]any)
	if !ok || len(conditions) != 1 {
		t.Fatalf("ReadTaskCompleteResponse.allOf = %#v, want EVIDENCE correlation", completeResponse["allOf"])
	}
	condition := object(t, conditions[0], "ReadTaskCompleteResponse condition")
	thenSchema := object(t, condition["then"], "ReadTaskCompleteResponse.then")
	elseSchema := object(t, condition["else"], "ReadTaskCompleteResponse.else")
	thenRequired, thenOK := thenSchema["required"].([]any)
	forbidden := object(t, elseSchema["not"], "ReadTaskCompleteResponse.else.not")
	forbiddenAlternatives, elseOK := forbidden["anyOf"].([]any)
	if !thenOK || !elseOK || len(forbiddenAlternatives) != 2 || strings.Join(anyStrings(t, thenRequired), ",") != "evidence_id,content_hash" {
		t.Error("ReadTaskCompleteResponse does not make evidence fields EVIDENCE-only")
	} else {
		for index, name := range []string{"evidence_id", "content_hash"} {
			required, ok := object(t, forbiddenAlternatives[index], "ReadTaskCompleteResponse.else.not.anyOf")["required"].([]any)
			if !ok || len(required) != 1 || required[0] != name {
				t.Errorf("ReadTaskCompleteResponse permits %s outside EVIDENCE", name)
			}
		}
	}

	completeOperation := object(t, object(t, paths["/runner/v1/read-tasks/{task_id}:complete"], "read complete path")["post"], "read complete")
	if object(t, completeOperation["responses"], "read complete responses")["422"] == nil {
		t.Error("READ completion does not declare result rejection as 422")
	}
	claimOperation := object(t, object(t, paths["/runner/v1/read-tasks/{task_id}:claim"], "read claim path")["post"], "read claim")
	if object(t, claimOperation["responses"], "read claim responses")["429"] != nil {
		t.Error("READ claim advertises rate limiting that its runtime cannot emit")
	}
	for path, contract := range map[string]struct {
		response string
		codes    []string
	}{
		"/runner/v1/read-tasks/{task_id}:start": {
			"ReadTaskStateConflict", []string{"runner_stale_lease", "runner_state_conflict"},
		},
		"/runner/v1/read-tasks/{task_id}:heartbeat": {
			"ReadTaskHeartbeatConflict", []string{"runner_stale_lease", "runner_state_conflict", "runner_heartbeat_sequence_conflict"},
		},
		"/runner/v1/read-tasks/{task_id}:release": {
			"ReadTaskStateConflict", []string{"runner_stale_lease", "runner_state_conflict"},
		},
		"/runner/v1/read-tasks/{task_id}:complete": {
			"ReadTaskResultConflict", []string{"runner_stale_lease", "runner_state_conflict", "runner_result_conflict"},
		},
	} {
		operation := object(t, object(t, paths[path], path)["post"], path+".post")
		response := object(t, object(t, operation["responses"], path+".responses")["409"], path+".409")
		wantReference := "#/components/responses/" + contract.response
		if response["$ref"] != wantReference {
			t.Errorf("%s 409 response = %#v, want %s", path, response, wantReference)
			continue
		}
		responseContract := object(t, object(t, components["responses"], "components.responses")[contract.response], contract.response)
		rawProblems, ok := responseContract["x-aiops-problems"].([]any)
		if !ok || len(rawProblems) != len(contract.codes) {
			t.Errorf("%s problem catalog = %#v, want %v", contract.response, responseContract["x-aiops-problems"], contract.codes)
			continue
		}
		for index, rawProblem := range rawProblems {
			if code := object(t, rawProblem, contract.response+" problem")["code"]; code != contract.codes[index] {
				t.Errorf("%s problem[%d] = %#v, want %s", contract.response, index, code, contract.codes[index])
			}
		}
	}
	for path, responseName := range map[string]string{
		"/runner/v1/read-tasks/{task_id}:claim":     "ReadTaskClaimsUnavailable",
		"/runner/v1/read-tasks/{task_id}:start":     "ReadTaskClaimsUnavailable",
		"/runner/v1/read-tasks/{task_id}:heartbeat": "ReadTaskDependencyUnavailable",
		"/runner/v1/read-tasks/{task_id}:release":   "ReadTaskDependencyUnavailable",
		"/runner/v1/read-tasks/{task_id}:complete":  "ReadTaskClaimsUnavailable",
	} {
		operation := object(t, object(t, paths[path], path)["post"], path+".post")
		response := object(t, object(t, operation["responses"], path+".responses")["503"], path+".503")
		wantReference := "#/components/responses/" + responseName
		if response["$ref"] != wantReference {
			t.Errorf("%s 503 response = %#v, want %s", path, response, wantReference)
		}
	}
	responses := object(t, components["responses"], "components.responses")
	claimsProblems := object(t, responses["ReadTaskClaimsUnavailable"], "ReadTaskClaimsUnavailable")["x-aiops-problems"].([]any)
	dependencyProblems := object(t, responses["ReadTaskDependencyUnavailable"], "ReadTaskDependencyUnavailable")["x-aiops-problems"].([]any)
	if len(claimsProblems) != 2 || len(dependencyProblems) != 1 ||
		object(t, dependencyProblems[0], "ReadTaskDependencyUnavailable problem")["code"] != "runner_dependency_unavailable" {
		t.Errorf("READ 503 catalogs are not endpoint-exact: claims=%#v dependency=%#v", claimsProblems, dependencyProblems)
	}
}

func anyStrings(t *testing.T, values []any) []string {
	t.Helper()
	result := make([]string, len(values))
	for index, value := range values {
		stringValue, ok := value.(string)
		if !ok {
			t.Fatalf("value[%d] = %#v, want string", index, value)
		}
		result[index] = stringValue
	}
	return result
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
		"/runner/v1/read-tasks/{task_id}:claim":            "post",
		"/runner/v1/read-tasks/{task_id}:start":            "post",
		"/runner/v1/read-tasks/{task_id}:heartbeat":        "post",
		"/runner/v1/read-tasks/{task_id}:release":          "post",
		"/runner/v1/read-tasks/{task_id}:complete":         "post",
	}
	for path, method := range wantMethod {
		pathItem := object(t, paths[path], path)
		operation := object(t, pathItem[method], path+"."+method)
		wantLimit := float64(65536)
		if strings.HasSuffix(path, ":lease") || strings.HasSuffix(path, ":claim") {
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
			if operation["x-aiops-required-pool"] != "WRITE" {
				t.Errorf("%s pool boundary = %#v, want WRITE", path, operation["x-aiops-required-pool"])
			}
		}
		if strings.Contains(path, "/revocations/{revocation_id}:") {
			assertANDSecurity(t, operation, "revocationLease", path)
		}
		if strings.Contains(path, "/revocations") {
			if operation["x-aiops-required-pool"] != "WRITE" || operation["x-aiops-required-capability"] != "CREDENTIAL_REVOCATION" {
				t.Errorf("%s capability boundary = pool %#v, capability %#v", path, operation["x-aiops-required-pool"], operation["x-aiops-required-capability"])
			}
		}
		if strings.Contains(path, "/read-tasks/") {
			if operation["x-aiops-required-pool"] != "READ" {
				t.Errorf("%s pool boundary = %#v, want READ", path, operation["x-aiops-required-pool"])
			}
			if strings.HasSuffix(path, ":claim") {
				security, ok := operation["security"].([]any)
				if !ok || len(security) != 1 {
					t.Errorf("%s security = %#v, want mutualTLS only", path, operation["security"])
				} else {
					entry := object(t, security[0], path+" security")
					if len(entry) != 1 || entry["mutualTLS"] == nil {
						t.Errorf("%s security = %#v, want mutualTLS only", path, entry)
					}
				}
				if operation["x-aiops-authorization-header"] != "forbidden" {
					t.Errorf("%s does not forbid Authorization", path)
				}
			} else {
				assertANDSecurity(t, operation, "readTaskLease", path)
			}
		}
		if path == "/runner/v1/jobs:lease" {
			if operation["x-aiops-200-required-pool"] != "WRITE" ||
				operation["x-aiops-read-behavior"] != "always-204-use-read-task-claim" {
				t.Errorf("%s mixed-pool boundary = %#v/%#v", path,
					operation["x-aiops-200-required-pool"], operation["x-aiops-read-behavior"])
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
		"Problem422":  {"urn:aiops:problem:runner:result-rejected|runner_result_rejected"},
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

func assertLocalReferencesResolve(t *testing.T, document map[string]any) {
	t.Helper()
	var walk func(any, string)
	walk = func(value any, path string) {
		switch typed := value.(type) {
		case map[string]any:
			if reference, ok := typed["$ref"].(string); ok && strings.HasPrefix(reference, "#/") {
				var current any = document
				for _, encodedPart := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
					part := strings.ReplaceAll(strings.ReplaceAll(encodedPart, "~1", "/"), "~0", "~")
					objectValue, objectOK := current.(map[string]any)
					if !objectOK {
						t.Errorf("%s local reference %q crosses a non-object", path, reference)
						break
					}
					current, ok = objectValue[part]
					if !ok {
						t.Errorf("%s local reference %q does not resolve", path, reference)
						break
					}
				}
			}
			for key, child := range typed {
				walk(child, path+"."+key)
			}
		case []any:
			for index, child := range typed {
				walk(child, path+"["+strconv.Itoa(index)+"]")
			}
		}
	}
	walk(document, "runner-v1")
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
			trustedRegistryBoundary := typed["x-aiops-trusted-registry-validation"] == true &&
				(path == "components.schemas.ReadTaskDescriptor.properties.input" ||
					path == "components.schemas.ReadTaskEvidenceCompletion.properties.items.items")
			if !trustedRegistryBoundary {
				t.Errorf("%s permits unknown fields", path)
			}
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
