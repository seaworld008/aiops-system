package workerbootstrap

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDecodePublicDocumentAcceptsOnlyExactPinnedContract(t *testing.T) {
	valid := validPublicDocumentJSON(t, []string{strings.Repeat("a", 64), strings.Repeat("b", 64)})
	document, err := decodePublicDocument(valid)
	if err != nil || document.SchemaVersion != PublicSourceSchemaVersion {
		t.Fatalf("decodePublicDocument(valid) = %#v, %v", document, err)
	}

	tests := map[string]string{
		"unknown":            strings.Replace(string(valid), `"schema_version":`, `"extra":true,"schema_version":`, 1),
		"duplicate escaped":  strings.Replace(string(valid), `"schema_version":`, `"schema_version":"control-worker-public-source.v1","schema_\u0076ersion":`, 1),
		"wrong schema":       strings.Replace(string(valid), PublicSourceSchemaVersion, "control-worker-public-source.v2", 1),
		"uppercase digest":   strings.Replace(string(valid), strings.Repeat("1", 64), strings.Repeat("A", 64), 1),
		"unsorted roots":     validPublicDocumentString(t, []string{strings.Repeat("b", 64), strings.Repeat("a", 64)}),
		"duplicate roots":    validPublicDocumentString(t, []string{strings.Repeat("a", 64), strings.Repeat("a", 64)}),
		"temporal URL":       strings.Replace(string(valid), "temporal.aiops.internal:7233", "https://temporal.aiops.internal:7233", 1),
		"temporal zero port": strings.Replace(string(valid), ":7233", ":07233", 1),
		"temporal plus port": strings.Replace(string(valid), ":7233", ":+7233", 1),
		"temporal wildcard":  strings.Replace(string(valid), `"server_name":"temporal.aiops.internal"`, `"server_name":"*.aiops.internal"`, 1),
		"postgres mismatch":  strings.Replace(string(valid), `"server_name":"postgres.aiops.internal"`, `"server_name":"other.aiops.internal"`, 1),
		"postgres port zero": strings.Replace(string(valid), `"port":5432`, `"port":0`, 1),
		"invalid database":   strings.Replace(string(valid), `"database":"aiops"`, `"database":"aiops-db"`, 1),
		"invalid namespace":  strings.Replace(string(valid), `"namespace":"aiops-prod"`, `"namespace":" aiops-prod"`, 1),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if decoded, decodeErr := decodePublicDocument([]byte(encoded)); !reflect.DeepEqual(decoded, publicDocument{}) || !errors.Is(decodeErr, ErrBootstrapRejected) {
				t.Fatalf("decodePublicDocument() = %#v, %v; want rejection", decoded, decodeErr)
			}
		})
	}
}

func TestTargetRootClosureRequiresExactContentAddressedSet(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "run", "aiops", "control-worker", "v1")
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	valid := []byte(`{"schema_version":"read-target-manifest.v1","targets":[` +
		`{"scope":{"tenant_id":"00000000-0000-4000-8000-000000000001","workspace_id":"00000000-0000-4000-8000-000000000002","environment_id":"00000000-0000-4000-8000-000000000003"},` +
		`"target_ref":"target-a","kind":"PROMETHEUS","endpoint":{"origin":"https://metrics.internal","server_name":"metrics.internal","ca_bundle_file":"` + filepath.Join(root, targetRootsDirectory, first+certificateFileSuffix) + `"},` +
		`"credential_role_ref":"read-a","network_policy_ref":"egress-a"},` +
		`{"scope":{"tenant_id":"00000000-0000-4000-8000-000000000001","workspace_id":"00000000-0000-4000-8000-000000000002","environment_id":"00000000-0000-4000-8000-000000000003"},` +
		`"target_ref":"target-b","kind":"PROMETHEUS","endpoint":{"origin":"https://metrics-b.internal","server_name":"metrics-b.internal","ca_bundle_file":"` + filepath.Join(root, targetRootsDirectory, second+certificateFileSuffix) + `"},` +
		`"credential_role_ref":"read-b","network_policy_ref":"egress-b"}]}`)
	if err := validateTargetRootClosure(valid, root, []string{first, second}); err != nil {
		t.Fatalf("validateTargetRootClosure(valid) error = %v", err)
	}

	tests := map[string]struct {
		manifest []byte
		expected []string
	}{
		"missing header root": {manifest: valid, expected: []string{first}},
		"extra header root":   {manifest: valid, expected: []string{first, second, strings.Repeat("c", 64)}},
		"relative path":       {manifest: []byte(strings.Replace(string(valid), filepath.Join(root, targetRootsDirectory, first+certificateFileSuffix), filepath.Join(targetRootsDirectory, first+certificateFileSuffix), 1)), expected: []string{first, second}},
		"foreign path":        {manifest: []byte(strings.Replace(string(valid), filepath.Join(root, targetRootsDirectory, first+certificateFileSuffix), filepath.Join(root, "foreign", first+certificateFileSuffix), 1)), expected: []string{first, second}},
		"digest filename":     {manifest: []byte(strings.Replace(string(valid), first+certificateFileSuffix, strings.Repeat("c", 64)+certificateFileSuffix, 1)), expected: []string{first, second}},
		"unknown field":       {manifest: []byte(strings.Replace(string(valid), `"target_ref":"target-a"`, `"target_ref":"target-a","extra":true`, 1)), expected: []string{first, second}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateTargetRootClosure(test.manifest, root, test.expected); !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("validateTargetRootClosure() error = %v, want ErrBootstrapRejected", err)
			}
		})
	}
}

func validPublicDocumentJSON(t *testing.T, roots []string) []byte {
	t.Helper()
	return []byte(validPublicDocumentString(t, roots))
}

func validPublicDocumentString(t *testing.T, roots []string) string {
	t.Helper()
	quoted := make([]string, len(roots))
	for index, root := range roots {
		quoted[index] = `"` + root + `"`
	}
	return `{"schema_version":"control-worker-public-source.v1",` +
		`"expected_snapshot":{"schema_version":"read-assembly-snapshot.v1","plan_manifest_digest":"` + strings.Repeat("1", 64) + `","connector_registry_digest":"` + strings.Repeat("2", 64) + `","target_registry_digest":"` + strings.Repeat("3", 64) + `","egress_registry_digest":"` + strings.Repeat("4", 64) + `","executor_profile_digest":"` + strings.Repeat("5", 64) + `","bundle_digest":"` + strings.Repeat("6", 64) + `"},` +
		`"postgres":{"host":"postgres.aiops.internal","port":5432,"database":"aiops","user":"aiops_worker","server_name":"postgres.aiops.internal"},` +
		`"temporal":{"host_port":"temporal.aiops.internal:7233","namespace":"aiops-prod","server_name":"temporal.aiops.internal"},` +
		`"artifacts":{"connector_manifest_sha256":"` + strings.Repeat("7", 64) + `","plan_manifest_sha256":"` + strings.Repeat("8", 64) + `","target_manifest_sha256":"` + strings.Repeat("9", 64) + `","egress_manifest_sha256":"` + strings.Repeat("a", 64) + `","postgres_root_ca_sha256":"` + strings.Repeat("b", 64) + `","postgres_client_certificate_sha256":"` + strings.Repeat("c", 64) + `","temporal_root_ca_sha256":"` + strings.Repeat("d", 64) + `","temporal_starter_certificate_sha256":"` + strings.Repeat("e", 64) + `","temporal_control_certificate_sha256":"` + strings.Repeat("f", 64) + `","target_root_bundle_sha256":[` + strings.Join(quoted, ",") + `]}}`
}
