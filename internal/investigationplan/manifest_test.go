package investigationplan_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigationplan"
	"github.com/seaworld008/aiops-system/internal/readconnector"
)

func TestLoadFileBuildsSameDigestAsTrustedMemoryDefinition(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	definition := testDefinition(registry.Digest(), connectorID)
	want, err := investigationplan.New(context.Background(), authority, registry, definition)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	encoded := manifestBytes(t, definition)
	path := filepath.Join(t.TempDir(), "investigation-plan.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	got, err := investigationplan.LoadFile(context.Background(), authority, path, registry)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if got.ManifestDigest() != want.ManifestDigest() || got.RegistryDigest() != registry.Digest() {
		t.Fatalf("LoadFile() digests = (%q, %q), want (%q, %q)",
			got.ManifestDigest(), got.RegistryDigest(), want.ManifestDigest(), registry.Digest())
	}
	trusted := trustedScope(t, authority, testTenantID, testWorkspaceID)
	if _, err := got.Resolve(context.Background(), investigationplan.ResolveRequest{
		ExpectedPlanDigest: got.ManifestDigest(), TrustedScope: trusted, Signal: validSignal(),
	}); err != nil {
		t.Fatalf("LoadFile() Planner.Resolve() error = %v", err)
	}
}

func TestLoadFileRejectsStrictJSONAndNeverLeaksManifestMaterial(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	valid := manifestBytes(t, testDefinition(registry.Digest(), connectorID))
	tests := []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "invalid utf8", encoded: []byte{'{', 0xff, '}'}},
		{name: "malformed", encoded: []byte(`{"schema_version":`)},
		{name: "root array", encoded: []byte(`[]`)},
		{name: "wrong schema", encoded: bytes.Replace(valid, []byte(investigationplan.ManifestSchemaVersion), []byte("investigation-plan-manifest.v2"), 1)},
		{name: "unknown top", encoded: replaceLast(valid, `}`, `,"unknown_field":"canary_value"}`)},
		{name: "unknown profile", encoded: bytes.Replace(valid, []byte(`"scope":`), []byte(`"unknown_field":"canary_value","scope":`), 1)},
		{name: "unknown scope", encoded: bytes.Replace(valid, []byte(`"tenant_id":`), []byte(`"unknown_field":"canary_value","tenant_id":`), 1)},
		{name: "unknown match", encoded: bytes.Replace(valid, []byte(`"integration_id":`), []byte(`"unknown_field":"canary_value","integration_id":`), 1)},
		{name: "unknown label", encoded: bytes.Replace(valid, []byte(`"labels":[{"key":`), []byte(`"labels":[{"unknown_field":"canary_value","key":`), 1)},
		{name: "unknown task", encoded: bytes.Replace(valid, []byte(`"tasks":[{"key":`), []byte(`"tasks":[{"unknown_field":"canary_value","key":`), 1)},
		{name: "duplicate top", encoded: bytes.Replace(valid, []byte(`"schema_version":`), []byte(`"schema_version":"investigation-plan-manifest.v1","schema_version":`), 1)},
		{name: "escaped duplicate top", encoded: bytes.Replace(valid, []byte(`"schema_version":`), []byte(`"schema_version":"investigation-plan-manifest.v1","schema_\u0076ersion":`), 1)},
		{name: "non canonical field", encoded: bytes.Replace(valid, []byte(`"schema_version":`), []byte(`"SchemaVersion":`), 1)},
		{name: "trailing document", encoded: append(append([]byte(nil), valid...), []byte(`{}`)...)},
		{name: "depth over limit", encoded: []byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "canary-secret-manifest.json")
			if err := os.WriteFile(path, test.encoded, 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			_, err := investigationplan.LoadFile(context.Background(), authority, path, registry)
			if !errors.Is(err, investigationplan.ErrManifestJSON) {
				t.Fatalf("LoadFile() error = %v, want ErrManifestJSON", err)
			}
			assertLowSensitivityError(t, err, path, connectorID, "canary_value")
		})
	}
}

func TestLoadFileRejectsUnsafeFilesDefinitionsAndCancelledContext(t *testing.T) {
	registry, connectorID := testRegistry(t)
	authority := investigationplan.NewScopeAuthority()
	validDefinition := testDefinition(registry.Digest(), connectorID)

	t.Run("relative path", func(t *testing.T) {
		_, err := investigationplan.LoadFile(context.Background(), authority, "manifest.json", registry)
		if !errors.Is(err, investigationplan.ErrManifestPath) {
			t.Fatalf("LoadFile() error = %v, want ErrManifestPath", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.json")
		link := filepath.Join(directory, "canary-link.json")
		if err := os.WriteFile(target, manifestBytes(t, validDefinition), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		_, err := investigationplan.LoadFile(context.Background(), authority, link, registry)
		if !errors.Is(err, investigationplan.ErrManifestFile) {
			t.Fatalf("LoadFile() error = %v, want ErrManifestFile", err)
		}
		assertLowSensitivityError(t, err, link)
	})
	t.Run("group writable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "canary-mode.json")
		if err := os.WriteFile(path, manifestBytes(t, validDefinition), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o620); err != nil {
			t.Fatal(err)
		}
		_, err := investigationplan.LoadFile(context.Background(), authority, path, registry)
		if !errors.Is(err, investigationplan.ErrManifestFile) {
			t.Fatalf("LoadFile() error = %v, want ErrManifestFile", err)
		}
		assertLowSensitivityError(t, err, path)
	})
	t.Run("hard link", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "canary-hardlink.json")
		other := filepath.Join(directory, "second.json")
		if err := os.WriteFile(path, manifestBytes(t, validDefinition), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, other); err != nil {
			t.Fatal(err)
		}
		_, err := investigationplan.LoadFile(context.Background(), authority, path, registry)
		if !errors.Is(err, investigationplan.ErrManifestFile) {
			t.Fatalf("LoadFile() error = %v, want ErrManifestFile", err)
		}
		assertLowSensitivityError(t, err, path)
	})
	t.Run("over file limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "canary-large.json")
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, investigationplan.MaximumDefinitionBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := investigationplan.LoadFile(context.Background(), authority, path, registry)
		if !errors.Is(err, investigationplan.ErrManifestFile) {
			t.Fatalf("LoadFile() error = %v, want ErrManifestFile", err)
		}
		assertLowSensitivityError(t, err, path)
	})
	t.Run("registry mismatch", func(t *testing.T) {
		definition := cloneDefinition(t, validDefinition)
		definition.RegistryDigest = strings.Repeat("b", 64)
		path := writeManifest(t, definition)
		_, err := investigationplan.LoadFile(context.Background(), authority, path, registry)
		if !errors.Is(err, investigationplan.ErrManifestDefinition) || !errors.Is(err, investigationplan.ErrRegistryMismatch) {
			t.Fatalf("LoadFile() error = %v, want manifest registry rejection", err)
		}
		assertLowSensitivityError(t, err, path, connectorID)
	})
	t.Run("overlapping profiles", func(t *testing.T) {
		definition := cloneDefinition(t, validDefinition)
		definition.Profiles = repeatProfile(definition.Profiles[0], 2)
		path := writeManifest(t, definition)
		_, err := investigationplan.LoadFile(context.Background(), authority, path, registry)
		if !errors.Is(err, investigationplan.ErrManifestDefinition) || !errors.Is(err, investigationplan.ErrProfileOverlap) {
			t.Fatalf("LoadFile() error = %v, want manifest overlap rejection", err)
		}
		assertLowSensitivityError(t, err, path, connectorID)
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := investigationplan.LoadFile(ctx, authority, filepath.Join(t.TempDir(), "does-not-matter.json"), registry)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("LoadFile() error = %v, want context.Canceled", err)
		}
	})
}

func TestLoadFileRejectsInvalidAuthorityBeforeFileAccess(t *testing.T) {
	registry, _ := testRegistry(t)
	missing := filepath.Join(t.TempDir(), "missing.json")
	for name, authority := range map[string]*investigationplan.ScopeAuthority{
		"nil":  nil,
		"zero": {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := investigationplan.LoadFile(context.Background(), authority, missing, registry)
			if !errors.Is(err, investigationplan.ErrInvalidRequest) {
				t.Fatalf("LoadFile() error = %v, want ErrInvalidRequest before file access", err)
			}
		})
	}
}

func testDefinition(registryDigest, connectorID string) investigationplan.Definition {
	return investigationplan.Definition{
		RegistryDigest: registryDigest,
		Profiles: []investigationplan.ProfileDefinition{{
			Scope: investigationplan.Scope{
				TenantID: testTenantID, WorkspaceID: testWorkspaceID,
				EnvironmentID: testEnvironmentID, ServiceID: testServiceID,
			},
			Match: investigationplan.MatchDefinition{
				IntegrationID: testIntegrationID, Provider: "alertmanager",
				Labels: []investigationplan.LabelMatch{
					{Key: "service", Value: "payments"},
					{Key: "cluster", Value: "staging-a"},
				},
			},
			Tasks: []investigationplan.TaskDefinition{{
				Key: "metrics", ConnectorID: connectorID, Operation: readconnector.OperationPrometheusRangeQuery,
				Input: json.RawMessage(`{"lookback_minutes":15}`),
			}},
		}},
	}
}

func manifestBytes(t *testing.T, definition investigationplan.Definition) []byte {
	t.Helper()
	document := struct {
		SchemaVersion  string                                `json:"schema_version"`
		RegistryDigest string                                `json:"registry_digest"`
		Profiles       []investigationplan.ProfileDefinition `json:"profiles"`
	}{
		SchemaVersion: investigationplan.ManifestSchemaVersion, RegistryDigest: definition.RegistryDigest,
		Profiles: definition.Profiles,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return encoded
}

func writeManifest(t *testing.T, definition investigationplan.Definition) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "canary-secret-manifest.json")
	if err := os.WriteFile(path, manifestBytes(t, definition), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	return path
}

func replaceLast(source []byte, old, replacement string) []byte {
	index := bytes.LastIndex(source, []byte(old))
	if index < 0 {
		return append([]byte(nil), source...)
	}
	result := make([]byte, 0, len(source)-len(old)+len(replacement))
	result = append(result, source[:index]...)
	result = append(result, replacement...)
	result = append(result, source[index+len(old):]...)
	return result
}

func assertLowSensitivityError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	message := err.Error()
	for _, value := range forbidden {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("error leaked forbidden material %q through %q", value, message)
		}
	}
}
