package readtarget_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readtarget"
)

func TestLoadFileRejectsUnsafeManifestFilesWithoutLeakingPaths(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)
	definition.TargetRef = mustBuildTargetRef(t, "prometheus-staging", definition)
	safePath := writeManifest(t, []readtarget.Definition{definition})
	contents, err := os.ReadFile(safePath)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	symlink := filepath.Join(directory, "manifest-link-canary.json")
	if err := os.Symlink(safePath, symlink); err != nil {
		t.Fatal(err)
	}
	groupWritable := filepath.Join(directory, "manifest-mode-canary.json")
	if err := os.WriteFile(groupWritable, contents, 0o620); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupWritable, 0o620); err != nil {
		t.Fatal(err)
	}
	hardlinkTarget := filepath.Join(directory, "manifest-hardlink-target.json")
	if err := os.WriteFile(hardlinkTarget, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "manifest-hardlink-canary.json")
	if err := os.Link(hardlinkTarget, hardlink); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "relative", path: "manifest-canary.json", want: readtarget.ErrManifestPath},
		{name: "non-clean", path: directory + "/nested/../manifest-canary.json", want: readtarget.ErrManifestPath},
		{name: "missing", path: filepath.Join(directory, "missing-canary.json"), want: readtarget.ErrManifestFile},
		{name: "directory", path: directory, want: readtarget.ErrManifestFile},
		{name: "symlink", path: symlink, want: readtarget.ErrManifestFile},
		{name: "group writable", path: groupWritable, want: readtarget.ErrManifestFile},
		{name: "hardlink", path: hardlink, want: readtarget.ErrManifestFile},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			registry, err := readtarget.LoadFile(testCase.path)
			if registry != nil || !errors.Is(err, testCase.want) {
				t.Fatalf("LoadFile() = %#v, %v; want %v", registry, err, testCase.want)
			}
			if strings.Contains(fmt.Sprint(err), testCase.path) || strings.Contains(fmt.Sprint(err), "canary") {
				t.Fatalf("LoadFile() leaked path: %v", err)
			}
		})
	}
}

func TestLoadFileRejectsStrictJSONViolationsWithoutLeakingContents(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)
	definition.TargetRef = mustBuildTargetRef(t, "prometheus-staging", definition)
	validPath := writeManifest(t, []readtarget.Definition{definition})
	valid, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	canary := "manifest-secret-canary-do-not-render"
	tests := map[string]string{
		"malformed":              `{`,
		"wrong schema":           strings.Replace(string(valid), readtarget.ManifestSchemaVersion, "read-target-manifest.v2", 1),
		"unknown top":            strings.Replace(string(valid), `"targets":`, `"unknown":"`+canary+`","targets":`, 1),
		"unknown nested":         strings.Replace(string(valid), `"origin":`, `"unknown":"`+canary+`","origin":`, 1),
		"duplicate":              strings.Replace(string(valid), `"schema_version":`, `"schema_version":"read-target-manifest.v1","schema_version":`, 1),
		"escaped duplicate":      strings.Replace(string(valid), `"target_ref":`, `"target_ref":"safe-v1-`+repeatHex("a")+`","target_\u0072ef":`, 1),
		"non canonical field":    strings.Replace(string(valid), `"schema_version":`, `"SchemaVersion":`, 1),
		"trailing":               string(valid) + `{}`,
		"secret-bearing unknown": strings.Replace(string(valid), `"credential_role_ref":`, `"token":"`+canary+`","credential_role_ref":`, 1),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
				t.Fatal(err)
			}
			registry, err := readtarget.LoadFile(path)
			if registry != nil || !errors.Is(err, readtarget.ErrManifestJSON) {
				t.Fatalf("LoadFile() = %#v, %v; want ErrManifestJSON", registry, err)
			}
			if strings.Contains(fmt.Sprint(err), canary) || strings.Contains(fmt.Sprint(err), definition.Endpoint.Origin) {
				t.Fatalf("LoadFile() leaked manifest material: %v", err)
			}
		})
	}
}

func TestLoadFileRejectsSensitiveTargetReferenceAlias(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)
	safeRef := mustBuildTargetRef(t, "prometheus-staging", definition)
	definition.TargetRef = "secret-token-v1-" + safeRef[len(safeRef)-64:]

	registry, err := readtarget.LoadFile(writeManifest(t, []readtarget.Definition{definition}))
	if registry != nil || !errors.Is(err, readtarget.ErrManifestDefinition) {
		t.Fatalf("LoadFile(sensitive target alias) = %#v, %v; want ErrManifestDefinition", registry, err)
	}
}

func TestLoadedRegistryIsDetachedFromManifestAndCABundleFiles(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)
	definition.TargetRef = mustBuildTargetRef(t, "prometheus-staging", definition)
	manifestPath := writeManifest(t, []readtarget.Definition{definition})
	registry, err := readtarget.LoadFile(manifestPath)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	digest := registry.Digest()
	if err := os.WriteFile(manifestPath, []byte(`{"schema_version":"changed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(definition.Endpoint.CABundleFile, []byte("destroyed-ca-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := registry.Resolve(context.Background(), validTaskScope(), definition.Kind, definition.TargetRef)
	if err != nil || !registry.Ready() || registry.Digest() != digest || target.TLSConfig() == nil || target.TLSConfig().RootCAs == nil {
		t.Fatalf("source mutation changed loaded registry: %#v / %v", target, err)
	}
}
