package readconnector_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/seaworld008/aiops-system/internal/readconnector"
)

const manifestSchemaVersion = "read-connector-registry.v1"

func TestLoadFileBuildsDetachedRegistryFromStrictManifest(t *testing.T) {
	path := writeManifestFile(t, validManifestBytes(t), 0o600)

	registry, err := readconnector.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if registry == nil || !registry.Ready() || registry.Digest() == "" {
		t.Fatalf("LoadFile() registry = %#v", registry)
	}
	digest := registry.Digest()

	// The returned registry must not retain the source buffer or depend on the
	// file after construction.
	if err := os.WriteFile(path, []byte(`{"schema_version":"changed"}`), 0o600); err != nil {
		t.Fatalf("overwrite manifest: %v", err)
	}
	if !registry.Ready() || registry.Digest() != digest {
		t.Fatal("source-file mutation changed the loaded immutable registry")
	}
}

func TestCompileManifestBuildsDetachedRegistryWithinWireBudget(t *testing.T) {
	valid := validManifestBytes(t)
	encoded := append(bytes.Repeat([]byte{' '}, (1<<20)-len(valid)), valid...)
	original := append([]byte(nil), encoded...)

	registry, err := readconnector.CompileManifest(encoded)
	if err != nil {
		t.Fatalf("CompileManifest() error = %v", err)
	}
	if registry == nil || !registry.Ready() || registry.Digest() == "" {
		t.Fatalf("CompileManifest() registry = %#v", registry)
	}
	digest := registry.Digest()
	if !bytes.Equal(encoded, original) {
		t.Fatal("CompileManifest() modified the caller-owned buffer")
	}
	clear(encoded)
	if !registry.Ready() || registry.Digest() != digest {
		t.Fatal("caller buffer mutation changed the compiled registry")
	}

	for name, contents := range map[string][]byte{
		"empty":      nil,
		"over limit": append(bytes.Repeat([]byte{' '}, (1<<20)+1-len(valid)), valid...),
	} {
		t.Run(name, func(t *testing.T) {
			compiled, compileErr := readconnector.CompileManifest(contents)
			if compiled != nil || !errors.Is(compileErr, readconnector.ErrManifestJSON) {
				t.Fatalf("CompileManifest() = %#v, %v; want nil, ErrManifestJSON", compiled, compileErr)
			}
		})
	}
}

func TestLoadFileRejectsUnsafePathsAndFileMetadata(t *testing.T) {
	valid := validManifestBytes(t)
	safePath := writeManifestFile(t, valid, 0o600)
	nonClean := filepath.Dir(safePath) + "/subdirectory/../" + filepath.Base(safePath)
	symlink := filepath.Join(t.TempDir(), "manifest-link.json")
	if err := os.Symlink(safePath, symlink); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}
	groupWritable := writeManifestFile(t, valid, 0o620)
	worldWritable := writeManifestFile(t, valid, 0o602)
	oversized := writeManifestFile(t, bytes.Repeat([]byte{'x'}, (1<<20)+1), 0o600)
	hardlinkTarget := writeManifestFile(t, valid, 0o600)
	hardlink := filepath.Join(t.TempDir(), "manifest-hardlink.json")
	if err := os.Link(hardlinkTarget, hardlink); err != nil {
		t.Fatalf("Link(): %v", err)
	}

	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "empty", path: "", want: readconnector.ErrManifestPath},
		{name: "relative", path: "manifest.json", want: readconnector.ErrManifestPath},
		{name: "non-clean", path: nonClean, want: readconnector.ErrManifestPath},
		{name: "missing", path: filepath.Join(t.TempDir(), "missing.json"), want: readconnector.ErrManifestFile},
		{name: "directory", path: t.TempDir(), want: readconnector.ErrManifestFile},
		{name: "symlink", path: symlink, want: readconnector.ErrManifestFile},
		{name: "group-writable", path: groupWritable, want: readconnector.ErrManifestFile},
		{name: "world-writable", path: worldWritable, want: readconnector.ErrManifestFile},
		{name: "oversized", path: oversized, want: readconnector.ErrManifestFile},
		{name: "hardlink", path: hardlink, want: readconnector.ErrManifestFile},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			registry, err := readconnector.LoadFile(testCase.path)
			if registry != nil || !errors.Is(err, testCase.want) {
				t.Fatalf("LoadFile() = %#v, %v; want nil, %v", registry, err, testCase.want)
			}
			if testCase.path != "" && strings.Contains(fmt.Sprint(err), testCase.path) {
				t.Fatalf("LoadFile() error leaked path: %v", err)
			}
		})
	}
}

func TestLoadFileRejectsForeignOwnerAndAccessExpandingMetadata(t *testing.T) {
	t.Run("extended attribute", func(t *testing.T) {
		path := writeManifestFile(t, validManifestBytes(t), 0o600)
		setManifestExtendedAttribute(t, path)
		registry, err := readconnector.LoadFile(path)
		if registry != nil || !errors.Is(err, readconnector.ErrManifestFile) {
			t.Fatalf("LoadFile(xattr) = %#v, %v; want ErrManifestFile", registry, err)
		}
	})

	if runtime.GOOS == "darwin" {
		t.Run("extended ACL", func(t *testing.T) {
			path := writeManifestFile(t, validManifestBytes(t), 0o600)
			command := exec.Command("/bin/chmod", "+a", "everyone allow read", path)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("chmod +a error = %v: %s", err, output)
			}
			registry, err := readconnector.LoadFile(path)
			if registry != nil || !errors.Is(err, readconnector.ErrManifestFile) {
				t.Fatalf("LoadFile(ACL) = %#v, %v; want ErrManifestFile", registry, err)
			}
		})
	}

	if os.Geteuid() == 0 {
		t.Run("foreign owner", func(t *testing.T) {
			path := writeManifestFile(t, validManifestBytes(t), 0o600)
			if err := os.Chown(path, 1, -1); err != nil {
				t.Fatalf("Chown(): %v", err)
			}
			registry, err := readconnector.LoadFile(path)
			if registry != nil || !errors.Is(err, readconnector.ErrManifestFile) {
				t.Fatalf("LoadFile(foreign owner) = %#v, %v; want ErrManifestFile", registry, err)
			}
		})
	}
}

func TestLoadFileRejectsUnknownDuplicateTrailingAndNonCanonicalJSON(t *testing.T) {
	valid := string(validManifestBytes(t))
	canary := "manifest-query-target-canary-do-not-render"
	tests := map[string]string{
		"malformed":                `{`,
		"trailing":                 valid + `{}`,
		"unknown top level":        strings.Replace(valid, `"definitions":`, `"unknown":true,"definitions":`, 1),
		"unknown nested":           strings.Replace(valid, `"step_seconds":30`, `"step_seconds":30,"unknown":true`, 1),
		"duplicate top level":      strings.Replace(valid, `"schema_version":`, `"schema_version":"read-connector-registry.v1","schema_version":`, 1),
		"escaped duplicate nested": strings.Replace(valid, `"target_ref":`, `"target_ref":"safe-target-v1","target_\u0072ef":`, 1),
		"non-canonical field":      strings.Replace(valid, `"schema_version":`, `"Schema_Version":`, 1),
		"wrong schema":             strings.Replace(valid, manifestSchemaVersion, "read-connector-registry.v2", 1),
		"secret unknown value":     strings.Replace(valid, `"definitions":`, `"unknown":"`+canary+`","definitions":`, 1),
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			registry, err := readconnector.LoadFile(writeManifestFile(t, []byte(encoded), 0o600))
			if registry != nil || !errors.Is(err, readconnector.ErrManifestJSON) {
				t.Fatalf("LoadFile() = %#v, %v; want nil, ErrManifestJSON", registry, err)
			}
			if strings.Contains(fmt.Sprint(err), canary) || strings.Contains(fmt.Sprint(err), "target_ref") {
				t.Fatalf("LoadFile() error leaked manifest data: %v", err)
			}
		})
	}
}

func TestLoadFileClassifiesDefinitionFailuresWithoutLeakingValues(t *testing.T) {
	canary := "manifest-definition-canary-do-not-render"
	invalid := string(validManifestBytes(t))
	invalid = strings.Replace(invalid, `"target_ref":"`+prometheusTargetRef+`"`, `"target_ref":"https://`+canary+`.invalid"`, 1)
	invalid = strings.Replace(invalid, `"expression":"sum(rate(http_requests_total[5m]))"`, `"expression":"`+canary+`"`, 1)

	tests := map[string][]byte{
		"empty definitions":    []byte(`{"schema_version":"read-connector-registry.v1","definitions":[]}`),
		"invalid definition":   []byte(invalid),
		"too many definitions": manifestWithDefinitionCount(t, 1001),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			registry, err := readconnector.LoadFile(writeManifestFile(t, encoded, 0o600))
			if registry != nil || !errors.Is(err, readconnector.ErrManifestDefinition) ||
				!errors.Is(err, readconnector.ErrInvalidDefinition) {
				t.Fatalf("LoadFile() = %#v, %v; want both definition sentinels", registry, err)
			}
			if strings.Contains(fmt.Sprint(err), canary) || strings.Contains(fmt.Sprint(err), "https://") {
				t.Fatalf("LoadFile() error leaked definition data: %v", err)
			}
		})
	}
}

func validManifestBytes(t *testing.T) []byte {
	t.Helper()
	document := struct {
		SchemaVersion string                     `json:"schema_version"`
		Definitions   []readconnector.Definition `json:"definitions"`
	}{SchemaVersion: manifestSchemaVersion, Definitions: validDefinitions()}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal(manifest): %v", err)
	}
	return encoded
}

func manifestWithDefinitionCount(t *testing.T, count int) []byte {
	t.Helper()
	definitions := make([]readconnector.Definition, count)
	for index := range definitions {
		definitions[index] = validDefinitions()[0]
	}
	document := struct {
		SchemaVersion string                     `json:"schema_version"`
		Definitions   []readconnector.Definition `json:"definitions"`
	}{SchemaVersion: manifestSchemaVersion, Definitions: definitions}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal(large manifest): %v", err)
	}
	if len(encoded) > 1<<20 {
		t.Fatalf("definition-count fixture unexpectedly exceeds manifest file limit: %d", len(encoded))
	}
	return encoded
}

func writeManifestFile(t *testing.T, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "read-connectors.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("os.Chmod(): %v", err)
	}
	return path
}

func setManifestExtendedAttribute(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(xattr fixture): %v", err)
	}
	defer file.Close()
	name, err := syscall.BytePtrFromString("user.aiops-read-connector-manifest-test")
	if err != nil {
		t.Fatalf("BytePtrFromString(xattr): %v", err)
	}
	value := []byte("present")
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		file.Fd(),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&value[0])),
		uintptr(len(value)),
		0,
		0,
	)
	runtime.KeepAlive(name)
	runtime.KeepAlive(value)
	if errno != 0 {
		t.Fatalf("fsetxattr(): %v", errno)
	}
}
