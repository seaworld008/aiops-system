package securemanifest_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

func TestLoadProvidesStableManifestAndClearsCallbackBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	contents := []byte(`{"schema_version":"test.v1"}`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var retained []byte
	err := securemanifest.Load(path, func(loaded []byte) error {
		if !bytes.Equal(loaded, contents) {
			t.Fatalf("Load() callback = %q, want %q", loaded, contents)
		}
		retained = loaded
		return nil
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(retained) != len(contents) || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatalf("Load() retained callback buffer was not cleared: %q", retained)
	}
}

func TestLoadClearsCallbackBufferOnErrorAndPreservesIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"test.v1"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	want := errors.New("consumer stopped")
	var retained []byte
	err := securemanifest.Load(path, func(loaded []byte) error {
		retained = loaded
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("Load() error = %v, want callback identity", err)
	}
	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatalf("Load() retained callback buffer after error: %q", retained)
	}
}

func TestLoadClearsCallbackBufferOnPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"test.v1"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	var retained []byte
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Load() callback did not panic")
			}
		}()
		_ = securemanifest.Load(path, func(loaded []byte) error {
			retained = loaded
			panic("test panic")
		})
	}()
	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatalf("Load() retained callback buffer after panic: %q", retained)
	}
}

func TestDecodeStrictRejectsUnknownDuplicateNonCanonicalAndTrailingJSON(t *testing.T) {
	type document struct {
		SchemaVersion string `json:"schema_version"`
	}
	tests := map[string][]byte{
		"unknown":             []byte(`{"schema_version":"test.v1","extra":true}`),
		"duplicate escaped":   []byte(`{"schema_version":"test.v1","schema_\u0076ersion":"test.v1"}`),
		"non canonical field": []byte(`{"SchemaVersion":"test.v1"}`),
		"trailing":            []byte(`{"schema_version":"test.v1"}{}`),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			var target document
			if err := securemanifest.DecodeStrict(encoded, &target); !errors.Is(err, securemanifest.ErrJSON) {
				t.Fatalf("DecodeStrict() error = %v, want ErrJSON", err)
			}
		})
	}

	var decoded document
	if err := securemanifest.DecodeStrict([]byte(`{"schema_version":"test.v1"}`), &decoded); err != nil || decoded.SchemaVersion != "test.v1" {
		t.Fatalf("DecodeStrict(valid) = %#v, %v", decoded, err)
	}
}
