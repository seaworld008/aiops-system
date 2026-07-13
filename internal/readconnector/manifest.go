package readconnector

import (
	"errors"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

const manifestSchemaVersion = "read-connector-registry.v1"

const maximumManifestBytes = 1 << 20

var (
	// These sentinels intentionally carry only a low-sensitivity category.
	// Callers must never receive an operating-system, path, query, or target
	// error through this configuration boundary.
	ErrManifestPath       = errors.New("read connector manifest path rejected")
	ErrManifestFile       = errors.New("read connector manifest file rejected")
	ErrManifestJSON       = errors.New("read connector manifest JSON rejected")
	ErrManifestDefinition = errors.New("read connector manifest definition rejected")
)

type manifestDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Definitions   []Definition `json:"definitions"`
}

// CompileManifest compiles one bounded, already-admitted manifest snapshot.
// It neither modifies nor retains the caller-owned wire buffer.
func CompileManifest(contents []byte) (*Registry, error) {
	return compileManifest(contents)
}

func compileManifest(contents []byte) (*Registry, error) {
	if len(contents) == 0 || len(contents) > maximumManifestBytes {
		return nil, ErrManifestJSON
	}
	var document manifestDocument
	if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
		document.SchemaVersion != manifestSchemaVersion {
		return nil, ErrManifestJSON
	}
	if len(document.Definitions) == 0 || len(document.Definitions) > maxDefinitions {
		return nil, manifestDefinitionError()
	}
	registry, err := New(document.Definitions)
	if err != nil {
		return nil, manifestDefinitionError()
	}
	return registry, nil
}

// LoadFile securely loads an immutable, server-owned READ connector registry.
// It accepts neither inline configuration nor environment expansion: the
// already-admitted file is the sole source of definitions.
func LoadFile(path string) (*Registry, error) {
	var registry *Registry
	err := securemanifest.Load(path, func(contents []byte) error {
		var err error
		registry, err = compileManifest(contents)
		return err
	})
	switch {
	case errors.Is(err, securemanifest.ErrPath):
		return nil, ErrManifestPath
	case errors.Is(err, securemanifest.ErrFile):
		return nil, ErrManifestFile
	case err != nil:
		return nil, err
	default:
		return registry, nil
	}
}

func manifestDefinitionError() error {
	return errors.Join(ErrManifestDefinition, ErrInvalidDefinition)
}
