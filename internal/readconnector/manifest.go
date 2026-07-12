package readconnector

import (
	"errors"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

const manifestSchemaVersion = "read-connector-registry.v1"

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

// LoadFile securely loads an immutable, server-owned READ connector registry.
// It accepts neither inline configuration nor environment expansion: the
// already-admitted file is the sole source of definitions.
func LoadFile(path string) (*Registry, error) {
	var registry *Registry
	err := securemanifest.Load(path, func(contents []byte) error {
		var document manifestDocument
		if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
			document.SchemaVersion != manifestSchemaVersion {
			return ErrManifestJSON
		}
		if len(document.Definitions) == 0 || len(document.Definitions) > maxDefinitions {
			return manifestDefinitionError()
		}
		var err error
		registry, err = New(document.Definitions)
		if err != nil {
			return manifestDefinitionError()
		}
		return nil
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
