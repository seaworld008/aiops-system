package readtarget

import (
	"errors"
	"time"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

type manifestDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Targets       []Definition `json:"targets"`
}

// LoadFile securely loads one immutable READ target registry. It accepts no
// inline fallback and never expands environment variables from the document.
func LoadFile(path string) (*Registry, error) {
	var registry *Registry
	err := securemanifest.Load(path, func(contents []byte) error {
		var document manifestDocument
		if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
			document.SchemaVersion != ManifestSchemaVersion {
			return ErrManifestJSON
		}
		compiled, err := newRegistry(document.Targets, time.Now().UTC())
		if err != nil {
			return errors.Join(ErrManifestDefinition, ErrInvalidDefinition)
		}
		registry = compiled
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
