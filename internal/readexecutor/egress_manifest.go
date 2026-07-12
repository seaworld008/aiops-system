package readexecutor

import (
	"errors"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

var (
	ErrEgressManifestPath       = errors.New("READ egress manifest path rejected")
	ErrEgressManifestFile       = errors.New("READ egress manifest file rejected")
	ErrEgressManifestJSON       = errors.New("READ egress manifest JSON rejected")
	ErrEgressManifestDefinition = errors.New("READ egress manifest definition rejected")
)

type egressManifestDocument struct {
	SchemaVersion string                   `json:"schema_version"`
	Policies      []EgressPolicyDefinition `json:"policies"`
}

// LoadEgressRegistryFile securely loads one owner-only, stable manifest
// snapshot. The resulting registry never observes later file changes.
func LoadEgressRegistryFile(path string) (*EgressRegistry, error) {
	var registry *EgressRegistry
	err := securemanifest.Load(path, func(contents []byte) error {
		var document egressManifestDocument
		if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
			document.SchemaVersion != EgressRegistrySchemaVersion {
			return ErrEgressManifestJSON
		}
		compiled, err := NewEgressRegistry(document.Policies)
		if err != nil {
			return errors.Join(ErrEgressManifestDefinition, ErrEgressRegistryRejected)
		}
		registry = compiled
		return nil
	})
	switch {
	case errors.Is(err, securemanifest.ErrPath):
		return nil, ErrEgressManifestPath
	case errors.Is(err, securemanifest.ErrFile):
		return nil, ErrEgressManifestFile
	case err != nil:
		return nil, err
	default:
		return registry, nil
	}
}
