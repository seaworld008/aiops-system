package readexecutor

import (
	"errors"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

const maximumEgressManifestBytes = 1 << 20

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

// CompileEgressManifest compiles one bounded, already-admitted manifest
// snapshot. It neither modifies nor retains the caller-owned wire buffer.
func CompileEgressManifest(contents []byte) (*EgressRegistry, error) {
	return compileEgressManifest(contents)
}

func compileEgressManifest(contents []byte) (*EgressRegistry, error) {
	if len(contents) == 0 || len(contents) > maximumEgressManifestBytes {
		return nil, ErrEgressManifestJSON
	}
	var document egressManifestDocument
	if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
		document.SchemaVersion != EgressRegistrySchemaVersion {
		return nil, ErrEgressManifestJSON
	}
	registry, err := NewEgressRegistry(document.Policies)
	if err != nil {
		return nil, errors.Join(ErrEgressManifestDefinition, ErrEgressRegistryRejected)
	}
	return registry, nil
}

// LoadEgressRegistryFile securely loads one owner-only, stable manifest
// snapshot. The resulting registry never observes later file changes.
func LoadEgressRegistryFile(path string) (*EgressRegistry, error) {
	var registry *EgressRegistry
	err := securemanifest.Load(path, func(contents []byte) error {
		var err error
		registry, err = compileEgressManifest(contents)
		return err
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
