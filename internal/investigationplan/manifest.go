package investigationplan

import (
	"context"
	"errors"

	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

type manifestDocument struct {
	SchemaVersion  string              `json:"schema_version"`
	RegistryDigest string              `json:"registry_digest"`
	Profiles       []ProfileDefinition `json:"profiles"`
}

// LoadFile securely loads one immutable, process-owned plan manifest. It does
// not accept inline definitions, environment expansion, or fallback content.
func LoadFile(
	ctx context.Context,
	authority *ScopeAuthority,
	path string,
	registry *readconnector.Registry,
) (*Planner, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if authority == nil || authority.marker == nil {
		return nil, ErrInvalidRequest
	}
	var planner *Planner
	err := securemanifest.Load(path, func(contents []byte) error {
		var document manifestDocument
		if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
			document.SchemaVersion != ManifestSchemaVersion {
			return ErrManifestJSON
		}
		compiled, err := New(ctx, authority, registry, Definition{
			RegistryDigest: document.RegistryDigest,
			Profiles:       document.Profiles,
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return errors.Join(ErrManifestDefinition, err)
		}
		planner = compiled
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
		return planner, nil
	}
}
