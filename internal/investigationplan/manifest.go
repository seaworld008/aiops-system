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

// CompileManifest compiles one bounded, already-admitted manifest snapshot.
// It neither modifies nor retains the caller-owned wire buffer.
func CompileManifest(
	ctx context.Context,
	authority *ScopeAuthority,
	contents []byte,
	registry *readconnector.Registry,
) (*Planner, error) {
	return compileManifest(ctx, authority, contents, registry)
}

func compileManifest(
	ctx context.Context,
	authority *ScopeAuthority,
	contents []byte,
	registry *readconnector.Registry,
) (*Planner, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if authority == nil || authority.marker == nil {
		return nil, ErrInvalidRequest
	}
	if len(contents) == 0 || len(contents) > MaximumDefinitionBytes {
		return nil, ErrManifestJSON
	}
	var document manifestDocument
	if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
		document.SchemaVersion != ManifestSchemaVersion {
		return nil, ErrManifestJSON
	}
	planner, err := New(ctx, authority, registry, Definition{
		RegistryDigest: document.RegistryDigest,
		Profiles:       document.Profiles,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, errors.Join(ErrManifestDefinition, err)
	}
	return planner, nil
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
		var err error
		planner, err = compileManifest(ctx, authority, contents, registry)
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
		return planner, nil
	}
}
