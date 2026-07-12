package readtarget

import (
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

const (
	maximumManifestBytes         = 1 << 20
	maximumCapturedRootPathBytes = 4096
)

type manifestDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Targets       []Definition `json:"targets"`
}

// CapturedRootBundle binds public root bytes to the exact path referenced by a
// captured target manifest. The contents are public trust anchors, not secret
// material, and remain owned by the caller.
type CapturedRootBundle struct {
	Path     string
	Contents []byte
}

type capturedRootSet struct {
	pool   *x509.CertPool
	hashes []string
}

// CompileCapturedManifest compiles one bounded, already-admitted manifest and
// its exact captured root closure. It performs no file-system reads and neither
// modifies nor retains any caller-owned wire buffer.
func CompileCapturedManifest(contents []byte, roots []CapturedRootBundle) (*Registry, error) {
	definitions, err := decodeManifest(contents)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 || len(roots) > maximumTargets {
		return nil, manifestDefinitionError()
	}
	now := time.Now().UTC()
	captured := make(map[string]capturedRootSet, len(roots))
	for _, root := range roots {
		if !validCapturedRootPath(root.Path) {
			return nil, manifestDefinitionError()
		}
		if _, duplicate := captured[root.Path]; duplicate {
			return nil, manifestDefinitionError()
		}
		certificates, hashes, parseErr := parseRoots(root.Contents, now)
		if parseErr != nil {
			return nil, manifestDefinitionError()
		}
		pool := x509.NewCertPool()
		for _, certificate := range certificates {
			pool.AddCert(certificate)
		}
		captured[root.Path] = capturedRootSet{pool: pool, hashes: hashes}
	}
	used := make(map[string]struct{}, len(captured))
	registry, err := newRegistryWithBuilder(definitions, now, func(definition Definition, buildTime time.Time) (builtContract, error) {
		return buildContractWithRoots(definition, buildTime, func(path string, _ time.Time) (*x509.CertPool, []string, error) {
			root, found := captured[path]
			if !found {
				return nil, nil, ErrInvalidDefinition
			}
			used[path] = struct{}{}
			return root.pool.Clone(), append([]string(nil), root.hashes...), nil
		})
	})
	if err != nil || len(used) != len(captured) {
		return nil, manifestDefinitionError()
	}
	return registry, nil
}

func decodeManifest(contents []byte) ([]Definition, error) {
	if len(contents) == 0 || len(contents) > maximumManifestBytes {
		return nil, ErrManifestJSON
	}
	var document manifestDocument
	if err := securemanifest.DecodeStrict(contents, &document); err != nil ||
		document.SchemaVersion != ManifestSchemaVersion {
		return nil, ErrManifestJSON
	}
	return document.Targets, nil
}

func validCapturedRootPath(path string) bool {
	if path == "" || len(path) > maximumCapturedRootPathBytes || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || strings.TrimSpace(path) != path {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func manifestDefinitionError() error {
	return errors.Join(ErrManifestDefinition, ErrInvalidDefinition)
}

// LoadFile securely loads one immutable READ target registry. It accepts no
// inline fallback and never expands environment variables from the document.
func LoadFile(path string) (*Registry, error) {
	var registry *Registry
	err := securemanifest.Load(path, func(contents []byte) error {
		definitions, decodeErr := decodeManifest(contents)
		if decodeErr != nil {
			return decodeErr
		}
		var compileErr error
		registry, compileErr = newRegistry(definitions, time.Now().UTC())
		if compileErr != nil {
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
