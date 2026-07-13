package readtarget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
)

const maximumTargets = 1000

type registryKey struct {
	tenantID      string
	workspaceID   string
	environmentID string
	kind          readconnector.Kind
	targetRef     string
}

// Registry is constructed once and supports only concurrent read operations.
type Registry struct {
	entries map[registryKey]Target
	digest  string
}

func newRegistry(definitions []Definition, now time.Time) (*Registry, error) {
	return newRegistryWithBuilder(definitions, now, buildContract)
}

type contractBuilder func(Definition, time.Time) (builtContract, error)

func newRegistryWithBuilder(definitions []Definition, now time.Time, build contractBuilder) (*Registry, error) {
	if len(definitions) == 0 || len(definitions) > maximumTargets || now.IsZero() || build == nil {
		return nil, ErrInvalidDefinition
	}
	registry := &Registry{entries: make(map[registryKey]Target, len(definitions))}
	aliases := make(map[string]struct{}, len(definitions))
	digestEntries := make([]registryDigestEntry, 0, len(definitions))
	for _, definition := range definitions {
		matches := referencePattern.FindStringSubmatch(definition.TargetRef)
		if len(matches) != 3 || sensitiveReferenceBase(matches[1]) {
			return nil, ErrInvalidDefinition
		}
		contract, err := build(definition, now)
		if err != nil || matches[2] != contract.digest {
			return nil, ErrInvalidDefinition
		}
		key := registryKey{
			tenantID: contract.scope.TenantID, workspaceID: contract.scope.WorkspaceID,
			environmentID: contract.scope.EnvironmentID, kind: contract.kind, targetRef: definition.TargetRef,
		}
		if _, duplicate := registry.entries[key]; duplicate {
			return nil, ErrInvalidDefinition
		}
		aliasKey := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", key.tenantID, key.workspaceID, key.environmentID, key.kind, contract.digest)
		if _, alias := aliases[aliasKey]; alias {
			return nil, ErrInvalidDefinition
		}
		aliases[aliasKey] = struct{}{}
		registry.entries[key] = targetFromContract(definition.TargetRef, contract)
		digestEntries = append(digestEntries, registryDigestEntry{
			Scope: contract.scope, TargetRef: definition.TargetRef, Kind: contract.kind, TargetDigest: contract.digest,
		})
	}
	digest, err := targetRegistryDigest(digestEntries)
	if err != nil {
		return nil, ErrInvalidDefinition
	}
	registry.digest = digest
	return registry, nil
}

func (registry *Registry) Ready() bool {
	return registry != nil && len(registry.entries) > 0 && domain.ValidSHA256Hex(registry.digest)
}

func (registry *Registry) Digest() string {
	if registry == nil {
		return ""
	}
	return registry.digest
}

func (registry *Registry) Resolve(
	ctx context.Context,
	scope investigation.TaskSpecScope,
	kind readconnector.Kind,
	targetRef string,
) (Target, error) {
	if err := resolveContextError(ctx); err != nil {
		return Target{}, err
	}
	if registry == nil || !registry.Ready() || scope.Validate() != nil || scope.MappingStatus != domain.MappingExact ||
		!validKind(kind) ||
		!referencePattern.MatchString(targetRef) {
		return Target{}, ErrTargetRejected
	}
	target, found := registry.entries[registryKey{
		tenantID: scope.TenantID, workspaceID: scope.WorkspaceID, environmentID: scope.EnvironmentID,
		kind: kind, targetRef: targetRef,
	}]
	if !found {
		return Target{}, ErrTargetRejected
	}
	if err := resolveContextError(ctx); err != nil {
		return Target{}, err
	}
	return target, nil
}

func resolveContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrTargetRejected
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return ErrTargetRejected
		}
	}
	return ctx.Err()
}

type registryDigestEntry struct {
	Scope        Scope              `json:"scope"`
	TargetRef    string             `json:"target_ref"`
	Kind         readconnector.Kind `json:"kind"`
	TargetDigest string             `json:"target_digest"`
}

func targetRegistryDigest(entries []registryDigestEntry) (string, error) {
	sort.Slice(entries, func(left, right int) bool {
		leftKey := entries[left].Scope.TenantID + "\x00" + entries[left].Scope.WorkspaceID + "\x00" +
			entries[left].Scope.EnvironmentID + "\x00" + string(entries[left].Kind) + "\x00" + entries[left].TargetRef
		rightKey := entries[right].Scope.TenantID + "\x00" + entries[right].Scope.WorkspaceID + "\x00" +
			entries[right].Scope.EnvironmentID + "\x00" + string(entries[right].Kind) + "\x00" + entries[right].TargetRef
		return leftKey < rightKey
	})
	document := struct {
		SchemaVersion string                `json:"schema_version"`
		Targets       []registryDigestEntry `json:"targets"`
	}{SchemaVersion: "read-target-registry.v1", Targets: entries}
	wire, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func (registry Registry) String() string {
	return fmt.Sprintf("ReadTargetRegistry{Ready:%t Targets:%d Digest:%q Security:[REDACTED]}",
		(&registry).Ready(), len(registry.entries), registry.digest)
}
func (registry Registry) GoString() string { return registry.String() }
func (registry Registry) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, registry.String())
}
func (Registry) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Registry) UnmarshalJSON([]byte) error  { return ErrInvalidDefinition }
