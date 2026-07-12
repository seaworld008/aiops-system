package readexecutor

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtarget"
)

const (
	// EgressRegistrySchemaVersion is both the strict manifest schema and the
	// domain separator for the canonical registry digest.
	EgressRegistrySchemaVersion = "read-egress-policy-registry.v1"
	maximumEgressPolicies       = 1000
)

var ErrEgressRegistryRejected = errors.New("READ egress registry rejected")

type egressRegistryKey struct {
	tenantID      string
	workspaceID   string
	environmentID string
	policyRef     string
}

type egressRegistrySeal struct{ value byte }

var trustedEgressRegistrySeal = &egressRegistrySeal{value: 1}

// EgressRegistry is a construction-time snapshot. It has no reload or
// mutation operation, and each entry is an immutable EgressPolicy capability.
type EgressRegistry struct {
	entries map[egressRegistryKey]*EgressPolicy
	digest  string
	seal    *egressRegistrySeal
	self    *EgressRegistry
}

func NewEgressRegistry(definitions []EgressPolicyDefinition) (*EgressRegistry, error) {
	if len(definitions) == 0 || len(definitions) > maximumEgressPolicies {
		return nil, ErrEgressRegistryRejected
	}
	created := &EgressRegistry{
		entries: make(map[egressRegistryKey]*EgressPolicy, len(definitions)),
		seal:    trustedEgressRegistrySeal,
	}
	aliases := make(map[string]struct{}, len(definitions))
	digestEntries := make([]egressRegistryDigestEntry, 0, len(definitions))
	for _, source := range definitions {
		definition := cloneEgressPolicyDefinition(source)
		policy, err := NewEgressPolicy(definition)
		if err != nil || policy == nil || !policy.Ready() {
			return nil, ErrEgressRegistryRejected
		}
		key := egressRegistryKey{
			tenantID: definition.Scope.TenantID, workspaceID: definition.Scope.WorkspaceID,
			environmentID: definition.Scope.EnvironmentID, policyRef: definition.PolicyRef,
		}
		if _, duplicate := created.entries[key]; duplicate {
			return nil, ErrEgressRegistryRejected
		}
		aliasKey := key.tenantID + "\x00" + key.workspaceID + "\x00" + key.environmentID + "\x00" + policy.Digest()
		if _, duplicate := aliases[aliasKey]; duplicate {
			return nil, ErrEgressRegistryRejected
		}
		aliases[aliasKey] = struct{}{}
		created.entries[key] = policy
		digestEntries = append(digestEntries, egressRegistryDigestEntry{
			Scope: definition.Scope, PolicyRef: definition.PolicyRef, PolicyDigest: policy.Digest(),
		})
	}
	digest, err := egressRegistryDigest(digestEntries)
	if err != nil || !domain.ValidSHA256Hex(digest) {
		return nil, ErrEgressRegistryRejected
	}
	created.digest = digest
	created.self = created
	return created, nil
}

func (registry *EgressRegistry) Ready() bool {
	if registry == nil || registry.self != registry || registry.seal != trustedEgressRegistrySeal ||
		len(registry.entries) == 0 || !domain.ValidSHA256Hex(registry.digest) {
		return false
	}
	for _, policy := range registry.entries {
		if policy == nil || !policy.Ready() {
			return false
		}
	}
	return true
}

func (registry *EgressRegistry) Digest() string {
	if !registry.Ready() {
		return ""
	}
	return registry.digest
}

// ResolveTarget returns the one policy whose scope, content-addressed
// reference, hostname and port all match the immutable target. It never falls
// back by hostname, environment, or policy name.
func (registry *EgressRegistry) ResolveTarget(scope readtarget.Scope, target readtarget.Target) (*EgressPolicy, error) {
	if !registry.Ready() || !validEgressScope(scope) || target.TargetRef() == "" || target.NetworkPolicyRef() == "" {
		return nil, ErrEgressRegistryRejected
	}
	policy, found := registry.entries[egressRegistryKey{
		tenantID: scope.TenantID, workspaceID: scope.WorkspaceID,
		environmentID: scope.EnvironmentID, policyRef: target.NetworkPolicyRef(),
	}]
	if !found || policy == nil || !policy.Ready() || !policy.matchesScope(scope.TenantID, scope.WorkspaceID, scope.EnvironmentID) ||
		subtle.ConstantTimeCompare([]byte(policy.Ref()), []byte(target.NetworkPolicyRef())) != 1 ||
		!referenceDigestMatches(policy.Ref(), policy.Digest()) {
		return nil, ErrEgressRegistryRejected
	}
	origin := target.OriginURL()
	if origin == nil || origin.Scheme != "https" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil ||
		origin.Hostname() == "" || origin.Port() == "" ||
		subtle.ConstantTimeCompare([]byte(policy.hostname()), []byte(origin.Hostname())) != 1 ||
		subtle.ConstantTimeCompare([]byte(strconv.Itoa(int(policy.port()))), []byte(origin.Port())) != 1 ||
		origin.Host != net.JoinHostPort(policy.hostname(), strconv.Itoa(int(policy.port()))) {
		return nil, ErrEgressRegistryRejected
	}
	return policy, nil
}

func (EgressRegistry) String() string   { return "<aiops-read-egress-registry>" }
func (EgressRegistry) GoString() string { return "<aiops-read-egress-registry>" }
func (EgressRegistry) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-egress-registry>")
}
func (EgressRegistry) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*EgressRegistry) UnmarshalJSON([]byte) error  { return ErrEgressRegistryRejected }

type egressRegistryDigestEntry struct {
	Scope        readtarget.Scope `json:"scope"`
	PolicyRef    string           `json:"policy_ref"`
	PolicyDigest string           `json:"policy_digest"`
}

func egressRegistryDigest(entries []egressRegistryDigestEntry) (string, error) {
	sort.Slice(entries, func(left, right int) bool {
		leftKey := entries[left].Scope.TenantID + "\x00" + entries[left].Scope.WorkspaceID + "\x00" +
			entries[left].Scope.EnvironmentID + "\x00" + entries[left].PolicyRef
		rightKey := entries[right].Scope.TenantID + "\x00" + entries[right].Scope.WorkspaceID + "\x00" +
			entries[right].Scope.EnvironmentID + "\x00" + entries[right].PolicyRef
		return leftKey < rightKey
	})
	document := struct {
		SchemaVersion string                      `json:"schema_version"`
		Policies      []egressRegistryDigestEntry `json:"policies"`
	}{SchemaVersion: EgressRegistrySchemaVersion, Policies: entries}
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

func cloneEgressPolicyDefinition(source EgressPolicyDefinition) EgressPolicyDefinition {
	return EgressPolicyDefinition{
		Scope: readtarget.Scope{
			TenantID: strings.Clone(source.Scope.TenantID), WorkspaceID: strings.Clone(source.Scope.WorkspaceID),
			EnvironmentID: strings.Clone(source.Scope.EnvironmentID),
		},
		PolicyRef: strings.Clone(source.PolicyRef), Hostname: strings.Clone(source.Hostname), Port: source.Port,
		AllowedPrefixes: append([]string(nil), source.AllowedPrefixes...),
	}
}
