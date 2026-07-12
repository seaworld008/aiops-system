package readexecutor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtarget"
)

const EgressPolicySchemaVersion = "read-egress-policy.v1"

const (
	allAnswersPolicyV1     = "all-dns-answers-must-be-allowed.v1"
	literalDialPolicyV1    = "literal-ip-only-dial.v1"
	hardDenyProfileV1      = "special-address-and-cloud-metadata-hard-deny.v1"
	maximumAllowedPrefixes = 32
	minimumIPv4PrefixBits  = 24
	minimumIPv6PrefixBits  = 64
)

var (
	ErrEgressPolicyRejected = errors.New("READ egress policy rejected")
	egressBasePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,59}$`)
	egressReferencePattern  = regexp.MustCompile(`^([a-z0-9][a-z0-9_.-]{0,59})-v1-([a-f0-9]{64})$`)
	egressUUIDPattern       = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

type EgressPolicyDefinition struct {
	Scope           readtarget.Scope `json:"scope"`
	PolicyRef       string           `json:"policy_ref"`
	Hostname        string           `json:"hostname"`
	Port            uint16           `json:"port"`
	AllowedPrefixes []string         `json:"allowed_prefixes"`
}

type egressPolicySeal struct{ value byte }

var trustedEgressPolicySeal = &egressPolicySeal{value: 1}

// EgressPolicy is an immutable, content-addressed application-layer network
// capability. Callers cannot add destinations after construction.
type EgressPolicy struct {
	ref            string
	digest         string
	scope          readtarget.Scope
	targetHostname string
	targetPort     uint16
	prefixes       []netip.Prefix
	seal           *egressPolicySeal
	self           *EgressPolicy
}

func BuildEgressPolicyRef(base string, definition EgressPolicyDefinition) (string, error) {
	if !egressBasePattern.MatchString(base) || sensitiveEgressReferenceBase(base) || definition.PolicyRef != "" {
		return "", ErrEgressPolicyRejected
	}
	compiled, digest, err := compileEgressPolicy(definition)
	if err != nil || len(compiled) == 0 {
		return "", ErrEgressPolicyRejected
	}
	return base + "-v1-" + digest, nil
}

func NewEgressPolicy(definition EgressPolicyDefinition) (*EgressPolicy, error) {
	matches := egressReferencePattern.FindStringSubmatch(definition.PolicyRef)
	if len(matches) != 3 || sensitiveEgressReferenceBase(matches[1]) {
		return nil, ErrEgressPolicyRejected
	}
	prefixes, digest, err := compileEgressPolicy(definition)
	if err != nil || matches[2] != digest {
		return nil, ErrEgressPolicyRejected
	}
	policy := &EgressPolicy{
		ref: strings.Clone(definition.PolicyRef), digest: digest,
		scope: readtarget.Scope{
			TenantID: strings.Clone(definition.Scope.TenantID), WorkspaceID: strings.Clone(definition.Scope.WorkspaceID),
			EnvironmentID: strings.Clone(definition.Scope.EnvironmentID),
		},
		targetHostname: strings.Clone(definition.Hostname), targetPort: definition.Port,
		prefixes: prefixes, seal: trustedEgressPolicySeal,
	}
	policy.self = policy
	return policy, nil
}

func (policy *EgressPolicy) Ready() bool {
	return policy != nil && policy.self == policy && policy.seal == trustedEgressPolicySeal &&
		egressReferencePattern.MatchString(policy.ref) && domain.ValidSHA256Hex(policy.digest) &&
		validEgressScope(policy.scope) && validEgressHostname(policy.targetHostname) && policy.targetPort != 0 && len(policy.prefixes) > 0
}

func (policy *EgressPolicy) Ref() string {
	if !policy.Ready() {
		return ""
	}
	return policy.ref
}

func (policy *EgressPolicy) Digest() string {
	if !policy.Ready() {
		return ""
	}
	return policy.digest
}

func (policy *EgressPolicy) matchesScope(tenantID, workspaceID, environmentID string) bool {
	return policy.Ready() && policy.scope.TenantID == tenantID && policy.scope.WorkspaceID == workspaceID &&
		policy.scope.EnvironmentID == environmentID
}

func (policy *EgressPolicy) hostname() string {
	if !policy.Ready() {
		return ""
	}
	return policy.targetHostname
}

func (policy *EgressPolicy) port() uint16 {
	if !policy.Ready() {
		return 0
	}
	return policy.targetPort
}

func (EgressPolicy) String() string   { return "<aiops-read-egress-policy>" }
func (EgressPolicy) GoString() string { return "<aiops-read-egress-policy>" }
func (EgressPolicy) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-egress-policy>")
}
func (EgressPolicy) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*EgressPolicy) UnmarshalJSON([]byte) error  { return ErrEgressPolicyRejected }

func (policy *EgressPolicy) allows(address netip.Addr) bool {
	if !policy.Ready() || hardDeniedAddress(address) {
		return false
	}
	for _, prefix := range policy.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

type egressPolicyWire struct {
	SchemaVersion    string           `json:"schema_version"`
	Scope            readtarget.Scope `json:"scope"`
	Hostname         string           `json:"hostname"`
	Port             uint16           `json:"port"`
	AllowedPrefixes  []string         `json:"allowed_prefixes"`
	AllAnswersPolicy string           `json:"all_answers_policy"`
	DialPolicy       string           `json:"dial_policy"`
	HardDenyProfile  string           `json:"hard_deny_profile"`
	HardDenyPrefixes []string         `json:"hard_deny_prefixes"`
}

func compileEgressPolicy(definition EgressPolicyDefinition) ([]netip.Prefix, string, error) {
	if !validEgressScope(definition.Scope) || !validEgressHostname(definition.Hostname) || definition.Port == 0 ||
		len(definition.AllowedPrefixes) == 0 || len(definition.AllowedPrefixes) > maximumAllowedPrefixes {
		return nil, "", ErrEgressPolicyRejected
	}
	prefixes := make([]netip.Prefix, 0, len(definition.AllowedPrefixes))
	canonical := make([]string, 0, len(definition.AllowedPrefixes))
	for _, encoded := range definition.AllowedPrefixes {
		prefix, err := netip.ParsePrefix(encoded)
		if err != nil || prefix.String() != encoded || !validAllowedPrefix(prefix) {
			return nil, "", ErrEgressPolicyRejected
		}
		prefixes = append(prefixes, prefix)
		canonical = append(canonical, encoded)
	}
	sort.Slice(prefixes, func(left, right int) bool { return prefixes[left].String() < prefixes[right].String() })
	sort.Strings(canonical)
	for left := 0; left < len(prefixes); left++ {
		for right := left + 1; right < len(prefixes); right++ {
			if prefixesOverlap(prefixes[left], prefixes[right]) {
				return nil, "", ErrEgressPolicyRejected
			}
		}
	}
	wire := egressPolicyWire{
		SchemaVersion: EgressPolicySchemaVersion, Scope: definition.Scope, Hostname: definition.Hostname, Port: definition.Port,
		AllowedPrefixes: canonical, AllAnswersPolicy: allAnswersPolicyV1, DialPolicy: literalDialPolicyV1,
		HardDenyProfile: hardDenyProfileV1, HardDenyPrefixes: hardDenyPrefixStrings(),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, "", ErrEgressPolicyRejected
	}
	canonicalJSON, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return nil, "", ErrEgressPolicyRejected
	}
	digest := sha256.Sum256(canonicalJSON)
	return prefixes, hex.EncodeToString(digest[:]), nil
}

func validAllowedPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return false
	}
	switch {
	case prefix.Addr().Is4() && prefix.Bits() < minimumIPv4PrefixBits:
		return false
	case prefix.Addr().Is6() && prefix.Bits() < minimumIPv6PrefixBits:
		return false
	case !prefix.Addr().Is4() && !prefix.Addr().Is6():
		return false
	}
	for _, denied := range hardDenyPrefixes() {
		if prefixesOverlap(prefix, denied) {
			return false
		}
	}
	return true
}

func hardDeniedAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() ||
		address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsInterfaceLocalMulticast() || address.IsMulticast() {
		return true
	}
	for _, denied := range hardDenyPrefixes() {
		if denied.Contains(address) {
			return true
		}
	}
	return false
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.IsValid() && right.IsValid() &&
		(left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func validEgressScope(scope readtarget.Scope) bool {
	return egressUUIDPattern.MatchString(scope.TenantID) && egressUUIDPattern.MatchString(scope.WorkspaceID) &&
		egressUUIDPattern.MatchString(scope.EnvironmentID)
}

func validEgressHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 || hostname != strings.ToLower(hostname) || strings.HasSuffix(hostname, ".") ||
		strings.Count(hostname, ".") < 1 {
		return false
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func sensitiveEgressReferenceBase(value string) bool {
	var skeleton strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			skeleton.WriteRune(character)
		}
	}
	normalized := skeleton.String()
	for _, token := range []string{
		"authorization", "authentication", "auth", "apikey", "accessor", "secret", "token",
		"password", "credential", "cookie", "privatekey", "endpoint", "url", "host", "dsn",
	} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func hardDenyPrefixes() [13]netip.Prefix {
	return [13]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.100.100.200/32"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("168.63.129.16/32"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
		netip.MustParsePrefix("fd20:ce::254/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
}

func hardDenyPrefixStrings() []string {
	prefixes := hardDenyPrefixes()
	encoded := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		encoded[index] = prefix.String()
	}
	return encoded
}
