package readexecutor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readtarget"
)

func TestEgressPolicyBuildsStableContentAddressAndAllowsOnlyDeclaredPrefixes(t *testing.T) {
	definition := validEgressPolicyDefinition()

	first, err := BuildEgressPolicyRef("metrics-egress", definition)
	if err != nil {
		t.Fatalf("BuildEgressPolicyRef() error = %v", err)
	}
	second, err := BuildEgressPolicyRef("metrics-egress", definition)
	if err != nil || first != second || !strings.HasPrefix(first, "metrics-egress-v1-") || len(first) != len("metrics-egress-v1-")+64 {
		t.Fatalf("BuildEgressPolicyRef() = %q / %q, %v", first, second, err)
	}

	definition.PolicyRef = first
	policy, err := NewEgressPolicy(definition)
	if err != nil || policy == nil || !policy.Ready() || policy.Ref() != first || policy.Digest() != first[len(first)-64:] {
		t.Fatalf("NewEgressPolicy() = %#v, %v", policy, err)
	}
	if !policy.matchesScope(definition.Scope.TenantID, definition.Scope.WorkspaceID, definition.Scope.EnvironmentID) ||
		policy.matchesScope(definition.Scope.TenantID, definition.Scope.WorkspaceID, "30000000-0000-4000-8000-000000000099") ||
		policy.hostname() != definition.Hostname || policy.port() != definition.Port {
		t.Fatal("constructed policy did not retain its exact safe routing identity")
	}
	for _, address := range []string{"10.42.8.12", "10.42.9.44", "2001:db8:42::12"} {
		if !policy.allows(netip.MustParseAddr(address)) {
			t.Fatalf("policy rejected declared address %s", address)
		}
	}
	for _, address := range []string{"10.42.10.1", "2001:db8:43::1", "127.0.0.1"} {
		if policy.allows(netip.MustParseAddr(address)) {
			t.Fatalf("policy allowed undeclared address %s", address)
		}
	}
}

func TestEgressPolicyDigestIsOrderIndependentAndRejectsDefinitionDrift(t *testing.T) {
	baseline := validEgressPolicyDefinition()
	want, err := BuildEgressPolicyRef("metrics-egress", baseline)
	if err != nil {
		t.Fatal(err)
	}
	reordered := cloneEgressDefinition(baseline)
	slices.Reverse(reordered.AllowedPrefixes)
	got, err := BuildEgressPolicyRef("metrics-egress", reordered)
	if err != nil || got != want {
		t.Fatalf("reordered policy ref = %q, %v; want %q", got, err, want)
	}

	for name, mutate := range map[string]func(*EgressPolicyDefinition){
		"scope": func(value *EgressPolicyDefinition) {
			value.Scope.EnvironmentID = "30000000-0000-4000-8000-000000000099"
		},
		"hostname": func(value *EgressPolicyDefinition) { value.Hostname = "logs.staging.internal" },
		"port":     func(value *EgressPolicyDefinition) { value.Port = 9443 },
		"prefix":   func(value *EgressPolicyDefinition) { value.AllowedPrefixes[0] = "10.42.11.0/24" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneEgressDefinition(baseline)
			mutate(&changed)
			changedRef, buildErr := BuildEgressPolicyRef("metrics-egress", changed)
			if buildErr != nil || changedRef == want {
				t.Fatalf("changed policy ref = %q, %v; want a distinct digest", changedRef, buildErr)
			}
			changed.PolicyRef = want
			if policy, newErr := NewEgressPolicy(changed); policy != nil || !errors.Is(newErr, ErrEgressPolicyRejected) {
				t.Fatalf("NewEgressPolicy(drift) = %#v, %v", policy, newErr)
			}
		})
	}
}

func TestEgressPolicyRejectsSpecialAndCloudMetadataAddressSpace(t *testing.T) {
	for name, prefix := range map[string]string{
		"unspecified":         "0.0.0.0/32",
		"loopback":            "127.0.0.1/32",
		"link local":          "169.254.169.0/24",
		"multicast":           "224.0.0.0/24",
		"AWS IPv6 metadata":   "fd00:ec2::254/128",
		"GCP IPv6 metadata":   "fd20:ce::254/128",
		"Azure fabric":        "168.63.129.16/32",
		"additional metadata": "100.100.100.200/32",
		"IPv6 link local":     "fe80::/64",
		"IPv6 multicast":      "ff00::/64",
		"IPv4 mapped IPv6":    "::ffff:192.0.2.1/128",
	} {
		t.Run(name, func(t *testing.T) {
			definition := validEgressPolicyDefinition()
			definition.AllowedPrefixes = []string{prefix}
			if ref, err := BuildEgressPolicyRef("metrics-egress", definition); ref != "" || !errors.Is(err, ErrEgressPolicyRejected) {
				t.Fatalf("BuildEgressPolicyRef(%s) = %q, %v; want rejection", prefix, ref, err)
			}
		})
	}
}

func TestEgressPolicyRejectsWideUnmaskedDuplicateOverlappingAndExcessivePrefixes(t *testing.T) {
	for name, prefixes := range map[string][]string{
		"IPv4 wider than slash 24": {"10.42.0.0/23"},
		"IPv6 wider than slash 64": {"2001:db8:42::/63"},
		"unmasked":                 {"10.42.8.1/24"},
		"duplicate":                {"10.42.8.0/24", "10.42.8.0/24"},
		"overlap":                  {"10.42.8.0/24", "10.42.8.128/25"},
	} {
		t.Run(name, func(t *testing.T) {
			definition := validEgressPolicyDefinition()
			definition.AllowedPrefixes = prefixes
			if ref, err := BuildEgressPolicyRef("metrics-egress", definition); ref != "" || !errors.Is(err, ErrEgressPolicyRejected) {
				t.Fatalf("BuildEgressPolicyRef(%v) = %q, %v; want rejection", prefixes, ref, err)
			}
		})
	}

	tooMany := make([]string, 33)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("10.80.%d.0/24", index)
	}
	definition := validEgressPolicyDefinition()
	definition.AllowedPrefixes = tooMany
	if ref, err := BuildEgressPolicyRef("metrics-egress", definition); ref != "" || !errors.Is(err, ErrEgressPolicyRejected) {
		t.Fatalf("BuildEgressPolicyRef(33 prefixes) = %q, %v; want rejection", ref, err)
	}
}

func TestEgressPolicyRejectsNonCanonicalIdentityAndDefinition(t *testing.T) {
	valid := validEgressPolicyDefinition()
	for name, base := range map[string]string{
		"empty":           "",
		"uppercase":       "Metrics-egress",
		"secret semantic": "secret-egress",
		"host semantic":   "target-host-policy",
	} {
		t.Run("base "+name, func(t *testing.T) {
			if ref, err := BuildEgressPolicyRef(base, valid); ref != "" || !errors.Is(err, ErrEgressPolicyRejected) {
				t.Fatalf("BuildEgressPolicyRef(%q) = %q, %v; want rejection", base, ref, err)
			}
		})
	}

	for name, mutate := range map[string]func(*EgressPolicyDefinition){
		"invalid tenant":        func(value *EgressPolicyDefinition) { value.Scope.TenantID = "tenant" },
		"uppercase hostname":    func(value *EgressPolicyDefinition) { value.Hostname = "Metrics.staging.internal" },
		"single label hostname": func(value *EgressPolicyDefinition) { value.Hostname = "localhost" },
		"IP hostname":           func(value *EgressPolicyDefinition) { value.Hostname = "192.0.2.1" },
		"zero port":             func(value *EgressPolicyDefinition) { value.Port = 0 },
		"empty prefixes":        func(value *EgressPolicyDefinition) { value.AllowedPrefixes = nil },
		"malformed prefix":      func(value *EgressPolicyDefinition) { value.AllowedPrefixes = []string{"not-a-prefix"} },
		"prepopulated ref":      func(value *EgressPolicyDefinition) { value.PolicyRef = "caller-selected" },
	} {
		t.Run(name, func(t *testing.T) {
			definition := cloneEgressDefinition(valid)
			mutate(&definition)
			if ref, err := BuildEgressPolicyRef("metrics-egress", definition); ref != "" || !errors.Is(err, ErrEgressPolicyRejected) {
				t.Fatalf("BuildEgressPolicyRef(%s) = %q, %v; want rejection", name, ref, err)
			}
		})
	}

	safeRef, err := BuildEgressPolicyRef("metrics-egress", valid)
	if err != nil {
		t.Fatal(err)
	}
	valid.PolicyRef = "secret-egress-v1-" + safeRef[len(safeRef)-64:]
	if policy, err := NewEgressPolicy(valid); policy != nil || !errors.Is(err, ErrEgressPolicyRejected) {
		t.Fatalf("NewEgressPolicy(sensitive alias) = %#v, %v; want rejection", policy, err)
	}
}

func TestEgressPolicyDetachesSourceRejectsCopiesAndRedactsEveryWireBoundary(t *testing.T) {
	definition := validEgressPolicyDefinition()
	ref, err := BuildEgressPolicyRef("metrics-egress", definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.PolicyRef = ref
	policy, err := NewEgressPolicy(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.AllowedPrefixes[0] = "10.99.99.0/24"
	if !policy.allows(netip.MustParseAddr("10.42.9.44")) || policy.allows(netip.MustParseAddr("10.99.99.1")) {
		t.Fatal("source mutation changed constructed policy")
	}

	copied := *policy
	if copied.Ready() || copied.Ref() != "" || copied.Digest() != "" || copied.hostname() != "" || copied.port() != 0 ||
		copied.matchesScope("10000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002", "30000000-0000-4000-8000-000000000003") ||
		copied.allows(netip.MustParseAddr("10.42.9.44")) {
		t.Fatal("copied policy retained authority")
	}

	encoded, err := json.Marshal(policy)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(EgressPolicy) = %s, %v", encoded, err)
	}
	rendered := fmt.Sprintf("%s %+v %#v", policy, policy, policy)
	for _, forbidden := range []string{ref, validEgressPolicyDefinition().Hostname, "10.42.9.0/24", "10000000-0000-4000-8000-000000000001"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("policy rendering leaked %q: %s", forbidden, rendered)
		}
	}
	var decoded EgressPolicy
	if err := json.Unmarshal([]byte(`{"redacted":true}`), &decoded); !errors.Is(err, ErrEgressPolicyRejected) {
		t.Fatalf("json.Unmarshal(EgressPolicy) error = %v", err)
	}
}

func validEgressPolicyDefinition() EgressPolicyDefinition {
	return EgressPolicyDefinition{
		Scope: readtarget.Scope{
			TenantID: "10000000-0000-4000-8000-000000000001", WorkspaceID: "20000000-0000-4000-8000-000000000002",
			EnvironmentID: "30000000-0000-4000-8000-000000000003",
		},
		Hostname: "metrics.staging.internal", Port: 8443,
		AllowedPrefixes: []string{"10.42.9.0/24", "10.42.8.12/32", "2001:db8:42::/64"},
	}
}

func cloneEgressDefinition(source EgressPolicyDefinition) EgressPolicyDefinition {
	source.AllowedPrefixes = append([]string(nil), source.AllowedPrefixes...)
	return source
}
