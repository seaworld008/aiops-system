package readruntime

import (
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readexecutor"
)

func TestPreparedCapabilityRejectsCrossBundleOwnerBeforeConsumption(t *testing.T) {
	digest := strings.Repeat("a", 64)
	first := &Bundle{digest: digest, seal: trustedBundleSeal}
	first.self = first
	second := &Bundle{digest: digest, seal: trustedBundleSeal}
	second.self = second
	prepared := &Prepared{
		owner: first, bundleDigest: digest, inner: new(readexecutor.Prepared),
		state: &preparedState{}, seal: trustedPreparedSeal,
	}
	prepared.self = prepared

	if inner, ok := prepared.claimFor(second); ok || inner != nil || prepared.state.claimed.Load() {
		t.Fatal("cross-Bundle claim accepted or consumed the capability")
	}
	copy := *prepared
	if inner, ok := copy.claimFor(first); ok || inner != nil || prepared.state.claimed.Load() {
		t.Fatal("copied capability retained Bundle execution authority")
	}
	inner, ok := prepared.claimFor(first)
	if !ok || inner == nil || !prepared.state.claimed.Load() {
		t.Fatal("owning Bundle could not claim its prepared capability exactly once")
	}
	if repeated, repeatedOK := prepared.claimFor(first); repeatedOK || repeated != nil {
		t.Fatal("prepared capability was claimable more than once")
	}
}
