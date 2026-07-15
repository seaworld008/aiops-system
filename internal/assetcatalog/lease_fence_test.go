package assetcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/seaworld008/aiops-system/internal/leasefence"
)

func TestLeaseFenceIsTheExactSealedInternalAlias(t *testing.T) {
	t.Parallel()

	var zero LeaseFence
	if zero.Matches(testAssetID, "control-plane-1", 1, testDigestA) {
		t.Fatal("zero root LeaseFence matched")
	}
	zero.Destroy()

	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	original := token
	internalFence, err := leasefence.FromManualRun(testAssetID, "control-plane-1", 1, &token)
	if err != nil {
		t.Fatalf("FromManualRun() error = %v", err)
	}
	var rootFence LeaseFence = internalFence
	var roundTrip leasefence.Fence = rootFence
	digest := sha256.Sum256(original[:])
	if !roundTrip.Matches(testAssetID, "control-plane-1", 1, hex.EncodeToString(digest[:])) {
		t.Fatal("assetcatalog.LeaseFence changed the sealed fence identity or behavior")
	}
	rootFence.Destroy()
	if internalFence.Matches(testAssetID, "control-plane-1", 1, hex.EncodeToString(digest[:])) {
		t.Fatal("Destroy through root alias did not invalidate the internal fence copy")
	}
}
