package readrunnerclient_test

import (
	"errors"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

func TestDedicatedClientRejectsEveryNonReadPoolBeforeLoadingTrustMaterial(t *testing.T) {
	for _, pool := range []runneridentity.Pool{"", runneridentity.PoolWrite, "ADMIN"} {
		client, err := readrunnerclient.New(readrunnerclient.Options{ExpectedPool: pool})
		if client != nil || !errors.Is(err, readrunnerclient.ErrInvalidConfiguration) {
			t.Fatalf("New(pool=%q) = %#v, %v; want invalid configuration", pool, client, err)
		}
	}
}
