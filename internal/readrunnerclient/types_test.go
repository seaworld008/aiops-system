package readrunnerclient_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

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

func TestDedicatedClientReadinessRejectsZeroAndCopyValues(t *testing.T) {
	var zero readrunnerclient.Client
	if zero.Ready() {
		t.Fatal("zero Client reported ready")
	}
	fixture := newGatewayFixture(t, runneridentity.PoolRead, func(http.ResponseWriter, *http.Request) {})
	client, err := readrunnerclient.New(fixture.options)
	if err != nil || !client.Ready() {
		t.Fatalf("New() readiness = %t, %v", client != nil && client.Ready(), err)
	}
	copy := *client
	if copy.Ready() {
		t.Fatal("copied Client retained readiness")
	}
	expected, _ := validExpectedTaskAndDescriptor(t, time.Now().UTC().Truncate(time.Microsecond))
	if lease, claimErr := copy.Claim(context.Background(), expected); lease != nil ||
		!errors.Is(claimErr, readrunnerclient.ErrInvalidConfiguration) {
		t.Fatalf("copied Client Claim() = %#v, %v", lease, claimErr)
	}
}
