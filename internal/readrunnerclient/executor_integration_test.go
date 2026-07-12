package readrunnerclient_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
)

func TestAuthenticatedStartCapabilityIsTheOnlyPublicExecutorStartAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected, descriptor := validExpectedTaskAndDescriptor(t, now)
	token := base64.RawURLEncoding.EncodeToString(bytesOf(0x63, 32))
	step := 0
	fixture := newGatewayFixture(t, runneridentity.PoolRead, func(writer http.ResponseWriter, _ *http.Request) {
		step++
		switch step {
		case 1:
			writeJSON(t, writer, http.StatusOK, claimResponse(descriptor, token, 3, 7, now.Add(30*time.Second)))
		case 2:
			writeJSON(t, writer, http.StatusOK, map[string]any{
				"schema_version": "runner-read-task-start-response.v1", "task_id": expected.TaskID,
				"attempt_status": "RUNNING", "lease_epoch": "3", "scope_revision": "7", "started_at": now,
			})
		default:
			t.Fatalf("unexpected Gateway request %d", step)
		}
	})
	client, err := readrunnerclient.New(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	lease, err := client.Claim(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Destroy)
	capability, err := client.Start(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	start, err := readexecutor.NewExecutionStart(capability)
	if err != nil || start == nil {
		t.Fatalf("NewExecutionStart(authenticated capability) = %#v, %v", start, err)
	}

	copied := *capability
	if forged, forgeErr := readexecutor.NewExecutionStart(&copied); forged != nil ||
		!errors.Is(forgeErr, readexecutor.ErrStartRejected) {
		t.Fatalf("NewExecutionStart(copied capability) = %#v, %v", forged, forgeErr)
	}
	lease.Destroy()
	if stale, staleErr := readexecutor.NewExecutionStart(capability); stale != nil ||
		!errors.Is(staleErr, readexecutor.ErrStartRejected) {
		t.Fatalf("NewExecutionStart(destroyed lease capability) = %#v, %v", stale, staleErr)
	}
	if step != 2 {
		t.Fatalf("Gateway requests = %d, want 2", step)
	}
}
