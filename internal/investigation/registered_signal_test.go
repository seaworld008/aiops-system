package investigation_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestRegisteredSignalIsRedactedAndCannotCrossSerializationBoundary(t *testing.T) {
	const canary = "registered-signal-secret-canary"
	registered := investigation.RegisteredSignal{
		TenantID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222",
		Signal: domain.Signal{
			ID: "33333333-3333-4333-8333-333333333333", WorkspaceID: "22222222-2222-4222-8222-222222222222",
			IntegrationID: "44444444-4444-4444-8444-444444444444", Provider: "alertmanager",
			ProviderEventID: canary, PayloadHash: strings.Repeat("a", 64), Fingerprint: canary,
			Status: "firing", Labels: map[string]string{"canary": canary}, ObservedAt: time.Now().UTC(),
		},
	}
	if err := registered.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	encoded, err := json.Marshal(registered)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	rendered := fmt.Sprintf("%s %#v %+v", encoded, registered, registered)
	if strings.Contains(rendered, canary) || !strings.Contains(rendered, "REDACTED") {
		t.Fatalf("registered signal rendering = %q", rendered)
	}
	var decoded investigation.RegisteredSignal
	if err := json.Unmarshal([]byte(`{"tenant_id":"11111111-1111-4111-8111-111111111111"}`), &decoded); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisteredSignalValidationRejectsScopeMismatch(t *testing.T) {
	registered := investigation.RegisteredSignal{
		TenantID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222",
		Signal: domain.Signal{WorkspaceID: "33333333-3333-4333-8333-333333333333"},
	}
	if !errors.Is(registered.Validate(), investigation.ErrInvalidRequest) {
		t.Fatalf("Validate(mismatch) should fail closed")
	}
}
