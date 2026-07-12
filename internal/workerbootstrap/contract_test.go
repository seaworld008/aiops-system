package workerbootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestPublicCapabilityIsRedactedNonSerializableAndRejectsCopies(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "bootstrap-capability")
	if err != nil {
		t.Fatal(err)
	}
	summary := PublicSourceSummary{
		SchemaVersion:  PublicSourceSchemaVersion,
		ManifestSHA256: strings.Repeat("a", 64),
		EnvelopeSHA256: strings.Repeat("b", 64),
		EnvelopeSize:   128,
	}
	capability := newPublicSourceCapability(file, summary)
	if got := capability.Summary(); got != summary {
		t.Fatalf("Summary() = %#v, want %#v", got, summary)
	}

	canary := "bootstrap-secret-canary"
	for _, value := range []any{capability, *capability} {
		for _, rendered := range []string{
			fmt.Sprint(value), fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value),
		} {
			if strings.Contains(rendered, canary) || !strings.Contains(rendered, "REDACTED") {
				t.Fatalf("capability formatting was not fixed redaction: %q", rendered)
			}
		}
		if encoded, marshalErr := json.Marshal(value); marshalErr == nil || len(encoded) != 0 {
			t.Fatalf("json.Marshal(%T) = %q, %v; want rejection", value, encoded, marshalErr)
		}
	}
	if err := json.Unmarshal([]byte(`{"schema_version":"`+canary+`"}`), &PublicSourceCapability{}); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrBootstrapRejected", err)
	}

	copy := *capability
	if got := copy.Summary(); got != (PublicSourceSummary{}) {
		t.Fatalf("copied Summary() = %#v, want zero", got)
	}
	if err := copy.Close(); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("copied Close() error = %v, want ErrBootstrapRejected", err)
	}
	if got := capability.Summary(); got != summary {
		t.Fatal("closing a copied capability damaged the original")
	}
	if err := capability.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := capability.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := capability.Summary(); got != (PublicSourceSummary{}) {
		t.Fatalf("closed Summary() = %#v, want zero", got)
	}
}

func TestPublicCapabilityConcurrentCloseHasOneLifecycle(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "bootstrap-capability")
	if err != nil {
		t.Fatal(err)
	}
	capability := newPublicSourceCapability(file, PublicSourceSummary{
		SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: strings.Repeat("a", 64),
		EnvelopeSHA256: strings.Repeat("b", 64), EnvelopeSize: 1,
	})
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- capability.Close()
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for closeErr := range errorsSeen {
		if closeErr != nil {
			t.Fatalf("concurrent Close() error = %v", closeErr)
		}
	}
	if got := capability.Summary(); got != (PublicSourceSummary{}) {
		t.Fatalf("closed Summary() = %#v, want zero", got)
	}
}
