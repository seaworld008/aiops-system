package workerbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestPublicSourceCapabilityStartsExactlyOnceAndClosesParentHandle(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "bootstrap-transfer")
	if err != nil {
		t.Fatal(err)
	}
	capability := newPublicSourceCapability(file, PublicSourceSummary{
		SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: strings.Repeat("a", 64),
		EnvelopeSHA256: strings.Repeat("b", 64), EnvelopeSize: 1,
	})
	if err := capability.startChild(func(inherited *os.File) error {
		if inherited != file {
			t.Fatal("startChild changed the owned descriptor")
		}
		return nil
	}); err != nil {
		t.Fatalf("startChild() error = %v", err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("parent descriptor remained open after transfer")
	}
	if got := capability.Summary(); got != (PublicSourceSummary{}) {
		t.Fatalf("transferred Summary() = %#v, want zero", got)
	}
	if err := capability.startChild(func(*os.File) error { return nil }); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("second startChild() error = %v", err)
	}
	if err := capability.Close(); err != nil {
		t.Fatalf("Close() after transfer error = %v", err)
	}
}

func TestPublicSourceCapabilityStartFailureAndPanicCloseTheHandle(t *testing.T) {
	for name, start := range map[string]func(*os.File) error{
		"error": func(*os.File) error { return context.DeadlineExceeded },
		"panic": func(*os.File) error { panic("bootstrap-transfer-canary") },
	} {
		t.Run(name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "bootstrap-transfer")
			if err != nil {
				t.Fatal(err)
			}
			capability := newPublicSourceCapability(file, PublicSourceSummary{
				SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: strings.Repeat("a", 64),
				EnvelopeSHA256: strings.Repeat("b", 64), EnvelopeSize: 1,
			})
			if err := capability.startChild(start); !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("startChild() error = %v, want ErrBootstrapRejected", err)
			}
			if _, err := file.Stat(); err == nil {
				t.Fatal("failed transfer left the parent descriptor open")
			}
		})
	}
}

func TestPublicSourceCapabilityStartAndCloseHaveOneWinner(t *testing.T) {
	for iteration := range 100 {
		file, err := os.CreateTemp(t.TempDir(), "bootstrap-transfer-race")
		if err != nil {
			t.Fatal(err)
		}
		capability := newPublicSourceCapability(file, PublicSourceSummary{
			SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: strings.Repeat("a", 64),
			EnvelopeSHA256: strings.Repeat("b", 64), EnvelopeSize: 1,
		})
		entered := make(chan struct{})
		release := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			result <- capability.startChild(func(*os.File) error {
				close(entered)
				<-release
				return nil
			})
		}()
		<-entered
		if err := capability.Close(); !errors.Is(err, ErrBootstrapRejected) {
			t.Fatalf("iteration %d concurrent Close() error = %v", iteration, err)
		}
		close(release)
		if err := <-result; err != nil {
			t.Fatalf("iteration %d startChild() error = %v", iteration, err)
		}
	}

	file, err := os.CreateTemp(t.TempDir(), "bootstrap-close-first")
	if err != nil {
		t.Fatal(err)
	}
	capability := newPublicSourceCapability(file, PublicSourceSummary{
		SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: strings.Repeat("a", 64),
		EnvelopeSHA256: strings.Repeat("b", 64), EnvelopeSize: 1,
	})
	if err := capability.Close(); err != nil {
		t.Fatal(err)
	}
	if err := capability.startChild(func(*os.File) error { return nil }); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("startChild() after Close error = %v", err)
	}
}

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
