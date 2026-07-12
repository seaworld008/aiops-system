package workerbootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestInheritedSourceIsRedactedNonSerializableAndRejectsCopies(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "inherited-source")
	if err != nil {
		t.Fatal(err)
	}
	summary := PublicSourceSummary{
		SchemaVersion: PublicSourceSchemaVersion, ManifestSHA256: strings.Repeat("a", 64),
		EnvelopeSHA256: strings.Repeat("b", 64), EnvelopeSize: 1,
	}
	source := newInheritedSource(file, summary)
	for _, rendered := range []string{fmt.Sprint(source), fmt.Sprintf("%+v", source), fmt.Sprintf("%#v", source)} {
		if !strings.Contains(rendered, "REDACTED") {
			t.Fatalf("InheritedSource formatting = %q", rendered)
		}
	}
	if encoded, marshalErr := json.Marshal(source); marshalErr == nil || len(encoded) != 0 {
		t.Fatalf("json.Marshal() = %q, %v", encoded, marshalErr)
	}
	if err := json.Unmarshal([]byte(`{"canary":true}`), &InheritedSource{}); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	copy := *source
	if copy.Summary() != (PublicSourceSummary{}) || !errors.Is(copy.Close(), ErrBootstrapRejected) {
		t.Fatal("copied InheritedSource was accepted")
	}
	if source.Summary() != summary {
		t.Fatal("copy rejection damaged original source")
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
