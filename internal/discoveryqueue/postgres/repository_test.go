package postgres

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
)

func TestClaimResultRejectsEverySerializationAndLoggingSurface(t *testing.T) {
	t.Parallel()

	var result discoveryqueue.ClaimResult
	if _, err := json.Marshal(result); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &result); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := result.MarshalText(); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Errorf("MarshalText() error = %v, want ErrSensitiveSerialization", err)
	}
	if _, err := result.MarshalBinary(); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Errorf("MarshalBinary() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := result.UnmarshalText(nil); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Errorf("UnmarshalText() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := result.UnmarshalBinary(nil); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Errorf("UnmarshalBinary() error = %v, want ErrSensitiveSerialization", err)
	}
	if got := fmt.Sprint(result); got != discoveryqueue.ClaimResultRedaction {
		t.Fatalf("fmt.Sprint() = %q, want fixed redaction", got)
	}
	if got := fmt.Sprintf("%#v", result); got != discoveryqueue.ClaimResultRedaction {
		t.Fatalf("fmt %%#v = %q, want fixed redaction", got)
	}
	if got := result.LogValue(); got.Kind() != slog.KindString || got.String() != discoveryqueue.ClaimResultRedaction {
		t.Fatalf("LogValue() = %#v, want fixed string redaction", got)
	}
}

func TestCleanupProofIsBoundedClonedDestroyedAndNonSerializable(t *testing.T) {
	t.Parallel()
	coordinates := discoveryqueue.RunCoordinates{
		Scope: assetcatalog.SourceScope{
			TenantID:    "10000000-0000-4000-8000-000000000001",
			WorkspaceID: "20000000-0000-4000-8000-000000000001",
		},
		RunID: "30000000-0000-4000-8000-000000000001",
	}
	attempt := discoveryqueue.CleanupAttempt{
		RunID: coordinates.RunID, AttemptID: "40000000-0000-4000-8000-000000000001", AttemptEpoch: 7,
	}
	authentication := bytes.Repeat([]byte{0x5a}, 32)
	proof, err := discoveryqueue.NewCleanupProof(
		coordinates, attempt, assetcatalog.CredentialCleanupRevoked,
		strings.Repeat("a", 64), authentication,
	)
	if err != nil {
		t.Fatalf("NewCleanupProof() error = %v", err)
	}
	authentication[0] = 0
	first := proof.Authentication()
	if first[0] != 0x5a {
		t.Fatal("CleanupProof retained the caller authentication slice")
	}
	first[0] = 0
	if proof.Authentication()[0] != 0x5a {
		t.Fatal("CleanupProof exposed mutable authentication storage")
	}
	clone := proof.Clone()
	clone.Destroy()
	if proof.Validate() != nil || clone.Validate() == nil {
		t.Fatal("destroying a clone changed the original or left the clone valid")
	}

	if _, err := json.Marshal(proof); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal() error = %v, want ErrSensitiveSerialization", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &proof); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrSensitiveSerialization", err)
	}
	for name, operation := range map[string]func() error{
		"marshal text":     func() error { _, err := proof.MarshalText(); return err },
		"unmarshal text":   func() error { return proof.UnmarshalText(nil) },
		"marshal binary":   func() error { _, err := proof.MarshalBinary(); return err },
		"unmarshal binary": func() error { return proof.UnmarshalBinary(nil) },
	} {
		if err := operation(); !errors.Is(err, discoveryqueue.ErrSensitiveSerialization) {
			t.Errorf("%s error = %v, want ErrSensitiveSerialization", name, err)
		}
	}
	const redaction = "[REDACTED_CLEANUP_PROOF]"
	if got := fmt.Sprint(proof); got != redaction {
		t.Fatalf("fmt.Sprint() = %q, want fixed redaction", got)
	}
	if got := fmt.Sprintf("%#v", proof); got != redaction {
		t.Fatalf("fmt %%#v = %q, want fixed redaction", got)
	}
	if got := proof.LogValue(); got.Kind() != slog.KindString || got.String() != redaction {
		t.Fatalf("LogValue() = %#v, want fixed string redaction", got)
	}
	proof.Destroy()
}

func TestDurableQueueValuesCannotCarryLeaseFence(t *testing.T) {
	t.Parallel()
	fenceType := reflect.TypeOf(assetcatalog.LeaseFence{})
	values := []any{
		discoveryqueue.RunCoordinates{}, discoveryqueue.RunCommand{}, discoveryqueue.ClaimCommand{},
		discoveryqueue.ReapCommand{}, discoveryqueue.CancelCommand{}, discoveryqueue.HeartbeatCommand{},
		discoveryqueue.AdvanceStageCommand{}, discoveryqueue.DelayIntent{}, discoveryqueue.PersistedDelay{},
		discoveryqueue.CleanupAttempt{}, discoveryqueue.CleanupResult{}, discoveryqueue.DelayCommand{},
		discoveryqueue.ValidationResultCommand{}, discoveryqueue.FailureIntentCommand{},
		discoveryqueue.WorkResult{}, discoveryqueue.RolloverCommand{},
		discoveryqueue.CheckpointLineageRolloverRequest{}, discoveryqueue.RolloverResult{},
		discoveryqueue.TerminalCommand{}, discoveryqueue.TerminalResult{}, discoveryqueue.CancelResult{},
	}
	for _, value := range values {
		if typeContains(reflect.TypeOf(value), fenceType, make(map[reflect.Type]bool)) {
			t.Fatalf("durable Queue value %T contains LeaseFence", value)
		}
	}
	claimType := reflect.TypeOf(discoveryqueue.ClaimResult{})
	field, found := claimType.FieldByName("Fence")
	if !found || field.Type != fenceType {
		t.Fatalf("ClaimResult Fence field = %#v", field)
	}
}

func TestRepositoryConstructorAndValidationCheckpointBoundaryFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := newRepository(nil, nil, nil, nil, nil); !errors.Is(err, discoveryqueue.ErrInvalidRequest) {
		t.Fatalf("newRepository(nil) error = %v, want ErrInvalidRequest", err)
	}
	validationSQL := strings.ToLower(lockValidationSourceSQL)
	if strings.Contains(validationSQL, "checkpoint_") || strings.Contains(validationSQL, "select *") {
		t.Fatalf("validation source lock includes checkpoint or wildcard columns: %s", lockValidationSourceSQL)
	}
	dataSQL := strings.ToLower(lockDataSourceSQL)
	if !strings.Contains(dataSQL, "checkpoint_sha256") || !strings.Contains(dataSQL, "checkpoint_version") ||
		strings.Contains(dataSQL, "checkpoint_ciphertext") || strings.Contains(dataSQL, "checkpoint_key_id") {
		t.Fatalf("data source lock has unsafe or incomplete checkpoint metadata: %s", lockDataSourceSQL)
	}
	if (discoveryqueue.HeartbeatCommand{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{
				TenantID:    "10000000-0000-4000-8000-000000000001",
				WorkspaceID: "20000000-0000-4000-8000-000000000001",
			},
			RunID: "30000000-0000-4000-8000-000000000001",
		},
		Sequence: 1, Extension: time.Microsecond + time.Nanosecond,
	}).Validate() == nil {
		t.Fatal("HeartbeatCommand accepted sub-microsecond persistence ambiguity")
	}
}

func typeContains(value, target reflect.Type, seen map[reflect.Type]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	if value == target {
		return true
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return typeContains(value.Elem(), target, seen)
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if typeContains(value.Field(index).Type, target, seen) {
				return true
			}
		}
	}
	return false
}

var _ encoding.TextMarshaler = discoveryqueue.ClaimResult{}
var _ encoding.BinaryMarshaler = discoveryqueue.ClaimResult{}
