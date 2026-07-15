package leasefence_test

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/seaworld008/aiops-system/internal/leasefence"
)

const (
	fenceRunID    = "11111111-1111-4111-8111-111111111111"
	fenceOwner    = "discovery-worker-1"
	fenceEpoch    = int64(7)
	fenceRedacted = "[REDACTED_LEASE_FENCE]"
)

func TestFenceConstructorsConsumeCallerTokenOnSuccessAndEveryError(t *testing.T) {
	t.Parallel()

	constructors := map[string]func(string, string, int64, *[32]byte) (leasefence.Fence, error){
		"manual run":  leasefence.FromManualRun,
		"queue claim": leasefence.FromQueueClaim,
	}
	for constructorName, constructor := range constructors {
		constructorName, constructor := constructorName, constructor
		t.Run(constructorName, func(t *testing.T) {
			t.Parallel()
			tests := map[string]struct {
				runID string
				owner string
				epoch int64
				token *[32]byte
				want  bool
			}{
				"success":           {fenceRunID, fenceOwner, fenceEpoch, fenceToken(1), true},
				"zero raw token":    {fenceRunID, fenceOwner, fenceEpoch, new([32]byte), true},
				"maximum owner":     {fenceRunID, strings.Repeat("w", 256), fenceEpoch, fenceToken(2), true},
				"safe owner code":   {fenceRunID, "worker_1:queue@host/zone", fenceEpoch, fenceToken(3), true},
				"nil token":         {fenceRunID, fenceOwner, fenceEpoch, nil, false},
				"invalid run":       {"not-a-uuid", fenceOwner, fenceEpoch, fenceToken(4), false},
				"missing owner":     {fenceRunID, "", fenceEpoch, fenceToken(5), false},
				"untrimmed owner":   {fenceRunID, " worker-1", fenceEpoch, fenceToken(6), false},
				"control owner":     {fenceRunID, "worker\n1", fenceEpoch, fenceToken(7), false},
				"oversized owner":   {fenceRunID, strings.Repeat("w", 257), fenceEpoch, fenceToken(8), false},
				"nonpositive epoch": {fenceRunID, fenceOwner, 0, fenceToken(9), false},
				"negative epoch":    {fenceRunID, fenceOwner, -1, fenceToken(10), false},
			}
			for name, test := range tests {
				name, test := name, test
				t.Run(name, func(t *testing.T) {
					original := [32]byte{}
					if test.token != nil {
						original = *test.token
					}
					fence, err := constructor(test.runID, test.owner, test.epoch, test.token)
					if test.token != nil && *test.token != ([32]byte{}) {
						t.Fatal("constructor retained raw bytes in caller token")
					}
					if test.want {
						if err != nil {
							t.Fatalf("constructor error = %v", err)
						}
						digest := sha256.Sum256(original[:])
						if !fence.Matches(test.runID, test.owner, test.epoch, hex.EncodeToString(digest[:])) {
							t.Fatal("constructed fence does not match exact persisted coordinates/hash")
						}
						fence.Destroy()
						return
					}
					if err == nil {
						t.Fatal("invalid fence constructor error = nil")
					}
					if test.token != nil {
						assertFenceErrorRedacted(t, err, original)
					}
					digest := sha256.Sum256(original[:])
					digestText := hex.EncodeToString(digest[:])
					if fence.Matches(test.runID, test.owner, test.epoch, digestText) || fence.Matches(fenceRunID, fenceOwner, fenceEpoch, digestText) {
						t.Fatal("failed constructor returned a fence retaining the consumed raw token")
					}
				})
			}
		})
	}
}

func TestFenceMatchesOnlyExactLockedCoordinatesAndLowercaseDigest(t *testing.T) {
	t.Parallel()

	token := fenceToken(21)
	original := *token
	fence, err := leasefence.FromQueueClaim(fenceRunID, fenceOwner, fenceEpoch, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fence.Destroy)
	digest := sha256.Sum256(original[:])
	digestText := hex.EncodeToString(digest[:])
	if !fence.Matches(fenceRunID, fenceOwner, fenceEpoch, digestText) {
		t.Fatal("exact fence did not match")
	}
	for _, test := range []struct {
		name, runID, owner string
		epoch              int64
		digest             string
	}{
		{"run drift", "22222222-2222-4222-8222-222222222222", fenceOwner, fenceEpoch, digestText},
		{"owner drift", fenceRunID, "discovery-worker-2", fenceEpoch, digestText},
		{"epoch drift", fenceRunID, fenceOwner, fenceEpoch + 1, digestText},
		{"digest drift", fenceRunID, fenceOwner, fenceEpoch, strings.Repeat("0", 64)},
		{"uppercase digest", fenceRunID, fenceOwner, fenceEpoch, strings.ToUpper(digestText)},
		{"short digest", fenceRunID, fenceOwner, fenceEpoch, digestText[:62]},
		{"invalid hex", fenceRunID, fenceOwner, fenceEpoch, strings.Repeat("z", 64)},
		{"zero run", "", fenceOwner, fenceEpoch, digestText},
		{"zero owner", fenceRunID, "", fenceEpoch, digestText},
		{"zero epoch", fenceRunID, fenceOwner, 0, digestText},
	} {
		if fence.Matches(test.runID, test.owner, test.epoch, test.digest) {
			t.Errorf("Matches(%s) = true", test.name)
		}
	}
	if (leasefence.Fence{}).Matches(fenceRunID, fenceOwner, fenceEpoch, digestText) {
		t.Fatal("zero fence matched")
	}
}

func TestFenceDestroyInvalidatesAllCopies(t *testing.T) {
	t.Parallel()

	token := fenceToken(31)
	original := *token
	fence, err := leasefence.FromManualRun(fenceRunID, fenceOwner, fenceEpoch, token)
	if err != nil {
		t.Fatal(err)
	}
	copyOne := fence
	copyTwo := copyOne
	digest := sha256.Sum256(original[:])
	digestText := hex.EncodeToString(digest[:])
	if !copyTwo.Matches(fenceRunID, fenceOwner, fenceEpoch, digestText) {
		t.Fatal("fence copy did not share valid state")
	}
	copyOne.Destroy()
	for name, candidate := range map[string]leasefence.Fence{"original": fence, "copy one": copyOne, "copy two": copyTwo} {
		if candidate.Matches(fenceRunID, fenceOwner, fenceEpoch, digestText) {
			t.Errorf("%s remained valid after Destroy", name)
		}
	}
	fence.Destroy()
	copyTwo.Destroy()
}

func TestFenceRejectsEverySerializationAndRedactsEveryFormattingPath(t *testing.T) {
	t.Parallel()

	token := fenceToken(41)
	original := *token
	fence, err := leasefence.FromQueueClaim(fenceRunID, fenceOwner, fenceEpoch, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fence.Destroy)

	if _, err := json.Marshal(fence); err == nil {
		t.Fatal("json.Marshal(Fence) error = nil")
	} else {
		assertFenceErrorRedacted(t, err, original)
	}
	if err := json.Unmarshal([]byte(`{}`), &fence); err == nil {
		t.Fatal("json.Unmarshal(Fence) error = nil")
	} else {
		assertFenceErrorRedacted(t, err, original)
	}
	textMarshaler, ok := any(fence).(encoding.TextMarshaler)
	if !ok {
		t.Fatal("Fence does not implement encoding.TextMarshaler")
	}
	if _, err := textMarshaler.MarshalText(); err == nil {
		t.Fatal("MarshalText() error = nil")
	} else {
		assertFenceErrorRedacted(t, err, original)
	}
	textUnmarshaler, ok := any(&fence).(encoding.TextUnmarshaler)
	if !ok {
		t.Fatal("*Fence does not implement encoding.TextUnmarshaler")
	}
	if err := textUnmarshaler.UnmarshalText([]byte("forged")); err == nil {
		t.Fatal("UnmarshalText() error = nil")
	} else {
		assertFenceErrorRedacted(t, err, original)
	}
	binaryMarshaler, ok := any(fence).(encoding.BinaryMarshaler)
	if !ok {
		t.Fatal("Fence does not implement encoding.BinaryMarshaler")
	}
	if _, err := binaryMarshaler.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary() error = nil")
	} else {
		assertFenceErrorRedacted(t, err, original)
	}
	binaryUnmarshaler, ok := any(&fence).(encoding.BinaryUnmarshaler)
	if !ok {
		t.Fatal("*Fence does not implement encoding.BinaryUnmarshaler")
	}
	if err := binaryUnmarshaler.UnmarshalBinary([]byte("forged")); err == nil {
		t.Fatal("UnmarshalBinary() error = nil")
	} else {
		assertFenceErrorRedacted(t, err, original)
	}

	for format, got := range map[string]string{
		"String":   fence.String(),
		"GoString": fence.GoString(),
		"%v":       fmt.Sprintf("%v", fence),
		"%+v":      fmt.Sprintf("%+v", fence),
		"%#v":      fmt.Sprintf("%#v", fence),
		"%s":       fmt.Sprintf("%s", fence),
		"%q":       fmt.Sprintf("%q", fence),
		"%x":       fmt.Sprintf("%x", fence),
		"pointer":  fmt.Sprintf("%+v", &fence),
	} {
		if got != fenceRedacted {
			t.Errorf("%s formatting = %q, want exact redaction", format, got)
		}
	}
	if value := fence.LogValue(); value.Kind() != slog.KindString || value.String() != fenceRedacted {
		t.Fatalf("Fence.LogValue() = %#v", value)
	}
	if value := slog.AnyValue(fence).Resolve(); value.Kind() != slog.KindString || value.String() != fenceRedacted {
		t.Fatalf("slog.AnyValue(Fence).Resolve() = %#v", value)
	}
	digest := sha256.Sum256(original[:])
	if !fence.Matches(fenceRunID, fenceOwner, fenceEpoch, hex.EncodeToString(digest[:])) {
		t.Fatal("failed serialization attempt mutated the valid fence")
	}
}

func TestFenceMatchesAndDestroyAreRaceSafe(t *testing.T) {
	token := fenceToken(51)
	original := *token
	fence, err := leasefence.FromQueueClaim(fenceRunID, fenceOwner, fenceEpoch, token)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(original[:])
	digestText := hex.EncodeToString(digest[:])
	if !fence.Matches(fenceRunID, fenceOwner, fenceEpoch, digestText) {
		t.Fatal("pre-race fence mismatch")
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		copy := fence
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 2000; iteration++ {
				_ = copy.Matches(fenceRunID, fenceOwner, fenceEpoch, digestText)
				_ = copy.String()
				_ = copy.LogValue()
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		fence.Destroy()
	}()
	close(start)
	wait.Wait()
	if fence.Matches(fenceRunID, fenceOwner, fenceEpoch, digestText) {
		t.Fatal("fence matched after concurrent Destroy")
	}
}

func fenceToken(seed byte) *[32]byte {
	value := new([32]byte)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}

func assertFenceErrorRedacted(t *testing.T, err error, token [32]byte) {
	t.Helper()
	errorText := err.Error()
	text := strings.ToLower(errorText)
	rawHex := hex.EncodeToString(token[:])
	if strings.Contains(errorText, string(token[:])) || strings.Contains(text, rawHex) {
		t.Fatalf("fence error exposed raw token material: %q", err)
	}
}
