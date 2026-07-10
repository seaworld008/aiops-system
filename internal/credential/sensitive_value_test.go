package credential

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestSensitiveValueClonesInputAndReads(t *testing.T) {
	t.Parallel()

	input := []byte("child-token-canary")
	value, err := NewSensitiveValue(input)
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	input[0] = 'X'

	first := value.Bytes()
	if got := string(first); got != "child-token-canary" {
		t.Fatalf("Bytes() = %q", got)
	}
	first[0] = 'Y'
	if got := string(value.Bytes()); got != "child-token-canary" {
		t.Fatalf("second Bytes() = %q", got)
	}
}

func TestSensitiveValueCopiesShareIdempotentDestruction(t *testing.T) {
	t.Parallel()

	value, err := NewSensitiveValue([]byte("dynamic-secret-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	copyOfValue := value

	const callers = 32
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			copyOfValue.Destroy()
		}()
	}
	close(start)
	waitGroup.Wait()

	if got := value.Bytes(); got != nil {
		t.Fatalf("original Bytes() after copy Destroy() = %q", got)
	}
	if got := copyOfValue.Bytes(); got != nil {
		t.Fatalf("copy Bytes() after Destroy() = %q", got)
	}
	value.Destroy()
}

func TestSensitiveValueConcurrentReadsAndDestroyAreRaceSafe(t *testing.T) {
	t.Parallel()

	canary := []byte("concurrent-secret-canary")
	value, err := NewSensitiveValue(canary)
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	start := make(chan struct{})
	errorsByReader := make(chan string, 16)
	var waitGroup sync.WaitGroup
	for range 16 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for range 256 {
				got := value.Bytes()
				if got != nil && !bytes.Equal(got, canary) {
					errorsByReader <- string(got)
					return
				}
			}
		}()
	}
	close(start)
	value.Destroy()
	waitGroup.Wait()
	close(errorsByReader)
	for got := range errorsByReader {
		t.Errorf("concurrent Bytes() = %q", got)
	}
	if got := value.Bytes(); got != nil {
		t.Fatalf("Bytes() after concurrent Destroy() = %q", got)
	}
}

func TestSensitiveValueFormattingAndJSONAreAlwaysRedacted(t *testing.T) {
	t.Parallel()

	const canary = "never-render-this-secret"
	value, err := NewSensitiveValue([]byte(canary))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	formats := []string{
		fmt.Sprint(value),
		fmt.Sprintf("%s", value),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
	}
	for _, format := range []string{"%q", "%x", "%X", "%d"} {
		formats = append(formats, fmt.Sprintf(format, value))
	}
	for _, formatted := range formats {
		if strings.Contains(formatted, canary) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("formatted value = %q", formatted)
		}
	}
	// fmt reserves %p and %T for built-in pointer/type metadata and does not
	// dispatch them through Formatter. They still must never reveal material.
	for _, formatted := range []string{fmt.Sprintf("%p", value), fmt.Sprintf("%T", value)} {
		if strings.Contains(formatted, canary) {
			t.Fatalf("built-in metadata formatting exposed material: %q", formatted)
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if bytes.Contains(encoded, []byte(canary)) || string(encoded) != `{"redacted":true}` {
		t.Fatalf("JSON = %s", encoded)
	}
}

func TestSensitiveValueRejectsJSONReconstruction(t *testing.T) {
	t.Parallel()

	for _, encoded := range []string{`{"redacted":true}`, `"secret-canary"`, `null`} {
		var value SensitiveValue
		if err := json.Unmarshal([]byte(encoded), &value); !errors.Is(err, ErrInvalidSensitiveValue) {
			t.Errorf("json.Unmarshal(%s) error = %v, want ErrInvalidSensitiveValue", encoded, err)
		}
		if got := value.Bytes(); got != nil {
			t.Errorf("json.Unmarshal(%s) reconstructed material = %q", encoded, got)
		}
	}
}

func TestSensitiveValueRejectsEmptyAndOversizedInputWithoutRenderingIt(t *testing.T) {
	t.Parallel()

	if _, err := NewSensitiveValue(nil); !errors.Is(err, ErrInvalidSensitiveValue) {
		t.Fatalf("NewSensitiveValue(nil) error = %v", err)
	}
	oversized := bytes.Repeat([]byte("s"), MaxSensitiveValueSize+1)
	if _, err := NewSensitiveValue(oversized); !errors.Is(err, ErrInvalidSensitiveValue) {
		t.Fatalf("NewSensitiveValue(oversized) error = %v", err)
	} else if strings.Contains(err.Error(), string(oversized)) {
		t.Fatal("oversized error rendered sensitive input")
	}

	maximum, err := NewSensitiveValue(bytes.Repeat([]byte("m"), MaxSensitiveValueSize))
	if err != nil {
		t.Fatalf("NewSensitiveValue(maximum) error = %v", err)
	}
	maximum.Destroy()
}

func TestZeroSensitiveValueIsSafeAndRedacted(t *testing.T) {
	t.Parallel()

	var value SensitiveValue
	if got := value.Bytes(); got != nil {
		t.Fatalf("zero Bytes() = %q", got)
	}
	value.Destroy()
	if got := fmt.Sprintf("%#v", value); !strings.Contains(got, "REDACTED") {
		t.Fatalf("zero formatting = %q", got)
	}
}
