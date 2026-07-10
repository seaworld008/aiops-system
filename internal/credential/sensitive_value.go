package credential

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

const MaxSensitiveValueSize = 64 << 10

var ErrInvalidSensitiveValue = errors.New("invalid sensitive value")

type sensitiveValueState struct {
	mu    sync.RWMutex
	value []byte
}

// SensitiveValue owns short-lived bearer or secret material. Value copies
// share the same state, so destroying any copy clears every copy. Bytes always
// returns a clone and formatting is deliberately non-revealing.
type SensitiveValue struct {
	state *sensitiveValueState
}

func NewSensitiveValue(value []byte) (SensitiveValue, error) {
	if len(value) == 0 || len(value) > MaxSensitiveValueSize {
		return SensitiveValue{}, ErrInvalidSensitiveValue
	}
	return SensitiveValue{state: &sensitiveValueState{value: bytes.Clone(value)}}, nil
}

func (value SensitiveValue) Bytes() []byte {
	if value.state == nil {
		return nil
	}
	value.state.mu.RLock()
	defer value.state.mu.RUnlock()
	return bytes.Clone(value.state.value)
}

func (value SensitiveValue) Destroy() {
	if value.state == nil {
		return
	}
	value.state.mu.Lock()
	defer value.state.mu.Unlock()
	clear(value.state.value)
	value.state.value = nil
}

func (SensitiveValue) String() string   { return "[REDACTED SENSITIVE VALUE]" }
func (SensitiveValue) GoString() string { return "[REDACTED SENSITIVE VALUE]" }

func (SensitiveValue) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED SENSITIVE VALUE]")
}

func (SensitiveValue) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

func (*SensitiveValue) UnmarshalJSON([]byte) error {
	return ErrInvalidSensitiveValue
}
