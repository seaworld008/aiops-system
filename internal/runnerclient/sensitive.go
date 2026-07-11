package runnerclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type bearer struct {
	mu    sync.Mutex
	value []byte
}

func newBearer(value []byte) *bearer {
	return &bearer{value: value}
}

func (secret *bearer) withValue(operation func([]byte) error) error {
	if secret == nil || operation == nil {
		return ErrSensitiveDestroyed
	}
	secret.mu.Lock()
	defer secret.mu.Unlock()
	if len(secret.value) == 0 {
		return ErrSensitiveDestroyed
	}
	return operation(secret.value)
}

func (secret *bearer) Destroy() {
	if secret == nil {
		return
	}
	secret.mu.Lock()
	clear(secret.value)
	secret.value = nil
	secret.mu.Unlock()
}

func (secret *bearer) alive() bool {
	if secret == nil {
		return false
	}
	secret.mu.Lock()
	defer secret.mu.Unlock()
	return len(secret.value) != 0
}

func (secret *bearer) take() ([]byte, error) {
	if secret == nil {
		return nil, ErrSensitiveDestroyed
	}
	secret.mu.Lock()
	defer secret.mu.Unlock()
	if len(secret.value) == 0 {
		return nil, ErrSensitiveDestroyed
	}
	value := bytes.Clone(secret.value)
	clear(secret.value)
	secret.value = nil
	return value, nil
}

func writeRedacted(state fmt.State, label string) {
	_, _ = io.WriteString(state, label+"{Security:[REDACTED]}")
}

type redactedJSON struct {
	Redacted bool `json:"redacted"`
}

func marshalRedacted() ([]byte, error) {
	return json.Marshal(redactedJSON{Redacted: true})
}
