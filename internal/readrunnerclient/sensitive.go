package readrunnerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
)

type bearer struct {
	mu    sync.Mutex
	value []byte
}

func newBearer(value []byte) *bearer {
	created := &bearer{value: bytes.Clone(value)}
	clear(value)
	return created
}

func (value *bearer) borrow(use func([]byte) error) error {
	if value == nil || use == nil {
		return ErrInvalidLease
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	if !validLeaseToken(value.value) {
		return ErrInvalidLease
	}
	copyValue := bytes.Clone(value.value)
	defer clear(copyValue)
	return use(copyValue)
}

func (value *bearer) destroy() {
	if value == nil {
		return
	}
	value.mu.Lock()
	clear(value.value)
	value.value = nil
	value.mu.Unlock()
}

type sensitiveASCII struct{ value []byte }

func (secret *sensitiveASCII) UnmarshalJSON(encoded []byte) error {
	if secret == nil || len(secret.value) != 0 || len(encoded) < 3 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return ErrInvalidResponse
	}
	value := encoded[1 : len(encoded)-1]
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return ErrInvalidResponse
		}
	}
	secret.value = bytes.Clone(value)
	return nil
}

func (*sensitiveASCII) MarshalJSON() ([]byte, error) {
	return nil, errors.New("sensitive READ Runner wire value cannot be marshaled")
}

func (secret *sensitiveASCII) take() []byte {
	if secret == nil {
		return nil
	}
	value := secret.value
	secret.value = nil
	return value
}

func (secret *sensitiveASCII) clear() {
	if secret == nil {
		return
	}
	clear(secret.value)
	secret.value = nil
}

func marshalRedacted() ([]byte, error) {
	return json.Marshal(struct {
		Redacted bool `json:"redacted"`
	}{Redacted: true})
}
