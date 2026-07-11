package credential

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const (
	refEncryptionKeySize = 32
	minRefHMACKeySize    = 32
	maxReferenceSize     = 4096
)

type ProtectionKey struct {
	EncryptionKey []byte
	HMACKey       []byte
}

func (ProtectionKey) String() string   { return "[REDACTED PROTECTION KEY]" }
func (ProtectionKey) GoString() string { return "[REDACTED PROTECTION KEY]" }

func (ProtectionKey) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

type KeyRing struct {
	ActiveKeyID string
	Keys        map[string]ProtectionKey
}

func (ring KeyRing) String() string {
	return fmt.Sprintf("KeyRing{ActiveKeyID:%q Keys:[REDACTED]}", ring.ActiveKeyID)
}

func (ring KeyRing) GoString() string { return ring.String() }

func (ring KeyRing) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ActiveKeyID string `json:"active_key_id"`
		Redacted    bool   `json:"redacted"`
	}{ActiveKeyID: ring.ActiveKeyID, Redacted: true})
}

type ReferenceContext struct {
	RevocationID   string
	ActionID       string
	ActionEpoch    int64
	Issuer         string
	IssuerRevision string
}

type ProtectedReference struct {
	Ciphertext   []byte `json:"-"`
	AccessorHMAC []byte `json:"-"`
	KeyID        string `json:"key_id"`
}

func (ProtectedReference) String() string   { return "[REDACTED PROTECTED REFERENCE]" }
func (ProtectedReference) GoString() string { return "[REDACTED PROTECTED REFERENCE]" }

func (reference ProtectedReference) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		KeyID    string `json:"key_id"`
		Redacted bool   `json:"redacted"`
	}{KeyID: reference.KeyID, Redacted: true})
}

func (reference ProtectedReference) clone() ProtectedReference {
	return ProtectedReference{
		Ciphertext:   append([]byte(nil), reference.Ciphertext...),
		AccessorHMAC: append([]byte(nil), reference.AccessorHMAC...),
		KeyID:        reference.KeyID,
	}
}

type sensitiveReferenceState struct {
	mu    sync.Mutex
	value []byte
}

type SensitiveReference struct {
	state *sensitiveReferenceState
}

func NewSensitiveReference(value []byte) (*SensitiveReference, error) {
	if len(value) == 0 || len(value) > maxReferenceSize {
		return nil, ErrInvalidRevocationRequest
	}
	return &SensitiveReference{state: &sensitiveReferenceState{value: bytes.Clone(value)}}, nil
}

func (reference *SensitiveReference) Bytes() []byte {
	if reference == nil || reference.state == nil {
		return nil
	}
	reference.state.mu.Lock()
	defer reference.state.mu.Unlock()
	return bytes.Clone(reference.state.value)
}

func (reference *SensitiveReference) Destroy() {
	if reference == nil || reference.state == nil {
		return
	}
	reference.state.mu.Lock()
	defer reference.state.mu.Unlock()
	clear(reference.state.value)
	reference.state.value = nil
}

func (SensitiveReference) String() string   { return "[REDACTED SENSITIVE REFERENCE]" }
func (SensitiveReference) GoString() string { return "[REDACTED SENSITIVE REFERENCE]" }

func (SensitiveReference) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

type ReferenceProtector interface {
	Protect(ReferenceContext, *SensitiveReference) (ProtectedReference, error)
	Matches(ReferenceContext, ProtectedReference, *SensitiveReference) (bool, error)
	Unprotect(ReferenceContext, ProtectedReference) (*SensitiveReference, error)
}

type AESGCMProtector struct {
	mu          sync.RWMutex
	activeKeyID string
	keys        map[string]ProtectionKey
	random      io.Reader
	destroyed   bool
}

func (protector *AESGCMProtector) String() string {
	if protector == nil {
		return "AESGCMProtector{Destroyed:true Keys:[REDACTED]}"
	}
	protector.mu.RLock()
	defer protector.mu.RUnlock()
	return fmt.Sprintf("AESGCMProtector{ActiveKeyID:%q Destroyed:%t Keys:[REDACTED]}", protector.activeKeyID, protector.destroyed)
}

func (protector *AESGCMProtector) GoString() string { return protector.String() }

func (protector *AESGCMProtector) MarshalJSON() ([]byte, error) {
	if protector == nil {
		return []byte(`{"redacted":true,"destroyed":true}`), nil
	}
	protector.mu.RLock()
	defer protector.mu.RUnlock()
	return json.Marshal(struct {
		ActiveKeyID string `json:"active_key_id"`
		Redacted    bool   `json:"redacted"`
		Destroyed   bool   `json:"destroyed"`
	}{ActiveKeyID: protector.activeKeyID, Redacted: true, Destroyed: protector.destroyed})
}

var _ ReferenceProtector = (*AESGCMProtector)(nil)

func NewAESGCMProtector(ring KeyRing) (*AESGCMProtector, error) {
	if !ValidIdentifier(ring.ActiveKeyID, 128) || len(ring.Keys) == 0 {
		return nil, ErrReferenceProtection
	}
	for keyID, key := range ring.Keys {
		if !ValidIdentifier(keyID, 128) || len(key.EncryptionKey) != refEncryptionKeySize ||
			len(key.HMACKey) < minRefHMACKeySize || bytes.Equal(key.EncryptionKey, key.HMACKey) {
			return nil, ErrReferenceProtection
		}
	}
	if _, ok := ring.Keys[ring.ActiveKeyID]; !ok {
		return nil, ErrReferenceProtection
	}
	keys := make(map[string]ProtectionKey, len(ring.Keys))
	for keyID, key := range ring.Keys {
		keys[keyID] = ProtectionKey{
			EncryptionKey: bytes.Clone(key.EncryptionKey),
			HMACKey:       bytes.Clone(key.HMACKey),
		}
	}
	return &AESGCMProtector{activeKeyID: ring.ActiveKeyID, keys: keys, random: rand.Reader}, nil
}

func (protector *AESGCMProtector) Protect(context ReferenceContext, reference *SensitiveReference) (ProtectedReference, error) {
	if protector == nil || !validReferenceContext(context) || reference == nil {
		return ProtectedReference{}, ErrReferenceProtection
	}
	protector.mu.RLock()
	defer protector.mu.RUnlock()
	if protector.destroyed {
		return ProtectedReference{}, ErrReferenceProtection
	}
	plaintext := reference.Bytes()
	defer clear(plaintext)
	if len(plaintext) == 0 || len(plaintext) > maxReferenceSize {
		return ProtectedReference{}, ErrReferenceProtection
	}
	key, ok := protector.keys[protector.activeKeyID]
	if !ok {
		return ProtectedReference{}, ErrReferenceProtection
	}
	aead, err := newGCM(key.EncryptionKey)
	if err != nil {
		return ProtectedReference{}, ErrReferenceProtection
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(protector.random, nonce); err != nil {
		return ProtectedReference{}, ErrReferenceProtection
	}
	aad := referenceAAD(context)
	ciphertext := aead.Seal(nonce, nonce, plaintext, aad)
	return ProtectedReference{
		Ciphertext:   ciphertext,
		AccessorHMAC: referenceHMAC(key.HMACKey, aad, plaintext),
		KeyID:        protector.activeKeyID,
	}, nil
}

// Matches authenticates an incoming accessor against the stable keyed digest
// written by Protect. It deliberately does not decrypt stored ciphertext, so
// repositories can reserve Unprotect exclusively for a successful claim.
func (protector *AESGCMProtector) Matches(context ReferenceContext, protected ProtectedReference, reference *SensitiveReference) (bool, error) {
	if protector == nil || !validReferenceContext(context) || reference == nil ||
		!ValidIdentifier(protected.KeyID, 128) || len(protected.AccessorHMAC) != sha256.Size {
		return false, ErrReferenceProtection
	}
	protector.mu.RLock()
	defer protector.mu.RUnlock()
	if protector.destroyed {
		return false, ErrReferenceProtection
	}
	key, ok := protector.keys[protected.KeyID]
	if !ok {
		return false, ErrReferenceProtection
	}
	plaintext := reference.Bytes()
	defer clear(plaintext)
	if len(plaintext) == 0 || len(plaintext) > maxReferenceSize {
		return false, ErrReferenceProtection
	}
	aad := referenceAAD(context)
	expectedHMAC := referenceHMAC(key.HMACKey, aad, plaintext)
	defer clear(expectedHMAC)
	return hmac.Equal(expectedHMAC, protected.AccessorHMAC), nil
}

func (protector *AESGCMProtector) Unprotect(context ReferenceContext, protected ProtectedReference) (*SensitiveReference, error) {
	if protector == nil || !validReferenceContext(context) || !ValidIdentifier(protected.KeyID, 128) || len(protected.AccessorHMAC) != sha256.Size {
		return nil, ErrReferenceProtection
	}
	protector.mu.RLock()
	defer protector.mu.RUnlock()
	if protector.destroyed {
		return nil, ErrReferenceProtection
	}
	key, ok := protector.keys[protected.KeyID]
	if !ok {
		return nil, ErrReferenceProtection
	}
	aead, err := newGCM(key.EncryptionKey)
	if err != nil || len(protected.Ciphertext) < aead.NonceSize()+aead.Overhead()+1 ||
		len(protected.Ciphertext) > aead.NonceSize()+aead.Overhead()+maxReferenceSize {
		return nil, ErrReferenceProtection
	}
	nonce := protected.Ciphertext[:aead.NonceSize()]
	ciphertext := protected.Ciphertext[aead.NonceSize():]
	aad := referenceAAD(context)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrReferenceProtection
	}
	defer clear(plaintext)
	expectedHMAC := referenceHMAC(key.HMACKey, aad, plaintext)
	if !hmac.Equal(expectedHMAC, protected.AccessorHMAC) {
		clear(expectedHMAC)
		return nil, ErrReferenceProtection
	}
	clear(expectedHMAC)
	reference, err := NewSensitiveReference(plaintext)
	if err != nil {
		return nil, ErrReferenceProtection
	}
	return reference, nil
}

// Destroy clears every cloned key and permanently fails this protector closed.
// It is safe to race with Protect, Unprotect, Close, or another Destroy call.
func (protector *AESGCMProtector) Destroy() {
	if protector == nil {
		return
	}
	protector.mu.Lock()
	defer protector.mu.Unlock()
	if protector.destroyed {
		return
	}
	for keyID, key := range protector.keys {
		clear(key.EncryptionKey)
		clear(key.HMACKey)
		delete(protector.keys, keyID)
	}
	protector.activeKeyID = ""
	protector.destroyed = true
}

func (protector *AESGCMProtector) Close() error {
	protector.Destroy()
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create reference cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func validReferenceContext(context ReferenceContext) bool {
	return ValidRevocationID(context.RevocationID) && ValidIdentifier(context.ActionID, 256) &&
		context.ActionEpoch > 0 && ValidOpaqueText(context.Issuer, 256) &&
		ValidIdentifier(context.IssuerRevision, 256)
}

func referenceAAD(context ReferenceContext) []byte {
	buffer := bytes.NewBuffer(make([]byte, 0,
		len(context.RevocationID)+len(context.ActionID)+len(context.Issuer)+len(context.IssuerRevision)+36))
	writeAADField(buffer, "credential-reference.v2")
	writeAADField(buffer, context.RevocationID)
	writeAADField(buffer, context.ActionID)
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], uint64(context.ActionEpoch))
	buffer.Write(epoch[:])
	writeAADField(buffer, context.Issuer)
	writeAADField(buffer, context.IssuerRevision)
	return buffer.Bytes()
}

func writeAADField(buffer *bytes.Buffer, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buffer.Write(length[:])
	buffer.WriteString(value)
}

func referenceHMAC(key, aad, plaintext []byte) []byte {
	digest := hmac.New(sha256.New, key)
	digest.Write(aad)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(plaintext)))
	digest.Write(length[:])
	digest.Write(plaintext)
	return digest.Sum(nil)
}
