package discoverycheckpoint

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"sync"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

var (
	ErrInvalidInput           = errors.New("checkpoint codec input invalid")
	ErrUnavailable            = errors.New("checkpoint codec unavailable")
	ErrAuthentication         = errors.New("checkpoint authentication failed")
	ErrSensitiveSerialization = errors.New("checkpoint codec sensitive value is not serializable")
)

const (
	CheckpointEnvelopeVersion byte = 1

	checkpointNonceSize        = 12
	checkpointEnvelopeOverhead = 1 + checkpointNonceSize + 16
	checkpointEnvelopeMaximum  = 65_536

	checkpointAADRedaction     = "[REDACTED_CHECKPOINT_AAD]"
	checkpointKeyringRedaction = "[REDACTED_CHECKPOINT_KEYRING]"
	checkpointCodecRedaction   = "[REDACTED_CHECKPOINT_CODEC]"
)

var (
	canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	providerKindPattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	lowercaseDigest      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type CheckpointAAD struct {
	TenantID, WorkspaceID, SourceID, ProviderKind   string
	CheckpointRevision                              int64
	CanonicalRevisionDigest, SourceDefinitionDigest string
	CheckpointKeyID                                 string
	CheckpointVersion                               int64
}

func (CheckpointAAD) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*CheckpointAAD) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (CheckpointAAD) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*CheckpointAAD) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (CheckpointAAD) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*CheckpointAAD) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (CheckpointAAD) String() string                 { return checkpointAADRedaction }
func (CheckpointAAD) GoString() string               { return checkpointAADRedaction }
func (CheckpointAAD) LogValue() slog.Value           { return slog.StringValue(checkpointAADRedaction) }
func (CheckpointAAD) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, checkpointAADRedaction)
}

type SealedCheckpoint struct {
	Envelope          []byte
	CheckpointKeyID   string
	CheckpointSHA256  string
	CheckpointVersion int64
}

func (value SealedCheckpoint) Clone() SealedCheckpoint {
	value.Envelope = bytes.Clone(value.Envelope)
	return value
}

type ReplayIdentity struct {
	CheckpointKeyID string
	DigestSHA256    string
}

type InMemoryKeyring struct {
	state *keyringState
}

func (InMemoryKeyring) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*InMemoryKeyring) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (InMemoryKeyring) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*InMemoryKeyring) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (InMemoryKeyring) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*InMemoryKeyring) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (InMemoryKeyring) String() string                 { return checkpointKeyringRedaction }
func (InMemoryKeyring) GoString() string               { return checkpointKeyringRedaction }
func (InMemoryKeyring) LogValue() slog.Value           { return slog.StringValue(checkpointKeyringRedaction) }
func (InMemoryKeyring) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, checkpointKeyringRedaction)
}

type keyringState struct {
	mu          sync.RWMutex
	activeKeyID string
	keys        map[string][]byte
	destroyed   bool
}

func NewInMemoryKeyring(activeKeyID string, retained map[string][32]byte) (*InMemoryKeyring, error) {
	if !validCheckpointKeyID(activeKeyID) || len(retained) == 0 {
		return nil, ErrInvalidInput
	}
	if _, ok := retained[activeKeyID]; !ok {
		return nil, ErrInvalidInput
	}
	for keyID := range retained {
		if !validCheckpointKeyID(keyID) {
			return nil, ErrInvalidInput
		}
	}
	owned := make(map[string][]byte, len(retained))
	for keyID, master := range retained {
		owned[keyID] = bytes.Clone(master[:])
	}
	return &InMemoryKeyring{state: &keyringState{
		activeKeyID: activeKeyID,
		keys:        owned,
	}}, nil
}

func (keys *InMemoryKeyring) ActiveKeyID() (string, error) {
	if keys == nil || keys.state == nil {
		return "", ErrUnavailable
	}
	keys.state.mu.RLock()
	defer keys.state.mu.RUnlock()
	if keys.state.destroyed || !validCheckpointKeyID(keys.state.activeKeyID) {
		return "", ErrUnavailable
	}
	if master, ok := keys.state.keys[keys.state.activeKeyID]; !ok || len(master) != 32 {
		return "", ErrUnavailable
	}
	return keys.state.activeKeyID, nil
}

func (keys *InMemoryKeyring) Destroy() {
	if keys == nil || keys.state == nil {
		return
	}
	keys.state.mu.Lock()
	defer keys.state.mu.Unlock()
	if keys.state.destroyed {
		return
	}
	for keyID, master := range keys.state.keys {
		clear(master)
		delete(keys.state.keys, keyID)
	}
	keys.state.activeKeyID = ""
	keys.state.destroyed = true
}

type CheckpointCodec struct {
	keys *keyringState
}

func (CheckpointCodec) MarshalJSON() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*CheckpointCodec) UnmarshalJSON([]byte) error    { return ErrSensitiveSerialization }
func (CheckpointCodec) MarshalText() ([]byte, error)   { return nil, ErrSensitiveSerialization }
func (*CheckpointCodec) UnmarshalText([]byte) error    { return ErrSensitiveSerialization }
func (CheckpointCodec) MarshalBinary() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*CheckpointCodec) UnmarshalBinary([]byte) error  { return ErrSensitiveSerialization }
func (CheckpointCodec) String() string                 { return checkpointCodecRedaction }
func (CheckpointCodec) GoString() string               { return checkpointCodecRedaction }
func (CheckpointCodec) LogValue() slog.Value           { return slog.StringValue(checkpointCodecRedaction) }
func (CheckpointCodec) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, checkpointCodecRedaction)
}

func NewCheckpointCodec(keys *InMemoryKeyring) (*CheckpointCodec, error) {
	if keys == nil || keys.state == nil {
		return nil, ErrInvalidInput
	}
	if _, err := keys.ActiveKeyID(); err != nil {
		return nil, err
	}
	return &CheckpointCodec{keys: keys.state}, nil
}

func (codec *CheckpointCodec) Seal(
	ctx context.Context,
	aad CheckpointAAD,
	checkpoint discoverysource.Checkpoint,
) (SealedCheckpoint, error) {
	if err := initialContextError(ctx); err != nil {
		return SealedCheckpoint{}, err
	}
	if codec == nil || codec.keys == nil || !aad.valid() {
		return SealedCheckpoint{}, ErrInvalidInput
	}
	profile := checkpoint.ProfileCode()
	if !profile.Valid() {
		return SealedCheckpoint{}, ErrInvalidInput
	}

	var sealed SealedCheckpoint
	err := discoverysource.WithCheckpointBytes(checkpoint, profile, func(plaintext []byte) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		codec.keys.mu.RLock()
		defer codec.keys.mu.RUnlock()
		if codec.keys.destroyed {
			return ErrUnavailable
		}
		if codec.keys.activeKeyID != aad.CheckpointKeyID {
			return ErrInvalidInput
		}
		master, ok := codec.keys.keys[codec.keys.activeKeyID]
		if !ok || len(master) != 32 {
			return ErrUnavailable
		}

		derived, err := deriveAEADKey(master, profile)
		if err != nil {
			return ErrUnavailable
		}
		defer clear(derived)
		gcm, err := newCheckpointGCM(derived)
		if err != nil {
			return ErrUnavailable
		}
		nonce, err := randomNonzeroNonce()
		if err != nil {
			return ErrUnavailable
		}
		defer clear(nonce)
		authenticatedData, err := aad.bytes()
		if err != nil {
			return ErrInvalidInput
		}
		defer clear(authenticatedData)

		envelope := make([]byte, 1+len(nonce), 1+len(nonce)+len(plaintext)+gcm.Overhead())
		envelope[0] = CheckpointEnvelopeVersion
		copy(envelope[1:], nonce)
		envelope = gcm.Seal(envelope, nonce, plaintext, authenticatedData)
		if err := contextError(ctx); err != nil {
			clear(envelope)
			return err
		}
		digest := sha256.Sum256(envelope)
		sealed = SealedCheckpoint{
			Envelope:          envelope,
			CheckpointKeyID:   aad.CheckpointKeyID,
			CheckpointSHA256:  hex.EncodeToString(digest[:]),
			CheckpointVersion: aad.CheckpointVersion,
		}
		return nil
	})
	if err != nil {
		return SealedCheckpoint{}, collapseSealError(err)
	}
	return sealed, nil
}

func (codec *CheckpointCodec) Open(
	ctx context.Context,
	aad CheckpointAAD,
	expectedProfile assetcatalog.ProfileCode,
	sealed SealedCheckpoint,
) (discoverysource.Checkpoint, error) {
	if err := initialContextError(ctx); err != nil {
		return discoverysource.Checkpoint{}, err
	}
	if codec == nil || codec.keys == nil {
		return discoverysource.Checkpoint{}, ErrInvalidInput
	}
	if !aad.valid() || !expectedProfile.Valid() || !sealed.authenticates(aad) {
		return discoverysource.Checkpoint{}, ErrAuthentication
	}

	codec.keys.mu.RLock()
	defer codec.keys.mu.RUnlock()
	if codec.keys.destroyed {
		return discoverysource.Checkpoint{}, ErrUnavailable
	}
	master, ok := codec.keys.keys[aad.CheckpointKeyID]
	if !ok || len(master) != 32 {
		return discoverysource.Checkpoint{}, ErrAuthentication
	}
	derived, err := deriveAEADKey(master, expectedProfile)
	if err != nil {
		return discoverysource.Checkpoint{}, ErrAuthentication
	}
	defer clear(derived)
	gcm, err := newCheckpointGCM(derived)
	if err != nil {
		return discoverysource.Checkpoint{}, ErrAuthentication
	}
	authenticatedData, err := aad.bytes()
	if err != nil {
		return discoverysource.Checkpoint{}, ErrAuthentication
	}
	defer clear(authenticatedData)
	plaintext, err := gcm.Open(nil, sealed.Envelope[1:13], sealed.Envelope[13:], authenticatedData)
	if err != nil {
		return discoverysource.Checkpoint{}, ErrAuthentication
	}
	defer clear(plaintext)
	if err := contextError(ctx); err != nil {
		return discoverysource.Checkpoint{}, err
	}
	checkpoint, err := discoverysource.NewCheckpoint(expectedProfile, plaintext)
	if err != nil {
		return discoverysource.Checkpoint{}, ErrAuthentication
	}
	if err := contextError(ctx); err != nil {
		checkpoint.Clear()
		return discoverysource.Checkpoint{}, err
	}
	return checkpoint, nil
}

func (codec *CheckpointCodec) ReplayIdentity(
	ctx context.Context,
	aad CheckpointAAD,
	checkpoint discoverysource.Checkpoint,
) (ReplayIdentity, error) {
	if err := initialContextError(ctx); err != nil {
		return ReplayIdentity{}, err
	}
	if codec == nil || codec.keys == nil || !aad.valid() {
		return ReplayIdentity{}, ErrInvalidInput
	}
	profile := checkpoint.ProfileCode()
	if !profile.Valid() {
		return ReplayIdentity{}, ErrInvalidInput
	}

	var identity ReplayIdentity
	err := discoverysource.WithCheckpointBytes(checkpoint, profile, func(checkpointBytes []byte) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		codec.keys.mu.RLock()
		defer codec.keys.mu.RUnlock()
		if codec.keys.destroyed {
			return ErrUnavailable
		}
		master, ok := codec.keys.keys[aad.CheckpointKeyID]
		if !ok || len(master) != 32 {
			return ErrAuthentication
		}
		replayKey, err := hkdf.Key(
			sha256.New,
			master,
			nil,
			"asset-source-checkpoint-replay-key.v1",
			sha256.Size,
		)
		if err != nil {
			return ErrUnavailable
		}
		defer clear(replayKey)
		message, err := aad.replayMessage(checkpointBytes)
		if err != nil {
			return ErrInvalidInput
		}
		defer clear(message)
		mac := hmac.New(sha256.New, replayKey)
		_, _ = mac.Write(message)
		digest := mac.Sum(nil)
		defer clear(digest)
		if err := contextError(ctx); err != nil {
			return err
		}
		identity = ReplayIdentity{
			CheckpointKeyID: aad.CheckpointKeyID,
			DigestSHA256:    hex.EncodeToString(digest),
		}
		return nil
	})
	if err != nil {
		return ReplayIdentity{}, collapseReplayError(err)
	}
	return identity, nil
}

func (aad CheckpointAAD) valid() bool {
	return canonicalUUIDPattern.MatchString(aad.TenantID) &&
		canonicalUUIDPattern.MatchString(aad.WorkspaceID) &&
		canonicalUUIDPattern.MatchString(aad.SourceID) &&
		providerKindPattern.MatchString(aad.ProviderKind) &&
		aad.CheckpointRevision > 0 &&
		lowercaseDigest.MatchString(aad.CanonicalRevisionDigest) &&
		lowercaseDigest.MatchString(aad.SourceDefinitionDigest) &&
		validCheckpointKeyID(aad.CheckpointKeyID) &&
		aad.CheckpointVersion > 0
}

func (aad CheckpointAAD) bytes() ([]byte, error) {
	return aad.framed("asset-source-checkpoint.v1")
}

func (aad CheckpointAAD) replayMessage(checkpoint []byte) ([]byte, error) {
	if len(checkpoint) > discoverysource.MaxCheckpointCanonicalBytes {
		return nil, ErrInvalidInput
	}
	return aad.framed("asset-source-checkpoint-replay.v1", checkpoint)
}

func (aad CheckpointAAD) framed(domain string, trailing ...[]byte) ([]byte, error) {
	if !aad.valid() {
		return nil, ErrInvalidInput
	}
	canonicalDigest, err := hex.DecodeString(aad.CanonicalRevisionDigest)
	if err != nil || len(canonicalDigest) != sha256.Size {
		clear(canonicalDigest)
		return nil, ErrInvalidInput
	}
	defer clear(canonicalDigest)
	definitionDigest, err := hex.DecodeString(aad.SourceDefinitionDigest)
	if err != nil || len(definitionDigest) != sha256.Size {
		clear(definitionDigest)
		return nil, ErrInvalidInput
	}
	defer clear(definitionDigest)
	fields := [][]byte{
		[]byte(domain),
		[]byte(aad.TenantID),
		[]byte(aad.WorkspaceID),
		[]byte(aad.SourceID),
		[]byte(aad.ProviderKind),
		[]byte(strconv.FormatInt(aad.CheckpointRevision, 10)),
		canonicalDigest,
		definitionDigest,
		[]byte(aad.CheckpointKeyID),
		[]byte(strconv.FormatInt(aad.CheckpointVersion, 10)),
	}
	fields = append(fields, trailing...)
	return framedTupleV1(fields...), nil
}

func (sealed SealedCheckpoint) authenticates(aad CheckpointAAD) bool {
	if sealed.CheckpointKeyID != aad.CheckpointKeyID ||
		sealed.CheckpointVersion != aad.CheckpointVersion ||
		!lowercaseDigest.MatchString(sealed.CheckpointSHA256) ||
		len(sealed.Envelope) < checkpointEnvelopeOverhead ||
		len(sealed.Envelope) > checkpointEnvelopeMaximum ||
		sealed.Envelope[0] != CheckpointEnvelopeVersion ||
		allZero(sealed.Envelope[1:13]) {
		return false
	}
	expected, err := hex.DecodeString(sealed.CheckpointSHA256)
	if err != nil || len(expected) != sha256.Size {
		clear(expected)
		return false
	}
	defer clear(expected)
	actual := sha256.Sum256(sealed.Envelope)
	return subtle.ConstantTimeCompare(actual[:], expected) == 1
}

func deriveAEADKey(master []byte, profile assetcatalog.ProfileCode) ([]byte, error) {
	if len(master) != 32 || !profile.Valid() {
		return nil, ErrInvalidInput
	}
	info := framedTupleV1(
		[]byte("asset-source-checkpoint-aead-key.v1"),
		[]byte(profile),
	)
	defer clear(info)
	return hkdf.Key(sha256.New, master, nil, string(info), 32)
}

func newCheckpointGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, checkpointNonceSize)
}

func randomNonzeroNonce() ([]byte, error) {
	nonce := make([]byte, checkpointNonceSize)
	for {
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			clear(nonce)
			return nil, err
		}
		if !allZero(nonce) {
			return nonce, nil
		}
	}
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func validCheckpointKeyID(value string) bool {
	if len(value) == 0 || len(value) > 256 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if asciiAlphaNumeric(character) || bytes.IndexByte([]byte("_.:/@+-"), character) >= 0 {
			continue
		}
		return false
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func framedTupleV1(fields ...[]byte) []byte {
	var total int
	for _, field := range fields {
		total += 1 + 4 + len(field)
	}
	framed := make([]byte, 0, total)
	for _, field := range fields {
		framed = append(framed, 1)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed
}

func initialContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	return contextError(ctx)
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func collapseSealError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrInvalidInput
	}
}

func collapseReplayError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	case errors.Is(err, ErrAuthentication):
		return ErrAuthentication
	default:
		return ErrInvalidInput
	}
}
