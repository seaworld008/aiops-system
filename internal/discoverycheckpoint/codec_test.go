package discoverycheckpoint

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	testProfileCode assetcatalog.ProfileCode = "CMDB_CATALOG_V1"
	testAADHex                               = "010000001a61737365742d736f757263652d636865636b706f696e742e7631010000002431313131313131312d313131312d343131312d383131312d313131313131313131313131010000002432323232323232322d323232322d343232322d383232322d323232323232323232323232010000002433333333333333332d333333332d343333332d383333332d333333333333333333333333010000000f434d44425f434154414c4f475f563101000000013701000000201111111111111111111111111111111111111111111111111111111111111111010000002022222222222222222222222222222222222222222222222222222222222222220100000011636865636b706f696e742d6b65792d7631010000000139"
	testAADSHA256                            = "f830a65258f8bb037b9582ec782bcac0b0c109a79c5b344161b920d23e709984"
)

func TestSealOpenUsesExactAADAndEnvelope(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x40)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{
		"checkpoint-key-v1": master,
	})
	if err != nil {
		t.Fatalf("NewInMemoryKeyring() error = %v", err)
	}
	t.Cleanup(keys.Destroy)
	if active, err := keys.ActiveKeyID(); err != nil || active != "checkpoint-key-v1" {
		t.Fatalf("ActiveKeyID() = %q, %v", active, err)
	}

	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatalf("NewCheckpointCodec() error = %v", err)
	}
	raw := []byte("opaque-checkpoint\x00canonical")
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, raw)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}
	t.Cleanup(checkpoint.Clear)

	aad := testCheckpointAAD()
	sealed, err := codec.Seal(context.Background(), aad, checkpoint)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if len(sealed.Envelope) != 29+len(raw) {
		t.Fatalf("envelope length = %d, want %d", len(sealed.Envelope), 29+len(raw))
	}
	if sealed.Envelope[0] != CheckpointEnvelopeVersion {
		t.Fatalf("envelope version = %d", sealed.Envelope[0])
	}
	if bytes.Equal(sealed.Envelope[1:13], make([]byte, 12)) {
		t.Fatal("Seal() emitted an all-zero nonce")
	}
	if sealed.CheckpointKeyID != aad.CheckpointKeyID || sealed.CheckpointVersion != aad.CheckpointVersion {
		t.Fatal("sealed coordinates do not match the AAD")
	}
	envelopeDigest := sha256.Sum256(sealed.Envelope)
	if sealed.CheckpointSHA256 != hex.EncodeToString(envelopeDigest[:]) {
		t.Fatal("sealed envelope digest is not canonical")
	}

	exactAAD := independentAADBytes(t, aad)
	if got := hex.EncodeToString(exactAAD); got != testAADHex {
		t.Fatal("AAD bytes differ from the frozen fixture")
	}
	aadDigest := sha256.Sum256(exactAAD)
	if got := hex.EncodeToString(aadDigest[:]); got != testAADSHA256 {
		t.Fatal("AAD digest differs from the frozen fixture")
	}

	derived := independentAEADKey(t, master, testProfileCode)
	decrypted := independentOpen(t, derived, sealed.Envelope, exactAAD)
	clear(derived)
	defer clear(decrypted)
	if !bytes.Equal(decrypted, raw) {
		t.Fatal("GCM plaintext does not equal the raw checkpoint")
	}

	opened, err := codec.Open(context.Background(), aad, testProfileCode, sealed)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(opened.Clear)
	if !opened.Equal(checkpoint) {
		t.Fatal("Open() did not rebuild the profile-bound checkpoint")
	}

	clone := sealed.Clone()
	clone.Envelope[0] ^= 0xff
	if sealed.Envelope[0] != CheckpointEnvelopeVersion {
		t.Fatal("SealedCheckpoint.Clone() shared the envelope backing array")
	}
}

func TestReplayIdentityUsesIndependentExactHMAC(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x60)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{
		"checkpoint-key-v1": master,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("stable replay checkpoint")
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)
	aad := testCheckpointAAD()

	identity, err := codec.ReplayIdentity(context.Background(), aad, checkpoint)
	if err != nil {
		t.Fatalf("ReplayIdentity() error = %v", err)
	}
	replayKey, err := hkdf.Key(
		sha256.New,
		master[:],
		nil,
		"asset-source-checkpoint-replay-key.v1",
		sha256.Size,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(replayKey)
	message := independentReplayMessage(t, aad, raw)
	defer clear(message)
	expectedMAC := hmac.New(sha256.New, replayKey)
	_, _ = expectedMAC.Write(message)
	expectedDigest := expectedMAC.Sum(nil)
	defer clear(expectedDigest)
	if identity.CheckpointKeyID != aad.CheckpointKeyID || identity.DigestSHA256 != hex.EncodeToString(expectedDigest) {
		t.Fatal("ReplayIdentity() differs from the independent HMAC fixture")
	}

	aeadKey := independentAEADKey(t, master, testProfileCode)
	defer clear(aeadKey)
	if bytes.Equal(master[:], replayKey) || bytes.Equal(master[:], aeadKey) || bytes.Equal(replayKey, aeadKey) {
		t.Fatal("master, AEAD, and replay keys were reused")
	}
	for name, forbiddenKey := range map[string][]byte{"master": master[:], "aead": aeadKey} {
		forbiddenMAC := hmac.New(sha256.New, forbiddenKey)
		_, _ = forbiddenMAC.Write(message)
		if hmac.Equal(forbiddenMAC.Sum(nil), expectedDigest) {
			t.Fatalf("ReplayIdentity used %s key directly", name)
		}
	}

	otherProfileCheckpoint, err := discoverysource.NewCheckpoint("OTHER_PROFILE_V1", raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherProfileCheckpoint.Clear)
	withoutHiddenProfile, err := codec.ReplayIdentity(context.Background(), aad, otherProfileCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	if withoutHiddenProfile != identity {
		t.Fatal("ReplayIdentity appended a hidden checkpoint profile frame")
	}

	changedCheckpoint, err := discoverysource.NewCheckpoint(testProfileCode, []byte("different checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(changedCheckpoint.Clear)
	changedRaw, err := codec.ReplayIdentity(context.Background(), aad, changedCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	if changedRaw.DigestSHA256 == identity.DigestSHA256 {
		t.Fatal("ReplayIdentity did not bind canonical checkpoint bytes")
	}
}

func TestSensitiveValuesRejectSerializationAndRedactLogs(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x20)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{
		"checkpoint-key-v1": master,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	aad := testCheckpointAAD()

	assertSensitiveCodecValue(
		t,
		aad,
		&CheckpointAAD{},
		[]string{aad.TenantID, aad.SourceID, aad.CheckpointKeyID, aad.CanonicalRevisionDigest},
	)
	assertSensitiveCodecValue(
		t,
		*keys,
		&InMemoryKeyring{},
		[]string{"checkpoint-key-v1", hex.EncodeToString(master[:])},
	)
	assertSensitiveCodecValue(
		t,
		*codec,
		&CheckpointCodec{},
		[]string{"checkpoint-key-v1", hex.EncodeToString(master[:])},
	)
}

func TestOpenCollapsesAADAndEnvelopeTamper(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x30)
	secondMaster := testMasterKey(0x70)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{
		"checkpoint-key-v1": master,
		"checkpoint-key-v2": secondMaster,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, []byte("tamper-sensitive-checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)
	aad := testCheckpointAAD()
	sealed, err := codec.Seal(context.Background(), aad, checkpoint)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range aadBindingMutations() {
		t.Run(test.name, func(t *testing.T) {
			changed := aad
			test.mutate(&changed)
			opened, err := codec.Open(context.Background(), changed, testProfileCode, sealed)
			assertAuthenticationFailure(t, opened, err, aad, sealed)
		})
	}

	opened, err := codec.Open(context.Background(), aad, "OTHER_PROFILE_V1", sealed)
	assertAuthenticationFailure(t, opened, err, aad, sealed)

	sealedMutations := []struct {
		name   string
		mutate func(*SealedCheckpoint)
	}{
		{"key id", func(value *SealedCheckpoint) { value.CheckpointKeyID = "checkpoint-key-v2" }},
		{"version", func(value *SealedCheckpoint) { value.CheckpointVersion++ }},
		{"hash", func(value *SealedCheckpoint) { value.CheckpointSHA256 = strings.Repeat("0", sha256.Size) }},
		{"uppercase hash", func(value *SealedCheckpoint) { value.CheckpointSHA256 = strings.ToUpper(value.CheckpointSHA256) }},
		{"empty", func(value *SealedCheckpoint) { value.Envelope = nil; rehashSealed(value) }},
		{"short", func(value *SealedCheckpoint) { value.Envelope = bytes.Clone(value.Envelope[:28]); rehashSealed(value) }},
		{"envelope version", func(value *SealedCheckpoint) { value.Envelope[0] = 2; rehashSealed(value) }},
		{"zero nonce", func(value *SealedCheckpoint) { clear(value.Envelope[1:13]); rehashSealed(value) }},
		{"ciphertext", func(value *SealedCheckpoint) { value.Envelope[13] ^= 1; rehashSealed(value) }},
		{"tag", func(value *SealedCheckpoint) { value.Envelope[len(value.Envelope)-1] ^= 1; rehashSealed(value) }},
		{"oversize", func(value *SealedCheckpoint) {
			value.Envelope = make([]byte, 65_537)
			value.Envelope[0] = CheckpointEnvelopeVersion
			value.Envelope[1] = 1
			rehashSealed(value)
		}},
	}
	for _, test := range sealedMutations {
		t.Run(test.name, func(t *testing.T) {
			changed := sealed.Clone()
			test.mutate(&changed)
			opened, err := codec.Open(context.Background(), aad, testProfileCode, changed)
			assertAuthenticationFailure(t, opened, err, aad, changed)
		})
	}
}

func TestSealValidatesEveryAADFieldBeforeCrypto(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x10)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{"checkpoint-key-v1": master})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)

	mutations := []struct {
		name   string
		mutate func(*CheckpointAAD)
	}{
		{"tenant empty", func(value *CheckpointAAD) { value.TenantID = "" }},
		{"workspace noncanonical", func(value *CheckpointAAD) { value.WorkspaceID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }},
		{"source wrong variant", func(value *CheckpointAAD) { value.SourceID = "33333333-3333-4333-7333-333333333333" }},
		{"provider empty", func(value *CheckpointAAD) { value.ProviderKind = "" }},
		{"provider lowercase", func(value *CheckpointAAD) { value.ProviderKind = "cmdb_catalog_v1" }},
		{"revision zero", func(value *CheckpointAAD) { value.CheckpointRevision = 0 }},
		{"canonical digest empty", func(value *CheckpointAAD) { value.CanonicalRevisionDigest = "" }},
		{"canonical digest uppercase", func(value *CheckpointAAD) { value.CanonicalRevisionDigest = strings.Repeat("AA", sha256.Size) }},
		{"definition digest short", func(value *CheckpointAAD) { value.SourceDefinitionDigest = "00" }},
		{"key id empty", func(value *CheckpointAAD) { value.CheckpointKeyID = "" }},
		{"key id whitespace", func(value *CheckpointAAD) { value.CheckpointKeyID = "key id" }},
		{"version zero", func(value *CheckpointAAD) { value.CheckpointVersion = 0 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			aad := testCheckpointAAD()
			test.mutate(&aad)
			sealed, err := codec.Seal(context.Background(), aad, checkpoint)
			if err != ErrInvalidInput || !zeroSealedCheckpoint(sealed) {
				t.Fatal("Seal(invalid AAD) did not return zero output and ErrInvalidInput")
			}
		})
	}
	wrongActiveAAD := testCheckpointAAD()
	wrongActiveAAD.CheckpointKeyID = "checkpoint-key-v2"
	sealed, err := codec.Seal(context.Background(), wrongActiveAAD, checkpoint)
	if err != ErrInvalidInput || !zeroSealedCheckpoint(sealed) {
		t.Fatal("Seal(wrong active key) did not return zero output and ErrInvalidInput")
	}
}

func TestEnvelopeBoundariesAndRandomNonce(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x50)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{"checkpoint-key-v1": master})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	aad := testCheckpointAAD()

	empty, err := discoverysource.NewCheckpoint(testProfileCode, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(empty.Clear)
	emptySealed, err := codec.Seal(context.Background(), aad, empty)
	if err != nil || len(emptySealed.Envelope) != 29 {
		t.Fatalf("Seal(empty) length/error = %d, %v", len(emptySealed.Envelope), err)
	}
	emptyOpened, err := codec.Open(context.Background(), aad, testProfileCode, emptySealed)
	if err != nil || !emptyOpened.IsEmpty() {
		t.Fatal("Open(empty) did not return an empty checkpoint")
	}
	t.Cleanup(emptyOpened.Clear)

	maximumRaw := bytes.Repeat([]byte{0xa5}, discoverysource.MaxCheckpointCanonicalBytes)
	maximum, err := discoverysource.NewCheckpoint(testProfileCode, maximumRaw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(maximum.Clear)
	maximumSealed, err := codec.Seal(context.Background(), aad, maximum)
	if err != nil || len(maximumSealed.Envelope) != 65_536 {
		t.Fatalf("Seal(maximum) length/error = %d, %v", len(maximumSealed.Envelope), err)
	}
	maximumOpened, err := codec.Open(context.Background(), aad, testProfileCode, maximumSealed)
	if err != nil || !maximumOpened.Equal(maximum) {
		t.Fatalf("Open(maximum) error/equal = %v, %t", err, maximumOpened.Equal(maximum))
	}
	t.Cleanup(maximumOpened.Clear)

	first, err := codec.Seal(context.Background(), aad, empty)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Seal(context.Background(), aad, empty)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Envelope[1:13], second.Envelope[1:13]) || bytes.Equal(first.Envelope, second.Envelope) {
		t.Fatal("two Seal calls reused nonce or envelope")
	}
	for _, candidate := range []SealedCheckpoint{first, second} {
		opened, err := codec.Open(context.Background(), aad, testProfileCode, candidate)
		if err != nil || !opened.Equal(empty) {
			t.Fatalf("Open(randomized envelope) error/equal = %v, %t", err, opened.Equal(empty))
		}
		opened.Clear()
	}
}

func TestKeyRotationRetainsOldKeysAndCopiesConstructorInput(t *testing.T) {
	t.Parallel()

	oldMaster := testMasterKey(0x11)
	newMaster := testMasterKey(0x91)
	oldInput := map[string][32]byte{"checkpoint-key-old": oldMaster}
	oldKeys, err := NewInMemoryKeyring("checkpoint-key-old", oldInput)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(oldKeys.Destroy)
	oldInput["checkpoint-key-old"] = newMaster
	oldCodec, err := NewCheckpointCodec(oldKeys)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, []byte("rotation-checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)
	oldAAD := testCheckpointAAD()
	oldAAD.CheckpointKeyID = "checkpoint-key-old"
	oldSealed, err := oldCodec.Seal(context.Background(), oldAAD, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	derivedOld := independentAEADKey(t, oldMaster, testProfileCode)
	decrypted := independentOpen(t, derivedOld, oldSealed.Envelope, independentAADBytes(t, oldAAD))
	clear(derivedOld)
	clear(decrypted)
	oldIdentity, err := oldCodec.ReplayIdentity(context.Background(), oldAAD, checkpoint)
	if err != nil {
		t.Fatal(err)
	}

	rotatedKeys, err := NewInMemoryKeyring("checkpoint-key-new", map[string][32]byte{
		"checkpoint-key-old": oldMaster,
		"checkpoint-key-new": newMaster,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotatedKeys.Destroy)
	rotatedCodec, err := NewCheckpointCodec(rotatedKeys)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := rotatedCodec.Open(context.Background(), oldAAD, testProfileCode, oldSealed)
	if err != nil || !opened.Equal(checkpoint) {
		t.Fatalf("rotated Open(old) error/equal = %v, %t", err, opened.Equal(checkpoint))
	}
	opened.Clear()
	replayedOld, err := rotatedCodec.ReplayIdentity(context.Background(), oldAAD, checkpoint)
	if err != nil || replayedOld != oldIdentity {
		t.Fatal("rotated ReplayIdentity(old) did not preserve identity")
	}
	if sealed, err := rotatedCodec.Seal(context.Background(), oldAAD, checkpoint); err != ErrInvalidInput || !zeroSealedCheckpoint(sealed) {
		t.Fatal("rotated Seal(old active) did not fail closed")
	}
	newAAD := oldAAD
	newAAD.CheckpointKeyID = "checkpoint-key-new"
	newSealed, err := rotatedCodec.Seal(context.Background(), newAAD, checkpoint)
	if err != nil || newSealed.CheckpointKeyID != "checkpoint-key-new" {
		t.Fatal("rotated Seal(new) did not use the active key")
	}

	newOnlyKeys, err := NewInMemoryKeyring("checkpoint-key-new", map[string][32]byte{"checkpoint-key-new": newMaster})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(newOnlyKeys.Destroy)
	newOnlyCodec, err := NewCheckpointCodec(newOnlyKeys)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = newOnlyCodec.Open(context.Background(), oldAAD, testProfileCode, oldSealed)
	assertAuthenticationFailure(t, opened, err, oldAAD, oldSealed)
	if identity, err := newOnlyCodec.ReplayIdentity(context.Background(), oldAAD, checkpoint); err != ErrAuthentication || identity != (ReplayIdentity{}) {
		t.Fatal("ReplayIdentity(missing retained key) did not fail authentication with zero output")
	}
}

func TestReplayIdentityBindsEveryAADField(t *testing.T) {
	t.Parallel()

	firstMaster := testMasterKey(0x21)
	secondMaster := testMasterKey(0x61)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{
		"checkpoint-key-v1": firstMaster,
		"checkpoint-key-v2": secondMaster,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, []byte("replay-aad-binding"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)
	aad := testCheckpointAAD()
	base, err := codec.ReplayIdentity(context.Background(), aad, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range aadBindingMutations() {
		t.Run(test.name, func(t *testing.T) {
			changed := aad
			test.mutate(&changed)
			identity, err := codec.ReplayIdentity(context.Background(), changed, checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			if identity.DigestSHA256 == base.DigestSHA256 {
				t.Fatalf("ReplayIdentity did not bind %s", test.name)
			}
		})
	}
}

func TestDestroyZeroizesSharedMastersAndInvalidatesCodecs(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x31)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{"checkpoint-key-v1": master})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, []byte("destroy-checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)
	aad := testCheckpointAAD()
	sealed, err := codec.Seal(context.Background(), aad, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	retainedStorage := keys.state.keys["checkpoint-key-v1"]
	keysCopy := *keys
	codecCopy := *codec

	keysCopy.Destroy()
	keys.Destroy()
	if !allZero(retainedStorage) {
		t.Fatal("Destroy() did not zeroize retained master storage")
	}
	if keys.state.activeKeyID != "" || len(keys.state.keys) != 0 || !keys.state.destroyed {
		t.Fatalf(
			"destroyed keyring state: active cleared=%t, retained=%d, destroyed=%t",
			keys.state.activeKeyID == "",
			len(keys.state.keys),
			keys.state.destroyed,
		)
	}
	for name, candidate := range map[string]*InMemoryKeyring{"original": keys, "copy": &keysCopy} {
		if active, err := candidate.ActiveKeyID(); active != "" || err != ErrUnavailable {
			t.Fatalf("%s ActiveKeyID() = %q, %v", name, active, err)
		}
		if _, err := NewCheckpointCodec(candidate); err != ErrUnavailable {
			t.Fatalf("NewCheckpointCodec(%s destroyed) error = %v", name, err)
		}
	}
	for name, candidate := range map[string]*CheckpointCodec{"original": codec, "copy": &codecCopy} {
		if output, err := candidate.Seal(context.Background(), aad, checkpoint); err != ErrUnavailable || !zeroSealedCheckpoint(output) {
			t.Fatalf("%s Seal(destroyed) did not fail unavailable with zero output", name)
		}
		if output, err := candidate.Open(context.Background(), aad, testProfileCode, sealed); err != ErrUnavailable || output.ProfileCode() != "" {
			t.Fatalf("%s Open(destroyed) did not fail unavailable with zero output", name)
		}
		if output, err := candidate.ReplayIdentity(context.Background(), aad, checkpoint); err != ErrUnavailable || output != (ReplayIdentity{}) {
			t.Fatalf("%s ReplayIdentity(destroyed) did not fail unavailable with zero output", name)
		}
	}
}

func TestDestroyIsRaceSafeWithCodecOperations(t *testing.T) {
	master := testMasterKey(0x41)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{"checkpoint-key-v1": master})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, []byte("race-checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)
	aad := testCheckpointAAD()
	sealed, err := codec.Seal(context.Background(), aad, checkpoint)
	if err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, _ = keys.ActiveKeyID()
			_, _ = codec.Seal(context.Background(), aad, checkpoint)
			opened, _ := codec.Open(context.Background(), aad, testProfileCode, sealed)
			opened.Clear()
			_, _ = codec.ReplayIdentity(context.Background(), aad, checkpoint)
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		keys.Destroy()
	}()
	group.Wait()
	if active, err := keys.ActiveKeyID(); active != "" || err != ErrUnavailable {
		t.Fatalf("ActiveKeyID() after race = %q, %v", active, err)
	}
}

func TestContextCancellationReturnsOnlyZeroOutputs(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x51)
	keys, err := NewInMemoryKeyring("checkpoint-key-v1", map[string][32]byte{"checkpoint-key-v1": master})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Destroy)
	codec, err := NewCheckpointCodec(keys)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := discoverysource.NewCheckpoint(testProfileCode, []byte("cancel-checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checkpoint.Clear)
	aad := testCheckpointAAD()
	sealed, err := codec.Seal(context.Background(), aad, checkpoint)
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for name, ctx := range map[string]context.Context{"cancelled": cancelled, "deadline": expired} {
		t.Run(name, func(t *testing.T) {
			if output, err := codec.Seal(ctx, aad, checkpoint); err != ctx.Err() || !zeroSealedCheckpoint(output) {
				t.Fatal("Seal(cancelled) did not return the context error and zero output")
			}
			if output, err := codec.Open(ctx, aad, testProfileCode, sealed); err != ctx.Err() || output.ProfileCode() != "" {
				t.Fatal("Open(cancelled) did not return the context error and zero output")
			}
			if output, err := codec.ReplayIdentity(ctx, aad, checkpoint); err != ctx.Err() || output != (ReplayIdentity{}) {
				t.Fatal("ReplayIdentity(cancelled) did not return the context error and zero output")
			}
		})
	}
	if output, err := codec.Seal(nil, aad, checkpoint); err != ErrInvalidInput || !zeroSealedCheckpoint(output) {
		t.Fatal("Seal(nil) did not return ErrInvalidInput and zero output")
	}
	if output, err := codec.Open(nil, aad, testProfileCode, sealed); err != ErrInvalidInput || output.ProfileCode() != "" {
		t.Fatal("Open(nil) did not return ErrInvalidInput and zero output")
	}
	if output, err := codec.ReplayIdentity(nil, aad, checkpoint); err != ErrInvalidInput || output != (ReplayIdentity{}) {
		t.Fatal("ReplayIdentity(nil) did not return ErrInvalidInput and zero output")
	}
}

func TestKeyringConstructorValidatesOpaqueIDsAndKeepsCallerOwnership(t *testing.T) {
	t.Parallel()

	master := testMasterKey(0x71)
	maximumID := "A" + strings.Repeat("x", 255)
	keys, err := NewInMemoryKeyring(maximumID, map[string][32]byte{maximumID: master})
	if err != nil {
		t.Fatalf("NewInMemoryKeyring(maximum ID) error = %v", err)
	}
	keys.Destroy()
	zeroMaster := [32]byte{}
	keys, err = NewInMemoryKeyring("zero-master-v1", map[string][32]byte{"zero-master-v1": zeroMaster})
	if err != nil {
		t.Fatalf("NewInMemoryKeyring(all-zero exact-size master) error = %v", err)
	}
	keys.Destroy()

	invalid := []struct {
		name     string
		activeID string
		retained map[string][32]byte
	}{
		{"empty active", "", map[string][32]byte{"checkpoint-key-v1": master}},
		{"empty retained", "checkpoint-key-v1", nil},
		{"missing active", "checkpoint-key-v2", map[string][32]byte{"checkpoint-key-v1": master}},
		{"invalid active", "checkpoint key", map[string][32]byte{"checkpoint key": master}},
		{"invalid retained", "checkpoint-key-v1", map[string][32]byte{"checkpoint-key-v1": master, "bad key": master}},
		{"oversize", "A" + strings.Repeat("x", 256), map[string][32]byte{"A" + strings.Repeat("x", 256): master}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			keys, err := NewInMemoryKeyring(test.activeID, test.retained)
			if keys != nil || err != ErrInvalidInput {
				t.Fatal("NewInMemoryKeyring(invalid input) did not return nil and ErrInvalidInput")
			}
		})
	}
	if codec, err := NewCheckpointCodec(nil); codec != nil || err != ErrInvalidInput {
		t.Fatal("NewCheckpointCodec(nil) did not return nil and ErrInvalidInput")
	}
	if active, err := (*InMemoryKeyring)(nil).ActiveKeyID(); active != "" || err != ErrUnavailable {
		t.Fatalf("nil ActiveKeyID() = %q, %v", active, err)
	}
	(*InMemoryKeyring)(nil).Destroy()
}

func assertAuthenticationFailure(
	t *testing.T,
	checkpoint discoverysource.Checkpoint,
	err error,
	aad CheckpointAAD,
	sealed SealedCheckpoint,
) {
	t.Helper()
	if err != ErrAuthentication || err.Error() != "checkpoint authentication failed" {
		t.Fatal("Open() did not return the stable authentication error")
	}
	if checkpoint.ProfileCode() != "" || checkpoint.IsEmpty() {
		t.Fatal("Open() returned nonzero checkpoint output")
	}
	for _, forbidden := range []string{
		aad.TenantID,
		aad.SourceID,
		aad.CheckpointKeyID,
		aad.CanonicalRevisionDigest,
		sealed.CheckpointSHA256,
		hex.EncodeToString(sealed.Envelope),
	} {
		if forbidden != "" && strings.Contains(err.Error(), forbidden) {
			t.Fatal("authentication error leaked bound input")
		}
	}
}

func rehashSealed(value *SealedCheckpoint) {
	digest := sha256.Sum256(value.Envelope)
	value.CheckpointSHA256 = hex.EncodeToString(digest[:])
}

func zeroSealedCheckpoint(value SealedCheckpoint) bool {
	return value.Envelope == nil && value.CheckpointKeyID == "" && value.CheckpointSHA256 == "" && value.CheckpointVersion == 0
}

func aadBindingMutations() []struct {
	name   string
	mutate func(*CheckpointAAD)
} {
	return []struct {
		name   string
		mutate func(*CheckpointAAD)
	}{
		{"tenant", func(value *CheckpointAAD) { value.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }},
		{"workspace", func(value *CheckpointAAD) { value.WorkspaceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }},
		{"source", func(value *CheckpointAAD) { value.SourceID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" }},
		{"provider", func(value *CheckpointAAD) { value.ProviderKind = "VSPHERE_VCENTER_V1" }},
		{"revision", func(value *CheckpointAAD) { value.CheckpointRevision++ }},
		{"canonical digest", func(value *CheckpointAAD) { value.CanonicalRevisionDigest = strings.Repeat("33", sha256.Size) }},
		{"definition digest", func(value *CheckpointAAD) { value.SourceDefinitionDigest = strings.Repeat("44", sha256.Size) }},
		{"key id", func(value *CheckpointAAD) { value.CheckpointKeyID = "checkpoint-key-v2" }},
		{"version", func(value *CheckpointAAD) { value.CheckpointVersion++ }},
	}
}

type sensitiveCodecValue interface {
	json.Marshaler
	encoding.TextMarshaler
	encoding.BinaryMarshaler
	fmt.Stringer
	fmt.GoStringer
	slog.LogValuer
	fmt.Formatter
}

type sensitiveCodecTarget interface {
	json.Unmarshaler
	encoding.TextUnmarshaler
	encoding.BinaryUnmarshaler
}

func assertSensitiveCodecValue(t *testing.T, value sensitiveCodecValue, target sensitiveCodecTarget, canaries []string) {
	t.Helper()
	if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(%T) error = %v", value, err)
	}
	if err := json.Unmarshal([]byte(`{"forbidden":"value"}`), target); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("json.Unmarshal(%T) error = %v", target, err)
	}
	if _, err := value.MarshalText(); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("MarshalText(%T) error = %v", value, err)
	}
	if err := target.UnmarshalText([]byte("forbidden")); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("UnmarshalText(%T) error = %v", target, err)
	}
	if _, err := value.MarshalBinary(); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("MarshalBinary(%T) error = %v", value, err)
	}
	if err := target.UnmarshalBinary([]byte("forbidden")); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatalf("UnmarshalBinary(%T) error = %v", target, err)
	}

	rendered := []string{
		value.String(),
		value.GoString(),
		value.LogValue().String(),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
		fmt.Sprintf("%s", value),
		fmt.Sprintf("%q", value),
		fmt.Sprintf("%x", value),
	}
	for _, output := range rendered {
		if !strings.Contains(output, "REDACTED") {
			t.Fatalf("%T rendered without a redaction marker", value)
		}
		for _, canary := range canaries {
			if canary != "" && strings.Contains(output, canary) {
				t.Fatalf("%T leaked sensitive material through rendering", value)
			}
		}
	}
}

func testCheckpointAAD() CheckpointAAD {
	return CheckpointAAD{
		TenantID:                "11111111-1111-4111-8111-111111111111",
		WorkspaceID:             "22222222-2222-4222-8222-222222222222",
		SourceID:                "33333333-3333-4333-8333-333333333333",
		ProviderKind:            "CMDB_CATALOG_V1",
		CheckpointRevision:      7,
		CanonicalRevisionDigest: strings.Repeat("11", sha256.Size),
		SourceDefinitionDigest:  strings.Repeat("22", sha256.Size),
		CheckpointKeyID:         "checkpoint-key-v1",
		CheckpointVersion:       9,
	}
}

func testMasterKey(seed byte) [32]byte {
	var key [32]byte
	for index := range key {
		key[index] = seed + byte(index)
	}
	return key
}

func independentAADBytes(t *testing.T, aad CheckpointAAD) []byte {
	t.Helper()
	return independentFramedTuple(independentAADFields(t, "asset-source-checkpoint.v1", aad)...)
}

func independentReplayMessage(t *testing.T, aad CheckpointAAD, checkpoint []byte) []byte {
	t.Helper()
	fields := independentAADFields(t, "asset-source-checkpoint-replay.v1", aad)
	fields = append(fields, checkpoint)
	return independentFramedTuple(fields...)
}

func independentAADFields(t *testing.T, domain string, aad CheckpointAAD) [][]byte {
	t.Helper()
	canonicalDigest, err := hex.DecodeString(aad.CanonicalRevisionDigest)
	if err != nil {
		t.Fatal(err)
	}
	definitionDigest, err := hex.DecodeString(aad.SourceDefinitionDigest)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{
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
}

func independentAEADKey(t *testing.T, master [32]byte, profile assetcatalog.ProfileCode) []byte {
	t.Helper()
	info := independentFramedTuple(
		[]byte("asset-source-checkpoint-aead-key.v1"),
		[]byte(profile),
	)
	derived, err := hkdf.Key(sha256.New, master[:], nil, string(info), 32)
	clear(info)
	if err != nil {
		t.Fatal(err)
	}
	return derived
}

func independentOpen(t *testing.T, key, envelope, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := gcm.Open(nil, envelope[1:13], envelope[13:], aad)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func independentFramedTuple(fields ...[]byte) []byte {
	var framed bytes.Buffer
	for _, field := range fields {
		_ = framed.WriteByte(1)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = framed.Write(length[:])
		_, _ = framed.Write(field)
	}
	return framed.Bytes()
}
