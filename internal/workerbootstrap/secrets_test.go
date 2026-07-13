package workerbootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSecretFrameRoundTripAndOwnedClear(t *testing.T) {
	privateKeyDER := testPKCS8PrivateKey(t, elliptic.P256())
	tests := []struct {
		name     string
		role     secretFrameRole
		password []byte
		encode   func([]byte) ([]byte, error)
	}{
		{
			name:     "postgres",
			role:     secretFramePostgres,
			password: []byte("pg-canary-password"),
			encode: func(key []byte) ([]byte, error) {
				return encodePostgresSecretFrame([]byte("pg-canary-password"), key)
			},
		},
		{
			name: "temporal starter",
			role: secretFrameTemporalStarter,
			encode: func(key []byte) ([]byte, error) {
				return encodeTemporalSecretFrame(secretFrameTemporalStarter, key)
			},
		},
		{
			name: "temporal control",
			role: secretFrameTemporalControl,
			encode: func(key []byte) ([]byte, error) {
				return encodeTemporalSecretFrame(secretFrameTemporalControl, key)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			framed, err := test.encode(privateKeyDER)
			if err != nil {
				t.Fatalf("encode secret frame: %v", err)
			}
			if len(framed) > maximumSecretFrameBytes {
				t.Fatalf("frame length = %d, maximum = %d", len(framed), maximumSecretFrameBytes)
			}
			decoded, err := decodeSecretFrame(test.role, framed)
			if err != nil {
				t.Fatalf("decodeSecretFrame(): %v", err)
			}
			if decoded == nil || decoded.role != test.role ||
				!bytes.Equal(decoded.password, test.password) ||
				!bytes.Equal(decoded.privateKeyPKCS8, privateKeyDER) ||
				len(decoded.privateKeySPKI) == 0 {
				t.Fatalf("decoded secret frame does not match encoded role material")
			}
			for _, rendered := range []string{
				fmt.Sprint(decoded), fmt.Sprintf("%+v", decoded), fmt.Sprintf("%#v", decoded),
			} {
				if !strings.Contains(rendered, "REDACTED") || strings.Contains(rendered, "pg-canary-password") {
					t.Fatalf("secret frame formatting leaked material: %q", rendered)
				}
			}
			if encoded, err := json.Marshal(decoded); err == nil || len(encoded) != 0 {
				t.Fatalf("json.Marshal(secret frame) = %q, %v; want rejection", encoded, err)
			}

			passwordAlias := decoded.password
			keyAlias := decoded.privateKeyPKCS8
			spkiAlias := decoded.privateKeySPKI
			clear(framed)
			if !bytes.Equal(decoded.password, test.password) ||
				!bytes.Equal(decoded.privateKeyPKCS8, privateKeyDER) {
				t.Fatal("decoded secret aliases its input frame")
			}
			decoded.clear()
			decoded.close()
			if decoded.role != secretFrameInvalid || decoded.password != nil ||
				decoded.privateKeyPKCS8 != nil || decoded.privateKeySPKI != nil {
				t.Fatalf("closed decoded secret retains live fields: %#v", decoded)
			}
			for name, owned := range map[string][]byte{
				"password":    passwordAlias,
				"private key": keyAlias,
				"spki":        spkiAlias,
			} {
				if !allZeroSecretTestBytes(owned) {
					t.Errorf("close did not clear owned %s buffer", name)
				}
			}
		})
	}
}

func TestSecretFrameEncodingRejectsInvalidMaterial(t *testing.T) {
	p256 := testPKCS8PrivateKey(t, elliptic.P256())
	if maximumSecretFrameBytes > 4096 {
		t.Fatalf("maximum secret frame = %d, exceeds Linux PIPE_BUF floor", maximumSecretFrameBytes)
	}
	maximumPassword := bytes.Repeat([]byte{'p'}, maximumSecretPasswordBytes)
	if framed, err := encodePostgresSecretFrame(maximumPassword, p256); err != nil || len(framed) > maximumSecretFrameBytes {
		t.Fatalf("maximum allowed password frame = %d bytes, %v", len(framed), err)
	}
	p384 := testPKCS8PrivateKey(t, elliptic.P384())
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal RSA key: %v", err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	legacyEC, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("marshal legacy EC key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	invalidPasswords := [][]byte{
		nil,
		{},
		bytes.Repeat([]byte{'p'}, maximumSecretPasswordBytes+1),
		[]byte("has\x00nul"),
		[]byte("has\rcarriage-return"),
		[]byte("has\nnewline"),
	}
	for _, password := range invalidPasswords {
		if framed, encodeErr := encodePostgresSecretFrame(password, p256); framed != nil ||
			!errors.Is(encodeErr, ErrBootstrapRejected) {
			t.Errorf("encodePostgresSecretFrame(%q) = %x, %v; want rejection", password, framed, encodeErr)
		}
	}

	invalidKeys := [][]byte{nil, {}, p384, rsaPKCS8, legacyEC, publicDER, bytes.Repeat([]byte{0xff}, 64)}
	for _, key := range invalidKeys {
		if framed, encodeErr := encodeTemporalSecretFrame(secretFrameTemporalStarter, key); framed != nil ||
			!errors.Is(encodeErr, ErrBootstrapRejected) {
			t.Errorf("encodeTemporalSecretFrame(invalid key length %d) = %x, %v; want rejection", len(key), framed, encodeErr)
		}
	}
	for _, role := range []secretFrameRole{secretFrameInvalid, 4, 255, secretFramePostgres} {
		if framed, encodeErr := encodeTemporalSecretFrame(role, p256); framed != nil ||
			!errors.Is(encodeErr, ErrBootstrapRejected) {
			t.Errorf("encodeTemporalSecretFrame(role %d) = %x, %v; want rejection", role, framed, encodeErr)
		}
	}
}

func TestSecretFrameDecodingRejectsWireCorruption(t *testing.T) {
	privateKeyDER := testPKCS8PrivateKey(t, elliptic.P256())
	valid, err := encodePostgresSecretFrame([]byte("pg-password"), privateKeyDER)
	if err != nil {
		t.Fatalf("encode valid PostgreSQL frame: %v", err)
	}
	temporal, err := encodeTemporalSecretFrame(secretFrameTemporalStarter, privateKeyDER)
	if err != nil {
		t.Fatalf("encode valid Temporal frame: %v", err)
	}

	mutateAndChecksum := func(mutate func([]byte)) []byte {
		mutated := bytes.Clone(valid)
		mutate(mutated)
		rewriteSecretTestChecksum(mutated)
		return mutated
	}
	tests := []struct {
		name   string
		role   secretFrameRole
		framed []byte
	}{
		{name: "empty", role: secretFramePostgres, framed: nil},
		{name: "oversized total frame", role: secretFramePostgres, framed: make([]byte, maximumSecretFrameBytes+1)},
		{name: "wrong magic", role: secretFramePostgres, framed: mutateAndChecksum(func(frame []byte) { frame[0] ^= 0xff })},
		{name: "wrong version", role: secretFramePostgres, framed: mutateAndChecksum(func(frame []byte) { frame[len(secretFrameMagicText)]++ })},
		{name: "unknown wire role", role: secretFramePostgres, framed: mutateAndChecksum(func(frame []byte) { frame[len(secretFrameMagicText)+1] = 99 })},
		{name: "reserved nonzero", role: secretFramePostgres, framed: mutateAndChecksum(func(frame []byte) { frame[len(secretFrameMagicText)+2] = 1 })},
		{name: "expected role mismatch", role: secretFrameTemporalStarter, framed: bytes.Clone(valid)},
		{name: "valid other role mismatch", role: secretFramePostgres, framed: bytes.Clone(temporal)},
		{name: "zero payload length", role: secretFramePostgres, framed: mutateAndChecksum(func(frame []byte) {
			binary.BigEndian.PutUint32(frame[len(secretFrameMagicText)+4:secretFrameHeaderBytes], 0)
		})},
		{name: "declared payload too large", role: secretFramePostgres, framed: mutateAndChecksum(func(frame []byte) {
			binary.BigEndian.PutUint32(frame[len(secretFrameMagicText)+4:secretFrameHeaderBytes], maximumSecretPayloadBytes+1)
		})},
		{name: "declared payload mismatch", role: secretFramePostgres, framed: mutateAndChecksum(func(frame []byte) {
			binary.BigEndian.PutUint32(frame[len(secretFrameMagicText)+4:secretFrameHeaderBytes], 1)
		})},
		{name: "trailing byte", role: secretFramePostgres, framed: append(bytes.Clone(valid), 0)},
		{name: "second frame", role: secretFramePostgres, framed: append(bytes.Clone(valid), valid...)},
		{name: "checksum", role: secretFramePostgres, framed: func() []byte {
			frame := bytes.Clone(valid)
			frame[len(frame)-1] ^= 0xff
			return frame
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, decodeErr := decodeSecretFrame(test.role, test.framed)
			if decoded != nil || !errors.Is(decodeErr, ErrBootstrapRejected) {
				t.Fatalf("decodeSecretFrame() = %#v, %v; want rejection", decoded, decodeErr)
			}
		})
	}
	for length := 1; length < len(valid); length++ {
		if decoded, decodeErr := decodeSecretFrame(secretFramePostgres, valid[:length]); decoded != nil ||
			!errors.Is(decodeErr, ErrBootstrapRejected) {
			t.Fatalf("decodeSecretFrame(truncated to %d) = %#v, %v; want rejection", length, decoded, decodeErr)
		}
	}
}

func TestSecretFrameDecodingRejectsMalformedRolePayload(t *testing.T) {
	privateKeyDER := testPKCS8PrivateKey(t, elliptic.P256())
	invalidPostgresPayloads := [][]byte{
		nil,
		{0, 0, 0, 0},
		{0, 1, 0, 0, 'p'},
		{0, 1, 0, 1, 'p'},
		append([]byte{0, 1, 0, byte(len(privateKeyDER)), '\n'}, privateKeyDER...),
		append([]byte{0, 2, 0, byte(len(privateKeyDER)), 'p'}, privateKeyDER...),
	}
	for index, payload := range invalidPostgresPayloads {
		framed := buildUncheckedSecretTestFrame(secretFramePostgres, payload)
		if decoded, err := decodeSecretFrame(secretFramePostgres, framed); decoded != nil ||
			!errors.Is(err, ErrBootstrapRejected) {
			t.Errorf("invalid PostgreSQL payload %d decoded as %#v, %v", index, decoded, err)
		}
	}

	for _, role := range []secretFrameRole{secretFrameTemporalStarter, secretFrameTemporalControl} {
		for index, payload := range [][]byte{nil, {1, 2, 3}, privateKeyDER[:len(privateKeyDER)-1]} {
			framed := buildUncheckedSecretTestFrame(role, payload)
			if decoded, err := decodeSecretFrame(role, framed); decoded != nil ||
				!errors.Is(err, ErrBootstrapRejected) {
				t.Errorf("invalid Temporal payload role %d case %d decoded as %#v, %v", role, index, decoded, err)
			}
		}
	}
}

func testPKCS8PrivateKey(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	return encoded
}

func buildUncheckedSecretTestFrame(role secretFrameRole, payload []byte) []byte {
	header := make([]byte, secretFrameHeaderBytes)
	copy(header, secretFrameMagicText)
	header[len(secretFrameMagicText)] = secretFrameVersion
	header[len(secretFrameMagicText)+1] = byte(role)
	binary.BigEndian.PutUint32(header[len(secretFrameMagicText)+4:], uint32(len(payload)))
	checksum := secretFrameChecksum(header, payload)
	framed := make([]byte, 0, len(header)+len(payload)+sha256.Size)
	framed = append(framed, header...)
	framed = append(framed, payload...)
	framed = append(framed, checksum[:]...)
	return framed
}

func rewriteSecretTestChecksum(framed []byte) {
	if len(framed) < secretFrameHeaderBytes+sha256.Size {
		return
	}
	payloadEnd := len(framed) - sha256.Size
	checksum := secretFrameChecksum(framed[:secretFrameHeaderBytes], framed[secretFrameHeaderBytes:payloadEnd])
	copy(framed[payloadEnd:], checksum[:])
}

func allZeroSecretTestBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
