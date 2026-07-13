package workerbootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	secretFrameMagicText             = "AIOPS-SECRET-V1!"
	secretFrameChecksumDomain        = "aiops/control-worker-secret-frame/v1\x00"
	secretFrameVersion         uint8 = 1
	secretFrameHeaderBytes           = len(secretFrameMagicText) + 8
	maximumSecretPayloadBytes        = 2048
	maximumSecretPasswordBytes       = 1024
	maximumSecretFrameBytes          = secretFrameHeaderBytes + maximumSecretPayloadBytes + sha256.Size
)

type secretFrameRole uint8

const (
	secretFrameInvalid secretFrameRole = iota
	secretFramePostgres
	secretFrameTemporalStarter
	secretFrameTemporalControl
)

// decodedSecretFrame privately owns the secret buffers created by a single
// verified frame. It deliberately has no raw-material getter. Its package
// consumers must either transfer ownership into the later sealed runtime
// capability or close it.
type decodedSecretFrame struct {
	role            secretFrameRole
	password        []byte
	privateKeyPKCS8 []byte
	privateKeySPKI  []byte
}

func encodePostgresSecretFrame(password, privateKeyPKCS8 []byte) ([]byte, error) {
	if !validSecretPassword(password) {
		return nil, ErrBootstrapRejected
	}
	spki, err := validateP256PKCS8PrivateKey(privateKeyPKCS8)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	clear(spki)
	if len(password) > int(^uint16(0)) || len(privateKeyPKCS8) > int(^uint16(0)) {
		return nil, ErrBootstrapRejected
	}
	payloadLength := 4 + len(password) + len(privateKeyPKCS8)
	if payloadLength > maximumSecretPayloadBytes {
		return nil, ErrBootstrapRejected
	}
	payload := make([]byte, payloadLength)
	defer clear(payload)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(password)))
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(privateKeyPKCS8)))
	copy(payload[4:], password)
	copy(payload[4+len(password):], privateKeyPKCS8)
	return encodeSecretFrame(secretFramePostgres, payload)
}

func encodeTemporalSecretFrame(role secretFrameRole, privateKeyPKCS8 []byte) ([]byte, error) {
	if role != secretFrameTemporalStarter && role != secretFrameTemporalControl {
		return nil, ErrBootstrapRejected
	}
	spki, err := validateP256PKCS8PrivateKey(privateKeyPKCS8)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	clear(spki)
	return encodeSecretFrame(role, privateKeyPKCS8)
}

func encodeSecretFrame(role secretFrameRole, payload []byte) ([]byte, error) {
	if !role.valid() || len(payload) == 0 || len(payload) > maximumSecretPayloadBytes {
		return nil, ErrBootstrapRejected
	}
	header := make([]byte, secretFrameHeaderBytes)
	copy(header, secretFrameMagicText)
	header[len(secretFrameMagicText)] = secretFrameVersion
	header[len(secretFrameMagicText)+1] = byte(role)
	// The two reserved bytes remain zero.
	binary.BigEndian.PutUint32(header[len(secretFrameMagicText)+4:], uint32(len(payload)))
	checksum := secretFrameChecksum(header, payload)
	framed := make([]byte, 0, len(header)+len(payload)+sha256.Size)
	framed = append(framed, header...)
	framed = append(framed, payload...)
	framed = append(framed, checksum[:]...)
	return framed, nil
}

func decodeSecretFrame(expectedRole secretFrameRole, framed []byte) (*decodedSecretFrame, error) {
	minimumLength := secretFrameHeaderBytes + 1 + sha256.Size
	if !expectedRole.valid() || len(framed) < minimumLength || len(framed) > maximumSecretFrameBytes {
		return nil, ErrBootstrapRejected
	}
	header := framed[:secretFrameHeaderBytes]
	if !bytes.Equal(header[:len(secretFrameMagicText)], []byte(secretFrameMagicText)) ||
		header[len(secretFrameMagicText)] != secretFrameVersion {
		return nil, ErrBootstrapRejected
	}
	wireRole := secretFrameRole(header[len(secretFrameMagicText)+1])
	if !wireRole.valid() || wireRole != expectedRole ||
		header[len(secretFrameMagicText)+2] != 0 || header[len(secretFrameMagicText)+3] != 0 {
		return nil, ErrBootstrapRejected
	}
	payloadLength := binary.BigEndian.Uint32(header[len(secretFrameMagicText)+4:])
	if payloadLength == 0 || payloadLength > maximumSecretPayloadBytes {
		return nil, ErrBootstrapRejected
	}
	payloadEnd := secretFrameHeaderBytes + int(payloadLength)
	if payloadEnd+sha256.Size != len(framed) {
		return nil, ErrBootstrapRejected
	}
	payload := framed[secretFrameHeaderBytes:payloadEnd]
	expectedChecksum := secretFrameChecksum(header, payload)
	if subtle.ConstantTimeCompare(expectedChecksum[:], framed[payloadEnd:]) != 1 {
		return nil, ErrBootstrapRejected
	}
	if wireRole == secretFramePostgres {
		return decodePostgresSecretPayload(payload)
	}
	return newDecodedSecretFrame(wireRole, nil, payload)
}

func decodePostgresSecretPayload(payload []byte) (*decodedSecretFrame, error) {
	if len(payload) < 4 {
		return nil, ErrBootstrapRejected
	}
	passwordLength := int(binary.BigEndian.Uint16(payload[:2]))
	privateKeyLength := int(binary.BigEndian.Uint16(payload[2:4]))
	if passwordLength == 0 || passwordLength > maximumSecretPasswordBytes || privateKeyLength == 0 ||
		4+passwordLength+privateKeyLength != len(payload) {
		return nil, ErrBootstrapRejected
	}
	password := payload[4 : 4+passwordLength]
	if !validSecretPassword(password) {
		return nil, ErrBootstrapRejected
	}
	return newDecodedSecretFrame(secretFramePostgres, password, payload[4+passwordLength:])
}

func newDecodedSecretFrame(
	role secretFrameRole,
	password []byte,
	privateKeyPKCS8 []byte,
) (*decodedSecretFrame, error) {
	spki, err := validateP256PKCS8PrivateKey(privateKeyPKCS8)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	created := &decodedSecretFrame{
		role:            role,
		password:        bytes.Clone(password),
		privateKeyPKCS8: bytes.Clone(privateKeyPKCS8),
		privateKeySPKI:  spki,
	}
	if created.password == nil && len(password) != 0 || created.privateKeyPKCS8 == nil {
		created.close()
		return nil, ErrBootstrapRejected
	}
	return created, nil
}

func (frame *decodedSecretFrame) close() {
	frame.clear()
}

func (frame *decodedSecretFrame) clear() {
	if frame == nil {
		return
	}
	clear(frame.password)
	clear(frame.privateKeyPKCS8)
	clear(frame.privateKeySPKI)
	frame.password = nil
	frame.privateKeyPKCS8 = nil
	frame.privateKeySPKI = nil
	frame.role = secretFrameInvalid
}

func (decodedSecretFrame) String() string   { return "ControlWorkerSecretFrame{[REDACTED]}" }
func (decodedSecretFrame) GoString() string { return "ControlWorkerSecretFrame{[REDACTED]}" }
func (decodedSecretFrame) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "ControlWorkerSecretFrame{[REDACTED]}")
}
func (decodedSecretFrame) MarshalJSON() ([]byte, error) { return nil, ErrBootstrapRejected }
func (*decodedSecretFrame) UnmarshalJSON([]byte) error  { return ErrBootstrapRejected }

func (inheritedSecretBundle) String() string   { return "ControlWorkerSecretBundle{[REDACTED]}" }
func (inheritedSecretBundle) GoString() string { return "ControlWorkerSecretBundle{[REDACTED]}" }
func (inheritedSecretBundle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "ControlWorkerSecretBundle{[REDACTED]}")
}
func (inheritedSecretBundle) MarshalJSON() ([]byte, error) { return nil, ErrBootstrapRejected }
func (*inheritedSecretBundle) UnmarshalJSON([]byte) error  { return ErrBootstrapRejected }

var _ fmt.Stringer = decodedSecretFrame{}
var _ fmt.GoStringer = decodedSecretFrame{}
var _ fmt.Formatter = decodedSecretFrame{}
var _ json.Marshaler = decodedSecretFrame{}
var _ json.Unmarshaler = (*decodedSecretFrame)(nil)
var _ fmt.Stringer = inheritedSecretBundle{}
var _ fmt.GoStringer = inheritedSecretBundle{}
var _ fmt.Formatter = inheritedSecretBundle{}
var _ json.Marshaler = inheritedSecretBundle{}
var _ json.Unmarshaler = (*inheritedSecretBundle)(nil)

func (role secretFrameRole) valid() bool {
	return role >= secretFramePostgres && role <= secretFrameTemporalControl
}

func validSecretPassword(password []byte) bool {
	if len(password) == 0 || len(password) > maximumSecretPasswordBytes {
		return false
	}
	for _, item := range password {
		if item == 0 || item == '\r' || item == '\n' {
			return false
		}
	}
	return true
}

func validateP256PKCS8PrivateKey(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > maximumSecretPayloadBytes {
		return nil, ErrBootstrapRejected
	}
	parsed, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || privateKey == nil {
		return nil, ErrBootstrapRejected
	}
	defer clearECDSAPrivateKey(privateKey)
	curve := elliptic.P256()
	if privateKey.Curve != curve || privateKey.PublicKey.Curve != curve ||
		privateKey.D == nil || privateKey.D.Sign() <= 0 || privateKey.D.Cmp(curve.Params().N) >= 0 ||
		privateKey.PublicKey.X == nil || privateKey.PublicKey.Y == nil ||
		!curve.IsOnCurve(privateKey.PublicKey.X, privateKey.PublicKey.Y) {
		return nil, ErrBootstrapRejected
	}
	scalar := privateKey.D.Bytes()
	defer clear(scalar)
	expectedX, expectedY := curve.ScalarBaseMult(scalar)
	if expectedX == nil || expectedY == nil ||
		expectedX.Cmp(privateKey.PublicKey.X) != 0 || expectedY.Cmp(privateKey.PublicKey.Y) != 0 {
		return nil, ErrBootstrapRejected
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, ErrBootstrapRejected
	}
	defer clear(canonical)
	if subtle.ConstantTimeCompare(canonical, encoded) != 1 {
		return nil, ErrBootstrapRejected
	}
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil || len(spki) == 0 {
		clear(spki)
		return nil, ErrBootstrapRejected
	}
	return spki, nil
}

func clearECDSAPrivateKey(privateKey *ecdsa.PrivateKey) {
	if privateKey == nil {
		return
	}
	if privateKey.D != nil {
		privateKey.D.SetInt64(0)
	}
	privateKey.PublicKey.X = nil
	privateKey.PublicKey.Y = nil
	privateKey.PublicKey.Curve = nil
	privateKey.Curve = nil
}

func secretFrameChecksum(header, payload []byte) [sha256.Size]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(secretFrameChecksumDomain))
	_, _ = hasher.Write(header)
	_, _ = hasher.Write(payload)
	var checksum [sha256.Size]byte
	hasher.Sum(checksum[:0])
	return checksum
}
