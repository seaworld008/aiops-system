package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const SignatureHeader = "X-AIOPS-Signature"

var (
	ErrInvalidSignature  = errors.New("invalid webhook signature")
	ErrSecretUnavailable = errors.New("webhook secret unavailable")
)

type SecretResolver func(integrationID, provider string) ([]byte, error)

type HMACVerifier struct {
	resolveSecret SecretResolver
}

func NewHMACVerifier(resolveSecret SecretResolver) *HMACVerifier {
	return &HMACVerifier{resolveSecret: resolveSecret}
}

func (verifier *HMACVerifier) Verify(integrationID, provider string, headers http.Header, body []byte) error {
	if verifier == nil || verifier.resolveSecret == nil {
		return ErrSecretUnavailable
	}
	secret, err := verifier.resolveSecret(integrationID, provider)
	if err != nil {
		return fmt.Errorf("resolve webhook secret: %w", err)
	}
	if len(secret) == 0 {
		return ErrSecretUnavailable
	}

	provided := headers.Get(SignatureHeader)
	algorithm, encoded, ok := strings.Cut(provided, "=")
	if !ok || algorithm != "sha256" {
		return ErrInvalidSignature
	}
	providedMAC, err := hex.DecodeString(encoded)
	if err != nil {
		return ErrInvalidSignature
	}

	expected := hmac.New(sha256.New, secret)
	_, _ = expected.Write(body)
	if !hmac.Equal(providedMAC, expected.Sum(nil)) {
		return ErrInvalidSignature
	}
	return nil
}

func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
