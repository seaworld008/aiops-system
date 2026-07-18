package proxmox

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	providerKind = "PROXMOX_VE_V1"
	profileCode  = assetcatalog.ProfileCode("PROXMOX_VE_V1")

	runtimeMaterialRedaction = "[REDACTED_PROXMOX_RUNTIME]"
	maxTokenBytes            = 8 << 10
)

var (
	errProfileContract   = errors.New("proxmox profile contract violation")
	canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}@[A-Za-z0-9][A-Za-z0-9_.-]{0,63}![A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	clusterIdentityCode  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$`)
	hostNamePattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

type EndpointHandle struct {
	endpoint *url.URL
}

func NewEndpointHandle(value string) (EndpointHandle, error) {
	parsed, err := url.Parse(value)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Path != "/api2/json" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" ||
		!validHostName(parsed.Hostname()) {
		return EndpointHandle{}, profileError("ENDPOINT_HANDLE_REJECTED")
	}
	clone := *parsed
	return EndpointHandle{endpoint: &clone}, nil
}

func (EndpointHandle) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*EndpointHandle) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (EndpointHandle) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*EndpointHandle) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (EndpointHandle) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*EndpointHandle) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (EndpointHandle) String() string       { return runtimeMaterialRedaction }
func (EndpointHandle) GoString() string     { return runtimeMaterialRedaction }
func (EndpointHandle) LogValue() slog.Value { return slog.StringValue(runtimeMaterialRedaction) }
func (EndpointHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeMaterialRedaction)
}

type endpointSnapshot struct {
	endpoint *url.URL
}

func (handle EndpointHandle) snapshot() endpointSnapshot {
	if handle.endpoint == nil {
		return endpointSnapshot{}
	}
	clone := *handle.endpoint
	return endpointSnapshot{endpoint: &clone}
}

func (snapshot endpointSnapshot) valid() bool {
	if snapshot.endpoint == nil {
		return false
	}
	handle, err := NewEndpointHandle(snapshot.endpoint.String())
	return err == nil && handle.endpoint.String() == snapshot.endpoint.String()
}

func (snapshot *endpointSnapshot) Clear() {
	if snapshot == nil || snapshot.endpoint == nil {
		return
	}
	snapshot.endpoint.Scheme = ""
	snapshot.endpoint.Host = ""
	snapshot.endpoint.Path = ""
	snapshot.endpoint = nil
}

type TrustHandle struct {
	roots      *x509.CertPool
	serverName string
}

func NewTrustHandle(roots *x509.CertPool, serverName string) (TrustHandle, error) {
	if roots == nil ||
		len(roots.Subjects()) == 0 ||
		!validHostName(serverName) {
		return TrustHandle{}, profileError("TRUST_HANDLE_REJECTED")
	}
	return TrustHandle{
		roots:      roots.Clone(),
		serverName: serverName,
	}, nil
}

func (TrustHandle) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*TrustHandle) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (TrustHandle) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*TrustHandle) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (TrustHandle) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*TrustHandle) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (TrustHandle) String() string       { return runtimeMaterialRedaction }
func (TrustHandle) GoString() string     { return runtimeMaterialRedaction }
func (TrustHandle) LogValue() slog.Value { return slog.StringValue(runtimeMaterialRedaction) }
func (TrustHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeMaterialRedaction)
}

type trustSnapshot struct {
	roots      *x509.CertPool
	serverName string
}

func (handle TrustHandle) snapshot() trustSnapshot {
	if handle.roots == nil {
		return trustSnapshot{}
	}
	return trustSnapshot{
		roots:      handle.roots.Clone(),
		serverName: handle.serverName,
	}
}

func (snapshot trustSnapshot) valid() bool {
	handle, err := NewTrustHandle(snapshot.roots, snapshot.serverName)
	return err == nil && handle.serverName == snapshot.serverName
}

func (snapshot trustSnapshot) tlsConfig() *tls.Config {
	if !snapshot.valid() {
		return nil
	}
	return &tls.Config{
		RootCAs:                snapshot.roots.Clone(),
		ServerName:             snapshot.serverName,
		NextProtos:             []string{"http/1.1"},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
}

func (snapshot *trustSnapshot) Clear() {
	if snapshot == nil {
		return
	}
	snapshot.roots = nil
	snapshot.serverName = ""
}

type TokenHandle struct {
	tokenID string
	secret  []byte
}

func NewTokenHandle(tokenID string, secret []byte) (TokenHandle, error) {
	if !tokenIDPattern.MatchString(tokenID) ||
		!safeSecret(secret) {
		return TokenHandle{}, profileError("TOKEN_HANDLE_REJECTED")
	}
	return TokenHandle{
		tokenID: tokenID,
		secret:  append([]byte(nil), secret...),
	}, nil
}

func (handle *TokenHandle) Clear() {
	if handle == nil {
		return
	}
	clear(handle.secret)
	handle.secret = nil
	handle.tokenID = ""
}

func (TokenHandle) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*TokenHandle) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (TokenHandle) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*TokenHandle) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (TokenHandle) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*TokenHandle) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (TokenHandle) String() string       { return runtimeMaterialRedaction }
func (TokenHandle) GoString() string     { return runtimeMaterialRedaction }
func (TokenHandle) LogValue() slog.Value { return slog.StringValue(runtimeMaterialRedaction) }
func (TokenHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeMaterialRedaction)
}

type tokenSnapshot struct {
	tokenID string
	secret  []byte
}

func (handle TokenHandle) snapshot() tokenSnapshot {
	return tokenSnapshot{
		tokenID: handle.tokenID,
		secret:  append([]byte(nil), handle.secret...),
	}
}

func (snapshot tokenSnapshot) valid() bool {
	handle, err := NewTokenHandle(snapshot.tokenID, snapshot.secret)
	if err == nil {
		handle.Clear()
	}
	return err == nil
}

func (snapshot *tokenSnapshot) Clear() {
	if snapshot == nil {
		return
	}
	clear(snapshot.secret)
	snapshot.secret = nil
	snapshot.tokenID = ""
}

type AuthorityHandle struct {
	clusterIdentity string
	environmentID   string
}

func NewAuthorityHandle(clusterIdentity, environmentID string) (AuthorityHandle, error) {
	if !clusterIdentityCode.MatchString(clusterIdentity) ||
		!canonicalUUIDPattern.MatchString(environmentID) ||
		sensitiveRuntimeText(clusterIdentity) {
		return AuthorityHandle{}, profileError("AUTHORITY_HANDLE_REJECTED")
	}
	return AuthorityHandle{
		clusterIdentity: clusterIdentity,
		environmentID:   environmentID,
	}, nil
}

func (AuthorityHandle) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*AuthorityHandle) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (AuthorityHandle) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*AuthorityHandle) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (AuthorityHandle) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*AuthorityHandle) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (AuthorityHandle) String() string       { return runtimeMaterialRedaction }
func (AuthorityHandle) GoString() string     { return runtimeMaterialRedaction }
func (AuthorityHandle) LogValue() slog.Value { return slog.StringValue(runtimeMaterialRedaction) }
func (AuthorityHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeMaterialRedaction)
}

type authoritySnapshot struct {
	clusterIdentity string
	environmentID   string
}

func (handle AuthorityHandle) snapshot() authoritySnapshot {
	return authoritySnapshot{
		clusterIdentity: handle.clusterIdentity,
		environmentID:   handle.environmentID,
	}
}

func (snapshot authoritySnapshot) valid() bool {
	handle, err := NewAuthorityHandle(snapshot.clusterIdentity, snapshot.environmentID)
	return err == nil && handle.clusterIdentity == snapshot.clusterIdentity
}

func (snapshot *authoritySnapshot) Clear() {
	if snapshot == nil {
		return
	}
	snapshot.clusterIdentity = ""
	snapshot.environmentID = ""
}

type RuntimeMaterial struct {
	endpoint                   endpointSnapshot
	trust                      trustSnapshot
	token                      tokenSnapshot
	authority                  authoritySnapshot
	acceptedCheckpointSequence int64
	active                     bool
}

func NewRuntimeMaterial(
	endpoint EndpointHandle,
	trust TrustHandle,
	token TokenHandle,
	authority AuthorityHandle,
	acceptedCheckpointSequence int64,
) (RuntimeMaterial, error) {
	material := RuntimeMaterial{
		endpoint:                   endpoint.snapshot(),
		trust:                      trust.snapshot(),
		token:                      token.snapshot(),
		authority:                  authority.snapshot(),
		acceptedCheckpointSequence: acceptedCheckpointSequence,
		active:                     true,
	}
	if !material.valid() {
		material.Clear()
		return RuntimeMaterial{}, profileError("RUNTIME_MATERIAL_REJECTED")
	}
	return material, nil
}

func (material RuntimeMaterial) valid() bool {
	return material.active &&
		material.endpoint.valid() &&
		material.trust.valid() &&
		material.token.valid() &&
		material.authority.valid() &&
		material.acceptedCheckpointSequence > 0
}

type resolvedRuntime struct {
	endpoint                   endpointSnapshot
	trust                      trustSnapshot
	token                      tokenSnapshot
	authority                  authoritySnapshot
	acceptedCheckpointSequence int64
}

func (material RuntimeMaterial) snapshot() (resolvedRuntime, bool) {
	if !material.valid() {
		return resolvedRuntime{}, false
	}
	return resolvedRuntime{
		endpoint:                   material.endpointCopy(),
		trust:                      material.trustCopy(),
		token:                      material.tokenCopy(),
		authority:                  material.authority,
		acceptedCheckpointSequence: material.acceptedCheckpointSequence,
	}, true
}

func (material RuntimeMaterial) endpointCopy() endpointSnapshot {
	if material.endpoint.endpoint == nil {
		return endpointSnapshot{}
	}
	clone := *material.endpoint.endpoint
	return endpointSnapshot{endpoint: &clone}
}

func (material RuntimeMaterial) trustCopy() trustSnapshot {
	if material.trust.roots == nil {
		return trustSnapshot{}
	}
	return trustSnapshot{
		roots:      material.trust.roots.Clone(),
		serverName: material.trust.serverName,
	}
}

func (material RuntimeMaterial) tokenCopy() tokenSnapshot {
	return tokenSnapshot{
		tokenID: material.token.tokenID,
		secret:  append([]byte(nil), material.token.secret...),
	}
}

func (runtime resolvedRuntime) valid() bool {
	return runtime.endpoint.valid() &&
		runtime.trust.valid() &&
		runtime.token.valid() &&
		runtime.authority.valid() &&
		runtime.acceptedCheckpointSequence > 0
}

func (runtime *resolvedRuntime) Clear() {
	if runtime == nil {
		return
	}
	runtime.endpoint.Clear()
	runtime.trust.Clear()
	runtime.token.Clear()
	runtime.authority.Clear()
	runtime.acceptedCheckpointSequence = 0
}

func (material *RuntimeMaterial) Clear() {
	if material == nil {
		return
	}
	material.endpoint.Clear()
	material.trust.Clear()
	material.token.Clear()
	material.authority.Clear()
	material.acceptedCheckpointSequence = 0
	material.active = false
}

func (RuntimeMaterial) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*RuntimeMaterial) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (RuntimeMaterial) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*RuntimeMaterial) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (RuntimeMaterial) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*RuntimeMaterial) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (RuntimeMaterial) String() string       { return runtimeMaterialRedaction }
func (RuntimeMaterial) GoString() string     { return runtimeMaterialRedaction }
func (RuntimeMaterial) LogValue() slog.Value { return slog.StringValue(runtimeMaterialRedaction) }
func (RuntimeMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeMaterialRedaction)
}

func profileError(code string) error {
	return fmt.Errorf("%w: %s", errProfileContract, code)
}

func validHostName(value string) bool {
	return len(value) >= 1 &&
		len(value) <= 253 &&
		hostNamePattern.MatchString(value) &&
		!strings.Contains(value, "..") &&
		!sensitiveRuntimeText(value)
}

func safeSecret(value []byte) bool {
	if len(value) == 0 || len(value) > maxTokenBytes || !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func safeRuntimeText(value string, minimum, maximum int) bool {
	if len(value) < minimum ||
		len(value) > maximum ||
		!utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func sensitiveRuntimeText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"-----begin",
		"password",
		"private_key",
		"private-key",
		"secret=",
		"token=",
		"authorization",
		"pveapitoken",
		"bearer ",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
