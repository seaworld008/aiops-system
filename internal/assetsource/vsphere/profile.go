package vsphere

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/vmware/govmomi/vim25/types"
)

const (
	providerKind = "VSPHERE_VCENTER_V1"
	profileCode  = assetcatalog.ProfileCode("VSPHERE_VCENTER_V1")

	runtimeMaterialRedaction = "[REDACTED_VSPHERE_RUNTIME]"
	maxCredentialBytes       = 8 << 10
	maxAuthorityRoots        = 100
)

var (
	errProfileContract    = errors.New("vsphere profile contract violation")
	canonicalUUIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	instanceUUIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	managedObjectTypeCode = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	managedObjectValue    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)
)

type TLSCompatibility uint8

const (
	TLSCompatibilityStrict TLSCompatibility = iota + 1
	TLSCompatibilityVCenter12
)

func (compatibility TLSCompatibility) valid() bool {
	return compatibility == TLSCompatibilityStrict ||
		compatibility == TLSCompatibilityVCenter12
}

type EndpointHandle struct {
	endpoint *url.URL
}

func NewEndpointHandle(value string) (EndpointHandle, error) {
	parsed, err := url.Parse(value)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Path != "/sdk" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" {
		return EndpointHandle{}, profileError("ENDPOINT_HANDLE_REJECTED")
	}
	if !safeRuntimeText(parsed.Hostname(), 1, 253) {
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

type CredentialHandle struct {
	userName string
	password []byte
}

func NewCredentialHandle(userName string, password []byte) (CredentialHandle, error) {
	if !safeRuntimeText(userName, 1, 256) ||
		len(password) == 0 ||
		len(password) > maxCredentialBytes {
		return CredentialHandle{}, profileError("CREDENTIAL_HANDLE_REJECTED")
	}
	return CredentialHandle{
		userName: userName,
		password: append([]byte(nil), password...),
	}, nil
}

func (handle *CredentialHandle) Clear() {
	if handle == nil {
		return
	}
	clear(handle.password)
	handle.password = nil
	handle.userName = ""
}

func (CredentialHandle) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*CredentialHandle) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (CredentialHandle) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*CredentialHandle) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (CredentialHandle) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*CredentialHandle) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (CredentialHandle) String() string       { return runtimeMaterialRedaction }
func (CredentialHandle) GoString() string     { return runtimeMaterialRedaction }
func (CredentialHandle) LogValue() slog.Value { return slog.StringValue(runtimeMaterialRedaction) }
func (CredentialHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, runtimeMaterialRedaction)
}

type credentialSnapshot struct {
	userName string
	password []byte
}

func (handle CredentialHandle) snapshot() credentialSnapshot {
	return credentialSnapshot{
		userName: handle.userName,
		password: append([]byte(nil), handle.password...),
	}
}

func (snapshot credentialSnapshot) valid() bool {
	return safeRuntimeText(snapshot.userName, 1, 256) &&
		len(snapshot.password) > 0 &&
		len(snapshot.password) <= maxCredentialBytes
}

func (snapshot *credentialSnapshot) Clear() {
	if snapshot == nil {
		return
	}
	clear(snapshot.password)
	snapshot.password = nil
	snapshot.userName = ""
}

type TrustHandle struct {
	config        *tls.Config
	compatibility TLSCompatibility
}

func NewTrustHandle(config *tls.Config, compatibility TLSCompatibility) (TrustHandle, error) {
	if config == nil ||
		config.InsecureSkipVerify ||
		config.RootCAs == nil ||
		len(config.RootCAs.Subjects()) == 0 ||
		!safeRuntimeText(config.ServerName, 1, 253) ||
		!compatibility.valid() ||
		!fixedTLSConfigInput(config) {
		return TrustHandle{}, profileError("TRUST_HANDLE_REJECTED")
	}
	minimum := uint16(tls.VersionTLS13)
	if compatibility == TLSCompatibilityVCenter12 {
		minimum = tls.VersionTLS12
	}
	if config.MinVersion > minimum {
		minimum = config.MinVersion
	}
	if config.MaxVersion != 0 && config.MaxVersion < minimum {
		return TrustHandle{}, profileError("TRUST_HANDLE_REJECTED")
	}
	fixed := &tls.Config{
		RootCAs:                config.RootCAs.Clone(),
		ServerName:             config.ServerName,
		NextProtos:             []string{"http/1.1"},
		MinVersion:             minimum,
		MaxVersion:             config.MaxVersion,
		SessionTicketsDisabled: true,
	}
	return TrustHandle{config: fixed, compatibility: compatibility}, nil
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
	config        *tls.Config
	compatibility TLSCompatibility
}

func (handle TrustHandle) snapshot() trustSnapshot {
	if handle.config == nil {
		return trustSnapshot{}
	}
	return trustSnapshot{
		config:        clonePinnedTLSConfig(handle.config),
		compatibility: handle.compatibility,
	}
}

func (snapshot trustSnapshot) valid() bool {
	if snapshot.config == nil {
		return false
	}
	handle, err := NewTrustHandle(snapshot.config, snapshot.compatibility)
	return err == nil &&
		handle.config.MinVersion == snapshot.config.MinVersion &&
		handle.config.MaxVersion == snapshot.config.MaxVersion &&
		handle.config.ServerName == snapshot.config.ServerName &&
		handle.config.SessionTicketsDisabled == snapshot.config.SessionTicketsDisabled &&
		slices.Equal(handle.config.NextProtos, snapshot.config.NextProtos) &&
		handle.config.RootCAs.Equal(snapshot.config.RootCAs)
}

func (snapshot *trustSnapshot) Clear() {
	if snapshot == nil || snapshot.config == nil {
		return
	}
	snapshot.config.Certificates = nil
	snapshot.config.RootCAs = nil
	snapshot.config.ClientCAs = nil
	snapshot.config.VerifyConnection = nil
	snapshot.config.VerifyPeerCertificate = nil
	snapshot.config.ServerName = ""
	snapshot.config = nil
	snapshot.compatibility = 0
}

type AuthorityHandle struct {
	instanceUUID  string
	environmentID string
	roots         []types.ManagedObjectReference
	rootDigest    string
}

func NewAuthorityHandle(
	instanceUUID string,
	environmentID string,
	roots []types.ManagedObjectReference,
) (AuthorityHandle, error) {
	if !instanceUUIDPattern.MatchString(instanceUUID) ||
		!canonicalUUIDPattern.MatchString(environmentID) ||
		len(roots) == 0 ||
		len(roots) > maxAuthorityRoots {
		return AuthorityHandle{}, profileError("AUTHORITY_HANDLE_REJECTED")
	}
	owned := slices.Clone(roots)
	slices.SortFunc(owned, compareManagedObjectReference)
	for index, root := range owned {
		if !validAuthorityRoot(root) ||
			index > 0 && compareManagedObjectReference(owned[index-1], root) == 0 {
			return AuthorityHandle{}, profileError("AUTHORITY_HANDLE_REJECTED")
		}
	}
	fields := []string{"vsphere-authority-roots.v1", instanceUUID}
	fields = append(fields, environmentID)
	for _, root := range owned {
		fields = append(fields, root.Type, root.Value)
	}
	return AuthorityHandle{
		instanceUUID:  instanceUUID,
		environmentID: environmentID,
		roots:         owned,
		rootDigest:    digestFramedStrings(fields...),
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
	instanceUUID  string
	environmentID string
	roots         []types.ManagedObjectReference
	rootDigest    string
}

func (handle AuthorityHandle) snapshot() authoritySnapshot {
	return authoritySnapshot{
		instanceUUID:  handle.instanceUUID,
		environmentID: handle.environmentID,
		roots:         slices.Clone(handle.roots),
		rootDigest:    handle.rootDigest,
	}
}

func (snapshot authoritySnapshot) valid() bool {
	handle, err := NewAuthorityHandle(snapshot.instanceUUID, snapshot.environmentID, snapshot.roots)
	return err == nil && handle.rootDigest == snapshot.rootDigest
}

func (snapshot *authoritySnapshot) Clear() {
	if snapshot == nil {
		return
	}
	clear(snapshot.roots)
	snapshot.roots = nil
	snapshot.instanceUUID = ""
	snapshot.environmentID = ""
	snapshot.rootDigest = ""
}

type normalizationScope struct {
	InstanceUUID        string
	EnvironmentID       string
	AuthorityRoots      []types.ManagedObjectReference
	AuthorityRootDigest string
}

func (handle AuthorityHandle) normalizationScope() normalizationScope {
	return normalizationScope{
		InstanceUUID:        handle.instanceUUID,
		EnvironmentID:       handle.environmentID,
		AuthorityRoots:      slices.Clone(handle.roots),
		AuthorityRootDigest: handle.rootDigest,
	}
}

func (scope normalizationScope) valid() bool {
	handle, err := NewAuthorityHandle(scope.InstanceUUID, scope.EnvironmentID, scope.AuthorityRoots)
	return err == nil && handle.rootDigest == scope.AuthorityRootDigest
}

type RuntimeMaterial struct {
	endpoint   endpointSnapshot
	credential credentialSnapshot
	trust      trustSnapshot
	authority  authoritySnapshot
	active     bool
}

func NewRuntimeMaterial(
	endpoint EndpointHandle,
	credential CredentialHandle,
	trust TrustHandle,
	authority AuthorityHandle,
) (RuntimeMaterial, error) {
	material := RuntimeMaterial{
		endpoint:   endpoint.snapshot(),
		credential: credential.snapshot(),
		trust:      trust.snapshot(),
		authority:  authority.snapshot(),
		active:     true,
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
		material.credential.valid() &&
		material.trust.valid() &&
		material.authority.valid()
}

type resolvedRuntime struct {
	endpoint   endpointSnapshot
	credential credentialSnapshot
	trust      trustSnapshot
	authority  authoritySnapshot
}

func (material RuntimeMaterial) snapshot() (resolvedRuntime, bool) {
	if !material.valid() {
		return resolvedRuntime{}, false
	}
	return resolvedRuntime{
		endpoint: endpointSnapshot{
			endpoint: cloneURL(material.endpoint.endpoint),
		},
		credential: credentialSnapshot{
			userName: material.credential.userName,
			password: append([]byte(nil), material.credential.password...),
		},
		trust: trustSnapshot{
			config:        clonePinnedTLSConfig(material.trust.config),
			compatibility: material.trust.compatibility,
		},
		authority: authoritySnapshot{
			instanceUUID:  material.authority.instanceUUID,
			environmentID: material.authority.environmentID,
			roots:         slices.Clone(material.authority.roots),
			rootDigest:    material.authority.rootDigest,
		},
	}, true
}

func (runtime resolvedRuntime) valid() bool {
	return runtime.endpoint.valid() &&
		runtime.credential.valid() &&
		runtime.trust.valid() &&
		runtime.authority.valid()
}

func (runtime *resolvedRuntime) Clear() {
	if runtime == nil {
		return
	}
	runtime.endpoint.Clear()
	runtime.credential.Clear()
	runtime.trust.Clear()
	runtime.authority.Clear()
}

func (material *RuntimeMaterial) Clear() {
	if material == nil {
		return
	}
	material.endpoint.Clear()
	material.credential.Clear()
	material.trust.Clear()
	material.authority.Clear()
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

func validAuthorityRoot(reference types.ManagedObjectReference) bool {
	switch reference.Type {
	case "Folder", "Datacenter", "ClusterComputeResource", "ResourcePool":
	default:
		return false
	}
	return managedObjectValue.MatchString(reference.Value) &&
		!sensitiveRuntimeText(reference.Value)
}

func fixedTLSConfigInput(config *tls.Config) bool {
	if config == nil {
		return false
	}
	var emptyTicketKey [32]byte
	return config.Rand == nil &&
		config.Time == nil &&
		len(config.Certificates) == 0 &&
		config.NameToCertificate == nil &&
		config.GetCertificate == nil &&
		config.GetClientCertificate == nil &&
		config.GetConfigForClient == nil &&
		config.VerifyPeerCertificate == nil &&
		config.VerifyConnection == nil &&
		(len(config.NextProtos) == 0 ||
			slices.Equal(config.NextProtos, []string{"http/1.1"})) &&
		config.ClientAuth == tls.NoClientCert &&
		config.ClientCAs == nil &&
		len(config.CipherSuites) == 0 &&
		!config.PreferServerCipherSuites &&
		config.SessionTicketKey == emptyTicketKey &&
		config.ClientSessionCache == nil &&
		config.UnwrapSession == nil &&
		config.WrapSession == nil &&
		(config.MinVersion == 0 ||
			config.MinVersion == tls.VersionTLS12 ||
			config.MinVersion == tls.VersionTLS13) &&
		(config.MaxVersion == 0 ||
			config.MaxVersion == tls.VersionTLS12 ||
			config.MaxVersion == tls.VersionTLS13) &&
		len(config.CurvePreferences) == 0 &&
		!config.DynamicRecordSizingDisabled &&
		config.Renegotiation == tls.RenegotiateNever &&
		config.KeyLogWriter == nil &&
		len(config.EncryptedClientHelloConfigList) == 0 &&
		config.EncryptedClientHelloRejectionVerify == nil &&
		config.GetEncryptedClientHelloKeys == nil &&
		len(config.EncryptedClientHelloKeys) == 0
}

func clonePinnedTLSConfig(config *tls.Config) *tls.Config {
	if config == nil || config.RootCAs == nil {
		return nil
	}
	return &tls.Config{
		RootCAs:                config.RootCAs.Clone(),
		ServerName:             config.ServerName,
		NextProtos:             slices.Clone(config.NextProtos),
		MinVersion:             config.MinVersion,
		MaxVersion:             config.MaxVersion,
		SessionTicketsDisabled: config.SessionTicketsDisabled,
	}
}

func validManagedObjectReference(reference types.ManagedObjectReference) bool {
	return managedObjectTypeCode.MatchString(reference.Type) &&
		managedObjectValue.MatchString(reference.Value) &&
		!sensitiveRuntimeText(reference.Type) &&
		!sensitiveRuntimeText(reference.Value)
}

func compareManagedObjectReference(left, right types.ManagedObjectReference) int {
	if byType := strings.Compare(left.Type, right.Type); byType != 0 {
		return byType
	}
	return strings.Compare(left.Value, right.Value)
}

func safeRuntimeText(value string, minimum, maximum int) bool {
	if len(value) < minimum ||
		len(value) > maximum ||
		!utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == utf8.RuneError ||
			character == 0 ||
			character == '\r' ||
			character == '\n' ||
			unicode.IsControl(character) ||
			unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func sensitiveRuntimeText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"authorization",
		"bearer ",
		"cookie",
		"credential",
		"password",
		"private key",
		"secret",
		"session",
		"token",
		"-----begin",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func digestFramedStrings(fields ...string) string {
	hasher := sha256.New()
	var length [4]byte
	for _, field := range fields {
		_, _ = hasher.Write([]byte{1})
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(field))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func profileError(code string) error {
	return fmt.Errorf("%w: %s", errProfileContract, code)
}
