package vault

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxProfileIdentifierBytes = 128
	maxDynamicPathBytes       = 512
	maxSecretFields           = 16
	maxSecretFieldBytes       = 64 << 10
)

var (
	ErrInvalidProfile  = errors.New("invalid Vault issuer profile")
	profileIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	secretFieldPattern = regexp.MustCompile(
		`^[A-Za-z][A-Za-z0-9_]{0,63}$`,
	)
)

type SecretField struct {
	Name     string
	MaxBytes int
}

type ProfileConfig struct {
	IssuerID      string
	Revision      string
	Address       string
	ServerName    string
	CAPEM         []byte
	Namespace     string
	ManagerPolicy string
	TokenRole     string
	ChildPolicy   string
	DynamicPath   string
	MountType     string
	Metadata      map[string]string
	SecretFields  []SecretField
}

type Profile struct {
	issuerID      string
	revision      string
	address       url.URL
	serverName    string
	rootCAs       *x509.CertPool
	namespace     string
	managerPolicy string
	tokenRole     string
	childPolicy   string
	dynamicPath   string
	mountType     string
	metadata      map[string]string
	secretFields  []SecretField
}

func NewProfile(config ProfileConfig) (*Profile, error) {
	if !validProfileID(config.IssuerID) || !validProfileID(config.Revision) ||
		!validProfileID(config.ManagerPolicy) || !validProfileID(config.TokenRole) ||
		!validProfileID(config.ChildPolicy) || !validProfileID(config.MountType) {
		return nil, ErrInvalidProfile
	}
	address, err := validateAddress(config.Address)
	if err != nil {
		return nil, ErrInvalidProfile
	}
	if !validServerName(config.ServerName) ||
		!validNamespace(config.Namespace) || !validDynamicPath(config.DynamicPath) {
		return nil, ErrInvalidProfile
	}
	rootCAs, ok := parseExactCAPEM(config.CAPEM)
	if !ok {
		return nil, ErrInvalidProfile
	}
	metadata, ok := copyAndValidateMetadata(config.Metadata, config.IssuerID, config.Revision)
	if !ok {
		return nil, ErrInvalidProfile
	}
	fields, ok := copyAndValidateFields(config.SecretFields)
	if !ok {
		return nil, ErrInvalidProfile
	}
	return &Profile{
		issuerID: config.IssuerID, revision: config.Revision, address: *address,
		serverName: config.ServerName, rootCAs: rootCAs, namespace: strings.Trim(config.Namespace, "/"),
		managerPolicy: config.ManagerPolicy, tokenRole: config.TokenRole, childPolicy: config.ChildPolicy,
		dynamicPath: config.DynamicPath, mountType: config.MountType,
		metadata: metadata, secretFields: fields,
	}, nil
}

func parseExactCAPEM(source []byte) (*x509.CertPool, bool) {
	if len(source) == 0 {
		return nil, false
	}
	pool := x509.NewCertPool()
	rest := source
	count := 0
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, false
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, false
		}
		pool.AddCert(certificate)
		count++
		rest = remaining
	}
	return pool, count > 0
}

func (profile *Profile) IssuerID() string {
	if profile == nil {
		return ""
	}
	return profile.issuerID
}

func (profile *Profile) Revision() string {
	if profile == nil {
		return ""
	}
	return profile.revision
}

func (profile *Profile) Metadata() map[string]string {
	if profile == nil {
		return nil
	}
	return cloneStringMap(profile.metadata)
}

func (profile *Profile) SecretFields() []SecretField {
	if profile == nil {
		return nil
	}
	return append([]SecretField(nil), profile.secretFields...)
}

func (profile *Profile) String() string {
	if profile == nil {
		return "VaultProfile{Invalid:true}"
	}
	return fmt.Sprintf("VaultProfile{IssuerID:%q Revision:%q Security:[REDACTED]}", profile.issuerID, profile.revision)
}

func (profile *Profile) GoString() string { return profile.String() }

func (profile *Profile) MarshalJSON() ([]byte, error) {
	if profile == nil {
		return []byte(`{"redacted":true,"invalid":true}`), nil
	}
	return json.Marshal(struct {
		IssuerID string `json:"issuer_id"`
		Revision string `json:"revision"`
		Redacted bool   `json:"redacted"`
	}{profile.issuerID, profile.revision, true})
}

func validateAddress(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "*") {
		return nil, ErrInvalidProfile
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.ForceQuery || parsed.OmitHost || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return nil, ErrInvalidProfile
	}
	if parsed.Hostname() == "" || strings.ContainsAny(parsed.Host, "\\%") {
		return nil, ErrInvalidProfile
	}
	return parsed, nil
}

func validProfileID(value string) bool {
	return len(value) <= maxProfileIdentifierBytes && profileIDPattern.MatchString(value)
}

func validServerName(serverName string) bool {
	if serverName == "" || strings.TrimSpace(serverName) != serverName || strings.Contains(serverName, "*") ||
		strings.ContainsAny(serverName, "/\\%") {
		return false
	}
	return net.ParseIP(serverName) != nil || validDNSName(serverName)
}

func validDNSName(value string) bool {
	if len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validNamespace(value string) bool {
	if value == "" {
		return true
	}
	if strings.TrimSpace(value) != value || len(value) > 256 || strings.ContainsAny(value, "\\%?#") {
		return false
	}
	trimmed := strings.Trim(value, "/")
	if trimmed == "" {
		return false
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if !validProfileID(segment) || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validDynamicPath(value string) bool {
	if value == "" || len(value) > maxDynamicPathBytes || strings.TrimSpace(value) != value ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.ContainsAny(value, "\\%?#") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || !validProfileID(segment) {
			return false
		}
	}
	return true
}

func copyAndValidateMetadata(source map[string]string, issuerID, revision string) (map[string]string, bool) {
	if len(source) != 2 || source["profile"] != issuerID || source["revision"] != revision {
		return nil, false
	}
	return cloneStringMap(source), true
}

func copyAndValidateFields(source []SecretField) ([]SecretField, bool) {
	if len(source) == 0 || len(source) > maxSecretFields {
		return nil, false
	}
	seen := make(map[string]struct{}, len(source))
	total := 0
	fields := append([]SecretField(nil), source...)
	for _, field := range fields {
		if !secretFieldPattern.MatchString(field.Name) || field.MaxBytes <= 0 || field.MaxBytes > maxSecretFieldBytes {
			return nil, false
		}
		if _, duplicate := seen[field.Name]; duplicate {
			return nil, false
		}
		seen[field.Name] = struct{}{}
		total += field.MaxBytes
		if total > maxSecretFieldBytes {
			return nil, false
		}
	}
	return fields, true
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
