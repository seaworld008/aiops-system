package readtarget

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/securemanifest"
)

const (
	targetContractSchemaV1 = "read-target-contract.v1"
	endpointProfileV1      = "canonical-https-origin.v1"
	caProfileV1            = "strict-self-signed-root-set.v1"
	transportProfileV1     = "tls13-http1-no-proxy-no-redirect-no-compression.v1"
	credentialProfileV1    = "bearer-role.v1"
	networkProfileV1       = "content-addressed-network-policy.v1"
	maximumRoots           = 16
	maximumRootBundleBytes = 64 << 10
	maximumRootDERBytes    = 16 << 10
)

var (
	referencePattern = regexp.MustCompile(`^([a-z0-9][a-z0-9_.-]{0,59})-v1-([a-f0-9]{64})$`)
	basePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,59}$`)
	uuidPattern      = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

type builtContract struct {
	digest            string
	kind              readconnector.Kind
	origin            url.URL
	serverName        string
	credentialRoleRef string
	networkPolicyRef  string
	rootCAs           *x509.CertPool
	scope             Scope
}

type contractWire struct {
	SchemaVersion     string             `json:"schema_version"`
	EndpointProfile   string             `json:"endpoint_profile"`
	CAProfile         string             `json:"ca_profile"`
	TransportProfile  string             `json:"transport_profile"`
	CredentialProfile string             `json:"credential_profile"`
	NetworkProfile    string             `json:"network_profile"`
	Scope             Scope              `json:"scope"`
	Kind              readconnector.Kind `json:"kind"`
	Origin            string             `json:"origin"`
	ServerName        string             `json:"server_name"`
	RootDERHashes     []string           `json:"root_der_sha256"`
	CredentialRoleRef string             `json:"credential_role_ref"`
	NetworkPolicyRef  string             `json:"network_policy_ref"`
}

// BuildTargetRef derives the only TargetRef accepted for a normalized target
// definition. The referenced CA file is part of the semantic contract through
// its parsed certificate identities, never through its deployment path.
func BuildTargetRef(base string, definition Definition) (string, error) {
	if !basePattern.MatchString(base) || sensitiveReferenceBase(base) || definition.TargetRef != "" {
		return "", ErrInvalidDefinition
	}
	contract, err := buildContract(definition, time.Now().UTC())
	if err != nil {
		return "", ErrInvalidDefinition
	}
	return base + "-v1-" + contract.digest, nil
}

func buildContract(definition Definition, now time.Time) (builtContract, error) {
	return buildContractWithRoots(definition, now, loadRoots)
}

type rootLoader func(string, time.Time) (*x509.CertPool, []string, error)

func buildContractWithRoots(definition Definition, now time.Time, roots rootLoader) (builtContract, error) {
	if !validScope(definition.Scope) || !validKind(definition.Kind) ||
		!validContentReference(definition.CredentialRoleRef) ||
		!validContentReference(definition.NetworkPolicyRef) || roots == nil {
		return builtContract{}, ErrInvalidDefinition
	}
	origin, err := canonicalOrigin(definition.Endpoint.Origin, definition.Endpoint.ServerName)
	if err != nil {
		return builtContract{}, ErrInvalidDefinition
	}
	pool, hashes, err := roots(definition.Endpoint.CABundleFile, now)
	if err != nil {
		return builtContract{}, ErrInvalidDefinition
	}
	wire := contractWire{
		SchemaVersion: targetContractSchemaV1, EndpointProfile: endpointProfileV1,
		CAProfile: caProfileV1, TransportProfile: transportProfileV1,
		CredentialProfile: credentialProfileV1, NetworkProfile: networkProfileV1,
		Scope: definition.Scope, Kind: definition.Kind, Origin: origin.String(),
		ServerName: definition.Endpoint.ServerName, RootDERHashes: hashes,
		CredentialRoleRef: definition.CredentialRoleRef, NetworkPolicyRef: definition.NetworkPolicyRef,
	}
	digest, err := canonicalDigest(wire)
	if err != nil {
		return builtContract{}, ErrInvalidDefinition
	}
	return builtContract{
		digest: digest, kind: definition.Kind, origin: *origin,
		serverName: definition.Endpoint.ServerName, credentialRoleRef: definition.CredentialRoleRef,
		networkPolicyRef: definition.NetworkPolicyRef, rootCAs: pool, scope: definition.Scope,
	}, nil
}

func validScope(scope Scope) bool {
	return uuidPattern.MatchString(scope.TenantID) && uuidPattern.MatchString(scope.WorkspaceID) &&
		uuidPattern.MatchString(scope.EnvironmentID)
}

func validKind(kind readconnector.Kind) bool {
	return kind == readconnector.KindPrometheus || kind == readconnector.KindVictoriaLogs
}

func canonicalOrigin(raw, serverName string) (*url.URL, error) {
	if raw == "" || raw != strings.ToLower(raw) || strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, "*\\%") {
		return nil, ErrInvalidDefinition
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.ForceQuery || parsed.OmitHost {
		return nil, ErrInvalidDefinition
	}
	hostname := parsed.Hostname()
	port := parsed.Port()
	portNumber, portErr := strconv.Atoi(port)
	if portErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port ||
		net.ParseIP(hostname) != nil || !validDNSName(hostname) || serverName != hostname ||
		parsed.Host != net.JoinHostPort(hostname, port) || raw != "https://"+net.JoinHostPort(hostname, port) {
		return nil, ErrInvalidDefinition
	}
	return parsed, nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") ||
		strings.Count(value, ".") < 1 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validContentReference(value string) bool {
	matches := referencePattern.FindStringSubmatch(value)
	return len(matches) == 3 && !sensitiveReferenceBase(matches[1])
}

func sensitiveReferenceBase(value string) bool {
	var skeleton strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			skeleton.WriteRune(character)
		}
	}
	normalized := skeleton.String()
	for _, token := range []string{
		"authorization", "authentication", "auth", "apikey", "accessor", "secret", "token",
		"password", "credential", "cookie", "privatekey", "endpoint", "url", "host", "dsn",
	} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func loadRoots(path string, now time.Time) (*x509.CertPool, []string, error) {
	var pool *x509.CertPool
	var hashes []string
	err := securemanifest.Load(path, func(contents []byte) error {
		certificates, parsedHashes, parseErr := parseRoots(contents, now)
		if parseErr != nil {
			return ErrInvalidDefinition
		}
		pool = x509.NewCertPool()
		for _, certificate := range certificates {
			pool.AddCert(certificate)
		}
		hashes = parsedHashes
		return nil
	})
	if err != nil || pool == nil {
		return nil, nil, ErrInvalidDefinition
	}
	return pool, hashes, nil
}

func parseRoots(contents []byte, now time.Time) ([]*x509.Certificate, []string, error) {
	if len(contents) == 0 || len(contents) > maximumRootBundleBytes {
		return nil, nil, ErrInvalidDefinition
	}
	remaining := bytes.Trim(contents, " \t\r\n")
	if len(remaining) == 0 || now.IsZero() {
		return nil, nil, ErrInvalidDefinition
	}
	certificates := make([]*x509.Certificate, 0, 1)
	hashes := make([]string, 0, 1)
	seen := make(map[[sha256.Size]byte]struct{})
	for len(remaining) > 0 {
		if len(certificates) == maximumRoots || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, nil, ErrInvalidDefinition
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			len(block.Bytes) == 0 || len(block.Bytes) > maximumRootDERBytes || len(rest) >= len(remaining) {
			return nil, nil, ErrInvalidDefinition
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		digest := sha256.Sum256(block.Bytes)
		_, duplicate := seen[digest]
		if err != nil || duplicate || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
			!bytes.Equal(certificate.RawSubject, certificate.RawIssuer) || certificate.CheckSignatureFrom(certificate) != nil {
			return nil, nil, ErrInvalidDefinition
		}
		seen[digest] = struct{}{}
		certificates = append(certificates, certificate)
		hashes = append(hashes, hex.EncodeToString(digest[:]))
		remaining = bytes.Trim(rest, " \t\r\n")
	}
	if len(certificates) == 0 {
		return nil, nil, ErrInvalidDefinition
	}
	sort.Strings(hashes)
	return certificates, hashes, nil
}

func canonicalDigest(value any) (string, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func targetFromContract(targetRef string, contract builtContract) Target {
	return Target{
		targetRef: targetRef, digest: contract.digest, kind: contract.kind, origin: contract.origin,
		serverName: contract.serverName, credentialRoleRef: contract.credentialRoleRef,
		networkPolicyRef: contract.networkPolicyRef,
		tlsConfiguration: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: contract.rootCAs.Clone(), ServerName: contract.serverName,
			NextProtos: []string{"http/1.1"}, InsecureSkipVerify: false,
			SessionTicketsDisabled: true, Renegotiation: tls.RenegotiateNever,
		},
	}
}
