package runneridentity

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidConfiguration = errors.New("invalid runner identity configuration")
	ErrAuthenticationFailed = errors.New("runner certificate authentication failed")
	ErrWireIdentity         = errors.New("authenticated runner identity cannot cross a wire boundary")
)

type Pool string

const (
	PoolRead  Pool = "READ"
	PoolWrite Pool = "WRITE"
)

func (pool Pool) Valid() bool {
	return pool == PoolRead || pool == PoolWrite
}

type Options struct {
	TrustDomain string
	ReadRoots   []*x509.Certificate
	WriteRoots  []*x509.Certificate
	Clock       func() time.Time
}

type Verifier struct {
	trustDomain string
	roots       *x509.CertPool
	rootPools   map[string]Pool
	clock       func() time.Time
}

type identityState struct {
	trustDomain string
	pool        Pool
	instance    string
	spiffeURI   string
	evidence    Evidence
}

type Identity struct {
	state *identityState
}

func (identity Identity) Valid() bool {
	return identity.state != nil && validTrustDomain(identity.state.trustDomain) && identity.state.pool.Valid() &&
		validInstance(identity.state.instance) && identity.state.spiffeURI != "" && identity.state.evidence.Valid()
}

func (identity Identity) TrustDomain() string {
	if identity.state == nil {
		return ""
	}
	return identity.state.trustDomain
}

func (identity Identity) Pool() Pool {
	if identity.state == nil {
		return ""
	}
	return identity.state.pool
}

func (identity Identity) Instance() string {
	if identity.state == nil {
		return ""
	}
	return identity.state.instance
}

func (identity Identity) SPIFFEURI() string {
	if identity.state == nil {
		return ""
	}
	return identity.state.spiffeURI
}

func (identity Identity) Evidence() Evidence {
	if identity.state == nil {
		return Evidence{}
	}
	return identity.state.evidence
}

func (Identity) MarshalJSON() ([]byte, error) { return nil, ErrWireIdentity }

func (*Identity) UnmarshalJSON([]byte) error { return ErrWireIdentity }

type evidenceState struct {
	leafSHA256     string
	spkiSHA256     string
	serialHex      string
	authorityKeyID string
	rootSHA256     string
	rootPool       Pool
	notBefore      time.Time
	notAfter       time.Time
}

type Evidence struct {
	state *evidenceState
}

func (evidence Evidence) Valid() bool {
	return evidence.state != nil && validSHA256(evidence.state.leafSHA256) && validSHA256(evidence.state.spkiSHA256) &&
		validHex(evidence.state.serialHex) && validHex(evidence.state.authorityKeyID) &&
		validSHA256(evidence.state.rootSHA256) && evidence.state.rootPool.Valid() &&
		!evidence.state.notBefore.IsZero() && evidence.state.notAfter.After(evidence.state.notBefore)
}

func (evidence Evidence) LeafSHA256() string {
	if evidence.state == nil {
		return ""
	}
	return evidence.state.leafSHA256
}

func (evidence Evidence) SPKISHA256() string {
	if evidence.state == nil {
		return ""
	}
	return evidence.state.spkiSHA256
}

func (evidence Evidence) SerialHex() string {
	if evidence.state == nil {
		return ""
	}
	return evidence.state.serialHex
}

func (evidence Evidence) AuthorityKeyIDHex() string {
	if evidence.state == nil {
		return ""
	}
	return evidence.state.authorityKeyID
}

func (evidence Evidence) RootSHA256() string {
	if evidence.state == nil {
		return ""
	}
	return evidence.state.rootSHA256
}

func (evidence Evidence) RootPool() Pool {
	if evidence.state == nil {
		return ""
	}
	return evidence.state.rootPool
}

func (evidence Evidence) NotBefore() time.Time {
	if evidence.state == nil {
		return time.Time{}
	}
	return evidence.state.notBefore
}

func (evidence Evidence) NotAfter() time.Time {
	if evidence.state == nil {
		return time.Time{}
	}
	return evidence.state.notAfter
}

func (Evidence) MarshalJSON() ([]byte, error) { return nil, ErrWireIdentity }

func (*Evidence) UnmarshalJSON([]byte) error { return ErrWireIdentity }

func NewVerifier(options Options) (*Verifier, error) {
	if !validTrustDomain(options.TrustDomain) || len(options.ReadRoots) == 0 || len(options.WriteRoots) == 0 {
		return nil, ErrInvalidConfiguration
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.Clock().UTC().IsZero() {
		return nil, ErrInvalidConfiguration
	}
	verifier := &Verifier{
		trustDomain: options.TrustDomain,
		roots:       x509.NewCertPool(), rootPools: make(map[string]Pool), clock: options.Clock,
	}
	rootKeyPools := make(map[string]Pool)
	for _, rootSet := range []struct {
		pool  Pool
		roots []*x509.Certificate
	}{{PoolRead, options.ReadRoots}, {PoolWrite, options.WriteRoots}} {
		for _, root := range rootSet.roots {
			cloned, digest, err := cloneRoot(root)
			if err != nil {
				return nil, ErrInvalidConfiguration
			}
			if _, exists := verifier.rootPools[digest]; exists {
				return nil, ErrInvalidConfiguration
			}
			keyDigest := certificateDigest(cloned.RawSubjectPublicKeyInfo)
			if _, exists := rootKeyPools[keyDigest]; exists {
				return nil, ErrInvalidConfiguration
			}
			verifier.rootPools[digest] = rootSet.pool
			rootKeyPools[keyDigest] = rootSet.pool
			verifier.roots.AddCert(cloned)
		}
	}
	return verifier, nil
}

func (verifier *Verifier) ServerTLSConfig(serverCertificate tls.Certificate) (*tls.Config, error) {
	if verifier == nil || verifier.roots == nil {
		return nil, ErrInvalidConfiguration
	}
	now := verifier.clock().UTC()
	if now.IsZero() {
		return nil, ErrInvalidConfiguration
	}
	certificate, err := cloneServerCertificate(serverCertificate, now)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	configuration := &tls.Config{
		Time:                   verifier.clock,
		Certificates:           []tls.Certificate{certificate},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              verifier.roots.Clone(),
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
	}
	configuration.VerifyConnection = func(state tls.ConnectionState) error {
		_, verifyErr := verifier.identityFromConnectionState(state, false)
		return verifyErr
	}
	return configuration, nil
}

func (verifier *Verifier) IdentityFromConnectionState(state tls.ConnectionState) (Identity, error) {
	return verifier.identityFromConnectionState(state, true)
}

func (verifier *Verifier) identityFromConnectionState(state tls.ConnectionState, requireCompletedHandshake bool) (Identity, error) {
	if verifier == nil || verifier.roots == nil || verifier.clock == nil || requireCompletedHandshake && !state.HandshakeComplete ||
		state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return Identity{}, ErrAuthenticationFailed
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || len(leaf.Raw) == 0 || len(state.VerifiedChains[0]) == 0 || state.VerifiedChains[0][0] == nil ||
		!equalBytes(leaf.Raw, state.VerifiedChains[0][0].Raw) || !validClientLeaf(leaf) {
		return Identity{}, ErrAuthenticationFailed
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		if certificate == nil {
			return Identity{}, ErrAuthenticationFailed
		}
		digest := certificateDigest(certificate.Raw)
		if _, root := verifier.rootPools[digest]; !root {
			intermediates.AddCert(certificate)
		}
	}
	now := verifier.clock().UTC()
	if now.IsZero() {
		return Identity{}, ErrAuthenticationFailed
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: verifier.roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil || len(chains) == 0 {
		return Identity{}, ErrAuthenticationFailed
	}
	if !chainsBindAuthorityKeyIDs(chains) {
		return Identity{}, ErrAuthenticationFailed
	}
	rootPool, rootDigest, ok := verifier.resolveRoot(chains)
	if !ok {
		return Identity{}, ErrAuthenticationFailed
	}
	spiffeURI, uriPool, instance, ok := parseSPIFFE(leaf, verifier.trustDomain)
	if !ok || uriPool != rootPool || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 ||
		len(leaf.AuthorityKeyId) == 0 || len(leaf.RawSubjectPublicKeyInfo) == 0 {
		return Identity{}, ErrAuthenticationFailed
	}
	leafDigest := sha256.Sum256(leaf.Raw)
	spkiDigest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	evidence := Evidence{state: &evidenceState{
		leafSHA256: hex.EncodeToString(leafDigest[:]), spkiSHA256: hex.EncodeToString(spkiDigest[:]),
		serialHex: hex.EncodeToString(leaf.SerialNumber.Bytes()), authorityKeyID: hex.EncodeToString(leaf.AuthorityKeyId),
		rootSHA256: rootDigest, rootPool: rootPool, notBefore: leaf.NotBefore.UTC(), notAfter: leaf.NotAfter.UTC(),
	}}
	identity := Identity{state: &identityState{
		trustDomain: verifier.trustDomain, pool: uriPool, instance: instance, spiffeURI: spiffeURI, evidence: evidence,
	}}
	if !identity.Valid() {
		return Identity{}, ErrAuthenticationFailed
	}
	return identity, nil
}

func chainsBindAuthorityKeyIDs(chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		if len(chain) < 2 {
			return false
		}
		for index := 0; index < len(chain)-1; index++ {
			if !certificateAuthorityBinding(chain[index], chain[index+1]) {
				return false
			}
		}
	}
	return true
}

func validClientLeaf(leaf *x509.Certificate) bool {
	if leaf == nil || leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.UnknownExtKeyUsage) != 0 || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 ||
		len(leaf.SerialNumber.Bytes()) > 20 || len(leaf.AuthorityKeyId) == 0 || len(leaf.AuthorityKeyId) > 64 ||
		leaf.NotBefore.IsZero() || !leaf.NotAfter.After(leaf.NotBefore) {
		return false
	}
	return true
}

func (verifier *Verifier) resolveRoot(chains [][]*x509.Certificate) (Pool, string, bool) {
	var pool Pool
	var rootDigest string
	for _, chain := range chains {
		if len(chain) < 2 || chain[len(chain)-1] == nil {
			return "", "", false
		}
		digest := certificateDigest(chain[len(chain)-1].Raw)
		chainPool, exists := verifier.rootPools[digest]
		if !exists {
			return "", "", false
		}
		if pool != "" && (pool != chainPool || rootDigest != digest) {
			return "", "", false
		}
		pool, rootDigest = chainPool, digest
	}
	return pool, rootDigest, pool.Valid() && validSHA256(rootDigest)
}

var instancePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)

var subjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

func parseSPIFFE(leaf *x509.Certificate, trustDomain string) (string, Pool, string, bool) {
	if leaf == nil || len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return "", "", "", false
	}
	rawURI, ok := singleURISAN(leaf)
	if !ok || leaf.URIs[0] == nil || leaf.URIs[0].String() != rawURI {
		return "", "", "", false
	}
	uri := leaf.URIs[0]
	if uri == nil || uri.Scheme != "spiffe" || uri.Opaque != "" || uri.User != nil || uri.Host != trustDomain ||
		uri.Port() != "" || uri.RawQuery != "" || uri.ForceQuery || uri.Fragment != "" || uri.RawFragment != "" ||
		uri.RawPath != "" || strings.Contains(uri.String(), "%") {
		return "", "", "", false
	}
	parts := strings.Split(uri.Path, "/")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "runner" || !validInstance(parts[3]) {
		return "", "", "", false
	}
	var pool Pool
	switch parts[2] {
	case "read":
		pool = PoolRead
	case "write":
		pool = PoolWrite
	default:
		return "", "", "", false
	}
	canonical := "spiffe://" + trustDomain + "/runner/" + parts[2] + "/" + parts[3]
	if uri.String() != canonical {
		return "", "", "", false
	}
	return canonical, pool, parts[3], true
}

func singleURISAN(certificate *x509.Certificate) (string, bool) {
	var sanValue []byte
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(subjectAlternativeNameOID) {
			continue
		}
		if sanValue != nil {
			return "", false
		}
		sanValue = extension.Value
	}
	if len(sanValue) == 0 {
		return "", false
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(sanValue, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return "", false
	}
	var generalName asn1.RawValue
	rest, err = asn1.Unmarshal(sequence.Bytes, &generalName)
	if err != nil || len(rest) != 0 || generalName.Class != asn1.ClassContextSpecific || generalName.Tag != 6 ||
		generalName.IsCompound || len(generalName.Bytes) == 0 {
		return "", false
	}
	for _, character := range generalName.Bytes {
		if character < 0x21 || character > 0x7e {
			return "", false
		}
	}
	return string(generalName.Bytes), true
}

func validTrustDomain(value string) bool {
	if len(value) < 1 || len(value) > 255 || value != strings.ToLower(value) || strings.ContainsAny(value, ":/@%") || net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func validInstance(value string) bool {
	return instancePattern.MatchString(value)
}

func cloneRoot(root *x509.Certificate) (*x509.Certificate, string, error) {
	if root == nil || len(root.Raw) == 0 {
		return nil, "", ErrInvalidConfiguration
	}
	cloned, err := x509.ParseCertificate(append([]byte(nil), root.Raw...))
	if err != nil || !cloned.IsCA || !cloned.BasicConstraintsValid || cloned.KeyUsage&x509.KeyUsageCertSign == 0 ||
		cloned.CheckSignatureFrom(cloned) != nil {
		return nil, "", ErrInvalidConfiguration
	}
	return cloned, certificateDigest(cloned.Raw), nil
}

func cloneServerCertificate(value tls.Certificate, now time.Time) (tls.Certificate, error) {
	if len(value.Certificate) == 0 || len(value.Certificate) > 16 || value.PrivateKey == nil || now.IsZero() {
		return tls.Certificate{}, ErrInvalidConfiguration
	}
	parsed := make([]*x509.Certificate, len(value.Certificate))
	seen := make(map[string]struct{}, len(value.Certificate))
	for index, raw := range value.Certificate {
		if len(raw) == 0 {
			return tls.Certificate{}, ErrInvalidConfiguration
		}
		certificate, err := x509.ParseCertificate(append([]byte(nil), raw...))
		if err != nil || !certificateCurrent(certificate, now) {
			return tls.Certificate{}, ErrInvalidConfiguration
		}
		digest := certificateDigest(certificate.Raw)
		if _, duplicate := seen[digest]; duplicate {
			return tls.Certificate{}, ErrInvalidConfiguration
		}
		seen[digest] = struct{}{}
		parsed[index] = certificate
	}
	leaf := parsed[0]
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		len(leaf.UnknownExtKeyUsage) != 0 {
		return tls.Certificate{}, ErrInvalidConfiguration
	}
	for index := 1; index < len(parsed); index++ {
		issuer := parsed[index]
		child := parsed[index-1]
		if !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.KeyUsage&x509.KeyUsageCertSign == 0 ||
			!bytes.Equal(child.RawIssuer, issuer.RawSubject) || child.CheckSignatureFrom(issuer) != nil ||
			!certificateAuthorityBinding(child, issuer) {
			return tls.Certificate{}, ErrInvalidConfiguration
		}
	}
	signer, ok := value.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, ErrInvalidConfiguration
	}
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, ErrInvalidConfiguration
	}
	signerPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(certificatePublicKey, signerPublicKey) {
		return tls.Certificate{}, ErrInvalidConfiguration
	}
	cloned := tls.Certificate{
		Certificate:                  make([][]byte, len(value.Certificate)),
		PrivateKey:                   value.PrivateKey,
		SupportedSignatureAlgorithms: append([]tls.SignatureScheme(nil), value.SupportedSignatureAlgorithms...),
		OCSPStaple:                   append([]byte(nil), value.OCSPStaple...),
		SignedCertificateTimestamps:  make([][]byte, len(value.SignedCertificateTimestamps)),
		Leaf:                         leaf,
	}
	for index, raw := range value.Certificate {
		cloned.Certificate[index] = append([]byte(nil), raw...)
	}
	for index, timestamp := range value.SignedCertificateTimestamps {
		cloned.SignedCertificateTimestamps[index] = append([]byte(nil), timestamp...)
	}
	return cloned, nil
}

func certificateAuthorityBinding(child, issuer *x509.Certificate) bool {
	return child != nil && issuer != nil && len(child.AuthorityKeyId) > 0 && len(child.AuthorityKeyId) <= 64 &&
		len(issuer.SubjectKeyId) > 0 && len(issuer.SubjectKeyId) <= 64 &&
		bytes.Equal(child.AuthorityKeyId, issuer.SubjectKeyId)
}

func certificateCurrent(certificate *x509.Certificate, now time.Time) bool {
	return certificate != nil && !certificate.NotBefore.IsZero() && certificate.NotAfter.After(certificate.NotBefore) &&
		!now.Before(certificate.NotBefore) && now.Before(certificate.NotAfter)
}

func certificateDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validSHA256(value string) bool {
	return len(value) == 64 && validHex(value)
}

func validHex(value string) bool {
	if len(value) == 0 || len(value)%2 != 0 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (identity Identity) String() string   { return "<authenticated-runner-identity>" }
func (identity Identity) GoString() string { return identity.String() }
func (evidence Evidence) String() string   { return "<runner-certificate-evidence>" }
func (evidence Evidence) GoString() string { return evidence.String() }

func (identity Identity) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(identity.String()))
}
func (evidence Evidence) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(evidence.String()))
}
