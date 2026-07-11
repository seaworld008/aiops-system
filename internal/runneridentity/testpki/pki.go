// Package testpki creates short-lived, in-memory certificates for Runner
// identity tests. It never writes private keys or certificates to disk.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

type Authority struct {
	Certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	chain       []*x509.Certificate
}

type Certificate struct {
	TLS  tls.Certificate
	Leaf *x509.Certificate
}

type ClientOptions struct {
	CommonName      string
	URIs            []*url.URL
	DNSNames        []string
	IPAddresses     []net.IP
	EmailAddresses  []string
	ExtKeyUsage     []x509.ExtKeyUsage
	KeyUsage        x509.KeyUsage
	NotBefore       time.Time
	NotAfter        time.Time
	IsCA            bool
	ExtraExtensions []pkix.Extension
}

type IntermediateOptions struct {
	ExtraExtensions []pkix.Extension
}

func NewAuthority(name string, now time.Time) (*Authority, error) {
	if name == "" || now.IsZero() {
		return nil, fmt.Errorf("test PKI authority requires a name and clock")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate authority key: %w", err)
	}
	return newAuthority(name, now, key)
}

func (authority *Authority) Reissue(name string, now time.Time) (*Authority, error) {
	if authority == nil || authority.key == nil {
		return nil, fmt.Errorf("valid test authority is required")
	}
	return newAuthority(name, now, authority.key)
}

func newAuthority(name string, now time.Time, key *ecdsa.PrivateKey) (*Authority, error) {
	if name == "" || now.IsZero() || key == nil {
		return nil, fmt.Errorf("test PKI authority requires a name, clock, and key")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal authority public key: %w", err)
	}
	subjectKeyID := sha256.Sum256(publicKey)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          append([]byte(nil), subjectKeyID[:20]...),
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create authority certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse authority certificate: %w", err)
	}
	return &Authority{Certificate: certificate, key: key, chain: []*x509.Certificate{certificate}}, nil
}

func (authority *Authority) IssueIntermediate(name string, options IntermediateOptions, now time.Time) (*Authority, error) {
	if authority == nil || authority.Certificate == nil || authority.key == nil || len(authority.chain) == 0 ||
		name == "" || now.IsZero() {
		return nil, fmt.Errorf("valid parent authority, name, and clock are required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal intermediate public key: %w", err)
	}
	subjectKeyID := sha256.Sum256(publicKey)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-30 * time.Minute),
		NotAfter:              now.Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          append([]byte(nil), subjectKeyID[:20]...),
		ExtraExtensions:       append([]pkix.Extension(nil), options.ExtraExtensions...),
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, &key.PublicKey, authority.key)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate certificate: %w", err)
	}
	chain := make([]*x509.Certificate, 1, len(authority.chain)+1)
	chain[0] = certificate
	chain = append(chain, authority.chain...)
	return &Authority{Certificate: certificate, key: key, chain: chain}, nil
}

func (authority *Authority) IssueClient(options ClientOptions, now time.Time) (Certificate, error) {
	if authority == nil || authority.Certificate == nil || authority.key == nil || now.IsZero() {
		return Certificate{}, fmt.Errorf("valid test authority and clock are required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Certificate{}, fmt.Errorf("generate client key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Certificate{}, err
	}
	if options.NotBefore.IsZero() {
		options.NotBefore = now.Add(-time.Minute)
	}
	if options.NotAfter.IsZero() {
		options.NotAfter = now.Add(time.Hour)
	}
	if options.KeyUsage == 0 {
		options.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if options.ExtKeyUsage == nil {
		options.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: options.CommonName},
		NotBefore:             options.NotBefore,
		NotAfter:              options.NotAfter,
		KeyUsage:              options.KeyUsage,
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), options.ExtKeyUsage...),
		BasicConstraintsValid: true,
		IsCA:                  options.IsCA,
		URIs:                  cloneURLs(options.URIs),
		DNSNames:              append([]string(nil), options.DNSNames...),
		IPAddresses:           cloneIPs(options.IPAddresses),
		EmailAddresses:        append([]string(nil), options.EmailAddresses...),
		ExtraExtensions:       append([]pkix.Extension(nil), options.ExtraExtensions...),
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, &key.PublicKey, authority.key)
	if err != nil {
		return Certificate{}, fmt.Errorf("create client certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse client certificate: %w", err)
	}
	return Certificate{TLS: tls.Certificate{
		Certificate: authority.leafChain(raw),
		PrivateKey:  key,
		Leaf:        leaf,
	}, Leaf: leaf}, nil
}

func (authority *Authority) IssueServer(serverName string, now time.Time) (Certificate, error) {
	if authority == nil || authority.Certificate == nil || authority.key == nil || serverName == "" || now.IsZero() {
		return Certificate{}, fmt.Errorf("valid test authority, server name, and clock are required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Certificate{}, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, &key.PublicKey, authority.key)
	if err != nil {
		return Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse server certificate: %w", err)
	}
	return Certificate{TLS: tls.Certificate{
		Certificate: authority.leafChain(raw),
		PrivateKey:  key,
		Leaf:        leaf,
	}, Leaf: leaf}, nil
}

func (authority *Authority) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if authority != nil && len(authority.chain) > 0 && authority.chain[len(authority.chain)-1] != nil {
		pool.AddCert(authority.chain[len(authority.chain)-1])
	}
	return pool
}

func (authority *Authority) leafChain(raw []byte) [][]byte {
	chain := make([][]byte, 1, len(authority.chain)+1)
	chain[0] = append([]byte(nil), raw...)
	for _, certificate := range authority.chain {
		chain = append(chain, append([]byte(nil), certificate.Raw...))
	}
	return chain
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func cloneURLs(values []*url.URL) []*url.URL {
	cloned := make([]*url.URL, len(values))
	for index, value := range values {
		if value == nil {
			continue
		}
		copyValue := *value
		cloned[index] = &copyValue
	}
	return cloned
}

func cloneIPs(values []net.IP) []net.IP {
	cloned := make([]net.IP, len(values))
	for index, value := range values {
		cloned[index] = append(net.IP(nil), value...)
	}
	return cloned
}
